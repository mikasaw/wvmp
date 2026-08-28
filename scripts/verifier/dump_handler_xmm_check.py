#!/usr/bin/env python3
"""
MIT-389 A.3: SSE handler byte-level dump verification for WVmpVerifier.

Why this gate exists (MIT-371 idle-handler defect):
  The six SSE handlers' Keystone asm once embedded a bare multi-digit
  immediate ("sub T9, 24" -> keystone reads 0x24=36), corrupting the xmm
  slot-offset formula so every SSE handler wrote the GPR slot area instead
  of ctx.xmm[0..7] -- the FP instruction itself was still present, so a
  naive "does the handler contain subss xmm0, xmm1" check would NOT have
  caught it.  The regression detector is therefore BOTH:

    1. FP instruction present and operating on xmm registers
       (dispatch-sheet literal ask: "emit subss xmm0, xmm1"), and
    2. the xmm slot-offset prologue constants are exactly right:
         sub <t9>, 0x18   (24 -- a `sub r, 0x24` = the MIT-371 bug)
         shl <t9>, 4
         add <t9>, 0x140  (kCtxXmmBase)
       each appearing >= 3 times (dst load / src load / dst store),
       plus the pc advance `add <pc>, 1`, with NO other immediate-bearing
       sub/shl/add in the handler (formula drift = FAIL), and
    3. >= 3 movups with xmm operands (128-bit ctx.xmm load / load / store).

Input artifacts (both from ONE protect run of a real sample, same seed):
  --asm <runtime_dump.txt>  text dump produced by setting
                            WVMP_RUNTIME_DUMP=<win path> before wvmp_cli
                            (writes handler names + offsets + total size).
  --pe  <protected.exe>     the .wvmp section of the protected exe starts
                            with the runtime image (stub_link_pass.cpp
                            writes rt.image.code at section offset 0), so
                            the executed handler bytes are sliced from it.
  --bin <wvmp_runtime_dump.bin>  alternative: use a previously extracted
                            image instead of --pe (file is written by
                            --out-bin on first extraction).

Checks every handler named in the SSE set:
  addss addps addpd subss subps subpd
(extend the set when new SSE/VMX/AVX ops land; unlisted handlers that emit
 xmm FP arithmetic are flagged as unregistered = forced review.)

Exit codes: 0 all checks passed; 1 at least one handler failed; 2 tooling error.

Usage:
  python scripts\\verifier\\dump_handler_xmm_check.py \
      --asm runtime_dump.txt --pe protected.exe --out-bin wvmp_runtime_dump.bin
  python scripts\\verifier\\dump_handler_xmm_check.py \
      --bin wvmp_runtime_dump.bin --asm runtime_dump.txt
"""

from __future__ import annotations

import argparse
import re
import struct
import sys

try:
    import capstone  # type: ignore
except ImportError:
    sys.stderr.write(
        "[ERROR] capstone Python binding not installed; "
        "install via `pip install capstone` and retry\n"
    )
    sys.exit(2)


# Handlers that must satisfy the SSE ctx.xmm readback gate (extend here when
# new SSE/VMX/AVX ops land -- keep in sync with the verifier instructions).
# MIT-374: divss/divps/divpd added (SSE float div, same movups slot-offset
# prologue as add/sub -- the constants below are op-agnostic).
SSE_HANDLERS = {"addss", "addps", "addpd", "subss", "subps", "subpd",
                "divss", "divps", "divpd"}

# Expected xmm slot-offset prologue constants (asmgen emit_xmm_offset_into_t9):
#   xmm slot offset = kCtxXmmBase(0x140) + (reg - 24) * 16
# MIT-371 bug shape: `sub r, 0x24` (=36) instead of `sub r, 0x18` (=24).
EXPECTED_SUB_IMMS = {0x18}
EXPECTED_SHL_IMMS = {0x4}
EXPECTED_ADD_IMMS = {0x140, 1}  # 0x140 = xmm base; 1 = pc advance
MIN_PROLOGUE_COUNT = 3          # dst load / src load / dst store
MIN_MOVUPS_COUNT = 3

FP_MNEMONIC_RE = re.compile(
    r"^(addss|addps|addpd|subss|subps|subpd|mulss|mulps|mulpd|divss|divps|divpd|"
    r"movss|movps|movsd|movapd|movaps|movups|movupd|xorps|orps|andps|andpd|"
    r"comiss|ucomiss|comisd|ucomisd)$"
)


def parse_asm_dump(text: str) -> tuple[int, int, list[tuple[str, int]]]:
    """Parse the WVMP_RUNTIME_DUMP text: total size, table offset, handlers."""
    total = None
    table = None
    handlers: list[tuple[str, int]] = []
    m = re.search(r"total=(0x[0-9A-Fa-f]+)", text)
    if m:
        total = int(m.group(1), 16)
    m = re.search(r"table=\+?(0x[0-9A-Fa-f]+)", text)
    if m:
        table = int(m.group(1), 16)
    for name, off in re.findall(
        r"; ---- handler (\S+) @ \+?(0x[0-9A-Fa-f]+) ----", text
    ):
        handlers.append((name, int(off, 16)))
    if total is None or table is None or not handlers:
        raise ValueError(
            "runtime dump text missing total/table/handler layout lines "
            "(is this a WVMP_RUNTIME_DUMP file?)"
        )
    return total, table, handlers


def extract_wvmp_section(pe_path: str) -> tuple[int, bytes]:
    """Return (raw_offset, raw_bytes) of the .wmp section raw data."""
    with open(pe_path, "rb") as f:
        data = f.read()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_sz = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    sec0 = e_lfanew + 24 + opt_sz
    for i in range(nsec):
        off = sec0 + i * 40
        name = data[off : off + 8].rstrip(b"\0").decode("ascii", "replace")
        if name == ".wvmp":
            raw_sz, raw_ptr = struct.unpack_from("<II", data, off + 16)
            return raw_ptr, data[raw_ptr : raw_ptr + raw_sz]
    raise ValueError(f".wvmp section not found in {pe_path} (was it protected?)")


def parse_imm(text: str) -> int:
    s = text.strip()
    neg = s.startswith("-")
    if neg:
        s = s[1:]
    v = int(s, 0)
    return -v if neg else v


def gpr_name(ins, idx: int) -> str | None:
    op = ins.operands[idx]
    if op.type != capstone.x86.X86_OP_REG:
        return None
    name = ins.reg_name(op.reg)
    return None if name.startswith("xmm") else name


def check_sse_handler(name: str, code: bytes, base_va: int, md) -> tuple[bool, list[str]]:
    """Return (ok, evidence lines) for one SSE handler's disassembly."""
    lines: list[str] = []
    ok = True

    fp_hits: list[str] = []
    sub_imms: list[tuple[str, int]] = []
    shl_imms: list[tuple[str, int]] = []
    add_imms: list[tuple[str, int]] = []
    movups_count = 0
    other_imm_ops: list[str] = []

    for ins in md.disasm(code, base_va):
        ops = ins.op_str
        if ins.mnemonic in ("sub", "shl", "add"):
            reg = gpr_name(ins, 0)
            if reg is not None and ins.operands[1].type == capstone.x86.X86_OP_IMM:
                imm = parse_imm(str(ins.operands[1].imm))
                if ins.mnemonic == "sub":
                    sub_imms.append((reg, imm))
                elif ins.mnemonic == "shl":
                    shl_imms.append((reg, imm))
                else:
                    add_imms.append((reg, imm))
        if ins.mnemonic == "movups" and ops and "xmm" in ops:
            movups_count += 1
        if FP_MNEMONIC_RE.match(ins.mnemonic):
            fp_hits.append(f"{ins.mnemonic} {ops}")

    fp_expected = [h for h in fp_hits if h.startswith(name + " ")]
    if not fp_expected:
        ok = False
        lines.append(f"    FAIL: no `{name} <xmm>, <xmm>` FP instruction found")
    else:
        # the FP instruction must have both operands in xmm registers
        parts = fp_expected[0].split(" ", 1)[1]
        regs = [p.strip() for p in parts.split(",")]
        if len(regs) != 2 or not all(r.startswith("xmm") for r in regs):
            ok = False
            lines.append(f"    FAIL: `{fp_expected[0]}` operands not both xmm")
        else:
            lines.append(f"    ok: FP instruction `{fp_expected[0]}` present (xmm, xmm)")

    for label, imms, allowed, minc in (
        ("sub", sub_imms, EXPECTED_SUB_IMMS, MIN_PROLOGUE_COUNT),
        ("shl", shl_imms, EXPECTED_SHL_IMMS, MIN_PROLOGUE_COUNT),
        ("add", add_imms, EXPECTED_ADD_IMMS, None),
    ):
        bad = [(r, v) for (r, v) in imms if v not in allowed]
        if bad:
            ok = False
            lines.append(
                f"    FAIL: {label} immediates outside expected set "
                f"{sorted(hex(v) for v in allowed)}: "
                + ", ".join(f"{r},{hex(v)}" for r, v in bad)
            )
        if minc is not None and sum(1 for (_, v) in imms if v in allowed) < minc:
            ok = False
            lines.append(
                f"    FAIL: {label} prologue count "
                f"({sum(1 for (_, v) in imms if v in allowed)}) < {minc}"
            )
        lines.append(
            f"    ok: {label} immediates = "
            + ", ".join(f"{r},{hex(v)}" for r, v in imms)
            + ("" if imms else "  (none)")
        )

    add_0x140 = sum(1 for (_, v) in add_imms if v == 0x140)
    add_1 = sum(1 for (_, v) in add_imms if v == 1)
    if add_0x140 < MIN_PROLOGUE_COUNT or add_1 < 1:
        ok = False
        lines.append(
            f"    FAIL: add counts wrong: 0x140 x{add_0x140} (<{MIN_PROLOGUE_COUNT}?) "
            f"or pc-advance 1 x{add_1} (<1?)"
        )

    if movups_count < MIN_MOVUPS_COUNT:
        ok = False
        lines.append(
            f"    FAIL: movups xmm ctx load/store count {movups_count} < {MIN_MOVUPS_COUNT}"
        )
    else:
        lines.append(f"    ok: movups xmm count = {movups_count}")

    return ok, lines


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--asm", required=True, help="WVMP_RUNTIME_DUMP text file")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--pe", help="protected exe (.wvmp section holds the runtime image)")
    g.add_argument("--bin", help="previously extracted runtime image bin")
    ap.add_argument(
        "--out-bin",
        default="wvmp_runtime_dump.bin",
        help="where to write the extracted runtime image (default: ./wvmp_runtime_dump.bin)",
    )
    args = ap.parse_args()

    try:
        with open(args.asm, "r", encoding="utf-8", errors="replace") as f:
            total, table_off, handlers = parse_asm_dump(f.read())
    except (OSError, ValueError) as e:
        print(f"[dump-check] FAIL tooling: {e}")
        return 2

    if args.pe:
        try:
            _, section = extract_wvmp_section(args.pe)
        except (OSError, ValueError) as e:
            print(f"[dump-check] FAIL tooling: {e}")
            return 2
        if len(section) < total:
            print(
                f"[dump-check] FAIL tooling: .wvmp raw size {len(section)} "
                f"< runtime total {total} (seed mismatch between --asm and --pe?)"
            )
            return 2
        image = bytes(section[:total])
        with open(args.out_bin, "wb") as f:
            f.write(image)
        print(f"[dump-check] runtime image {total} bytes -> {args.out_bin}")
    else:
        with open(args.bin, "rb") as f:
            image = f.read()
        if len(image) < total:
            print(f"[dump-check] FAIL tooling: bin {len(image)} < total {total}")
            return 2
        print(f"[dump-check] runtime image {len(image)} bytes from {args.bin}")

    boundaries = sorted([off for _, off in handlers] + [table_off, total])
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    all_ok = True
    passed: list[str] = []
    failed: list[str] = []
    unregistered_fp: list[str] = []

    print(
        f"[dump-check] handlers={len(handlers)} table=+{hex(table_off)} "
        f"total={hex(total)}"
    )
    for name, off in handlers:
        nxt = min(b for b in boundaries if b > off)
        code = image[off:nxt]
        if name in SSE_HANDLERS:
            ok, lines = check_sse_handler(name, code, off, md)
            verdict = "PASS" if ok else "FAIL"
            print(f"  [{verdict}] handler {name} @ +{hex(off)} ({len(code)} bytes)")
            for ln in lines:
                print(ln)
            (passed if ok else failed).append(name)
            all_ok = all_ok and ok
        else:
            fp = [h for h in (f"{i.mnemonic} {i.op_str}" for i in md.disasm(code, off)) if FP_MNEMONIC_RE.match(h.split(" ", 1)[0])]
            note = ""
            if fp:
                note = f"  (emits FP/xmm ops: {fp[0]} -> unregistered SSE handler?)"
                unregistered_fp.append(name)
            print(f"  [skip] handler {name} @ +{hex(off)} ({len(code)} bytes, non-SSE){note}")

    print(f"[dump-check] SSE handlers passed: {passed}")
    if unregistered_fp:
        print(
            f"[dump-check] WARNING: handlers emit FP/xmm ops but are not in the "
            f"SSE gate set: {unregistered_fp} (extend SSE_HANDLERS and re-run)"
        )
    if failed:
        print(f"[dump-check] RESULT: FAIL - {failed}")
        return 1
    print("[dump-check] RESULT: PASS - all SSE handlers emit real ctx.xmm updates")
    return 0


if __name__ == "__main__":
    sys.exit(main())
