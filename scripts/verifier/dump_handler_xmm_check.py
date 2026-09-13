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
  addss addps addpd subss subps subpd divss divps divpd
  xorps orps andps addsd subsd divsd movsd
(extend the set when new SSE/VMX/AVX ops land; unlisted handlers that emit
 xmm FP arithmetic are flagged as unregistered = forced review.)
Plus the MIT-408 mem-form primitives xmmload/xmmstore (check_mem_handler:
 memory-operand FP load/store + width chain + dual xmm/GP slot addressing).

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
# MIT-376: xorps/orps/andps added (SSE float bitwise, reuse the MIT-375
# build_xmm_transfer four-step template -- same 3x movups + sub/shl/add
# prologue, FP instruction swapped).  ucomiss/ucomisd deliberately NOT
# registered: they are compare-only (no dst writeback -> 2 movups / 2-slot
# prologue), so the writeback-shaped constants below would false-FAIL them;
# their flags path is asserted by the sse_bwcmpss_flags_readback shadow
# sample instead (dispatch sheet §D D2.1).  They are listed in
# FP_MNEMONIC_RE, so they still surface as "unregistered" WARNING for review.
# MIT-408: addsd/subsd/divsd/movsd added (SSE scalar-double family, same
# four-step template as addss -- identical prologue constants, native
# mnemonic swapped).  xmmload/xmmstore deliberately NOT registered here:
# they are the mem-form primitives (memory-operand FP instruction, width
# chain from aux, dual xmm/GP-slot addressing) -- checked by the separate
# check_mem_handler gate (MEM_HANDLERS below) with a dedicated shape.
SSE_HANDLERS = {"addss", "addps", "addpd", "subss", "subps", "subpd",
                "divss", "divps", "divpd",
                "xorps", "orps", "andps",
                "addsd", "subsd", "divsd", "movsd",
                # MIT-425 (G1b): SSE mul family + andnps (all share the
                # build_xmm_transfer four-step template with dual_src=True;
                # pand/por/pxor/pandn fold onto andps/orps/xorps/andnps so
                # no separate handlers exist for them).
                "mulss", "mulsd", "mulps", "mulpd", "andnps"}

# MIT-427 (G1c): movd/movq GP<->xmm bridge primitives (xmmfromgp/gpfromxmm).
# Checked with the mem-form shape (check_mem_handler): both handlers carry
#   - memory-operand movd/movq/movsd (zeroing/truncation semantics are native),
#   - >= 1 xmm slot-offset prologue (sub 0x18 / shl 4 / add 0x140) + add 1,
#   - >= 1 movups touching ctx,
#   - width-chain cmp imm in {4, 8} (aux width dispatch).
# xmmfromgp has 2 prologues (src-xmm read path + dst write); gpfromxmm has 1.
BRIDGE_HANDLERS = {"xmmfromgp", "gpfromxmm"}

# MIT-511 (T63 · AVX 档B wave1): vzeroupper/vzeroall ABI words.  Shape
# asserted (check_vzero_handler): no slot-offset prologue (operand-free
# words), pxor xmm0, xmm0 zero source, >= 16 movups face stores (upper
# halves; vzeroall has 8 xmm-face + 32 ymm-face = 40), physical
# vzeroupper/vzeroall instruction present, pc advance add 1, and no
# immediate-bearing sub/shl (the MIT-371 slot bug shape cannot occur here).
VZERO_HANDLERS = {"vzeroupper", "vzeroall"}
# MIT-512 (T64 · AVX 档B wave2①): ymm data-path words (ymmmov/ymmload/
# ymmstore).  Shape asserted (check_ymm_handler): slot-offset prologue is
#   shl 5 / sub 0x300 (24*32) / add 0x1C0 (kCtxYmmBase) -- stride 32 face,
# plus pc advance add 1 and >= 2 vmovups with ymm operands (load/store
# pair; ymmmov has 2 prologues, mem forms 1).  All face accesses must be
# vmovups (ctx base only 16B-aligned -- MIT-511 F3), so no vmovaps allowed.
YMM_HANDLERS = {"ymmmov", "ymmload", "ymmstore",
                # MIT-513 (wave2②): packed arithmetic full set
                "ymmaddps", "ymmaddpd", "ymmsubps", "ymmsubpd",
                "ymmmulps", "ymmmulpd", "ymmdivps", "ymmdivpd",
                "ymmxorps", "ymmxorpd", "ymmorps", "ymmorpd",
                "ymmandps", "ymmandpd", "ymmpxor", "ymmpor",
                "ymmpand", "ymmpandn"}

# MIT-408: mem-form primitives (XmmLoad / XmmStore).  Expected shape:
#   - memory-operand FP instruction present (movss/movsd/movups with a
#     [reg] memory operand -- width chain from aux: cmp <aux>, 0x4 / 0x8,
#     16 is the chain-tail fallthrough);
#   - >= 1 xmm slot-offset prologue (sub 0x18 / shl 4 / add 0x140: the
#     xmm-area branch of the dual slot addressing) + pc advance add 1;
#   - >= 1 movups touching ctx (slot read/write via ctx reg);
#   - no other immediate-bearing sub/shl/add (0x10 appears only as a
#     memory displacement, which is not an instruction immediate).
MEM_HANDLERS = {"xmmload", "xmmstore"}

# Expected xmm slot-offset prologue constants (asmgen emit_xmm_offset_into_t9):
#   xmm slot offset = kCtxXmmBase(0x140) + (reg - 24) * 16
# MIT-371 bug shape: `sub r, 0x24` (=36) instead of `sub r, 0x18` (=24).
EXPECTED_SUB_IMMS = {0x18}
EXPECTED_SHL_IMMS = {0x4}
EXPECTED_ADD_IMMS = {0x140, 1}  # 0x140 = xmm base; 1 = pc advance
MIN_PROLOGUE_COUNT = 3          # dst load / src load / dst store
MIN_MOVUPS_COUNT = 3
# MIT-408: mem-form handlers have exactly ONE xmm-area branch per slot access
# (xmmload: dst store; xmmstore: src read) -- prologue constants appear once.
MEM_MIN_PROLOGUE_COUNT = 1
# Width chain constants (aux = 4/8/16 bytes; 16 = chain-tail fallthrough, so
# only 4 and 8 appear as explicit cmp immediates).
MEM_WIDTH_CMP_IMMS = {4, 8}

FP_MNEMONIC_RE = re.compile(
    r"^(addss|addps|addpd|addsd|subss|subps|subpd|subsd|mulss|mulsd|mulps|mulpd|"
    r"divss|divps|divpd|divsd|"
    r"movss|movps|movsd|movapd|movaps|movups|movupd|xorps|orps|andps|andpd|"
    r"andnps|comiss|ucomiss|comisd|ucomisd|"
    r"movd|movq|movdqa|movdqu|paddq|psubq|paddb|paddd|pmovmskb|pcmpeqd)$"
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


def check_mem_handler(name: str, code: bytes, base_va: int, md) -> tuple[bool, list[str]]:
    """Return (ok, evidence lines) for one MIT-408 mem-form primitive (xmmload/xmmstore).

    Shape asserted (see MEM_HANDLERS comment):
      1. >= 1 memory-operand FP load/store (movss/movsd/movups with a [reg]
         operand) -- the width chain (aux 4/8, 16 = chain-tail);
      2. >= 1 xmm slot-offset prologue (sub 0x18 / shl 4 / add 0x140) -- the
         xmm-area branch of the dual slot addressing, and add 1 (pc advance);
      3. >= 1 movups touching ctx (slot read/write);
      4. no other immediate-bearing sub/shl/add (0x10 appears only as a
         memory displacement, not an instruction immediate -- the MIT-371
         bug shape `sub r, 0x24` still FAILs);
      5. >= 1 cmp with width-chain immediate 4 or 8 (aux width dispatch).
    """
    lines: list[str] = []
    ok = True

    fp_mem_hits: list[str] = []
    sub_imms: list[tuple[str, int]] = []
    shl_imms: list[tuple[str, int]] = []
    add_imms: list[tuple[str, int]] = []
    cmp_imms: list[tuple[str, int]] = []
    movups_ctx = 0

    for ins in md.disasm(code, base_va):
        ops = ins.op_str
        if ins.mnemonic in ("sub", "shl", "add", "cmp"):
            reg = gpr_name(ins, 0)
            if reg is not None and ins.operands[1].type == capstone.x86.X86_OP_IMM:
                immv = parse_imm(str(ins.operands[1].imm))
                if ins.mnemonic == "sub":
                    sub_imms.append((reg, immv))
                elif ins.mnemonic == "shl":
                    shl_imms.append((reg, immv))
                elif ins.mnemonic == "cmp":
                    cmp_imms.append((reg, immv))
                else:
                    add_imms.append((reg, immv))
        if ins.mnemonic == "movups" and "xmm" in ops:
            movups_ctx += 1
        if FP_MNEMONIC_RE.match(ins.mnemonic) and any(
            o.type == capstone.x86.X86_OP_MEM for o in ins.operands
        ):
            fp_mem_hits.append(f"{ins.mnemonic} {ops}")

    if not fp_mem_hits:
        ok = False
        lines.append("    FAIL: no memory-operand FP instruction (movss/movsd/movups [..])")
    else:
        lines.append(f"    ok: memory-operand FP: {fp_mem_hits[0]}")

    bad_sub = [(r, v) for (r, v) in sub_imms if v not in EXPECTED_SUB_IMMS]
    bad_shl = [(r, v) for (r, v) in shl_imms if v not in EXPECTED_SHL_IMMS]
    bad_add = [(r, v) for (r, v) in add_imms if v not in EXPECTED_ADD_IMMS]
    if bad_sub or bad_shl or bad_add:
        ok = False
        lines.append(
            "    FAIL: immediates outside expected sets "
            f"sub{{{sorted(hex(v) for v in EXPECTED_SUB_IMMS)}}} "
            f"shl{{{sorted(hex(v) for v in EXPECTED_SHL_IMMS)}}} "
            f"add{{{sorted(hex(v) for v in EXPECTED_ADD_IMMS)}}}: "
            + ", ".join(f"sub {r},{hex(v)}" for r, v in bad_sub)
            + ", ".join(f"shl {r},{hex(v)}" for r, v in bad_shl)
            + ", ".join(f"add {r},{hex(v)}" for r, v in bad_add)
        )
    else:
        lines.append(
            "    ok: sub/shl/add immediates = "
            + ", ".join(f"sub {r},{hex(v)}" for r, v in sub_imms)
            + ", ".join(f"shl {r},{hex(v)}" for r, v in shl_imms)
            + ", ".join(f"add {r},{hex(v)}" for r, v in add_imms)
        )

    n_sub = sum(1 for (_, v) in sub_imms if v in EXPECTED_SUB_IMMS)
    n_shl = sum(1 for (_, v) in shl_imms if v in EXPECTED_SHL_IMMS)
    n_add140 = sum(1 for (_, v) in add_imms if v == 0x140)
    n_add1 = sum(1 for (_, v) in add_imms if v == 1)
    if min(n_sub, n_shl, n_add140) < MEM_MIN_PROLOGUE_COUNT or n_add1 < 1:
        ok = False
        lines.append(
            f"    FAIL: prologue counts sub 0x18 x{n_sub} shl 4 x{n_shl} "
            f"add 0x140 x{n_add140} add 1 x{n_add1} "
            f"(need >= {MEM_MIN_PROLOGUE_COUNT} and >= 1)"
        )
    else:
        lines.append(
            f"    ok: prologue counts sub 0x18 x{n_sub} shl 4 x{n_shl} "
            f"add 0x140 x{n_add140} add 1 x{n_add1}"
        )

    width_cmps = [(r, v) for (r, v) in cmp_imms if v in MEM_WIDTH_CMP_IMMS]
    if not width_cmps:
        ok = False
        lines.append(
            f"    FAIL: no width-chain cmp with imm in "
            f"{sorted(MEM_WIDTH_CMP_IMMS)} (aux width dispatch missing)"
        )
    else:
        lines.append(f"    ok: width-chain cmp = " + ", ".join(f"{r},{v}" for r, v in width_cmps))

    if movups_ctx < 1:
        ok = False
        lines.append("    FAIL: no movups touching ctx (slot read/write missing)")
    else:
        lines.append(f"    ok: movups ctx count = {movups_ctx}")

    return ok, lines


def check_ymm_handler(name: str, code: bytes, base_va: int, md) -> tuple[bool, list[str]]:
    """Return (ok, evidence) for one MIT-512 ymm data-path word handler."""
    lines: list[str] = []
    ok = True

    sub_imms: list[tuple[str, int]] = []
    shl_imms: list[tuple[str, int]] = []
    add_imms: list[tuple[str, int]] = []
    vmovups_count = 0

    for ins in md.disasm(code, base_va):
        ops = ins.op_str
        if ins.mnemonic in ("sub", "shl", "add"):
            reg = gpr_name(ins, 0)
            if reg is not None and ins.operands[1].type == capstone.x86.X86_OP_IMM:
                immv = parse_imm(str(ins.operands[1].imm))
                if ins.mnemonic == "sub":
                    sub_imms.append((reg, immv))
                elif ins.mnemonic == "shl":
                    shl_imms.append((reg, immv))
                else:
                    add_imms.append((reg, immv))
        if ins.mnemonic == "vmovups" and ops and "ymm" in ops:
            vmovups_count += 1
        if ins.mnemonic in ("vmovaps", "vmovapd", "vmovdqa", "vmovdqu"):
            ok = False
            lines.append(f"    FAIL: aligned ymm access `{ins.mnemonic} {ops}` (vmovups only)")

    bad_sub = [(r, v) for (r, v) in sub_imms if v != 0x300]
    bad_shl = [(r, v) for (r, v) in shl_imms if v != 5]
    bad_add = [(r, v) for (r, v) in add_imms if v not in (0x1C0, 1)]
    if bad_sub or bad_shl or bad_add:
        ok = False
        lines.append(
            "    FAIL: immediates outside expected sets "
            "sub{0x300} shl{5} add{0x1c0,1}: "
            + ", ".join(f"{r},{hex(v)}" for r, v in bad_sub + bad_shl + bad_add)
        )
    else:
        lines.append(
            "    ok: sub/shl/add immediates = "
            + ", ".join(f"{r},{hex(v)}" for r, v in sub_imms + shl_imms + add_imms)
        )
    if not any(v == 0x300 for (_, v) in sub_imms):
        ok = False
        lines.append("    FAIL: ymm stride prologue (sub 0x300) missing")
    if not any(v == 5 for (_, v) in shl_imms):
        ok = False
        lines.append("    FAIL: ymm stride prologue (shl 5) missing")
    n_add1c0 = sum(1 for (_, v) in add_imms if v == 0x1C0)
    n_add1 = sum(1 for (_, v) in add_imms if v == 1)
    if n_add1c0 < 1 or n_add1 < 1:
        ok = False
        lines.append(
            f"    FAIL: prologue counts: add 0x1c0 x{n_add1c0} (<1?) "
            f"or pc advance add 1 x{n_add1} (<1?)"
        )
    else:
        lines.append(f"    ok: prologue add 0x1c0 x{n_add1c0}, add 1 x{n_add1}")
    if vmovups_count < 2:
        ok = False
        lines.append(f"    FAIL: vmovups ymm count {vmovups_count} < 2")
    else:
        lines.append(f"    ok: vmovups ymm count = {vmovups_count}")

    return ok, lines


def check_vzero_handler(name: str, code: bytes, base_va: int, md) -> tuple[bool, list[str]]:
    """Return (ok, evidence) for one MIT-511 vzero ABI word handler."""
    lines: list[str] = []
    ok = True

    vzero_hits: list[str] = []
    pxor_zero = False
    sub_imms: list[tuple[str, int]] = []
    shl_imms: list[tuple[str, int]] = []
    add_imms: list[tuple[str, int]] = []
    movups_count = 0

    for ins in md.disasm(code, base_va):
        ops = ins.op_str
        if ins.mnemonic == name:
            vzero_hits.append(f"{ins.mnemonic} {ops}")
        if ins.mnemonic == "pxor" and ops == "xmm0, xmm0":
            pxor_zero = True
        if ins.mnemonic in ("sub", "shl", "add"):
            reg = gpr_name(ins, 0)
            if reg is not None and ins.operands[1].type == capstone.x86.X86_OP_IMM:
                immv = parse_imm(str(ins.operands[1].imm))
                if ins.mnemonic == "sub":
                    sub_imms.append((reg, immv))
                elif ins.mnemonic == "shl":
                    shl_imms.append((reg, immv))
                else:
                    add_imms.append((reg, immv))
        if ins.mnemonic == "movups" and ops and "xmm" in ops:
            movups_count += 1

    if not vzero_hits:
        ok = False
        lines.append(f"    FAIL: physical `{name}` instruction missing")
    else:
        lines.append(f"    ok: physical `{vzero_hits[0]}` present")
    if not pxor_zero:
        ok = False
        lines.append("    FAIL: `pxor xmm0, xmm0` zero source missing")
    else:
        lines.append("    ok: pxor xmm0, xmm0 zero source present")
    if sub_imms or shl_imms:
        ok = False
        lines.append(
            "    FAIL: immediate-bearing sub/shl in operand-free handler: "
            + ", ".join(f"{r},{hex(v)}" for r, v in sub_imms + shl_imms)
        )
    else:
        lines.append("    ok: no sub/shl immediates (no slot prologue)")
    bad_add = [(r, v) for (r, v) in add_imms if v != 1]
    if bad_add:
        ok = False
        lines.append(
            "    FAIL: add immediates outside {1}: "
            + ", ".join(f"{r},{hex(v)}" for r, v in bad_add)
        )
    else:
        lines.append(
            "    ok: add immediates = "
            + ", ".join(f"{r},{hex(v)}" for r, v in add_imms)
            + ("" if add_imms else "  (none)")
        )
    if not any(v == 1 for (_, v) in add_imms):
        ok = False
        lines.append("    FAIL: pc advance add 1 missing")
    min_movups = 16 if name == "vzeroupper" else 40
    if movups_count < min_movups:
        ok = False
        lines.append(
            f"    FAIL: movups xmm face-store count {movups_count} < {min_movups}"
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
        elif name in MEM_HANDLERS or name in BRIDGE_HANDLERS:
            ok, lines = check_mem_handler(name, code, off, md)
            verdict = "PASS" if ok else "FAIL"
            print(f"  [{verdict}] handler {name} @ +{hex(off)} ({len(code)} bytes, mem-form)")
            for ln in lines:
                print(ln)
            (passed if ok else failed).append(name)
            all_ok = all_ok and ok
        elif name in VZERO_HANDLERS:
            ok, lines = check_vzero_handler(name, code, off, md)
            verdict = "PASS" if ok else "FAIL"
            print(f"  [{verdict}] handler {name} @ +{hex(off)} ({len(code)} bytes, vzero-form)")
            for ln in lines:
                print(ln)
            (passed if ok else failed).append(name)
            all_ok = all_ok and ok
        elif name in YMM_HANDLERS:
            ok, lines = check_ymm_handler(name, code, off, md)
            verdict = "PASS" if ok else "FAIL"
            print(f"  [{verdict}] handler {name} @ +{hex(off)} ({len(code)} bytes, ymm-form)")
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
