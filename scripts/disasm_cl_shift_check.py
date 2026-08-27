#!/usr/bin/env python3
"""
WVmp capstone disassembly verification script (MIT-368).

Disassembles build/passes/marker_scan/tests/wvmp_cl_shift_sample.exe with
capstone and verifies the six MASM helpers emitted by
passes/marker_scan/tests/cl_shift_sample_asm.asm:

  - popcnt32_fn (F3 0F B8 C0)
  - popcnt64_fn (F3 48 0F B8 C0)
  - lzcnt32_fn  (F3 0F BD C1)
  - lzcnt64_fn  (F3 48 0F BD C1)
  - tzcnt32_fn  (F3 0F BC C1)
  - tzcnt64_fn  (F3 48 0F BC C1)

For each helper we check two invariants:

  1. NOP padding >= kStubWindow (=64) bytes immediately before the
     helper's characteristic instruction (covers both the explicit
     `REPEAT 64 nop` block in cl_shift_sample_asm.asm and any extra
     multi-byte alignment NOPs the linker inserts).

  2. The minimum spacing between any two consecutive helper
     characteristic-instruction RVAs is strictly greater than
     kStubWindow (=64).  marker_scan refuses to attribute a call to a
     helper as the marker_begin anchor if the call sits within
     kStubWindow bytes of any helper, so helpers must be >64 apart.

Outputs both a human-readable summary and a JSON dump on stdout.  Exit
codes:

  0 - all checks passed
  1 - at least one check failed (helper missing / spacing / padding)
  2 - tooling error (capstone missing / exe not found / PE parse fail)

Usage:

  scripts/disasm_cl_shift_check.py                 # default paths
  scripts/disasm_cl_shift_check.py --exe <path>    # override exe
  scripts/disasm_cl_shift_check.py --json          # JSON-only output
  scripts/disasm_cl_shift_check.py --repo <path>   # override repo root

Reuses the capstone disassembly logic verified by MIT-358 agent for
pitfall #39 (MASM helpers near marker_begin require 64-NOP padding to
stay clear of kStubWindow=64).
"""

from __future__ import annotations

import argparse
import json
import os
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


KSTUB_WINDOW = 64          # passes/marker_scan/include/wvmp/passes/marker_scan/scan_core.hpp
NOP_PADDING_REQUIRED = 64  # REPEAT 64 nop in cl_shift_sample_asm.asm

# (helper name, characteristic instruction bytes)
# 32-bit forms use F3 0F B8/BD/BC (no REX.W).
# 64-bit forms use F3 48 0F B8/BD/BC (REX.W inserted between prefix
# and opcode; this is the canonical Intel encoding order).
HELPERS = [
    ("popcnt32_fn", bytes.fromhex("F30FB8C0")),
    ("popcnt64_fn", bytes.fromhex("F3480FB8C0")),
    ("lzcnt32_fn",  bytes.fromhex("F30FBDC1")),
    ("lzcnt64_fn",  bytes.fromhex("F3480FBDC1")),
    ("tzcnt32_fn",  bytes.fromhex("F30FBCC1")),
    ("tzcnt64_fn",  bytes.fromhex("F3480FBCC1")),
]


def parse_pe_sections(data: bytes) -> list:
    """Parse PE32+ header and return section descriptors.

    Each entry is a dict with keys: name, vaddr, vsize, raw_off,
    raw_size.  Raises ValueError on any header inconsistency.
    """
    if len(data) < 0x40:
        raise ValueError("file too small for DOS header")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data):
        raise ValueError("PE header offset out of range")
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("PE signature missing")
    coff = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    sec_off = coff + 20 + opt_size
    sections = []
    for i in range(num_sections):
        s = sec_off + i * 40
        name = data[s:s + 8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize = struct.unpack_from("<I", data, s + 8)[0]
        vaddr = struct.unpack_from("<I", data, s + 12)[0]
        raw_size = struct.unpack_from("<I", data, s + 16)[0]
        raw_off = struct.unpack_from("<I", data, s + 20)[0]
        sections.append({
            "name": name,
            "vaddr": vaddr,
            "vsize": vsize,
            "raw_off": raw_off,
            "raw_size": raw_size,
        })
    return sections


def file_off_to_rva(off: int, sections: list) -> int:
    """Translate a file offset to its RVA inside the matching section."""
    for sec in sections:
        if sec["raw_off"] <= off < sec["raw_off"] + sec["raw_size"]:
            return sec["vaddr"] + (off - sec["raw_off"])
    raise ValueError(f"file offset 0x{off:x} not inside any PE section")


def find_helper_offsets(data: bytes, sections: list) -> dict:
    """Locate each helper's characteristic instruction by byte signature.

    Searches only inside the .text section.  Returns dict keyed by
    helper name with value {insn_off, rva, sig_hex, error}.  An entry
    with error set signals that the helper could not be uniquely
    located (missing or ambiguous).
    """
    text_sec = next((s for s in sections if s["name"] == ".text"), None)
    if text_sec is None:
        return {
            name: {"insn_off": None, "rva": None, "sig_hex": sig.hex(),
                   "error": "no .text section"}
            for name, sig in HELPERS
        }
    text_start = text_sec["raw_off"]
    text_end = text_start + text_sec["raw_size"]
    chunk = data[text_start:text_end]
    out = {}
    for name, sig in HELPERS:
        hits = []
        pos = 0
        while True:
            p = chunk.find(sig, pos)
            if p < 0:
                break
            hits.append(text_start + p)
            pos = p + 1
        if len(hits) == 1:
            off = hits[0]
            out[name] = {
                "insn_off": off,
                "rva": file_off_to_rva(off, sections),
                "sig_hex": sig.hex(),
            }
        else:
            out[name] = {
                "insn_off": None,
                "rva": None,
                "sig_hex": sig.hex(),
                "error": f"signature matches {len(hits)} locations "
                         f"(expected exactly 1)",
            }
    return out


def count_nop_padding(disasm_by_off: dict, char_off: int, max_back: int = 4096) -> int:
    """Walk backwards from char_off and count NOP bytes that immediately
    precede the helper.

    Algorithm:
      - Skip any non-NOP instructions (function prologue such as
        `sub rsp, 0x28` / `push rbx`).
      - Once a NOP is hit, keep walking back over NOPs (including
        multi-byte NOPs encoded as a single capstone instruction).
      - Stop as soon as a non-NOP is encountered, or after max_back
        bytes (safety cap to avoid scanning the whole .text).

    `disasm_by_off` is a dict mapping file offset -> CsInsn.

    Returns the total number of NOP bytes preceding the helper.
    """
    addr_list = sorted(disasm_by_off.keys())

    def prev_addr(cur: int):
        # Largest addr strictly less than cur
        lo, hi = 0, len(addr_list) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            if addr_list[mid] < cur:
                lo = mid + 1
            else:
                hi = mid - 1
        return addr_list[hi] if hi >= 0 else None

    # Phase 1: skip non-NOPs (function prologue); remember the first NOP
    first_nop_off = None
    cur = char_off
    while True:
        p = prev_addr(cur)
        if p is None:
            return 0
        ins = disasm_by_off[p]
        if ins.mnemonic == "nop":
            first_nop_off = p
            break
        cur = p

    # Phase 2: walk back over consecutive NOPs (counting bytes)
    # disasm_by_off is keyed by file offset, so cur/p are file offsets
    # and a contiguous instruction is one whose file-end equals the
    # next file-start.
    # Initialize with the first NOP we found in Phase 1 -- Phase 2
    # then walks further back over preceding NOPs.
    first_ins = disasm_by_off[first_nop_off]
    nop_bytes = first_ins.size
    cur = first_nop_off
    scanned = first_ins.size
    while scanned < max_back:
        p = prev_addr(cur)
        if p is None:
            break
        ins = disasm_by_off[p]
        ins_file_end = p + ins.size
        if ins_file_end != cur:
            break
        if ins.mnemonic != "nop":
            break
        nop_bytes += ins.size
        cur = p
        scanned += ins.size
    return nop_bytes


def locate_exe(args: argparse.Namespace) -> str:
    if args.exe:
        return args.exe
    if args.repo:
        repo = args.repo
    else:
        here = os.path.dirname(os.path.abspath(__file__))
        repo = os.path.dirname(here)
    return os.path.join(
        repo, "build", "passes", "marker_scan", "tests",
        "wvmp_cl_shift_sample.exe",
    )


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--exe", help="path to wvmp_cl_shift_sample.exe")
    p.add_argument("--repo", help="path to WVmp repo root "
                                  "(defaults to parent of script dir)")
    p.add_argument("--json", action="store_true",
                   help="emit only JSON on stdout")
    p.add_argument("--quiet", action="store_true",
                   help="suppress human-readable summary")
    args = p.parse_args()

    exe_path = locate_exe(args)
    if not os.path.isfile(exe_path):
        sys.stderr.write(f"[ERROR] exe not found: {exe_path}\n")
        return 2

    with open(exe_path, "rb") as f:
        data = f.read()

    try:
        sections = parse_pe_sections(data)
    except ValueError as exc:
        sys.stderr.write(f"[ERROR] PE parse failed: {exc}\n")
        return 2

    text_sec = next((s for s in sections if s["name"] == ".text"), None)
    if text_sec is None:
        sys.stderr.write("[ERROR] no .text section in PE\n")
        return 2

    # Disassemble .text with capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    text_bytes = data[text_sec["raw_off"]:
                      text_sec["raw_off"] + text_sec["raw_size"]]
    # Note: capstone instruction .address is in our chosen linear
    # address space; we pass vaddr so disasm.address == RVA, which
    # matches file_off_to_rva() output for cross-checks.
    disasm = list(md.disasm(text_bytes, text_sec["vaddr"]))

    found = find_helper_offsets(data, sections)

    # Per-helper NOP padding walk-back.  For the walk-back we need
    # file offsets, so rebuild an address-keyed map keyed on file offset
    # by translating capstone's RVA addresses back through the section.
    disasm_by_off = {}
    for ins in disasm:
        off = ins.address - text_sec["vaddr"] + text_sec["raw_off"]
        disasm_by_off[off] = ins

    helpers_report = []
    for name, _sig in HELPERS:
        info = found[name]
        entry = {"name": name, "sig_hex": info["sig_hex"]}
        if "error" in info:
            entry["found"] = False
            entry["error"] = info["error"]
            helpers_report.append(entry)
            continue
        insn_off = info["insn_off"]
        insn_rva = info["rva"]
        nop_bytes = count_nop_padding(disasm_by_off, insn_off)
        entry.update({
            "found": True,
            "insn_rva": f"0x{insn_rva:x}",
            "insn_rva_dec": insn_rva,
            "nop_padding_bytes": nop_bytes,
            "nop_padding_required": NOP_PADDING_REQUIRED,
            "nop_padding_ok": nop_bytes >= NOP_PADDING_REQUIRED,
        })
        helpers_report.append(entry)

    # Compute spacings between consecutive helpers (sorted by RVA).
    found_helpers = [h for h in helpers_report if h["found"]]
    found_helpers.sort(key=lambda h: h["insn_rva_dec"])
    spacings = []
    min_spacing = None
    for i in range(1, len(found_helpers)):
        prev_rva = found_helpers[i - 1]["insn_rva_dec"]
        cur_rva = found_helpers[i]["insn_rva_dec"]
        delta = cur_rva - prev_rva
        spacings.append({
            "from": found_helpers[i - 1]["name"],
            "to": found_helpers[i]["name"],
            "delta_bytes": delta,
            "delta_hex": f"0x{delta:x}",
        })
        if min_spacing is None or delta < min_spacing:
            min_spacing = delta

    all_found = len(found_helpers) == len(HELPERS)
    all_padding_ok = all(h.get("nop_padding_ok", False)
                         for h in helpers_report if h["found"])
    spacing_ok = (min_spacing is not None and min_spacing > KSTUB_WINDOW)
    overall_ok = all_found and all_padding_ok and spacing_ok

    result = {
        "exe_path": exe_path,
        "exe_size_bytes": len(data),
        "kstub_window": KSTUB_WINDOW,
        "nop_padding_required": NOP_PADDING_REQUIRED,
        "helpers": helpers_report,
        "spacings": spacings,
        "min_spacing_bytes": min_spacing,
        "min_spacing_required_gt": KSTUB_WINDOW,
        "min_spacing_ok": spacing_ok,
        "all_helpers_found": all_found,
        "all_padding_ok": all_padding_ok,
        "overall_ok": overall_ok,
    }

    if args.json:
        print(json.dumps(result, indent=2))
    elif not args.quiet:
        print("=== WVmp capstone disassembly check (MIT-368) ===")
        print(f"exe              : {exe_path}")
        print(f"size             : {len(data)} bytes")
        print(f"kStubWindow      : {KSTUB_WINDOW}")
        print(f"required padding : {NOP_PADDING_REQUIRED}")
        print()
        print("Per-helper:")
        for h in helpers_report:
            if not h["found"]:
                print(f"  [{h['name']}] MISSING ({h.get('error', '?')})")
                continue
            pad_status = "OK" if h["nop_padding_ok"] else "FAIL"
            print(f"  [{h['name']}] RVA={h['insn_rva']} "
                  f"nop_pad={h['nop_padding_bytes']}B "
                  f"(need >={NOP_PADDING_REQUIRED}B) [{pad_status}]")
        print()
        print("Spacings (RVA delta between consecutive helpers):")
        for s in spacings:
            print(f"  {s['from']:14s} -> {s['to']:14s} "
                  f"delta={s['delta_bytes']}B ({s['delta_hex']})")
        if min_spacing is not None:
            spacing_status = "OK" if spacing_ok else "FAIL"
            print(f"  min spacing   = {min_spacing}B "
                  f"(must be > {KSTUB_WINDOW}B) [{spacing_status}]")
        else:
            print("  min spacing   = N/A (fewer than 2 helpers found)")
        print()
        print(f"all helpers found : {all_found}")
        print(f"all padding ok    : {all_padding_ok}")
        print(f"min spacing ok    : {spacing_ok}")
        print(f"OVERALL           : {'PASS' if overall_ok else 'FAIL'}")

    return 0 if overall_ok else 1


if __name__ == "__main__":
    sys.exit(main())
