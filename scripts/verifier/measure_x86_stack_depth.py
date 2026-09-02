#!/usr/bin/env python3
"""MIT-451 (X5b) B.1 — x86 marked-region stack-depth static measurement.

Mirrors the X5b translator stack-walk rules (push/pop net depth + rsp-ALU +
rsp/aliased-base negative-displacement reach + backward-edge growth +
ExitNative/Halt balance) over the marked regions of a PE32 target, and
reports the survival table for:
  (i)  pure stack gate @ budget 0 (no guard pad)
  (v)  guard pad @ N in {128, 256, 512} bytes (32/64/128 dwords)

Marker pairing mirrors marker_scan scan_core.cpp: x86 dual-magic anchors
("WVMP"+"BEG1" / "WVMP"+"END1", either half order, gap <= 8), E8 rel32
attribution (first anchor with magic_off >= target, distance <= 64), and
stack-based region pairing ([begin_next, end_call)).

Usage: python measure_x86_stack_depth.py <pe32.exe> [<pe32.exe> ...] [--json OUT]
"""
import struct
import sys
import json
from collections import Counter

import capstone

HALF_WVMP = b"WVMP"
HALF_BEG = b"BEG1"
HALF_END = b"END1"
MAX_HALF_GAP = 8          # scan_core kX86MaxHalfGap
MAX_BACK = 64             # stub entry to magic distance bound
GUARDS = [128, 256, 512]  # (v) candidates in bytes


def parse_pe32(data):
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[e_lfanew:e_lfanew + 4] == b"PE\0\0", "not a PE file"
    coff = e_lfanew + 4
    machine, nsec = struct.unpack_from("<HH", data, coff)
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    assert machine == 0x14C, f"machine=0x{machine:X} not PE32"
    assert magic == 0x10B, "not PE32 optional header"
    image_base = struct.unpack_from("<I", data, opt + 28)[0]
    secs = []
    so = opt + opt_size
    for i in range(nsec):
        name, vsize, vaddr, rsize, roff = struct.unpack_from(
            "<8sIIII", data, so + i * 40)[:5]
        secs.append({"name": name.rstrip(b"\0").decode(errors="replace"),
                     "vsize": vsize, "vaddr": vaddr,
                     "rsize": rsize, "roff": roff})
    return image_base, secs


def rva_map(secs):
    """RVA -> file offset for mapped sections."""
    m = []
    for s in secs:
        if s["rsize"] == 0:
            continue
        m.append((s["vaddr"], s["vaddr"] + max(s["vsize"], s["rsize"]),
                  s["roff"], s["rsize"]))
    return m


def rva_to_off(m, rva):
    for va, ve, roff, rsize in m:
        if va <= rva < va + rsize:
            return roff + (rva - va)
    return None


def find_anchors(text):
    """-> sorted list of (off, is_begin)."""
    anchors = []
    for half, is_begin in ((HALF_BEG, True), (HALF_END, False)):
        starts = []
        p = text.find(half)
        while p != -1:
            starts.append(p)
            p = text.find(half, p + 1)
        wvmps = []
        p = text.find(HALF_WVMP)
        while p != -1:
            wvmps.append(p)
            p = text.find(HALF_WVMP, p + 1)
        import bisect
        for b in starts:
            # hi->lo direction: BEG1/END1 first, WVMP within [b+4, b+4+gap]
            i = bisect.bisect_left(wvmps, b + 4)
            if i < len(wvmps) and wvmps[i] <= b + 4 + MAX_HALF_GAP:
                anchors.append((b, is_begin))
        for w in wvmps:
            # lo->hi direction: WVMP first
            i = bisect.bisect_left(starts, w + 4)
            if i < len(starts) and starts[i] <= w + 4 + MAX_HALF_GAP:
                anchors.append((w, is_begin))
    anchors.sort()
    return anchors


def find_calls(text):
    calls = []
    for off in range(len(text) - 5):
        if text[off] != 0xE8:
            continue
        rel = struct.unpack_from("<i", text, off + 1)[0]
        target = off + 5 + rel
        if target < 0 or target >= len(text):
            continue
        calls.append((off, target))
    return calls


def pair_regions(text):
    anchors = find_anchors(text)
    magic_offs = [a[0] for a in anchors]
    import bisect
    begins, ends = [], []
    for site, target in find_calls(text):
        i = bisect.bisect_left(magic_offs, target)
        if i >= len(anchors):
            continue
        off, is_begin = anchors[i]
        if off - target > MAX_BACK:
            continue
        (begins if is_begin else ends).append(site)
    begins.sort()
    ends.sort()
    regions, open_stack = [], []
    bi = ei = 0
    while bi < len(begins) or ei < len(ends):
        take_begin = ei >= len(ends) or (bi < len(begins) and begins[bi] <= ends[ei])
        if take_begin:
            open_stack.append(begins[bi] + 5)  # begin_next = after the call
            bi += 1
        else:
            e = ends[ei]
            ei += 1
            if open_stack:
                regions.append((open_stack.pop(), e))
            else:
                regions.append((None, e))
    regions.sort()
    return regions


ALIASABLE = {"eax", "ecx", "edx", "ebx", "ebp", "esi", "edi"}
CALLER_SAVED = {"eax", "ecx", "edx"}


def walk_region(text, start, end):
    """Mirror of the X5b translator stack walk. Returns stats dict."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    st = {
        "max_d": 0, "max_reach": 0, "violations": [], "insns": 0,
        "pushes": 0, "pops": 0, "sub_esp_max": 0,
        "reaches": [], "net_end": None,
    }
    d = 0
    alias = {}
    d_at = {}
    last_term = None
    try:
        insns = []
        pos = start
        end_pos = end
        while pos < end_pos:
            got = list(md.disasm(text[pos:end_pos], pos))
            if not got:
                pos += 1
                continue
            insns.extend(got)
            nxt = got[-1].address + got[-1].size
            if nxt <= pos:
                pos += 1
            else:
                pos = nxt
    except Exception:
        insns = []
    if len(insns) == 0:
        st["violations"].append("disasm-empty")
        return st
    for insn in insns:
        st["insns"] += 1
        d_at[insn.address] = d
        m, ops = insn.mnemonic, insn.op_str
        parts = ops.split(",") if ops else []
        dst = parts[0].strip() if parts else ""
        src = parts[1].strip() if len(parts) > 1 else ""

        def reg_name(tok):
            tok = tok.strip().lower()
            return tok if tok in ALIASABLE else None

        def mem_of(tok):
            # parse '[base + index*scale + disp]' for base + negative disp
            if "[" not in tok:
                return None
            inner = tok[tok.index("[") + 1:tok.rindex("]")].replace(" ", "")
            base = None
            disp = 0
            # tokenize on +/- keeping signs
            import re
            for tok2 in re.findall(r"[+-]?[^+-]+", inner):
                neg = tok2.startswith("-")
                t = tok2.lstrip("+-")
                if t in ("eax", "ebx", "ecx", "edx", "ebp", "esi", "edi", "esp"):
                    base = base or t
                else:
                    try:
                        v = int(t, 0)
                        disp += -v if neg else v
                    except ValueError:
                        pass
            return base, disp

        def reach_check(mem, sz):
            nonlocal d
            if mem is None:
                return
            base, disp = mem
            if disp >= 0:
                return
            off = 0
            if base == "esp":
                off = d
            elif base in alias:
                off = d - alias[base]
            else:
                return  # value-unknown base: disclosed compromise
            reach = off + (-disp) + sz
            st["max_reach"] = max(st["max_reach"], reach)
            st["reaches"].append((hex(insn.address), base, hex(disp), reach))

        if m == "push":
            st["pushes"] += 1
            d += 4
            st["max_d"] = max(st["max_d"], d)
            alias.pop(reg_name(dst) or "", None) if False else None
        elif m == "pop":
            st["pops"] += 1
            d -= 4
            r = reg_name(dst)
            if r:
                alias.pop(r, None)
        elif m in ("sub", "add") and dst == "esp":
            try:
                v = int(src, 16) if src.startswith("0x") else int(src)
            except ValueError:
                st["violations"].append(f"esp-arith-nonimm@{insn.address:#x}")
                v = 0
            d += v if m == "sub" else -v
            st["max_d"] = max(st["max_d"], d)
            if m == "sub":
                st["sub_esp_max"] = max(st["sub_esp_max"], v)
        elif m == "mov" and dst == "esp":
            r = reg_name(src)
            if src == "esp":
                pass  # self-move: no-op
            elif r and r in alias:
                d = alias[r]  # esp := frame reg (leave idiom head)
            else:
                st["violations"].append(f"esp-absolute@{insn.address:#x}")
        elif m == "lea" and dst == "esp":
            mem = mem_of(src)
            if mem and mem[0] == "esp":
                d += -mem[1] if mem[1] < 0 else -mem[1]  # disp added below
                d = d  # disp semantics: esp := esp + disp
                # recompute: base esp disp disp → new d = d - disp
                # (handled below properly)
            else:
                st["violations"].append(f"esp-lea-unknown@{insn.address:#x}")
        elif m == "leave":
            off = alias.get("ebp")
            if off is not None:
                d = d - off + 4  # esp := ebp; pop ebp
            else:
                d += 4  # conservative: ebp unknown, only pop accounted
            alias.pop("ebp", None)
        # mem reach checks (load/store/lea/alu)
        sz = insn.size if m in ("push",) else max(1, insn.size // max(1, len(parts)))
        if m in ("mov", "movzx", "movsx", "lea", "add", "sub", "and", "or",
                 "xor", "cmp", "test", "adc", "sbb", "inc", "dec", "neg",
                 "not", "xadd", "bts", "btr", "btc", "xchg", "cmpxchg"):
            for tok in parts:
                if "[" in tok:
                    mem = mem_of(tok)
                    # approximate access width by the other operand / mnemonic
                    reach_check(mem, 4)
        # alias updates
        r = reg_name(dst)
        if m == "mov" and r:
            if src == "esp":
                alias[r] = 0
            else:
                alias.pop(r, None)
        elif m == "lea" and r:
            mem = mem_of(src)
            if mem and mem[0] == "esp" and mem[1] >= 0:
                alias[r] = -mem[1]
            elif mem and mem[0] == "esp":
                alias[r] = -mem[1]
            else:
                alias.pop(r, None)
        elif m in ("add", "sub") and r and r in alias:
            try:
                v = int(src, 16) if src.startswith("0x") else int(src)
                alias[r] += -v if m == "add" else v
            except ValueError:
                alias.pop(r, None)
        elif r and m in ("imul", "shl", "shr", "sar", "not", "neg", "mul",
                         "div", "idiv", "bswap", "sete", "setne", "cwde", "cdq"):
            alias.pop(r, None)
        if m in ("call",):
            for rr in CALLER_SAVED:
                alias.pop(rr, None)
        # backward edge growth check
        if m in ("jmp",) or m.startswith("j"):
            try:
                t = int(src, 16) if src.startswith("0x") else int(src)
            except (ValueError, IndexError):
                t = None
            if t is not None and start <= t < end:
                if t < insn.address and t in d_at and d > d_at[t]:
                    st["violations"].append(
                        f"backward-growth@{insn.address:#x}(d={d},tgt={d_at[t]})")
            elif t is not None and (t < start or t >= end):
                if d != 0:
                    st["violations"].append(
                        f"exit-native-unbalanced@{insn.address:#x}(d={d})")
        if m in ("ret", "jmp", "retf"):
            last_term = m
        elif m.startswith("j"):
            last_term = None  # conditional: may fall through
        else:
            last_term = None
    st["net_end"] = d
    if last_term not in ("ret", "jmp"):
        if d != 0:
            st["violations"].append(f"halt-unbalanced(d={d})")
    return st


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    all_regions = []
    for path in args:
        data = open(path, "rb").read()
        image_base, secs = parse_pe32(data)
        text = next(s for s in secs if s["name"] == ".text")
        m = rva_map(secs)
        body = data[text["roff"]:text["roff"] + text["rsize"]]
        regions = pair_regions(body)
        for (s, e) in regions:
            if s is None:
                continue
            # zero/near-zero padding pair artifact: >=90% of bytes are 0x00
            chunk = body[s:min(e, s + 0x400)]
            if chunk and chunk.count(0) >= 0.9 * len(chunk):
                continue
            st = walk_region(body, s, e)
            st["file"] = path.split("\\")[-1].split("/")[-1]
            st["rva"] = f"{image_base + text['vaddr'] + s:#x}"
            all_regions.append(st)
    n = len(all_regions)
    print(f"regions paired: {n}")
    if n == 0:
        return
    nets = sorted(r["max_d"] for r in all_regions)
    reaches = sorted(r["max_reach"] for r in all_regions)
    bad = [r for r in all_regions if r["violations"]]
    print(f"max net depth  : p50={nets[n//2]} p90={nets[int(n*0.9)]} "
          f"p99={nets[min(n-1, int(n*0.99))]} max={nets[-1]}")
    print(f"max reach      : p50={reaches[n//2]} p90={reaches[int(n*0.9)]} "
          f"p99={reaches[min(n-1, int(n*0.99))]} max={reaches[-1]}")
    viol_names = Counter(v.split("@")[0] for r in bad for v in r["violations"])
    print(f"regions with structural violations: {len(bad)} {dict(viol_names)}")
    print()
    print(f"{'budget':>8} {'survive':>8} {'rate':>7}")
    print(f"{'(i)@0':>8} {sum(1 for r in all_regions if r['max_d'] == 0 and r['max_reach'] == 0 and not r['violations']):>8} "
          f"{sum(1 for r in all_regions if r['max_d'] == 0 and r['max_reach'] == 0 and not r['violations']) / n:>6.1%}")
    for g in GUARDS:
        ok = sum(1 for r in all_regions
                 if r["max_d"] <= g and r["max_reach"] <= g and not r["violations"])
        print(f"{'(v)@'+str(g):>8} {ok:>8} {ok / n:>6.1%}")
    print()
    nz = [r for r in all_regions if r["max_d"] > 0 or r["max_reach"] > 0 or r["violations"]]
    print(f"regions with any below-ns activity: {len(nz)}")
    for r in sorted(nz, key=lambda r: -r["max_d"])[:40]:
        print(f"  {r['file']:<28} {r['rva']} net={r['max_d']:<4} reach={r['max_reach']:<4} "
              f"pushes={r['pushes']:<3} viol={r['violations'][:2]}")


if __name__ == "__main__":
    main()
