#!/usr/bin/env python3
# MIT-X5cr (MIT-452) 离线 triage 脚本 —— 纯只读分析，零产品代码。
#
# 目的（issue §B.1/B.2）：
#   1. 复刻 marker_scan 区域表（x64 8B magic / x86 双段 magic + E8 归因 +
#      栈配对，逐算法对应 scan_core.cpp / marker_scan_pass.cpp），拿到每个
#      FunctionRegion 的 [begin_rva, end_rva)。
#   2. capstone 反汇编两类站点：x86 protect log 的 17 处
#      "跳转目标块未找到"（rva=0x…）与 x64 log 的 17 处 "exit-native @"，
#      逐处走查 translator.cpp translate_jump 的 ExitNative 判定链五条件：
#      A) op ∈ {Jmp, Jcc} 且目标 Imm
#      B) upper_bound_of_ 可用
#      C) target >= end_rva_（越出本区域）
#      D) upper.has_value() 且 target < upper（.pdata 函数尾界；x86 无
#         .pdata → 恒 nullopt）
#      E) fits_aux(target)
#   3. 双 arch 站点语义配对（区域序 + 区内序），裁决 "17 vs 17 是否同一批
#      源级跳转"。
#   4. 目标落点分型：区内未 lift / 区间 gap（本函数尾）/ 越入其他区域 /
#      越过下一区域 begin，并给出替代上界策略 P1/P2 的预期翻正数。
#
# 用法：
#   python mit_x5cr_jtbn_triage.py --pe-x86 <x86 exe> --log-x86 <log> \
#                                  --pe-x64 <x64 exe> --log-x64 <log> \
#                                  [--out <report.txt>]
#
# 依赖：capstone（C:/Python314 已装 5.0.7）。标准库外无其他依赖。

import argparse
import re
import struct
import sys

try:
    import capstone
except ImportError:
    sys.exit("capstone 未安装（需要 C:/Python314/python.exe）")

# ---- 与 scan_core.hpp 同步的常量（MagicSync 护栏同源） ----
BEGIN_MAGIC = b"WVMPBEG1"
END_MAGIC = b"WVMPEND1"
X86_MAX_HALF_GAP = 8   # kX86MaxHalfGap
STUB_WINDOW = 64       # kStubWindow

JCC_COND = {  # ir::Cond 枚举序 = jcc opcode 低 4 位序（insn.hpp:258）
    "jo": 0, "jno": 1, "jb": 2, "jae": 3, "je": 4, "jne": 5, "jbe": 6,
    "ja": 7, "js": 8, "jns": 9, "jp": 10, "jnp": 11, "jl": 12, "jge": 13,
    "jle": 14, "jg": 15,
}
COND_NAME = {v: k for k, v in JCC_COND.items()}


# ---------------------------------------------------------------- PE 解析 --
class Pe:
    """最小 PE 解析：节表 / DataDirectory[3] / RVA↔offset。只读。"""

    def __init__(self, path):
        with open(path, "rb") as f:
            self.image = f.read()
        img = self.image
        lfanew = struct.unpack_from("<I", img, 0x3C)[0]
        if img[lfanew:lfanew + 4] != b"PE\0\0":
            sys.exit(f"{path}: 非 PE")
        self.machine = struct.unpack_from("<H", img, lfanew + 4)[0]
        num_sec = struct.unpack_from("<H", img, lfanew + 6)[0]
        opt_size = struct.unpack_from("<H", img, lfanew + 20)[0]
        opt = lfanew + 24
        magic = struct.unpack_from("<H", img, opt)[0]
        self.plus = magic == 0x20B
        ddir = opt + (112 if self.plus else 96)   # DataDirectory 起点
        # DataDirectory[3] = Exception Directory（.pdata；x86 恒 0/0）
        self.pdata_rva, self.pdata_size = struct.unpack_from("<II", img, ddir + 3 * 8)
        self.sections = []
        sec = opt + opt_size
        for i in range(num_sec):
            sh = sec + i * 40
            name = img[sh:sh + 8].rstrip(b"\0").decode("ascii", "replace")
            vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", img, sh + 8)
            chars = struct.unpack_from("<I", img, sh + 36)[0]
            self.sections.append((name, va, vsize, raw_ptr, raw_size, chars))

    @property
    def is_x86(self):
        return self.machine == 0x014C

    def rva_to_offset(self, rva):
        for name, va, vsize, raw_ptr, raw_size, chars in self.sections:
            if va <= rva < va + max(vsize, raw_size):
                off = rva - va + raw_ptr
                if raw_ptr <= off < raw_ptr + raw_size:
                    return off
                return None  # 落节虚拟尾（未初始化）
        return None

    def offset_to_rva(self, off):
        for name, va, vsize, raw_ptr, raw_size, chars in self.sections:
            if raw_ptr <= off < raw_ptr + raw_size:
                return off - raw_ptr + va
        return None

    def exec_ranges(self):
        """marker_scan_pass.cpp executable_ranges 同判据。"""
        out = []
        for name, va, vsize, raw_ptr, raw_size, chars in self.sections:
            if chars & 0x2000_0020 and raw_ptr and raw_size:  # CNT_CODE|MEM_EXECUTE
                out.append((raw_ptr, min(raw_ptr + raw_size, len(self.image))))
        return out

    # ---- .pdata RUNTIME_FUNCTION 表（pe_image.cpp:139-170 同解析） ----
    def pdata_table(self):
        if self.pdata_rva == 0 or self.pdata_size < 12:
            return None  # pdata_empty 语义
        table = []
        for i in range(self.pdata_size // 12):
            off = self.rva_to_offset(self.pdata_rva + i * 12)
            if off is None:
                return None
            b, e, u = struct.unpack_from("<III", self.image, off)
            if e <= b:
                return None
            table.append((b, e, u))
        for i in range(1, len(table)):
            if table[i][0] < table[i - 1][0]:
                return None
        return table

    def find_function_end_rva(self, begin_rva):
        """PeImage::find_function_end_rva 同二分语义。"""
        table = self.pdata_table()
        if not table:
            return None
        lo, hi = 0, len(table)
        while lo < hi:
            mid = (lo + hi) // 2
            if table[mid][0] <= begin_rva:
                lo = mid + 1
            else:
                hi = mid
        if lo == 0:
            return None
        b, e, _ = table[lo - 1]
        return e if b <= begin_rva < e else None


# -------------------------------------------------------- marker_scan 复刻 --
def find_all(hay, needle):
    hits, last = [], len(hay) - len(needle)
    i = 0
    while i <= last:
        if hay[i:i + len(needle)] == needle:
            hits.append(i)
        i += 1
    return hits


def find_all_x86(hay, magic8):
    """scan_core.cpp find_all_x86：双段共现（lo→hi 与 hi→lo 两方向）。"""
    lo_m, hi_m = magic8[:4], magic8[4:]
    lo_hits, hi_hits = find_all(hay, lo_m), find_all(hay, hi_m)
    hits, second_last = [], 4 + X86_MAX_HALF_GAP
    for lo in lo_hits:
        for hi in hi_hits:
            if hi > lo + second_last:
                break
            if hi >= lo + 4:
                hits.append(lo)
                break
    for hi in hi_hits:
        for lo in lo_hits:
            if lo > hi + second_last:
                break
            if lo >= hi + 4:
                hits.append(hi)
                break
    return sorted(hits)


def scan_calls(code, base_off):
    """scan_core.cpp scan_calls：字节枚举 E8 rel32。"""
    calls = []
    for off in range(len(code) - 4):
        if code[off] != 0xE8:
            continue
        rel = struct.unpack_from("<i", code, off + 1)[0]
        next_abs = base_off + off + 5
        target = next_abs + rel
        if target < 0:
            continue
        calls.append((base_off + off, base_off + off + 5, target))
    return calls


def marker_regions(img, is_x86):
    """marker_scan_pass.cpp run() 步骤 1-4 复刻 → [(begin_off, end_off)]。"""
    bh = find_all_x86(img, BEGIN_MAGIC) if is_x86 else find_all(img, BEGIN_MAGIC)
    eh = find_all_x86(img, END_MAGIC) if is_x86 else find_all(img, END_MAGIC)
    anchors = sorted([(o, True) for o in bh] + [(o, False) for o in eh])
    calls = []
    for lo, hi in exec_ranges_of(img):
        calls.extend(scan_calls(img[lo:hi], lo))
    calls.sort(key=lambda c: c[0])
    magic_offs = [a[0] for a in anchors]
    begin_nexts, end_addrs = [], []
    for insn_off, next_off, target_off in calls:
        # attribute_marker_calls：第一个 magic_off >= target 的锚
        import bisect
        idx = bisect.bisect_left(magic_offs, target_off)
        if idx == len(magic_offs):
            continue
        if magic_offs[idx] - target_off > STUB_WINDOW:
            continue
        if anchors[idx][1]:
            begin_nexts.append(next_off)
        else:
            end_addrs.append(insn_off)
    begin_nexts, end_addrs = sorted(set(begin_nexts)), sorted(set(end_addrs))
    # pair_regions：栈配对
    regions, open_stack = [], []
    bi = ei = 0
    while bi < len(begin_nexts) or ei < len(end_addrs):
        take_begin = ei >= len(end_addrs) or (
            bi < len(begin_nexts) and begin_nexts[bi] <= end_addrs[ei])
        if take_begin:
            open_stack.append(begin_nexts[bi])
            bi += 1
        else:
            if open_stack:
                regions.append((open_stack.pop(), end_addrs[ei]))
            ei += 1
    return sorted(regions)


def exec_ranges_of(img):
    """独立于 Pe 类的字节级 exec 节范围（marker_scan_pass 同判据）。"""
    lfanew = struct.unpack_from("<I", img, 0x3C)[0]
    num_sec = struct.unpack_from("<H", img, lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", img, lfanew + 20)[0]
    sec = lfanew + 24 + opt_size
    out = []
    for i in range(num_sec):
        sh = sec + i * 40
        raw_size, raw_ptr = struct.unpack_from("<II", img, sh + 16)
        chars = struct.unpack_from("<I", img, sh + 36)[0]
        if chars & 0x2000_0020 and raw_ptr and raw_size:
            out.append((raw_ptr, min(raw_ptr + raw_size, len(img))))
    return out or [(0, len(img))]


# ------------------------------------------------------------- capstone ----
class Disasm:
    def __init__(self, pe):
        mode = capstone.CS_MODE_32 if pe.is_x86 else capstone.CS_MODE_64
        self.md = capstone.Cs(capstone.CS_ARCH_X86, mode)
        self.md.detail = True
        self.pe = pe

    def at(self, rva, count=1):
        off = self.pe.rva_to_offset(rva)
        if off is None:
            return []
        code = self.pe.image[off:off + 16 * count]
        return list(self.md.disasm(code, rva, count=count))


# ------------------------------------------------------------ 日志解析 ----
def parse_x86_log(path):
    sites = []
    pat = re.compile(
        r"函数 \(marker@0x([0-9a-fA-F]+)\).*?跳转目标块未找到.*?rva=0x([0-9a-fA-F]+)")
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = pat.search(line)
            if m:
                sites.append((int(m.group(1), 16), int(m.group(2), 16)))
    return sites


def parse_x64_log(path):
    sites = []
    pat = re.compile(r"exit-native @ 0x([0-9a-fA-F]+) -> 0x([0-9a-fA-F]+)")
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = pat.search(line)
            if m:
                sites.append((int(m.group(1), 16), int(m.group(2), 16)))
    return sites


# ------------------------------------------------------------- 主流程 ------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pe-x86", required=True)
    ap.add_argument("--log-x86", required=True)
    ap.add_argument("--pe-x64", required=True)
    ap.add_argument("--log-x64", required=True)
    ap.add_argument("--out")
    args = ap.parse_args()

    pe86, pe64 = Pe(args.pe_x86), Pe(args.pe_x64)
    dis86, dis64 = Disasm(pe86), Disasm(pe64)
    regions86 = marker_regions(pe86.image, pe86.is_x86)
    regions64 = marker_regions(pe64.image, pe64.is_x86)

    out = []
    say = out.append
    say(f"x86 machine=0x{pe86.machine:04X} pdata_rva=0x{pe86.pdata_rva:X} "
        f"pdata_size=0x{pe86.pdata_size:X} regions={len(regions86)}")
    say(f"x64 machine=0x{pe64.machine:04X} pdata_rva=0x{pe64.pdata_rva:X} "
        f"pdata_size=0x{pe64.pdata_size:X} regions={len(regions64)}")

    def region_table(pe, regions, tag):
        say(f"\n== 区域表 [{tag}]（marker@hex=begin 文件偏移, 与日志命名一致）==")
        for b_off, e_off in regions:
            b_rva, e_rva = pe.offset_to_rva(b_off), pe.offset_to_rva(e_off)
            say(f"  marker@0x{b_off:x}  begin_rva=0x{b_rva:x}  end_rva=0x{e_rva:x}  "
                f"size=0x{e_rva - b_rva:x}")

    region_table(pe86, regions86, "x86")
    region_table(pe64, regions64, "x64")

    # 统一换算到 RVA 空间（site/target/upper 全是 RVA；文件偏移只用于命名）
    def regions_rva(pe, regions):
        return [(b, pe.offset_to_rva(b), pe.offset_to_rva(e))
                for b, e in regions]

    reg86, reg64 = regions_rva(pe86, regions86), regions_rva(pe64, regions64)

    def find_region(regs, rva):
        for i, (_, b, e) in enumerate(regs):
            if b <= rva < e:
                return i
        return None

    def next_begin_after(regs, b_rva):
        nexts = [b for _, b, _ in regs if b > b_rva]
        return min(nexts) if nexts else None

    def jtbn_chain(pe, dis, regs, marker_off, site_rva, site_target=None):
        """逐条件走查 translate_jump（translator.cpp:1629-1672）。"""
        i = find_region(regs, site_rva)
        insns = dis.at(site_rva)
        if i is None or not insns:
            return {"err": f"site 0x{site_rva:x} 不在任何区域/不可反汇编"}
        insn = insns[0]
        mne = insn.mnemonic
        # 目标：capstone imm 操作数（rel → 绝对已由 capstone 完成）
        target = None
        if insn.operands and insn.operands[0].type == capstone.x86.X86_OP_IMM:
            target = insn.operands[0].imm & 0xFFFFFFFFFFFFFFFF
        if site_target is not None and target is not None and site_target != target:
            return {"err": f"目标与日志不符 site=0x{target:x} log=0x{site_target:x}"}
        _, b_rva, e_rva = regs[i]
        cond = JCC_COND.get(mne)
        condA = mne in ("jmp",) or cond is not None
        condB = True  # std::function 非空（backend 恒传入 lambda）
        condC = target is not None and target >= e_rva
        if pe.is_x86:
            upper = None  # pdata_empty → lambda 恒 nullopt（backend.cpp:98）
        else:
            upper = pe.find_function_end_rva(b_rva)
        condD = upper is not None and target is not None and target < upper
        condE = target is not None and 0 <= target <= 0xFFFFFFFF
        emit = condA and condB and condC and condD and condE
        # 目标落点分型（全部 RVA 域）
        if target is None:
            where = "非直接目标"
        elif target < b_rva:
            where = "区域前代码（回跳）"
        elif target < e_rva:
            where = "区内未 lift（无块首）"
        else:
            j = find_region(regs, target)
            nb = next_begin_after(regs, b_rva)
            if j is not None and j != i:
                where = f"越入其他区域 idx={j} (marker@0x{regs[j][0]:x})"
            elif nb is not None and target >= nb:
                where = f"越过下一区域 begin 0x{nb:x}"
            else:
                hi = f"0x{nb:x}" if nb is not None else "EOB"
                where = f"本函数尾 gap [0x{e_rva:x}, {hi})"
        return {"site": site_rva, "marker": f"0x{marker_off:x}", "idx": i,
                "insn": f"{mne} {insn.op_str}", "bytes": insn.bytes.hex(),
                "cond": cond, "target": target, "begin": b_rva, "end": e_rva,
                "A": condA, "B": condB, "C": condC, "D": condD, "E": condE,
                "upper": upper, "emit": emit, "where": where}

    say("\n== x86 17 处 skip 逐处判定链 ==（C=target≥end_rva, D=upper 界, "
        "E=fits_aux; 全真才 emit ExitNative）")
    x86_sites = parse_x86_log(args.log_x86)
    x86_res = []
    for marker_off, site_rva in x86_sites:
        r = jtbn_chain(pe86, dis86, reg86, marker_off, site_rva)
        x86_res.append(r)
        if "err" in r:
            say(f"  site 0x{site_rva:x} marker@0x{marker_off:x}: ERR {r['err']}")
            continue
        fail = [k for k in "ABCDE" if not r[k]]
        say(f"  site 0x{r['site']:x} marker@{r['marker']} idx={r['idx']} "
            f"[{r['insn']}] tgt=0x{r['target']:x} end=0x{r['end']:x} "
            f"upper={'None' if r['upper'] is None else hex(r['upper'])} "
            f"fail={fail or 'none'} emit={r['emit']} 落点={r['where']}")

    say("\n== x64 17 处 exit-native 复核（模型应全部 emit=True）==")
    x64_sites = parse_x64_log(args.log_x64)
    x64_res = []
    for site_rva, tgt in x64_sites:
        r = jtbn_chain(pe64, dis64, reg64, 0, site_rva, site_target=tgt)
        x64_res.append(r)
        if "err" in r:
            say(f"  site 0x{site_rva:x}: ERR {r['err']}")
            continue
        say(f"  site 0x{r['site']:x} idx={r['idx']} [{r['insn']}] "
            f"tgt=0x{r['target']:x} end=0x{r['end']:x} "
            f"upper={'None' if r['upper'] is None else hex(r['upper'])} "
            f"emit={r['emit']} 落点={r['where']}")

    # ---- 双 arch 语义配对（区域序 + 区内序） ----
    say("\n== 双 arch 站点配对（同序号 = 同一 marker 区域内第 j 处跳转）==")
    from collections import defaultdict
    by_region_x = defaultdict(list)
    for r in x86_res:
        if "err" not in r:
            by_region_x[r["idx"]].append(r)
    by_region_64 = defaultdict(list)
    for r in x64_res:
        if "err" not in r:
            by_region_64[r["idx"]].append(r)
    paired = mismatch = 0
    for idx in sorted(set(by_region_x) | set(by_region_64)):
        sx = sorted(by_region_x.get(idx, []), key=lambda r: r["site"])
        s6 = sorted(by_region_64.get(idx, []), key=lambda r: r["site"])
        say(f"  区域 idx={idx}: x86 sites={len(sx)} x64 sites={len(s6)}")
        for j in range(max(len(sx), len(s6))):
            rx = sx[j] if j < len(sx) else None
            r6 = s6[j] if j < len(s6) else None
            if rx and r6:
                op_x = rx["insn"].split()[0]
                op_6 = r6["insn"].split()[0]
                same_op = (op_x == op_6) or (op_x in JCC_COND and op_6 in JCC_COND)
                paired += 1
                if not same_op:
                    mismatch += 1
                say(f"    j={j}: x86 [{rx['insn']}] tgt=0x{rx['target']:x} "
                    f"vs x64 [{r6['insn']}] tgt=0x{r6['target']:x} "
                    f"op匹配={same_op}")
            else:
                say(f"    j={j}: x86={'—' if not rx else hex(rx['site'])} "
                    f"x64={'—' if not r6 else hex(r6['site'])} (不对称)")
    say(f"  配对合计={paired} 操作码不匹配={mismatch}")

    # ---- gap 内容抽样（证明目标 = end 桩 call + 尾声，非第三函数代码）----
    say("\n== gap 内容抽样（x86 idx=0 / idx=13）==")
    for idx in (0, 13):
        _, b, e = reg86[idx]
        nb = next_begin_after(reg86, b)
        hi = nb if nb is not None else e + 0x40
        off = pe86.rva_to_offset(e)
        insns = list(dis86.md.disasm(pe86.image[off:off + (hi - e)], e))
        say(f"  区域 idx={idx} gap [0x{e:x}, 0x{hi:x}):")
        for ci in insns[:8]:
            say(f"    0x{ci.address:x}: {ci.bytes.hex():<14} {ci.mnemonic} {ci.op_str}")

    # ---- lifter back_jump_reaches_region 复刻（lifter_core.cpp:34-100 同语义）----
    def backjump_reaches_region(dis, own, target):
        """BFS ≤3 层 / 256 预算；达 own [begin,end) → True。"""
        _, b, e = own
        queue, visited = [(target, 0)], set()
        budget = 256
        while queue:
            addr, layer = queue.pop(0)
            if layer > 3:
                continue
            if b <= addr < e:
                return True
            if addr in visited:
                continue
            visited.add(addr)
            if budget == 0:
                break
            budget -= 1
            off = dis.pe.rva_to_offset(addr)
            if off is None:
                continue
            insns = list(dis.md.disasm(dis.pe.image[off:off + 16], addr, count=1))
            if not insns:
                continue
            ci = insns[0]
            nxt = ci.address + ci.size
            groups = {ci.group(g) for g in range(len(ci.groups))}
            is_ret = capstone.x86.X86_GRP_RET in groups
            is_jump = capstone.x86.X86_GRP_JUMP in groups
            imm = None
            if (is_jump or is_ret) and ci.operands and \
                    ci.operands[0].type == capstone.x86.X86_OP_IMM:
                imm = ci.operands[0].imm & 0xFFFFFFFFFFFFFFFF
            if is_ret:
                continue
            if capstone.x86.X86_GRP_JUMP in groups and not ci.mnemonic.startswith("j"):
                is_jump = False  # loop/jrcxz 等保守按条件分支处理
            if is_jump and imm is not None and not ci.mnemonic.startswith("j"):
                pass
            if ci.mnemonic == "jmp" and imm is not None:
                queue.append((imm, layer + 1))
                continue
            if is_jump:  # 条件分支：跟目标 + fallthrough 两条边（保守）
                if imm is not None:
                    queue.append((imm, layer + 1))
                queue.append((nxt, layer + 1))
                continue
            queue.append((nxt, layer + 1))  # 非跳转：fallthrough
        return False

    say("\n== back-jump 回跳检出复核（fix 后 exit_native_blocked 干扰排查）==")
    blocked = 0
    for r in x86_res:
        if "err" in r:
            continue
        _, b, e = reg86[r["idx"]]
        own = (r["marker"], b, e)
        bj = backjump_reaches_region(dis86, own, r["target"])
        r["backjump"] = bj
        blocked += bj
        say(f"  site 0x{r['site']:x} tgt=0x{r['target']:x} backjump={bj}")
    say(f"  backjump 命中 {blocked}/17（0 = fix 后无 exit_native_blocked 干扰）")

    # ---- 替代上界策略预期翻正 ----
    say("\n== 替代上界策略翻正预估（x86 17 处）==")
    text_end = max(va + max(vs, rs) for _, va, vs, _, rs, _ in pe86.sections)
    for policy in ("P1: upper=下一区域 begin", "P2: upper=.text 节尾+目标不入任何区域"):
        flipped = 0
        for r in x86_res:
            if "err" in r or not (r["A"] and r["B"] and r["C"] and r["E"]):
                continue
            t, b_rva = r["target"], r["begin"]
            if policy.startswith("P1"):
                ub = next_begin_after(reg86, b_rva)
            else:
                ub = text_end
            # 两策略同附加守卫：目标不得落入任何其他区域（防 ExitNative 落
            # 进将被 stub 覆写的区域体）
            j = find_region(reg86, t)
            guard = j is None or j == r["idx"]
            if ub is not None and t < ub and guard:
                flipped += 1
        say(f"  {policy}: 翻正 {flipped}/17")

    text = "\n".join(out)
    print(text)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")


if __name__ == "__main__":
    main()
