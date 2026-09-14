#!/usr/bin/env python3
"""MIT-517 (T69) AVX 真实 codegen 词流频率画像 — capstone 分类统计。

用法: python profile_avx.py <exe1> [exe2 ...]
对每个 PE 的 .text 做线性反汇编，分类统计：
  VEX256  = ymm 操作数的 VEX 指令（AVX-256 词面）
  VEX128  = xmm 操作数的 VEX 指令（VEX.128 词面）
  LEGACY_SSE = 非 VEX 的 xmm 指令（legacy SSE 编码——混排判据的 SSE 域）
  VZERO   = vzeroupper/vzeroall
  BRIDGE  = vextractf128/vextracti128/vinsertf128/vinserti128
  混排切换 = 相邻"有效 SIMD 指令"（ymm 域 ↔ xmm legacy 域）的域翻转次数
             （每次翻转 = 一处 AVX↔SSE 过渡 + 本保护器混排 gate 的潜在翻面成本）
"""
import struct
import sys
import re
import capstone

YMM_RE = re.compile(r"\bymm\b")
XMM_RE = re.compile(r"\bxmm\b")
LEGACY_SSE_OPS = {
    0x0F,   # movups/movss 家族经由 opcode 判据不可靠 — 用 mnemonic 前缀判据
}
VEX = {0xC4, 0xC5}


def classify(ins):
    mn = ins.mnemonic
    ops = ins.op_str
    is_vex = bytes(ins.bytes)[0] in VEX
    has_ymm = "ymm" in ops or "ymm" in mn
    has_xmm = "xmm" in ops or "xmm" in mn
    if mn in ("vzeroupper", "vzeroall"):
        return "VZERO"
    if mn.startswith(("vextractf128", "vextracti128", "vinsertf128", "vinserti128")):
        return "BRIDGE"
    if is_vex:
        return "VEX256" if has_ymm else ("VEX128" if has_xmm else "VEX_OTHER")
    if has_xmm:
        return "LEGACY_SSE"
    return "OTHER"


def text_section(pe):
    data = pe
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_sz = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    sec0 = e_lfanew + 24 + opt_sz
    for i in range(nsec):
        off = sec0 + i * 40
        name = data[off:off + 8].rstrip(b"\0").decode("ascii", "replace")
        if name == ".text":
            vsz, va, rsz, rptr = struct.unpack_from("<IIII", data, off + 8)
            return data[rptr:rptr + rsz]
    raise ValueError(".text not found")


def profile(pe_bytes):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = False
    text = text_section(pe_bytes)
    counts = {}
    seq = []  # 域序列: 'Y'(ymm/vex256) / 'X'(legacy sse) / 其他不入序
    total = 0
    last = None
    switches = 0
    for ins in md.disasm(text, 0x1000):
        total += 1
        cls = classify(ins)
        counts[cls] = counts.get(cls, 0) + 1
        if cls == "VEX256":
            dom = "Y"
        elif cls == "LEGACY_SSE":
            dom = "X"
        else:
            dom = None
        if dom:
            if last and last != dom:
                switches += 1
            last = dom
        seq.append(cls)
    return total, counts, switches


def main():
    print(f"{'exe':<28} {'insns':>7} {'VEX256':>7} {'VEX128':>7} {'LEG_SSE':>8} "
          f"{'VZERO':>6} {'BRIDGE':>7} {'VEXoth':>7} {'switches':>9}")
    for path in sys.argv[1:]:
        with open(path, "rb") as f:
            data = f.read()
        total, counts, sw = profile(data)
        print(f"{path:<28} {total:>7} {counts.get('VEX256',0):>7} "
              f"{counts.get('VEX128',0):>7} {counts.get('LEGACY_SSE',0):>8} "
              f"{counts.get('VZERO',0):>6} {counts.get('BRIDGE',0):>7} "
              f"{counts.get('VEX_OTHER',0):>7} {sw:>9}")


if __name__ == "__main__":
    main()
