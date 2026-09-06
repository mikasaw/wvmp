#!/usr/bin/env python3
"""MIT-477 (T9.1)：IAT 引用重写静态校验。

用法: check_import_rewrite.py <native.exe> <packed.exe>

从 native 解析原 IAT 范围（dd[1] → 描述符链 FT 连续区间，FT 宽按 PE32+
8B）；扫描 packed 全部 EXECUTE 节的 rip 相对引用：落原 IAT 区的引用必须
为 0（全部已重指镜像）。命中 → 退出码 1。
"""
import struct
import sys

import capstone


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def sections(data):
    e = u32(data, 0x3C)
    nsec = struct.unpack_from("<H", data, e + 6)[0]
    opt = e + 24
    opt_size = struct.unpack_from("<H", data, e + 20)[0]
    plus = struct.unpack_from("<H", data, opt)[0] == 0x20B
    dd = opt + (112 if plus else 96)
    table = opt + opt_size
    out = []
    for i in range(nsec):
        sh = table + i * 40
        name = data[sh:sh + 8].split(b"\x00")[0].decode(errors="replace")
        vs, va, rs, rp = struct.unpack_from("<IIII", data, sh + 8)
        chars = u32(data, sh + 36)
        out.append((name, va, vs, rp, rs, chars))
    return out, dd


def iat_span(data):
    secs, dd = sections(data)
    desc_rva = u32(data, dd + 1 * 8)
    if desc_rva == 0:
        return None

    def r2o(r):
        for (_n, va, vs, rp, rs, _c) in secs:
            if va and va <= r < va + max(vs, rs):
                return rp + r - va
        return None

    base = None
    end = None
    o = r2o(desc_rva)
    if o is None:
        return None
    while o + 20 <= len(data):
        intl, _ts, _fc, _nm, ft = struct.unpack_from("<IIIII", data, o)
        if intl == 0 and ft == 0:
            break
        n = 0
        io_ = r2o(intl)
        if io_ is None:
            return None
        while u32(data, io_ + n * 4) != 0:
            n += 1
        if base is None or ft < base:
            base = ft
        e = ft + (n + 1) * 8
        if end is None or e > end:
            end = e
        o += 20
    return (base, end - base) if base else None


def main():
    native = open(sys.argv[1], "rb").read()
    packed = open(sys.argv[2], "rb").read()
    span = iat_span(native)
    if not span:
        print("no imports in native")
        return 0
    lo, size = span
    secs, _dd = sections(packed)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    orig_hits = 0
    for (_n, va, vs, rp, rs, chars) in secs:
        if not (chars & 0x20000000) or rs == 0:
            continue
        code = packed[rp:rp + rs]
        for ins in md.disasm(code, va):
            for op in ins.operands:
                if op.type != capstone.x86.X86_OP_MEM:
                    continue
                if op.mem.base != capstone.x86.X86_REG_RIP:
                    continue
                t = ins.address + ins.size + op.mem.disp
                if lo <= t < lo + size:
                    orig_hits += 1
    print(f"orig_iat=[{lo:#x},{lo + size:#x}) exec-rip-hits={orig_hits}")
    return 1 if orig_hits else 0


if __name__ == "__main__":
    sys.exit(main())
