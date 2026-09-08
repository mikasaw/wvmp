#!/usr/bin/env python3
"""MIT-477 (T9.1) / MIT-486 (T9.2)：IAT 引用重写静态校验。

用法: check_import_rewrite.py <native.exe> <packed.exe>

从 native 解析原 IAT 范围（dd[1] → 描述符链 FT 连续区间，槽宽按 PE 格式
PE32+ 8B / PE32 4B）；扫描 packed：
  - EXECUTE 节代码引用——PE32+ rip 相对（base=RIP）/ PE32 abs32 直接编址
    （base=INVALID，disp 为全 VA）——落原 IAT 区的引用必须为 0；
  - 数据指针——dd[5] BASERELOC 全扫，非 EXECUTE 节内 DIR64/HIGHLOW 站点
    值落原 IAT 区必须为 0。
任一命中 → 退出码 1。
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
    return out, dd, plus


def iat_span(data):
    secs, dd, plus = sections(data)
    w = 8 if plus else 4
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
        e = ft + (n + 1) * w
        if end is None or e > end:
            end = e
        o += 20
    return (base, end - base, plus) if base else None


def main():
    native = open(sys.argv[1], "rb").read()
    packed = open(sys.argv[2], "rb").read()
    span = iat_span(native)
    if not span:
        print("no imports in native")
        return 0
    lo, size, plus = span
    w = 8 if plus else 4
    ib = struct.unpack_from("<Q" if plus else "<I", packed,
                            u32(packed, 0x3C) + 24 + (24 if plus else 28))[0]
    secs, dd, _p = sections(packed)
    md = capstone.Cs(capstone.CS_ARCH_X86,
                     capstone.CS_MODE_64 if plus else capstone.CS_MODE_32)
    md.detail = True
    exec_hits = 0
    for (_n, va, vs, rp, rs, chars) in secs:
        if not (chars & 0x20000000) or rs == 0:
            continue
        code = packed[rp:rp + rs]
        for ins in md.disasm(code, va):
            for op in ins.operands:
                if op.type != capstone.x86.X86_OP_MEM:
                    continue
                if plus:
                    if op.mem.base != capstone.x86.X86_REG_RIP:
                        continue
                    t = ins.address + ins.size + op.mem.disp
                else:
                    if op.mem.base != capstone.x86.X86_REG_INVALID:
                        continue
                    t = op.mem.disp - ib  # abs32 disp 承载全 VA → RVA
                if lo <= t < lo + size:
                    exec_hits += 1
    # 数据指针残留：packed dd[5] 全扫，非 EXECUTE 节 DIR64/HIGHLOW 站点值
    # 落原 IAT 区（VA 空间）→ 命中。
    data_hits = 0
    reloc_rva = u32(packed, dd + 5 * 8)
    reloc_size = u32(packed, dd + 5 * 8 + 4)
    want_type = 10 if plus else 3
    if reloc_rva and reloc_size >= 8:
        r2o = None
        for (_n, va, vs, rp, rs, _c) in secs:
            if va and va <= reloc_rva < va + max(vs, rs):
                r2o = rp + reloc_rva - va
                break
        if r2o is not None and r2o + reloc_size <= len(packed):
            pos = 0
            blob = packed
            while pos + 8 <= reloc_size:
                page = u32(blob, r2o + pos)
                bsz = u32(blob, r2o + pos + 4)
                if bsz < 8 or pos + bsz > reloc_size:
                    break
                for i in range((bsz - 8) // 2):
                    e = struct.unpack_from("<H", blob, r2o + pos + 8 + i * 2)[0]
                    if e >> 12 != want_type:
                        continue
                    site = page + (e & 0x0FFF)
                    # 站点判据与 rewriter 全含式一致（site+w 全落节内），
                    # 避免节尾 w-1 字节站点的校验假阳（MIT-486 复审建议 3）。
                    sec = next((s for s in secs
                                if s[1] and s[1] <= site
                                and site + w <= s[1] + s[2]), None)
                    if sec is None or (sec[5] & 0x20000000):
                        continue
                    so = sec[3] + site - sec[1]
                    if so + w > len(packed):
                        continue
                    v = int.from_bytes(packed[so:so + w], "little")
                    if v >= ib and lo <= v - ib < lo + size:
                        data_hits += 1
                pos += bsz
    print(f"orig_iat=[{lo:#x},{lo + size:#x}) plus={plus} "
          f"exec-hits={exec_hits} data-hits={data_hits}")
    return 1 if (exec_hits or data_hits) else 0


if __name__ == "__main__":
    sys.exit(main())
