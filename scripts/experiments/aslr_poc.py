#!/usr/bin/env python3
"""MIT-493 (T25)：ASLR 兼容性 PoC——.reloc 扩展 + DYNAMIC_BASE 置位。

用法: aslr_poc.py <packed.exe> <out.exe> [--no-reloc]

对 skip_backfill 模式的 x64 packed 产物做后处理：
  1. 字节粒度普查全部绝对 VA（[ImageBase, ImageBase+0x20000)）；
  2. 取 packer 面（.wvmp/.wvmpc 全部 + .rdata 原 IAT 区 skip 桩值站点）
     为 DIR64 站点集；
  3. 在 .reloc 节 raw slack（下一节起点前）内按页追加 DIR64 块，扩
     dd[5].Size；
  4. 置 DllCharacteristics.DYNAMIC_BASE，checksum 清 0。

--no-reloc = 只置 DYNAMIC_BASE 不扩展 reloc（MIT-340 崩溃形态对照）。

实验结论（MIT-493，x64 tls 样本 seed=1 skip 模式）：
  PoC（扩展 55 站点 + ASLR）→ rc=0，stdout 与 native byte-exact；
  对照（仅 DYNAMIC_BASE）→ rc=139 segfault（MIT-340 形态复现）。
  即"Windows 加载器拒绝保护后 .reloc 扩展"系当年误诊——崩因是覆盖
  不全（未登记站点 delta 未应用）；加载器对扩展块行为完全正常。
"""
import struct
import sys


def main():
    src, dst = sys.argv[1], sys.argv[2]
    no_reloc = "--no-reloc" in sys.argv
    d = bytearray(open(src, "rb").read())
    e = struct.unpack_from("<I", d, 0x3C)[0]
    opt = e + 24
    dd = opt + 112
    ib = struct.unpack_from("<Q", d, opt + 24)[0]
    nsec = struct.unpack_from("<H", d, e + 6)[0]
    table = opt + struct.unpack_from("<H", d, e + 20)[0]
    secs = []
    for i in range(nsec):
        sh = table + i * 40
        nm = d[sh:sh + 8].split(b"\0")[0].decode()
        vs, va, rs, rp = struct.unpack_from("<IIII", d, sh + 8)
        secs.append({"nm": nm, "vs": vs, "va": va, "rs": rs, "rp": rp})
    size = 0x20000

    def off2rva(o):
        for s in secs:
            if s["rp"] <= o < s["rp"] + s["rs"]:
                return s["va"] + (o - s["rp"])
        return None

    sites = []
    if not no_reloc:
        for o in range(0, len(d) - 8):
            v = struct.unpack_from("<Q", d, o)[0]
            if ib <= v < ib + size:
                nm = next((s["nm"] for s in secs
                           if s["rp"] <= o < s["rp"] + s["rs"]), None)
                if nm in (".wvmp", ".wvmpc"):
                    sites.append(off2rva(o))
                elif nm == ".rdata" and 0x3000 <= off2rva(o) < 0x3150:
                    # 原 IAT 区 skip 桩值站点（硬编码 span 系 tls 样本专用）
                    sites.append(off2rva(o))
    if sites:
        rel = next(s for s in secs if s["nm"] == ".reloc")
        nxt = min(s["rp"] for s in secs if s["rp"] > rel["rp"])
        reloc_sz = struct.unpack_from("<I", d, dd + 5 * 8 + 4)[0]
        cur_end = rel["rp"] + reloc_sz
        need = (8 + 2 * len(sites) + 7) // 8 * 8
        if cur_end + need > nxt:
            print(f"slack insufficient: need {need}, avail {nxt - cur_end}")
            return 1
        from collections import defaultdict
        pages = defaultdict(list)
        for rva in sites:
            pages[rva & ~0xFFF].append(rva & 0xFFF)
        blob = bytearray()
        for page in sorted(pages):
            ents = bytearray()
            for off in sorted(set(pages[page])):
                ents += struct.pack("<H", 10 << 12 | off)
            while len(ents) % 8:
                ents += struct.pack("<H", 0)
            blob += struct.pack("<II", page, 8 + 2 * len(ents)) + ents
        d[cur_end:cur_end + len(blob)] = blob
        struct.pack_into("<I", d, dd + 5 * 8 + 4, reloc_sz + len(blob))
        print(f"reloc extended: {len(sites)} DIR64 sites, +{len(blob)} bytes")
    ch_off = opt + 0x46
    ch = struct.unpack_from("<H", d, ch_off)[0]
    struct.pack_into("<H", d, ch_off, ch | 0x0040)
    struct.pack_into("<I", d, opt + 64, 0)
    open(dst, "wb").write(bytes(d))
    print(f"written {dst} (DYNAMIC_BASE set)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
