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
        # INT 槽宽 = w（PE32+ 8B / PE32 4B）：4 字节步进会在首个 8B 槽的
        # 高半字 0 处提前终止 → span 少算（MIT-487 验收 MUST-FIX，同
        # census 脚本坑）。
        while u32(data, io_ + n * w) != 0:
            n += 1
        if base is None or ft < base:
            base = ft
        e = ft + (n + 1) * w
        if end is None or e > end:
            end = e
        o += 20
    return (base, end - base, plus) if base else None


def tls_callback_windows(packed, secs, dd, plus, ib):
    """MIT-532：TLS 回调桩窗（RVA 区间列表）。

    import_protect 的回填循环在 tls_hook 生成的回调桩里装载原 IAT 基址作
    rep movs 目的（设计内的"写方"），与本门要抓的"残留读方"语义相反；该
    桩是 tls_hook 对代码节的最后一次追加，窗 = [回调 RVA, 所在节末)（与
    tls_e2e.sh MIT-490 ③ 的扫描窗口径一致）。回调数组从 packed dd[9] 的
    IMAGE_TLS_DIRECTORY.AddressOfCallBacks 解出（数组以 NULL 结尾，槽内
    是全 VA，归一到 RVA 后与反汇地址同空间）。解不出 TLS 目录时返回空
    列表 = 一个窗都不豁免（fail-closed）。
    """
    dd9_rva = u32(packed, dd + 9 * 8)
    dd9_size = u32(packed, dd + 9 * 8 + 4)
    if not dd9_rva or dd9_size == 0:
        return []

    def r2o(r):
        for (_n, va, vs, rp, rs, _c) in secs:
            if va and va <= r < va + max(vs, rs):
                return rp + r - va
        return None

    tls_off = r2o(dd9_rva)
    if tls_off is None or tls_off + (40 if plus else 24) > len(packed):
        return []
    # AddressOfCallBacks 槽内存的是全 VA（TLS 目录字段约定），先归一到 RVA。
    # PE32 目录 24B (AddressOfCallBacks @12, u32); PE32+ 目录 40B (三
    # ULONGLONG 后 @24, u64——MIT-532 验收 F2: 旧 +16/u32 读到的是
    # AddressOfIndex 低半, 恒 < ib 空窗 = fail-closed 假红)。
    if plus:
        cb_arr_va = int.from_bytes(packed[tls_off + 24:tls_off + 32], "little")
    else:
        cb_arr_va = u32(packed, tls_off + 12)
    if cb_arr_va < ib:
        return []
    arr_off = r2o(cb_arr_va - ib)
    if arr_off is None:
        return []
    wins = []
    w = 8 if plus else 4
    i = 0
    while arr_off + i * w + w <= len(packed):
        cb = int.from_bytes(packed[arr_off + i * w:arr_off + i * w + w], "little")
        if cb == 0:
            break
        if cb >= ib:
            cb_rva = cb - ib
            sec = next((s for s in secs
                        if s[1] and s[1] <= cb_rva < s[1] + max(s[2], s[4])), None)
            # 只对 wvmp 生成节（.wvmpc/.wvmp）里的回调建窗：tls_hook 桩永远
            # 追加在 .wvmpc（它是该节最后一次代码追加，[cb, 节末) 即桩体）；
            # 原用户回调住在 .text 一类原节中间，"到节末"会罩住整片原代码，
            # 豁免面不可接受地扩大（MIT-532 反例实测抓到）。
            if sec is not None and sec[0].startswith(".wvmp"):
                wins.append((cb_rva, sec[1] + max(sec[2], sec[4])))
        i += 1
    return wins


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
    cb_wins = tls_callback_windows(packed, secs, dd, plus, ib)
    md = capstone.Cs(capstone.CS_ARCH_X86,
                     capstone.CS_MODE_64 if plus else capstone.CS_MODE_32)
    md.detail = True
    exec_hits = 0
    imm_hits = 0
    backfill_loads = 0
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
            # MIT-487 (T9.3a)：模型外形态负扫——imm32 直接载荷（B8+r
            # mov r32, imm32；x64 基址 >4GB 时 imm32 结构上装不下全 VA，
            # 该族结构性缺席——负扫兜底仍留）。C7 /0 mov [x], imm32 的
            # imm 载荷不经本扫：其 mem 操作数已由 MEM 面覆盖、imm 语义
            # 是"写入槽的值"而非"槽地址引用"。moffs64（A0-A3，long 模式
            # MSVC 不生成）。命中即残面证据。
            # MIT-532：TLS 回调桩窗内的 imm 装载豁免（计 backfill_loads
            # 披露）——import_protect 回填循环装载原 IAT 基址作 rep movs
            # 目的，是设计内的"写方"，与残留"读方"语义相反；桩窗的
            # rep-movs 有无极性由 tls_e2e.sh 专项断言另行看管。窗由
            # tls_callback_windows() 从 packed TLS 目录解出（解不出 =
            # 空列表 = 不豁免，fail-closed）。窗外命中仍是残面证据。
            b = ins.bytes
            hit = False
            if 0xB8 <= b[0] <= 0xBF and len(b) == 5:
                v = struct.unpack_from("<I", b, 1)[0]
                hit = v >= ib and lo <= v - ib < lo + size
            elif plus and b[0] in (0xA0, 0xA1, 0xA2, 0xA3) and len(b) == 10:
                v = struct.unpack_from("<Q", b, 2)[0]
                hit = v >= ib and lo <= v - ib < lo + size
            if hit:
                if any(c0 <= ins.address < c1 for (c0, c1) in cb_wins):
                    backfill_loads += 1
                else:
                    imm_hits += 1
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
          f"exec-hits={exec_hits} data-hits={data_hits} imm-hits={imm_hits} "
          f"backfill-loads={backfill_loads}"
          + (f" (tls cb windows: {['%#x-%#x' % w for w in cb_wins]})"
             if backfill_loads else ""))
    # span 自检（MIT-487 验收建议 2）：native dd[12]（IAT 目录 Size）非零
    # 时必须与 INT 步进计数一致——自动捕获 span 分母错误类缺陷。
    _secs, dd_native, _p2 = sections(native)
    dd12_size = u32(native, dd_native + 12 * 8 + 4)
    if dd12_size not in (0, size):
        print(f"span self-check FAILED: dd[12].Size={dd12_size:#x} "
              f"!= INT-counted {size:#x}")
        return 1
    return 1 if (exec_hits or data_hits or imm_hits) else 0


if __name__ == "__main__":
    sys.exit(main())
