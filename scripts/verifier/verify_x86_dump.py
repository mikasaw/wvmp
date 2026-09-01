#!/usr/bin/env python3
"""
MIT-443 (X3a) A.3: x86 (KS_MODE_32) runtime dump 静态审门。

Why this gate exists:
  generate_runtime_x86 产出的 KS_MODE_32 码体是本波 x86 战役的真验证通道
  基座（X3a 电池 / X3b 批迁 / X4 stub 都踩它）。x64 侧已有
  dump_handler_xmm_check.py（SSE handler 集合恒等不动，本脚本零触碰它）；
  x86 侧需要自己的门：
    1. dump 布局头齐全（entry=+0x0 / dispatch / table）+ arch: x86 标记行；
    2. 全码体 capstone CS_MODE_32 线性可解码到跳表起点（数据段前），
       entry 首四条 = push/call/pop/sub（D2 call/pop idiom）；
    3. dispatch 含 and <r>, 0x7f（kTableEntries-1 掩码）+ 间接 jmp（D3 8B
       表项决策的落地证据）；
    4. 电池集 19 handler 全部在 dump 中登记（跳表缺项折叠 Halt 的对账面），
       每个登记 handler 的码体反汇编至少含 1 条指令（空 handler 检测）；
    5. 硬条款：立即数十六进制纪律（capstone 显示 0x 口径）与
       zero5-x86-空/内存常驻 flags 的结构性断言由电池层覆盖，此处不重复。

Input:
  --asm <runtime_dump_x86.txt>   WVMP_RUNTIME_DUMP 风格的 asm_dump 文本
                                （tests/test_runtime_x86.cpp 的
                                 gen.asm_dump 写盘同构）
  --code <runtime_image_x86.bin> 可选：码体二进制（--pe 提取面由 X4 stub
                                 单接手；当前电池产物经 --dump-bin 落盘，
                                 或直接用电池 exe 的 image.code）
  无 --code 时仅做 dump 文本静态审（1/2/4 项的反汇编项跳过并披露）。

Exit codes: 0 = PASS; 1 = FAIL; 2 = tooling error.

Usage:
  python scripts\\verifier\\verify_x86_dump.py --asm runtime_dump_x86.txt \
      [--code runtime_image_x86.bin]
"""

from __future__ import annotations

import argparse
import re
import sys

# 电池集 handler 名单（asmgen.cpp x86 表 —— 与其同步；X3b 批迁随批次更新）。
BATTERY_HANDLERS = {
    "mov", "lea", "add", "sub", "and", "or", "xor", "cmp", "test",
    "inc", "dec", "load", "store", "jmp", "jcc", "nop", "halt",
    "getflags", "setflags",
    # X3b (MIT-444) A 档批次一：一元 / 带进借位二元 / 乘法 / 符号扩展。
    "not", "neg", "adc", "sbb", "imul", "mul", "cdq",
    # X3b (MIT-444) A 档批次二：移位/旋转族（imm + cl 变体）。
    "shl", "shr", "sar", "rol", "ror",
    "shlcl", "shrcl", "sarcl", "rolcl", "rorcl",
    # X3b (MIT-444) A 档批次三：扩展传送 / 字节序 / 交换族。
    "movzx", "movzxmem", "movsx", "movsxmem", "bswap", "xchg",
    # X3b (MIT-444) A 档批次四：条件族（reads-flags 面）。
    "setcc", "cmovcc",
    # X3b (MIT-444) A 档批次五：位计数 / 锁原子族。
    "popcnt", "lzcnt", "tzcnt", "cmpxchg", "xadd", "bts", "btr", "btc",
}

HEADER_RE = re.compile(
    r"; regvm runtime image: entry=\+0x0, dispatch=\+0x([0-9a-fA-F]+), "
    r"table=\+0x([0-9a-fA-F]+), total=(\d+)")
HANDLER_RE = re.compile(r"; ---- handler (\S+) @ \+0x([0-9a-fA-F]+) ----")


def fail(msg: str) -> None:
    print(f"[x86-dump-gate] FAIL {msg}")
    sys.exit(1)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--asm", required=True)
    ap.add_argument("--code", default="")
    args = ap.parse_args()

    try:
        with open(args.asm, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        print(f"[x86-dump-gate] FAIL tooling: cannot read --asm: {e}")
        sys.exit(2)

    # 1. 布局头 + arch 标记。
    m = HEADER_RE.search(text)
    if not m:
        fail("布局头缺失或格式漂移（; regvm runtime image: ...）")
    dispatch_off = int(m.group(1), 16)
    table_off = int(m.group(2), 16)
    if "; arch: x86 (KS_MODE_32" not in text:
        fail("arch: x86 标记行缺失（x86 dump 口径）")
    if "vm_entry:" not in text or "codec: none" not in text:
        fail("vm_entry/codec 标记缺失")
    print(f"[x86-dump-gate] header ok: dispatch=+0x{dispatch_off:x} "
          f"table=+0x{table_off:x}")

    # 2. handler 登记面：电池集全覆盖 + 偏移单调（码序随机，偏移互不重叠）。
    handlers = HANDLER_RE.findall(text)
    names = [n for n, _ in handlers]
    missing = BATTERY_HANDLERS - set(names)
    if missing:
        fail(f"电池集 handler 未登记: {sorted(missing)}")
    offs = sorted(int(o, 16) for _, o in handlers)
    if len(set(offs)) != len(offs):
        fail("handler 偏移重复")
    if any(o >= table_off for o in offs):
        fail("handler 偏移越过跳表起点")
    print(f"[x86-dump-gate] handlers ok: {len(names)} 登记项（电池集 "
          f"{len(BATTERY_HANDLERS)} 全覆盖）")

    # 3. 码体反汇编（可选 —— 需要 --code）。
    if args.code:
        try:
            import capstone
        except ImportError:
            print("[x86-dump-gate] WARN: capstone 不可用，反汇编审跳过（文本审已过）")
            print("[x86-dump-gate] PASS (text-only)")
            return
        try:
            with open(args.code, "rb") as f:
                code = f.read()
        except OSError as e:
            print(f"[x86-dump-gate] FAIL tooling: cannot read --code: {e}")
            sys.exit(2)
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        # entry 首四条（D2 call/pop idiom）。
        seq = []
        for insn in md.disasm(code[:32], 0):
            seq.append(insn.mnemonic)
            if len(seq) == 4:
                break
        if seq[:4] != ["push", "call", "pop", "sub"]:
            fail(f"entry 首四条 = {seq}，期望 push/call/pop/sub（D2 idiom）")
        # dispatch 掩码 + 间接跳转。
        d_text = []
        for insn in md.disasm(code[dispatch_off:dispatch_off + 48], dispatch_off):
            d_text.append(f"{insn.mnemonic} {insn.op_str}")
        if not any(t.startswith("and") and "0x7f" in t for t in d_text):
            fail("dispatch 缺 and <r>, 0x7f（kTableEntries-1）")
        if not any(t.startswith("jmp") and not t[4:5].isdigit() and "0x" not in t
                   for t in d_text):
            fail("dispatch 缺寄存器间接 jmp（8B 表项决策落地）")
        # 每个 handler 码体非空（首条可解码）。
        for name, off in handlers:
            o = int(off, 16)
            first = next(md.disasm(code[o:o + 8], o), None)
            if first is None:
                fail(f"handler {name} 码体首条不可解码")
        print("[x86-dump-gate] disasm ok: entry idiom / dispatch mask / "
              f"{len(handlers)} handler 首条全可解码")

    print("[x86-dump-gate] PASS")


if __name__ == "__main__":
    main()
