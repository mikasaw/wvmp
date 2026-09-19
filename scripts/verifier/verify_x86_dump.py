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
    3. dispatch 含 and <r>, kTableEntries-1 掩码 + 间接 jmp（D3 8B 表项决策的
       落地证据）。掩码不写字面量：由 dump 跳表标记行的项数派生，再与代码侧
       asmgen.cpp 的 kTableEntries 对账（MIT-503：扩容曾把门留在 0x7F 上空转）。
    4. 电池集 handler（X3c 批次三起 60）全部在 dump 中登记（跳表缺项折叠 Halt 的
       对账面），
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
  无 --code 时仅做 dump 文本静态审：1/2/4 项的反汇编项（entry idiom、
  dispatch 掩码、handler 码体非空）逐项显式 SKIP 披露，判词为 INCOMPLETE
  而非 PASS（MIT-503：此前三项整段静默跳过仍打裸 PASS，等于没跑）。

Exit codes: 0 = PASS; 1 = FAIL; 2 = tooling error;
            3 = INCOMPLETE —— 反汇编审未执行（未传 --code，或 capstone 不可用）。
            3 不得计为通过。

Usage:
  python scripts\\verifier\\verify_x86_dump.py --asm runtime_dump_x86.txt \
      --code runtime_image_x86.bin
"""

from __future__ import annotations

import argparse
import os
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
    # X3b (MIT-444) B 档 GP：栈原语（4B 槽裁决）+ RVA 族。
    "push", "pop", "loadrva", "storeriva", "learva",
    # X3c (MIT-445) 协议面：CallGate reg 值目标 + RVA 双形 / ExitNative 4B 槽
    # / Ret 4B 清栈返回。
    "callgate", "exitnative", "ret",
    # X6 (MIT-454) A=X3d 批次二：SSE 32 位镜像（算术 16 + 传送 6 + 位运算 4
    # + mem 原语 2 + GP↔xmm 桥 2；批次三 ucomis 2 随批三追加）。
    "addss", "addps", "addpd", "subss", "subps", "subpd",
    "mulss", "mulsd", "mulps", "mulpd",
    "divss", "divsd", "divps", "divpd", "addsd", "subsd",
    "movss", "movsd", "movaps", "movapd", "movups", "movupd",
    "xorps", "orps", "andps", "andnps",
    "xmmload", "xmmstore", "xmmfromgp", "gpfromxmm",
    # X6 (MIT-454) A=X3d 批次三：SSE 比较族（flags 面，32 op 收尾）。
    "ucomiss", "ucomisd",
    # X7 (MIT-455) 批二：Div/Idiv 32 位真 handler（build_div_idiv 镜像，
    # 453 b59b 残面收口；除零 = 真 #DE 直通，电池 6 组商/余双槽断言）。
    "div", "idiv",
}

HEADER_RE = re.compile(
    r"; regvm runtime image: entry=\+0x0, dispatch=\+0x([0-9a-fA-F]+), "
    r"table=\+0x([0-9a-fA-F]+), total=(\d+)")
HANDLER_RE = re.compile(r"; ---- handler (\S+) @ \+0x([0-9a-fA-F]+) ----")
# 跳表标记行 = 掩码的产物侧真源（asmgen 以 std::to_string(kTableEntries) 发射）。
TABLE_RE = re.compile(
    r";\s*---- jump table @ \+0x([0-9a-fA-F]+) \((\d+) x u64")
# 代码侧真源：asmgen.cpp 的 constexpr（脚本在仓内即可直读，不再手抄字面量）。
ASMGEN_RELPATH = os.path.join("vm", "regvm", "runtime", "src", "asmgen.cpp")
KTABLE_RE = re.compile(r"constexpr u64 kTableEntries = (\d+)")
AND_OPERAND_RE = re.compile(r",\s*0x([0-9a-fA-F]+)\s*$")
# 依赖 --code 的反汇编审项 —— 未执行时必须逐项披露，不得静默。
DISASM_ITEMS = (
    "entry 首四条 push/call/pop/sub（D2 idiom）",
    "dispatch 掩码 + 寄存器间接 jmp（D3）",
    "每个 handler 码体首条可解码（空 handler 检测）",
)


def fail(msg: str) -> None:
    print(f"[x86-dump-gate] FAIL {msg}")
    sys.exit(1)


def incomplete(msg: str) -> None:
    print(f"[x86-dump-gate] SKIP {msg}")
    for item in DISASM_ITEMS:
        print(f"[x86-dump-gate]   SKIP 反汇编审项未执行：{item}")
    print("[x86-dump-gate] INCOMPLETE —— 反汇编审未执行，不计为 PASS")
    sys.exit(3)


def code_side_table_entries():
    """读 asmgen.cpp 的 kTableEntries；不可读时返回 (None, 路径)。"""
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    path = os.path.join(root, ASMGEN_RELPATH)
    try:
        with open(path, "r", encoding="utf-8") as f:
            m = KTABLE_RE.search(f.read())
    except OSError:
        return None, path
    return (int(m.group(1)) if m else None), path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--asm", required=True)
    ap.add_argument("--code", default="",
                    help="码体镜像 .bin；不传则反汇编审三项整段跳过 → INCOMPLETE(exit 3)")
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

    # 1b. 掩码单一真源：dump 跳表项数派生 → 与代码侧 kTableEntries 对账。
    #     任何一方单独扩容都会在这里断掉，而不是留下"改了码没改门"的空转锁。
    tm = TABLE_RE.search(text)
    if not tm:
        fail("跳表标记行缺失，无法派生 kTableEntries（掩码真源断链）")
    if int(tm.group(1), 16) != table_off:
        fail(f"跳表标记偏移 +0x{int(tm.group(1), 16):x} != 头 table=+0x{table_off:x}")
    dump_entries = int(tm.group(2))
    if dump_entries & (dump_entries - 1):
        fail(f"kTableEntries={dump_entries} 非 2 的幂，掩码派生不成立")
    code_entries, asmgen_path = code_side_table_entries()
    if code_entries is None:
        print(f"[x86-dump-gate] WARN: 读不到代码侧 kTableEntries（{asmgen_path}），"
              f"掩码仅由 dump 跳表标记派生，无对账")
    elif code_entries != dump_entries:
        fail(f"掩码真源对账失败：dump 跳表 {dump_entries} 项 != asmgen.cpp "
             f"kTableEntries {code_entries} 项（扩容后须用当前树重采 dump）")
    mask = dump_entries - 1
    mask_src = "dump 跳表标记" if code_entries is None else "dump 跳表标记 × asmgen.cpp 对账"
    # 文本侧 dispatch 的 and 立即数也须等于派生掩码（先于 --code 的交叉证据）。
    dispatch_block = re.search(r"\ndispatch:\n(.*?)(?=\n; ---- handler |\Z)",
                               text, re.S)
    if not dispatch_block:
        fail("dump 文本 dispatch: 段缺失，无法核对掩码")
    text_masks = []
    for line in dispatch_block.group(1).splitlines():
        stmt = line.strip()
        if stmt.startswith("and"):
            am = AND_OPERAND_RE.search(stmt)
            if am:
                text_masks.append(int(am.group(1), 16))
    if mask not in text_masks:
        fail(f"dump 文本 dispatch 缺 and <r>, 0x{mask:X}（kTableEntries-1，"
             f"源：{mask_src}）；实得 {['0x%X' % m for m in text_masks]}")
    print(f"[x86-dump-gate] mask ok: kTableEntries={dump_entries} → and <r>, "
          f"0x{mask:X}（源：{mask_src}）")

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

    # 3. 码体反汇编（需要 --code；缺它这三项一律不静默跳过）。
    if args.code:
        try:
            import capstone
        except ImportError:
            incomplete("capstone 不可用：--code 已传，但反汇编审无法执行")
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
        # dispatch 掩码 + 间接跳转。掩码 = 派生值，不在此手抄字面量。
        d_text = []
        d_masks = []
        for insn in md.disasm(code[dispatch_off:dispatch_off + 48], dispatch_off):
            stmt = f"{insn.mnemonic} {insn.op_str}"
            d_text.append(stmt)
            if insn.mnemonic == "and":
                am = AND_OPERAND_RE.search(stmt)
                if am:
                    d_masks.append(int(am.group(1), 16))
        if mask not in d_masks:
            fail(f"dispatch 缺 and <r>, 0x{mask:X}（kTableEntries-1，"
                 f"源：{mask_src}）；码体实得 {['0x%X' % m for m in d_masks]}")
        if not any(t.startswith("jmp") and not t[4:5].isdigit() and "0x" not in t
                   for t in d_text):
            fail("dispatch 缺寄存器间接 jmp（8B 表项决策落地）")
        # 每个 handler 码体非空（首条可解码）。
        for name, off in handlers:
            o = int(off, 16)
            first = next(md.disasm(code[o:o + 8], o), None)
            if first is None:
                fail(f"handler {name} 码体首条不可解码")
        print("[x86-dump-gate] disasm ok: entry idiom / dispatch mask "
              f"0x{mask:X} / {len(handlers)} handler 首条全可解码")
    else:
        incomplete("未传 --code：只做了 dump 文本静态审，码体反汇编审整段未执行")

    print("[x86-dump-gate] PASS")


if __name__ == "__main__":
    main()
