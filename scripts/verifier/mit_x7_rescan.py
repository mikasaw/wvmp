#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MIT-X7 客户态重扫（双 arch 三层口径）——批一零产品代码侦察脚本。

方法学 = 436 (X0) mit-X0-triage.md §9 留样全套照用（X0 留样 jsonl 已随
%TEMP% 清理失效，语料按 X0 §1.2 分层口径重建，405 坐标纪律）：
  ① mnemonic 级新旧对照 —— X6 后白名单重映射（x86 / x64 分开），输出
     direct / fork(shape 残面) / gate 三态覆盖率；
  ② x64 侧首扫 —— System32 对称语料（X0 从未扫过 x64 域，本单新数据；
     §F.2 同源镜像偏置按文件清单披露）；
  ③ 区域级纸面 lift 通过率 —— x64 用 .pdata 真函数域逐函数归因（函数域
     扫描法 x64 合法，X0 §1.1）；x86 无 .pdata（436 §E 钉死不可平抄），
     用递归 BFS 对账子集误差界 + 文件级 any-hit 代理，口径如实披露。

X6b 三候选面裁决数据（预登记阈值 D2，项目主已拍板）：
  - push-imm x64：助记符占比 ≥0.5% → 实施；<0.5% → 维持 gate 销案。
  - 间接 jmp：区域占比 ≥1% 且可实施形态明确（表形 = mem 带 index*scale）
    → 仅收跳转表可静态形；否则维持 gate。
  - Div 族 x86：不依赖数据默认做（本脚本出双 arch 密度对照）。
x87 B 路线触发判定（445 §6）：x87 密度双 arch 分档 + 含 x87 函数占比。

白名单一致性断言（§E：扫描脚本与产品 lifter walk 规则一致性，漂移即误报
数据）：脚本启动时解析 passes/lifter/src/x86_translate.cpp 的 case X86_INS_*
全集，逐条断言 DIRECT 助记符集 ⊆ 产品白名单。

用法： python scripts/verifier/mit_x7_rescan.py [--out DIR] [--quick]
输出： <out>/mit_x7_rescan.jsonl   每文件记录（原始计数全留样，可复跑对账）
       <out>/mit_x7_summary.json   汇总（三层口径表 + X6b 裁决读数）
扫描只读，产物不写系统目录（D5）。
"""

import argparse
import bisect
import json
import os
import re
import random
import struct
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

from capstone import (Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64)
import capstone.x86 as cx

# ---------------------------------------------------------------------------
# 语料定义（D5：只用系统目录 + 自有样本 + 436 第三方清单；全部只读）
# ---------------------------------------------------------------------------

WIN = Path(os.environ.get("SystemRoot", r"C:\Windows"))
SYSWOW = WIN / "SysWOW64"
SYSTEM32 = WIN / "System32"

# X0 §1.2 core_os 全点名集口径（37 文件；OS 核心库名单两代系统间稳定，个别
# 缺位文件如实记 absent，不静默替换）。
CORE_OS_NAMES = [
    "kernel32.dll", "user32.dll", "gdi32.dll", "ntdll.dll", "shell32.dll",
    "ole32.dll", "oleaut32.dll", "advapi32.dll", "rpcrt4.dll", "ws2_32.dll",
    "comdlg32.dll", "shlwapi.dll", "wininet.dll", "urlmon.dll", "uxtheme.dll",
    "comctl32.dll", "setupapi.dll", "crypt32.dll", "wintrust.dll",
    "userenv.dll", "version.dll", "secur32.dll", "netapi32.dll",
    "powrprof.dll", "imagehlp.dll", "psapi.dll", "wtsapi32.dll",
    "ddraw.dll", "dsound.dll", "dinput8.dll", "jscript.dll", "vbscript.dll",
    "msimg32.dll", "winmm.dll", "winspool.drv", "odbcbcp.dll", "msctf.dll",
]

# X0 §1.2 old_runtime 12 文件（逐名列出）。
OLD_RUNTIME_NAMES = [
    "msvcrt.dll", "msvcp60.dll", "mfc42.dll", "mfc42u.dll", "msvbvm60.dll",
    "msdart.dll", "d3dx9_24.dll", "d3dx9_30.dll", "d3dx9_35.dll",
    "d3dx9_40.dll", "xactengine2_0.dll", "xinput1_1.dll",
]

# X0 §1.2 modern_ucrt 7 文件（5 逐名 + 2 同族按存在性补位）。
MODERN_UCRT_NAMES = [
    "ucrtbase.dll", "vcruntime140.dll", "msvcp140.dll", "mfc140.dll",
    "ucrtbase_clr0400.dll", "msvcp140_1.dll", "concrt140.dll",
]

# 436 第三方清单（X0 §1.2 家族名）。X0 文件级清单未留样（%TEMP% 失效），
# 本单按家族取现存子集（确定性：家族内按文件大小取最大 N 个 PE32），
# 缺位家族如实披露（PhysX/Steam/dxcompiler/hha/wab32 本机不在位）。
THIRD_PARTY_ROOTS = [
    (r"C:\Program Files (x86)\VMware\VMware Workstation", 5),
    (r"C:\Program Files (x86)\IncrediBuild", 2),
    (r"C:\Program Files (x86)\Google\GoogleUpdater", 1),
]

NOISE_MNEMONICS = {
    "outsd", "outsb", "insb", "insd", "popal", "pushal", "popaw", "pushaw",
    "arpl", "aas", "daa", "das", "bound", "aaa", "aam", "aad", "les", "lds",
    "into", "int3",
}

X87_FIRST_BYTES = set(range(0xD8, 0xE0)) | {0x9B}

SEG_FIRST = {0x2E: "cs", 0x36: "ss", 0x3E: "ds", 0x26: "es",
             0x64: "fs", 0x65: "gs"}

# ---------------------------------------------------------------------------
# X6 后白名单三态字典（判据 = passes/lifter/src/x86_translate.cpp @bf2a41d
# 逐 case 源读 + docs/GAPS.md X6 收口节；shape 级 gate 在 shape_rec 处理）
# ---------------------------------------------------------------------------

JCC16 = {"ja", "jae", "jb", "jbe", "je", "jg", "jge", "jl", "jle",
         "jne", "jno", "jnp", "jns", "jo", "jp", "js"}
_COND = {c[1:] for c in JCC16}
SETCC16 = {"set" + c for c in _COND}
CMOVCC16 = {"cmov" + c for c in _COND}

# SSE 直接面（X6 后 32 op + 桥 + ucomis/comis flags 面；mm 形 gate 另计）。
SSE_DIRECT = {
    "addss", "addsd", "addps", "addpd", "subss", "subsd", "subps", "subpd",
    "mulss", "mulsd", "mulps", "mulpd", "divss", "divsd", "divps", "divpd",
    "movss", "movaps", "movapd", "movups", "movupd", "movdqa", "movdqu",
    "andps", "andpd", "andnps", "andnpd", "orps", "orpd", "xorps", "xorpd",
    "pand", "por", "pxor", "pandn",
    "ucomiss", "ucomisd", "comiss", "comisd",
}

# SSE 残余 gate 面（X6 D 裁决：Cvt/Sqrt/MaxMin/Unpck/Shuf 无 ir 载体 =
# 双 arch lifter 层 gate；428 负例面 pcmpeq/punpck/pmovmskb；G1b 未开面）。
SSE_RESIDUAL = {
    "sqrtsd", "sqrtss", "sqrtps", "sqrtpd",
    "maxsd", "maxss", "maxps", "maxpd", "minsd", "minss", "minps", "minpd",
    "unpcklps", "unpckhps", "unpcklpd", "unpckhpd",
    "shufps", "shufpd", "pshufd", "pshuflw", "pshufhw", "pshufb",
    "movlpd", "movlps", "movhpd", "movhps", "movlhps", "movhlps", "lddqu",
    "movmskps", "movmskpd", "pmovmskb",
    "punpcklbw", "punpcklwd", "punpckldq", "punpcklqdq", "punpckhbw",
    "punpckhwd", "punpckhdq", "punpckhqdq",
    "packsswb", "packssdw", "packuswb", "packusdw",
    "pcmpeqb", "pcmpeqw", "pcmpeqd", "pcmpeqq", "pcmpgtb", "pcmpgtw",
    "pcmpgtd", "pcmpgtq", "pcmpestri", "pcmpestrm", "pcmpistri",
    "paddb", "paddw", "paddd", "paddq", "paddsb", "paddsw", "paddusb",
    "paddusw", "psubb", "psubw", "psubd", "psubq", "psubsb", "psubsw",
    "psubusb", "psubusw", "pmulld", "pmullw", "pmuludq", "pmuldq",
    "pmulhuw", "pmulhw", "pmaddwd", "pmaddubsw",
    "psllw", "pslld", "psllq", "psrlw", "psrld", "psrlq", "psraw", "psrad",
    "pavgb", "pavgw", "psadbw", "palignr", "pabsb", "pabsw", "pabsd",
    "pblendw", "pblendvb", "pextrb", "pextrw", "pextrd", "pextrq",
    "pinsrb", "pinsrw", "pinsrd", "pinsrq", "ptest",
    "roundps", "roundpd", "roundss", "roundsd",
    "blendps", "blendpd", "blendvps", "blendvpd",
    "haddps", "haddpd", "hsubps", "hsubpd", "addsubps", "addsubpd",
    "cvtsi2sd", "cvtsi2ss", "cvtsd2si", "cvtsd2ss", "cvtss2sd", "cvtss2si",
    "cvtpd2ps", "cvtps2pd", "cvtpd2dq", "cvtdq2pd", "cvttpd2dq", "cvtdq2ps",
    "cvttps2dq", "cvttps2pi", "cvttsd2si", "cvttss2si",
    "aesenc", "aesenclast", "aesdec", "aesdeclast", "aesimc",
    "aeskeygenassist", "pclmulqdq",
    "phaddw", "phaddd", "phaddsw", "phsubw", "phsubd", "phsubsw",
    "psignb", "psignw", "psignd", "pmulhrsw",
    "mpsadbw", "pmaxsb", "pmaxsw", "pmaxsd", "pmaxub", "pmaxud",
    "pminsb", "pminsw", "pminsd", "pminub", "pminud",
    "psrldq", "pslldq",
}

# VEX V-pair 直通面（产品 vex_desc_of 42 id 逐条镜像，v 前缀助记符）。
VEX_DIRECT = {
    "vaddss", "vaddsd", "vaddps", "vaddpd", "vsubss", "vsubsd", "vsubps",
    "vsubpd", "vmulss", "vmulsd", "vmulps", "vmulpd", "vdivss", "vdivsd",
    "vdivps", "vdivpd", "vandps", "vandpd", "vandnps", "vandnpd",
    "vorps", "vorpd", "vxorps", "vxorpd", "vpand", "vpandn", "vpor", "vpxor",
    "vucomiss", "vucomisd", "vcomiss", "vcomisd",
    "vmovss", "vmovsd", "vmovaps", "vmovapd", "vmovups", "vmovupd",
    "vmovdqa", "vmovdqu", "vmovd", "vmovq",
}

X87_MNEMONICS = {
    "fld", "fld1", "fldz", "fldpi", "fldl2e", "fldlg2", "fldln2", "fldl2t",
    "fst", "fstp", "fxch", "fadd", "faddp", "fiadd", "fsub", "fsubp",
    "fsubr", "fsubrp", "fisub", "fisubr", "fmul", "fmulp", "fimul", "fdiv",
    "fdivp", "fdivr", "fdivrp", "fidiv", "fidivr", "fprem", "fprem1",
    "fsqrt", "fabs", "fchs", "frndint", "fscale", "fxtract", "fcom", "fcomp",
    "fcompp", "fcomi", "fcomip", "fucom", "fucomp", "fucompp", "fucomi",
    "fucomip", "fcmovb", "fcmove", "fcmovbe", "fcmovu", "fcmovnb", "fcmovne",
    "fcmovnbe", "fcmovnu", "fnstsw", "fstsw", "fnstcw", "fstcw", "fnstenv",
    "fstenv", "fnsave", "fsave", "frstor", "fldenv", "fild", "fist", "fistp",
    "fisttp", "fbld", "fbstp", "fnop", "fwait", "finit", "fninit", "fclex",
    "fnclex", "fdecstp", "fincstp", "ffree", "ffreep", "fsin", "fcos",
    "fsincos", "fptan", "fpatan", "f2xm1", "fyl2x", "fyl2xp1",
    "wait", "fldcw",  # capstone 9B = "wait"（=fwait 别名）
    "ficom", "ficomp",  # x87 整数比较
}

# DIRECT 公共面（div/idiv、push imm、movsxd 按 arch 在 classify 分叉）。
DIRECT_COMMON = (
    {"mov", "lea", "add", "sub", "adc", "sbb", "and", "or", "xor", "cmp",
     "test", "inc", "dec", "neg", "not", "shl", "shr", "sar", "rol", "ror",
     "imul", "mul", "movzx", "movsx", "bswap", "xchg", "xadd", "cmpxchg",
     "jmp", "call", "ret", "nop", "push", "pop", "cdq", "cwde", "cbw",
     "cdqe", "cld", "leave", "movd", "movq", "movabs",
     "bts", "btr", "btc"}  # bt 位测试族 = X5b B.4 bitreg 翻正后 direct
    | JCC16 | SETCC16 | CMOVCC16 | SSE_DIRECT
    | {"andn", "bzhi", "rorx", "shlx", "sarx", "shrx", "popcnt", "lzcnt",
       "tzcnt"}
    | VEX_DIRECT
    # plain + rep 串 S8/S32/S64（X2a 收面）；S16 串形维持 gate。
    | {"movsb", "movsd", "movsq", "stosb", "stosd", "stosq", "lodsb",
       "lodsd", "lodsq", "scasb", "scasd", "scasq", "cmpsb", "cmpsd",
       "cmpsq"}
    | {"cqo"}  # x64 cqo 配 idiv（capstone 独立 id，产品 X86_INS_CQO）
)

STRING_S16 = {"movsw", "stosw", "lodsw", "scasw", "cmpsw"}  # G3 S16 砍面维持

SYSTEM_GATE = {
    "int", "int1", "into", "iret", "iretd", "iretq", "in", "insw", "out",
    "outsw", "cli", "sti", "hlt", "sysenter", "sysexit", "syscall", "sysret",
    "rdmsr", "wrmsr", "cpuid", "ltr", "lldt", "lgdt", "lidt", "sgdt", "sidt",
    "str", "sldt", "lar", "lsl", "verr", "verw", "invd", "wbinvd", "std",
    "pushf", "popf", "pushfd", "popfd", "pushfq", "popfq", "sahf", "lahf",
    "emms", "sfence", "mfence", "lfence", "femms", "prefetchnta", "movbe",
    "crc32", "enter", "loop", "loope", "loopne", "jecxz", "jrcxz", "xlat",
    "rdfsbase", "rdgsbase", "wrfsbase", "wrgsbase",
}

MMX_REGS = {getattr(cx, nm) for nm in dir(cx)
            if nm.startswith("X86_REG_MM") and nm[10:].isdigit()}

# capstone X86_INS_<UPPER> 反查表：脚本 ↔ 产品 lifter case 集合一致性断言用。
_MNEMONIC_TO_INS = {}
for _name in dir(cx):
    if _name.startswith("X86_INS_"):
        _MNEMONIC_TO_INS.setdefault(_name[len("X86_INS_"):].lower(), _name)


def product_whitelist_ids(repo_root: Path) -> set:
    """解析 x86_translate.cpp 全部 case X86_INS_*（产品 lifter 白名单真源，
    含注释外代码；与直接 grep 同口径）。"""
    src = repo_root / "passes" / "lifter" / "src" / "x86_translate.cpp"
    toks = set()
    for line in src.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.split("//", 1)[0]
        i = 0
        while True:
            i = s.find("X86_INS_", i)
            if i < 0:
                break
            j = i + len("X86_INS_")
            while j < len(s) and (s[j].isalnum() or s[j] == "_"):
                j += 1
            toks.add(s[i:j])
            i = j
    return toks


def assert_whitelist_consistency(direct_mnemonics: set, product: set):
    """断言脚本 DIRECT 集 ⊆ 产品 lifter case 集（§E：漂移即误报数据）。"""
    problems = []
    for mn in sorted(direct_mnemonics):
        ins = _MNEMONIC_TO_INS.get(mn)
        if ins is None:
            problems.append(f"{mn}: 无 X86_INS_* 常量可断言")
        elif ins not in product:
            problems.append(f"{mn}: 产品 lifter 无 case {ins} —— 脚本漂移")
    if problems:
        raise SystemExit("[FATAL] 白名单一致性断言失败:\n  " + "\n  ".join(problems))
    # 反向披露：产品有而脚本未分类的 case（人工核对，不阻断）
    mine = {_MNEMONIC_TO_INS[m] for m in direct_mnemonics if m in _MNEMONIC_TO_INS}
    extra = sorted(p for p in product if p not in mine)
    return extra


# ---------------------------------------------------------------------------
# PE 解析（手搓，X0 §9.1 口径；x64 附带 .pdata 函数表 + 导出表种子）
# ---------------------------------------------------------------------------

def _sections(data, e_lfanew, opt, opt_size, nsec):
    sec0 = opt + opt_size
    out = []
    for i in range(nsec):
        off = sec0 + i * 40
        if off + 40 > len(data):
            break
        name = data[off:off + 8].rstrip(b"\0").decode("latin1")
        vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, off + 8)
        chars = struct.unpack_from("<I", data, off + 36)[0]
        out.append({"name": name, "vsize": vsize, "vaddr": vaddr,
                    "rsize": rsize, "rptr": rptr, "exec": bool(chars & 0x20000000)})
    return out


def parse_pe(data: bytes):
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 26 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return None
    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
    secs = _sections(data, e_lfanew, opt, opt_size, nsec)
    text = next((s for s in secs if s["name"] == ".text"), None) or \
        next((s for s in secs if s["exec"] and s["rsize"]), None)
    if text is None:
        return None
    pdata = next((s for s in secs if s["name"] == ".pdata" and s["rsize"]), None)

    exports = []
    try:
        dd_off = opt + (112 if magic == 0x20B else 96)
        exp_rva, _exp_size = struct.unpack_from("<II", data, dd_off)
        if exp_rva:
            fo = _rva2off(secs, exp_rva)
            nfuncs = struct.unpack_from("<I", data, fo + 0x14)[0]
            af_rva = struct.unpack_from("<I", data, fo + 0x1C)[0]
            if af_rva:
                afo = _rva2off(secs, af_rva)
                for k in range(min(nfuncs, 300)):
                    frva = struct.unpack_from("<I", data, afo + k * 4)[0]
                    if frva:
                        exports.append(frva)
    except Exception:
        pass

    pdata_list = []
    if pdata and machine == 0x8664:
        try:
            for i in range(pdata["rsize"] // 12):
                b, e, _u = struct.unpack_from("<III", data,
                                              pdata["rptr"] + i * 12)
                if e > b:
                    pdata_list.append((b, e))
        except Exception:
            pass
    return {
        "machine": machine, "entry_rva": entry_rva,
        "text": data[text["rptr"]:text["rptr"] + text["rsize"]],
        "text_va": text["vaddr"], "pdata": pdata_list, "exports": exports,
    }


def _rva2off(secs, rva):
    for s in secs:
        if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rsize"]):
            return s["rptr"] + (rva - s["vaddr"])
    raise ValueError("rva out of sections")


# ---------------------------------------------------------------------------
# 扫描核
# ---------------------------------------------------------------------------

# 需要函数级归因的 gate 族（X6b 三面 + x87 B 路线 + SEH/67 + SSE 残余）。
FUNC_FAMILIES = {"x87", "seg_override", "p67", "sse_residual", "div_gate",
                 "push_imm", "indirect_jmp", "push_mem", "string_s16",
                 "shld_shrd", "system_legacy"}


def scan_file(path: Path, mode):
    """capstone 线性全扫 + skipdata（X0 §9.1 口径；性能档 = disasm_lite 主
    通道 + op_str 形级分类，另见 cross_check_shapes detail 通道交叉校验）。
    返回记录 dict 或 None。"""
    try:
        data = path.read_bytes()
    except OSError as e:
        return {"error": str(e)}
    pe = parse_pe(data)
    if pe is None or pe["machine"] not in (0x14C, 0x8664):
        return None
    want = 0x8664 if mode == CS_MODE_64 else 0x14C
    if pe["machine"] != want:
        return None

    md = Cs(CS_ARCH_X86, mode)
    md.skipdata = True

    mn = Counter()
    fam = Counter()
    shape = Counter()
    seg = Counter()
    data_bytes = 0
    raw = 0
    gate_hits = []  # [(addr, family)] 稀疏表，x64 .pdata 函数归因用

    text, base_va = pe["text"], pe["text_va"]
    ptr = 8 if mode == CS_MODE_64 else 4

    for addr, size, m, op_str in md.disasm_lite(text, base_va):
        raw += 1
        off = addr - base_va
        b0 = text[off]
        if m == ".byte" or m == "(bad)":
            data_bytes += 1
            continue
        if " " in m:  # capstone lite: "rep movsd"/"lock xadd" 形 → 归一本体
            pre, rest = m.split(" ", 1)
            if pre in ("rep", "repe", "repne", "lock", "notrack", "bnd"):
                m = rest
        mn[m] += 1

        # 前导 legacy 前缀扫描（编码定义：前缀必居最前；X0 §9.1 计数器全集）
        s = [0, 0, 0, 0]  # [0]=lock/rep [1]=seg [2]=66 [3]=67
        i = 0
        while i < size and i < 15:
            b = text[off + i]
            if b == 0xF0:
                s[0] = b
            elif b in (0xF2, 0xF3):
                if not s[0]:
                    s[0] = b
            elif b in SEG_FIRST:
                if not s[1]:
                    s[1] = b
            elif b == 0x66:
                if not s[2]:
                    s[2] = b
            elif b == 0x67:
                if not s[3]:
                    s[3] = b
            elif 0x40 <= b <= 0x4F and mode == CS_MODE_64:
                break  # REX 终止 legacy 前缀区
            else:
                break
            i += 1

        # 字节级族计数（X0 §9.1 全套）
        if b0 in X87_FIRST_BYTES or m in X87_MNEMONICS:
            fam["x87"] += 1
        if mode == CS_MODE_32:
            if b0 in (0xC4, 0xC5) and m.startswith("v"):
                fam["vex"] += 1
        else:
            if b0 in (0xC4, 0xC5):
                fam["vex"] += 1
        if b0 in SEG_FIRST:
            seg[SEG_FIRST[b0]] += 1
        if s[1]:
            fam["seg_override"] += 1
        if s[2]:
            fam["p66"] += 1
        if s[3]:
            fam["p67"] += 1
        if s[0] == 0xF0:
            fam["lock"] += 1
        elif s[0] in (0xF2, 0xF3):
            fam["rep"] += 1

        # shape 级计数（X6b 三面 + 残 gate 族；op_str 分类，交叉校验见
        # cross_check_shapes）
        f = None
        head = op_str.split(",", 1)[0].strip()
        is_mem = "[" in head
        is_imm = bool(head) and (head[0] in "0123456789-") and not is_mem
        if m == "push":
            if is_mem:
                shape["push_mem"] += 1
                f = "push_mem"
            elif is_imm:
                shape["push_imm"] += 1
                f = "push_imm" if mode == CS_MODE_64 else None
                # 编码宽度拆分（x64 sext 面实施输入：6A=imm8 sext / 68=imm32）
                if b0 == 0x6A:
                    shape["push_imm8_sext"] += 1
                elif b0 == 0x68:
                    shape["push_imm32"] += 1
            else:
                shape["push_reg"] += 1
        elif m == "jmp":
            if is_mem:
                if f"*{ptr}" in head:
                    shape["jmp_mem_table"] += 1  # 静态可表化形候选（413 复用）
                else:
                    shape["jmp_mem_plain"] += 1  # 任意 mem 形（L，拒做挂账）
                f = "indirect_jmp"
            elif not is_imm:
                shape["jmp_reg"] += 1
                f = "indirect_jmp"
        elif m in ("div", "idiv"):
            shape["div_idiv"] += 1
            if mode == CS_MODE_32:
                f = "div_gate"  # X6b 面：x86 runtime handler 缺（批二默认补）
        elif m == "call":
            if is_mem:
                shape["call_mem"] += 1
            elif not is_imm:
                shape["call_reg"] += 1
        elif m == "ret":
            if op_str.strip():
                shape["ret_imm16"] += 1
        elif m in ("movd", "movq"):
            if re.search(r"(?<![xw])mm[0-7]", op_str):
                shape["mmx_form"] += 1
                f = "mmx"
        elif m in ("bt", "bts", "btr", "btc"):
            if not is_mem:
                shape["bitreg_form"] += 1  # X5b B.4 翻正后 direct，informational
        if f is None:
            if m in STRING_S16:
                f = "string_s16"
            elif m in SSE_RESIDUAL:
                f = "sse_residual"
            elif m in ("shld", "shrd"):
                f = "shld_shrd"
            elif m in SYSTEM_GATE:
                f = "system_legacy"
        if f is not None:
            fam[f] += 1
            if f in FUNC_FAMILIES:
                gate_hits.append((addr, f))

    clean = sum(v for k, v in mn.items() if k not in NOISE_MNEMONICS)
    noise = sum(v for k, v in mn.items() if k in NOISE_MNEMONICS)
    return {
        "file": str(path), "size_bytes": path.stat().st_size,
        "machine": pe["machine"], "raw_insns": raw, "clean_insns": clean,
        "noise_insns": noise, "data_bytes": data_bytes,
        "families": dict(fam), "segments": dict(seg), "shapes": dict(shape),
        "mnemonics": dict(mn), "n_pdata_funcs": len(pe["pdata"]),
        "n_export_seeds": len(pe["exports"]), "gate_hits": gate_hits,
        "pdata": pe["pdata"], "entry_rva": pe["entry_rva"],
        "text_va": base_va,
    }


def cross_check_shapes(path: Path, mode):
    """单文件 detail 通道 vs op_str 通道 shape 计数交叉校验（一致性断言
    扩展到形级解析：两通道不等即 Fatal，防误报数据）。"""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    pe = parse_pe(data)
    if pe is None:
        return None
    md = Cs(CS_ARCH_X86, mode)
    md.skipdata = True
    md.detail = True
    d1 = Counter()
    text, base = pe["text"], pe["text_va"]
    ptr = 8 if mode == CS_MODE_64 else 4
    for insn in md.disasm(text, base):
        if insn.id == 0 or insn.mnemonic in (".byte", "(bad)"):
            continue
        m = insn.mnemonic
        ops = insn.operands
        op0 = ops[0] if ops else None
        if m == "push":
            if op0.type == 1:
                d1["push_reg"] += 1
            elif op0.type == 2:
                d1["push_imm"] += 1
                # 编码宽度拆分（与 op_str 通道同判据：首字节 6A/68）
                if insn.bytes[0] == 0x6A:
                    d1["push_imm8_sext"] += 1
                elif insn.bytes[0] == 0x68:
                    d1["push_imm32"] += 1
            elif op0.type == 3:
                d1["push_mem"] += 1
        elif m == "jmp" and op0 is not None:
            if op0.type == 1:
                d1["jmp_reg"] += 1
            elif op0.type == 3:
                if op0.mem.index != 0 and op0.mem.scale == ptr:
                    d1["jmp_mem_table"] += 1
                else:
                    d1["jmp_mem_plain"] += 1
        elif m == "call" and op0 is not None and op0.type != 2:
            d1["call_" + ("reg" if op0.type == 1 else "mem")] += 1
        elif m == "ret" and ops:
            d1["ret_imm16"] += 1
        elif m in ("div", "idiv"):
            d1["div_idiv"] += 1
        elif m in ("movd", "movq") and any(
                o.type == 1 and o.reg in MMX_REGS for o in ops):
            d1["mmx_form"] += 1
        elif m in ("bt", "bts", "btr", "btc") and op0 is not None and op0.type == 1:
            d1["bitreg_form"] += 1
    rec = scan_file(path, mode)
    s2 = rec["shapes"]
    diffs = {k: (d1.get(k, 0), s2.get(k, 0))
             for k in set(d1) | set(s2) if d1.get(k, 0) != s2.get(k, 0)}
    if diffs:
        raise SystemExit(f"[FATAL] 形级交叉校验失败 {path.name}: {diffs}")
    return dict(s2)


def scan_recursive(path: Path, mode, cap=150000):
    """X0 §1.1 递归对账通道（x86 误差界）：种子 = entry + 导出表(≤300)，
    BFS；每地址解线性游程至不可解（skipdata 关闭 = 非代码天然止损），游程内
    直接转移目标入队；单跑 ≤cap 指令（X0 实测 ntdll 磨穿 → 上限截断）。"""
    data = path.read_bytes()
    pe = parse_pe(data)
    if pe is None:
        return None
    md = Cs(CS_ARCH_X86, mode)
    md.detail = True
    text, base = pe["text"], pe["text_va"]
    stack = [base + pe["entry_rva"]] + [base + r for r in pe["exports"]]
    seen = set()
    fam = Counter()
    mn_seen = Counter()
    n = 0
    while stack and n < cap:
        a = stack.pop()
        if a in seen or not (base <= a < base + len(text)):
            continue
        seen.add(a)  # 游程头
        run = md.disasm(text[a - base:], a)
        for insn in run:
            if n >= cap:
                break
            n += 1
            m = insn.mnemonic
            mn_seen[m] += 1
            x = insn  # shim 访问器（operands/prefix）
            if insn.bytes[0] in X87_FIRST_BYTES or m in X87_MNEMONICS:
                fam["x87"] += 1
            if insn.prefix[1] != 0:
                fam["seg_override"] += 1
            if m in ("div", "idiv"):
                fam["div_gate"] += 1
            if m in SSE_RESIDUAL:
                fam["sse_residual"] += 1
            if m in NOISE_MNEMONICS:
                fam["noise"] += 1
            if insn.operands and insn.operands[0].type == 2 and \
                    (m in JCC16 or m in ("jmp", "call")):
                stack.append(insn.operands[0].imm)
            if m == "ret":
                break  # 游程止于 ret（保守；call 之后的新游程由目标入队补）
    return {"file": str(path), "reachable": n, "families": dict(fam),
            "n_export_seeds": len(pe["exports"])}


# ---------------------------------------------------------------------------
# 三态分类（X6 后；arch 分叉）
# ---------------------------------------------------------------------------

def classify(mode, mn, shape):
    """三态计数（分母 = clean；noise 族先行剔除）。返回 (direct, gates)。"""
    arch = "x64" if mode == CS_MODE_64 else "x86"
    direct = 0
    gates = Counter()
    for m, c in mn.items():
        if m in NOISE_MNEMONICS:
            continue
        if m in X87_MNEMONICS:
            gates["x87"] += c
        elif m in STRING_S16:
            gates["string_s16"] += c
        elif m in SSE_RESIDUAL:
            gates["sse_residual"] += c
        elif m in ("shld", "shrd"):
            gates["shld_shrd"] += c
        elif m in SYSTEM_GATE:
            gates["system_legacy"] += c
        elif m in ("div", "idiv"):
            if arch == "x86":
                gates["div_x86"] += c   # X6b 面（批二默认补，读数照出）
            else:
                direct += c             # x64 = build_div_idiv 真 handler
        elif m == "bt":
            gates["bt"] += c
        elif arch == "x86" and m == "movsxd":
            gates["movsxd_x86_unreachable"] += c
        elif m in DIRECT_COMMON or (arch == "x64" and m == "movsxd"):
            direct += c
        else:
            gates["other_missing"] += c
    # shape 级修正（mnemonic direct 内的形级 gate）
    if arch == "x64" and shape.get("push_imm"):
        pi = shape["push_imm"]
        direct -= pi
        gates["push_imm_x64"] += pi     # X6b 面：x64 push imm gate
    if shape.get("push_mem"):
        pm = shape["push_mem"]
        direct -= pm
        gates["push_mem"] += pm         # translate_push Mem skip（双 arch 残面）
    ij = shape.get("jmp_reg", 0) + shape.get("jmp_mem_table", 0) + \
        shape.get("jmp_mem_plain", 0)
    if ij:
        direct -= ij
        gates["indirect_jmp"] += ij     # X6b 面
    return direct, gates


# ---------------------------------------------------------------------------
# x64 .pdata 函数级归因（区域级口径；x86 无 .pdata 用文件代理 + 递归对账）
# ---------------------------------------------------------------------------

def attribute_functions(rec):
    """x64：.pdata 函数域 × 稀疏 gate_hits → 每函数命中族集合。"""
    funcs = sorted({(b, e) for (b, e) in rec["pdata"]})
    if not funcs:
        return None
    addrs = [a for a, _f in rec["gate_hits"]]
    fams_by_addr = {}
    for a, f in rec["gate_hits"]:
        fams_by_addr.setdefault(a, set()).add(f)
    starts = [b for b, _e in funcs]
    per_func = []
    for a, f in rec["gate_hits"]:
        i = bisect.bisect_right(starts, a) - 1
        if i >= 0:
            b, e = funcs[i]
            if b <= a < e:
                per_func.append((i, f))
    hit = [set() for _ in funcs]
    for i, f in per_func:
        hit[i].add(f)
    n_with = sum(1 for s in hit if s)
    fam_funcs = Counter()
    for s in hit:
        for f in s:
            fam_funcs[f] += 1
    return {"n_funcs": len(funcs), "n_funcs_any_gate": n_with,
            "funcs_by_family": dict(fam_funcs)}


# ---------------------------------------------------------------------------
# 语料组装
# ---------------------------------------------------------------------------

def build_corpus(quick=False):
    layers = []  # (arch, layer_name, [Path], [absent_names])

    def pick(root, names):
        have = [root / n for n in names if (root / n).exists()]
        miss = [n for n in names if not (root / n).exists()]
        return have, miss

    for root, tag in ((SYSWOW, "syswow"), (SYSTEM32, "system32")):
        arch = "x86" if tag == "syswow" else "x64"
        for layer, names in (("core_os", CORE_OS_NAMES),
                             ("old_runtime", OLD_RUNTIME_NAMES),
                             ("modern_ucrt", MODERN_UCRT_NAMES)):
            have, miss = pick(root, names)
            layers.append((arch, f"{tag}_{layer}", have, miss))

    # random 八分位抽样：大小×mtime 排序 → 8 等分 × 各抽 6（quick=2），
    # seed=436（X0 §1.2 口径重建；与 X0 原逐文件样本不同 —— 披露口径）。
    oct_n = 6 if not quick else 2
    already_x86 = {p.name.lower() for a, l, fs, _ in layers
                   if a == "x86" for p in fs}
    already_x64 = {p.name.lower() for a, l, fs, _ in layers
                   if a == "x64" for p in fs}
    for arch, root, already, exclude_third in (
            ("x86", SYSWOW, already_x86, True),
            ("x64", SYSTEM32, already_x64, False)):
        cands = []
        for p in root.iterdir():
            if p.suffix.lower() not in (".dll", ".exe"):
                continue
            if p.name.lower() in already:
                continue
            try:
                if p.stat().st_size > 0:
                    cands.append(p)
            except OSError:
                continue
        cands.sort(key=lambda p: (p.stat().st_size, p.stat().st_mtime))
        rng = random.Random(436)
        per = len(cands) // 8 + 1
        picks = []
        for i in range(8):
            chunk = cands[i * per:(i + 1) * per]
            if chunk:
                picks.extend(rng.sample(chunk, min(len(chunk), oct_n)))
        layers.append((arch, f"{'syswow' if arch == 'x86' else 'system32'}_random",
                       sorted(picks, key=str), []))

    # 436 第三方现存子集（x86；PE32 机器感知，家族内按大小取最大 N 个 PE32）
    tp = []
    for root_s, want in THIRD_PARTY_ROOTS:
        root = Path(root_s)
        if not root.exists():
            continue
        pes = []
        for dirpath, _dirs, files in os.walk(root):
            for f in files:
                p = Path(dirpath) / f
                if p.suffix.lower() in (".dll", ".exe"):
                    try:
                        pes.append((p.stat().st_size, p))
                    except OSError:
                        continue
        pes.sort(reverse=True)
        got = 0
        for _sz, p in pes:
            if got >= want:
                break
            try:
                pe = parse_pe(p.read_bytes())
            except OSError:
                continue
            if pe and pe["machine"] == 0x14C:
                tp.append(p)
                got += 1
    layers.append(("x86", "third_party_436subset", sorted(tp, key=str), []))
    return layers


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def git_head(repo: Path):
    try:
        r = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=repo,
                           capture_output=True, text=True, timeout=10)
        return r.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    ap.add_argument("--quick", action="store_true", help="语料抽样缩小档（冒烟）")
    ap.add_argument("--repo-root", default=str(Path(__file__).resolve().parents[2]))
    args = ap.parse_args()
    repo = Path(args.repo_root)
    out_dir = Path(args.out) if args.out else \
        repo / "scripts" / "verifier" / "mit_x7_rescan_out"
    out_dir.mkdir(parents=True, exist_ok=True)

    product = product_whitelist_ids(repo)
    assert_set = set(DIRECT_COMMON)
    extra = assert_whitelist_consistency(assert_set, product)
    print(f"[ok] 白名单一致性断言通过: 脚本 direct {len(assert_set)} 助记符 ⊆ "
          f"产品 lifter case {len(product)} id；产品有而脚本未直接分类 "
          f"{len(extra)} id（arch 分叉/防御面，见 summary.disclosure_unmapped）")
    print("[note] div/idiv、push-imm、间接 jmp 为 arch 分叉面，不进公共断言集;"
          " x87/SSE 残余/串 S16 本就 gate。")

    # 形级交叉校验（detail 通道 vs op_str 通道，单文件双 arch 各一；不等即
    # Fatal——§E 一致性断言扩展到形级解析）。
    for f, m in ((SYSTEM32 / "kernel32.dll", CS_MODE_64),
                 (SYSWOW / "kernel32.dll", CS_MODE_32)):
        if f.exists():
            sh = cross_check_shapes(f, m)
            print(f"[ok] 形级交叉校验通过: {f} ({sum(sh.values()):,} shape 项)")
        else:
            print(f"[warn] 交叉校验文件缺位: {f}")

    layers = build_corpus(quick=args.quick)
    t0 = time.time()
    jsonl = out_dir / "mit_x7_rescan.jsonl"
    summary = {"generated_by": "scripts/verifier/mit_x7_rescan.py",
               "repo_commit": git_head(repo), "corpus_notes": [],
               "layers": []}

    with jsonl.open("w", encoding="utf-8") as fp:
        for arch, layer, files, absent in layers:
            mode = CS_MODE_64 if arch == "x64" else CS_MODE_32
            lay = {"arch": arch, "layer": layer, "files": [], "paths": [],
                   "absent": absent,
                   "raw": 0, "clean": 0, "noise": 0, "data_bytes": 0,
                   "direct": 0, "gates": Counter(), "shapes": Counter(),
                   "families": Counter(), "scanned": 0,
                   "skipped_machine": 0,
                   "func_attr": {"n_funcs": 0, "n_funcs_any_gate": 0,
                                 "funcs_by_family": Counter()}}
            for p in files:
                rec = scan_file(p, mode)
                if rec is None or "error" in rec:
                    lay["skipped_machine"] += 1
                    continue
                d, g = classify(mode, {k: v for k, v in rec["mnemonics"].items()},
                                rec["shapes"])
                rec["classified"] = {"direct": d, "gates": dict(g)}
                if mode == CS_MODE_64:
                    fa = attribute_functions(rec)
                    if fa:
                        rec["func_attr"] = {k: v for k, v in fa.items()
                                            if k != "funcs_by_family"}
                        rec["func_attr"]["funcs_by_family"] = fa["funcs_by_family"]
                        lay["func_attr"]["n_funcs"] += fa["n_funcs"]
                        lay["func_attr"]["n_funcs_any_gate"] += fa["n_funcs_any_gate"]
                        lay["func_attr"]["funcs_by_family"] += Counter(
                            fa["funcs_by_family"])
                else:
                    rec.pop("pdata", None)
                rec.pop("gate_hits", None)  # 稀疏表体积大，jsonl 不留（汇总留）
                fp.write(json.dumps(rec, ensure_ascii=False) + "\n")
                lay["files"].append(p.name)
                lay["paths"].append(str(p))
                lay["raw"] += rec["raw_insns"]
                lay["clean"] += rec["clean_insns"]
                lay["noise"] += rec["noise_insns"]
                lay["data_bytes"] += rec["data_bytes"]
                lay["families"] += Counter(rec["families"])
                lay["shapes"] += Counter(rec["shapes"])
                lay["direct"] += d
                lay["gates"] += g
                lay["scanned"] += 1
            for k in ("gates", "shapes", "families"):
                lay[k] = dict(lay[k])
            lay["func_attr"]["funcs_by_family"] = dict(
                lay["func_attr"]["funcs_by_family"])
            summary["layers"].append(lay)
            print(f"[scan] {arch}/{layer}: n={lay['scanned']} "
                  f"clean={lay['clean']:,} direct={lay['direct']:,} "
                  f"gate={sum(lay['gates'].values()):,}")

    # x86 递归对账（误差界；X0 §1.1 纪律 ≤6 代表文件：每层取第 1 个）
    recon = []
    seen = set()
    for lay in summary["layers"]:
        if lay["arch"] != "x86" or not lay.get("paths"):
            continue
        pth = lay["paths"][0]
        key = Path(pth).name
        if key in seen:
            continue
        seen.add(key)
        r = scan_recursive(Path(pth), CS_MODE_32)
        if r:
            recon.append(r)
            print(f"[recon] {key}: reachable={r['reachable']} "
                  f"fams={r['families']}")
    summary["x86_recursive_recon"] = recon

    summary["disclosure_unmapped"] = extra
    summary["elapsed_sec"] = round(time.time() - t0, 1)
    (out_dir / "mit_x7_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"[done] jsonl={jsonl}")
    print(f"[done] summary={out_dir / 'mit_x7_summary.json'} "
          f"elapsed={summary['elapsed_sec']}s")


if __name__ == "__main__":
    main()
