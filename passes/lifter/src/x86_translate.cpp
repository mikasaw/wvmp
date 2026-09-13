#include "x86_translate.hpp"

namespace wvmp::passes::lifter {

namespace {

using ir::Cond;
using ir::Op;
using ir::Operand;
using ir::Size;

Size pointer_size(ir::Arch arch) { return arch == ir::Arch::X86 ? Size::S32 : Size::S64; }

Size size_from_bytes(unsigned bytes, ir::Arch arch) {
    switch (bytes) {
    case 1: return Size::S8;
    case 2: return Size::S16;
    case 4: return Size::S32;
    case 8: return Size::S64;
    default: return pointer_size(arch); // 0 / 16（xmm）等：数据指令场景退化为指针宽
    }
}

// dst 操作数的访问宽度；dst 无尺寸时看 src，再不行退化为指针宽。
Size data_size(const cs_x86_op* ops, u8 count, ir::Arch arch) {
    for (u8 i = 0; i < count && i < 2; ++i) {
        if (ops[i].size == 1 || ops[i].size == 2 || ops[i].size == 4 || ops[i].size == 8) {
            return size_from_bytes(ops[i].size, arch);
        }
    }
    return pointer_size(arch);
}

// capstone 内存操作数 → ir::MemOperand。
// base/index 不可映射（含 INVALID/RIZ 段寄存器等）时用 Reg::Flags 哨兵；
// 无 index 时 scale 规整为 0。
std::optional<Operand> mem_operand(const x86_op_mem& m) {
    ir::MemOperand out;
    if (auto base = map_reg(m.base)) out.base = *base;
    if (auto index = map_reg(m.index)) {
        out.index = *index;
        out.scale = static_cast<u8>(m.scale);
    }
    out.disp = m.disp;
    return Operand::mem_(out);
}

// 通用操作数转换。REG/IMM/MEM → ir::Operand；寄存器无法映射（xmm 等）→ nullopt。
std::optional<Operand> to_operand(const cs_x86_op& op) {
    switch (op.type) {
    case X86_OP_REG: {
        auto r = map_reg(op.reg);
        if (!r) return std::nullopt;
        return Operand::reg_(*r);
    }
    case X86_OP_IMM:
        return Operand::imm_(static_cast<i64>(op.imm));
    case X86_OP_MEM:
        return mem_operand(op.mem);
    default:
        return std::nullopt;
    }
}

bool is_data_operand(const Operand& o) {
    return o.kind == Operand::Kind::Reg || o.kind == Operand::Kind::Imm ||
           o.kind == Operand::Kind::Mem;
}

TranslateResult ok(ir::Insn insn) { return {TranslateStatus::Ok, insn, {}}; }
// MIT-249 follow-up (issue-09): unsupported()/todo() 接收 (rva, size) 并填
// skipped_ranges, 让 lifter_core 能聚合到 LiftMetadata, 供下游 C1 gate 识别
// IR 缺字节。Ok 时 skipped_ranges 留空。
TranslateResult unsupported(u64 rva, u64 size) {
    TranslateResult r{TranslateStatus::Unsupported, {}, {{rva, size}}};
    return r;
}
TranslateResult todo(u64 rva, u64 size) {
    TranslateResult r{TranslateStatus::Todo, {}, {{rva, size}}};
    return r;
}

TranslateResult translate_mov(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    if (x.op_count != 2) return unsupported(ci.address, ci.size);
    auto d = to_operand(x.operands[0]);
    auto s = to_operand(x.operands[1]);
    if (!d || !s) return unsupported(ci.address, ci.size);

    ir::Insn out;
    out.addr = ci.address;
    out.size = data_size(x.operands, x.op_count, arch);
    out.updates_flags = false;
    if (d->kind == Operand::Kind::Mem && (s->kind == Operand::Kind::Reg || s->kind == Operand::Kind::Imm)) {
        out.op = Op::Store; // 寄存器/立即数 → 内存
        out.dst = *d;
        out.src = *s;
        return ok(out);
    }
    if (d->kind == Operand::Kind::Reg && s->kind == Operand::Kind::Mem) {
        out.op = Op::Load; // 内存 → 寄存器
        out.dst = *d;
        out.src = *s;
        return ok(out);
    }
    if (d->kind == Operand::Kind::Reg &&
        (s->kind == Operand::Kind::Reg || s->kind == Operand::Kind::Imm)) {
        out.op = Op::Mov; // 纯寄存器/立即数搬运
        out.dst = *d;
        out.src = *s;
        return ok(out);
    }
    return unsupported(ci.address, ci.size); // 双内存等非法组合
}

TranslateResult translate_lea(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    if (x.op_count != 2) return unsupported(ci.address, ci.size);
    auto d = to_operand(x.operands[0]);
    auto s = to_operand(x.operands[1]);
    if (!d || !s || d->kind != Operand::Kind::Reg || s->kind != Operand::Kind::Mem) {
        return unsupported(ci.address, ci.size);
    }
    ir::Insn out;
    out.op = Op::Lea;
    out.addr = ci.address;
    out.size = data_size(x.operands, x.op_count, arch);
    out.dst = *d; // lea 不实际访存
    out.src = *s;
    out.updates_flags = false;
    return ok(out);
}

// add/sub/adc/sbb/and/or/xor：允许 src 为内存（v1 约定：不拆 Load，后端展开）。
TranslateResult translate_alu(const cs_insn& ci, const cs_x86& x, ir::Arch arch, Op op) {
    if (x.op_count != 2) return unsupported(ci.address, ci.size);
    auto d = to_operand(x.operands[0]);
    auto s = to_operand(x.operands[1]);
    if (!d || !s || !is_data_operand(*d) || !is_data_operand(*s)) return unsupported(ci.address, ci.size);
    if (d->kind == Operand::Kind::Mem && s->kind == Operand::Kind::Mem) return unsupported(ci.address, ci.size);

    ir::Insn out;
    out.op = op;
    out.addr = ci.address;
    out.size = data_size(x.operands, x.op_count, arch);
    out.dst = *d;
    out.src = *s;
    out.updates_flags = true;
    return ok(out);
}

// not/neg/inc/dec：一元，dst 可为寄存器或内存。
TranslateResult translate_unary(const cs_insn& ci, const cs_x86& x, ir::Arch arch, Op op,
                                bool sets_flags) {
    if (x.op_count != 1) return unsupported(ci.address, ci.size);
    auto d = to_operand(x.operands[0]);
    if (!d || (d->kind != Operand::Kind::Reg && d->kind != Operand::Kind::Mem)) {
        return unsupported(ci.address, ci.size);
    }
    ir::Insn out;
    out.op = op;
    out.addr = ci.address;
    out.size = data_size(x.operands, x.op_count, arch);
    out.dst = *d;
    out.updates_flags = sets_flags;
    return ok(out);
}

// shl/shr/sar/rol/ror：
//   - imm 计数 (C1 /4 ib / C1 /r ib) → src = Operand::imm_(count)
//   - cl  计数 (D3 /5)                → src = Operand::reg_(Rcx)（cl 是 RCX 低 8 位）
//   - 隐式计数 1 (D1 /4)              → src = Operand::imm_(1)（capstone 不报第二操作数）
// 区分依赖 Operand::Kind 现有字段（Reg vs Imm），不改 ir/ 冻结契约头。
// 其他形式（ch/cx 等非 cl 寄存器计数）保守 unsupported，由 C1 gate 兜底。
TranslateResult translate_shift(const cs_insn& ci, const cs_x86& x, ir::Arch arch, Op op) {
    if (x.op_count == 0 || x.op_count > 2) return unsupported(ci.address, ci.size);
    auto d = to_operand(x.operands[0]);
    if (!d || (d->kind != Operand::Kind::Reg && d->kind != Operand::Kind::Mem)) {
        return unsupported(ci.address, ci.size);
    }
    ir::Insn out;
    out.op = op;
    out.addr = ci.address;
    out.size = data_size(x.operands, x.op_count, arch);
    out.dst = *d;
    out.updates_flags = true;
    if (x.op_count == 1) {
        // capstone 对隐式计数 1（D1 /r）只报 1 个操作数
        out.src = Operand::imm_(1);
    } else if (x.operands[1].type == X86_OP_IMM) {
        out.src = Operand::imm_(static_cast<i64>(x.operands[1].imm));
    } else if (x.operands[1].type == X86_OP_REG && x.operands[1].reg == X86_REG_CL) {
        // MIT-301: cl 变体（D3 /5）— cl 是 RCX 低 8 位，用 Reg 区分
        out.src = Operand::reg_(ir::Reg::Rcx);
    } else {
        // ch / cx / 内存等非 cl 寄存器计数：v1 不接, 触发 C1 gate 兜底
        return unsupported(ci.address, ci.size);
    }
    return ok(out);
}

TranslateResult translate_cmp_test(const cs_insn& ci, const cs_x86& x, ir::Arch arch, Op op) {
    if (x.op_count != 2) return unsupported(ci.address, ci.size);
    auto d = to_operand(x.operands[0]);
    auto s = to_operand(x.operands[1]);
    if (!d || !s || !is_data_operand(*d) || !is_data_operand(*s)) return unsupported(ci.address, ci.size);
    if (d->kind == Operand::Kind::Mem && s->kind == Operand::Kind::Mem) return unsupported(ci.address, ci.size);
    ir::Insn out;
    out.op = op;
    out.addr = ci.address;
    out.size = data_size(x.operands, x.op_count, arch);
    out.dst = *d;
    out.src = *s;
    out.updates_flags = true;
    return ok(out);
}

TranslateResult translate_push(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    if (x.op_count != 1) return unsupported(ci.address, ci.size);
    auto d = to_operand(x.operands[0]);
    if (!d || !is_data_operand(*d)) return unsupported(ci.address, ci.size);
    ir::Insn out;
    out.op = Op::Push;
    out.addr = ci.address;
    out.size = data_size(x.operands, x.op_count, arch);
    out.dst = *d;
    out.updates_flags = false;
    return ok(out);
}

TranslateResult translate_pop(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    if (x.op_count != 1) return unsupported(ci.address, ci.size);
    auto d = to_operand(x.operands[0]);
    if (!d || d->kind != Operand::Kind::Reg) return unsupported(ci.address, ci.size);
    ir::Insn out;
    out.op = Op::Pop;
    out.addr = ci.address;
    out.size = data_size(x.operands, x.op_count, arch);
    out.dst = *d;
    out.updates_flags = false;
    return ok(out);
}

// jmp（rel/abs/reg 均为 Jmp，目标在 dst）。MIT-413 (G2-b): 间接内存跳转
// `jmp [mem]`（clang/GCC `jmp [tbl+idx*8]` 平台表）lift 为 Jmp(dst=Mem)——
// 翻译器跳转表匹配器按 MEM 源形态静态展开；非表形态在翻译器侧照旧
// skip → C1 gate（行为与 409 前逐字节一致，仅 gate note 文本由 lifter
// skip 变为 translator skip）。
TranslateResult translate_jmp(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    if (x.op_count != 1) return unsupported(ci.address, ci.size);
    auto d = to_operand(x.operands[0]);
    if (!d) return unsupported(ci.address, ci.size);
    ir::Insn out;
    out.op = Op::Jmp;
    out.addr = ci.address;
    out.size = pointer_size(arch);
    out.dst = *d;
    out.updates_flags = false;
    return ok(out);
}

TranslateResult translate_jcc(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    auto cond = map_cond(static_cast<x86_insn>(ci.id));
    if (!cond) return unsupported(ci.address, ci.size);
    if (x.op_count != 1 || x.operands[0].type != X86_OP_IMM) return unsupported(ci.address, ci.size);
    ir::Insn out;
    out.op = Op::Jcc;
    out.addr = ci.address;
    out.size = pointer_size(arch);
    out.cond = *cond;
    out.dst = Operand::imm_(static_cast<i64>(x.operands[0].imm));
    out.updates_flags = false;
    return ok(out);
}

// MIT-442 (X2a) ①: call [mem] 开口 — IAT thunk `call [__imp_x]` / `call [esp+..]`
// 形 (X0 §1.4: msvbvm60 35% 的 call 是 mem 形)。镜像 409 Jmp(dst=Mem) 先例:
// lift 为 Op::Call(dst=Mem), 翻译器侧按折条可行性裁决。
//
// ⚠️ #33 实测兜底推翻派单预判 (MIT-442 D4 停手披露): 派单 §A.2 "① = Load(目标
// 地址) + 既有 call-reg 通路折条, 零新 VmOp 高置信" 被 asmgen 直读推翻 ——
// build_callgate 的目标只吃 T5(=aux, 翻译期 RVA), 无 reg 值目标通路
// (asmgen.cpp step1: `mov t0, t5; add t0, [ctx+0x110]`), 且 "call reg 可直用"
// 也只是 lifter 白名单级 (translator translate_call 对 Reg/Mem 一律 skip →
// C1 gate, runtime 从未有 call-reg E2E)。折条落地需 CallGate 支持 reg 值目标
// = asmgen 改动 → 本单 D4 红线停手, 归 X3 (GAPS X2a 节 + 样本负例区钉 gate)。
// 本开口零行为变化: lift 成功后 translator 照旧 skip (带 X3 披露 note) →
// C1 整函数原生 byte-identical, 与 call reg 既有行为逐位一致。
TranslateResult translate_call(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    if (x.op_count != 1) return unsupported(ci.address, ci.size);
    if (x.operands[0].type != X86_OP_IMM && x.operands[0].type != X86_OP_REG &&
        x.operands[0].type != X86_OP_MEM) {
        return unsupported(ci.address, ci.size);
    }
    auto d = to_operand(x.operands[0]);
    if (!d) return unsupported(ci.address, ci.size);
    ir::Insn out;
    out.op = Op::Call;
    out.addr = ci.address;
    out.size = pointer_size(arch);
    out.dst = *d;
    out.updates_flags = false;
    return ok(out);
}

TranslateResult translate_ret(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    if (x.op_count > 1) return unsupported(ci.address, ci.size);
    ir::Insn out;
    out.op = Op::Ret;
    out.addr = ci.address;
    out.size = pointer_size(arch);
    out.updates_flags = false;
    if (x.op_count == 1) {
        if (x.operands[0].type != X86_OP_IMM) return unsupported(ci.address, ci.size);
        out.src = Operand::imm_(static_cast<i64>(x.operands[0].imm)); // ret imm16
    }
    return ok(out);
}

// MIT-442 (X2a) ⑥: cbw 载体标记 — 域 28 (与 0..4 string / 5..13 lock /
// 14..18 SSE mul+andn / 19..21 bridge / 22 flagless / 23..27 plain 串形
// 分区连续零重叠; op 限定 Movsx, movsx 常规构造从不写 src2 — 419 §B.1
// 审计纪律)。定义前置于此 (translate_cbw 前向引用)。
constexpr int kExtCbw = 28;

// MIT-442 (X2a) ③: leave (C9) — x86 栈帧主形 epilogue 惯用法 (X0 §1.4: 全语料
// 0.37%, 非 FP 缺口第一名; x64 可执行形态 = 编译器 alloca/EH 函数真产 + 手写)。
// 折叠 = 两既有 IR (零新 VmOp, X0 §7 #9 预判实测成立): SDM 语义 `RSP←RBP;
// Pop RBP` →
//   [Mov{Rsp←Rbp, size=ptr}   ; translator Mov-Rsp 通路现成 (v4 := v5 槽)
//    Pop{Rbp,  size=ptr}]      ; translator Pop 通路现成 (Load+Add, stride 按
//                              ; size 派生 — B.2 栈宽分叉, x64 8B / x86 4B)
// updates_flags=false (SDM: LEAVE 不影响 EFLAGS); extra 通道 = 426 VEX 前置
// IR 先例 (pre_insns 与主 insn 共享机器地址, 顺序执行语义)。
TranslateResult translate_leave(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    (void)x;  // leave 零显式操作数
    const Size sz = pointer_size(arch);
    ir::Insn mv;
    mv.op = Op::Mov;
    mv.addr = ci.address;
    mv.size = sz;
    mv.updates_flags = false;
    mv.dst = Operand::reg_(ir::Reg::Rsp);
    mv.src = Operand::reg_(ir::Reg::Rbp);
    ir::Insn pp;
    pp.op = Op::Pop;
    pp.addr = ci.address;
    pp.size = sz;
    pp.updates_flags = false;
    pp.dst = Operand::reg_(ir::Reg::Rbp);
    TranslateResult r = ok(pp);
    r.extra.push_back(mv);
    return r;
}

// MIT-442 (X2a) ⑥: cbw/cwde (98 族) — 符号扩展主形之一 (X0 §1.4: 低频, MSVC
// 偏好 movsx; "≤1 小时顺路收" 预算内, 双形全收)。
//
// capstone 分裂枚举 (404 CDQE/MOVSXD 同款教训): 98 族按操作数宽分三态 —
//   cwde (98, dst 32 位, x86 主形 / x64 手写面): X86_INS_CWDE 与 X86_INS_CBW
//     双 id 均可报 (模式相关) → 统一经本派发器按 66 前缀判别;
//   cbw  (66 98, dst 16 位, 双 arch 同 id 同语义): 66 落 prefix[2] (B.4 位置
//     判据, 双 arch probe 单测钉死);
//   cdqe (48 98, x64): 独立 id X86_INS_CDQE, 已由 translate_cdqe 归一
//     Movsxd (404), 不经本函数。
//
// cwde (EAX←SX(AX), 双 arch 语义相同) 折条 = 两既有 IR (零新 VmOp):
//   [Movsx{Rax←Rax, size=S32, src_size=S16}  ; VmOp::Movsx word 源符号扩展
//    (槽 = sx64(ax) — build_movsx 恒 qword 写回, 高 32 位被符号位污染)
//    Mov{Rax←Rax, size=S32}]                  ; "mov eax,eax" 零扩展 idiom —
//   ; build_mov S32 writeback 清高 32 位 → 槽 = zext32(sx32(ax)) = 原生 cwde
//   ⚠ 单条 Movsx 直折不可行 (实测代码直读结论, 非纸面): 槽高位污染在后续
//   S64 地址拼装 (emit_address Mov acc,base S64 读全槽) 时错址 — 双 IR 补偿
//   为必要。updates_flags=false (SDM: CWDE/CBW 不影响 EFLAGS)。
//
// cbw (AX←SX(AL), 高 48 位必须保持) 在 64 位槽模型下无既有 op 直折通路
// (Movsx qword 写回污染 + IR 无 16 位合并原语 + IR 层无 scratch 寄存器) —
// 走 translator 载体微程序: Op::Movsx + src2=Imm(28)=kExtCbw (域 28 与
// 0..4 string / 5..13 lock / 14..18 SSE mul / 19..21 bridge / 22 flagless /
// 23..27 plain 串形 分区连续零重叠; op 限定 Movsx, movsx 常规构造从不写
// src2 — 419 §B.1 审计纪律)。
TranslateResult translate_cwde(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    (void)arch;  // cwde 双 arch 语义相同 (EAX←SX(AX)), 槽宽补偿恒 S32
    (void)x;
    ir::Insn sx;
    sx.op = Op::Movsx;
    sx.addr = ci.address;
    sx.size = Size::S32;
    sx.src_size = Size::S16;
    sx.updates_flags = false;
    sx.dst = Operand::reg_(ir::Reg::Rax);
    sx.src = Operand::reg_(ir::Reg::Rax);
    ir::Insn zx;
    zx.op = Op::Mov;
    zx.addr = ci.address;
    zx.size = Size::S32;
    zx.updates_flags = false;
    zx.dst = Operand::reg_(ir::Reg::Rax);
    zx.src = Operand::reg_(ir::Reg::Rax);
    TranslateResult r = ok(zx);
    r.extra.push_back(sx);
    return r;
}

TranslateResult translate_cbw(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    (void)arch;
    (void)x;  // cbw 零显式操作数 (隐式 AL→AX), 判别由调用方按 66 前缀完成
    ir::Insn out;
    out.op = Op::Movsx;                 // 载体 (src2=kExtCbw 标记区分, 见上)
    out.addr = ci.address;
    out.size = Size::S16;               // dst = AX (语义标注; asmgen Movsx
                                        // 不消费 size 字段, 宽度由微程序定)
    out.src_size = Size::S8;
    out.updates_flags = false;
    out.dst = Operand::reg_(ir::Reg::Rax);
    out.src = Operand::reg_(ir::Reg::Rax);
    out.src2 = Operand::imm_(kExtCbw);
    return ok(out);
}

// MIT-442 (X2a) ④ D5: cld — VM flags 无 DF 位 (G3 D1 在案, kFlagsMask 冻结),
// VM 串微程序按 DF=0 展开 (415 既定披露)。cld 语义 = DF←0, 与 VM 假设完全
// 一致 (且 stub 入口 Win64 ABI 本就 DF=0) → no-op 放行 (Op::Nop), 对齐 415
// 既定 DF 判 (D5: 禁新语义发明)。std (DF←1) 无 case → switch default 照旧
// gate: DF=1 输入下串微程序方向错 = 行为错误 (415 披露口径的边界内侧),
// 保守整函数原生; 登记 GAPS「x86 已知 gate 清单」。
TranslateResult translate_cld(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    (void)x;
    ir::Insn out;
    out.op = Op::Nop;
    out.addr = ci.address;
    out.size = pointer_size(arch);
    out.updates_flags = false;
    return ok(out);
}

// imul 三形式（MIT-302）+ MIT-306 MEM 形式扩展：
//   1) imul r, r/m, imm (3-op imm, 69 /r id 或 6B /r ib): dst = src * imm
//   2) imul r, r/m       (2-op, 0F AF /r):              dst = dst * src
//   3) imul r/m          (1-op, F7 /5): 同 mul, lifter 转 Op::Mul 兜底
// MIT-306: 形式 1/2 的 src 操作数可同时为 REG 或 MEM（MSVC /Od 对栈局部变量
// 的乘法默认 codegen 为 REG-MEM / REG-MEM-IMM 形式, 靠 [rsp+disp] 寻址）。
// MEM 形式在 lifter 层直接 emit Operand::mem_(...); 翻译器层把 MEM 折成
// Load + Imul (2-op) 或 Load + Mov + Mov + Imul (3-op imm 处理 dst = [mem]*imm
// 语义)。
// imm 形式 src2=Operand::imm_(imm32)（Insn.src2 字段是 MIT-302 新增的第三个
// 操作数槽）。其余 2 形式只用 dst/src。3 形式与 2 形式都标 updates_flags=true
// （OF/CF 当低半 != 高半时 set，与 add/sub 完全不同；语义由 asmgen 直读
// native imul flags）。
// v1 限制：8-bit 2-op imul 不存在（Intel SDM: IMUL r/m8 仅单操作数 AL 形式；
// 2-op 仅 r16/r32/r64）。`char * char` 由 C/C++ 语义提升到 int，lifter 不会产
// S8 imul——若 capstone 解出 (e.g. 编译器刻意生成), 拒为 unsupported 让 C1 gate
// 兜底。同理 1-op 形式拒 S8 (mul 1-op r/m8 写 AX，与 Rdx:RAx 不一致)。
// MIT-306 改：3-op imm 形式 size 从硬编码 S32 改用 data_size()——REX.W (48 前缀)
// 下 MEM 反汇编全部是 64-bit, 硬编码 S32 会传错。
TranslateResult translate_imul(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    ir::Insn out;
    out.op = Op::Imul;
    out.addr = ci.address;
    out.updates_flags = true;

    // 3-op imm 形式：imul dst, src, imm（src 可 REG 或 MEM；MIT-306 扩 MEM）
    if (x.op_count == 3 && x.operands[2].type == X86_OP_IMM &&
        x.operands[0].type == X86_OP_REG &&
        (x.operands[1].type == X86_OP_REG || x.operands[1].type == X86_OP_MEM)) {
        auto d = map_reg(x.operands[0].reg);
        auto s = to_operand(x.operands[1]);
        if (!d || !s) return unsupported(ci.address, ci.size);
        out.dst = Operand::reg_(*d);
        out.src = *s;
        // MIT-306: 改用 data_size() 取真实位宽（REX.W 下 S64, 否则 S32）。
        // MIT-302 硬编码 S32 对 REX.W + 69 /r id (64-bit imul) 会出错，但当时
        // 测试集 (69 C1, eax/ecx) 恰为 S32, 未触发。MEM 反汇编全是 REX.W,
        // 必须 data_size() 才能正确传 S64。
        out.size = data_size(x.operands, x.op_count, arch);
        if (out.size == Size::S8) return unsupported(ci.address, ci.size);
        out.src2 = Operand::imm_(static_cast<i64>(x.operands[2].imm));
        return ok(out);
    }
    // 2-op 形式：imul dst, src（src 可 REG 或 MEM；MIT-306 扩 MEM）
    if (x.op_count == 2 && x.operands[0].type == X86_OP_REG &&
        (x.operands[1].type == X86_OP_REG || x.operands[1].type == X86_OP_MEM)) {
        auto d = map_reg(x.operands[0].reg);
        auto s = to_operand(x.operands[1]);
        if (!d || !s) return unsupported(ci.address, ci.size);
        out.dst = Operand::reg_(*d);
        out.src = *s;
        out.size = data_size(x.operands, x.op_count, arch);
        if (out.size == Size::S8) return unsupported(ci.address, ci.size); // S8 imul 2-op 不存在
        return ok(out);
    }
    // 1-op 形式（F7 /5, signed rdx:rax = rax * src）—— MSVC /Od 对 `int a * b`
    // 不产此形式（产 2-op 0F AF /r），但 v1 lifter 接住以兜底 F7 /5 字节。语义上
    // 与 Mul（同 1 操作数）一致：低半 bit-exact 相同（imul/mul 对低 N 位结果
    // 完全相同），仅高半 signed/unsigned 解读差异。保守按 Mul 路径发射。
    if (x.op_count == 1 && x.operands[0].type == X86_OP_REG) {
        auto s = map_reg(x.operands[0].reg);
        if (!s) return unsupported(ci.address, ci.size);
        auto sz = data_size(x.operands, x.op_count, arch);
        if (sz == Size::S8) return unsupported(ci.address, ci.size); // S8 mul 写 AX 而非 Rdx:Rax
        out.op = Op::Mul;
        out.dst = Operand::reg_(ir::Reg::Rdx);  // upper half
        out.src = Operand::reg_(*s);
        out.size = sz;
        return ok(out);
    }
    return unsupported(ci.address, ci.size);
}

// mul 单操作数（F7 /4）：unsigned rdx:rax = rax * src。
// 只接寄存器源（内存源触发 C1 gate 兜底）。S8 拒（mul r/m8 写 AX 与 Rdx:Rax 语义
// 不一致，C/C++ 自动提升到 int 由 32-bit mul 处理）。
TranslateResult translate_mul(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    if (x.op_count != 1 || x.operands[0].type != X86_OP_REG) {
        return unsupported(ci.address, ci.size);
    }
    auto s = map_reg(x.operands[0].reg);
    if (!s) return unsupported(ci.address, ci.size);
    auto sz = data_size(x.operands, x.op_count, arch);
    if (sz == Size::S8) return unsupported(ci.address, ci.size);
    ir::Insn out;
    out.op = Op::Mul;
    out.addr = ci.address;
    out.updates_flags = true; // OF/CF 当低半 != 高半时 set
    out.dst = Operand::reg_(ir::Reg::Rdx);  // upper half
    out.src = Operand::reg_(*s);            // 乘数（Rax 是隐式被乘数，asmgen 硬编码）
    out.size = sz;
    return ok(out);
}

// movsxd (REX.W + 0x63 /r)：32→64 位有符号扩展，x64 专用。
// MSVC /Od 默认 codegen REG-REG 与 REG-MEM（RSP 栈上局部变量 / RAX 字段访问）两种：
//   - REG-REG：movsxd rax, edx   → ir::Op::Movsxd, src=Reg
//   - REG-MEM：movsxd rax, [mem] → ir::Op::Movsxd, src=Mem
//   - 字节结构：48/49 (REX.W/.B) | 63 (opcode) | ModR/M | 可选 SIB | 可选 disp8
//   - 关键：movsxd 本身完成 32 位 load + 符号扩展（不分两条 Load + SignExt）。
//     lifter 不拆分，emit Operand::mem_(...); 翻译器折 Load + Movsxd 或 MovsxdMem。
// size 恒为 S64（movsxd 必 32→64）；updates_flags=false（movsxd 不影响 flags）。
TranslateResult translate_movsxd(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    if (x.op_count != 2) return unsupported(ci.address, ci.size);
    // dst 必是 64-bit 寄存器（x86 不支持 movsxd）
    if (x.operands[0].type != X86_OP_REG) return unsupported(ci.address, ci.size);
    auto d = map_reg(x.operands[0].reg);
    if (!d) return unsupported(ci.address, ci.size);
    if (arch != ir::Arch::X64) return unsupported(ci.address, ci.size);

    ir::Insn out;
    out.op = Op::Movsxd;
    out.addr = ci.address;
    out.size = Size::S64;
    out.updates_flags = false;
    out.dst = Operand::reg_(*d);

    if (x.operands[1].type == X86_OP_REG) {
        // movsxd r, r — REG-REG 形式
        auto s = map_reg(x.operands[1].reg);
        if (!s) return unsupported(ci.address, ci.size);
        out.src = Operand::reg_(*s);
        return ok(out);
    }
    if (x.operands[1].type == X86_OP_MEM) {
        // movsxd r, [m] — REG-MEM 形式
        auto m = mem_operand(x.operands[1].mem);
        if (!m) return unsupported(ci.address, ci.size);
        out.src = *m;
        return ok(out);
    }
    return unsupported(ci.address, ci.size);
}

// MIT-315 movzx (0F B6 /r, 可选 REX.W): 8→32/64 位零扩展。
// MIT-345 扩展：0F B7 (16 位源) 形式——8→16/16→32/16→64 zero-extend。
// MSVC /Od 默认 codegen REG-REG 与 REG-MEM（RSP 栈上局部变量 / 复杂寻址）两种：
//   - REG-REG：movzx rax, cl   → ir::Op::Movzx, src=Reg
//   - REG-MEM：movzx rax, [mem] → ir::Op::Movzx, src=Mem
//   - 字节结构：[48] (REX.W 可选) | 0F B6 (opcode, 8 位源) / 0F B7 (16 位源)
//              | ModR/M | 可选 SIB | 可选 disp
//   - 关键：movzx 本身完成 8/16 位 load + 零扩展（不分两条 Load + ZeroExt）。
//     lifter 不拆分，emit Operand::mem_(...); 翻译器折 MovzxMem。
// size 取目的位宽（无 REX.W → S16/S32；有 REX.W → S64）；
// src_size 取源位宽：0F B6 → S8, 0F B7 → S16（MIT-345 新增）。
// updates_flags=false。
TranslateResult translate_movzx(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    if (x.op_count != 2) return unsupported(ci.address, ci.size);
    // dst 必是寄存器
    if (x.operands[0].type != X86_OP_REG) return unsupported(ci.address, ci.size);
    auto d = map_reg(x.operands[0].reg);
    if (!d) return unsupported(ci.address, ci.size);

    // MIT-345: src_size 由 ci.bytes[*] 决定 (0F B6 = 8-bit 源, 0F B7 = 16-bit 源).
    // 字节布局: [66] (0x66 prefix, 16-bit dst) [REX] (0x40-0x4F) [0F] [B6/B7] [ModR/M]
    //   - 无前缀: 0xB6/0xB7 在 ci.bytes[1]
    //   - 有 0x66 或 REX: 0xB6/0xB7 在 ci.bytes[2]
    //   - 两个前缀都有: 0xB6/0xB7 在 ci.bytes[3]
    // 我们扫描 [1..3] 找 B6/B7 (其他字节是 0x0F / REX / 0x66 已知, 不会冲突).
    Size src_size = Size::S8;
    bool found = false;
    for (size_t i = 1; i < ci.size && i < 4; ++i) {
        if (ci.bytes[i] == 0xB6) { src_size = Size::S8; found = true; break; }
        if (ci.bytes[i] == 0xB7) { src_size = Size::S16; found = true; break; }
    }
    if (!found) {
        // 0x0F B6/B7 之外: 不应进入 movzx 分支, 防御性拒绝 (caller 已 ci.id 检查).
        return unsupported(ci.address, ci.size);
    }

    ir::Insn out;
    out.op = Op::Movzx;
    out.addr = ci.address;
    // size 由 data_size() 取目的位宽：movzx ecx, al → S32, movzx rcx, al → S64
    out.size = data_size(x.operands, x.op_count, arch);
    out.src_size = src_size;  // MIT-345: 源位宽 (S8 / S16) 传给翻译器/asmgen
    out.updates_flags = false;
    out.dst = Operand::reg_(*d);

    if (x.operands[1].type == X86_OP_REG) {
        // movzx r, r8/r16 — REG-REG 形式
        auto s = map_reg(x.operands[1].reg);
        if (!s) return unsupported(ci.address, ci.size);
        out.src = Operand::reg_(*s);
        return ok(out);
    }
    if (x.operands[1].type == X86_OP_MEM) {
        // movzx r, [m] — REG-MEM 形式
        auto m = mem_operand(x.operands[1].mem);
        if (!m) return unsupported(ci.address, ci.size);
        out.src = *m;
        return ok(out);
    }
    return unsupported(ci.address, ci.size);
}

// MIT-347 movsx (0F BE / 0F BF, 可选 REX.W): 8/16→32/64 位符号扩展。
// 与 movzx 是对偶指令（movsx 符号扩展 vs movzx 零扩展），两者共用 src_size
// 字段 (S8 / S16) 与 size 字段 (S32 / S64) 的编码方式。
// MSVC /Od 默认 codegen REG-REG 与 REG-MEM 两种：
//   - REG-REG：movsx rax, cl   → ir::Op::Movsx, src=Reg
//   - REG-MEM：movsx rax, [mem] → ir::Op::Movsx, src=Mem
//   - 字节结构：[66] (0x66 prefix 可选, 16-bit dst) [48] (REX.W 可选)
//              | 0F BE (opcode, 8 位源) / 0F BF (16 位源) | ModR/M
//              | 可选 SIB | 可选 disp
//   - 关键：movsx 本身完成 8/16 位 load + 符号扩展（不分两条 Load + SignExt）。
//     lifter 不拆分，emit Operand::mem_(...); 翻译器折 MovsxMem。
// size 取目的位宽（无 REX.W → S32，有 REX.W → S64）；
// src_size 取源位宽：0F BE → S8, 0F BF → S16。
// updates_flags=false（movsx 不影响 CF/OF/SF/ZF/PF）。
TranslateResult translate_movsx(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    if (x.op_count != 2) return unsupported(ci.address, ci.size);
    // dst 必是寄存器
    if (x.operands[0].type != X86_OP_REG) return unsupported(ci.address, ci.size);
    auto d = map_reg(x.operands[0].reg);
    if (!d) return unsupported(ci.address, ci.size);

    // MIT-347: src_size 由 ci.bytes[*] 决定 (0F BE = 8-bit 源, 0F BF = 16-bit 源).
    // 字节布局: [66] (0x66 prefix, 16-bit dst) [REX] (0x40-0x4F) [0F] [BE/BF] [ModR/M]
    //   - 无前缀: 0xBE/0xBF 在 ci.bytes[1]
    //   - 有 0x66 或 REX: 0xBE/0xBF 在 ci.bytes[2]
    //   - 两个前缀都有: 0xBE/0xBF 在 ci.bytes[3]
    // 我们扫描 [1..3] 找 BE/BF (其他字节是 0x0F / REX / 0x66 已知, 不会冲突).
    Size src_size = Size::S8;
    bool found = false;
    for (size_t i = 1; i < ci.size && i < 4; ++i) {
        if (ci.bytes[i] == 0xBE) { src_size = Size::S8; found = true; break; }
        if (ci.bytes[i] == 0xBF) { src_size = Size::S16; found = true; break; }
    }
    if (!found) {
        // 0x0F BE/BF 之外: 不应进入 movsx 分支, 防御性拒绝 (caller 已 ci.id 检查).
        return unsupported(ci.address, ci.size);
    }

    ir::Insn out;
    out.op = Op::Movsx;
    out.addr = ci.address;
    // size 由 data_size() 取目的位宽：movsx ecx, al → S32, movsx rcx, al → S64
    out.size = data_size(x.operands, x.op_count, arch);
    out.src_size = src_size;  // MIT-347: 源位宽 (S8 / S16) 传给翻译器/asmgen
    out.updates_flags = false;
    out.dst = Operand::reg_(*d);

    if (x.operands[1].type == X86_OP_REG) {
        // movsx r, r8/r16 — REG-REG 形式
        auto s = map_reg(x.operands[1].reg);
        if (!s) return unsupported(ci.address, ci.size);
        out.src = Operand::reg_(*s);
        return ok(out);
    }
    if (x.operands[1].type == X86_OP_MEM) {
        // movsx r, [m] — REG-MEM 形式
        auto m = mem_operand(x.operands[1].mem);
        if (!m) return unsupported(ci.address, ci.size);
        out.src = *m;
        return ok(out);
    }
    return unsupported(ci.address, ci.size);
}

// MIT-353 lzcnt (F3 0F BD+rm, 可选 REX.W): BMI1 前导零计数。
// MSVC /Od 默认 codegen REG-REG (mod=11)：
//   - 32-bit (no REX.W):    F3 0F BD C0 = lzcnt eax, eax
//   - 32-bit 不同寄存器:    F3 0F BD C8 = lzcnt ecx, eax
//   - 64-bit (REX.W):       48 F3 0F BD C0 = lzcnt rax, rax
//   - 64-bit 不同寄存器:    48 F3 0F BD C8 = lzcnt rcx, rax
// 字节结构: [48] (REX.W 可选) | F3 0F BD | ModR/M (mod=11 REG-REG; mod=00/01/10
//   MEM 派活单限定不支持)。
//   - lzcnt 2 操作数 (dst + src), src 必 REG (派活单限定不支持 MEM form)。
//   - size 由 REX.W 决定: x.rex bit 3 (REX.W) → S64, 否则 → S32.
//   - updates_flags=false (lzcnt 不改 CF/OF/SF/ZF/PF; BMI1 lzcnt 仅设 ZF
//     根据结果 0/非0, lifter 不关心)。lzcnt 不是 ALU binop, 不调 setcc5.
TranslateResult translate_lzcnt(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    if (x.op_count != 2) return unsupported(ci.address, ci.size);
    // 两个操作数必都是寄存器 (lzcnt r, r REG-REG); MEM 形式派活单限定不支持
    if (x.operands[0].type != X86_OP_REG) return unsupported(ci.address, ci.size);
    if (x.operands[1].type != X86_OP_REG) return unsupported(ci.address, ci.size);
    auto d = map_reg(x.operands[0].reg);
    auto s = map_reg(x.operands[1].reg);
    if (!d || !s) return unsupported(ci.address, ci.size);

    // size 由 REX.W 标志决定: REX.W (0x48..0x4F, bit 3 = 1) → S64, 否则 → S32.
    // 派活单限定仅 32/64-bit REG-REG 形式 (Intel SDM Vol. 2 LZCNT 仅 32/64-bit 寄存器),
    // 8/16-bit lzcnt 不存在 (lifter 防 C1 gate 兜底, 但保留 size_chain 4 路 size)。
    // 注: 这里**不**用 x.rex — capstone 对 lzcnt 的 REX 报告与实际字节位置不一致
    // (与 popcnt 行为相同). 直接扫描 ci.bytes 找 REX byte (0x40-0x4F, 含 F3 前缀
    // 可能掩盖), bit 3 = REX.W.
    bool rex_w = false;
    for (size_t i = 0; i + 1 < ci.size; ++i) {
        if (ci.bytes[i] == 0xF3 && ci.bytes[i + 1] >= 0x40 && ci.bytes[i + 1] <= 0x4F) {
            rex_w = (ci.bytes[i + 1] & 0x08) != 0;
            break;
        }
        if (ci.bytes[i] >= 0x40 && ci.bytes[i] <= 0x4F &&
            ci.bytes[i + 1] == 0xF3) {
            rex_w = (ci.bytes[i] & 0x08) != 0;
            break;
        }
    }

    ir::Insn out;
    out.op = Op::Lzcount;
    out.addr = ci.address;
    out.size = rex_w ? Size::S64 : Size::S32;
    out.updates_flags = false;  // lzcnt 不改 flags
    out.dst = Operand::reg_(*d);
    out.src = Operand::reg_(*s);
    return ok(out);
}

// MIT-353 tzcnt (F3 0F BC+rm, 可选 REX.W): BMI1 末尾零计数。
// MSVC /Od 默认 codegen REG-REG (mod=11)：
//   - 32-bit (no REX.W):    F3 0F BC C0 = tzcnt eax, eax
//   - 32-bit 不同寄存器:    F3 0F BC C8 = tzcnt ecx, eax
//   - 64-bit (REX.W):       48 F3 0F BC C0 = tzcnt rax, rax
//   - 64-bit 不同寄存器:    48 F3 0F BC C8 = tzcnt rcx, rax
// 字节结构: [48] (REX.W 可选) | F3 0F BC | ModR/M (mod=11 REG-REG; mod=00/01/10
//   MEM 派活单限定不支持)。
//   - tzcnt 2 操作数 (dst + src), src 必 REG (派活单限定不支持 MEM form)。
//   - size 由 REX.W 决定: x.rex bit 3 (REX.W) → S64, 否则 → S32.
//   - updates_flags=false (tzcnt 不改 CF/OF/SF/ZF/PF; BMI1 tzcnt 仅设 ZF
//     根据结果 0/非0, lifter 不关心)。tzcnt 不是 ALU binop, 不调 setcc5.
TranslateResult translate_tzcnt(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    if (x.op_count != 2) return unsupported(ci.address, ci.size);
    // 两个操作数必都是寄存器 (tzcnt r, r REG-REG); MEM 形式派活单限定不支持
    if (x.operands[0].type != X86_OP_REG) return unsupported(ci.address, ci.size);
    if (x.operands[1].type != X86_OP_REG) return unsupported(ci.address, ci.size);
    auto d = map_reg(x.operands[0].reg);
    auto s = map_reg(x.operands[1].reg);
    if (!d || !s) return unsupported(ci.address, ci.size);

    // size 由 REX.W 标志决定 (与 lzcnt 同源): 见 translate_lzcnt 注释
    bool rex_w = false;
    for (size_t i = 0; i + 1 < ci.size; ++i) {
        if (ci.bytes[i] == 0xF3 && ci.bytes[i + 1] >= 0x40 && ci.bytes[i + 1] <= 0x4F) {
            rex_w = (ci.bytes[i + 1] & 0x08) != 0;
            break;
        }
        if (ci.bytes[i] >= 0x40 && ci.bytes[i] <= 0x4F &&
            ci.bytes[i + 1] == 0xF3) {
            rex_w = (ci.bytes[i] & 0x08) != 0;
            break;
        }
    }

    ir::Insn out;
    out.op = Op::Tzcount;
    out.addr = ci.address;
    out.size = rex_w ? Size::S64 : Size::S32;
    out.updates_flags = false;  // tzcnt 不改 flags
    out.dst = Operand::reg_(*d);
    out.src = Operand::reg_(*s);
    return ok(out);
}
// MSVC /Od 默认 codegen REG-REG (mod=11)：
//   - 32-bit (no REX.W):    F3 0F B8 C0 = popcnt eax, eax
//   - 32-bit 不同寄存器:    F3 0F B8 C8 = popcnt ecx, eax
//   - 64-bit (REX.W):       48 F3 0F B8 C0 = popcnt rax, rax
//   - 64-bit 不同寄存器:    48 F3 0F B8 C8 = popcnt rcx, rax
// 字节结构: [48] (REX.W 可选) | F3 0F B8 | ModR/M (mod=11 REG-REG; mod=00/01/10
//   MEM 派活单限定不支持)。
//   - popcnt 2 操作数 (dst + src), src 必 REG (派活单限定不支持 MEM form)。
//   - size 由 REX.W 决定: x.rex bit 3 (REX.W) → S64, 否则 → S32.
//   - updates_flags=false (popcnt 不改 CF/OF/SF/ZF/PF; SSE4.2 popcnt 仅设 ZF
//     根据结果 0/非0, lifter 不关心)。popcnt 不是 ALU binop, 不调 setcc5.
TranslateResult translate_popcnt(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    if (x.op_count != 2) return unsupported(ci.address, ci.size);
    // 两个操作数必都是寄存器 (popcnt r, r REG-REG); MEM 形式派活单限定不支持
    if (x.operands[0].type != X86_OP_REG) return unsupported(ci.address, ci.size);
    if (x.operands[1].type != X86_OP_REG) return unsupported(ci.address, ci.size);
    auto d = map_reg(x.operands[0].reg);
    auto s = map_reg(x.operands[1].reg);
    if (!d || !s) return unsupported(ci.address, ci.size);

    // size 由 REX.W 标志决定: REX.W (0x48..0x4F, bit 3 = 1) → S64, 否则 → S32.
    // 派活单限定仅 32/64-bit REG-REG 形式 (Intel SDM Vol. 2 POPCNT 仅 32/64-bit 寄存器),
    // 8/16-bit popcnt 不存在 (lifter 防 C1 gate 兜底, 但保留 size_chain 4 路 size)。
    // 注: 这里**不**用 x.rex 也不**不**用 data_size() — capstone 对 popcnt 的
    // operand size 报告与 REX.W 不一致 (与 movzx/movsx 行为不同). 直接扫描
    // ci.bytes 找 REX byte (0x40-0x4F, 含 F3 前缀可能掩盖), bit 3 = REX.W.
    bool rex_w = false;
    for (size_t i = 0; i + 1 < ci.size; ++i) {
        if (ci.bytes[i] == 0xF3 && ci.bytes[i + 1] >= 0x40 && ci.bytes[i + 1] <= 0x4F) {
            rex_w = (ci.bytes[i + 1] & 0x08) != 0;
            break;
        }
        if (ci.bytes[i] >= 0x40 && ci.bytes[i] <= 0x4F &&
            ci.bytes[i + 1] == 0xF3) {
            rex_w = (ci.bytes[i] & 0x08) != 0;
            break;
        }
    }

    ir::Insn out;
    out.op = Op::Popcnt;
    out.addr = ci.address;
    out.size = rex_w ? Size::S64 : Size::S32;
    out.updates_flags = false;  // popcnt 不改 flags
    out.dst = Operand::reg_(*d);
    out.src = Operand::reg_(*s);
    return ok(out);
}
// MSVC /Od 默认 codegen:
//   - bswap eax       (无 REX.W, S32): 32 位字节反转, 上 32 位 zero-extend
//   - bswap rax       (REX.W,   S64): 64 位字节反转
// MIT-333 bswap reg32/reg64 (0F C8+rd, 可选 REX.W): 字节序反转。
// 字节结构: [48] (REX.W 可选) | 0F C8 (opcode + reg 直接编码) | ModR/M
// bswap 是单操作数 (dst only, no src), ModR/M 字节由 capstone 自动解析
// 为 reg 操作数。
// size 由 REX.W 标志决定: x.rex bit 3 (REX.W) → S64, 否则 → S32.
// 不存在 8/16-bit bswap (Intel SDM Vol. 2 BSWAP), lifter 仅产 S32/S64.
// updates_flags=false (bswap 不影响 CF/OF/SF/ZF/PF)。
TranslateResult translate_bswap(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    if (x.op_count != 1) return unsupported(ci.address, ci.size);
    if (x.operands[0].type != X86_OP_REG) return unsupported(ci.address, ci.size);
    auto d = map_reg(x.operands[0].reg);
    if (!d) return unsupported(ci.address, ci.size);

    // REX.W 检测: x86 capstone 的 x.rex 是 REX 字节 (无 REX 时为 0).
    // REX.W = bit 3 (0x48 与 0x49/0x4A/0x4B/0x4C/0x4D/0x4E/0x4F 均置位)。
    const bool rex_w = (x.rex & 0x08) != 0;

    ir::Insn out;
    out.op = Op::Bswap;
    out.addr = ci.address;
    out.size = rex_w ? Size::S64 : Size::S32;
    out.updates_flags = false;
    out.dst = Operand::reg_(*d);
    return ok(out);
}

// MIT-334 xchg r, r (87 /r, 可选 REX.W): 寄存器/内存交换。
// MSVC /Od 默认 codegen:
//   - xchg rax, rax (48 90)  → 1 字节 REX.W + 0x90, 单操作数隐式 rax → NOP
//   - xchg rax, rbx (48 87 D8) → 3 字节 REX.W + 0x87 + ModR/M
//   - xchg eax, ebx (87 D8)   → 2 字节 (无 REX.W, S32)
// 字节结构: [48] (REX.W 可选) | 87 (opcode) | ModR/M (mod=11 表示 reg-reg)
// 特殊: `48 90` / `90` 是 xchg rax,rax / xchg eax,eax 当 NOP, capstone 自动
// 识别为 X86_INS_NOP (不进入本 case), 走 X86_INS_NOP 分支单独 emit
// ir::Op::Nop (沿用现有 Nop Op, 不加新 enum).
// xchg 是 2 操作数 (dst + src), ModR/M 字节由 capstone 自动解析为 2 个
// reg 操作数. xchg 是对称操作 (Intel SDM: xchg a, b == xchg b, a), 但
// IR 仍按 IR.dst / IR.src 顺序编码 dst 和 src (语义等价).
// size 由 REX.W 标志决定: x.rex bit 3 (REX.W) → S64, 否则 → S32.
// updates_flags=false (xchg 不影响 CF/OF/SF/ZF/PF)。
// MIT-419 (G4): MEM 形式 (xchg [reg], reg) 放开——InterlockedExchange 的
// MSVC 真产物是**裸 xchg [m], r (87 /r, 无 F0; xchg 访存隐式锁)** (probe
// 实证, 2026-08-30), 故无前缀 xchg mem 与 lock xchg mem 两形态都要支持。
// 翻译器折 Load+Xchg+Store 三条 (xchg 对称, 拆条语义等价); 宽度限定
// S32/S64 (S8/S16 xchg mem 形态 handler 防御 no-op, 拒收防静默错)。
TranslateResult translate_xchg(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    if (x.op_count != 2) return unsupported(ci.address, ci.size);
    // xchg 是对称操作, 但 IR 仍按 dst/src 编码 (语义等价). src 必为寄存器
    // (xchg r/m, r 第二操作数必是 r); dst 可 REG 或 MEM。
    if (x.operands[1].type != X86_OP_REG) return unsupported(ci.address, ci.size);
    auto s = map_reg(x.operands[1].reg);
    if (!s) return unsupported(ci.address, ci.size);

    // REX.W 检测: x.rex bit 3 (REX.W) → S64, 否则 → S32.
    const bool rex_w = (x.rex & 0x08) != 0;

    ir::Insn out;
    out.op = Op::Xchg;
    out.addr = ci.address;
    out.size = rex_w ? Size::S64 : Size::S32;
    out.updates_flags = false;
    out.src = Operand::reg_(*s);

    if (x.operands[0].type == X86_OP_REG) {
        auto d = map_reg(x.operands[0].reg);
        if (!d) return unsupported(ci.address, ci.size);
        out.dst = Operand::reg_(*d);
        return ok(out);
    }
    if (x.operands[0].type == X86_OP_MEM) {
        // MEM 形式: lifter 直接 emit Operand::mem_(...), 翻译器折
        // Load + Xchg + Store 三条 (与 cmpxchg MEM 路径同结构)。
        // S8/S16 拒收 (handler 防御 no-op, 放行 = 静默空转; S16 66 前缀入口
        // 已拒, 此处 S8 (86 /r) 防御性收口)。
        if (out.size != Size::S32 && out.size != Size::S64)
            return unsupported(ci.address, ci.size);
        auto m = mem_operand(x.operands[0].mem);
        if (!m) return unsupported(ci.address, ci.size);
        out.dst = *m;
        return ok(out);
    }
    return unsupported(ci.address, ci.size);
}

// MIT-336 setcc r/m8 (0F 90+cc+rm, 16 variants): 条件设置字节。
//   - 字节结构: [0F] [90+cc] [ModR/M] (3 字节；mod=11 REG, mod=00 MEM)
//   - 单操作数 (dst only, no src), size 恒为 S8 (r/m8, 1 字节固定)
//   - 条件码由 capstone `ci.id` 字段识别 (16 variants: SETE/SETNE/SETB/SETBE/
//     SETA/SETAE/SETS/SETNS/SETP/SETNP/SETL/SETLE/SETG/SETGE/SETO/SETNO) —
//     capstone 自动映射到 ir::Cond (复用 Jcc 已有的 16-条件枚举, 不加新 enum)。
//   - setcc reads flags (CF/OF/SF/ZF/PF) 决定结果 0/1, **不**改 flags
//     (updates_flags=false; 与 test/cmp 的"产生 flags"语义相反)。
//   - MEM 形式 (setcc [reg]) lifter 直接 emit Operand::mem_(...); 翻译器折
//     SetccMem (类似 MovsxdMem / MovzxMem 的 REG-MEM 拆条模式)。
TranslateResult translate_setcc(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    if (x.op_count != 1) return unsupported(ci.address, ci.size);
    auto d = to_operand(x.operands[0]);
    if (!d || (d->kind != Operand::Kind::Reg && d->kind != Operand::Kind::Mem)) {
        return unsupported(ci.address, ci.size);
    }
    // 16 setcc variants 全部统一映射到 ir::Cond (与 Jcc 共享 16 条件枚举)。
    auto cond = map_setcc_cond(static_cast<x86_insn>(ci.id));
    if (!cond) return unsupported(ci.address, ci.size);

    ir::Insn out;
    out.op = Op::Setcc;
    out.addr = ci.address;
    out.size = Size::S8;  // r/m8, 1 字节固定
    out.updates_flags = false;  // setcc 不改 flags
    out.cond = *cond;
    out.dst = *d;
    return ok(out);
}

// MIT-339 cmovcc r, r/m (0F 40+cc+rm, 16 variants): 条件移动。
//   - 字节结构：[48] (REX.W 可选) | 0F 40+cc | ModR/M
//     (3 字节 REX.W → 64-bit; 3 字节无 REX.W → 32-bit; mod=11 REG-REG,
//      mod=00 MEM-REG; mod=01/10 派活单限定不支持 → C1 gate 兜底)
//   - 2 操作数 (dst + src)，src 可 REG 或 MEM
//   - 条件码由 capstone `ci.id` 字段识别 (16 variants: CMOVE/CMOVNE/CMOVB/CMOVBE/
//     CMOVA/CMOVAE/CMOVS/CMOVNS/CMOVP/CMOVNP/CMOVL/CMOVLE/CMOVG/CMOVGE/CMOVO/
//     CMOVNO) — capstone 自动映射到 ir::Cond (复用 Jcc/Setcc 已有的 16-条件枚举,
//     不加新 enum; 沿用 MIT-337 setcc 经验)
//   - cmovcc reads flags (CF/OF/SF/ZF/PF) 决定是否赋值 (cond 真则 dst = src,
//     cond 假则 dst 保留), **不**改 flags (updates_flags=false; 与 setcc 同语义)
//   - size 由 REX.W 决定: 无 REX.W → S32, 有 REX.W → S64
//   - MEM 形式 (cmovcc [reg]) lifter 直接 emit Operand::mem_(...); 翻译器折
//     Load + Cmovcc (REG-REG 路径, src 用 [addr] 的值) 一条, 类似 movzx MEM 路径。
TranslateResult translate_cmovcc(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    if (x.op_count != 2) return unsupported(ci.address, ci.size);
    // dst 必是寄存器（cmovcc r/m, r/m 不存在; cmovcc r, r/m 中 r 必是 dst）
    if (x.operands[0].type != X86_OP_REG) return unsupported(ci.address, ci.size);
    // src 可 REG 或 MEM；其他形式（IMM 等）不支持
    if (x.operands[1].type != X86_OP_REG && x.operands[1].type != X86_OP_MEM) {
        return unsupported(ci.address, ci.size);
    }
    auto d = map_reg(x.operands[0].reg);
    if (!d) return unsupported(ci.address, ci.size);

    // 16 cmovcc variants 全部统一映射到 ir::Cond（与 Jcc/Setcc 共享 16 条件枚举）。
    auto cond = map_cmovcc_cond(static_cast<x86_insn>(ci.id));
    if (!cond) return unsupported(ci.address, ci.size);

    // REX.W 检测: x.rex bit 3 (REX.W) → S64, 否则 → S32 (cmovcc 无 8/16-bit 形式)
    const bool rex_w = (x.rex & 0x08) != 0;

    ir::Insn out;
    out.op = Op::Cmovcc;
    out.addr = ci.address;
    out.size = rex_w ? Size::S64 : Size::S32;
    out.updates_flags = false;  // cmovcc 不改 flags
    out.cond = *cond;
    out.dst = Operand::reg_(*d);

    if (x.operands[1].type == X86_OP_REG) {
        // REG-REG: cmovcc r, r
        auto s = map_reg(x.operands[1].reg);
        if (!s) return unsupported(ci.address, ci.size);
        out.src = Operand::reg_(*s);
    } else {
        // REG-MEM: cmovcc r, [m] — 直接 emit Operand::mem_(...), 翻译器折 Load + Cmovcc
        auto m = mem_operand(x.operands[1].mem);
        if (!m) return unsupported(ci.address, ci.size);
        out.src = *m;
    }
    return ok(out);
}

// MIT-404: cdqe (48 98) — 隐式 eax→rax 符号扩展, x64 专用。
// 语义 == movsxd rax, eax → **归一到既有 Op::Movsxd** (D1.1 决策, 不加
// Op::Cdqe): dst=src=Rax 槽, size 恒 S64, 与 translate_movsxd 的 REG-REG
// 路径共用翻译器/asmgen 通路。capstone 对 cdqe 报 0 显式操作数 (隐式)。
// vendored capstone 分裂枚举陷阱: X86_INS_CDQE=452 与 X86_INS_MOVSXD=880 是
// 两个独立枚举 (pip capstone 5.x 合并报 movsxd — 以 vendored 为准, 两个
// case 都要显式收口, MIT-313 教训)。
TranslateResult translate_cdqe(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    (void)x;  // 操作数全隐式 (eax→rax), 无显式操作数可查
    if (arch != ir::Arch::X64) return unsupported(ci.address, ci.size);
    ir::Insn out;
    out.op = Op::Movsxd;      // 归一 (D1.1): cdqe == movsxd rax, eax
    out.addr = ci.address;
    out.size = Size::S64;     // movsxd 必 32→64
    out.updates_flags = false;
    out.dst = Operand::reg_(ir::Reg::Rax);
    out.src = Operand::reg_(ir::Reg::Rax);
    return ok(out);
}

// MIT-404: cdq (99) / cqo (48 99) — 隐式 rax→rdx 符号扩展, 共用新 Op::Cdq。
// 无显式操作数 (全隐式); size 由 REX.W 决定: 无 REX.W → S32 (cdq),
// 有 REX.W → S64 (cqo)。updates_flags=false (Intel SDM: CDQ/CQO 不影响
// EFLAGS)。asmgen build_cdq 按 size 选 native 99 / 48 99 直通。
// 注: cwd (66 99, S16) 的 0x66 落 prefix[0], translate_insn 入口统一拒绝,
// 不可达 — handler 的 S16 分支仅为模板完备的防御路径。
// MIT-X7 批二: x86 cdq 开面（S32 形）—— Div face 必要条件（真实 idiv
// 代码恒有 cdq 前置，无 cdq lift 则 x86 Div 族面只剩无符号 div 孤形，
// 派活单 §B.2 "Div 族 x86 handler" 交付不成形；MIT-404 时点 x86 asmgen
// 未存在故当时限 x64，X3b 已备 build_cdq_x86 S32 真面 handler，本单接线）。
// cqo（REX.W）仍 x64 专属：32 位模式无 REX 前缀，rex_w 恒 false，防御拒。
TranslateResult translate_cdq(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    const bool rex_w = (x.rex & 0x08) != 0;
    if (arch == ir::Arch::X86 && rex_w) return unsupported(ci.address, ci.size);
    ir::Insn out;
    out.op = Op::Cdq;
    out.addr = ci.address;
    out.size = rex_w ? Size::S64 : Size::S32;
    out.updates_flags = false;  // CDQ/CQO 不影响 CF/OF/SF/ZF/PF
    return ok(out);
}

// MIT-404: div (F7 /6) / idiv (F7 /7) — 无符号/有符号除, 单显式操作数 = 除数。
// 隐式 dividend = rdx:rax (S32: edx:eax) **不经 lifter 表达** — dst=Rdx 槽
// tag (对齐 Op::Mul 约定), VM handler 内部从 Rax/Rdx 双槽拼装, 商写 Rax 槽、
// 余写 Rdx 槽 (native 语义直通)。支持 REG + MEM 形式 (capstone 实证
// `F7 31` = div dword ptr [rcx]; MEM 由翻译器折 Load + Div/Idiv, rip 形式
// 除数走既有 LoadRva 通路)。除零/商溢出 = 真 #DE, handler native 直通
// (D2.1 决策, 崩溃行为与未加壳一致)。size 取 S32/S64:
//   - S8 (F6 /6, dividend=AX 写 AL:AH) 与 rdx:rax 双槽协议不符 → 拒 (§F);
//   - S16 需 0x66 prefix, translate_insn 入口已拒。
// updates_flags=true — flags 按 Intel undefined, 处置照抄 build_imul
// (setcc5 捕获同 CPU 真值, 与 native 执行一致, D4.1)。
TranslateResult translate_div_idiv(const cs_insn& ci, const cs_x86& x, ir::Arch arch, Op op) {
    if (x.op_count != 1) return unsupported(ci.address, ci.size);
    auto sz = data_size(x.operands, x.op_count, arch);
    if (sz == Size::S8 || sz == Size::S16) return unsupported(ci.address, ci.size);
    ir::Insn out;
    out.op = op;
    out.addr = ci.address;
    out.size = sz;
    out.updates_flags = true;  // flags undefined — 照抄 build_imul 处置
    out.dst = Operand::reg_(ir::Reg::Rdx);  // 隐式高半槽 tag (对齐 Mul)
    if (x.operands[0].type == X86_OP_REG) {
        auto s = map_reg(x.operands[0].reg);
        if (!s) return unsupported(ci.address, ci.size);
        out.src = Operand::reg_(*s);
        return ok(out);
    }
    if (x.operands[0].type == X86_OP_MEM) {
        auto m = mem_operand(x.operands[0].mem);
        if (!m) return unsupported(ci.address, ci.size);
        out.src = *m;
        return ok(out);
    }
    return unsupported(ci.address, ci.size);
}

// MIT-341 cmpxchg r/m, r (0F B0/B1+rm, mod=11 REG-REG / mod=00 MEM-REG)。
//   - 字节结构：[48] (REX.W 可选) | 0F B0 (S8) | 0F B1 (S16/S32/S64) | ModR/M
//     (mod=11 REG-REG, mod=00 MEM; mod=01/10 派活单限定不支持 → C1 gate 兜底)
//   - 2 操作数 (dst=r/m + src=r), lifter 接收 REG-REG 与 MEM-REG 两种 dst 形式
//   - 隐式累加器 Rax 槽 (8/16/32/64 位由 size 字段决定, 不加新 IR 字段;
//     沿用 pitfall #34 additive enum append-only 不破坏 Insn 布局)
//   - cmpxchg **read** Rax 槽 + dst, **write** dst 与 Rax 槽 (依 cmp 结果),
//     且 **write** flags (CF/OF/SF/ZF/PF 全更新, 与 cmp 同语义); updates_flags=true
//   - size 取真实操作数位宽 (capstone data_size(): r/m8 → S8, r/m32 → S32,
//     r/m64 (REX.W) → S64); S16 cmpxchg 需要 0x66 operand-size prefix,
//     lifter 的 prefix[0] 检查直接拒绝, S16 不走此路径 (派活单限定不支持)
//   - MEM 形式 (cmpxchg [reg], r) lifter 直接 emit Operand::mem_(...) 到 dst;
//     翻译器折 Load + Cmpxchg + Store 三条拆条 (与 setcc MEM 路径同结构)
// MIT-371: SSE 浮点加 addss/addps/addpd (+ MIT-408: addsd 经 (Addss,S64) 编码,
// 字节 F2 0F 58, scalar double)。
// MSVC /Od 默认 codegen REG-REG (mod=11); 对全局浮点/数组直接 emit MEM 形式
// (addss/addsd xmm, [mem], 实测见 MIT-408 §A.1)。
//   - addss xmm1, xmm2/m32  F3 0F 58 /r  (scalar single, 1 element)
//   - addps xmm1, xmm2/m128 0F 58 /r     (packed single, 4 elements)
//   - addpd xmm1, xmm2/m128 66 0F 58 /r  (packed double, 2 elements)
//   - addsd xmm1, xmm2/m64  F2 0F 58 /r  (scalar double, 1 element)
//   - size 字段: addss=ir::Size::S32 (scalar 单精度), addsd=ir::Size::S64
//     (scalar 双精度, 与 packed S64 tag 由 Op 区分), addps/addpd=ir::Size::S64
//     (packed 128-bit; handler 用 movups 全 128-bit 读写)。size 不影响 codegen,
//     仅作形式区分 tag（handler 也按 size 派发）。
//   - updates_flags=false (SSE 浮点加不影响 x86 EFLAGS; MXCSR rounding mode
//     v1 不追踪)。
//
// **XMM 寄存器编码 (关键设计)**:
// 派活单限定不修改 ir/reg.hpp (冻结契约头文件, 沿用 MIT-345/347/349/353 pitfall #34
// additive enum append-only). XMM 寄存器号 0..7 在 IR 层借用现有 ir::Reg 值 0..7
// (Rax..Rdi) — 这些值在 Addss/Addps/Addpd 上下文中**重新解释**为 xmm0..xmm7,
// 而非 GPR. translator 层按 Op 分派识别 "这是 SSE Op, 0..7 = xmm0..7",
// 加 24 偏移映射到 VmContext.regs[24..31] (vm_op.hpp 保留槽位 v24..v31 沿用).
// IR.dst/IR.src.kind 仍为 Kind::Reg, 但 reg 值 0..7 在 SSE Op 语义下
// 复用为 xmm0..xmm7 (asmgen 看到 reg_a/reg_b 在 [24..31] 区间即按 xmm 处理).
//
// MIT-408 (C4b): MEM 形式放开。dst 必为 XMM 寄存器; src 为 XMM 寄存器或
// 内存 (mem_operand 通用通道, :37)。
// MIT-411 (G1-a) 实测结论: "dst=mem 双访存" (addsd [mem],xmm) **在 x86
// ISA 层不存在** — SSE ALU/位运算/比较指令的目标操作数恒为 XMM 寄存器,
// 内存只可能是源 (SDM 编码表 + ml64 A2000 "memory operand not allowed in
// context" + capstone 实证 F2 0F 58 rm=mem 反汇编为 `addsd xmm0,[mem]`)。
// "读→算→写回" 双访存语义在真实代码里 = movsd load + op + movsd store
// 三条指令, 各自 408/MIT-411 已支持。本函数 op0=REG 检查因此是防御性
// 死代码 (对非法手写 IR 仍兜底 unsupported → C1 gate)。
TranslateResult translate_sse_add(const cs_insn& ci, const cs_x86& x, ir::Arch arch, Op op,
                                  ir::Size sz) {
    if (x.op_count != 2) return unsupported(ci.address, ci.size);
    // dst 必是 XMM 寄存器; src 是 XMM 寄存器或内存 (MIT-408: MEM form 放开).
    if (x.operands[0].type != X86_OP_REG) return unsupported(ci.address, ci.size);
    if (x.operands[1].type != X86_OP_REG && x.operands[1].type != X86_OP_MEM)
        return unsupported(ci.address, ci.size);
    // 手动 XMM 编号映射（X86_REG_XMM0..XMM7 → 0..7），不调 to_operand/map_reg
    // (它们对 XMM* 返回 nullopt, 沿用 SEG/xmm 不可映射的现有约定).
    auto xmm_idx = [&](x86_reg r) -> std::optional<u8> {
        switch (r) {
        case X86_REG_XMM0: return static_cast<u8>(0); case X86_REG_XMM1: return static_cast<u8>(1);
        case X86_REG_XMM2: return static_cast<u8>(2); case X86_REG_XMM3: return static_cast<u8>(3);
        case X86_REG_XMM4: return static_cast<u8>(4); case X86_REG_XMM5: return static_cast<u8>(5);
        case X86_REG_XMM6: return static_cast<u8>(6); case X86_REG_XMM7: return static_cast<u8>(7);
        default: return std::nullopt;
        }
    };
    auto di = xmm_idx(x.operands[0].reg);
    if (!di) return unsupported(ci.address, ci.size);
    // IR Insn.dst.reg / IR.src.reg 借用现有 ir::Reg 值 0..7 (Rax..Rdi), 翻译器
    // 层在 dispatch Addss/Addps/Addpd 时识别 "这是 SSE Op, 加 24 偏移 → v24..v31".
    // 用 static_cast 把 u8 xmm 索引写成 ir::Reg 枚举值（编译期已知 0..7 落在
    // ir::Reg 值域内, 编译器接受该 cast）。
    (void)arch;
    ir::Insn out;
    out.op = op;
    out.addr = ci.address;
    out.size = sz;
    out.updates_flags = false;
    out.dst = ir::Operand::reg_(static_cast<ir::Reg>(*di));
    if (x.operands[1].type == X86_OP_MEM) {
        // 内存源: mem_operand 通用通道构造 IR (base/index/scale/disp 齐全),
        // 翻译器折 XmmLoad(临时槽) + Add 两条 (MIT-408).
        auto m = mem_operand(x.operands[1].mem);
        if (!m) return unsupported(ci.address, ci.size);
        out.src = *m;
    } else {
        auto si = xmm_idx(x.operands[1].reg);
        if (!si) return unsupported(ci.address, ci.size);
        out.src = ir::Operand::reg_(static_cast<ir::Reg>(*si));
    }
    return ok(out);
}

// MIT-373: SSE 浮点减 subss/subps/subpd (+ MIT-408: subsd 经 (Subss,S64) 编码,
// 字节 F2 0F 5C, scalar double)。
// 与 translate_sse_add (MIT-371) 同构: XMM 寄存器编码借用 ir::Reg 值 0..7,
// 翻译期加 24 偏移 → VmContext.regs[24..31] (XMM 编码设计见上方 MIT-371 注释块).
//   - subss xmm1, xmm2/m32  F3 0F 5C /r  (scalar single, 1 element)
//   - subps xmm1, xmm2/m128 0F 5C /r     (packed single, 4 elements)
//   - subpd xmm1, xmm2/m128 66 0F 5C /r  (packed double, 2 elements)
//   - subsd xmm1, xmm2/m64  F2 0F 5C /r  (scalar double, 1 element)
//   - size 字段: subss=ir::Size::S32 (scalar 单精度), subsd=ir::Size::S64
//     (scalar 双精度), subps/subpd=ir::Size::S64 (packed 128-bit; handler
//     用 movups 全 128-bit 读写)。size 不影响 codegen, 仅作形式区分 tag。
//   - updates_flags=false (SSE 浮点减不影响 x86 EFLAGS; MXCSR rounding mode
//     v1 不追踪)。
// MIT-408 (C4b): MEM 形式放开。dst 必为 XMM 寄存器; src 为 XMM 寄存器或内存。
TranslateResult translate_sse_sub(const cs_insn& ci, const cs_x86& x, ir::Arch arch, Op op,
                                  ir::Size sz) {
    if (x.op_count != 2) return unsupported(ci.address, ci.size);
    // dst 必是 XMM 寄存器; src 是 XMM 寄存器或内存 (MIT-408: MEM form 放开).
    if (x.operands[0].type != X86_OP_REG) return unsupported(ci.address, ci.size);
    if (x.operands[1].type != X86_OP_REG && x.operands[1].type != X86_OP_MEM)
        return unsupported(ci.address, ci.size);
    // 手动 XMM 编号映射（X86_REG_XMM0..XMM7 → 0..7），不调 to_operand/map_reg
    // (它们对 XMM* 返回 nullopt, 沿用 SEG/xmm 不可映射的现有约定).
    auto xmm_idx = [&](x86_reg r) -> std::optional<u8> {
        switch (r) {
        case X86_REG_XMM0: return static_cast<u8>(0); case X86_REG_XMM1: return static_cast<u8>(1);
        case X86_REG_XMM2: return static_cast<u8>(2); case X86_REG_XMM3: return static_cast<u8>(3);
        case X86_REG_XMM4: return static_cast<u8>(4); case X86_REG_XMM5: return static_cast<u8>(5);
        case X86_REG_XMM6: return static_cast<u8>(6); case X86_REG_XMM7: return static_cast<u8>(7);
        default: return std::nullopt;
        }
    };
    auto di = xmm_idx(x.operands[0].reg);
    if (!di) return unsupported(ci.address, ci.size);
    // IR Insn.dst.reg / IR.src.reg 借用现有 ir::Reg 值 0..7 (Rax..Rdi), 翻译器
    // 层在 dispatch Subss/Subps/Subpd 时识别 "这是 SSE Op, 加 24 偏移 → v24..v31".
    // 用 static_cast 把 u8 xmm 索引写成 ir::Reg 枚举值（编译期已知 0..7 落在
    // ir::Reg 值域内, 编译器接受该 cast）。
    (void)arch;
    ir::Insn out;
    out.op = op;
    out.addr = ci.address;
    out.size = sz;
    out.updates_flags = false;
    out.dst = ir::Operand::reg_(static_cast<ir::Reg>(*di));
    if (x.operands[1].type == X86_OP_MEM) {
        // 内存源: mem_operand 通用通道 (MIT-408), 翻译器折条.
        auto m = mem_operand(x.operands[1].mem);
        if (!m) return unsupported(ci.address, ci.size);
        out.src = *m;
    } else {
        auto si = xmm_idx(x.operands[1].reg);
        if (!si) return unsupported(ci.address, ci.size);
        out.src = ir::Operand::reg_(static_cast<ir::Reg>(*si));
    }
    return ok(out);
}

// MIT-374: SSE 浮点除 divss/divps/divpd (+ MIT-408: divsd 经 (Divss,S64) 编码,
// 字节 F2 0F 5E, scalar double)。
// 与 translate_sse_sub (MIT-373) / translate_sse_add (MIT-371) 同构: XMM 寄存器
// 编码借用 ir::Reg 值 0..7, 翻译期加 24 偏移 → VmContext.regs[24..31]
// (XMM 编码设计见上方 MIT-371 注释块).
//   - divss xmm1, xmm2/m32  F3 0F 5E /r  (scalar single, 1 element)
//   - divps xmm1, xmm2/m128 0F 5E /r     (packed single, 4 elements)
//   - divpd xmm1, xmm2/m128 66 0F 5E /r  (packed double, 2 elements)
//   - divsd xmm1, xmm2/m64  F2 0F 5E /r  (scalar double, 1 element)
//   (capstone 5.0.7 实证: F30F5EC1/0F5EC1/660F5EC1 → divss/divps/divpd xmm0,xmm1)
//   - size 字段: divss=ir::Size::S32 (scalar 单精度), divsd=ir::Size::S64
//     (scalar 双精度), divps/divpd=ir::Size::S64 (packed 128-bit; handler 用
//     movups 全 128-bit 读写)。size 不影响 codegen, 仅作形式区分 tag。
//   - 除零 / NaN / 非规格化语义: 由 handler 内的真 div* 指令在 native MXCSR
//     下保真执行 (与未保护路径同一舍入模式), v1 不额外追踪。
//   - updates_flags=false (SSE 浮点除不影响 x86 EFLAGS; MXCSR rounding mode
//     v1 不追踪)。
// MIT-408 (C4b): MEM 形式放开。dst 必为 XMM 寄存器; src 为 XMM 寄存器或内存。
TranslateResult translate_sse_div(const cs_insn& ci, const cs_x86& x, ir::Arch arch, Op op,
                                  ir::Size sz) {
    if (x.op_count != 2) return unsupported(ci.address, ci.size);
    // dst 必是 XMM 寄存器; src 是 XMM 寄存器或内存 (MIT-408: MEM form 放开).
    if (x.operands[0].type != X86_OP_REG) return unsupported(ci.address, ci.size);
    if (x.operands[1].type != X86_OP_REG && x.operands[1].type != X86_OP_MEM)
        return unsupported(ci.address, ci.size);
    // 手动 XMM 编号映射（X86_REG_XMM0..XMM7 → 0..7），不调 to_operand/map_reg
    // (它们对 XMM* 返回 nullopt, 沿用 SEG/xmm 不可映射的现有约定).
    auto xmm_idx = [&](x86_reg r) -> std::optional<u8> {
        switch (r) {
        case X86_REG_XMM0: return static_cast<u8>(0); case X86_REG_XMM1: return static_cast<u8>(1);
        case X86_REG_XMM2: return static_cast<u8>(2); case X86_REG_XMM3: return static_cast<u8>(3);
        case X86_REG_XMM4: return static_cast<u8>(4); case X86_REG_XMM5: return static_cast<u8>(5);
        case X86_REG_XMM6: return static_cast<u8>(6); case X86_REG_XMM7: return static_cast<u8>(7);
        default: return std::nullopt;
        }
    };
    auto di = xmm_idx(x.operands[0].reg);
    if (!di) return unsupported(ci.address, ci.size);
    // IR Insn.dst.reg / IR.src.reg 借用现有 ir::Reg 值 0..7 (Rax..Rdi), 翻译器
    // 层在 dispatch Divss/Divps/Divpd 时识别 "这是 SSE Op, 加 24 偏移 → v24..v31".
    // 用 static_cast 把 u8 xmm 索引写成 ir::Reg 枚举值（编译期已知 0..7 落在
    // ir::Reg 值域内, 编译器接受该 cast）。
    (void)arch;
    ir::Insn out;
    out.op = op;
    out.addr = ci.address;
    out.size = sz;
    out.updates_flags = false;
    out.dst = ir::Operand::reg_(static_cast<ir::Reg>(*di));
    if (x.operands[1].type == X86_OP_MEM) {
        // 内存源: mem_operand 通用通道 (MIT-408), 翻译器折条.
        auto m = mem_operand(x.operands[1].mem);
        if (!m) return unsupported(ci.address, ci.size);
        out.src = *m;
    } else {
        auto si = xmm_idx(x.operands[1].reg);
        if (!si) return unsupported(ci.address, ci.size);
        out.src = ir::Operand::reg_(static_cast<ir::Reg>(*si));
    }
    return ok(out);
}

// MIT-375: SSE 浮点传送 (movss / movaps / movapd / movups / movupd,
// + MIT-408: movsd 经 (Movss,S64) 编码, 字节 F2 0F 10/11)。
// 与 translate_sse_div 同构: XMM 寄存器编码借用 ir::Reg 值 0..7, 翻译期加 24 偏移 →
// VmContext.regs[24..31] (XMM 编码设计见 MIT-371 注释块).
//   - movss  xmm1, xmm2       F3 0F 10 /r   (标量: **只搬低 32 位, 高 96 位保持不变**;
//     内存源形式 movss xmm,[m32] 的**清零**语义由 XmmLoad handler 的 native
//     movss 直产, SDM: 内存源清零高位)
//   - movsd  xmm1, xmm2/m64   F2 0F 10 /r   (标量: 只搬低 64 位, 高位保持;
//     内存源形式清零高位, 同 movss 语义)
//   - movaps xmm1, xmm2/m128  0F 28 /r      (对齐, 全 128-bit 搬)
//   - movapd xmm1, xmm2/m128  66 0F 28 /r   (对齐, 全 128-bit 搬)
//   - movups xmm1, xmm2/m128  0F 10 /r      (未对齐, 全 128-bit 搬)
//   - movupd xmm1, xmm2/m128  66 0F 10 /r   (未对齐, 全 128-bit 搬)
// capstone 实证: load 方向 reg,reg 报 X86_INS_MOVSS/MOVAPS/MOVAPD/MOVUPS/MOVUPD;
//   store 方向 / MEM 形式 lifter 拒 → C1 gate 兜底保持原生 (MIT-375 限定,
//   MIT-408 放开, 见下)。
//   - size 字段: Movss=ir::Size::S32 (movss), Movss+S64=(movsd),
//     其余 4 条=ir::Size::S64 (movaps/movapd/movups/movupd)。
//   - updates_flags=false.
//
// MIT-408 (C4b): MEM 形式放开 (派活单 §A.3 读/写两类):
//   - dst=Reg, src=Mem  (load 方向): movss/movsd/movaps/movapd/movups/movupd
//     xmm, [mem] → 翻译器 emit_address + XmmLoad (宽度 aux=4/8/16)。
//   - dst=Mem, src=Reg  (store 方向): movss/movsd/movaps/movapd/movups/movupd
//     [mem], xmm → 翻译器 emit_address + XmmStore。
//   - 双 MEM (string movsd A5 报 X86_INS_MOVSD 同 id, capstone 实证) 非法 →
//     unsupported → C1 gate 兜底保持原生。
//   - movaps/movapd 的 mem 形式运行时一律 movups 非对齐语义 (D2: PE 不保证
//     全局 16B 对齐)。
TranslateResult translate_sse_mov(const cs_insn& ci, const cs_x86& x, ir::Arch arch, Op op,
                                  ir::Size sz) {
    if (x.op_count != 2) return unsupported(ci.address, ci.size);
    // 形式矩阵: (Reg,Reg) REG-REG / (Reg,Mem) load / (Mem,Reg) store;
    // (Mem,Mem) string movsd → unsupported (C1 gate 兜底).
    const bool dst_reg = x.operands[0].type == X86_OP_REG;
    const bool dst_mem = x.operands[0].type == X86_OP_MEM;
    const bool src_reg = x.operands[1].type == X86_OP_REG;
    const bool src_mem = x.operands[1].type == X86_OP_MEM;
    if (dst_mem && src_mem) return unsupported(ci.address, ci.size);  // string movsd
    if (!dst_reg && !dst_mem) return unsupported(ci.address, ci.size);
    if (!src_reg && !src_mem) return unsupported(ci.address, ci.size);
    // 手动 XMM 编号映射 (X86_REG_XMM0..XMM7 → 0..7).
    auto xmm_idx = [&](x86_reg r) -> std::optional<u8> {
        switch (r) {
        case X86_REG_XMM0: return static_cast<u8>(0); case X86_REG_XMM1: return static_cast<u8>(1);
        case X86_REG_XMM2: return static_cast<u8>(2); case X86_REG_XMM3: return static_cast<u8>(3);
        case X86_REG_XMM4: return static_cast<u8>(4); case X86_REG_XMM5: return static_cast<u8>(5);
        case X86_REG_XMM6: return static_cast<u8>(6); case X86_REG_XMM7: return static_cast<u8>(7);
        default: return std::nullopt;
        }
    };
    (void)arch;
    ir::Insn out;
    out.op = op;
    out.addr = ci.address;
    out.size = sz;
    out.updates_flags = false;
    if (dst_mem) {
        // store 方向: [mem], xmm (src 必为 XMM 寄存器)
        auto m = mem_operand(x.operands[0].mem);
        if (!m) return unsupported(ci.address, ci.size);
        out.dst = *m;
        auto si = xmm_idx(x.operands[1].reg);
        if (!si) return unsupported(ci.address, ci.size);
        out.src = ir::Operand::reg_(static_cast<ir::Reg>(*si));
        return ok(out);
    }
    auto di = xmm_idx(x.operands[0].reg);
    if (!di) return unsupported(ci.address, ci.size);
    out.dst = ir::Operand::reg_(static_cast<ir::Reg>(*di));
    if (src_mem) {
        // load 方向: xmm, [mem]
        auto m = mem_operand(x.operands[1].mem);
        if (!m) return unsupported(ci.address, ci.size);
        out.src = *m;
    } else {
        auto si = xmm_idx(x.operands[1].reg);
        if (!si) return unsupported(ci.address, ci.size);
        out.src = ir::Operand::reg_(static_cast<ir::Reg>(*si));
    }
    return ok(out);
}

// MIT-376: SSE 浮点位运算 xorps/orps/andps (+ MIT-408: MEM 形式放开)。
// 与 translate_sse_div (MIT-374) 同构: XMM 寄存器编码借用 ir::Reg 值 0..7,
// 翻译期加 24 偏移 → VmContext.regs[24..31] (XMM 编码设计见 MIT-371 注释块).
//   - xorps xmm1, xmm2/m128  0F 57 /r   (bitwise xor, 全 128-bit 按位)
//   - orps  xmm1, xmm2/m128  0F 56 /r   (bitwise or,  全 128-bit 按位)
//   - andps xmm1, xmm2/m128 0F 54 /r    (bitwise and, 全 128-bit 按位)
//   (capstone 实证: 0F57C1/0F56C1/0F54C1 → xorps/orps/andps xmm0, xmm1)
//   - size 字段: 3 条均 ir::Size::S64 (128-bit 整体读写; handler 用 movups)。
//     size 不影响 codegen, 仅作形式区分 tag。
//   - updates_flags=false (SSE 位运算不影响 x86 EFLAGS — 位运算不解释浮点值,
//     不产 NaN/无序; 与 add/sub/div 同口径)。
// MIT-408 (C4b): MEM 形式放开。dst 必为 XMM 寄存器; src 为 XMM 寄存器或内存。
TranslateResult translate_sse_bitwise(const cs_insn& ci, const cs_x86& x, ir::Arch arch, Op op,
                                      ir::Size sz) {
    if (x.op_count != 2) return unsupported(ci.address, ci.size);
    // dst 必是 XMM 寄存器; src 是 XMM 寄存器或内存 (MIT-408: MEM form 放开).
    if (x.operands[0].type != X86_OP_REG) return unsupported(ci.address, ci.size);
    if (x.operands[1].type != X86_OP_REG && x.operands[1].type != X86_OP_MEM)
        return unsupported(ci.address, ci.size);
    // 手动 XMM 编号映射 (X86_REG_XMM0..XMM7 → 0..7), 不调 to_operand/map_reg.
    auto xmm_idx = [&](x86_reg r) -> std::optional<u8> {
        switch (r) {
        case X86_REG_XMM0: return static_cast<u8>(0); case X86_REG_XMM1: return static_cast<u8>(1);
        case X86_REG_XMM2: return static_cast<u8>(2); case X86_REG_XMM3: return static_cast<u8>(3);
        case X86_REG_XMM4: return static_cast<u8>(4); case X86_REG_XMM5: return static_cast<u8>(5);
        case X86_REG_XMM6: return static_cast<u8>(6); case X86_REG_XMM7: return static_cast<u8>(7);
        default: return std::nullopt;
        }
    };
    auto di = xmm_idx(x.operands[0].reg);
    if (!di) return unsupported(ci.address, ci.size);
    (void)arch;
    ir::Insn out;
    out.op = op;
    out.addr = ci.address;
    out.size = sz;
    out.updates_flags = false;
    out.dst = ir::Operand::reg_(static_cast<ir::Reg>(*di));
    if (x.operands[1].type == X86_OP_MEM) {
        // 内存源: mem_operand 通用通道 (MIT-408), 翻译器折条.
        auto m = mem_operand(x.operands[1].mem);
        if (!m) return unsupported(ci.address, ci.size);
        out.src = *m;
    } else {
        auto si = xmm_idx(x.operands[1].reg);
        if (!si) return unsupported(ci.address, ci.size);
        out.src = ir::Operand::reg_(static_cast<ir::Reg>(*si));
    }
    return ok(out);
}

// MIT-376: SSE 浮点比较 ucomiss/ucomisd (+ MIT-408: MEM 形式放开, 派活单 D4
// "ucomis src=mem 必做")。
// 与 translate_sse_bitwise 同构, 关键差异: **updates_flags=true** —
// ucomiss/ucomisd 比较后只写 EFLAGS (ZF/PF/CF), 不改 xmm 操作数; 翻译器
// emit 单条 VmOp::Ucomiss/Ucomisd, 运行时 handler 走 ALU binop 同一条
// flags 通路 (zero5 → native ucomis* → setcc5 → flags_tail), 让区域内
// 紧随的 setcc/jcc 读到真比较结果 (派活单 §C 6 + §D D1.1 决策, 禁止
// decode+advance 空转, pitfall #79)。
//   - ucomiss xmm1, xmm2/m32  0F 2E /r   (标量单精度无序比较, size=S32)
//   - ucomisd xmm1, xmm2/m64  66 0F 2E /r (标量双精度无序比较, size=S64)
//   (capstone 实证: 0F2EC1 → ucomiss, 660F2EC1 → ucomisd, 均 xmm0, xmm1;
//    F3 0F 2E 编码不存在; comiss/comisd = 0F 2F 系, MIT-411 折叠为
//    Ucomiss/Ucomisd (flags 语义逐位相同, 见 translate_insn case 注释))
//   - NaN → unordered → ZF=PF=CF=1, 按 Intel SDM UCOMISD/UCOMISS 真值表
//     (OF/SF/AF 清 0); 完整 x87 式语义细分不做 (D1.1 限定)。
// MIT-408 (C4b): MEM 形式放开。dst 必为 XMM 寄存器; src 为 XMM 寄存器或内存。
TranslateResult translate_ucomis(const cs_insn& ci, const cs_x86& x, ir::Arch arch, Op op,
                                 ir::Size sz) {
    if (x.op_count != 2) return unsupported(ci.address, ci.size);
    // dst 必是 XMM 寄存器; src 是 XMM 寄存器或内存 (MIT-408: MEM form 放开).
    if (x.operands[0].type != X86_OP_REG) return unsupported(ci.address, ci.size);
    if (x.operands[1].type != X86_OP_REG && x.operands[1].type != X86_OP_MEM)
        return unsupported(ci.address, ci.size);
    // 手动 XMM 编号映射 (X86_REG_XMM0..XMM7 → 0..7), 不调 to_operand/map_reg.
    auto xmm_idx = [&](x86_reg r) -> std::optional<u8> {
        switch (r) {
        case X86_REG_XMM0: return static_cast<u8>(0); case X86_REG_XMM1: return static_cast<u8>(1);
        case X86_REG_XMM2: return static_cast<u8>(2); case X86_REG_XMM3: return static_cast<u8>(3);
        case X86_REG_XMM4: return static_cast<u8>(4); case X86_REG_XMM5: return static_cast<u8>(5);
        case X86_REG_XMM6: return static_cast<u8>(6); case X86_REG_XMM7: return static_cast<u8>(7);
        default: return std::nullopt;
        }
    };
    auto di = xmm_idx(x.operands[0].reg);
    if (!di) return unsupported(ci.address, ci.size);
    (void)arch;
    ir::Insn out;
    out.op = op;
    out.addr = ci.address;
    out.size = sz;
    out.updates_flags = true;
    out.dst = ir::Operand::reg_(static_cast<ir::Reg>(*di));
    if (x.operands[1].type == X86_OP_MEM) {
        // 内存源: mem_operand 通用通道 (MIT-408), 翻译器折条.
        auto m = mem_operand(x.operands[1].mem);
        if (!m) return unsupported(ci.address, ci.size);
        out.src = *m;
    } else {
        auto si = xmm_idx(x.operands[1].reg);
        if (!si) return unsupported(ci.address, ci.size);
        out.src = ir::Operand::reg_(static_cast<ir::Reg>(*si));
    }
    return ok(out);
}

// ==================== MIT-425 (G1b): SSE mul 族 + andnps/andnpd/pandn ====================
//
// src2 载体标记域 (与 translator.cpp is_sse_mul_marker/is_andn_marker 对账):
//   14..17 = SSE mul 族 (Op::Mul 载体) / 18 = andn (Op::Andps 载体)。
//   与 string family (0..4) / lock 标记 (5..13) 分区连续零碰撞; src2=imm
//   写入点对账: imul 3-op (op=Imul, 立即数任意 — 翻译器 Mul/Andps 派发
//   必须 op+标记双限定) / 本域唯一。GP mul 与 1-op imul→Mul 路径从不写
//   src2 (Operand 默认 kind=None)。
enum : int { kSseMulSs = 14, kSseMulSd = 15, kSseMulPs = 16, kSseMulPd = 17,
             kSseAndn = 18 };

// MIT-427 (G1c): movd/movq GP↔xmm 桥 src2 标记 — 与 SSE mul/andn (14..18)
// 分域连续 (string 0..4 / lock 5..13 / mul+andn 14..18 / bridge 19..21)。
//   19 kBridgeFromGp:  GP→xmm 桥 (movd/movq xmm, r32/r64 REG 形式), 高位清零
//   20 kBridgeToGp:    xmm→GP 桥 (movd/movq r32/r64, xmm REG 形式), 宽度截取
//   21 kBridgeFromXmm: xmm→xmm 低 64 拷贝 + 目的高 64 清零 (F3 0F 7E / VEX
//                      pp=F3 同语义形态; dst 高位清零是本形态独有语义, 与
//                      66 0F D6 "高 64 保持" 相区分 — 与 426 §F.4 "假 Mov"
//                      同款纪律)
// 载体 = Op::Movss (G3/G4 "op 载体 + src2=imm(族)" 先例): movss 常规构造
// (translate_sse_mov) 从不写 src2, 零碰撞; size 字段 = 桥宽度 (S32=movd /
// S64=movq)。IR 操作数约定 (与 SSE 借用 0..7 惯例对账):
//   kBridgeFromGp:  dst = xmm 索引 0..7 (借用, 翻译期 +24);
//                   src = GP 真寄存器 (map_reg 全值 0..15)
//   kBridgeToGp:    dst = GP 真寄存器 (0..15); src = xmm 索引 0..7 (借用)
//   kBridgeFromXmm: dst/src 均 = xmm 索引 0..7 (借用)
// mem 操作数形态不经标记 — lifter 直接产 (Op::Movss, mem) 既有载体 →
// XmmLoad/XmmStore (408 通路, movss/movsd mem 形式自产清零/截断语义)。
enum : int { kBridgeFromGp = 19, kBridgeToGp = 20, kBridgeFromXmm = 21 };

// MIT-425 (R1): SSE 浮点乘 mulss/mulsd/mulps/mulpd (+ mem 源含 rip 一次
// 到位, 408 通路现成)。与 translate_sse_add 同构: XMM 寄存器编码借用
// ir::Reg 值 0..7, 翻译期加 24 偏移 → VmContext.xmm 槽 (XMM 编码设计见
// translate_sse_add 注释块); IR 编码 = (Op::Mul, src2=imm(marker)) 载体,
// size 字段为形式标签 (ss=S32 / sd,ps,pd=S64, 与 Addss/Addsd/Addps/Addpd
// 同约定)。updates_flags=false (SSE 浮点乘不影响 x86 EFLAGS; MXCSR
// rounding mode v1 不追踪)。
TranslateResult translate_sse_mul(const cs_insn& ci, const cs_x86& x, ir::Arch arch,
                                  ir::Size sz, int marker) {
    if (x.op_count != 2) return unsupported(ci.address, ci.size);
    // dst 必是 XMM 寄存器; src 是 XMM 寄存器或内存 (408: MEM form 放开)。
    if (x.operands[0].type != X86_OP_REG) return unsupported(ci.address, ci.size);
    if (x.operands[1].type != X86_OP_REG && x.operands[1].type != X86_OP_MEM)
        return unsupported(ci.address, ci.size);
    // 手动 XMM 编号映射 (X86_REG_XMM0..XMM7 → 0..7), 不调 to_operand/map_reg
    // (它们对 XMM* 返回 nullopt, 沿用 SEG/xmm 不可映射的现有约定)。
    auto xmm_idx = [&](x86_reg r) -> std::optional<u8> {
        switch (r) {
        case X86_REG_XMM0: return static_cast<u8>(0); case X86_REG_XMM1: return static_cast<u8>(1);
        case X86_REG_XMM2: return static_cast<u8>(2); case X86_REG_XMM3: return static_cast<u8>(3);
        case X86_REG_XMM4: return static_cast<u8>(4); case X86_REG_XMM5: return static_cast<u8>(5);
        case X86_REG_XMM6: return static_cast<u8>(6); case X86_REG_XMM7: return static_cast<u8>(7);
        default: return std::nullopt;
        }
    };
    auto di = xmm_idx(x.operands[0].reg);
    if (!di) return unsupported(ci.address, ci.size);
    (void)arch;
    ir::Insn out;
    out.op = Op::Mul;  // 载体 (src2=族标记区分 SSE/GP, 见上)
    out.addr = ci.address;
    out.size = sz;
    out.updates_flags = false;
    out.src2 = Operand::imm_(marker);
    out.dst = ir::Operand::reg_(static_cast<ir::Reg>(*di));
    if (x.operands[1].type == X86_OP_MEM) {
        // 内存源: mem_operand 通用通道, 翻译器折条 (408 通路)。
        auto m = mem_operand(x.operands[1].mem);
        if (!m) return unsupported(ci.address, ci.size);
        out.src = *m;
    } else {
        auto si = xmm_idx(x.operands[1].reg);
        if (!si) return unsupported(ci.address, ci.size);
        out.src = ir::Operand::reg_(static_cast<ir::Reg>(*si));
    }
    return ok(out);
}

// MIT-425 (R3/R2 档①): andnps/andnpd/pandn → (Op::Andps,
// src2=imm(kSseAndn)) 载体, 翻译器折叠单条 VmOp::Andnps (dst = ~dst & src;
// 三编码逐位同语义 — SDM ANDNPS/ANDNPD/PANDN 均为 128-bit 按位
// NOT(第一操作数) AND 第二操作数, 不解释浮点值)。操作数形状与位运算族
// 完全一致, 复用 translate_sse_bitwise 后补标记。
TranslateResult translate_sse_andn(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    auto r = translate_sse_bitwise(ci, x, arch, Op::Andps, Size::S64);
    if (r.status != TranslateStatus::Ok) return r;
    r.insn.src2 = Operand::imm_(kSseAndn);
    return ok(r.insn);
}

// ==================== MIT-427 (G1c): movd/movq GP↔xmm 桥 ====================
//
// SDM 表 (编码判据全量 #33 probe 实测, vendored capstone 5.0.6, 2026-08-30;
// probe 输出见派单报告对照表):
//   - MOVD  xmm, r32   66 0F 6E /r      id=X86_INS_MOVD (377), prefix[2]=0x66
//   - MOVQ  xmm, r64   66 REX.W 0F 6E   id=X86_INS_MOVQ (378), rex&8
//   - MOVD  r32, xmm   66 0F 7E /r      id=X86_INS_MOVD, prefix[2]=0x66
//   - MOVQ  r64, xmm   66 REX.W 0F 7E   id=X86_INS_MOVQ, rex&8
//   - MOVQ  xmm, xmm   F3 0F 7E /r      id=X86_INS_MOVQ, **prefix 全零**
//     (F3 被吸收进 id — 与 ADDSS/MOVSS 同纪律, 不经入口前缀闸)
//   - MOVQ  xmm, xmm   66 0F D6 /r      id=X86_INS_MOVQ, prefix[2]=0x66
//   **#33 实测推翻先验 (d6_probe 独立 native 探针, 2026-08-30)**: 66 0F D6
//   reg-reg 与 F3 0F 7E 语义**逐位相同** — 低 64 拷贝 + 目的高 64 **清零**
//   (66 0F D6 C8 实测 high=0; SDM MOVQ 条目 register-dest 伪码
//   DEST[127:64] ← 0 同口径)。"仅写 8 字节不触碰高位" 只对 **mem-dest**
//   形式成立 (→ XmmStore 截取通路)。reg-reg 全部 → kBridgeFromXmm。
//   - MOVD/MOVQ mem 操作数形式 (66 0F 6E/7E mem, VEX 同): capstone 报
//     op.size=4/8, 走既有 (Op::Movss, mem) 载体 → XmmLoad/XmmStore (408
//     通路; movss/movsd mem 形式自产清零/截断语义, 逐位等价 movd/movq)。
//   - VEX (B.3, 426 §F.4 ④ 挂账清偿): VMOVD 1025 / VMOVQ 1021, prefix 全零
//     (VEX bits 被 capstone 吸收)。all-xmm VMOVQ 的 D6/F3 语义由 VEX.pp
//     区分 (capstone 不暴露 final opcode — 经 ci.bytes 解析 pp: C5 形
//     bytes[1]&3 / C4 形 bytes[2]&3; pp=1(66)→D6 保持 / pp=2(F3)→清零)。
//     ymm 形态由 translate_vex128 位宽闸 (op.size>16) 拒, xmm8..15 由
//     xmm_idx 不可映射拒 (426 §F.3 同口径)。
//   - **D2 MMX 禁入**: 裸 0F 6E/6F/7E/7F (mm 操作数, 与 x87 共享状态域 —
//     418 永久 gate 面)。probe 实测: NP 0F 6F → id=MOVQ ops=[mm0,mm1] /
//     NP 0F 6E → id=MOVD ops=[mm0,ecx] / NP 0F 7E → id=MOVD — **同 id 混入
//     MMX 形态, mm 操作数判据是唯一可靠闸** (本函数首检查)。
//   - movdqa/movdqu (66/F3 0F 6F/7F, id 468/469) MIT-428 (G1d) 起入面
//     (translate_sse_mov 直复用, 零新 VmOp; 427 时点为砍面留档)。
// 派单方编码自错纠正 (#33): 派单 §A.2 "paddq=66 0F FC" 实测为 PADDB
// (INSID=388); paddq 真值 = 66 0F D4 (425 GAPS 原文正确, 425 仅 psubq 的
// 5C→FB 需修) — paddq/psubq 本单砍面 (频率实测 shell32 16/854k + 其余
// 二进制 0, 见 GAPS G1c 节), 负例样本钉 gate。
TranslateResult translate_movd_movq(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    if (x.op_count != 2) return unsupported(ci.address, ci.size);
    // D2 MMX 闸: 任何 mm 操作数 (X86_REG_MM0..MM7) 一律 unsupported。
    for (int i = 0; i < x.op_count; ++i) {
        if (x.operands[i].type == X86_OP_REG &&
            x.operands[i].reg >= X86_REG_MM0 && x.operands[i].reg <= X86_REG_MM7)
            return unsupported(ci.address, ci.size);
    }
    // 手动 XMM 编号映射 (X86_REG_XMM0..XMM7 → 0..7; xmm8..15 → nullopt = gate)。
    auto xmm_idx = [&](x86_reg r) -> std::optional<u8> {
        switch (r) {
        case X86_REG_XMM0: return static_cast<u8>(0); case X86_REG_XMM1: return static_cast<u8>(1);
        case X86_REG_XMM2: return static_cast<u8>(2); case X86_REG_XMM3: return static_cast<u8>(3);
        case X86_REG_XMM4: return static_cast<u8>(4); case X86_REG_XMM5: return static_cast<u8>(5);
        case X86_REG_XMM6: return static_cast<u8>(6); case X86_REG_XMM7: return static_cast<u8>(7);
        default: return std::nullopt;
        }
    };
    (void)arch;
    const cs_x86_op& op0 = x.operands[0];
    const cs_x86_op& op1 = x.operands[1];
    const bool op0_xmm = op0.type == X86_OP_REG && xmm_idx(op0.reg).has_value();
    const bool op1_xmm = op1.type == X86_OP_REG && xmm_idx(op1.reg).has_value();
    const bool op0_gp = op0.type == X86_OP_REG && map_reg(op0.reg).has_value();
    const bool op1_gp = op1.type == X86_OP_REG && map_reg(op1.reg).has_value();
    const u64 op0_sz = op0.size;
    const u64 op1_sz = op1.size;
    ir::Insn out;
    out.op = Op::Movss;  // 桥载体 (src2=族标记, 见 kBridge* 注释)
    out.addr = ci.address;
    out.updates_flags = false;

    // ---- load 方向: xmm ← r/m (66 0F 6E 系 + VEX vmovd/vmovq load) ----
    if (op0_xmm) {
        out.dst = ir::Operand::reg_(static_cast<ir::Reg>(*xmm_idx(op0.reg)));
        if (op1_gp && op1_sz == 4) {          // MOVD xmm, r32
            out.size = Size::S32;
            out.src2 = Operand::imm_(kBridgeFromGp);
            out.src = ir::Operand::reg_(*map_reg(op1.reg));
            return ok(out);
        }
        if (op1_gp && op1_sz == 8) {          // MOVQ xmm, r64
            out.size = Size::S64;
            out.src2 = Operand::imm_(kBridgeFromGp);
            out.src = ir::Operand::reg_(*map_reg(op1.reg));
            return ok(out);
        }
        if (op1.type == X86_OP_MEM && (op1_sz == 4 || op1_sz == 8)) {
            // MOVD/MOVQ xmm, m32/m64 → 既有 XmmLoad 载体 (无标记 —
            // translate_sse_mov mem-load 通路, movsd mem 清零语义直产)。
            auto m = mem_operand(op1.mem);
            if (!m) return unsupported(ci.address, ci.size);
            out.size = op1_sz == 4 ? Size::S32 : Size::S64;
            out.src = *m;
            return ok(out);
        }
        if (op1_xmm) {
            // all-xmm MOVQ (F3 0F 7E / 66 0F D6 legacy + VEX 全 pp): #33
            // 实测语义统一 = 低 64 拷贝 + 目的高 64 **清零** (d6_probe,
            // 66 0F D6 C8 与 F3 0F 7E C1 逐位同结果) → 全部 kBridgeFromXmm。
            // (prefix/pp 不参与语义 — D6 与 F3 reg-reg 在本机实测逐位相同。)
            out.size = Size::S64;                // all-xmm 形态固有 64 位
            out.dst = ir::Operand::reg_(static_cast<ir::Reg>(*xmm_idx(op0.reg)));
            out.src = ir::Operand::reg_(static_cast<ir::Reg>(*xmm_idx(op1.reg)));
            out.src2 = Operand::imm_(kBridgeFromXmm);
            return ok(out);
        }
        return unsupported(ci.address, ci.size);
    }

    // ---- store 方向: r/m ← xmm (66 0F 7E 系 + VEX store) ----
    if (op1_xmm) {
        out.src = ir::Operand::reg_(static_cast<ir::Reg>(*xmm_idx(op1.reg)));
        if (op0_gp && op0_sz == 4) {          // MOVD r32, xmm
            out.size = Size::S32;
            out.src2 = Operand::imm_(kBridgeToGp);
            out.dst = ir::Operand::reg_(*map_reg(op0.reg));
            return ok(out);
        }
        if (op0_gp && op0_sz == 8) {          // MOVQ r64, xmm
            out.size = Size::S64;
            out.src2 = Operand::imm_(kBridgeToGp);
            out.dst = ir::Operand::reg_(*map_reg(op0.reg));
            return ok(out);
        }
        if (op0.type == X86_OP_MEM && (op0_sz == 4 || op0_sz == 8)) {
            // MOVD/MOVQ m32/m64, xmm → 既有 XmmStore 载体。
            auto m = mem_operand(op0.mem);
            if (!m) return unsupported(ci.address, ci.size);
            out.size = op0_sz == 4 ? Size::S32 : Size::S64;
            out.dst = *m;
            return ok(out);
        }
        return unsupported(ci.address, ci.size);
    }
    return unsupported(ci.address, ci.size);
}

// ==================== MIT-426 (G6a): VEX.128 V-pair 折叠进既有 SSE 通路 ====================
//
// 路线: MIT-424 (G6r) 裁决 R2 档A — 38 个既有 SSE 白名单 id 的 V-对
// (VADDSS..VPANDN, vendored capstone x86.h 全量对账 EXISTS) 经三地址折叠
// 复用既有 translate_sse_* 函数。硬约束 (派活单 §C):
//   D1 零新 VmOp — 折叠只产既有 VmOp (Movaps 前置 + 2-op 载体);
//   D2 d==s2 gate 面 — 非交换族 + **标量族一律 gate** (标量 VEX
//      "dst 高位 ← s1 高位" 与 2-op "高位保持" 不相容且 pre-Mov 摧毁
//      s2==dst 的值; 正确序列需 xmm→GP 双槽暂存, 既有 VmOp 无此原语);
//      packed 可交换族 (add/mul/位运算) swap 直走。频率: d==s2 合并
//      0.75% < 1% (ucrtbase 单列 2.19% 含标量), 见 GAPS G6a 节;
//   D3 标量 FP 优先 (/arch:AVX 下 100% 标量浮点走 VEX = 本档价值锚);
//   D4 vmovaps/vmovups 纯拷贝 2-op 直折单条, 不进 binop 前置框架;
//   D5 C4 全前缀与 C5 短前缀同 INS id — capstone 已解 VEX bits
//      (prefix=[0,0,0,0], rex=64 常量, lifter 不消费), 按 id 入面天然
//      覆盖两编码。
//
// 行为链基线 (triage §3, 本单不破坏): 白名单外 VEX id (vpaddd/vfmadd*/
// rorx/vzeroupper/EVEX 全谱) 仍落 switch default → unsupported → C1 gate
// 整函数原生保持, 零逃逸 byte-identical。
//
// 位宽闸 (派活单 §B.4 最大陷阱): X86_INS_VADDPS 等 id 同时覆盖 128/256
// 两宽 — 仅靠 mnemonic 白名单会放 ymm 进来 → 错误 lift 静默坏壳。必须
// 按操作数位宽判: 32B (ymm reg / ymm mem) 落 unsupported → gate;
// 寄存器非 16B 同拒。SSE 跟踪区只有 8 槽 (ctx.xmm[0..7]) — xmm8..15
// 与 legacy SSE 同口径 gate (map 不可达 → unsupported)。
//
// 三地址折叠 (派活单 §A.3 三分法, VEX.NDS: operand[0]=dst REG,
// operand[1]=src1 REG (VEX.vvvv, 只读), operand[2]=src2 REG/MEM):
//   dst==src1            → 2-op (dst, s2) 直走既有通路 (零成本)
//   dst==src2 且可交换    → 交换: 2-op (dst, s1) (零成本; **仅 packed/位
//                          运算** — 全 128-bit 语义, 标量 gate 见 D2)
//   dst 独立             → 前置 Op::Movaps(dst←src1) 16B 纯拷贝
//                          (既有 VmOp, 寄存器终值与 VEX 语义逐位等价:
//                          VEX "dst 高位 ← s1 高位" + 2-op "dst 高位保持"
//                          == 16B 拷贝后接 2-op) + 2-op (dst, s2)
//   dst==src2 标量/非交换 → D2 gate (见上)
//   vmovss/vmovsd 3-op    → 插入语义 (§F.4 "假 Mov": dst 低位 ← s2,
//   (插入形态)               dst 高位 ← s1 ≠ 纯拷贝) — 仅 dst==src1 可折
//                          (2-op "高位保持" 与 s1 高位一致), 其余 gate。
//
// 可交换性披露 (known compromise): 浮点 add/mul 交换 src1/src2 对数值
// 逐位等价; NaN 载荷传播顺序 (src1 优先) 理论上可差 — 与 MIT-411
// comiss QNaN 同级别的 v1 披露面, native handler 执行的仍是真 add*/mul*。

TranslateResult translate_ymm_mov(const cs_insn& ci, const cs_x86& x, ir::Arch arch);

// V-pair 家族描述: 全部复用既有 translate 函数 (零新 IR 语义)。
struct VexDesc {
    enum class Fam : u8 { Add, Sub, Div, Mul, Bit, Andn, Mov, Ucomis,
                          Bridge };  // Bridge = MIT-427 vmovd/vmovq 桥镜像
    Fam fam;
    Op op;          // IR op 载体 (Add/Sub/Div/Bit/Mov/Ucomis 族; Bridge 忽略)
    ir::Size sz;    // 形式标签 (与 legacy 同约定: ss=S32 / sd=S64 / packed=S64)
    int marker = 0; // Mul 族 14..17 / Andn 18 (src2 载体标记, 与 425 对账)
    bool commutative = false; // add/mul/位运算 = true; sub/div/andn = false
    bool scalar = false;      // ss/sd 标量 (dst 高位 ← s1 高位语义面, 见下)
};

std::optional<VexDesc> vex_desc_of(x86_insn id) {
    switch (id) {
    // ---- 标量 FP (D3 主验收面: /arch:AVX 下 100% 标量走 VEX) ----
    case X86_INS_VADDSS: return VexDesc{VexDesc::Fam::Add, Op::Addss, ir::Size::S32, 0, true, true};
    case X86_INS_VADDSD: return VexDesc{VexDesc::Fam::Add, Op::Addss, ir::Size::S64, 0, true, true};
    case X86_INS_VADDPS: return VexDesc{VexDesc::Fam::Add, Op::Addps, ir::Size::S64, 0, true, false};
    case X86_INS_VADDPD: return VexDesc{VexDesc::Fam::Add, Op::Addpd, ir::Size::S64, 0, true, false};
    case X86_INS_VSUBSS: return VexDesc{VexDesc::Fam::Sub, Op::Subss, ir::Size::S32, 0, false, true};
    case X86_INS_VSUBSD: return VexDesc{VexDesc::Fam::Sub, Op::Subss, ir::Size::S64, 0, false, true};
    case X86_INS_VSUBPS: return VexDesc{VexDesc::Fam::Sub, Op::Subps, ir::Size::S64, 0, false, false};
    case X86_INS_VSUBPD: return VexDesc{VexDesc::Fam::Sub, Op::Subpd, ir::Size::S64, 0, false, false};
    case X86_INS_VDIVSS: return VexDesc{VexDesc::Fam::Div, Op::Divss, ir::Size::S32, 0, false, true};
    case X86_INS_VDIVSD: return VexDesc{VexDesc::Fam::Div, Op::Divss, ir::Size::S64, 0, false, true};
    case X86_INS_VDIVPS: return VexDesc{VexDesc::Fam::Div, Op::Divps, ir::Size::S64, 0, false, false};
    case X86_INS_VDIVPD: return VexDesc{VexDesc::Fam::Div, Op::Divpd, ir::Size::S64, 0, false, false};
    // ---- mul 族 (Op::Mul + src2 载体标记 14..17, 与 legacy 425 同编码) ----
    case X86_INS_VMULSS: return VexDesc{VexDesc::Fam::Mul, Op::Mul, ir::Size::S32, kSseMulSs, true, true};
    case X86_INS_VMULSD: return VexDesc{VexDesc::Fam::Mul, Op::Mul, ir::Size::S64, kSseMulSd, true, true};
    case X86_INS_VMULPS: return VexDesc{VexDesc::Fam::Mul, Op::Mul, ir::Size::S64, kSseMulPs, true, false};
    case X86_INS_VMULPD: return VexDesc{VexDesc::Fam::Mul, Op::Mul, ir::Size::S64, kSseMulPd, true, false};
    // ---- 位运算 (ps/pd 整数 p 系全折叠既有 Bit 载体, 411/425 先例) ----
    case X86_INS_VXORPS: return VexDesc{VexDesc::Fam::Bit, Op::Xorps, ir::Size::S64, 0, true};
    case X86_INS_VXORPD: return VexDesc{VexDesc::Fam::Bit, Op::Xorps, ir::Size::S64, 0, true};
    case X86_INS_VORPS:  return VexDesc{VexDesc::Fam::Bit, Op::Orps,  ir::Size::S64, 0, true};
    case X86_INS_VORPD:  return VexDesc{VexDesc::Fam::Bit, Op::Orps,  ir::Size::S64, 0, true};
    case X86_INS_VANDPS: return VexDesc{VexDesc::Fam::Bit, Op::Andps, ir::Size::S64, 0, true};
    case X86_INS_VANDPD: return VexDesc{VexDesc::Fam::Bit, Op::Andps, ir::Size::S64, 0, true};
    case X86_INS_VPXOR:  return VexDesc{VexDesc::Fam::Bit, Op::Xorps, ir::Size::S64, 0, true};
    case X86_INS_VPOR:   return VexDesc{VexDesc::Fam::Bit, Op::Orps,  ir::Size::S64, 0, true};
    case X86_INS_VPAND:  return VexDesc{VexDesc::Fam::Bit, Op::Andps, ir::Size::S64, 0, true};
    // ---- andn (dst = ~src1 & src2, 非交换; Op::Andps + kSseAndn 载体) ----
    case X86_INS_VANDNPS: return VexDesc{VexDesc::Fam::Andn, Op::Andps, ir::Size::S64, kSseAndn, false};
    case X86_INS_VANDNPD: return VexDesc{VexDesc::Fam::Andn, Op::Andps, ir::Size::S64, kSseAndn, false};
    case X86_INS_VPANDN:  return VexDesc{VexDesc::Fam::Andn, Op::Andps, ir::Size::S64, kSseAndn, false};
    // ---- mov 族 (2-op 拷贝/load/store 直通; 3-op 插入形态仅 d==s1) ----
    case X86_INS_VMOVSS:  return VexDesc{VexDesc::Fam::Mov, Op::Movss,  ir::Size::S32, 0, false};
    case X86_INS_VMOVSD:  return VexDesc{VexDesc::Fam::Mov, Op::Movss,  ir::Size::S64, 0, false};
    case X86_INS_VMOVAPS: return VexDesc{VexDesc::Fam::Mov, Op::Movaps, ir::Size::S64, 0, false};
    case X86_INS_VMOVAPD: return VexDesc{VexDesc::Fam::Mov, Op::Movapd, ir::Size::S64, 0, false};
    case X86_INS_VMOVUPS: return VexDesc{VexDesc::Fam::Mov, Op::Movups, ir::Size::S64, 0, false};
    // MIT-428 (G1d): vmovdqa/vmovdqu 镜像 (1028/1033, probe 实测 id) —
    // 纯拷贝 2-op 直折 (426 D4 vmovaps 先例); ymm 位宽闸 + xmm8..15 闸
    // 继承 translate_vex128; EVEX VMOVDQA32/64/8/16 (x86.h:1413-1419)
    // 独立 INS id 天然不入面 (426 §F.3 同款)。
    case X86_INS_VMOVDQA: return VexDesc{VexDesc::Fam::Mov, Op::Movaps, ir::Size::S64, 0, false};
    case X86_INS_VMOVDQU: return VexDesc{VexDesc::Fam::Mov, Op::Movups, ir::Size::S64, 0, false};
    case X86_INS_VMOVUPD: return VexDesc{VexDesc::Fam::Mov, Op::Movupd, ir::Size::S64, 0, false};
    // ---- 桥镜像 (MIT-427 B.3): vmovd/vmovq 2-op 形态, 语义全由操作数
    // 形状 + VEX pp 判定 (translate_movd_movq 统一处理 legacy/VEX) ----
    case X86_INS_VMOVD: return VexDesc{VexDesc::Fam::Bridge, Op::Mov, ir::Size::S32};
    case X86_INS_VMOVQ: return VexDesc{VexDesc::Fam::Bridge, Op::Mov, ir::Size::S64};
    // ---- 比较族 (2-op, flags 通路; 无 3-op 形态) ----
    case X86_INS_VUCOMISS: return VexDesc{VexDesc::Fam::Ucomis, Op::Ucomiss, ir::Size::S32, 0, false};
    case X86_INS_VUCOMISD: return VexDesc{VexDesc::Fam::Ucomis, Op::Ucomisd, ir::Size::S64, 0, false};
    case X86_INS_VCOMISS:  return VexDesc{VexDesc::Fam::Ucomis, Op::Ucomiss, ir::Size::S32, 0, false};
    case X86_INS_VCOMISD:  return VexDesc{VexDesc::Fam::Ucomis, Op::Ucomisd, ir::Size::S64, 0, false};
    default:
        return std::nullopt;
    }
}

// 按 VexDesc 调用既有 translate 函数 (2-op 形态 — legacy 通路原样复用)。
TranslateResult vex_invoke(const VexDesc& d, const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    switch (d.fam) {
    case VexDesc::Fam::Add:    return translate_sse_add(ci, x, arch, d.op, d.sz);
    case VexDesc::Fam::Sub:    return translate_sse_sub(ci, x, arch, d.op, d.sz);
    case VexDesc::Fam::Div:    return translate_sse_div(ci, x, arch, d.op, d.sz);
    case VexDesc::Fam::Mul:    return translate_sse_mul(ci, x, arch, d.sz, d.marker);
    case VexDesc::Fam::Bit:    return translate_sse_bitwise(ci, x, arch, d.op, d.sz);
    case VexDesc::Fam::Andn:   return translate_sse_andn(ci, x, arch);
    case VexDesc::Fam::Mov:    return translate_sse_mov(ci, x, arch, d.op, d.sz);
    case VexDesc::Fam::Ucomis: return translate_ucomis(ci, x, arch, d.op, d.sz);
    // MIT-427 (G1c) B.3: vmovd/vmovq 桥镜像 — 操作数形状 + VEX pp 判据在
    // translate_movd_movq 内, 2-op 直通 (VMOVD/VMOVQ 无 3-op 形态, 不会经
    // 三地址折叠改写)。
    case VexDesc::Fam::Bridge: return translate_movd_movq(ci, x, arch);
    }
    return unsupported(ci.address, ci.size);
}

// VEX.128 V-pair 入口: 位宽闸 → 2-op 直通 / 3-op 三地址折叠 (见顶部说明块)。
TranslateResult translate_vex128(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    const auto desc = vex_desc_of(static_cast<x86_insn>(ci.id));
    if (!desc) return unsupported(ci.address, ci.size);  // 白名单外 (现状 gate 保持)
    // ---- MIT-512 (T64): 32B (ymm) 传送形态 → ymm 数据通路 (位宽闸前置)。
    // 仅 Fam::Mov 六 id (vmovaps/vmovupd/vmovups/vmovdqa/vmovdqu/vmovapd);
    // 算术族 32B 仍被下方位宽闸拒 (wave2② 翻面)。 ----
    if (desc->fam == VexDesc::Fam::Mov && x.op_count == 2) {
        bool all32 = true;
        for (u8 i = 0; i < x.op_count; ++i)
            if (x.operands[i].size != 32) all32 = false;
        if (all32) return translate_ymm_mov(ci, x, arch);
    }
    // ---- B.4 位宽闸: 32B (ymm) 禁入 — 同 mnemonic 覆盖 128/256 两宽 ----
    // MIT-427 (G1c): Fam::Bridge (vmovd/vmovq) 混合宽度操作数 (r32=4/r64=8)
    // 是合法形态 — 寄存器 16B 防御检查仅约束 SIMD 家族; 桥的形状/宽度判据
    // 在 translate_movd_movq 内 (mm 闸 / xmm8..15 闸 / r32|r64 宽度链)。
    const bool bridge = desc->fam == VexDesc::Fam::Bridge;
    for (u8 i = 0; i < x.op_count; ++i) {
        const cs_x86_op& op = x.operands[i];
        if (op.size > 16) return unsupported(ci.address, ci.size);  // ymm/ymm mem
        if (!bridge && op.type == X86_OP_REG && op.size != 16)
            return unsupported(ci.address, ci.size);                // 防御 (寄存器恒 16B)
    }

    // ---- 2-op 直通: vmov* 拷贝/load/store + vucomis*/vcomis* (D4) ----
    // 操作数形状由既有 translate_sse_* 自检 (dst mem 形式 408 通路; xmm0..7
    // 之外不可映射 → nullopt → gate, 与 legacy SSE 同口径)。
    if (x.op_count == 2) return vex_invoke(*desc, ci, x, arch);
    if (x.op_count != 3) return unsupported(ci.address, ci.size);

    // ---- 3-op VEX.NDS: [0]=dst REG, [1]=src1 REG (VEX.vvvv), [2]=src2 R/M ----
    // (slot 语义 capstone 5 实测: C5 FA 58 C1 → vaddss xmm0, xmm0, xmm1,
    //  ops=[xmm0, xmm0, xmm1]; 报告附对照表)
    if (x.operands[0].type != X86_OP_REG || x.operands[1].type != X86_OP_REG)
        return unsupported(ci.address, ci.size);
    auto xmm_idx = [&](x86_reg r) -> std::optional<u8> {
        switch (r) {
        case X86_REG_XMM0: return static_cast<u8>(0); case X86_REG_XMM1: return static_cast<u8>(1);
        case X86_REG_XMM2: return static_cast<u8>(2); case X86_REG_XMM3: return static_cast<u8>(3);
        case X86_REG_XMM4: return static_cast<u8>(4); case X86_REG_XMM5: return static_cast<u8>(5);
        case X86_REG_XMM6: return static_cast<u8>(6); case X86_REG_XMM7: return static_cast<u8>(7);
        default: return std::nullopt;  // xmm8..15 / ymm (位宽闸已拒 ymm, 双保险)
        }
    };
    const auto di = xmm_idx(x.operands[0].reg);
    if (!di) return unsupported(ci.address, ci.size);
    const auto s1i = xmm_idx(x.operands[1].reg);
    if (!s1i) return unsupported(ci.address, ci.size);
    const bool s2_reg = x.operands[2].type == X86_OP_REG;
    const bool s2_mem = x.operands[2].type == X86_OP_MEM;
    if (!s2_reg && !s2_mem) return unsupported(ci.address, ci.size);
    std::optional<u8> s2i;
    if (s2_reg) {
        s2i = xmm_idx(x.operands[2].reg);
        if (!s2i) return unsupported(ci.address, ci.size);
    }

    // 比较族无 3-op 形态 (SDM); 防御 gate。
    if (desc->fam == VexDesc::Fam::Ucomis) return unsupported(ci.address, ci.size);

    const bool d_eq_s1 = *di == *s1i;
    const bool d_eq_s2 = s2_reg && *di == *s2i;

    // vmovss/vmovsd 3-op 插入语义 (§F.4 "假 Mov"): dst 低 32/64 位 ← src2、
    // 高位 ← src1 — 非 2-op 表达, 仅 dst==src1 可折 (2-op "dst 高位保持"
    // 恰等于 s1 高位); d==s2 交换/d 独立一律 gate。
    if (desc->fam == VexDesc::Fam::Mov && !d_eq_s1)
        return unsupported(ci.address, ci.size);

    // D2 裁决: d==s2 的折叠边界 —
    //   packed/位运算 (全 128-bit 语义): 可交换族 swap 直走 (值与位全等价);
    //   **标量 (ss/sd): 一律 gate** — VEX 标量 "dst 高位 ← s1 高位" 与
    //   2-op 通路 "dst 高位保持" 不相容: swap 后高位 = dst 原值 (≠ s1
    //   高位, 错); pre-Mov(dst←s1) 又先摧毁 s2(==dst) 的值 (低 32/64 位
    //   错)。正确序列需先暂存原 dst (xmm→GP 双槽), 既有 VmOp 无此原语
    //   (build_xmm_transfer 写路径仅 xmm 区), 新 VmOp 违反 D1 → gate
    //   (保守退化整函数原生, 非坏壳)。频率: d==s2 合并 0.75% (<1%),
    //   ucrtbase 单列 2.19% (含标量), 见 GAPS G6a 节。
    //   (非交换族 sub/div/andn 的 d==s2 同 gate — 交换不成立, 同上理由。)
    if (d_eq_s2 && (!desc->commutative || desc->scalar))
        return unsupported(ci.address, ci.size);

    // ---- 三地址折叠 (派活单 §B.2) ----
    cs_x86 x0 = x;
    if (d_eq_s1 || d_eq_s2) {
        // d==s1: 2-op (dst, s2) 直走; d==s2 (可交换): 交换 s1 上位。
        x0.op_count = 2;
        x0.operands[1] = x.operands[d_eq_s1 ? 2 : 1];
        return vex_invoke(*desc, ci, x0, arch);
    }
    // dst 独立 → 前置 Op::Movaps(dst←src1) 16B 纯拷贝 (既有 VmOp 通路),
    // 再 2-op (dst, s2)。pre-Mov 借用 Op::Movaps→VmOp::Movaps (16B movups
    // 语义, 425 惯例); 与 VEX "dst 高位 ← s1 高位" + 2-op "高位保持"
    // 逐位等价 (标量/packed/整数统一成立)。
    x0.op_count = 2;
    x0.operands[1] = x.operands[2];
    TranslateResult r = vex_invoke(*desc, ci, x0, arch);
    if (r.status != TranslateStatus::Ok) return r;
    ir::Insn pre;
    pre.op = Op::Movaps;
    pre.size = ir::Size::S64;   // 16B (128-bit 全量)
    pre.updates_flags = false;
    pre.addr = ci.address;      // 与主 insn 共享机器地址 (next_ip_of 覆盖语义)
    pre.dst = ir::Operand::reg_(static_cast<ir::Reg>(*di));
    pre.src = ir::Operand::reg_(static_cast<ir::Reg>(*s1i));
    r.extra.push_back(std::move(pre));
    return r;
}

// MIT-511 (T63 · AVX 档B wave1): vzeroupper/vzeroall ABI 词 — 无操作数
// VEX 词 (C5 F8 77 / C5 FC 77, capstone 吸收前缀后 id 独立, op_count=0)。
// 只写 YMM 状态不触 guest EFLAGS。**x64 专属**: x86 架构 gate (MSVC x86
// 语料无 VEX 发射面, 频率≈0 — 与 GAPS G6a "VEX = x64 面" 口径一致);
// x86 区出现 → 现状 gate 整函数原生保持。
TranslateResult translate_vzero(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    if (arch != ir::Arch::X64) return unsupported(ci.address, ci.size);
    if (x.op_count != 0) return unsupported(ci.address, ci.size);  // 防御
    ir::Insn out;
    out.op = (ci.id == X86_INS_VZEROUPPER) ? Op::Vzeroupper : Op::Vzeroall;
    out.size = ir::Size::S32;
    out.updates_flags = false;
    out.addr = ci.address;
    return ok(std::move(out));
}

// MIT-512 (T64 · 档B wave2①): ymm 传送通路 — vmovaps/vmovups/vmovapd/
// vmovupd/vmovdqa/vmovdqu 的 32B (ymm) 形态。寄存器映射沿用 SSE 惯例:
// IR.dst/src.reg 借用 ir::Reg 值 0..7 代表 ymm0..7 (翻译器 +24 → v24..31
// 槽位); ymm8..15 维持 xmm8..15 同款 gate。三形式:
//   (Reg,Reg) → Op::YmmMov / (Reg,Mem) → Op::YmmLoad / (Mem,Reg) → Op::YmmStore
// 对齐语义差异 (aps vs ups / dqa vs dqu) 不模拟 (#GP 不模拟, MIT-428 D2
// 先例 — face 访问一律 vmovups, ctx 栈基址仅 16B 对齐)。x86 架构 gate。
TranslateResult translate_ymm_mov(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    if (arch != ir::Arch::X64) return unsupported(ci.address, ci.size);
    if (x.op_count != 2) return unsupported(ci.address, ci.size);
    const bool dst_reg = x.operands[0].type == X86_OP_REG;
    const bool dst_mem = x.operands[0].type == X86_OP_MEM;
    const bool src_reg = x.operands[1].type == X86_OP_REG;
    const bool src_mem = x.operands[1].type == X86_OP_MEM;
    if (dst_mem && src_mem) return unsupported(ci.address, ci.size);
    if (!dst_reg && !dst_mem) return unsupported(ci.address, ci.size);
    if (!src_reg && !src_mem) return unsupported(ci.address, ci.size);
    auto ymm_idx = [&](x86_reg r) -> std::optional<u8> {
        if (r >= X86_REG_YMM0 && r <= X86_REG_YMM7)
            return static_cast<u8>(r - X86_REG_YMM0);
        return std::nullopt;  // ymm8..15 gate (双保险: 位宽闸外层已拒一次)
    };
    ir::Insn out;
    out.size = ir::Size::S64;   // 32B 整体读写 (与 SSE mov 族 tag 惯例一致)
    out.updates_flags = false;
    out.addr = ci.address;
    if (dst_mem) {
        auto si = ymm_idx(x.operands[1].reg);
        if (!si) return unsupported(ci.address, ci.size);
        auto m = mem_operand(x.operands[0].mem);
        if (!m) return unsupported(ci.address, ci.size);
        out.op = Op::YmmStore;
        out.dst = *m;
        out.src = ir::Operand::reg_(static_cast<ir::Reg>(*si));
        return ok(std::move(out));
    }
    auto di = ymm_idx(x.operands[0].reg);
    if (!di) return unsupported(ci.address, ci.size);
    out.dst = ir::Operand::reg_(static_cast<ir::Reg>(*di));
    if (src_mem) {
        auto m = mem_operand(x.operands[1].mem);
        if (!m) return unsupported(ci.address, ci.size);
        out.op = Op::YmmLoad;
        out.src = *m;
    } else {
        auto si = ymm_idx(x.operands[1].reg);
        if (!si) return unsupported(ci.address, ci.size);
        out.op = Op::YmmMov;
        out.src = ir::Operand::reg_(static_cast<ir::Reg>(*si));
    }
    return ok(std::move(out));
}

TranslateResult translate_cmpxchg(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    if (x.op_count != 2) return unsupported(ci.address, ci.size);
    // dst 必为 r/m (REG 或 MEM); src 必为 REG
    if (x.operands[0].type != X86_OP_REG && x.operands[0].type != X86_OP_MEM) {
        return unsupported(ci.address, ci.size);
    }
    if (x.operands[1].type != X86_OP_REG) return unsupported(ci.address, ci.size);

    // 取 size: capstone 报 r/m 操作数的真实位宽; data_size() 已处理 1/2/4/8 字节。
    // S16 cmpxchg (0x66 0F B1+rm) 必带 0x66 prefix, 而 prefix[0] 检查在
    // translate_insn 入口处已统一拒绝, 故本函数只可能收到 S8/S32/S64 三种 size。
    const ir::Size sz = data_size(x.operands, x.op_count, arch);
    if (sz != ir::Size::S8 && sz != ir::Size::S32 && sz != ir::Size::S64) {
        // S16 (0x66 prefix) 在入口已拒; 此处 defensive 兜底。
        return unsupported(ci.address, ci.size);
    }

    ir::Insn out;
    out.op = Op::Cmpxchg;
    out.addr = ci.address;
    out.size = sz;
    out.updates_flags = true;  // cmpxchg writes CF/OF/SF/ZF/PF (与 cmp 同语义)

    // dst = r/m (REG 或 MEM), src = r (REG only)
    if (x.operands[0].type == X86_OP_REG) {
        auto d = map_reg(x.operands[0].reg);
        if (!d) return unsupported(ci.address, ci.size);
        out.dst = Operand::reg_(*d);
    } else {
        // MEM 形式: lifter 直接 emit Operand::mem_(...), 翻译器折 Load + Cmpxchg + Store
        auto m = mem_operand(x.operands[0].mem);
        if (!m) return unsupported(ci.address, ci.size);
        out.dst = *m;
    }
    auto s = map_reg(x.operands[1].reg);
    if (!s) return unsupported(ci.address, ci.size);
    out.src = Operand::reg_(*s);
    return ok(out);
}

// ==================== MIT-415 (G3): rep/repnz 串指令微程序 VM 化 ====================
//
// 挂点 = lifter 入口前缀闸 (translate_insn :1494 起): 带前缀指令 v1 一律拒,
// rep/F2/F3/66 前缀的串指令全部在 lifter 层被拒 → 本单从 lifter 放行开始
// (派活单 §A.2 锚 1), 翻译器微程序展开 (D2), 零新 VmOp。
//
// 放行判定 = detail 级三元组白名单 (mnemonic + prefix + 宽度), 禁
// "prefix[0]!=0 全放" (派活单 §B.1):
//   - prefix[0] ∈ {F3 (rep/repe/repz), F2 (repne/repnz)} — vendored capstone
//     x86.h 实证: prefix[0]=rep/repne/lock, prefix[1]=段覆盖, prefix[2]=66
//     操作数宽, prefix[3]=67 地址宽 (probe 实测, 2026-08-29)
//   - mnemonic ∈ 串指令族: MOVSB..MOVSQ / STOSB..STOSQ / SCASB..SCASQ /
//     CMPSB..CMPSQ / LODSB..LODSQ。string movsd (A5) 与 SSE movsd (F2 0F 10)
//     同 id=X86_INS_MOVSD (408 实证) — 由双 MEM 操作数形状区分 (408 规则,
//     translate_sse_mov 的 (Mem,Mem) 拒绝面正是本面)
//   - F3: 全族放行 (movs/stos/lods = count-only; scas/cmps = repe)
//   - F2: 仅 scas/cmps (repne); F2+movs/stos/lods = Intel undefined → 照旧 gate
//   - 66 (prefix[2], 16 位操作数) / 67 (prefix[3], 地址宽) / 段覆盖 (prefix[1])
//     / lock (F0) → 照旧 gate (66 砍面披露于 §B.7 残余; 67 改变计数宽/指针
//     语义; lock 对串指令 undefined)
//   - 宽度 = 操作数 size ∈ {1,4,8} (S16 砍面); **REX.W 修正**: capstone 对
//     `48 F3 A5` (ml64 `rep movsq` 规范编码) 实证解为 'rep movsd' dword
//     (id=486, rex=0, op_size=4) — F3 先于 REX 的 `F3 48 A5` 才正确报 MOVSQ
//     qword。Q 形 (movsq/stosq/scasq/cmpsq/lodsq) 一律按 "op_size==4 且字节
//     流含 REX.W → S64" 修正 (串指令无 ModRM/立即数, 0x40..0x4F 字节必为
//     REX, 与 popcnt/lzcnt REX 扫描同纪律, §A.3 先验实测)
//
// IR 编码 (ir::Insn 冻结契约, 零碰撞):
//   op=Op::Mov + src2=imm(family 0..4) + cond (E=rep/repe, Ne=repne) +
//   size=元素宽 (S8/S32/S64) + dst/src=语义寄存器形态 + updates_flags
//   (scas/cmps=true)。普通 mov 的 src2 恒空; imul 的 src2 在 Op::Imul 上 —
//   与翻译器 translate_string_op (translator.cpp) 对账的私有约定。

enum : int { kStrMovs = 0, kStrStos = 1, kStrScas = 2, kStrCmps = 3, kStrLods = 4 };

// MIT-442 (X2a) ②: plain (无前缀) 单发串形 — 形级 fork 面 (X0 §1.4: plain
// movsd dxcompiler 10116 / msvbvm60 1311 lodsd 级, 结构体拷贝惯用法)。域
// 23..27 与既有 0..4 (rep 串) / 5..13 (lock) / 14..18 (SSE mul+andn) /
// 19..21 (bridge) / 22 (flagless) 分区连续零重叠; 载体仍 = Op::Mov +
// src2=imm(域) (G3 先例), op 限定下与 cbw 载体 (域 28, op=Movsx) 零碰撞。
// 单发语义 = G3 微程序"循环一次" (X0 §A.2 折叠预判实测成立): movs/stos/lods
// 原生不写 flags → 无 GetFlags/SetFlags 包裹; scas/cmps 单发 flags = 末次
// 比较 (与原生一致, 体内 Cmp 后直落)。DF 语义引用 G3 D1 裁决 (微程序恒
// DF=0 方向, note 披露)。
constexpr int kStrPlainBase = 23;  // 23..27 = plain movs/stos/scas/cmps/lods
// (kExtCbw = 28 定义于 translate_leave 前置块 — translate_cbw 前向引用)

// MIT-419 (G4): lock 族 src2 标记 — 与 string family (0..4) 分域零碰撞。
// 编码约定 (与 translator.cpp is_lock_marker 对账):
//   - 5..8: Op::Mov 载体族 (xadd/bts/btr/btc 无 ir::Op 枚举 — 冻结契约不可增,
//     沿用 G3 串指令 "Op::Mov + src2=imm(family)" 载体先例)
//   - 9..11: 本体 op 族 (ALU/Cmpxchg/Xchg — op 字段已表达语义, 标记仅声明
//     "曾带 lock 前缀", 供翻译器发 lock-strip note 且不影响本体折条)
//   - 12..13: 本体 op 族 (Inc/Dec — MIT-423 G4b; 本体通路 translate_unary
//     已有, 标记仅声明"曾带 lock", 供翻译器发 note 后派发回本体折条)。
//     载体域对账 (MIT-423 B.1, 419 铁律第 4 次教训): src2=imm **任意值**
//     写入点全仓仅 translate_imul 3-op 形式一处 (op=Imul 不入
//     is_lock_carrier_op, 12/13 不误拦 — 回归用例锁死); 其余写点全为上列
//     固定标记值。Inc/Dec 唯一构造点 translate_unary 不写 src2 (Operand
//     默认 kind=None, operand.hpp), 加进 is_lock_carrier_op 无碰撞面。
enum : int {
    kLockXadd = 5, kLockBts = 6, kLockBtr = 7, kLockBtc = 8,
    kLockStripAlu = 9, kLockStripCmpxchg = 10, kLockStripXchg = 11,
    kLockInc = 12, kLockDec = 13
};
constexpr int kLockMarkerMin = kLockXadd;
constexpr int kLockMarkerMax = kLockDec;

// id → 串指令族 (nullopt = 非串指令)。MOVSD 双形态由调用方按操作数形状区分。
std::optional<int> string_family_of(x86_insn id) {
    switch (id) {
    case X86_INS_MOVSB: case X86_INS_MOVSW: case X86_INS_MOVSD: case X86_INS_MOVSQ:
        return kStrMovs;
    case X86_INS_STOSB: case X86_INS_STOSW: case X86_INS_STOSD: case X86_INS_STOSQ:
        return kStrStos;
    case X86_INS_SCASB: case X86_INS_SCASW: case X86_INS_SCASD: case X86_INS_SCASQ:
        return kStrScas;
    case X86_INS_CMPSB: case X86_INS_CMPSW: case X86_INS_CMPSD: case X86_INS_CMPSQ:
        return kStrCmps;
    case X86_INS_LODSB: case X86_INS_LODSW: case X86_INS_LODSD: case X86_INS_LODSQ:
        return kStrLods;
    default:
        return std::nullopt;
    }
}

// rep/repnz 串指令 → ir::Insn (编码约定见上)。形态不符一律 unsupported →
// C1 gate 兜底 (保守底线零让步)。
// MIT-442 (X2a) ②: prefix[0]==0 的 plain 单发形 (A4/A5/AA/AB/AC/AD/AE/A6/A7
// 及 Q 形) 亦经本函数 (switch 新 case 派入) — 前缀三元组放行 p==0, 编码域
// 23..27 (kStrPlainBase), 单发语义见 translator translate_string_op。
TranslateResult translate_string_op(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    // ① 前缀三元组: F3/F2 (rep 形) / 0 (plain 单发形) + 无段覆盖 (prefix[1]) +
    // 无 66 (prefix[2], S16 串形 G3 砍面维持) + 无 67 (prefix[3], B.4 地址宽闸)
    const u8 p = x.prefix[0];
    if ((p != 0xF3 && p != 0xF2 && p != 0) || x.prefix[1] != 0 || x.prefix[2] != 0 ||
        x.prefix[3] != 0) {
        return unsupported(ci.address, ci.size);
    }
    // ② lock 字节级检查: capstone 对 `F0 F3 A4` (lock rep movsb) 实证把 F0
    // 吸收掉只报 prefix[0]=F3 — 必须字节扫描。串指令无 ModRM/立即数, 字节
    // 流中任何 0xF0 必为 lock 前缀。
    for (size_t i = 0; i < ci.size; ++i) {
        if (ci.bytes[i] == 0xF0) return unsupported(ci.address, ci.size);
    }
    // ③ family × prefix 合法性 (F2 仅 scas/cmps)
    const auto fam = string_family_of(static_cast<x86_insn>(ci.id));
    if (!fam) return unsupported(ci.address, ci.size);
    if (p == 0xF2 && *fam != kStrScas && *fam != kStrCmps) {
        return unsupported(ci.address, ci.size);  // repne + movs/stos/lods = undefined
    }
    // ④ 操作数形状 (串指令无显式操作数变体, 形状固定; MOVSD 双形态判据)
    if (x.op_count != 2) return unsupported(ci.address, ci.size);
    const cs_x86_op& o0 = x.operands[0];
    const cs_x86_op& o1 = x.operands[1];
    const bool dst_mem = o0.type == X86_OP_MEM;
    const bool src_mem = o1.type == X86_OP_MEM;
    if (*fam == kStrMovs || *fam == kStrCmps) {
        // movs/cmps: 双 MEM — 非双 MEM 的 MOVSD id 即 SSE movsd (408 双形态互斥)
        if (!dst_mem || !src_mem) return unsupported(ci.address, ci.size);
    } else if (*fam == kStrStos) {
        // stos: [rdi] ← AL/EAX/RAX
        if (!dst_mem || src_mem) return unsupported(ci.address, ci.size);
    } else {
        // scas/lods: AL/EAX/RAX ← [rdi]/[rsi]
        if (dst_mem || !src_mem) return unsupported(ci.address, ci.size);
    }
    // ⑤ 宽度: op_size ∈ {1,4,8}; REX.W 修正 (Q 形 capstone 缺陷, 见上)
    unsigned width = o0.size;
    if (width == 4) {
        for (size_t i = 0; i < ci.size; ++i) {
            if (ci.bytes[i] >= 0x40 && ci.bytes[i] <= 0x4F && (ci.bytes[i] & 0x08)) {
                width = 8;
                break;
            }
        }
    }
    if (width != 1 && width != 4 && width != 8) {
        return unsupported(ci.address, ci.size);  // S16 (66 F3 xx) 砍面 → §B.7
    }
    // ⑥ IR 编码 (family → 语义寄存器硬编码: 串指令寄存器由 ISA 固定, 无变体)
    // MIT-442 (X2a): plain 单发形编码域 = kStrPlainBase + family (23..27);
    // cond 字段对 plain 无意义 (无 rep/repne 之分), 恒 E — translator 按
    // 域值判 plain, 不读 cond。
    const bool plain = (p == 0);
    ir::Insn out;
    out.op = Op::Mov;  // 载体 (src2=family 标记区分, 见上)
    out.addr = ci.address;
    out.size = width == 1 ? ir::Size::S8 : width == 4 ? ir::Size::S32 : ir::Size::S64;
    out.cond = (p == 0xF2) ? ir::Cond::Ne : ir::Cond::E;  // repne / rep(repe)
    // updates_flags: scas/cmps 真写 flags (rep 形微程序末态恢复 = 末次比较,
    // plain 单发形 Cmp 后直落 = 原生) — movs/stos/lods 全形态不写 (SDM)。
    out.updates_flags = (*fam == kStrScas || *fam == kStrCmps);
    out.src2 = Operand::imm_(plain ? kStrPlainBase + *fam : *fam);
    const auto rsi_m = Operand::mem_(ir::MemOperand{ir::Reg::Rsi, ir::Reg::Flags, 0, 0});
    const auto rdi_m = Operand::mem_(ir::MemOperand{ir::Reg::Rdi, ir::Reg::Flags, 0, 0});
    const auto rax_r = Operand::reg_(ir::Reg::Rax);
    switch (*fam) {
    case kStrMovs: out.dst = rdi_m; out.src = rsi_m; break;  // [rdi] ← [rsi]
    case kStrStos: out.dst = rdi_m; out.src = rax_r; break;  // [rdi] ← AL/EAX/RAX
    case kStrScas: out.dst = rax_r; out.src = rdi_m; break;  // cmp AL/EAX/RAX, [rdi]
    case kStrCmps: out.dst = rsi_m; out.src = rdi_m; break;  // cmp [rsi], [rdi]
    case kStrLods: out.dst = rax_r; out.src = rsi_m; break;  // AL/EAX/RAX ← [rsi]
    default: return unsupported(ci.address, ci.size);        // 防御 (family 越界)
    }
    return ok(out);
}

// ==================== MIT-419 (G4): lock 前缀原子族 strip-and-execute ====================
//
// 挂点 = lifter 入口前缀闸 (translate_insn): F0 (lock) 前缀 v1 一律拒; 本单
// 对白名单三元组开 F0 口 (D1: strip-and-execute, 原子性边界文档化于 GAPS)。
//
// 放行判定 (D4: 仅 F0 独前缀 (+REX) 放行, 组合前缀面收窄):
//   - prefix[0]==0xF0 && prefix[1..3]==0 (无段覆盖/66/67) && bytes[0]==0xF0
//     (字节级确认 — 415 纪律: capstone 对 `F0 F3 A4` 实证吸收 F0 只报 F3,
//     白名单判据以字节流为准不轻信 prefix 字段; F0 恒为首前缀字节)
//   - mnemonic × 形状白名单:
//       add/adc/sub/sbb/and/or/xor × dst=Mem (src=Reg/Imm)  → 剥 F0 走
//         translate_alu (本体通路已有, 零新 VmOp)
//       cmpxchg × dst=Mem × src=Reg                         → translate_cmpxchg
//       xchg   × dst=Mem × src=Reg                         → translate_xchg
//         (InterlockedExchange 真产物是裸 xchg [m],r 无 F0 — translate_xchg
//         MEM 形式本单放开, lock 版同享)
//       xadd   × dst=Mem × src=Reg  (InterlockedAdd 真产物) → Op::Mov 载体 +
//         src2=kLockXadd (新 VmOp::Xadd, handler 内 native lock xadd [addr],r
//         单指令直执行 — 硬件原子性保真, D1 折条妥协不适用本指令)
//       bts/btr/btc × dst=Mem × (src=Reg | src=Imm 0..255) (InterlockedBitTest*
//         真产物 = imm8 形式, D3) → Op::Mov 载体 + src2=kLockBts/Btr/Btc
//       inc/dec × dst=Mem (S32/S64)                            → translate_unary
//         本体折条 + 标记 (MIT-423 G4b; D1 零新 VmOp — _InterlockedIncrement/
//         Decrement 真产物实测为 lock xadd +1 走 Xadd 硬件原子通路, 裸
//         lock inc/dec 无 MSVC 产物, 折条撕裂窗口同 ALU 族)
//   - 其余 lock 组合 (reg-dst / lock not/neg (D2: 合法编码但无 MSVC 产物,
//     gate) / 不可锁助记符 / lock+rep 串=undefined / 66 16 位操作数 / 67
//     地址宽) 照旧拒 → C1 gate。
//
// IR 编码 (ir::Insn 冻结契约, 零碰撞):
// MIT-451 (X5b) B.4：REG-REG 位测试族提升（x86 专属）。`xadd r,r` /
// `bts/btr/btc r,r`（无 lock）→ Op::Mov 载体 + src2=G4 族标记 + dst/src =
// Reg 双形。判据：op_count==2 且两操作数皆 REG；arch 必须 x86（x64 REG-REG
// 照旧 unsupported → C1 gate，与 G4 残余清单一致）；宽度 xadd S8/S32、
// bts 系 S32（S16 66 前缀维持 gate 口径；bts 无字节形式）。updates_flags =
// true（xadd = add 语义全量；bts 系 CF 有定义，handler setcc5 捕宿主真值 —
// 与 lock MEM 形同源）。
TranslateResult translate_bitreg(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    if (arch != ir::Arch::X86) return unsupported(ci.address, ci.size);
    if (x.op_count != 2 || x.operands[0].type != X86_OP_REG ||
        x.operands[1].type != X86_OP_REG)
        return unsupported(ci.address, ci.size);
    const auto d = map_reg(x.operands[0].reg);
    const auto sr = map_reg(x.operands[1].reg);
    if (!d || !sr) return unsupported(ci.address, ci.size);
    ir::Insn out;
    out.op = Op::Mov;  // 载体（src2=族标记区分，与 lock MEM 形同域零碰撞）
    out.addr = ci.address;
    out.size = data_size(x.operands, x.op_count, arch);
    const bool is_xadd = ci.id == X86_INS_XADD;
    if (is_xadd) {
        if (out.size != ir::Size::S8 && out.size != ir::Size::S32)
            return unsupported(ci.address, ci.size);  // S16/S64 gate（S16 口径维持）
        out.src2 = Operand::imm_(kLockXadd);
    } else {
        if (out.size != ir::Size::S32)
            return unsupported(ci.address, ci.size);  // bts 系无 S8 形；S16 gate
        out.src2 = Operand::imm_(ci.id == X86_INS_BTS   ? kLockBts
                                 : ci.id == X86_INS_BTR ? kLockBtr
                                                        : kLockBtc);
    }
    out.dst = Operand::reg_(*d);
    out.src = Operand::reg_(*sr);
    out.updates_flags = true;
    return ok(out);
}

//   - 本体 op 族: op 不变 + src2=imm(kLockStrip*) — 普通 alu/cmpxchg/xchg 的
//     src2 恒空 (imul 的 src2 在 Op::Imul 上; 串指令载体 Op::Mov 的 src2 是
//     family 0..4 — 分域 9..11 零碰撞)
//   - xadd/bts/btr/btc: op=Op::Mov 载体 + src2=imm(5..8) + dst=Mem + src=Reg/
//     Imm (普通 mov 的 dst 恒 Reg, mem-dst mov 走 Op::Store — 载体零碰撞)
//   - size: 本体 op 走 data_size() (xadd S8/S32/S64; bts 系 S32/S64 — S16 66
//     前缀入口已拒, S8 bts 编码不存在; 防御性拒 S8/S16)
//   - updates_flags: xadd=true (add 语义 flags), bts 系=true (CF 有定义,
//     SDM 其余未定义 — handler setcc5 捕 host CPU 真值, 与原生同 CPU 行为),
//     本体 op 族沿用 translate_* 原值
TranslateResult translate_lock_op(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    // D4: 仅 F0 独前缀 (+REX, REX 不入 prefix 数组) — 66/67/段覆盖/组合拒。
    if (x.prefix[0] != 0xF0 || x.prefix[1] != 0 || x.prefix[2] != 0 || x.prefix[3] != 0)
        return unsupported(ci.address, ci.size);
    // 字节级确认 (415 纪律): capstone 对合法 lock 指令恒报 bytes[0]==0xF0;
    // 防御性拒绝 F0 被吸收的形态 (如 F0 F3 xx → prefix[0]=F3 走串闸, 见下)。
    if (ci.size == 0 || ci.bytes[0] != 0xF0)
        return unsupported(ci.address, ci.size);

    // 剥 F0 后复用本体 translate_*: cs_x86 是值类型 (operands 内联数组),
    // 复制后清零 prefix[0] 即可按普通指令翻译。
    cs_x86 x0 = x;
    x0.prefix[0] = 0;

    switch (ci.id) {
    case X86_INS_ADD: case X86_INS_ADC: case X86_INS_SUB: case X86_INS_SBB:
    case X86_INS_AND: case X86_INS_OR:  case X86_INS_XOR: {
        // 白名单三元组: ALU 族 × mem-dst (reg-dst lock 是非法编码, capstone
        // 对 `F0 01 C0` 等拒解码, 此处形状检查防御收口)。
        if (x.op_count != 2 || x.operands[0].type != X86_OP_MEM)
            return unsupported(ci.address, ci.size);
        Op op = Op::Add;
        switch (ci.id) {
        case X86_INS_ADC: op = Op::Adc; break;
        case X86_INS_SUB: op = Op::Sub; break;
        case X86_INS_SBB: op = Op::Sbb; break;
        case X86_INS_AND: op = Op::And; break;
        case X86_INS_OR:  op = Op::Or;  break;
        case X86_INS_XOR: op = Op::Xor; break;
        default: break;
        }
        auto r = translate_alu(ci, x0, arch, op);
        if (r.status != TranslateStatus::Ok) return r;
        r.insn.src2 = Operand::imm_(kLockStripAlu);  // 标记"曾带 lock"→ 翻译器发 note
        return ok(r.insn);
    }
    case X86_INS_CMPXCHG: {
        // lock cmpxchg: 仅 mem-dst 合法 (lock 必须作用内存操作数)。
        if (x.op_count != 2 || x.operands[0].type != X86_OP_MEM ||
            x.operands[1].type != X86_OP_REG)
            return unsupported(ci.address, ci.size);
        auto r = translate_cmpxchg(ci, x0, arch);
        if (r.status != TranslateStatus::Ok) return r;
        r.insn.src2 = Operand::imm_(kLockStripCmpxchg);
        return ok(r.insn);
    }
    case X86_INS_XCHG: {
        if (x.op_count != 2 || x.operands[0].type != X86_OP_MEM ||
            x.operands[1].type != X86_OP_REG)
            return unsupported(ci.address, ci.size);
        auto r = translate_xchg(ci, x0, arch);
        if (r.status != TranslateStatus::Ok) return r;
        r.insn.src2 = Operand::imm_(kLockStripXchg);
        return ok(r.insn);
    }
    case X86_INS_XADD: {
        // lock xadd [m], r — InterlockedAdd 真产物 (返回旧值语义)。
        if (x.op_count != 2 || x.operands[0].type != X86_OP_MEM ||
            x.operands[1].type != X86_OP_REG)
            return unsupported(ci.address, ci.size);
        auto d = to_operand(x.operands[0]);
        auto s = to_operand(x.operands[1]);
        if (!d || !s) return unsupported(ci.address, ci.size);
        ir::Insn out;
        out.op = Op::Mov;  // 载体 (src2=族标记区分, 见上)
        out.addr = ci.address;
        out.size = data_size(x.operands, x.op_count, arch);
        if (out.size != ir::Size::S8 && out.size != ir::Size::S32 &&
            out.size != ir::Size::S64)
            return unsupported(ci.address, ci.size);  // S16 防御 (66 前缀入口已拒)
        out.dst = *d;
        out.src = *s;
        out.src2 = Operand::imm_(kLockXadd);
        out.updates_flags = true;  // xadd flags = add 语义 (CF/OF/SF/ZF/PF)
        return ok(out);
    }
    case X86_INS_BTS: case X86_INS_BTR: case X86_INS_BTC: {
        // lock bts/btr/btc [m], r/imm8 — InterlockedBitTest* 真产物 (imm8
        // 形式高频, D3)。src=Imm 限定 0..255 (imm8 编码域)。
        if (x.op_count != 2 || x.operands[0].type != X86_OP_MEM)
            return unsupported(ci.address, ci.size);
        auto d = to_operand(x.operands[0]);
        if (!d) return unsupported(ci.address, ci.size);
        ir::Insn out;
        out.op = Op::Mov;  // 载体 (src2=族标记区分)
        out.addr = ci.address;
        out.size = data_size(x.operands, x.op_count, arch);
        if (out.size != ir::Size::S32 && out.size != ir::Size::S64)
            return unsupported(ci.address, ci.size);  // bts 无字节形式; S16 砍面
        out.dst = *d;
        if (x.operands[1].type == X86_OP_REG) {
            auto s = map_reg(x.operands[1].reg);
            if (!s) return unsupported(ci.address, ci.size);
            out.src = Operand::reg_(*s);
        } else if (x.operands[1].type == X86_OP_IMM) {
            const i64 bit = x.operands[1].imm;
            if (bit < 0 || bit > 255) return unsupported(ci.address, ci.size);
            out.src = Operand::imm_(bit);
        } else {
            return unsupported(ci.address, ci.size);
        }
        out.src2 = Operand::imm_(ci.id == X86_INS_BTS   ? kLockBts
                                 : ci.id == X86_INS_BTR ? kLockBtr
                                                        : kLockBtc);
        out.updates_flags = true;  // 仅 CF 有定义 (SDM), setcc5 捕 host CPU 真值
        return ok(out);
    }
    case X86_INS_INC: case X86_INS_DEC: {
        // MIT-423 (G4b): lock inc/dec [m] — 本体通路折条 (D1: 零新 VmOp,
        // translate_unary mem 拆条 Load+Inc/Dec+Store, 撕裂窗口同 ALU 族;
        // _InterlockedIncrement/Decrement 真产物实测是 lock xadd +1 → 走
        // 419 已有 Xadd 硬件原子通路, 裸 lock inc/dec 仅手写/第三方形态,
        // 无 MSVC 产物 — probe 实测 2026-08-30, 见报告 B.3)。
        // mem-dst 唯一合法形状 (lock 必须作用内存操作数; reg-dst `lock inc
        // ecx` capstone 实测拒解码 → skipped_ranges 通道, 形状检查防御收口)。
        // 宽度 S32/S64 (S8 FE /0 编码合法但 MSVC 无产物 — 无 InterlockedInc8
        // intrinsic, 保守 gate; S16 66 前缀入口已拒)。
        if (x.op_count != 1 || x.operands[0].type != X86_OP_MEM)
            return unsupported(ci.address, ci.size);
        const Size sz = data_size(x.operands, x.op_count, arch);
        if (sz != Size::S32 && sz != Size::S64)
            return unsupported(ci.address, ci.size);  // S8/S16 gate (B.2 pin)
        auto r = translate_unary(ci, x0, arch,
                                 ci.id == X86_INS_INC ? Op::Inc : Op::Dec,
                                 /*sets_flags=*/true);
        if (r.status != TranslateStatus::Ok) return r;
        r.insn.src2 = Operand::imm_(ci.id == X86_INS_INC ? kLockInc : kLockDec);
        return ok(r.insn);
    }
    default:
        // lock not/neg (SDM 合法编码 F7 /2、/3, capstone 实测 id=511/509 可
        // 解到此 default — D2 裁决: 无 MSVC 产物 (无 InterlockedNot/Neg
        // intrinsic), 继续 gate, GAPS 残余精确化) / lock mov/lock nop/rep
        // 组合等白名单外 → 照旧 gate。
        // (capstone 对 F0 89 18 lock mov / F0 90 lock nop 直接拒解码 → 无
        // detail → 上游 skipped_ranges 通道; 到不了本函数的组合由形状检查拒)
        return unsupported(ci.address, ci.size);
    }
}

} // namespace

std::optional<ir::Reg> map_reg(x86_reg r) {
    switch (r) {
    case X86_REG_RAX: case X86_REG_EAX: case X86_REG_AX: case X86_REG_AL: case X86_REG_AH:
        return ir::Reg::Rax;
    case X86_REG_RCX: case X86_REG_ECX: case X86_REG_CX: case X86_REG_CL: case X86_REG_CH:
        return ir::Reg::Rcx;
    case X86_REG_RDX: case X86_REG_EDX: case X86_REG_DX: case X86_REG_DL: case X86_REG_DH:
        return ir::Reg::Rdx;
    case X86_REG_RBX: case X86_REG_EBX: case X86_REG_BX: case X86_REG_BL: case X86_REG_BH:
        return ir::Reg::Rbx;
    case X86_REG_RSP: case X86_REG_ESP: case X86_REG_SP: case X86_REG_SPL:
        return ir::Reg::Rsp;
    case X86_REG_RBP: case X86_REG_EBP: case X86_REG_BP: case X86_REG_BPL:
        return ir::Reg::Rbp;
    case X86_REG_RSI: case X86_REG_ESI: case X86_REG_SI: case X86_REG_SIL:
        return ir::Reg::Rsi;
    case X86_REG_RDI: case X86_REG_EDI: case X86_REG_DI: case X86_REG_DIL:
        return ir::Reg::Rdi;
    case X86_REG_R8: case X86_REG_R8D: case X86_REG_R8W: case X86_REG_R8B:
        return ir::Reg::R8;
    case X86_REG_R9: case X86_REG_R9D: case X86_REG_R9W: case X86_REG_R9B:
        return ir::Reg::R9;
    case X86_REG_R10: case X86_REG_R10D: case X86_REG_R10W: case X86_REG_R10B:
        return ir::Reg::R10;
    case X86_REG_R11: case X86_REG_R11D: case X86_REG_R11W: case X86_REG_R11B:
        return ir::Reg::R11;
    case X86_REG_R12: case X86_REG_R12D: case X86_REG_R12W: case X86_REG_R12B:
        return ir::Reg::R12;
    case X86_REG_R13: case X86_REG_R13D: case X86_REG_R13W: case X86_REG_R13B:
        return ir::Reg::R13;
    case X86_REG_R14: case X86_REG_R14D: case X86_REG_R14W: case X86_REG_R14B:
        return ir::Reg::R14;
    case X86_REG_R15: case X86_REG_R15D: case X86_REG_R15W: case X86_REG_R15B:
        return ir::Reg::R15;
    case X86_REG_RIP: case X86_REG_EIP: case X86_REG_IP:
        return ir::Reg::Rip;
    default:
        return std::nullopt; // 段寄存器 / EFLAGS / xmm / RIZ 等
    }
}

std::optional<ir::Cond> map_cond(x86_insn id) {
    switch (id) {
    case X86_INS_JO: return Cond::O;
    case X86_INS_JNO: return Cond::No;
    case X86_INS_JB: return Cond::B;
    case X86_INS_JAE: return Cond::Ae;
    case X86_INS_JE: return Cond::E;
    case X86_INS_JNE: return Cond::Ne;
    case X86_INS_JBE: return Cond::Be;
    case X86_INS_JA: return Cond::A;
    case X86_INS_JS: return Cond::S;
    case X86_INS_JNS: return Cond::Ns;
    case X86_INS_JP: return Cond::P;
    case X86_INS_JNP: return Cond::Np;
    case X86_INS_JL: return Cond::L;
    case X86_INS_JGE: return Cond::Ge;
    case X86_INS_JLE: return Cond::Le;
    case X86_INS_JG: return Cond::G;
    default: return std::nullopt; // jcxz/jecxz/jrcxz 等
    }
}

// MIT-336: setcc 16 variants → ir::Cond (与 map_cond 一一对应, 不同 capstone id 命名)
// 共享同一 16 条件枚举: SETO=O, SETNO=No, SETB=B, SETAE=Ae, SETE=E, SETNE=Ne,
// SETBE=Be, SETA=A, SETS=S, SETNS=Ns, SETP=P, SETNP=Np, SETL=L, SETGE=Ge,
// SETLE=Le, SETG=G。return nullopt 仅对理论上不存在的 X86_INS_SETcc 通用 ID
// (capstone 实际产出 16 个独立 enum, 不产通用 SETcc)。
std::optional<ir::Cond> map_setcc_cond(x86_insn id) {
    switch (id) {
    case X86_INS_SETO:  return Cond::O;
    case X86_INS_SETNO: return Cond::No;
    case X86_INS_SETB:  return Cond::B;
    case X86_INS_SETAE: return Cond::Ae;
    case X86_INS_SETE:  return Cond::E;
    case X86_INS_SETNE: return Cond::Ne;
    case X86_INS_SETBE: return Cond::Be;
    case X86_INS_SETA:  return Cond::A;
    case X86_INS_SETS:  return Cond::S;
    case X86_INS_SETNS: return Cond::Ns;
    case X86_INS_SETP:  return Cond::P;
    case X86_INS_SETNP: return Cond::Np;
    case X86_INS_SETL:  return Cond::L;
    case X86_INS_SETGE: return Cond::Ge;
    case X86_INS_SETLE: return Cond::Le;
    case X86_INS_SETG:  return Cond::G;
    default: return std::nullopt;
    }
}

// MIT-339: cmovcc 16 variants → ir::Cond (与 map_cond 一一对应, 不同 capstone id 命名)
// 共享同一 16 条件枚举: CMOVE=E, CMOVNE=Ne, CMOVB=B, CMOVAE=Ae, CMOVA=A,
// CMOVBE=Be, CMOVS=S, CMOVNS=Ns, CMOVP=P, CMOVNP=Np, CMOVL=L, CMOVGE=Ge,
// CMOVLE=Le, CMOVG=G, CMOVO=O, CMOVNO=No (与 setcc 1:1 对应,
// capstone 命名不同但 cc 值相同)。
std::optional<ir::Cond> map_cmovcc_cond(x86_insn id) {
    switch (id) {
    case X86_INS_CMOVE:  return Cond::E;
    case X86_INS_CMOVNE: return Cond::Ne;
    case X86_INS_CMOVB:  return Cond::B;
    case X86_INS_CMOVAE: return Cond::Ae;
    case X86_INS_CMOVA:  return Cond::A;
    case X86_INS_CMOVBE: return Cond::Be;
    case X86_INS_CMOVS:  return Cond::S;
    case X86_INS_CMOVNS: return Cond::Ns;
    case X86_INS_CMOVP:  return Cond::P;
    case X86_INS_CMOVNP: return Cond::Np;
    case X86_INS_CMOVL:  return Cond::L;
    case X86_INS_CMOVGE: return Cond::Ge;
    case X86_INS_CMOVLE: return Cond::Le;
    case X86_INS_CMOVG:  return Cond::G;
    case X86_INS_CMOVO:  return Cond::O;
    case X86_INS_CMOVNO: return Cond::No;
    default: return std::nullopt;
    }
}

// ==================== MIT-434 (G8a): BMI1/2 折条款目 ====================
//
// src2 载体域 (与 translator.cpp is_bmi_flagless_marker / andn / bzhi 载体
// 分支严格对账; string 0..4 / lock 5..13 / sse mul+andn 14..18 / bridge
// 19..21 分区连续, 下一可用自 22 起):
//   22 kFlagless: (Op::{Shl,Shr,Sar,Rol,Ror}, src2=Imm(22)) = rorx/shlx/
//                 sarx/shrx flagless 载体。原生 ror/shl 的 count 走 **src**
//                 (Imm/CL, translate_shift), src2 恒 None → `ror eax,24`
//                 不误拦 (陷阱② 的值域碰撞被 kind 判据绕开: 判据是 src2
//                 的存在性, 不是 src 的立即数值); translator 展开为
//                 GetFlags/SetFlags 包裹 (D1 (i) 变体, 零新 VmOp, asmgen
//                 零改动)。
//   另两域骑真操作数 (andn/bzhi 三操作数, imm 标记无槽可占), 判据 =
//   src2.kind≠None 骑在"全仓从不写 src2"的 op 上 (写入点全仓审计 = 零,
//   imul 3-op 只写 Op::Imul, 419 §B.1 同款审计):
//   (Op::And, src2={Reg}) = andn: src = NOT 项 (vvvv, reg-only — ml64 实测
//                 `andn r8d,[m],r` 拒), src2 = AND 项 (r/m 可 mem,
//                 `andn r8d, r, [m]` 实测收; d==s2 载体形恒 reg);
//   (Op::Sub, src2={Reg}) = bzhi: src = value (r/m 可 mem, `bzhi r8d,[m],r`
//                 实测收), src2 = index (vvvv reg-only)。
enum : int { kFlagless = 22 };

// ---- andn (BMI1, VEX.NDS.LZ.0F38.F2): dst = ~s1 & s2 ----
// 操作数映射 (probe 实测 2026-08-31, ml64 v145 + capstone 5.0.7 双验):
//   op[0]=dst(reg) / op[1]=NOT 项(reg-only) / op[2]=AND 项(reg 或 mem)。
// flags (Zen5 probe raw 0x286): CF=0 / OF=0 / ZF,SF,PF 按结果 — 与
// Op::Not(无 flags) + Op::And 尾行(AND 全集) 折叠逐位对齐, 零特判。
// 三态折叠 (d==s2 需 ~s1 独占临时 → 唯一进 translator 载体的形态):
//   d==s1: [Not(d); And(d, s2)]            — 2 IR 纯 lifter 折叠 (extra+main)
//   d 独立: [Mov(d, s1); Not(d); And(d, s2)] — 3 IR; s2=mem 时主 And 直带
//          mem src (既有 alu-binop src_mem 通道, emit_load 折条)
//   d==s2: (Op::And, d, src=s1, src2=s2) 载体 → translator
//          [Mov(s0, s1); Not(s0); And(d, s0)] (scratch v18..v23)
TranslateResult translate_andn(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    if (x.op_count != 3) return unsupported(ci.address, ci.size);
    auto d = to_operand(x.operands[0]);
    auto s1 = to_operand(x.operands[1]);
    auto s2 = to_operand(x.operands[2]);
    if (!d || !s1 || !s2) return unsupported(ci.address, ci.size);
    if (d->kind != Operand::Kind::Reg || s1->kind != Operand::Kind::Reg)
        return unsupported(ci.address, ci.size);  // dst/NOT 项 reg-only (probe)
    if (s2->kind != Operand::Kind::Reg && s2->kind != Operand::Kind::Mem)
        return unsupported(ci.address, ci.size);
    const ir::Size sz = data_size(x.operands, x.op_count, arch);
    if (sz != ir::Size::S32 && sz != ir::Size::S64)
        return unsupported(ci.address, ci.size);  // BMI 无 S8/S16 形
    const bool d_eq_s1 = (d->kind == Operand::Kind::Reg && s1->kind == Operand::Kind::Reg &&
                          d->reg == s1->reg);
    const bool d_eq_s2 = (d->kind == Operand::Kind::Reg && s2->kind == Operand::Kind::Reg &&
                          d->reg == s2->reg);

    ir::Insn main_insn;
    main_insn.addr = ci.address;
    main_insn.size = sz;
    main_insn.dst = *d;
    main_insn.updates_flags = true;
    std::vector<ir::Insn> pre;

    if (d_eq_s2) {
        // 载体形: (Op::And, d, src=s1, src2=s2) — ~s1 需独占临时
        // (d 槽持有 AND 项, 前置 Mov/Not 会先摧毁它)。
        main_insn.op = Op::And;
        main_insn.src = *s1;
        main_insn.src2 = *s2;
        return ok(main_insn);
    }
    // 纯 IR 折叠: extra = [可选 Mov; Not], main = And(d, s2)
    if (!d_eq_s1) {
        // d 独立: 先拷 NOT 项到 dst (保护 s1 — 原生 andn 不写 s1)
        ir::Insn mv;
        mv.op = Op::Mov;
        mv.addr = ci.address;
        mv.size = sz;
        mv.dst = *d;
        mv.src = *s1;
        mv.updates_flags = false;
        pre.push_back(mv);
    }
    ir::Insn nt;
    nt.op = Op::Not;
    nt.addr = ci.address;
    nt.size = sz;
    nt.dst = *d;
    nt.updates_flags = false;
    pre.push_back(nt);
    main_insn.op = Op::And;
    main_insn.src = *s2;
    TranslateResult r = ok(main_insn);
    r.extra = std::move(pre);
    return r;
}

// ---- bzhi (BMI1, VEX.NDS.LZ.0F38.F7): dst = value & ((1<<idx)-1) ----
// 操作数映射 (probe 实测): op[0]=dst(reg) / op[1]=value (r/m 可 mem,
// `bzhi r8d,[m],r` 收) / op[2]=index (reg-only)。
// 边界语义 (Zen5 probe, 纠正 432 §2.1 预判):
//   - index 用 SRC2[7:0] (0x105 → 5, 高位垃圾忽略);
//   - index=0 → 结果 0 ((1<<0)-1=0, 与 shift 的 count=0 no-op 不同);
//   - index≥N → **结果 = value 原值不变 + CF=1** (非"结果 0"; ZF/SF/PF 按
//     结果, OF=0)。
// 恒走载体 (mask 需独占临时 + 边界 clamp/CF 补丁, 无纯 IR 折叠形):
// (Op::Sub, dst, src=value, src2=Reg(index)), translator 展开 (见该函数注)。
TranslateResult translate_bzhi(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    if (x.op_count != 3) return unsupported(ci.address, ci.size);
    auto d = to_operand(x.operands[0]);
    auto v = to_operand(x.operands[1]);
    auto ix = to_operand(x.operands[2]);
    if (!d || !v || !ix) return unsupported(ci.address, ci.size);
    if (d->kind != Operand::Kind::Reg || ix->kind != Operand::Kind::Reg)
        return unsupported(ci.address, ci.size);
    if (v->kind != Operand::Kind::Reg && v->kind != Operand::Kind::Mem)
        return unsupported(ci.address, ci.size);
    const ir::Size sz = data_size(x.operands, x.op_count, arch);
    if (sz != ir::Size::S32 && sz != ir::Size::S64)
        return unsupported(ci.address, ci.size);
    ir::Insn out;
    out.op = Op::Sub;  // 载体 (src2=Reg(index) 判据, 见域注)
    out.addr = ci.address;
    out.size = sz;
    out.dst = *d;
    out.src = *v;
    out.src2 = *ix;
    out.updates_flags = true;
    return ok(out);
}

// ---- rorx/shlx/sarx/shrx (BMI2) flagless 变体 ----
// 操作数映射 (probe 实测): op[0]=dst(reg) / op[1]=value (r/m 可 mem) /
// op[2]=count (rorx=imm8 / shlx 族=reg-only)。count 掩码 & (N-1) (rorx 32→0、
// 193→1 实测; shlx 0x105 → 5, 低字节语义与 VM 既有 cl 掩码通路一致);
// **五位 flags 全不受影响** (probe raw 0x247 全程, count=0 同 — 与原生
// ror/shl "按结果写全量" 分叉, 正是 P1 机制要抹平的面)。
// IR: [可选 Mov/Load(d, value)] + 主 insn:
//   rorx:       (Op::Ror, d, src=Imm(count), src2=Imm(kFlagless))
//               — count 骑 src (与原生 ror-imm 同形)
//   shlx/sarx/  (Op::{Shl,Sar,Shr}, d, src=Reg(cnt), src2=Imm(kFlagless))
//   shrx:         — cnt 骑 src (与原生 shl-cl 的 Reg 形同构); translator
//                   展开为 [GetFlags(s); VmOp(d, Reg cnt); SetFlags(s)],
//                   build_shift 的 b=Reg 通用计数通路 (T7 任意槽, B.4)
TranslateResult translate_bmi_shift(const cs_insn& ci, const cs_x86& x, ir::Arch arch, Op op) {
    if (x.op_count != 3) return unsupported(ci.address, ci.size);
    auto d = to_operand(x.operands[0]);
    auto v = to_operand(x.operands[1]);
    if (!d || !v) return unsupported(ci.address, ci.size);
    if (d->kind != Operand::Kind::Reg) return unsupported(ci.address, ci.size);
    if (v->kind != Operand::Kind::Reg && v->kind != Operand::Kind::Mem)
        return unsupported(ci.address, ci.size);
    const ir::Size sz = data_size(x.operands, x.op_count, arch);
    if (sz != ir::Size::S32 && sz != ir::Size::S64)
        return unsupported(ci.address, ci.size);

    // 前置: value ≠ dst 时先装载 (reg=Mov / mem=Load, 408/248 通道)
    std::vector<ir::Insn> pre;
    if (v->kind == Operand::Kind::Reg) {
        if (v->reg == d->reg) {
            // d==value: 直走 (dst 覆写 = 原生三地址语义)
        } else {
            ir::Insn mv;
            mv.op = Op::Mov;
            mv.addr = ci.address;
            mv.size = sz;
            mv.dst = *d;
            mv.src = *v;
            mv.updates_flags = false;
            pre.push_back(mv);
        }
    } else {
        ir::Insn ld;
        ld.op = Op::Load;
        ld.addr = ci.address;
        ld.size = sz;
        ld.dst = *d;
        ld.src = *v;
        ld.updates_flags = false;
        pre.push_back(ld);
    }

    ir::Insn main_insn;
    main_insn.op = op;
    main_insn.addr = ci.address;
    main_insn.size = sz;
    main_insn.dst = *d;
    main_insn.src2 = Operand::imm_(kFlagless);  // flagless 载体 (判据见域注)
    main_insn.updates_flags = false;            // 五位全不写 (probe)
    if (op == Op::Ror) {
        // rorx: count = imm8 (op[2]); 恒 Imm (probe n=['r','r','i'])
        if (x.operands[2].type != X86_OP_IMM) return unsupported(ci.address, ci.size);
        main_insn.src = Operand::imm_(static_cast<i64>(x.operands[2].imm));
    } else {
        // shlx/sarx/shrx: count = reg (op[2], vvvv reg-only)
        auto cnt = to_operand(x.operands[2]);
        if (!cnt || cnt->kind != Operand::Kind::Reg) return unsupported(ci.address, ci.size);
        main_insn.src = *cnt;
    }
    TranslateResult r = ok(main_insn);
    r.extra = std::move(pre);
    return r;
}

// ============================================================================
// MIT-506/507 (T60): x87 L0 translate —— 物理FPU驻留直执行 (架构定案
// GAPS MIT-506)。guest ST 栈 = 物理 st0-st7 (硬件 TOP 相对, st(i) 索引
// 即物理栈位, 零翻译); IR/VmOp 只携带 形/宽度/栈位, handler 直发真实
// x87 指令。fnop → Op::Nop (零新 op); fcom/ftst/fcmov/超越族/状态控制
// 全族维持 gate (L1-L3)。tbyte(10B) 宽度经 src2=Imm(10) 标记 (G8a src2
// 载体先例; ir::Size 无 10B 值)。fstsw(含 wait 前缀) 与 fnstsw 同映射
// (掩码异常缺省下 wait 语义等价, 披露)。
// ============================================================================
namespace {
std::optional<u8> st87_index(x86_reg r) {
    if (r >= X86_REG_ST0 && r <= X86_REG_ST7)
        return static_cast<u8>(r - X86_REG_ST0);
    return std::nullopt;
}
} // namespace

TranslateResult translate_x87(const cs_insn& ci, const cs_x86& x) {
    // T61 重启（4C 修复 + 硬件真值表）：T60 热修回退的根因 = 词流链路三处
    // 缺陷 —— ① farith rev/pop/目的方向未按编码字节推导（D8/DC r 位反转
    // 与 D8/DE 单操作数报告面，X87MatrixHardwareTruthFull 宿主实测钉表）；
    // ② fcomip handler 双弹栈；③ Fnstsw87 AX 形发射/判据冲突。修复后
    // handler 电池（X87FarithQuadrantsVm 等）+ 样本 E2E 复验。
    const bool kX87L0Enabled = true;
    if (!kX87L0Enabled) return unsupported(ci.address, ci.size);
    ir::Insn out;
    out.addr = ci.address;
    const auto fail = [&]() { return unsupported(ci.address, ci.size); };
    // mem 宽度: 4 → S32, 8 → S64; 10 → S64 载体 + src2=Imm(10) (tbyte)。
    const auto set_width = [&](ir::Insn& o, unsigned bytes) {
        o.size = (bytes == 4) ? ir::Size::S32 : ir::Size::S64;
        if (bytes == 10) o.src2 = ir::Operand::imm_(10);
    };
    switch (ci.id) {
    case X86_INS_FLD: {
        if (x.op_count != 1) return fail();
        if (x.operands[0].type == X86_OP_MEM) {
            auto m = mem_operand(x.operands[0].mem);
            if (!m) return fail();
            const unsigned w = x.operands[0].size;
            if (w != 4 && w != 8 && w != 10) return fail();
            out.op = Op::Fld87Mem;
            out.src = *m;
            set_width(out, w);
            return ok(out);
        }
        const auto si = st87_index(x.operands[0].reg);
        if (!si) return fail();
        out.op = Op::Fld87St;
        out.src = ir::Operand::imm_(*si);
        return ok(out);
    }
    case X86_INS_FLD1:
        out.op = Op::Fld87Const;
        out.src = ir::Operand::imm_(1);
        return ok(out);
    case X86_INS_FLDZ:
        out.op = Op::Fld87Const;
        out.src = ir::Operand::imm_(0);
        return ok(out);
    case X86_INS_FST:
    case X86_INS_FSTP: {
        if (x.op_count != 1) return fail();
        const bool pop = ci.id == X86_INS_FSTP;
        if (x.operands[0].type == X86_OP_MEM) {
            auto m = mem_operand(x.operands[0].mem);
            if (!m) return fail();
            const unsigned w = x.operands[0].size;
            // fst 无 tbyte 形 (SDM: fst 仅 m32/m64/st(i)); fstp 有 10B。
            if (w != 4 && w != 8 && !(pop && w == 10)) return fail();
            out.op = pop ? Op::Fstp87Mem : Op::Fst87Mem;
            out.dst = *m;
            set_width(out, w);
            return ok(out);
        }
        const auto si = st87_index(x.operands[0].reg);
        if (!si) return fail();
        out.op = pop ? Op::Fstp87St : Op::Fst87St;
        out.dst = ir::Operand::imm_(*si);
        return ok(out);
    }
    case X86_INS_FILD:
    case X86_INS_FIST:
    case X86_INS_FISTP: {
        if (x.op_count != 1 || x.operands[0].type != X86_OP_MEM) return fail();
        auto m = mem_operand(x.operands[0].mem);
        if (!m) return fail();
        const unsigned w = x.operands[0].size;
        // SDM: FILD m16/m32/m64; FIST 仅 m16/m32 (**无 64 位形式**); FISTP
        // m16/m32/m64。m16 维持 gate (L0 范围 m32/m64); FIST m64 → 编码不
        // 存在 → fail (keystone 实证 fist qword 装配非法)。
        if (w != 4 && w != 8) return fail();
        if (ci.id == X86_INS_FIST && w == 8) return fail();
        out.op = ci.id == X86_INS_FILD  ? Op::Fild87Mem
                 : ci.id == X86_INS_FIST ? Op::Fist87Mem
                                          : Op::Fistp87Mem;
        out.src = *m;
        set_width(out, w);
        return ok(out);
    }
    case X86_INS_FADD:  // 含 faddp (DE /0 折叠, capstone 无 FADDP id)
    case X86_INS_FMUL: case X86_INS_FMULP:
    case X86_INS_FSUB: case X86_INS_FSUBP: case X86_INS_FSUBR: case X86_INS_FSUBRP:
    case X86_INS_FDIV: case X86_INS_FDIVP: case X86_INS_FDIVR: case X86_INS_FDIVRP: {
        // ** rev/pop 与目的方向从编码字节推导 ** (硬件真表, X86Battery.
        // X87MatrixHardwareTruthFull 宿主实测钉死):
        //   D8 reg: dst=st(0), 显式位=源; f=4 fsub, 5 fsubr, 6 fdiv, 7 fdivr
        //   DC reg: dst=st(rm), 显式位=目的; f=4 fsubr, 5 fsub, 6 fdivr,
        //           7 fdiv —— **r 位反转在 D8 与 DC 之间** (首版 Intel 表
        //           记忆误置 DE, 实测推翻)
        //   DE reg: 沿用 DC 方向 + pop; f=4 fsubrp, 5 fsubp, 6 fdivrp,
        //           7 fdivp
        //   mem 形: f=4 sub/6 div, f=5 subr/7 divr (mem 表**不**反转)
        // capstone 5.0.6 对 D8/DE reg 报**单操作数** (op0=st(rm)), DC reg
        // 报双操作数 (op0=st(rm)=dst, op1=st(0)); 命名与硬件全程一致。
        const u8 opc = ci.bytes[0];
        const u8 modrm = ci.bytes[1];  // cs_insn::bytes 定长 16, 矩阵形必有 modrm
        const u8 f = (modrm >> 3) & 7;  // modrm reg 字段
        const bool is_de = opc == 0xDE;
        const bool is_mem = x.operands[0].type == X86_OP_MEM;
        const bool rev = is_mem ? (f == 5 || f == 7)
                        : opc == 0xD8 ? (f == 5 || f == 7)
                                      : (f == 4 || f == 6);
        u32 aux = 0;
        if (rev) aux |= 0x2;  // reverse 位
        if (is_de) aux |= 0x1;  // pop 位
        Op base;
        if (f == 0) base = Op::Fadd87;
        else if (f == 1) base = Op::Fmul87;
        else if (f == 4 || f == 5) base = Op::Fsub87;
        else base = Op::Fdiv87;
        if (is_mem) {
            // mem 形: st0 ±×÷ [mem], 无 pop (DE mod≠11 非算术矩阵)。
            if (x.op_count != 1) return fail();
            if (is_de) return fail();
            auto m = mem_operand(x.operands[0].mem);
            if (!m) return fail();
            const unsigned w = x.operands[0].size;
            if (w != 4 && w != 8) return fail();
            out.op = base;
            out.src = *m;
            set_width(out, w);
            out.src2 = ir::Operand::imm_(aux);
            return ok(out);
        }
        if (x.op_count == 1 && x.operands[0].type == X86_OP_REG) {
            // 单操作数报告 (D8/DE reg): op0=st(rm)。
            const auto si = st87_index(x.operands[0].reg);
            if (!si) return fail();
            out.op = base;
            if (is_de) {
                out.dst = ir::Operand::imm_(*si);  // DE: 目的 = st(rm)
                out.src = ir::Operand::imm_(0);
            } else {
                out.dst = ir::Operand::imm_(0);    // D8: 目的 = st(0)
                out.src = ir::Operand::imm_(*si);
            }
            out.src2 = ir::Operand::imm_(aux);
            return ok(out);
        }
        // 双操作数报告 (DC reg): op0 = dst st(rm), op1 = src st(0)。
        if (x.op_count != 2) return fail();
        const auto di = st87_index(x.operands[0].reg);
        const auto sj = st87_index(x.operands[1].reg);
        if (!di || !sj || *sj != 0) return fail();
        out.op = base;
        out.dst = ir::Operand::imm_(*di);
        out.src = ir::Operand::imm_(*sj);
        out.src2 = ir::Operand::imm_(aux);
        return ok(out);
    }
    case X86_INS_FCHS:
        out.op = Op::Fchs87;
        return ok(out);
    case X86_INS_FABS:
        out.op = Op::Fabs87;
        return ok(out);
    case X86_INS_FSQRT:
        out.op = Op::Fsqrt87;
        return ok(out);
    case X86_INS_FCOMI:  // fcomip = X86_INS_FCOMPI (T61 探针: dff1 报 fcompi)
    case X86_INS_FCOMPI: {  // pop 按首字节判定 (DF)
        // capstone 实测: fcomi/fcomip 报**单 REG 操作数** (op0=st(i), 隐式
        // st0); 双操作数形式保留兼容分支。FCOMI 只写 EFLAGS (不更新 SW
        // C0) — handler 捕获链走物理 EFLAGS (setz/setp/setc)。
        const bool pop = ci.bytes[0] == 0xDF;
        const auto si = (x.op_count == 1 && x.operands[0].type == X86_OP_REG)
                            ? st87_index(x.operands[0].reg)
                            : (x.op_count == 2 && x.operands[1].type == X86_OP_REG)
                                  ? st87_index(x.operands[1].reg)
                                  : std::nullopt;
        if (!si) return fail();
        out.op = pop ? Op::Fcomip87 : Op::Fcomi87;
        out.src = ir::Operand::imm_(*si);
        out.updates_flags = true;  // 物理 ZF/PF/CF → ctx flags 捕获链
        return ok(out);
    }
    case X86_INS_FLDCW:
    case X86_INS_FNSTCW:  // 含 fstcw (9B 前缀折叠, 无 FSTCW id)
    case X86_INS_FNSTSW: {  // 含 fstsw ax/m16 (9B 折叠, 无 FSTSW id)
        if (x.op_count != 1) return fail();
        const bool sw = ci.id == X86_INS_FNSTSW;  // fstsw (9B) 折叠同 id
        // AX 形 (fnstsw ax / fstsw ax): capstone op = REG_AX。
        if (x.operands[0].type == X86_OP_REG && sw &&
            x.operands[0].reg == X86_REG_AX) {
            out.op = Op::Fnstsw87;
            out.dst = ir::Operand::reg_(ir::Reg::Rax);  // AX 形标记
            return ok(out);
        }
        if (x.operands[0].type != X86_OP_MEM) return fail();
        auto m = mem_operand(x.operands[0].mem);
        if (!m) return fail();
        out.op = sw ? Op::Fnstsw87
                     : (ci.id == X86_INS_FNSTCW ? Op::Fnstcw87 : Op::Fldcw87);
        out.src = *m;
        out.size = ir::Size::S16;
        return ok(out);
    }
    case X86_INS_FNOP:
        out.op = Op::Nop;
        return ok(out);

        // ---- MIT-510 (T62): x87 L1-L4 续延 ----
    case X86_INS_FCOM:  // fcom/fcomp: 单操作数报告 (reg=st(i) 源 / mem);
    case X86_INS_FCOMP: // DC mem 形不反转; pop 按 id。aux 位图:
    case X86_INS_FUCOM: // bit0=pop, bit1=u, bit2=dword, bit3=qword。
    case X86_INS_FUCOMP: {
        u32 aux = 0;
        if (ci.id == X86_INS_FCOMP || ci.id == X86_INS_FUCOMP) aux |= 0x1;
        if (ci.id == X86_INS_FUCOM || ci.id == X86_INS_FUCOMP) aux |= 0x2;
        if (x.op_count == 1 && x.operands[0].type == X86_OP_MEM) {
            auto m = mem_operand(x.operands[0].mem);
            if (!m) return fail();
            // ⚠️ keystone 不装配 fucom/fucomp mem 形 (INVALIDOPERAND 实证)
            // → mem+u 组合 D5 gate (罕见面, native 保字节精确)。
            if (aux & 0x2) return fail();
            const unsigned w = x.operands[0].size;
            if (w != 4 && w != 8) return fail();
            out.op = Op::Fcom87;
            out.src = *m;
            set_width(out, w);
            out.src2 = ir::Operand::imm_(aux | (w == 4 ? 0x4u : 0x8u));
            return ok(out);
        }
        const auto si = (x.op_count >= 1 && x.operands[0].type == X86_OP_REG)
                            ? st87_index(x.operands[0].reg)
                            : std::nullopt;
        if (!si) return fail();
        out.op = Op::Fcom87;
        out.dst = ir::Operand::imm_(0);  // fcom st(0), st(i) — 显式位=源
        out.src = ir::Operand::imm_(*si);
        out.src2 = ir::Operand::imm_(aux);
        return ok(out);
    }
    case X86_INS_FCOMPP:
        out.op = Op::Fcompp87;
        return ok(out);
    case X86_INS_FTST:
        out.op = Op::Ftst87;
        return ok(out);
    case X86_INS_FXAM:
        out.op = Op::Fxam87;
        return ok(out);
    case X86_INS_FUCOMI:  // 写 EFLAGS (ZF/PF/CF, NaN → ZF=PF=1) — 沿用
    case X86_INS_FUCOMPI: {  // Fcomi87/Fcomip87 词, aux bit0=u 选助记符。
        const bool pop = ci.id == X86_INS_FUCOMPI;
        const auto si = (x.op_count >= 1 && x.operands[0].type == X86_OP_REG)
                            ? st87_index(x.operands[0].reg)
                            : std::nullopt;
        if (!si) return fail();
        out.op = pop ? Op::Fcomip87 : Op::Fcomi87;
        out.src = ir::Operand::imm_(*si);
        out.src2 = ir::Operand::imm_(0x1);  // u 助记符位 (handler 选 fucomi)
        out.updates_flags = true;
        return ok(out);
    }
    case X86_INS_FXCH: {
        // capstone 报双操作数 (op0=st0, op1=st(i)) — fxch st, st(i)。
        if (x.op_count != 2 || x.operands[1].type != X86_OP_REG) return fail();
        const auto sj = st87_index(x.operands[1].reg);
        if (!sj) return fail();
        out.op = Op::Fxch87;
        out.src = ir::Operand::imm_(*sj);  // Fxch87 词域 = b=Imm i
        return ok(out);
    }
    case X86_INS_FFREE:
    case X86_INS_FFREEP: {  // DF C0+i = ffreep (capstone 实证); pop 变体
        // 由 handler 发 ffree st(k) + fstp st(0) 等价组合 (keystone 装配
        // ffreep 兜底风险)。
        const auto si = (x.op_count >= 1 && x.operands[0].type == X86_OP_REG)
                            ? st87_index(x.operands[0].reg)
                            : std::nullopt;
        if (!si) return fail();
        out.op = Op::Ffree87;
        out.src = ir::Operand::imm_(*si);
        out.src2 = ir::Operand::imm_(ci.id == X86_INS_FFREEP ? 0x1u : 0x0u);
        return ok(out);
    }
    case X86_INS_FDECSTP:
        out.op = Op::Fincdecstp87;
        out.src2 = ir::Operand::imm_(0x0);
        return ok(out);
    case X86_INS_FINCSTP:
        out.op = Op::Fincdecstp87;
        out.src2 = ir::Operand::imm_(0x1);
        return ok(out);
    case X86_INS_FCMOVB: case X86_INS_FCMOVE: case X86_INS_FCMOVBE:
    case X86_INS_FCMOVU: case X86_INS_FCMOVNB: case X86_INS_FCMOVNE:
    case X86_INS_FCMOVNBE: case X86_INS_FCMOVNU: {
        // ⚠️ 宿主实测 (T62 探针): **DA 段=正形 (b/e/be/u), DB 段=反形
        // (nb/ne/nbe/nu)** — dbc1 报 fcmovnb。cc 序 0..7 = b/e/be/u/
        // nb/ne/nbe/nu。capstone 报双操作数 (op0=st0 dst, op1=st(i) 源)。
        u32 cc;
        switch (ci.id) {
        case X86_INS_FCMOVB: cc = 0; break;
        case X86_INS_FCMOVE: cc = 1; break;
        case X86_INS_FCMOVBE: cc = 2; break;
        case X86_INS_FCMOVU: cc = 3; break;
        case X86_INS_FCMOVNB: cc = 4; break;
        case X86_INS_FCMOVNE: cc = 5; break;
        case X86_INS_FCMOVNBE: cc = 6; break;
        case X86_INS_FCMOVNU: cc = 7; break;
        default: return fail();
        }
        if (x.op_count != 2 || x.operands[1].type != X86_OP_REG) return fail();
        const auto sj = st87_index(x.operands[1].reg);
        if (!sj) return fail();
        out.op = Op::Fcmov87;
        out.dst = ir::Operand::imm_(0);
        out.src = ir::Operand::imm_(*sj);
        out.src2 = ir::Operand::imm_(cc);
        return ok(out);
    }
    case X86_INS_FLDPI:
        out.op = Op::Fld87Const;
        out.src = ir::Operand::imm_(2);
        return ok(out);
    case X86_INS_FLDL2T:
        out.op = Op::Fld87Const;
        out.src = ir::Operand::imm_(3);
        return ok(out);
    case X86_INS_FLDL2E:
        out.op = Op::Fld87Const;
        out.src = ir::Operand::imm_(4);
        return ok(out);
    case X86_INS_FLDLG2:
        out.op = Op::Fld87Const;
        out.src = ir::Operand::imm_(5);
        return ok(out);
    case X86_INS_FLDLN2:
        out.op = Op::Fld87Const;
        out.src = ir::Operand::imm_(6);
        return ok(out);
    case X86_INS_F2XM1:
        out.op = Op::F2xm187;
        return ok(out);
    case X86_INS_FYL2X:
        out.op = Op::Fyl2x87;
        return ok(out);
    case X86_INS_FYL2XP1:
        out.op = Op::Fyl2xp187;
        return ok(out);
    case X86_INS_FSCALE:
        out.op = Op::Fscale87;
        return ok(out);
    case X86_INS_FPATAN:
        out.op = Op::Fpatan87;
        return ok(out);
    case X86_INS_FPREM:
        out.op = Op::Fprem87;
        out.src2 = ir::Operand::imm_(0x0);
        return ok(out);
    case X86_INS_FPREM1:
        out.op = Op::Fprem87;
        out.src2 = ir::Operand::imm_(0x1);
        return ok(out);
    case X86_INS_FSIN:
        out.op = Op::Fsin87;
        return ok(out);
    case X86_INS_FCOS:
        out.op = Op::Fcos87;
        return ok(out);
    case X86_INS_FSINCOS:
        out.op = Op::Fsincos87;
        return ok(out);
    case X86_INS_FPTAN:
        out.op = Op::Fptan87;
        return ok(out);
    case X86_INS_FRNDINT:
        out.op = Op::Frndint87;
        return ok(out);
    case X86_INS_FXTRACT:
        out.op = Op::Fxtract87;
        return ok(out);
    case X86_INS_FNCLEX:
        out.op = Op::Fnclex87;
        return ok(out);
    case X86_INS_FNINIT:
        out.op = Op::Fninit87;
        return ok(out);
    default:
        return fail();
    }
}

TranslateResult translate_insn(const cs_insn& ci, ir::Arch arch) {
    if (ci.detail == nullptr) return unsupported(ci.address, ci.size);
    const cs_x86& x = ci.detail->x86;

    // 带 lock/rep/repne 前缀（prefix[0]）的指令语义与普通形式不同，
    // 段覆盖前缀（prefix[1]，如 gs:[..] TLS 访问）无法在平坦内存模型下
    // 虚拟化——v1 一律跳过。
    // MIT-415 (G3): 例外放行 rep/repnz 串指令族 (movs/stos/scas/cmps/lods)
    // — 经 detail 级三元组白名单 (mnemonic+prefix+宽度) 判定
    // (translate_string_op); 其余带前缀指令 (lock/rep 非串指令/rep x87
    // 逃逸类等) 照旧拒。无前缀串指令 (plain movsb) 不在白名单 — 落
    // switch default 照旧 gate (§B.7 残余披露)。
    // MIT-419 (G4): 例外放行 F0 (lock) 白名单三元组 — add/adc/sub/sbb/and/
    // or/xor × mem-dst + cmpxchg/xchg/xadd mem 形式 + bts/btr/btc mem 形式
    // (translate_lock_op; D4 仅 F0 独前缀, strip-and-execute, 原子性边界见
    // GAPS G4 节)。非白名单 lock 组合照旧拒。
    // MIT-442 (X2a) B.4: 67 (地址宽覆盖, prefix[3]) 显式 gate —— 16 位寻址
    // (x86) / 地址截断 32 位 (x64) 编译器不产 (X0 §1.4 lea 行判), 平坦模型
    // 地址语义不符 (x64 67 形 base 截断会错址), 保守拒。四位前缀位置判据
    // (probe 单测钉死): prefix[0]=rep/lock, prefix[1]=段覆盖 (SEH 闸 438),
    // prefix[2]=66 操作数宽 (S16/p66 通路, 双 arch 同位), prefix[3]=67 地址
    // 宽 —— 互不误伤: 66/67 不触碰 SEH 闸, 66+67 组合由本闸先拦。
    if (x.prefix[3] != 0) {
        return unsupported(ci.address, ci.size);
    }
    if (x.prefix[0] != 0 || x.prefix[1] != 0) {
        if (string_family_of(static_cast<x86_insn>(ci.id)).has_value())
            return translate_string_op(ci, x, arch);
        if (x.prefix[0] == 0xF0)
            return translate_lock_op(ci, x, arch);
        return unsupported(ci.address, ci.size);
    }

    switch (ci.id) {
    case X86_INS_MOV: return translate_mov(ci, x, arch);
    case X86_INS_MOVABS: return translate_mov(ci, x, arch);  // MIT-247 fix: movabs imm64 与 mov 共用 translate_mov, 翻译器对 S64 不可直放 imm 走 emit_imm64_split
    case X86_INS_LEA: return translate_lea(ci, x, arch);
    case X86_INS_ADD: return translate_alu(ci, x, arch, Op::Add);
    case X86_INS_SUB: return translate_alu(ci, x, arch, Op::Sub);
    case X86_INS_ADC: return translate_alu(ci, x, arch, Op::Adc);
    case X86_INS_SBB: return translate_alu(ci, x, arch, Op::Sbb);
    case X86_INS_AND: return translate_alu(ci, x, arch, Op::And);
    case X86_INS_OR: return translate_alu(ci, x, arch, Op::Or);
    case X86_INS_XOR: return translate_alu(ci, x, arch, Op::Xor);
    case X86_INS_NOT: return translate_unary(ci, x, arch, Op::Not, /*sets_flags=*/false);
    case X86_INS_NEG: return translate_unary(ci, x, arch, Op::Neg, /*sets_flags=*/true);
    case X86_INS_INC: return translate_unary(ci, x, arch, Op::Inc, /*sets_flags=*/true);
    case X86_INS_DEC: return translate_unary(ci, x, arch, Op::Dec, /*sets_flags=*/true);
    case X86_INS_SHL: return translate_shift(ci, x, arch, Op::Shl);
    case X86_INS_SHR: return translate_shift(ci, x, arch, Op::Shr);
    case X86_INS_SAR: return translate_shift(ci, x, arch, Op::Sar);
    case X86_INS_ROL: return translate_shift(ci, x, arch, Op::Rol);
    case X86_INS_ROR: return translate_shift(ci, x, arch, Op::Ror);
    case X86_INS_CMP: return translate_cmp_test(ci, x, arch, Op::Cmp);
    case X86_INS_TEST: return translate_cmp_test(ci, x, arch, Op::Test);
    case X86_INS_PUSH: return translate_push(ci, x, arch);
    case X86_INS_POP: return translate_pop(ci, x, arch);
    case X86_INS_JMP: return translate_jmp(ci, x, arch);
    case X86_INS_JO: case X86_INS_JNO: case X86_INS_JB: case X86_INS_JAE:
    case X86_INS_JE: case X86_INS_JNE: case X86_INS_JBE: case X86_INS_JA:
    case X86_INS_JS: case X86_INS_JNS: case X86_INS_JP: case X86_INS_JNP:
    case X86_INS_JL: case X86_INS_JGE: case X86_INS_JLE: case X86_INS_JG:
        return translate_jcc(ci, x, arch);
    case X86_INS_CALL: return translate_call(ci, x, arch);
    case X86_INS_RET: return translate_ret(ci, x, arch);
    case X86_INS_IMUL: return translate_imul(ci, x, arch);
    case X86_INS_MUL: return translate_mul(ci, x, arch);
    case X86_INS_MOVSXD: return translate_movsxd(ci, x, arch);
    // MIT-404: cdqe (48 98) 归一 Movsxd (D1.1) — vendored capstone 分裂枚举,
    // X86_INS_CDQE=452 与 X86_INS_MOVSXD=880 两个 case 显式收口 (MIT-313)。
    case X86_INS_CDQE: return translate_cdqe(ci, x, arch);
    // MIT-404: cdq (99) / cqo (48 99) 共用 Op::Cdq, size 由 REX.W 区分。
    case X86_INS_CDQ: return translate_cdq(ci, x, arch);
    case X86_INS_CQO: return translate_cdq(ci, x, arch);
    // MIT-404: div (F7 /6) / idiv (F7 /7) — REG + MEM 形式, 隐式 dividend
    // rdx:rax 由 VM handler 内部拼装 (双结果槽协议)。
    case X86_INS_DIV: return translate_div_idiv(ci, x, arch, Op::Div);
    case X86_INS_IDIV: return translate_div_idiv(ci, x, arch, Op::Idiv);
    case X86_INS_MOVZX: return translate_movzx(ci, x, arch);
    case X86_INS_MOVSX: return translate_movsx(ci, x, arch);
    // MIT-349: popcnt (F3 0F B8+rm, mod=11 REG-REG / mod=00/01/10 MEM 派活单限定不支持).
    case X86_INS_POPCNT: return translate_popcnt(ci, x, arch);
    // MIT-353: lzcnt (F3 0F BD+rm, mod=11 REG-REG / mod=00/01/10 MEM 派活单限定不支持).
    case X86_INS_LZCNT: return translate_lzcnt(ci, x, arch);
    // MIT-353: tzcnt (F3 0F BC+rm, mod=11 REG-REG / mod=00/01/10 MEM 派活单限定不支持).
    case X86_INS_TZCNT: return translate_tzcnt(ci, x, arch);
    // MIT-371: SSE 浮点加 addss/addps/addpd (REG-REG only, mod=11).
    //   - addss xmm1, xmm2/m32  F3 0F 58 /r  (scalar single, size=S32)
    //   - addps xmm1, xmm2/m128 0F 58 /r     (packed single, size=S64)
    //   - addpd xmm1, xmm2/m128 66 0F 58 /r  (packed double, size=S64)
    // MSVC /Od 默认 codegen REG-REG (mod=11), MSVC x64 不支持 inline asm,
    // 高 level C++ 在 /Od 下用 <intrin.h> 的 _mm_add_ss/_mm_add_ps/_mm_add_pd
    // 内部函数直接 emit 真 SSE 字节（无需 MASM helper 强制 codegen）。
    case X86_INS_ADDSS: return translate_sse_add(ci, x, arch, Op::Addss, Size::S32);
    case X86_INS_ADDPS: return translate_sse_add(ci, x, arch, Op::Addps, Size::S64);
    case X86_INS_ADDPD: return translate_sse_add(ci, x, arch, Op::Addpd, Size::S64);
    // MIT-408: addsd (F2 0F 58, scalar double) 经 (Addss,S64) 编码 —
    // ir::Op 冻结不可增枚举, (op,size) 组合在旧 lifter 中从不产生, 无歧义.
    case X86_INS_ADDSD: return translate_sse_add(ci, x, arch, Op::Addss, Size::S64);
    // MIT-373: SSE 浮点减 subss/subps/subpd (REG-REG only, mod=11).
    //   - subss xmm1, xmm2/m32  F3 0F 5C /r  (scalar single, size=S32)
    //   - subps xmm1, xmm2/m128 0F 5C /r     (packed single, size=S64)
    //   - subpd xmm1, xmm2/m128 66 0F 5C /r  (packed double, size=S64)
    // MASM helper 强制 codegen (pitfall #35): /Od 下 intrinsics 会融合
    // load+sub 为 MEM 形式, E2E 样本由 sse_sub_sample_asm.asm emit 真 REG-REG 字节.
    case X86_INS_SUBSS: return translate_sse_sub(ci, x, arch, Op::Subss, Size::S32);
    case X86_INS_SUBPS: return translate_sse_sub(ci, x, arch, Op::Subps, Size::S64);
    case X86_INS_SUBPD: return translate_sse_sub(ci, x, arch, Op::Subpd, Size::S64);
    // MIT-408: subsd (F2 0F 5C, scalar double) 经 (Subss,S64) 编码.
    case X86_INS_SUBSD: return translate_sse_sub(ci, x, arch, Op::Subss, Size::S64);
    // MIT-374: SSE 浮点除 divss/divps/divpd (REG-REG only, mod=11).
    //   - divss xmm1, xmm2/m32  F3 0F 5E /r  (scalar single, size=S32)
    //   - divps xmm1, xmm2/m128 0F 5E /r     (packed single, size=S64)
    //   - divpd xmm1, xmm2/m128 66 0F 5E /r  (packed double, size=S64)
    // MASM helper 强制 codegen (pitfall #35): /Od 下 intrinsics 会融合
    // load+div 为 MEM 形式, E2E 样本由 sse_div_sample_asm.asm emit 真 REG-REG 字节.
    // divsd (F2 0F 5E, scalar double) 不在本单范围 → 落 C1 gate 兜底.
    case X86_INS_DIVSS: return translate_sse_div(ci, x, arch, Op::Divss, Size::S32);
    case X86_INS_DIVPS: return translate_sse_div(ci, x, arch, Op::Divps, Size::S64);
    case X86_INS_DIVPD: return translate_sse_div(ci, x, arch, Op::Divpd, Size::S64);
    // MIT-408: divsd (F2 0F 5E, scalar double) 经 (Divss,S64) 编码.
    case X86_INS_DIVSD: return translate_sse_div(ci, x, arch, Op::Divss, Size::S64);
    // MIT-375: SSE 浮点传送 movss/movaps/movapd/movups/movupd (REG-REG load only).
    //   - movss  F3 0F 10 /r (标量, 只搬低 32 位/高位保持) / movaps 0F 28 /r /
    //     movapd 66 0F 28 /r / movups 0F 10 /r / movupd 66 0F 10 /r
    //   - store 方向与 MEM 形式 lifter 拒 → C1 gate 兜底 (详见 translate_sse_mov).
    case X86_INS_MOVSS: return translate_sse_mov(ci, x, arch, Op::Movss, Size::S32);
    case X86_INS_MOVAPS: return translate_sse_mov(ci, x, arch, Op::Movaps, Size::S64);
    case X86_INS_MOVAPD: return translate_sse_mov(ci, x, arch, Op::Movapd, Size::S64);
    case X86_INS_MOVUPS: return translate_sse_mov(ci, x, arch, Op::Movups, Size::S64);
    case X86_INS_MOVUPD: return translate_sse_mov(ci, x, arch, Op::Movupd, Size::S64);
    // MIT-428 (G1d): SSE2 对齐传送 movdqa/movdqu (66/F3 0F 6F load /
    // 66/F3 0F 7F store) — 语义 = 16B 全宽拷贝, 与 movaps/movups 同构,
    // 直复用 translate_sse_mov (零新 VmOp / 零新 handler, D1 硬约束)。
    //   - movdqa xmm1, xmm2/m128  66 0F 6F /r   (对齐形式, 16B 全宽)
    //   - movdqu xmm1, xmm2/m128  F3 0F 6F /r   (非对齐形式, 16B 全宽)
    //   - 存储方向 66/F3 0F 7F /r (Mem,Reg 形) — 与 movaps 0F 29 同构。
    // §A.4 编码方向 probe 实测 (2026-08-31, vendored capstone 5.0.6):
    //   6F (reg 字段=dst) 与 7F (rm 字段=dst, reg,reg 反写合法形) 双编码
    //   capstone 均归一化为 dst-first 报操作数 (access W 位钉死) —
    //   66 0F 7F C8 报 [xmm0 W, xmm1 R], 与 6F C1 报序一致, 无需调度层
    //   方向修正 (先验 "7F 反写需手动换位" 被实测推翻)。
    // 对齐语义 (D2, 375 先例): movdqa 对齐陷阱 #GP 不模拟 — mem 形式折
    // XmmLoad/XmmStore (408 通路, 运行时 movups 非对齐宽松语义), reg-reg
    // 折 Movaps (handler 中间行 = native movaps xmm0, xmm1 寄存器形态,
    // 无对齐语义面)。EVEX VMOVDQA32/64 (x86.h:1413-1414) 显式不入面。
    case X86_INS_MOVDQA: return translate_sse_mov(ci, x, arch, Op::Movaps, Size::S64);
    case X86_INS_MOVDQU: return translate_sse_mov(ci, x, arch, Op::Movups, Size::S64);
    // MIT-408: movsd (F2 0F 10/11, scalar double, load/store 双向) 经
    // (Movss,S64) 编码。capstone 把 string movsd (A5, mem,mem) 与 SSE movsd
    // 报同一 X86_INS_MOVSD (实证 id=486) — 由双 MEM 操作数形状互斥区分。
    // MIT-442 (X2a) ②: string 形 (Mem,Mem, prefix 全零 = plain 单发) 改派
    // translate_string_op (域 23 单发微程序, 415 前 "落 C1 gate" 的 plain
    // 形翻正); SSE 形 (reg/mem 操作数) 照旧 translate_sse_mov (408 通路)。
    case X86_INS_MOVSD:
        if (x.op_count == 2 && x.operands[0].type == X86_OP_MEM &&
            x.operands[1].type == X86_OP_MEM) {
            return translate_string_op(ci, x, arch);
        }
        return translate_sse_mov(ci, x, arch, Op::Movss, Size::S64);
    // MIT-494x (T47): movlpd store (66 0F 13 /r)——低 64 位存储与 Movss
    // S64 编码语义恒等 → 复用既有 Movss+S64 通路（零新 VmOp/零 asmgen 改
    // 动）。收口面 = MSVC /Od 的 8 字节局部零初始化对（xorps + movlpd
    // [mem], xmm，wvmpTest list_sum 实测：两条 movlpd 未支持 → lifter 跳
    // 2 条 → C1 gate）。load 形（66 0F 12）上 64 位保留语义与标量 store
    // 不同 → 仅收 store 形，load 形维持 unsupported 保守 gate。⚠️ 编码：
    // 0F E2 = PSRAD（首版误认，CapstoneSession 解码探针证伪）。
    case X86_INS_MOVLPD:
        if (x.op_count == 2 && x.operands[0].type == X86_OP_MEM &&
            x.operands[1].type == X86_OP_REG) {
            return translate_sse_mov(ci, x, arch, Op::Movss, Size::S64);
        }
        return unsupported(ci.address, ci.size);
    // MIT-442 (X2a) ②: plain 单发串形 (A4/A5/AA/AB/AC/AD/AE/A6/A7 + Q 形)。
    // rep 形经入口前缀闸 (prefix[0]=F3/F2) 派入同一 translate_string_op 的
    // rep 通路; 本组 case 只接 prefix 全零的单发形 (66 形 movsw/stosw/... 由
    // 函数内前缀三元组检查照旧拒 — G3 S16 串形砍面维持)。CMPSD 的 SSE 同名
    // 形 (F2 0F C2, 3 操作数 (xmm,xmm/m64,imm8)) 由 ④ 形状检查互斥 (非双
    // MEM → unsupported, 与本单前 default-gate 行为一致); MOVSD 同理已在
    // 上方双形态派发。Q 形 (48 A5 等) capstone 正常报 size 8 (REX 在前,
    // 415 F3-in-front 缺陷不涉 plain); 宽度 1/4/8 放行, 2 (66 形) 拒。
    case X86_INS_MOVSB: case X86_INS_MOVSW: case X86_INS_MOVSQ:
    case X86_INS_STOSB: case X86_INS_STOSW: case X86_INS_STOSD: case X86_INS_STOSQ:
    case X86_INS_SCASB: case X86_INS_SCASW: case X86_INS_SCASD: case X86_INS_SCASQ:
    case X86_INS_CMPSB: case X86_INS_CMPSW: case X86_INS_CMPSD: case X86_INS_CMPSQ:
    case X86_INS_LODSB: case X86_INS_LODSW: case X86_INS_LODSD: case X86_INS_LODSQ:
        return translate_string_op(ci, x, arch);
    // MIT-442 (X2a) ③: leave (C9) — [Mov rsp←rbp; Pop rbp] 两既有 IR 折条。
    case X86_INS_LEAVE: return translate_leave(ci, x, arch);
    // MIT-442 (X2a) ④ D5: cld — DF←0 与 VM DF=0 假设一致 → no-op 放行;
    // std (F9) 无 case → default 照旧 gate (D5 裁决, GAPS 清单登记)。
    case X86_INS_CLD: return translate_cld(ci, x, arch);
    // MIT-442 (X2a) ⑥: 98 族 — 66 前缀判别 cbw (66 98) / cwde (98)。
    // capstone 分裂枚举: X86_INS_CWDE 与 X86_INS_CBW 双 id 皆可报 cwde
    // (模式相关), 统一按 prefix[2]==0x66 派发 (B.4 位置判据); cdqe (48 98)
    // 走独立 X86_INS_CDQE case (上方 404 通路)。
    case X86_INS_CBW: case X86_INS_CWDE:
        return (x.prefix[2] == 0x66) ? translate_cbw(ci, x, arch)
                                     : translate_cwde(ci, x, arch);
    // MIT-376: SSE 浮点位运算 xorps/orps/andps (REG-REG only, mod=11).
    //   - xorps 0F 57 /r / orps 0F 56 /r / andps 0F 54 /r (全 128-bit 按位,
    //     size=S64)。updates_flags=false (位运算不影响 EFLAGS)。
    //   - AVX VEX 编码 (vxorps/vorps/vandps, VEX.NDS.128.0F.WIG 57/56/54 —
    //     triage §0.6 名实对齐: 57/56/54 是 float 位运算编码, 整数 vpxor/
    //     vpor/vpand 为 VEX.128.66.0F WIG EF/EB/DA) 由 capstone 报独立
    //     INS id; MIT-426 (G6a) 起 V-pair 白名单折叠, 见 translate_vex128。
    // MIT-411 (G1-c): pd 位运算族 (66 0F 54/56/57) — andpd/orpd/xorpd 与
    // ps 同名位运算逐位同语义 (全 128-bit 按位, 不解释浮点值, 零 flags,
    // 零异常) → **零新 VmOp** 复用 ps 编码 (派活单 §C D1)。实证: ml64
    // 汇编 66 0F 54C1/56C1/57C1 → capstone 报独立 id ANDPD/ORPD/XORPD,
    // prefix[0]=0 (0x66 被吸收进 id, 不经入口前缀拒绝); MSVC /Od 对
    // _mm_and_pd/_mm_or_pd/_mm_xor_pd 甚至直接 emit andps/orps/xorps
    // (ps/pd 互换无损, 编译器自身即证据)。
    case X86_INS_XORPS: return translate_sse_bitwise(ci, x, arch, Op::Xorps, Size::S64);
    case X86_INS_ORPS: return translate_sse_bitwise(ci, x, arch, Op::Orps, Size::S64);
    case X86_INS_ANDPS: return translate_sse_bitwise(ci, x, arch, Op::Andps, Size::S64);
    case X86_INS_XORPD: return translate_sse_bitwise(ci, x, arch, Op::Xorps, Size::S64);
    case X86_INS_ORPD:  return translate_sse_bitwise(ci, x, arch, Op::Orps, Size::S64);
    case X86_INS_ANDPD: return translate_sse_bitwise(ci, x, arch, Op::Andps, Size::S64);
    // MIT-376: SSE 浮点比较 ucomiss/ucomisd (REG-REG only, mod=11).
    //   - ucomiss 0F 2E /r (size=S32) / ucomisd 66 0F 2E /r (size=S64)。
    //     updates_flags=**true** — 真写 VM flags 槽, 派活单 §D D1.1 (禁止
    //     空转, pitfall #79)。
    // MIT-411 (G1-b): comiss/comisd (0F 2F / 66 0F 2F) — flags 语义与
    // ucomis* 逐位相同 (SDM 真值表一致: ZF/PF/CF 按比较结果装配, OF/SF/AF
    // 双清 0) → **参数化复用 translate_ucomis** 折叠为 Op::Ucomiss/Ucomisd
    // (ir::Op 冻结不可增枚举; 派活单 §C D2)。实测: 编码 0F 2F C1 →
    // capstone id COMISS (mem 源 0F 2F 05.. 同 id, op0=REG op1=MEM);
    // MSVC /Od 对 `g_f < 常量` 天然 emit comiss (有序比较), 对 `==`
    // 用 ucomiss。已知妥协: comiss 对 QNaN 会 #IA (有序比较), VM 不模拟
    // 浮点异常, handler 执行 native ucomiss — flags 结果不变, 披露于报告。
    case X86_INS_UCOMISS: return translate_ucomis(ci, x, arch, Op::Ucomiss, Size::S32);
    case X86_INS_UCOMISD: return translate_ucomis(ci, x, arch, Op::Ucomisd, Size::S64);
    case X86_INS_COMISS:  return translate_ucomis(ci, x, arch, Op::Ucomiss, Size::S32);
    case X86_INS_COMISD:  return translate_ucomis(ci, x, arch, Op::Ucomisd, Size::S64);
    // MIT-425 (G1b): SSE 浮点乘 mul 族 (R1) + andnps/andnpd (R3) + SSE2
    // 整数位运算族 pand/por/pxor/pandn (R2 档①)。
    //   - mulss xmm1, xmm2/m32  F3 0F 59 /r  (scalar single, size=S32)
    //   - mulsd xmm1, xmm2/m64  F2 0F 59 /r  (scalar double, size=S64)
    //   - mulps xmm1, xmm2/m128 0F 59 /r     (packed single, size=S64)
    //   - mulpd xmm1, xmm2/m128 66 0F 59 /r  (packed double, size=S64)
    //     (capstone 实证: F30F59C1/F20F59C1/0F59C1/660F59C1 → MULSS/MULSD/
    //      MULPS/MULPD xmm0,xmm1; 66 前缀被吸收进 id, prefix[0]=0, 与
    //      ANDPD 同纪律不经入口前缀拒)。vendored capstone 枚举名实测
    //      (x86.h): X86_INS_MULSS/MULSD/MULPS/MULPD 独立于 GP MUL/IMUL —
    //      404 CDQE/MOVSXD 分裂教训面, 四 id 全显式收口。
    //     IR 编码: (Op::Mul, src2=imm(kSseMulSs..kSseMulPd, 14..17)) 载体
    //     标记 — ir::Op 冻结不可增枚举, GP Op::Mul 占用 (Mul,S32/S64)
    //     使 (Op,Size) 双语义装不下 4 形态 ((Addss,S8)=mulss 类映射 op
    //     名与语义相反, 弃); 沿用 G3 串指令 / G4 lock 的 "op 载体 +
    //     src2=imm(族)" 先例 (域 14..17 与 0..4 string / 5..13 lock 分区
    //     连续, 零碰撞; 写入点唯一, GP mul / 1-op imul→Mul 从不写 src2)。
    //     选型披露: D2 禁 aux 位域 hack — 本方案零 aux 使用, 见报告 §选型。
    //   - andnps xmm1, xmm2/m128 0F 55 /r  / andnpd 66 0F 55 /r:
    //     dst = ~dst & src — 非纯位运算三元组, 无法单折 Andps; VM 无
    //     128-bit NOT 原语 (GP Not 单 u64 槽语义), 双折不可行 → 新
    //     VmOp::Andnps (派活单 §B.2 "两条折 或 新 VmOp 你实测选")。
    //     IR: (Op::Andps, src2=imm(kSseAndn=18)) 载体标记。
    //   - pand (66 0F DB) / por (66 0F EB) / pxor (66 0F EF) / pandn
    //     (66 0F DF): 与 ps 位运算逐位同语义 (128-bit 按位, 不解释操作
    //     数类型, 零 flags) → 零新 VmOp 折叠 Andps/Orps/Xorps (411
    //     pd 折叠 ps 先例的整数扩展; MSVC v145 对 _mm_and_si128/
    //     _mm_andnot_si128 实测直产 andps/andnps — 编译器自身即互认证据,
    //     424 "pand 直产 legacy" 先验被本机实测推翻, pand 真 66 字节由
    //     MASM 样本直写)。pandn 折叠 Andnps (与 andnps 逐位同语义)。
    //   - paddq/psubq 系 (66 0F D4/5C) 不在本单面 (跳表预算 95 顶格,
    //     砍面留 G1c, 见报告) → 落 default 照旧 C1 gate。
    case X86_INS_MULSS: return translate_sse_mul(ci, x, arch, Size::S32, kSseMulSs);
    case X86_INS_MULSD: return translate_sse_mul(ci, x, arch, Size::S64, kSseMulSd);
    case X86_INS_MULPS: return translate_sse_mul(ci, x, arch, Size::S64, kSseMulPs);
    case X86_INS_MULPD: return translate_sse_mul(ci, x, arch, Size::S64, kSseMulPd);
    case X86_INS_ANDNPS: return translate_sse_andn(ci, x, arch);
    case X86_INS_ANDNPD: return translate_sse_andn(ci, x, arch);
    case X86_INS_PAND:  return translate_sse_bitwise(ci, x, arch, Op::Andps, Size::S64);
    case X86_INS_POR:   return translate_sse_bitwise(ci, x, arch, Op::Orps,  Size::S64);
    case X86_INS_PXOR:  return translate_sse_bitwise(ci, x, arch, Op::Xorps, Size::S64);
    case X86_INS_PANDN: return translate_sse_andn(ci, x, arch);
    // MIT-427 (G1c): movd/movq GP↔xmm 桥 (核心必做 B.1) — 66 0F 6E/7E 系
    // (REG/MEM 双操作数, REX.W 64 位) + F3 0F 7E + 66 0F D6 全编码形,
    // MMX 裸 0F 6E/6F/7E/7F (mm 操作数) D2 永久 gate。判据/分域见
    // translate_movd_movq 注释块。paddq/psubq (66 0F D4/FB) 本单砍面
    // (频率实测) → 照旧 default gate; movdqa/movdqu (468/469) 已由
    // MIT-428 (G1d) 折叠入面 (translate_sse_mov 通路)。
    case X86_INS_MOVD: return translate_movd_movq(ci, x, arch);
    case X86_INS_MOVQ: return translate_movd_movq(ci, x, arch);
    // MIT-426 (G6a): VEX.128 V-pair 白名单 — 38 id = 既有 SSE 白名单逐行
    // 镜像 (vendored capstone x86.h 全量对账 EXISTS, 映射表见报告)。
    // VEX 前缀 (C4/C5) 被 capstone 吸收进 id (prefix=[0,0,0,0], triage
    // §2.4), 不经入口前缀闸, 直达本 case → translate_vex128 (位宽闸 +
    // 三地址折叠, 零新 IR 语义 / 零新 VmOp / 零新 handler)。白名单外 VEX
    // id (vpaddd/vfmadd*/rorx/vzeroupper/EVEX 全谱) 落 default → 现状
    // C1 gate 整函数原生保持, 零逃逸。
    case X86_INS_VADDSS: case X86_INS_VADDSD: case X86_INS_VADDPS: case X86_INS_VADDPD:
    case X86_INS_VSUBSS: case X86_INS_VSUBSD: case X86_INS_VSUBPS: case X86_INS_VSUBPD:
    case X86_INS_VDIVSS: case X86_INS_VDIVSD: case X86_INS_VDIVPS: case X86_INS_VDIVPD:
    case X86_INS_VMULSS: case X86_INS_VMULSD: case X86_INS_VMULPS: case X86_INS_VMULPD:
    case X86_INS_VMOVSS: case X86_INS_VMOVSD: case X86_INS_VMOVAPS: case X86_INS_VMOVAPD:
    case X86_INS_VMOVUPS: case X86_INS_VMOVUPD:
    // MIT-428 (G1d): vmovdqa/vmovdqu 对齐传送镜像入面 (零新 VmOp, 折叠
    // 既有 Mov 通路; ymm 位宽闸 / xmm8..15 闸 / EVEX 不入面见 vex_desc_of)。
    case X86_INS_VMOVDQA: case X86_INS_VMOVDQU:
    // MIT-427 (G1c) B.3: vmovd/vmovq VEX 镜像随桥本体入面 (426 §F.4 ④
    // 挂账清偿; 2-op 形态直达既有 2-op 直通路径, ymm 位宽闸 + xmm8..15
    // 闸继承 translate_vex128)。vpaddq/vpsubq 随 paddq/psubq 本体砍面
    // (D1 频率实测) → 照旧 default gate (G6a ④ 保持)。
    case X86_INS_VMOVD: case X86_INS_VMOVQ:
    case X86_INS_VXORPS: case X86_INS_VXORPD: case X86_INS_VORPS: case X86_INS_VORPD:
    case X86_INS_VANDPS: case X86_INS_VANDPD: case X86_INS_VPXOR: case X86_INS_VPOR:
    case X86_INS_VPAND:
    case X86_INS_VANDNPS: case X86_INS_VANDNPD: case X86_INS_VPANDN:
    case X86_INS_VUCOMISS: case X86_INS_VUCOMISD: case X86_INS_VCOMISS: case X86_INS_VCOMISD:
        return translate_vex128(ci, x, arch);
    // MIT-511 (档B wave1): vzeroupper/vzeroall ABI 词入面 (translate_vzero
    // 内 x64 架构 gate + op_count=0 防御; VexVzeroupperGate 先例翻转)。
    case X86_INS_VZEROUPPER: case X86_INS_VZEROALL:
        return translate_vzero(ci, x, arch);
    case X86_INS_BSWAP: return translate_bswap(ci, x, arch);
    case X86_INS_XCHG: return translate_xchg(ci, x, arch);
    // MIT-336: setcc 16 variants (0F 90+cc+rm, mod=11 REG / mod=00 MEM).
    // capstone 对每 variant 独立命名 (X86_INS_SETE/SETNE/.../SETG), 走同一
    // translate_setcc, 由 ci.id 字段确定条件码。
    case X86_INS_SETE: case X86_INS_SETNE: case X86_INS_SETB: case X86_INS_SETBE:
    case X86_INS_SETA: case X86_INS_SETAE: case X86_INS_SETS: case X86_INS_SETNS:
    case X86_INS_SETP: case X86_INS_SETNP: case X86_INS_SETL: case X86_INS_SETLE:
    case X86_INS_SETG: case X86_INS_SETGE: case X86_INS_SETO: case X86_INS_SETNO:
        return translate_setcc(ci, x, arch);
    // MIT-339: cmovcc 16 variants (0F 40+cc+rm, mod=11 REG-REG / mod=00 MEM-REG).
    // capstone 对每 variant 独立命名 (X86_INS_CMOVE/CMOVNE/.../CMOVG), 走同一
    // translate_cmovcc, 由 ci.id 字段确定条件码 (复用 Jcc/Setcc 16-条件枚举)。
    case X86_INS_CMOVE: case X86_INS_CMOVNE: case X86_INS_CMOVB: case X86_INS_CMOVBE:
    case X86_INS_CMOVA: case X86_INS_CMOVAE: case X86_INS_CMOVS: case X86_INS_CMOVNS:
    case X86_INS_CMOVP: case X86_INS_CMOVNP: case X86_INS_CMOVL: case X86_INS_CMOVLE:
    case X86_INS_CMOVG: case X86_INS_CMOVGE: case X86_INS_CMOVO: case X86_INS_CMOVNO:
        return translate_cmovcc(ci, x, arch);
    // MIT-434 (G8a): BMI1/2 折条款目 — andn/bzhi 零新 VmOp 折条 + rorx/shlx/
    // sarx/shrx flagless 变体 (D1 (i) 变体: translator 层 GetFlags/SetFlags
    // 包裹, asmgen 零改动)。操作数映射/flags 语义/边界行为全部 probe 实测
    // (见各 translate 函数注与 .multica 方案简述); 载体域判据见 kFlagless
    // 域注。VEX 前缀 (C4/C5) 被 capstone 吸收进 id (426 同纪律), 不经入口
    // 前缀闸直达本 case。mulx/pdep/pext/blsr/blsi/blsmsk/bextr 族不入面 →
    // default 照旧 C1 gate (G8b / 文档化 gate 裁决, 432 §6.4)。
    case X86_INS_ANDN: return translate_andn(ci, x, arch);
    case X86_INS_BZHI: return translate_bzhi(ci, x, arch);
    case X86_INS_RORX: return translate_bmi_shift(ci, x, arch, Op::Ror);
    case X86_INS_SHLX: return translate_bmi_shift(ci, x, arch, Op::Shl);
    case X86_INS_SARX: return translate_bmi_shift(ci, x, arch, Op::Sar);
    case X86_INS_SHRX: return translate_bmi_shift(ci, x, arch, Op::Shr);
    // MIT-341: cmpxchg r/m, r (0F B0/B1+rm, mod=11 REG-REG / mod=00 MEM-REG).
    // capstone 用单一 X86_INS_CMPXCHG 涵盖 S8 (0F B0) 和 S16/S32/S64 (0F B1)
    // 全部形式, size 由 ModR/M 与 REX.W 决定. size 取 data_size() 自动识别.
    // 隐式 acc 字段不入 IR (沿用 pitfall #34 additive enum append-only);
    // handler 硬编码 regs[Rax] 槽位 + IR.size 决定宽度.
    case X86_INS_CMPXCHG: return translate_cmpxchg(ci, x, arch);
    // MIT-451 (X5b) B.4：REG-REG 位测试族翻正面 — X86_INS_XADD/BTS/BTR/BTC
    // REG-REG 形（无 lock 前缀；**仅 x86 arch**，x64 维持 G4 残余 gate 面不
    // 变 — "无锁 bts reg 形式未入面照旧 gate" 口径不动）。载体复用 G4 标记
    // 域（kLockXadd/kLockBts/Btr/Btc 值域 5..8 零新增，D3），dst=Reg 形由
    // translator translate_lock_xadd/lock_bit 的 REG 分支单 VmOp 直执行
    // （419/432 单 VmOp native 直执行先例；b_kind=None 判别，编码零改动）。
    // 其余形态（REG-IMM / REG-MEM 裸形 / MEM 形无 lock）照旧 unsupported →
    // C1 gate（MEM 仅 lock 白名单面，G4）。S16（66 0F C1/AB）维持 gate 口径。
    case X86_INS_XADD: case X86_INS_BTS: case X86_INS_BTR: case X86_INS_BTC:
        return translate_bitreg(ci, x, arch);
    case X86_INS_NOP: {
        ir::Insn out;
        out.op = Op::Nop;
        out.addr = ci.address;
        out.size = pointer_size(arch);
        out.updates_flags = false;
        return ok(out);
    }
    // —— MIT-506/507 (T60): x87 L0 (物理 FPU 驻留直执行, GAPS MIT-506) ——
    case X86_INS_FLD: case X86_INS_FLD1: case X86_INS_FLDZ:
    case X86_INS_FST: case X86_INS_FSTP:
    case X86_INS_FILD: case X86_INS_FIST: case X86_INS_FISTP:
    case X86_INS_FADD:  // 含 faddp (DE /0, capstone 无 FADDP id)
    case X86_INS_FMUL: case X86_INS_FMULP:
    case X86_INS_FSUB: case X86_INS_FSUBP: case X86_INS_FSUBR: case X86_INS_FSUBRP:
    case X86_INS_FDIV: case X86_INS_FDIVP: case X86_INS_FDIVR: case X86_INS_FDIVRP:
    case X86_INS_FCHS: case X86_INS_FABS: case X86_INS_FSQRT:
    case X86_INS_FCOMI:
    case X86_INS_FCOMPI:  // fcomip 独立 id (T61 探针: dff1 报 fcompi)
    case X86_INS_FCOM: case X86_INS_FCOMP: case X86_INS_FCOMPP:
    case X86_INS_FTST: case X86_INS_FXAM:
    case X86_INS_FUCOM: case X86_INS_FUCOMP: case X86_INS_FUCOMI:
    case X86_INS_FUCOMPI:
    case X86_INS_FXCH: case X86_INS_FFREE: case X86_INS_FFREEP:
    case X86_INS_FDECSTP: case X86_INS_FINCSTP:
    case X86_INS_FCMOVB: case X86_INS_FCMOVE: case X86_INS_FCMOVBE:
    case X86_INS_FCMOVU: case X86_INS_FCMOVNB: case X86_INS_FCMOVNE:
    case X86_INS_FCMOVNBE: case X86_INS_FCMOVNU:
    case X86_INS_FLDPI: case X86_INS_FLDL2T: case X86_INS_FLDL2E:
    case X86_INS_FLDLG2: case X86_INS_FLDLN2:
    case X86_INS_F2XM1: case X86_INS_FYL2X: case X86_INS_FYL2XP1:
    case X86_INS_FSCALE: case X86_INS_FPATAN: case X86_INS_FPREM:
    case X86_INS_FPREM1: case X86_INS_FSIN: case X86_INS_FCOS:
    case X86_INS_FSINCOS: case X86_INS_FPTAN: case X86_INS_FRNDINT:
    case X86_INS_FXTRACT: case X86_INS_FNCLEX: case X86_INS_FNINIT:
    case X86_INS_FLDCW:
    case X86_INS_FNSTCW:  // 含 fstcw (9B 前缀折叠, 无 FSTCW id)
    case X86_INS_FNSTSW:  // 含 fstsw ax/m16 (9B 前缀折叠, 无 FSTSW id)
    case X86_INS_FNOP:
        // ⚠️ x87 词仅 x86 收录 (T60 架构定案: x64 运行时无 x87 词面,
        // handler 帧语义 x86 专属) — x64 区维持 gate。MIT-510 回归修复:
        // T62 新增 case 使 x64 x87_gate 样本误入虚拟化 (全零输出实证)。
        if (arch != ir::Arch::X86) return unsupported(ci.address, ci.size);
        return translate_x87(ci, x);
    default:
        return unsupported(ci.address, ci.size);
    }
}

} // namespace wvmp::passes::lifter
