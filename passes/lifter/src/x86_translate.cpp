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

// jmp（rel/abs/reg 均为 Jmp，目标在 dst）；间接内存跳转 jmp [..] v1 跳过。
TranslateResult translate_jmp(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    if (x.op_count != 1) return unsupported(ci.address, ci.size);
    if (x.operands[0].type != X86_OP_IMM && x.operands[0].type != X86_OP_REG) {
        return unsupported(ci.address, ci.size);
    }
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

TranslateResult translate_call(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    if (x.op_count != 1) return unsupported(ci.address, ci.size);
    if (x.operands[0].type != X86_OP_IMM && x.operands[0].type != X86_OP_REG) {
        return unsupported(ci.address, ci.size); // call [..] v1 跳过
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

TranslateResult translate_insn(const cs_insn& ci, ir::Arch arch) {
    if (ci.detail == nullptr) return unsupported(ci.address, ci.size);
    const cs_x86& x = ci.detail->x86;

    // 带 lock/rep/repne 前缀（prefix[0]）的指令语义与普通形式不同，
    // 段覆盖前缀（prefix[1]，如 gs:[..] TLS 访问）无法在平坦内存模型下
    // 虚拟化——v1 一律跳过。
    if (x.prefix[0] != 0 || x.prefix[1] != 0) return unsupported(ci.address, ci.size);

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
    case X86_INS_NOP: {
        ir::Insn out;
        out.op = Op::Nop;
        out.addr = ci.address;
        out.size = pointer_size(arch);
        out.updates_flags = false;
        return ok(out);
    }
    default:
        return unsupported(ci.address, ci.size);
    }
}

} // namespace wvmp::passes::lifter
