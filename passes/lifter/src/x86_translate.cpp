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
// MEM 形式 (xchg [reg], reg) 派活单限定不支持 (需 temp 寄存器, 复杂),
// lifter 拒 MEM → 触发 C1 gate 兜底 (与原生行为一致).
TranslateResult translate_xchg(const cs_insn& ci, const cs_x86& x, ir::Arch arch) {
    if (x.op_count != 2) return unsupported(ci.address, ci.size);
    // xchg 是对称操作, 但 IR 仍按 dst/src 编码 (语义等价). 两个操作数都必须
    // 是寄存器 (MEM-REG 派活单限定不支持, lifter 拒 → C1 gate 兜底)。
    if (x.operands[0].type != X86_OP_REG) return unsupported(ci.address, ci.size);
    if (x.operands[1].type != X86_OP_REG) return unsupported(ci.address, ci.size);
    auto d = map_reg(x.operands[0].reg);
    auto s = map_reg(x.operands[1].reg);
    if (!d || !s) return unsupported(ci.address, ci.size);

    // REX.W 检测: x.rex bit 3 (REX.W) → S64, 否则 → S32.
    const bool rex_w = (x.rex & 0x08) != 0;

    ir::Insn out;
    out.op = Op::Xchg;
    out.addr = ci.address;
    out.size = rex_w ? Size::S64 : Size::S32;
    out.updates_flags = false;
    out.dst = Operand::reg_(*d);
    out.src = Operand::reg_(*s);
    return ok(out);
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
// MIT-371: SSE 浮点加 addss/addps/addpd (REG-REG only, mod=11).
// MSVC /Od 默认 codegen REG-REG (mod=11), MSVC x64 不支持 inline asm,
// 高 level C++ 在 /Od 下用 <intrin.h> 的 _mm_add_ss/_mm_add_ps/_mm_add_pd
// 内部函数直接 emit 真 SSE 字节（F3 0F 58 / 0F 58 / 66 0F 58）——
// 无需 MASM helper 强制 codegen（与 MIT-349 popcnt MASM helper 强制 codegen
// 路径不同, 沿用 MIT-353 lzcnt/tzcnt 的"MSVC /Od 直接 emit 真字节"路径）。
//   - addss xmm1, xmm2/m32  F3 0F 58 /r  (scalar single, 1 element)
//   - addps xmm1, xmm2/m128 0F 58 /r     (packed single, 4 elements)
//   - addpd xmm1, xmm2/m128 66 0F 58 /r  (packed double, 2 elements)
//   - 2 操作数 (dst + src), 必都是 XMM 寄存器 (派活单限定不支持 MEM form,
//     lifter 拒 MEM → C1 gate 兜底)。
//   - size 字段: addss=ir::Size::S32 (scalar 单精度), addps/addpd=ir::Size::S64
//     (packed 128-bit; handler 用 movups 全 128-bit 读写)。size 不影响 codegen,
//     仅作 addss/addps/addpd 的区分 tag（handler 也按 size 派发）。
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
TranslateResult translate_sse_add(const cs_insn& ci, const cs_x86& x, ir::Arch arch, Op op,
                                  ir::Size sz) {
    if (x.op_count != 2) return unsupported(ci.address, ci.size);
    // 两个操作数必都是 XMM 寄存器 (派活单限定不支持 MEM form).
    if (x.operands[0].type != X86_OP_REG) return unsupported(ci.address, ci.size);
    if (x.operands[1].type != X86_OP_REG) return unsupported(ci.address, ci.size);
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
    auto si = xmm_idx(x.operands[1].reg);
    if (!di || !si) return unsupported(ci.address, ci.size);
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
    out.src = ir::Operand::reg_(static_cast<ir::Reg>(*si));
    return ok(out);
}

// MIT-373: SSE 浮点减 subss/subps/subpd (REG-REG only, mod=11).
// 与 translate_sse_add (MIT-371) 同构: XMM 寄存器编码借用 ir::Reg 值 0..7,
// 翻译期加 24 偏移 → VmContext.regs[24..31] (XMM 编码设计见上方 MIT-371 注释块).
//   - subss xmm1, xmm2/m32  F3 0F 5C /r  (scalar single, 1 element)
//   - subps xmm1, xmm2/m128 0F 5C /r     (packed single, 4 elements)
//   - subpd xmm1, xmm2/m128 66 0F 5C /r  (packed double, 2 elements)
//   - size 字段: subss=ir::Size::S32 (scalar 单精度), subps/subpd=ir::Size::S64
//     (packed 128-bit; handler 用 movups 全 128-bit 读写)。size 不影响 codegen,
//     仅作 subss/subps/subpd 的区分 tag（handler 也按 size 派发）。
//   - updates_flags=false (SSE 浮点减不影响 x86 EFLAGS; MXCSR rounding mode
//     v1 不追踪)。
TranslateResult translate_sse_sub(const cs_insn& ci, const cs_x86& x, ir::Arch arch, Op op,
                                  ir::Size sz) {
    if (x.op_count != 2) return unsupported(ci.address, ci.size);
    // 两个操作数必都是 XMM 寄存器 (派活单限定不支持 MEM form).
    if (x.operands[0].type != X86_OP_REG) return unsupported(ci.address, ci.size);
    if (x.operands[1].type != X86_OP_REG) return unsupported(ci.address, ci.size);
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
    auto si = xmm_idx(x.operands[1].reg);
    if (!di || !si) return unsupported(ci.address, ci.size);
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
    out.src = ir::Operand::reg_(static_cast<ir::Reg>(*si));
    return ok(out);
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
    case X86_INS_IMUL: return translate_imul(ci, x, arch);
    case X86_INS_MUL: return translate_mul(ci, x, arch);
    case X86_INS_MOVSXD: return translate_movsxd(ci, x, arch);
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
    // MIT-373: SSE 浮点减 subss/subps/subpd (REG-REG only, mod=11).
    //   - subss xmm1, xmm2/m32  F3 0F 5C /r  (scalar single, size=S32)
    //   - subps xmm1, xmm2/m128 0F 5C /r     (packed single, size=S64)
    //   - subpd xmm1, xmm2/m128 66 0F 5C /r  (packed double, size=S64)
    // MASM helper 强制 codegen (pitfall #35): /Od 下 intrinsics 会融合
    // load+sub 为 MEM 形式, E2E 样本由 sse_sub_sample_asm.asm emit 真 REG-REG 字节.
    case X86_INS_SUBSS: return translate_sse_sub(ci, x, arch, Op::Subss, Size::S32);
    case X86_INS_SUBPS: return translate_sse_sub(ci, x, arch, Op::Subps, Size::S64);
    case X86_INS_SUBPD: return translate_sse_sub(ci, x, arch, Op::Subpd, Size::S64);
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
    // MIT-341: cmpxchg r/m, r (0F B0/B1+rm, mod=11 REG-REG / mod=00 MEM-REG).
    // capstone 用单一 X86_INS_CMPXCHG 涵盖 S8 (0F B0) 和 S16/S32/S64 (0F B1)
    // 全部形式, size 由 ModR/M 与 REX.W 决定. size 取 data_size() 自动识别.
    // 隐式 acc 字段不入 IR (沿用 pitfall #34 additive enum append-only);
    // handler 硬编码 regs[Rax] 槽位 + IR.size 决定宽度.
    case X86_INS_CMPXCHG: return translate_cmpxchg(ci, x, arch);
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
