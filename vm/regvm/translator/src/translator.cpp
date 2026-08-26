// regvm 翻译器：ir::Insn -> RegVM 字节码（纯函数、流式、逐指令翻译）。
// 翻译约定总注释见 translator.hpp。

#include "wvmp/regvm/translator/translator.hpp"

#include "wvmp/common/bytes.hpp"
#include "wvmp/regvm/isa/blob.hpp"
#include "wvmp/regvm/isa/encoding.hpp"
#include "wvmp/regvm/isa/vm_op.hpp"
#include "wvmp/regvm/isa/vm_reg.hpp"

#include <cinttypes>
#include <cstdio>
#include <limits>
#include <string>
#include <unordered_map>
#include <vector>

namespace wvmp::regvm::translator {
namespace {

using isa::OpKind;
using isa::VmInsn;
using isa::VmOp;
namespace ir = wvmp::ir;

// 立即数能否直接放进 aux（约定 aux 零扩展：负数与 >u32 均不可往返）。
[[nodiscard]] bool fits_aux(i64 v) {
    return v >= 0 && static_cast<u64>(v) <= 0xFFFF'FFFFull;
}

// 块内指令发射器：每条 IR 指令一个临时实例，成功后整体拼接进主序列；
// 失败则整体丢弃（事务性），保证永不产生半截序列。scratch 亦随之重置。
struct Emitter {
    std::vector<VmInsn> out;

    void emit(VmOp op, OpKind ak, u8 ra, OpKind bk, u8 rb, u32 aux, u8 cs) {
        out.push_back(isa::make_insn(op, ak, ra, bk, rb, aux, cs));
    }
    void emit_rr(VmOp op, u8 ra, u8 rb, u8 cs) { // a=Reg, b=Reg
        emit(op, OpKind::Reg, ra, OpKind::Reg, rb, 0, cs);
    }
    void emit_ri(VmOp op, u8 ra, u32 aux, u8 cs) { // a=Reg, b=Imm
        emit(op, OpKind::Reg, ra, OpKind::Imm, 0, aux, cs);
    }
};

// scratch 轮转分配（v18..v23，预算 6）。单条 IR 指令的任何展开路径至多用 5：
// 地址 acc + index + 立即数拼装 2 + 读入值 1。
struct Scratch {
    u8 next = isa::kScratchFirst;
    u8 take() { return next++; }
};

// notes 便捷拼接（含指令 RVA，便于上层 diag 定位）。
void add_note(std::vector<std::string>& notes, u64 addr, std::string_view what) {
    char buf[64];
    std::snprintf(buf, sizeof(buf), " (rva=0x%" PRIX64 ")", addr);
    notes.emplace_back(std::string(what) + buf);
}

// ir::Op -> VmOp（值从 1 起的一一同义段；显式 switch 防枚举漂移）。
[[nodiscard]] bool vm_op_of(ir::Op op, VmOp& out) {
    switch (op) {
    case ir::Op::Mov: out = VmOp::Mov; return true;
    case ir::Op::Lea: out = VmOp::Lea; return true;
    case ir::Op::Add: out = VmOp::Add; return true;
    case ir::Op::Sub: out = VmOp::Sub; return true;
    case ir::Op::Adc: out = VmOp::Adc; return true;
    case ir::Op::Sbb: out = VmOp::Sbb; return true;
    case ir::Op::And: out = VmOp::And; return true;
    case ir::Op::Or: out = VmOp::Or; return true;
    case ir::Op::Xor: out = VmOp::Xor; return true;
    case ir::Op::Not: out = VmOp::Not; return true;
    case ir::Op::Neg: out = VmOp::Neg; return true;
    case ir::Op::Inc: out = VmOp::Inc; return true;
    case ir::Op::Dec: out = VmOp::Dec; return true;
    case ir::Op::Shl: out = VmOp::Shl; return true;
    case ir::Op::Shr: out = VmOp::Shr; return true;
    case ir::Op::Sar: out = VmOp::Sar; return true;
    case ir::Op::Rol: out = VmOp::Rol; return true;
    case ir::Op::Ror: out = VmOp::Ror; return true;
    case ir::Op::Cmp: out = VmOp::Cmp; return true;
    case ir::Op::Test: out = VmOp::Test; return true;
    default: return false;
    }
}

// ir::Op (Shl/Shr/Sar/Rol/Ror) -> VmOp (ShlCl/ShrCl/SarCl/RolCl/RorCl)。
// MIT-301: lifter 用 Operand::Kind::Reg + Reg::Rcx 表示 cl 计数（D3 /5）,
// 翻译器据此发射新 VmOp 让字节码语义显式。运行时 handler 复用 build_shift,
// 读 regs[reg_b], 按宽度掩码, count=0 走 no-op 出口不更新 flags。
[[nodiscard]] bool shift_cl_op_of(ir::Op op, VmOp& out) {
    switch (op) {
    case ir::Op::Shl: out = VmOp::ShlCl; return true;
    case ir::Op::Shr: out = VmOp::ShrCl; return true;
    case ir::Op::Sar: out = VmOp::SarCl; return true;
    case ir::Op::Rol: out = VmOp::RolCl; return true;
    case ir::Op::Ror: out = VmOp::RorCl; return true;
    default: return false;
    }
}

// 把 64 位立即数 v 拼进寄存器 d（4 条，全 S64）：
//   Mov s,hi32 / Shl s,32 / Mov d,lo32 / Or d,s
void emit_imm64_split(Emitter& em, Scratch& sc, u8 d, u64 v) {
    const u8 s = sc.take();
    const u8 sz64 = isa::size_field(ir::Size::S64);
    em.emit_ri(VmOp::Mov, s, static_cast<u32>(v >> 32), sz64);
    em.emit_ri(VmOp::Shl, s, 32, sz64);
    em.emit_ri(VmOp::Mov, d, static_cast<u32>(v), sz64);
    em.emit_rr(VmOp::Or, d, s, sz64);
}

// 地址计算：base(+index*scale)(+disp) -> acc。RIP 相对：base=Rip 时用
// next_ip + disp 算 RVA 直接发为 S64 立即数（带 index/disp 一律零相加；
// x64 [rip+disp32] 实际 = next_ip + disp32, next_ip = current_rva + insn_len,
// 由 caller 通过 next_ip_of_ 传入). 无效 scale/越界 RVA 返回 false.
[[nodiscard]] bool emit_address(Emitter& em, Scratch& sc, const ir::MemOperand& m,
                                u64 current_rva, u64 next_ip, u8& acc_out) {
    if (m.base == ir::Reg::Rip) {
        // rip-relative: RVA = next_ip + disp (disp 是 i64, 可负).
        // PE RVA 字段为 u32, 正常范围 [0, end_rva); 越界（极负 disp 跌出 image 起点）
        // 拒绝, 触发 C1 gate 拦截（保持原生）, 不作为 halt VM 的硬错误.
        const i64 rva_i = static_cast<i64>(next_ip) + m.disp;
        if (rva_i < 0 || rva_i > static_cast<i64>(std::numeric_limits<u32>::max()))
            return false;
        const u64 rva = static_cast<u64>(rva_i);
        const u8 acc = sc.take();
        const u8 sz64 = isa::size_field(ir::Size::S64);
        if (fits_aux(rva_i)) {
            em.emit_ri(VmOp::Mov, acc, static_cast<u32>(rva_i), sz64);
        } else {
            emit_imm64_split(em, sc, acc, rva);
        }
        // index/scale 在 [rip+disp] 形式中不会出现（Capstone 不产 rip+index）；
        // 即便 lifter 出, 也按 (index<<scale) + (RVA+disp) 一并入 acc, 行为
        // 等价于 lea 后再访存. 守护：仅在 base=Rip 时 index 也飘零，否则接受.
        if (m.index != ir::Reg::Flags) {
            unsigned shift_bits = 0;
            switch (m.scale == 0 ? 1u : m.scale) {
            case 1: shift_bits = 0; break;
            case 2: shift_bits = 1; break;
            case 4: shift_bits = 2; break;
            case 8: shift_bits = 3; break;
            default: return false;
            }
            const u8 ix = sc.take();
            em.emit_rr(VmOp::Mov, ix, isa::vm_reg_of(m.index), sz64);
            if (shift_bits > 0)
                em.emit_ri(VmOp::Shl, ix, shift_bits, sz64);
            em.emit_rr(VmOp::Add, acc, ix, sz64);
        }
        (void)current_rva;
        acc_out = acc;
        return true;
    }
    const u8 sz64 = isa::size_field(ir::Size::S64);
    const u8 acc = sc.take();
    if (m.base != ir::Reg::Flags) {
        em.emit_rr(VmOp::Mov, acc, isa::vm_reg_of(m.base), sz64);
    } else {
        em.emit_ri(VmOp::Mov, acc, 0, sz64); // 无 base：绝对 / 纯 index 形式，从 0 起算
    }
    if (m.index != ir::Reg::Flags) {
        unsigned shift_bits = 0;
        switch (m.scale == 0 ? 1u : m.scale) {
        case 1: shift_bits = 0; break;
        case 2: shift_bits = 1; break;
        case 4: shift_bits = 2; break;
        case 8: shift_bits = 3; break;
        default: return false; // x86 scale 只能是 1/2/4/8
        }
        const u8 ix = sc.take();
        em.emit_rr(VmOp::Mov, ix, isa::vm_reg_of(m.index), sz64);
        if (shift_bits > 0)
            em.emit_ri(VmOp::Shl, ix, shift_bits, sz64);
        em.emit_rr(VmOp::Add, acc, ix, sz64);
    }
    if (m.disp != 0) {
        if (fits_aux(m.disp)) {
            em.emit_ri(VmOp::Add, acc, static_cast<u32>(m.disp), sz64);
        } else if (m.disp < 0) {
            // 负 disp：Sub |disp|（aux 零扩展放不下负数，减法等价，见头文件约定）。
            const u64 mag = static_cast<u64>(-(m.disp + 1)) + 1; // 避开 INT64_MIN 的 UB
            if (mag > 0xFFFF'FFFFull)
                return false; // 超大负 disp：x86 不可编码，防御拒绝
            em.emit_ri(VmOp::Sub, acc, static_cast<u32>(mag), sz64);
        } else {
            const u8 t = sc.take();
            emit_imm64_split(em, sc, t, static_cast<u64>(m.disp));
            em.emit_rr(VmOp::Add, acc, t, sz64);
        }
    }
    (void)current_rva;
    acc_out = acc;
    return true;
}

// 读 [mem] 到 fresh scratch（Load s, [acc]，方向：a=Reg(s)，b=Reg(acc)）。
// 返回 false 的唯一原因（非法 scale / 越界 RVA）已由调用方先行检查。
u8 emit_load(Emitter& em, Scratch& sc, const ir::MemOperand& m, ir::Size size,
             u64 current_rva, u64 next_ip) {
    u8 acc = 0;
    const bool ok = emit_address(em, sc, m, current_rva, next_ip, acc);
    (void)ok;
    const u8 val = sc.take();
    const isa::VmOp load_op =
        (m.base == ir::Reg::Rip) ? isa::VmOp::LoadRva : isa::VmOp::Load;
    em.emit_rr(load_op, val, acc, isa::size_field(size));
    return val;
}

[[nodiscard]] bool is_alu_binop(ir::Op op) {
    switch (op) {
    case ir::Op::Add: case ir::Op::Sub: case ir::Op::Adc: case ir::Op::Sbb:
    case ir::Op::And: case ir::Op::Or: case ir::Op::Xor:
    case ir::Op::Shl: case ir::Op::Shr: case ir::Op::Sar:
    case ir::Op::Rol: case ir::Op::Ror:
    case ir::Op::Cmp: case ir::Op::Test:
        return true;
    default:
        return false;
    }
}

[[nodiscard]] bool is_unary(ir::Op op) {
    switch (op) {
    case ir::Op::Not: case ir::Op::Neg: case ir::Op::Inc: case ir::Op::Dec:
        return true;
    default:
        return false;
    }
}

struct PendingJump {
    size_t index;      // 回填目标：发射后在最终序列中的序号
    size_t block_idx;  // 目标块下标
};

// 单条 IR 指令翻译器。所有失败路径经 skip() 记 notes 并返回 false，
// 临时发射内容随之丢弃；flags 语义见头文件（v1 不做额外指令）。
//
// rip-relative 计算用 next_ip_of_（每条 insn 的结束 RVA, 即 current_rva + insn_len;
// 翻译期不持 capstone, 由 caller 从 fn.blocks 推断）。
struct Translator {
    std::vector<VmInsn>& code;
    std::vector<PendingJump>& pending;
    const std::unordered_map<u64, size_t>& block_of_addr;
    std::vector<std::string>& notes;
    const std::unordered_map<u64, u64>* next_ip_of_;   // insn.addr -> next_ip (=addr+len)

    bool skip(const ir::Insn& in, std::string_view what, const ir::MemOperand* rip) {
        if (rip && rip->base == ir::Reg::Rip)
            what = "rip-relative 未支持";
        add_note(notes, in.addr, what);
        return false;
    }

    void run(const ir::Insn& in) {
        Emitter em;
        Scratch sc;
        bool ok = true;
        const u64 current_rva = in.addr;
        // next_ip_of_ 在 translate_function 前已构造, 必有该 insn.addr; find 是
        // const 安全路径（operator[] 会插入默认 0, 与语义不符, 故显式 find）。
        u64 next_ip = current_rva;
        if (next_ip_of_) {
            const auto it = next_ip_of_->find(current_rva);
            if (it != next_ip_of_->end()) next_ip = it->second;
        }
        switch (in.op) {
        case ir::Op::Mov: ok = translate_mov(em, sc, in); break;
        case ir::Op::Lea: ok = translate_lea(em, sc, in, current_rva, next_ip); break;
        case ir::Op::Load: ok = translate_load(em, sc, in, current_rva, next_ip); break;
        case ir::Op::Store: ok = translate_store(em, sc, in, current_rva, next_ip); break;
        case ir::Op::Push: ok = translate_push(em, in); break;
        case ir::Op::Pop: ok = translate_pop(em, in); break;
        case ir::Op::Ret:
            em.emit(VmOp::Ret, OpKind::None, 0, OpKind::None, 0, 0,
                    isa::size_field(in.size));
            break;
        case ir::Op::Jmp:
        case ir::Op::Jcc: ok = translate_jump(em, in); break;
        case ir::Op::Call:
            ok = translate_call(em, in, next_ip);
            break;
        case ir::Op::Nop:
            em.emit(VmOp::Nop, OpKind::None, 0, OpKind::None, 0, 0,
                    isa::size_field(in.size));
            break;
        default:
            if (in.op == ir::Op::Imul) {
                ok = translate_imul(em, sc, in, current_rva, next_ip);
            } else if (in.op == ir::Op::Mul) {
                ok = translate_mul(em, in);
            } else if (in.op == ir::Op::Movsxd) {
                ok = translate_movsxd(em, sc, in, current_rva, next_ip);
            } else if (in.op == ir::Op::Movzx) {
                ok = translate_movzx(em, sc, in, current_rva, next_ip);
            } else if (in.op == ir::Op::Movsx) {
                ok = translate_movsx(em, sc, in, current_rva, next_ip);
            } else if (in.op == ir::Op::Popcnt) {
                // MIT-349: popcnt dispatch — REG-REG 形式 emit 单条 VmOp::Popcnt
                // (handler 用 native popcnt 完成比特计数; src 必是 REG 派活单限定).
                ok = translate_popcnt(em, in);
            } else if (in.op == ir::Op::Lzcount) {
                // MIT-353: lzcnt dispatch — REG-REG 形式 emit 单条 VmOp::Lzcount
                // (handler 用 native lzcnt 完成前导零计数; src 必是 REG 派活单限定).
                ok = translate_lzcnt(em, in);
            } else if (in.op == ir::Op::Tzcount) {
                // MIT-353: tzcnt dispatch — REG-REG 形式 emit 单条 VmOp::Tzcount
                // (handler 用 native tzcnt 完成末尾零计数; src 必是 REG 派活单限定).
                ok = translate_tzcnt(em, in);
            } else if (in.op == ir::Op::Bswap) {
                ok = translate_bswap(em, in);
            } else if (in.op == ir::Op::Xchg) {
                ok = translate_xchg(em, in);
            } else if (in.op == ir::Op::Setcc) {
                // MIT-336: setcc dispatch — REG 形式 emit 单条 VmOp::Setcc,
                // MEM 形式 emit Load+Setcc+Store 三条拆条 (translate_setcc 内部展开)。
                ok = translate_setcc(em, sc, in, current_rva, next_ip);
            } else if (in.op == ir::Op::Cmovcc) {
                // MIT-339: cmovcc dispatch — REG-REG 形式 emit 单条 VmOp::Cmovcc,
                // MEM 形式 emit Load + Cmovcc 两条拆条 (translate_cmovcc 内部展开)。
                ok = translate_cmovcc(em, sc, in, current_rva, next_ip);
            } else if (in.op == ir::Op::Cmpxchg) {
                // MIT-341: cmpxchg dispatch — REG-REG 形式 emit 单条 VmOp::Cmpxchg,
                // MEM 形式 emit Load + Cmpxchg + Store 三条拆条
                // (translate_cmpxchg 内部展开; 隐式 acc 字段不入 IR, 由 handler
                // 硬编码 regs[Rax] 槽位 + IR.size 决定宽度)。
                ok = translate_cmpxchg(em, sc, in, current_rva, next_ip);
            } else if (is_alu_binop(in.op)) {
                ok = translate_alu_binop(em, sc, in, current_rva, next_ip);
            } else if (is_unary(in.op)) {
                ok = translate_unary(em, sc, in, current_rva, next_ip);
            } else {
                ok = skip(in, "未支持的操作码", nullptr);
            }
            break;
        }
        if (ok)
            code.insert(code.end(), em.out.begin(), em.out.end());
    }

    // ---- 数据移动 ----

    // mov 不接 mem 操作数（lifter 已将 mem-src 拆为 Load, mem-dst 拆为 Store），
    // 故不需要 next_ip 参数.
    bool translate_mov(Emitter& em, Scratch& sc, const ir::Insn& in) {
        if (in.dst.kind != ir::Operand::Kind::Reg)
            return skip(in, "mov 操作数形态未支持",
                        in.dst.kind == ir::Operand::Kind::Mem ? &in.dst.mem : nullptr);
        const u8 d = isa::vm_reg_of(in.dst.reg);
        const u8 sz = isa::size_field(in.size);
        if (in.src.kind == ir::Operand::Kind::Reg) {
            em.emit_rr(VmOp::Mov, d, isa::vm_reg_of(in.src.reg), sz);
            return true;
        }
        if (in.src.kind != ir::Operand::Kind::Imm)
            return skip(in, "mov 操作数形态未支持", nullptr); // mem 源应已 lift 成 Load
        if (in.size == ir::Size::S64 && !fits_aux(in.src.imm)) {
            // imm64 拆条（头文件约定）：Mov s,hi / Shl s,32 / Mov d,lo / Or d,s。
            emit_imm64_split(em, sc, d, static_cast<u64>(in.src.imm));
            return true;
        }
        // sub-64 或可直放：截断 aux，写回经 alias 折叠即正确。
        em.emit_ri(VmOp::Mov, d, static_cast<u32>(static_cast<u64>(in.src.imm)), sz);
        return true;
    }

    bool translate_lea(Emitter& em, Scratch& sc, const ir::Insn& in,
                       u64 current_rva, u64 next_ip) {
        if (in.dst.kind != ir::Operand::Kind::Reg ||
            in.src.kind != ir::Operand::Kind::Mem)
            return skip(in, "lea 操作数形态未支持", nullptr);
        u8 acc = 0;
        if (!emit_address(em, sc, in.src.mem, current_rva, next_ip, acc))
            return skip(in, "lea 地址形态未支持", &in.src.mem);
        // lea 不访存：地址值即结果；按原 size 写回（S32 lea 零扩展高位）。
        // MIT-322: rip-relative lea 的 emit_address 把 RVA 写进 acc, 但 lea
        // 期望结果是 VA (供后续非 rip Load/Store 直接当绝对 VA 访存, M2-8 起
        // Load/Store 不再加 scratch_mem). 用 VmOp::LeaRva 让运行时自动
        // + image_base, 把 RVA 转 VA 后写回 dst 槽. 非 rip 分支保持
        // 原有 `Mov dst, acc` (acc 已是 VA).
        if (in.src.mem.base == ir::Reg::Rip) {
            em.emit_rr(VmOp::LeaRva, isa::vm_reg_of(in.dst.reg), acc,
                       isa::size_field(in.size));
        } else {
            em.emit_rr(VmOp::Mov, isa::vm_reg_of(in.dst.reg), acc,
                       isa::size_field(in.size));
        }
        return true;
    }

    bool translate_load(Emitter& em, Scratch& sc, const ir::Insn& in,
                        u64 current_rva, u64 next_ip) {
        if (in.dst.kind != ir::Operand::Kind::Reg ||
            in.src.kind != ir::Operand::Kind::Mem)
            return skip(in, "load 操作数形态未支持", nullptr);
        u8 acc = 0;
        if (!emit_address(em, sc, in.src.mem, current_rva, next_ip, acc))
            return skip(in, "load 地址形态未支持", &in.src.mem);
        // rip-relative 翻译期算绝对 RVA, 运行时经 LoadRva 加 scratch_mem 还原 VA；
        // 非 rip 已为绝对 VA（来自 host 寄存器拷贝 / 算术）, 走普通 Load.
        const isa::VmOp load_op =
            (in.src.mem.base == ir::Reg::Rip) ? isa::VmOp::LoadRva : isa::VmOp::Load;
        em.emit_rr(load_op, isa::vm_reg_of(in.dst.reg), acc, isa::size_field(in.size));
        return true;
    }

    bool translate_store(Emitter& em, Scratch& sc, const ir::Insn& in,
                         u64 current_rva, u64 next_ip) {
        if (in.dst.kind != ir::Operand::Kind::Mem)
            return skip(in, "store 操作数形态未支持", nullptr);
        if (in.src.kind != ir::Operand::Kind::Reg &&
            in.src.kind != ir::Operand::Kind::Imm)
            return skip(in, "store 操作数形态未支持", nullptr); // 双 mem 不合法
        u8 acc = 0;
        if (!emit_address(em, sc, in.dst.mem, current_rva, next_ip, acc))
            return skip(in, "store 地址形态未支持", &in.dst.mem);
        u8 src_reg = 0;
        if (in.src.kind == ir::Operand::Kind::Reg) {
            src_reg = isa::vm_reg_of(in.src.reg);
        } else if (in.size != ir::Size::S64 || fits_aux(in.src.imm)) {
            src_reg = sc.take();
            em.emit_ri(VmOp::Mov, src_reg, static_cast<u32>(static_cast<u64>(in.src.imm)),
                       isa::size_field(in.size));
        } else {
            src_reg = sc.take();
            emit_imm64_split(em, sc, src_reg, static_cast<u64>(in.src.imm));
        }
        // rip-relative 用 StoreRva（运行时 + image_base）；非 rip 用普通 Store.
        const isa::VmOp store_op =
            (in.dst.mem.base == ir::Reg::Rip) ? isa::VmOp::StoreRva : isa::VmOp::Store;
        em.emit_rr(store_op, acc, src_reg, isa::size_field(in.size));
        return true;
    }

    // ---- 栈 ----

    bool translate_push(Emitter& em, const ir::Insn& in) {
        if (in.dst.kind != ir::Operand::Kind::Reg)
            return skip(in, "push 操作数形态未支持", nullptr); // push imm：lifter 不产出
        const u8 sz64 = isa::size_field(ir::Size::S64);
        const u8 rsp = isa::vm_reg_of(ir::Reg::Rsp);
        em.emit_ri(VmOp::Sub, rsp, 8, sz64);
        em.emit_rr(VmOp::Store, rsp, isa::vm_reg_of(in.dst.reg), sz64);
        return true;
    }

    bool translate_pop(Emitter& em, const ir::Insn& in) {
        if (in.dst.kind != ir::Operand::Kind::Reg)
            return skip(in, "pop 操作数形态未支持", nullptr);
        const u8 sz64 = isa::size_field(ir::Size::S64);
        const u8 rsp = isa::vm_reg_of(ir::Reg::Rsp);
        em.emit_rr(VmOp::Load, isa::vm_reg_of(in.dst.reg), rsp, sz64);
        em.emit_ri(VmOp::Add, rsp, 8, sz64);
        return true;
    }

    // ---- 控制流 ----

    bool translate_jump(Emitter& em, const ir::Insn& in) {
        if (in.op == ir::Op::Jmp && in.dst.kind == ir::Operand::Kind::Reg)
            return skip(in, "间接 jmp 未支持，建议 gate", nullptr);
        if (in.dst.kind != ir::Operand::Kind::Imm)
            return skip(in, "跳转目标非立即数，未支持", nullptr);
        const auto it = block_of_addr.find(static_cast<u64>(in.dst.imm));
        if (it == block_of_addr.end())
            return skip(in, "跳转目标块未找到（区域外/未 lift）", nullptr);
        if (in.op == ir::Op::Jcc)
            em.emit(VmOp::Jcc, OpKind::None, 0, OpKind::None, 0, 0,
                    static_cast<u8>(in.cond)); // cond_or_size = ir::Cond
        else
            em.emit(VmOp::Jmp, OpKind::None, 0, OpKind::None, 0, 0,
                    isa::size_field(in.size));
        // 跳转恒为本 IR 指令展开的最后一条：最终序号 = 已有 code 长度 + 偏移。
        pending.push_back({code.size() + em.out.size() - 1, it->second});
        return true;
    }

    // Call（MIT-249 call gate）。
    //   - 间接 call（dst = Reg，如 call rax）：target RVA 翻译期不可知，
    //     走 C1 gate 兜底（保持原生），不作为 halt VM 硬错误。
    //   - 内存间接 call（dst = Mem，如 call [rip+disp]）：target 来自内存
    //     加载，翻译期同样不可知——保守 skip，C1 gate。
    //   - 直接 call（dst = Imm，Capstone 解出 E8 + disp32 或 FF /2 imm32）：
    //     in.dst.imm = 绝对目标 RVA（lifter 约定，与 Jcc/Jmp 的 dst.imm
    //     语义一致——Capstone 给的是绝对地址，jcc/jmp 直接当块起点查）。
    //     emit VmOp::CallGate（aux = target RVA, cond_or_size = arg_count）。
    //   - 目标 RVA 越界（同 rip-relative 越界判定）→ skip 触发 C1 gate。
    bool translate_call(Emitter& em, const ir::Insn& in, u64 /*next_ip*/) {
        if (in.dst.kind == ir::Operand::Kind::Reg)
            return skip(in, "间接 call 未支持，建议 gate", nullptr);
        if (in.dst.kind == ir::Operand::Kind::Mem)
            return skip(in, "call [mem] 未支持，建议 gate",
                        in.dst.mem.base == ir::Reg::Rip ? &in.dst.mem : nullptr);
        if (in.dst.kind != ir::Operand::Kind::Imm)
            return skip(in, "call 目标非立即数，未支持", nullptr);
        const i64 rva_i = static_cast<i64>(in.dst.imm);
        if (rva_i < 0 || rva_i > static_cast<i64>(std::numeric_limits<u32>::max()))
            return skip(in, "call 目标 RVA 越界", nullptr);
        // aux = target RVA（u32 零扩展）；cond_or_size = 0（arg_count v1 固定 0）。
        // a_kind/b_kind/reg_a/reg_b 一律 None——CallGate 与 VM 操作数无关。
        em.emit(VmOp::CallGate, OpKind::None, 0, OpKind::None, 0,
                static_cast<u32>(rva_i), 0);
        return true;
    }

    // ---- 运算 ----

    bool translate_alu_binop(Emitter& em, Scratch& sc, const ir::Insn& in,
                             u64 current_rva, u64 next_ip) {
        VmOp vop{};
        if (!vm_op_of(in.op, vop))
            return skip(in, "未支持的操作码", nullptr);
        const bool dst_mem = in.dst.kind == ir::Operand::Kind::Mem;
        const bool src_mem = in.src.kind == ir::Operand::Kind::Mem;
        if (dst_mem && src_mem)
            return skip(in, "alu 双内存操作数未支持", nullptr);

        if (dst_mem) {
            // [m] op src：地址一次计算、Load/Store 复用（scratch 预算内）。
            u8 acc = 0;
            if (!emit_address(em, sc, in.dst.mem, current_rva, next_ip, acc))
                return skip(in, "alu 内存目的地址形态未支持", &in.dst.mem);
            const u8 s = sc.take();
            const isa::VmOp load_op =
                (in.dst.mem.base == ir::Reg::Rip) ? isa::VmOp::LoadRva : isa::VmOp::Load;
            em.emit_rr(load_op, s, acc, isa::size_field(in.size));
            if (!emit_binop_tail(em, sc, in, vop, s))
                return skip(in, "alu 操作数形态未支持", nullptr);
            if (in.op != ir::Op::Cmp && in.op != ir::Op::Test) { // Cmp/Test 无写回
                const isa::VmOp store_op =
                    (in.dst.mem.base == ir::Reg::Rip) ? isa::VmOp::StoreRva : isa::VmOp::Store;
                em.emit_rr(store_op, acc, s, isa::size_field(in.size));
            }
            return true;
        }
        if (in.dst.kind != ir::Operand::Kind::Reg)
            return skip(in, "alu 操作数形态未支持", nullptr);
        const u8 d = isa::vm_reg_of(in.dst.reg);
        if (src_mem) {
            const u8 s = emit_load(em, sc, in.src.mem, in.size, current_rva, next_ip);
            em.emit_rr(vop, d, s, isa::size_field(in.size));
            return true;
        }
        // MIT-301: shift ops with cl variant (src.kind=Reg) emit dedicated VmOp.
        // b_kind=OpKind::Reg, reg_b=Rcx（lifter 已限定 X86_REG_CL → Rcx）。
        // 不走 emit_binop_tail（其用 vop 即 Shl 等, b_kind 同样 Reg, 行为亦正确,
        // 但字节码语义上 ShlCl 等更显式, 与 imm 计数 Shl 等严格区分）。
        VmOp cl_op{};
        if (shift_cl_op_of(in.op, cl_op) && in.src.kind == ir::Operand::Kind::Reg) {
            em.emit_rr(cl_op, d, isa::vm_reg_of(in.src.reg), isa::size_field(in.size));
            return true;
        }
        if (!emit_binop_tail(em, sc, in, vop, d))
            return skip(in, "alu 操作数形态未支持", nullptr);
        return true;
    }

    // dst 已就位（寄存器 d）：处理 src 为 Reg / Imm（含 S64 超宽立即数拼装）。
    bool emit_binop_tail(Emitter& em, Scratch& sc, const ir::Insn& in, VmOp vop, u8 d) {
        const u8 sz = isa::size_field(in.size);
        if (in.src.kind == ir::Operand::Kind::Reg) {
            em.emit_rr(vop, d, isa::vm_reg_of(in.src.reg), sz);
            return true;
        }
        if (in.src.kind != ir::Operand::Kind::Imm)
            return false;
        if (in.size != ir::Size::S64 || fits_aux(in.src.imm)) {
            // sub-64 的负立即数：截断 aux 零扩展参与模 2^bits 运算，与 x86
            // imm 符号扩展在目的位宽下逐位等价（含 CF/OF 所需的操作数值）。
            em.emit_ri(vop, d, static_cast<u32>(static_cast<u64>(in.src.imm)), sz);
            return true;
        }
        // S64 超出 aux 零扩展表示能力（如 add rax,-1）：scratch 拼完整值再以 Reg 参与。
        const u8 t = sc.take();
        emit_imm64_split(em, sc, t, static_cast<u64>(in.src.imm));
        em.emit_rr(vop, d, t, sz);
        return true;
    }

    bool translate_unary(Emitter& em, Scratch& sc, const ir::Insn& in,
                         u64 current_rva, u64 next_ip) {
        VmOp vop{};
        if (!vm_op_of(in.op, vop))
            return skip(in, "未支持的操作码", nullptr);
        const u8 sz = isa::size_field(in.size);
        if (in.dst.kind == ir::Operand::Kind::Reg) {
            em.emit(vop, OpKind::Reg, isa::vm_reg_of(in.dst.reg), OpKind::None, 0, 0, sz);
            return true;
        }
        if (in.dst.kind != ir::Operand::Kind::Mem)
            return skip(in, "单目操作数形态未支持", nullptr);
        // [m]：Load s; op s; Store s（地址一次计算、复用）。
        u8 acc = 0;
        if (!emit_address(em, sc, in.dst.mem, current_rva, next_ip, acc))
            return skip(in, "单目操作内存地址形态未支持", &in.dst.mem);
        const u8 s = sc.take();
        const isa::VmOp load_op =
            (in.dst.mem.base == ir::Reg::Rip) ? isa::VmOp::LoadRva : isa::VmOp::Load;
        em.emit_rr(load_op, s, acc, sz);
        em.emit(vop, OpKind::Reg, s, OpKind::None, 0, 0, sz);
        const isa::VmOp store_op =
            (in.dst.mem.base == ir::Reg::Rip) ? isa::VmOp::StoreRva : isa::VmOp::Store;
        em.emit_rr(store_op, acc, s, sz);
        return true;
    }

    // ---- MIT-302: imul / mul ----
    //
    // imul 三形式（lifter 区分）：
    //   1) 3-op imm 形式：dst = src * imm32（src2 = Imm，size 由 data_size 决定）
    //   2) 2-op 形式：dst = dst * src（src = Reg 或 Mem，size = 真实位宽）
    //   3) 1-op 形式（极少见，F7 /5）：lifter 直接转 Op::Mul
    // MIT-306 扩 MEM 形式 (lifter emit Operand::mem_):
    //   - 2-op MEM (imul r, [mem]): 拆成 Load + Imul(dst, tmp), dst = dst * [mem].
    //   - 3-op imm MEM (imul r, [mem], imm): 拆成 Load + Mov(dst, tmp)
    //     + Mov(scratch, imm) + Imul(dst, scratch), dst = [mem] * imm
    //     (注意 native 3-op imm 是 dst = src*imm, 不是 dst = dst*imm;
    //     必须先把 [mem] 拷到 dst 再与 imm 相乘)。
    // 翻译器对 Op::Imul 按 src.kind + src2.kind 区分:
    //   - src=Mem, src2=Imm → Load+Mov+Mov+Imul (MEM 3-op imm)
    //   - src=Mem, src2!=Imm → Load+Imul (MEM 2-op)
    //   - src=Reg, src2=Imm → mov_scratch+Imul(dst, scratch) (REG 3-op imm)
    //     ⚠ MIT-302 老路径: src=dst 时 dst=dst*imm 与 dst=src*imm 等价; MSVC
    //     /Od 实际产 imul r,r,imm 全部 src==dst, 现有实现正确。src!=dst
    //     (如 imul rax, rdx, 7) MSVC 不产, 未测试。
    //   - src=Reg, src2!=Imm → emit VmOp::Imul (REG 2-op)
    // mul 单操作数：emit VmOp::Mul (a_kind=Reg reg_a=Rdx 槽, b_kind=Reg
    // reg_b=src; Rax 是隐式被乘数, asmgen handler 硬编码读 regs[Rax] /
    // 写 regs[Rax]+regs[Rdx])。
    //
    // flags 语义（与 add/sub 完全不同）：
    //   - CF/OF 当低半 != 高半时 set（与 mul 末尾 carry/IMUL 截断同语义）
    //   - SF/ZF/PF 按结果
    //   - handler 用 native imul/mul 直读 host CPU flags, setcc5 捕获——与
    //     add/sub 的 zero5 + setcc5 路径一致, 复用 build_binary("imul"/"mul")
    //     即可。
    bool translate_imul(Emitter& em, Scratch& sc, const ir::Insn& in,
                        u64 current_rva, u64 next_ip) {
        if (in.dst.kind != ir::Operand::Kind::Reg)
            return skip(in, "imul 操作数形态未支持", nullptr);
        const u8 d = isa::vm_reg_of(in.dst.reg);
        const u8 sz = isa::size_field(in.size);

        // MIT-306: MEM 形式 (lifter emit Operand::mem_).
        if (in.src.kind == ir::Operand::Kind::Mem) {
            // emit_load: emit_address(1 scratch for acc) + sc.take() 1 scratch
            // for val (tmp 持有 [mem] 值)。
            const u8 tmp = emit_load(em, sc, in.src.mem, in.size, current_rva, next_ip);
            if (in.src2.kind == ir::Operand::Kind::Imm) {
                // 3-op imm MEM (dst = [mem] * imm):
                //   1. Mov dst, tmp        (dst := [mem])
                //   2. Mov scratch, imm    (scratch := imm)
                //   3. Imul dst, scratch   (dst := dst * scratch = [mem]*imm)
                // scratch 预算: emit_load 用 acc+tmp (2), 本步用 scratch (1) = 3,
                // 在 6 scratch 预算内。
                if (!fits_aux(in.src2.imm))
                    return skip(in, "imul imm32 越界", nullptr);
                const u8 scratch = sc.take();
                em.emit_rr(VmOp::Mov, d, tmp, sz);
                em.emit_ri(VmOp::Mov, scratch,
                           static_cast<u32>(static_cast<u64>(in.src2.imm)), sz);
                em.emit_rr(VmOp::Imul, d, scratch, sz);
                return true;
            }
            // 2-op MEM (dst = dst * [mem]):
            //   1. Imul dst, tmp
            // scratch 预算: emit_load 用 acc+tmp (2), 本步 0 = 2, 在预算内。
            em.emit_rr(VmOp::Imul, d, tmp, sz);
            return true;
        }
        if (in.src.kind != ir::Operand::Kind::Reg)
            return skip(in, "imul 操作数形态未支持", nullptr);

        const u8 s = isa::vm_reg_of(in.src.reg);
        // 3-op imm 形式 (REG)：mov scratch, imm32 → Imul(dst, scratch)
        // native imul 第 3 操作数必须是汇编期常量, 不可用 reg, 故拆 mov+imul。
        // 注意: 语义是 dst = src*imm, 但本路径下 src 与 dst 同寄存器 (MSVC
        // /Od 默认 codegen imul r,r,imm, 例 imul rax, rax, 100), 故
        // dst=dst*imm 与 dst=src*imm 等价。
        if (in.src2.kind == ir::Operand::Kind::Imm) {
            if (!fits_aux(in.src2.imm))
                return skip(in, "imul imm32 越界", nullptr);
            const u8 scratch = sc.take();
            em.emit_ri(VmOp::Mov, scratch,
                       static_cast<u32>(static_cast<u64>(in.src2.imm)), sz);
            em.emit_rr(VmOp::Imul, d, scratch, sz);
            return true;
        }
        // 2-op reg 形式：emit VmOp::Imul（aux = 0）。
        em.emit_rr(VmOp::Imul, d, s, sz);
        return true;
    }

    bool translate_mul(Emitter& em, const ir::Insn& in) {
        // dst = Rdx（高半，lifter 约定），src = Reg 乘数（Rax 是隐式被乘数）。
        if (in.dst.kind != ir::Operand::Kind::Reg ||
            in.src.kind != ir::Operand::Kind::Reg) {
            return skip(in, "mul 操作数形态未支持", nullptr);
        }
        // a_kind=Reg, reg_a = Rdx 槽（asmgen 硬编码读 Rax/写 Rax+Rdx，reg_a 仅
        // 作为 handler 入口 tag，实际计算不依赖 reg_a 的值；保留 Rdx 槽让 handler
        // 在 self-check 时知道这是 Mul 而非别的操作）。
        const u8 sz = isa::size_field(in.size);
        em.emit(VmOp::Mul, OpKind::Reg, isa::vm_reg_of(in.dst.reg),
                OpKind::Reg, isa::vm_reg_of(in.src.reg), 0, sz);
        return true;
    }

    // ---- MIT-307: movsxd (32→64 位符号扩展，x64 专用) ----
    //
    // lifter 区分两种形式：
    //   - REG-REG：movsxd r, r   → emit VmOp::Movsxd
    //   - REG-MEM：movsxd r, [m] → emit_address 算地址到 scratch + VmOp::MovsxdMem
    //
    // Movsxd (Reg-Reg): native `movsxd <r64>, <r/m32>` 一次完成 32→64 符号扩展。
    //   handler: movsxd t0, dword ptr [ctx + reg_b*8 + 0x10] (读 src 32 位)
    //            mov [ctx + reg_a*8 + 0x10], t0 (写回 dst 64 位)
    //
    // MovsxdMem (Reg-Mem): 翻译期把地址算到 scratch 槽 (emit_address → acc),
    //                     运行时 handler 把 acc 槽值当地址访存, 32 位 load + 符号扩展。
    //   handler: mov t1, [ctx + reg_b*8 + 0x10]       (取地址)
    //            movsxd t0, dword ptr [t1]              (32 位 load + 符号扩展)
    //            mov [ctx + reg_a*8 + 0x10], t0        (写回 dst 64 位)
    //
    // 不更新 flags（movsxd 不影响 CF/OF/SF/ZF/PF）。
    bool translate_movsxd(Emitter& em, Scratch& sc, const ir::Insn& in,
                          u64 current_rva, u64 next_ip) {
        if (in.dst.kind != ir::Operand::Kind::Reg)
            return skip(in, "movsxd 操作数形态未支持", nullptr);
        const u8 d = isa::vm_reg_of(in.dst.reg);
        const u8 sz = isa::size_field(in.size);

        if (in.src.kind == ir::Operand::Kind::Reg) {
            // movsxd r, r：emit Movsxd（handler 内部 sign_ext_32）。
            const u8 s = isa::vm_reg_of(in.src.reg);
            em.emit_rr(VmOp::Movsxd, d, s, sz);
            return true;
        }
        if (in.src.kind == ir::Operand::Kind::Mem) {
            // movsxd r, [m]：emit_address 算 acc + emit MovsxdMem。
            // scratch 预算: emit_address 用 1 scratch (acc)；本步不另取。
            u8 acc = 0;
            if (!emit_address(em, sc, in.src.mem, current_rva, next_ip, acc))
                return skip(in, "movsxd 地址形态未支持", &in.src.mem);
            em.emit_rr(VmOp::MovsxdMem, d, acc, sz);
            return true;
        }
        return skip(in, "movsxd 操作数形态未支持", nullptr);
    }

    // ---- MIT-315: movzx (8→32/64 位零扩展) ----
    // ---- MIT-345: 扩 8→16/16→64 形式 (0F B7, 16 位源) ----
    //
    // lifter 区分两种形式：
    //   - REG-REG：movzx r, r8/r16 → emit VmOp::Movzx
    //   - REG-MEM：movzx r, [m]    → emit_address 算地址到 scratch 槽 + VmOp::MovzxMem
    //
    // Movzx (Reg-Reg): native `movzx <r32/r64>, byte/word ptr [...]` 一次完成零扩展。
    //   handler: movzx t_[0], byte/word ptr [ctx + reg_b*8 + 0x10]
    //            mov qword ptr [ctx + reg_a*8 + 0x10], t_[0]
    //   native movzx 自动根据目的寄存器宽度 emit REX.W (S32 vs S64), VM 槽
    //   总是 qword, 与 IR.size (S32 or S64) 一致。
    //   MIT-345 扩：源位宽 src_size 由 lifter 传过来 (S8 → byte ptr, S16 → word ptr),
    //              编码进 aux[3..0] (movzx 不使用 aux 其他位, 与既有 emit_rr aux=0
    //              = src_size S8 默认语义一致).
    //
    // MovzxMem (Reg-Mem): 翻译期把地址算到 scratch 槽 (emit_address → acc),
    //                     运行时 handler 把 acc 槽值当地址访存, src_size 位 load + 零扩展。
    //   handler: mov t_[1], qword ptr [ctx + reg_b*8 + 0x10] (取地址)
    //            movzx t_[0], byte/word ptr [t_[1]]          (8/16 位 load + 零扩展)
    //            mov qword ptr [ctx + reg_a*8 + 0x10], t_[0] (写回 dst VM 槽)
    //
    // 不更新 flags（movzx 不影响 CF/OF/SF/ZF/PF）。
    bool translate_movzx(Emitter& em, Scratch& sc, const ir::Insn& in,
                         u64 current_rva, u64 next_ip) {
        if (in.dst.kind != ir::Operand::Kind::Reg)
            return skip(in, "movzx 操作数形态未支持", nullptr);
        const u8 d = isa::vm_reg_of(in.dst.reg);
        const u8 sz = isa::size_field(in.size);
        // MIT-345: src_size 编码进 aux[3..0], asmgen 据此选 byte ptr / word ptr.
        const u32 src_size_aux = static_cast<u32>(in.src_size) & 0x3u;

        if (in.src.kind == ir::Operand::Kind::Reg) {
            // movzx r, r8/r16：emit Movzx（handler 内部 zero_ext_8/16）。
            const u8 s = isa::vm_reg_of(in.src.reg);
            em.emit(VmOp::Movzx, OpKind::Reg, d, OpKind::Reg, s, src_size_aux, sz);
            return true;
        }
        if (in.src.kind == ir::Operand::Kind::Mem) {
            // movzx r, [m]：emit_address 算 acc + emit MovzxMem。
            // scratch 预算: emit_address 用 1 scratch (acc)；本步不另取。
            u8 acc = 0;
            if (!emit_address(em, sc, in.src.mem, current_rva, next_ip, acc))
                return skip(in, "movzx 地址形态未支持", &in.src.mem);
            em.emit(VmOp::MovzxMem, OpKind::Reg, d, OpKind::Reg, acc, src_size_aux, sz);
            return true;
        }
        return skip(in, "movzx 操作数形态未支持", nullptr);
    }

    // ---- MIT-347: movsx (8/16→32/64 位有符号扩展) ----
    //
    // movsx 与 movzx 是对偶指令（movsx 符号扩展 vs movzx 零扩展）。两者共用
    // src_size 字段 (S8 / S16) 与 size 字段 (S32 / S64) 的编码方式；翻译器折
    // 出的 VmOp 也一一对应 (Movsx / MovsxMem)。
    //   - REG-REG：movsx r, r8/r16 → emit VmOp::Movsx
    //   - REG-MEM：movsx r, [m]    → emit_address 算地址到 scratch 槽 + VmOp::MovsxMem
    //
    // Movsx (Reg-Reg): native `movsx <r32/r64>, byte/word ptr [...]` 一次完成符号扩展。
    //   handler: movsx t_[0], byte/word ptr [ctx + reg_b*8 + 0x10]
    //   aux 编码 src_size (低 2 位: 0=S8, 1=S16)；asmgen 运行时 cmp/jne 选 byte vs word。
    //
    // MovsxMem (Reg-Mem): 翻译期把地址算到 scratch 槽 (emit_address → acc),
    //   然后 emit MovsxMem (handler 读 acc 槽作地址):
    //            mov t_[1], qword ptr [ctx + reg_b*8 + 0x10]   (取地址)
    //            movsx t_[0], byte/word ptr [t_[1]]             (8/16 位 load + 符号扩展)
    //            mov qword ptr [ctx + reg_a*8 + 0x10], t_[0]    (写回 64 位 dst)
    //
    // 不更新 flags（movsx 不影响 CF/OF/SF/ZF/PF）。
    bool translate_movsx(Emitter& em, Scratch& sc, const ir::Insn& in,
                         u64 current_rva, u64 next_ip) {
        if (in.dst.kind != ir::Operand::Kind::Reg)
            return skip(in, "movsx 操作数形态未支持", nullptr);
        const u8 d = isa::vm_reg_of(in.dst.reg);
        const u8 sz = isa::size_field(in.size);
        // MIT-347: src_size 编码进 aux[3..0], asmgen 据此选 byte ptr / word ptr.
        //   S8=0, S16=1（与 movzx 共用 src_size_aux 编码方式, MIT-345 pitfall）。
        const u32 src_size_aux = static_cast<u32>(in.src_size) & 0x3u;

        if (in.src.kind == ir::Operand::Kind::Reg) {
            // movsx r, r8/r16：emit Movsx（handler 内部 sign_ext_8/16）。
            const u8 s = isa::vm_reg_of(in.src.reg);
            em.emit(VmOp::Movsx, OpKind::Reg, d, OpKind::Reg, s, src_size_aux, sz);
            return true;
        }
        if (in.src.kind == ir::Operand::Kind::Mem) {
            // movsx r, [m]：emit_address 算 acc + emit MovsxMem。
            // scratch 预算: emit_address 用 1 scratch (acc)；本步不另取。
            u8 acc = 0;
            if (!emit_address(em, sc, in.src.mem, current_rva, next_ip, acc))
                return skip(in, "movsx 地址形态未支持", &in.src.mem);
            em.emit(VmOp::MovsxMem, OpKind::Reg, d, OpKind::Reg, acc, src_size_aux, sz);
            return true;
        }
        return skip(in, "movsx 操作数形态未支持", nullptr);
    }

    // ---- MIT-349: popcnt (比特计数, SSE4.2) ----
    //
    // popcnt 是 2 操作数 (dst + src 都是寄存器, 派活单限定 REG-REG, MEM 派活单
    // 限定不支持 → lifter 拒 MEM → C1 gate 兜底). emit VmOp::Popcnt 一条:
    //   a_kind=Reg reg_a=dst, b_kind=Reg reg_b=src, aux=0, cond_or_size=size
    //   (S32 或 S64 由 REX.W 决定, lifter 已传过来).
    //
    // popcnt 是 bit-counting (不修改 flags, CF/OF/SF/ZF/PF 不变; SSE4.2 popcnt
    // 仅设 ZF 根据结果 0/非0, lifter 不关心). handler 用 native popcnt 直读 host
    // CPU 完成计数, 不调 setcc5 也不走 flags_tail.
    //
    // handler 在 asmgen.cpp 的 build_popcnt: 按 cond_or_size 分 S32/S64 emit
    // native popcnt eax,eax / popcnt rax,rax (S32/S64). S32 路径用 32 位寄存器
    // (上 32 位自动 zero-extend), qword 写回完整 64 位; S64 路径全 64 位读写。
    // 不更新 flags 槽。
    bool translate_popcnt(Emitter& em, const ir::Insn& in) {
        if (in.op != ir::Op::Popcnt) return false;
        // dst = reg_a, src = reg_b (派活单限定 REG-REG, MEM 派活单限定不支持,
        // lifter 拒 MEM → C1 gate 兜底).
        if (in.dst.kind != ir::Operand::Kind::Reg ||
            in.src.kind != ir::Operand::Kind::Reg)
            return skip(in, "popcnt 操作数形态未支持", nullptr);
        const u8 d = isa::vm_reg_of(in.dst.reg);
        const u8 b = isa::vm_reg_of(in.src.reg);
        em.emit_rr(VmOp::Popcnt, d, b, isa::size_field(in.size));
        return true;
    }

    // ---- MIT-353: lzcnt (前导零计数, BMI1) ----
    //
    // lzcnt 是 2 操作数 (dst + src 都是寄存器, 派活单限定 REG-REG, MEM 派活单
    // 限定不支持 → lifter 拒 MEM → C1 gate 兜底). emit VmOp::Lzcount 一条:
    //   a_kind=Reg reg_a=dst, b_kind=Reg reg_b=src, aux=0, cond_or_size=size
    //   (S32 或 S64 由 REX.W 决定, lifter 已传过来).
    //
    // lzcnt 是 bit-scan (前导零计数, 不修改 flags, CF/OF/SF/ZF/PF 不变; BMI1 lzcnt
    // 仅设 ZF 根据结果 0/非0, lifter 不关心). handler 用 native lzcnt 直读 host
    // CPU 完成计数, 不调 setcc5 也不走 flags_tail.
    //
    // handler 在 asmgen.cpp 的 build_lzcnt: 按 cond_or_size 分 S32/S64 emit
    // native lzcnt eax,eax / lzcnt rax,rax (S32/S64). S32 路径用 32 位寄存器
    // (上 32 位自动 zero-extend), qword 写回完整 64 位; S64 路径全 64 位读写。
    //
    // **关键 (pitfall #37)**: lzcnt 与 popcnt 不同 — lzcnt 不修改 src
    // (native lzcnt r, r/m 只写 dst, src 寄存器保留), 但 handler 必须先
    // `mov T6, T1` 保存 src (T1) 到 T6, 再 `lzcnt t_[0], t_[1]` (dst 写到 T0).
    // 这与 popcnt "T1 in-place, 不需 T6 保存" 不同 — popcnt 的源寄存器被消耗
    // 可重用 T1, lzcnt 的源寄存器必须保留. 不更新 flags 槽。
    bool translate_lzcnt(Emitter& em, const ir::Insn& in) {
        if (in.op != ir::Op::Lzcount) return false;
        // dst = reg_a, src = reg_b (派活单限定 REG-REG, MEM 派活单限定不支持,
        // lifter 拒 MEM → C1 gate 兜底).
        if (in.dst.kind != ir::Operand::Kind::Reg ||
            in.src.kind != ir::Operand::Kind::Reg)
            return skip(in, "lzcnt 操作数形态未支持", nullptr);
        const u8 d = isa::vm_reg_of(in.dst.reg);
        const u8 b = isa::vm_reg_of(in.src.reg);
        em.emit_rr(VmOp::Lzcount, d, b, isa::size_field(in.size));
        return true;
    }

    // ---- MIT-353: tzcnt (末尾零计数, BMI1) ----
    //
    // tzcnt 是 2 操作数 (dst + src 都是寄存器, 派活单限定 REG-REG, MEM 派活单
    // 限定不支持 → lifter 拒 MEM → C1 gate 兜底). emit VmOp::Tzcount 一条:
    //   a_kind=Reg reg_a=dst, b_kind=Reg reg_b=src, aux=0, cond_or_size=size
    //   (S32 或 S64 由 REX.W 决定, lifter 已传过来).
    //
    // tzcnt 是 bit-scan (末尾零计数, 不修改 flags, CF/OF/SF/ZF/PF 不变; BMI1 tzcnt
    // 仅设 ZF 根据结果 0/非0, lifter 不关心). handler 用 native tzcnt 直读 host
    // CPU 完成计数, 不调 setcc5 也不走 flags_tail.
    //
    // handler 在 asmgen.cpp 的 build_tzcnt: 按 cond_or_size 分 S32/S64 emit
    // native tzcnt eax,eax / tzcnt rax,rax (S32/S64). S32 路径用 32 位寄存器
    // (上 32 位自动 zero-extend), qword 写回完整 64 位; S64 路径全 64 位读写。
    //
    // **关键 (pitfall #37)**: tzcnt 与 popcnt 不同 — tzcnt 不修改 src
    // (native tzcnt r, r/m 只写 dst, src 寄存器保留), 但 handler 必须先
    // `mov T6, T1` 保存 src (T1) 到 T6, 再 `tzcnt t_[0], t_[1]` (dst 写到 T0).
    // 与 lzcnt 路径同源 pitfall #37 守恒. 不更新 flags 槽。
    bool translate_tzcnt(Emitter& em, const ir::Insn& in) {
        if (in.op != ir::Op::Tzcount) return false;
        // dst = reg_a, src = reg_b (派活单限定 REG-REG, MEM 派活单限定不支持,
        // lifter 拒 MEM → C1 gate 兜底).
        if (in.dst.kind != ir::Operand::Kind::Reg ||
            in.src.kind != ir::Operand::Kind::Reg)
            return skip(in, "tzcnt 操作数形态未支持", nullptr);
        const u8 d = isa::vm_reg_of(in.dst.reg);
        const u8 b = isa::vm_reg_of(in.src.reg);
        em.emit_rr(VmOp::Tzcount, d, b, isa::size_field(in.size));
        return true;
    }

    // ---- MIT-333: bswap (字节序反转) ----
    //
    // bswap 是单操作数 (dst only, no src), emit VmOp::Bswap 一条：
    //   a_kind=Reg reg_a=dst, b_kind=None reg_b=0, aux=0, cond_or_size=size
    //   (S32 或 S64 由 REX.W 决定, lifter 已传过来)。
    //
    // handler 在 asmgen.cpp 的 build_bswap：按 cond_or_size 分 S32/S64 emit
    // native bswap eax/rax。S32 路径用 32 位寄存器读 + bswap, 写回 qword
    // (上 32 位自动 zero-extend); S64 路径全 64 位。
    //
    // 不更新 flags（bswap 不影响 CF/OF/SF/ZF/PF）。
    bool translate_bswap(Emitter& em, const ir::Insn& in) {
        if (in.op != ir::Op::Bswap) return false;
        if (in.dst.kind != ir::Operand::Kind::Reg) return false;
        const u8 d = isa::vm_reg_of(in.dst.reg);
        const u8 sz = isa::size_field(in.size);
        em.emit(VmOp::Bswap, OpKind::Reg, d, OpKind::None, 0, 0, sz);
        return true;
    }

    // ---- MIT-334: xchg (寄存器交换) ----
    //
    // xchg 是 2 操作数 (dst + src 都是寄存器, 派活单限定 REG-REG, MEM-REG
    // 由 lifter 拒为 unsupported → C1 gate 兜底). emit VmOp::Xchg 一条:
    //   a_kind=Reg reg_a=dst, b_kind=Reg reg_b=src, aux=0, cond_or_size=size
    //   (S32 或 S64 由 REX.W 决定, lifter 已传过来).
    //
    // xchg 是对称操作 (Intel SDM: xchg a, b == xchg b, a), IR.dst/src 顺序
    // 不影响语义, 翻译器按 IR 直产 a=dst, b=src.
    //
    // handler 在 asmgen.cpp 的 build_xchg: 按 cond_or_size 分 S32/S64 emit
    // native xchg eax,ebx (S32) 或 xchg rax,rbx (S64). S32 路径用 dword
    // 读写 (上 32 位 slot 保留), S64 路径用 qword 读写 (full 64 互换).
    //
    // 不更新 flags (xchg 不影响 CF/OF/SF/ZF/PF).
    bool translate_xchg(Emitter& em, const ir::Insn& in) {
        if (in.op != ir::Op::Xchg) return false;
        if (in.dst.kind != ir::Operand::Kind::Reg) return false;
        if (in.src.kind != ir::Operand::Kind::Reg) return false;
        const u8 d = isa::vm_reg_of(in.dst.reg);
        const u8 s = isa::vm_reg_of(in.src.reg);
        const u8 sz = isa::size_field(in.size);
        em.emit_rr(VmOp::Xchg, d, s, sz);
        return true;
    }

    // ---- MIT-336: setcc (条件设置字节) ----
    //
    // setcc 是单操作数 (dst only, no src), 支持 REG 与 MEM 两种 dst 形式：
    //   - REG (mod=11): setcc al/bl/cl/... 子寄存器折叠到全寄存器 (lifter 已折叠),
    //     直接 emit VmOp::Setcc (a_kind=Reg reg_a=dst)。
    //   - MEM (mod=00): setcc [m]，走 Load(tmp, [m], S8) + Setcc(tmp) + Store([m], tmp, S8)
    //     三条拆条；scratch 预算 = emit_address(1) + tmp(1) + emit_address 复用 = 2,在 6 预算内。
    //     严格遵循派活单 §D 改动清单 (仅加 VmOp::Setcc, 不加 SetccMem)，
    //     MEM 形式由 Load/Setcc/Store 三条组合实现 (类似 movzx MEM)。
    //
    // 编码：cond_or_size = ir::Cond (0..15, 与 Jcc 共享 4 位字段)；
    // setcc 是**条件设置**, 不修改 flags (CF/OF/SF/ZF/PF 不变); reads flags 决定结果。
    bool translate_setcc(Emitter& em, Scratch& sc, const ir::Insn& in,
                         u64 current_rva, u64 next_ip) {
        if (in.op != ir::Op::Setcc) return false;
        const u8 sz = isa::size_field(in.size);  // S8 (setcc 必 S8, lifter 已强制)
        if (in.dst.kind == ir::Operand::Kind::Reg) {
            // REG-REG: emit Setcc 一条。
            const u8 d = isa::vm_reg_of(in.dst.reg);
            em.emit(VmOp::Setcc, isa::OpKind::Reg, d, isa::OpKind::None, 0, 0,
                    static_cast<u8>(in.cond));
            return true;
        }
        if (in.dst.kind != ir::Operand::Kind::Mem)
            return skip(in, "setcc 操作数形态未支持", nullptr);
        // REG-MEM: setcc [m] 走 Load+Setcc+Store 三条拆条。
        // 1) Load tmp, [m] (S8) — emit_address 用 1 scratch (acc) + 1 scratch (tmp)。
        u8 acc = 0;
        if (!emit_address(em, sc, in.dst.mem, current_rva, next_ip, acc))
            return skip(in, "setcc 地址形态未支持", &in.dst.mem);
        const u8 tmp = sc.take();
        const isa::VmOp load_op =
            (in.dst.mem.base == ir::Reg::Rip) ? isa::VmOp::LoadRva : isa::VmOp::Load;
        em.emit_rr(load_op, tmp, acc, sz);  // Load tmp, [acc] (S8)
        // 2) Setcc tmp — 单操作数, 直接改 tmp 寄存器低 8 位。
        em.emit(VmOp::Setcc, isa::OpKind::Reg, tmp, isa::OpKind::None, 0, 0,
                static_cast<u8>(in.cond));
        // 3) Store [acc], tmp (S8) — 写回低字节。
        const isa::VmOp store_op =
            (in.dst.mem.base == ir::Reg::Rip) ? isa::VmOp::StoreRva : isa::VmOp::Store;
        em.emit_rr(store_op, acc, tmp, sz);  // Store [acc], tmp (S8)
        return true;
    }

    // ---- MIT-339: cmovcc (条件移动, 16 variants) ----
    //
    // cmovcc 是 2 操作数 (dst + src)，支持 REG-REG 与 MEM-REG 两种 src 形式：
    //   - REG-REG (mod=11): cmovcc r64, r64 → emit 单条 VmOp::Cmovcc
    //     (a_kind=Reg reg_a=dst, b_kind=Reg reg_b=src, aux=0, cond_or_size=ir::Cond)。
    //   - MEM-REG (mod=00): cmovcc r64, [m] → 翻译期把地址算到 scratch 槽 (emit_address
    //     → acc), emit Load(tmp, [m], size) + Cmovcc(dst, tmp) 两条拆条；scratch 预算
    //     = emit_address(1) + tmp(1) = 2, 在 6 预算内。
    //     严格遵循派活单 §D 改动清单 (仅加 VmOp::Cmovcc, 不加 CmovccMem),
    //     MEM 形式由 Load/Cmovcc 两条组合实现 (类似 movzx MEM 路径)。
    //
    // 编码：cond_or_size = ir::Cond (0..15, 与 Jcc/Setcc 共享 4 位字段)；
    // cmovcc 是**条件移动**, 不修改 flags (CF/OF/SF/ZF/PF 不变); reads flags 决定
    // 是否赋值。handler 用 native cmovcc 完成条件赋值, 不动 flags。
    // size 由 IR.size 决定 (lifter 已传过来, S32 或 S64)。
    bool translate_cmovcc(Emitter& em, Scratch& sc, const ir::Insn& in,
                          u64 current_rva, u64 next_ip) {
        if (in.op != ir::Op::Cmovcc) return false;
        if (in.dst.kind != ir::Operand::Kind::Reg) {
            return skip(in, "cmovcc 操作数形态未支持", nullptr);
        }
        const u8 d = isa::vm_reg_of(in.dst.reg);
        const u8 sz = isa::size_field(in.size);

        if (in.src.kind == ir::Operand::Kind::Reg) {
            // REG-REG: cmovcc r, r — emit 单条 VmOp::Cmovcc
            // (handler 用 native cmovcc 完成条件赋值, 保留 dst 高位)。
            // 编码约定：cond_or_size = ir::Size (asmgen size_chain 用 T2 派发),
            //           aux[31..28] = ir::Cond (16 conditions, asmgen cc chain 用);
            //           aux[27..0] = 0 (cmovcc 无 aux 立即数)。这样与既有
            //           build_setcc / build_xchg 等共享 size_chain 助手 (T2 = size),
            //           cc 字段用 aux[31..28] 单独编码避免与 size 冲突。
            const u8 s = isa::vm_reg_of(in.src.reg);
            const u32 cond_aux = static_cast<u32>(in.cond) << 28;
            em.emit(VmOp::Cmovcc, OpKind::Reg, d, OpKind::Reg, s, cond_aux,
                    isa::size_field(in.size));
            return true;
        }
        if (in.src.kind != ir::Operand::Kind::Mem) {
            return skip(in, "cmovcc 操作数形态未支持", nullptr);
        }
        // REG-MEM: cmovcc r, [m] — emit_address 算 acc + emit Load + emit Cmovcc。
        // scratch 预算: emit_address 用 1 scratch (acc) + 1 scratch (tmp) = 2, 在 6 预算内。
        u8 acc = 0;
        if (!emit_address(em, sc, in.src.mem, current_rva, next_ip, acc))
            return skip(in, "cmovcc 地址形态未支持", &in.src.mem);
        const u8 tmp = sc.take();
        const isa::VmOp load_op =
            (in.src.mem.base == ir::Reg::Rip) ? isa::VmOp::LoadRva : isa::VmOp::Load;
        em.emit_rr(load_op, tmp, acc, sz);  // Load tmp, [acc]
        // 同 REG-REG 编码约定：cond_or_size = size, aux[31..28] = cond。
        const u32 cond_aux = static_cast<u32>(in.cond) << 28;
        em.emit(VmOp::Cmovcc, OpKind::Reg, d, OpKind::Reg, tmp, cond_aux,
                isa::size_field(in.size));
        return true;
    }

    // ---- MIT-341: cmpxchg (比较并交换, 隐式 Rax 累加器) ----
    //
    // cmpxchg r/m, r 语义 (Intel SDM Vol. 2 CMPXCHG):
    //   if (Rax == dst) { ZF=1; dst = src }
    //   else              { ZF=0; Rax = dst }
    //
    // lifter 区分两种 dst 形式:
    //   - REG-REG (mod=11): cmpxchg r, r → emit 单条 VmOp::Cmpxchg
    //     (a_kind=Reg reg_a=dst, b_kind=Reg reg_b=src, aux=0, cond_or_size=ir::Size)。
    //   - MEM (mod=00): cmpxchg [m], r → 翻译期把地址算到 scratch 槽 (emit_address
    //     → acc), emit Load(tmp, [m], size) + Cmpxchg(tmp, src) + Store([m], tmp, size)
    //     三条拆条; scratch 预算 = emit_address(1) + tmp(1) = 2, 在 6 预算内。
    //     严格遵循派活单 §D 改动清单 (仅加 VmOp::Cmpxchg, 不加 CmpxchgMem)。
    //
    // 编码：cond_or_size = ir::Size (S8/S16/S32/S64, 与 ALU binop 共享 2 bits);
    // 隐式 acc 由 handler 硬编码读 regs[Rax] (= vm_reg_of(Rax) 槽, slot 0),
    //     按 cond_or_size 选 8/16/32/64 位宽度 native `cmpxchg`, 再写回 dst 槽
    //     与 Rax 槽。Rax 槽是 VM 寄存器槽表的固定位置, 无需新增 IR 字段即可定位
    //     (沿用 pitfall #34 additive enum append-only 不破坏 Insn 布局/大小)。
    //
    // cmpxchg **writes** flags (CF/OF/SF/ZF/PF 全更新, 与 cmp 同语义);
    // handler 用 native cmpxchg 直读 host CPU flags, setcc5 捕获 — 与
    // imul/mul/shift 等 ALU 路径共享 zero5 + setcc5 + flags_tail 复用。
    bool translate_cmpxchg(Emitter& em, Scratch& sc, const ir::Insn& in,
                           u64 current_rva, u64 next_ip) {
        if (in.op != ir::Op::Cmpxchg) return false;
        // src 必为寄存器 (cmpxchg r/m, r 第二操作数必是 r)
        if (in.src.kind != ir::Operand::Kind::Reg) {
            return skip(in, "cmpxchg src 操作数形态未支持", nullptr);
        }
        const u8 s = isa::vm_reg_of(in.src.reg);
        const u8 sz = isa::size_field(in.size);

        if (in.dst.kind == ir::Operand::Kind::Reg) {
            // REG-REG: cmpxchg r, r — emit 单条 VmOp::Cmpxchg
            // (handler 读 Rax 槽, native cmpxchg 完成条件赋值, 写回 dst + Rax)。
            const u8 d = isa::vm_reg_of(in.dst.reg);
            em.emit(VmOp::Cmpxchg, OpKind::Reg, d, OpKind::Reg, s, 0, sz);
            return true;
        }
        if (in.dst.kind != ir::Operand::Kind::Mem) {
            return skip(in, "cmpxchg 操作数形态未支持", nullptr);
        }
        // MEM: cmpxchg [m], r — emit_address 算 acc + emit Load + Cmpxchg + Store。
        // scratch 预算: emit_address 用 1 scratch (acc) + 1 scratch (tmp) = 2, 在 6 预算内。
        u8 acc = 0;
        if (!emit_address(em, sc, in.dst.mem, current_rva, next_ip, acc))
            return skip(in, "cmpxchg 地址形态未支持", &in.dst.mem);
        const u8 tmp = sc.take();
        const isa::VmOp load_op =
            (in.dst.mem.base == ir::Reg::Rip) ? isa::VmOp::LoadRva : isa::VmOp::Load;
        em.emit_rr(load_op, tmp, acc, sz);  // Load tmp, [acc]
        em.emit(VmOp::Cmpxchg, OpKind::Reg, tmp, OpKind::Reg, s, 0, sz);  // Cmpxchg(tmp, src)
        const isa::VmOp store_op =
            (in.dst.mem.base == ir::Reg::Rip) ? isa::VmOp::StoreRva : isa::VmOp::Store;
        em.emit_rr(store_op, acc, tmp, sz);  // Store [acc], tmp
        return true;
    }
};

} // namespace

TranslateResult translate_function(const ir::FunctionRegion& fn) {
    TranslateResult result;

    // 地址 -> 块下标（块按向量顺序即布局顺序排放）。
    std::unordered_map<u64, size_t> block_of_addr;
    for (size_t i = 0; i < fn.blocks.size(); ++i)
        block_of_addr.emplace(fn.blocks[i].addr, i);

    // 地址 -> next_ip（每条 insn 的结束 RVA; rip-relative 翻译用 next_ip+disp 算 RVA）。
    // 推断规则：同一块内下一条 insn.addr; 块末尾下一条 = 下一块 .addr; 函数末尾
    // 块的最后一条 = fn.end_rva. lifter 产出保证 insn.addr 块内严格递增, blocks
    // 按地址升序, 故 next_ip > current_rva 恒成立.
    std::unordered_map<u64, u64> next_ip_of;
    next_ip_of.reserve(fn.blocks.size() * 4);
    for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        const ir::BasicBlock& b = fn.blocks[bi];
        for (size_t ii = 0; ii < b.insns.size(); ++ii) {
            const u64 cur = b.insns[ii].addr;
            u64 nxt;
            if (ii + 1 < b.insns.size()) {
                nxt = b.insns[ii + 1].addr;
            } else if (bi + 1 < fn.blocks.size()) {
                nxt = fn.blocks[bi + 1].addr;
            } else {
                nxt = fn.end_rva;
            }
            next_ip_of.emplace(cur, nxt);
        }
    }

    std::vector<VmInsn> code;
    std::vector<PendingJump> pending;
    std::vector<size_t> block_start(fn.blocks.size());
    Translator tr{code, pending, block_of_addr, result.notes, &next_ip_of};
    const u8 sz64 = isa::size_field(ir::Size::S64);

    for (size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        const ir::BasicBlock& b = fn.blocks[bi];
        block_start[bi] = code.size();
        for (const ir::Insn& in : b.insns)
            tr.run(in);
        // 块末尾非无条件控制流（Jmp/Ret）：补 fallthrough Jmp +1。
        const bool ends_uncond =
            !b.insns.empty() &&
            (b.insns.back().op == ir::Op::Jmp || b.insns.back().op == ir::Op::Ret);
        if (!ends_uncond)
            code.push_back(isa::make_insn(VmOp::Jmp, OpKind::None, 0, OpKind::None,
                                          0, 1, sz64));
    }
    // 函数末尾恒补 Halt（空函数也至少一条，保证 blob 非空）。
    code.push_back(isa::make_insn(VmOp::Halt, OpKind::None, 0, OpKind::None, 0, 0, 0));

    // 回填跳转：aux = 目标块起始序号 - 本指令序号（条数；负值补码入 u32）。
    for (const PendingJump& pj : pending) {
        const i64 rel = static_cast<i64>(block_start[pj.block_idx]) -
                        static_cast<i64>(pj.index);
        code[pj.index].aux = static_cast<u32>(static_cast<i32>(rel));
    }

    // 序列化：VmInsn 流 -> blob -> 字节。
    std::vector<u8> stream;
    stream.reserve(code.size() * 8);
    for (const VmInsn& insn : code)
        isa::append_insn(stream, insn);
    const isa::VmBlob blob = isa::make_blob(fn.arch, 0, std::move(stream));

    std::vector<u8> bytes;
    bytes.reserve(32 + blob.stream.size());
    wvmp::ByteWriter w(bytes);
    isa::write_blob(w, blob);

    result.program.bytecode = std::move(bytes);
    result.program.entry_offset = 0;
    return result;
}

} // namespace wvmp::regvm::translator
