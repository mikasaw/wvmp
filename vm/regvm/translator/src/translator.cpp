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
            if (is_alu_binop(in.op))
                ok = translate_alu_binop(em, sc, in, current_rva, next_ip);
            else if (is_unary(in.op))
                ok = translate_unary(em, sc, in, current_rva, next_ip);
            else
                ok = skip(in, "未支持的操作码", nullptr);
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
        em.emit_rr(VmOp::Mov, isa::vm_reg_of(in.dst.reg), acc, isa::size_field(in.size));
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
