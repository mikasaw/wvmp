// regvm 翻译器：ir::Insn -> RegVM 字节码（纯函数、流式、逐指令翻译）。
// 翻译约定总注释见 translator.hpp。

#include "wvmp/regvm/translator/translator.hpp"

#include "wvmp/common/bytes.hpp"
#include "wvmp/regvm/isa/blob.hpp"
#include "wvmp/regvm/isa/encoding.hpp"
#include "wvmp/regvm/isa/vm_op.hpp"
#include "wvmp/regvm/isa/vm_reg.hpp"
// MIT-451 (X5b) B.2：kX86GuardBytes（x86 栈深 walk 预算单一来源）。
#include "wvmp/regvm/runtime/runtime_x86.hpp"

#include <cinttypes>
#include <cstdio>
#include <limits>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
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

// MIT-419 (G4): lock 族 src2 标记 — 与 lifter (x86_translate.cpp
// translate_lock_op) 的枚举分域严格对账 (5..13; string family 0..4 不相干):
//   5..8: Op::Mov 载体族 (xadd/bts/btr/btc — ir::Op 冻结契约不可增枚举,
//         沿用 G3 串指令 "Op::Mov + src2=imm(family)" 载体先例)
//   9..11: 本体 op 族 (ALU/Cmpxchg/Xchg — 标记仅声明"曾带 lock", 发 note 用)
//   12..13: 本体 op 族 (Inc/Dec — MIT-423 G4b; 本体折条通路 translate_unary
//         mem 拆条既有, 发 note 后派发回本体)
enum : int { kLockXadd = 5, kLockBts = 6, kLockBtr = 7, kLockBtc = 8,
             kLockStripAlu = 9, kLockStripCmpxchg = 10, kLockStripXchg = 11,
             kLockInc = 12, kLockDec = 13 };
[[nodiscard]] bool is_lock_marker(i64 v) {
    return v >= kLockXadd && v <= kLockDec;
}
// lock 标记只可能骑在下列 op 上 (lifter 约定) — **必须 op 限定**:
// imul 3-op imm 形式也用 src2=imm 且立即数任意 (exitnative 样本实证
// imul rax,[rsp+0x40],7 → src2=imm(7) 恰落在标记域, 无条件拦截会误伤)。
// MIT-423 (G4b) 域扩 12..13 对账: Inc/Dec 加入载体面 — 其唯一构造点 lifter
// translate_unary 不写 src2 (Operand 默认 kind=None, operand.hpp; 拦截条件
// src2.kind==Imm 不可能为真); Imul 仍排除在外 (12/13 同 7 一样是合法 imul
// 立即数 — 回归用例 ImulThreeOpImmAtNewMarkerValuesNotIntercepted 锁死)。
[[nodiscard]] bool is_lock_carrier_op(ir::Op op) {
    switch (op) {
    case ir::Op::Mov: case ir::Op::Add: case ir::Op::Sub: case ir::Op::Adc:
    case ir::Op::Sbb: case ir::Op::And: case ir::Op::Or: case ir::Op::Xor:
    case ir::Op::Cmpxchg: case ir::Op::Xchg:
    case ir::Op::Inc: case ir::Op::Dec:
        return true;
    default:
        return false;
    }
}

// MIT-425 (G1b): SSE mul 族 + andn 的 src2 载体标记 — 与 lifter
// (x86_translate.cpp translate_sse_mul / translate_sse_andn) 的枚举分域
// 严格对账 (14..18; string family 0..4 / lock 5..13 分区连续不相交):
//   14..17: Op::Mul 载体族 (mulss/mulsd/mulps/mulpd — ir::Op 冻结契约不可
//           增枚举, GP Op::Mul 的 (Mul,S32/S64) 双占用使 (Op,Size) 双语义
//           装不下 4 形态; (Addss,S8)=mulss 类映射 op 名与语义相反, 弃。
//           沿用 G3/G4 "op 载体 + src2=imm(族)" 先例)
//   18:     Op::Andps 载体 (andnps/andnpd/pandn 折叠 Andnps — dst=~dst&src
//           非纯位运算三元组, 无法单折 Andps; VM 无 128-bit NOT 原语,
//           双折不可行, 派活单 §B.2 选新 VmOp)
// 碰撞对账 (419 §B.1 同款审计): src2=imm 写入点全仓 = imul 3-op (op=Imul,
// 立即数任意 — 14..18 同为合法 imul 立即数, **必须 op 限定**) / string
// 载体 (op=Mov, 0..4) / lock (5..13) / 本域 (op=Mul|Andps, 仅 14..18)。
// GP mul 与 1-op imul→Mul 路径 (translate_imul 1-op/translate_mul) 从不写
// src2 (默认 kind=None); translate_sse_bitwise (Andps 常规构造) 同样不写。
enum : int { kSseMulSs = 14, kSseMulSd = 15, kSseMulPs = 16, kSseMulPd = 17,
             kSseAndn = 18 };
[[nodiscard]] bool is_sse_mul_marker(i64 v) {
    return v >= kSseMulSs && v <= kSseMulPd;
}
[[nodiscard]] bool is_andn_marker(i64 v) {
    return v == kSseAndn;
}

// MIT-427 (G1c): movd/movq GP↔xmm 桥 src2 载体标记 — 与 lifter
// (x86_translate.cpp translate_movd_movq) 的枚举分域严格对账 (19..21;
// string 0..4 / lock 5..13 / SSE mul+andn 14..18 分区连续不相交):
//   19 kBridgeFromGp:  GP→xmm 桥 (dst=xmm 借用 0..7 → 翻译期 +24;
//                      src=GP 真寄存器 0..15 直发槽号)
//   20 kBridgeToGp:    xmm→GP 桥 (dst=GP 真寄存器 0..15 直发槽号;
//                      src=xmm 借用 0..7 → 翻译期 +24)
//   21 kBridgeFromXmm: xmm→xmm 低 64 拷贝 + 目的高 64 清零 (F3 0F 7E /
//                      66 0F D6 reg-reg 全形态 — #33 实测两编码语义逐位
//                      相同, d6_probe 2026-08-30; "高 64 保持" 只对 mem-dest
//                      形式成立, 由 XmmStore 截取通路表达; dst/src 均借用
//                      0..7 → 双 +24)
// 载体 = Op::Movss (碰撞对账 425 §B.1 同款审计): src2=imm 写入点全仓 =
// imul 3-op (op=Imul, 必须本派发 op+标记双限定) / string 载体 (op=Mov,
// 0..4) / lock (5..13) / SSE mul (op=Mul, 14..17) / andn (op=Andps, 18) /
// 本域 (op=Movss, 19..21)。movss 常规构造 (translate_sse_mov) 从不写
// src2 — 本派发必须先于 SSE mov 分支 (marker 载体若落 translate_sse_mov
// 会错误 emit 真 movss)。
enum : int { kBridgeFromGp = 19, kBridgeToGp = 20, kBridgeFromXmm = 21 };
[[nodiscard]] bool is_bridge_marker(i64 v) {
    return v >= kBridgeFromGp && v <= kBridgeFromXmm;
}

// MIT-434 (G8a): BMI 载体判据 — 与 lifter (x86_translate.cpp kFlagless 域注)
// 严格对账。判据 = src2.kind≠None 骑在"全仓从不写 src2"的 op 上
// (andn/bzhi 三操作数, imm 标记无槽可占, src2 骑真操作数):
//   - (Op::{Shl,Shr,Sar,Rol,Ror}, src2=Imm(22)=kFlagless) = rorx/shlx/sarx/
//     shrx flagless 载体 — 原生 shift 的 count 走 **src** (Imm/CL,
//     translate_shift), src2 恒 None → `ror eax,24` 不误拦 (陷阱② 的
//     "count 值域撞标记域"被 kind 判据绕开);
//   - (Op::And, src2=Reg) = andn d==s2 载体形: src=NOT 项 (reg-only),
//     src2=AND 项;
//   - (Op::Sub, src2=Reg) = bzhi: src=value (r/m), src2=Reg(index)。
// 全仓 src2 写入点审计 (419 §B.1 同款): imul 3-op (op=Imul, 立即数任意) /
// string (op=Mov, imm 0..4) / lock (op 载体族, imm 5..13) / SSE mul (op=Mul,
// 14..17) / andnps (op=Andps, 18) / bridge (op=Movss, 19..21) / 本域
// (And|Sub 仅 src2=Reg; shift 仅 src2=Imm(22)) — op+kind 双限定下零碰撞;
// 域 22 与 0..21 分区连续零重叠。
enum : int { kBmiFlagless = 22 };
[[nodiscard]] bool is_bmi_flagless_marker(i64 v) {
    return v == kBmiFlagless;
}
[[nodiscard]] bool is_bmi_shift_op(ir::Op op) {
    switch (op) {
    case ir::Op::Shl: case ir::Op::Shr: case ir::Op::Sar:
    case ir::Op::Rol: case ir::Op::Ror:
        return true;
    default:
        return false;
    }
}

// MIT-442 (X2a) ②: plain (无前缀) 单发串形标记域 — 与 lifter
// (x86_translate.cpp kStrPlainBase 域注) 严格对账 (23..27; 载体 = Op::Mov +
// src2=imm(域), op 限定 Mov — 与 0..4 rep 串同载体, 域值连续分区)。
// 语义 = G3 rep 微程序"循环一次": 无 rcx 预检 / 无循环回边; movs/stos/lods
// 无 GetFlags/SetFlags 包裹 (原生不写 flags), scas/cmps 体内 Cmp 后直落
// (flags = 末次比较, 与原生一致)。
enum : int { kStrPlainBase = 23 };  // 23..27 = plain movs/stos/scas/cmps/lods

// MIT-442 (X2a) ⑥: cbw 载体 — Op::Movsx + src2=Imm(28) (kExtCbw)。与 lifter
// (x86_translate.cpp translate_cbw 域注) 对账: 域 28 与 0..27 分区连续零重叠;
// op 限定 Movsx (movsx 常规构造从不写 src2 — 419 §B.1 审计纪律), 与 plain
// 串形 (op=Mov) 零碰撞。
enum : int { kExtCbw = 28 };
[[nodiscard]] bool is_cbw_marker(i64 v) {
    return v == kExtCbw;
}

// ==================== MIT-409 + MIT-413 (G2): 跳转表特化 ====================
//
// 识别模式 = 受限模板匹配（D1 决策，派活单 §A.2 实测模板 + G2 三参数
// 扩面），翻译期预扫描。REG 源形态（块尾 `jmp <t>`）：
//   mov <idx>, [mem]             idx 载入（链接防御 cmp 的桥）
//   lea <b>, [rip+T] 或 mov <b>, VA（G2: movabs 基址）
//   mov <ix>, [<b>+<idx>*scale+off]  表项读入（要求 t==ix）
//   add <t>, <b>                 仅 4B/8B delta 语义存在（G2-a 绝对表无此条）
//   jmp <t>
//   其中 lea 与 idx 载入可互换（实测两种 MSVC codegen：r06 载入在前、
//   jmp_table_sample lea 在前）。
// MEM 源形态（G2-b，clang/GCC 风格 `jmp [tbl+idx*8]`）：
//   mov <idx>, [mem] ; lea <b>, [rip+T]（或 mov <b>,VA）; jmp [<b>+<idx>*scale+off]
//   块尾 jmp 的 dst 为 Mem（lifter 409 起 lift，非表形态照旧 gate）。
// 前一块尾部防御（表长 K 唯一合法来源，D1 锁死"严禁靠扫非法值推导"；
// G2 兼容 GCC 双编码）：
//   cmp <idx>, K-1 ; ja <越区>    MSVC：K = 立即数 + 1
//   cmp <idx>, K   ; jae <越区>    GCC：K = 立即数
// 表项语义候选（D4 三参数：宽度 / 基址语义 / MEM 源；首个全项通过者入选）：
//   DeltaFromBase: 目标 RVA = 表基址 RVA + 项（REG 源带 add；项宽 4B 零扩展、
//                   8B signed）
//   DeltaFromJmp:  目标 RVA = jmp 指令 RVA + 项（GCC `.L4` 风格，8B signed）
//   AbsoluteVa:    目标 RVA = 项 − image_base（完整 VA 表；需 image_base）
// 运行时展开 = 比较链（D2 决策，零新 VmOp）：
//   REG 源: t = jmp 目标寄存器槽（运行时 = VA）
//   MEM 源: 先物化表项 t = [idx<<log2(scale) + b + off]（Load S64/S32），
//           delta 系再锚定 Add t, anchor_rva; LeaRva t,t → VA
//   链: Mov s, rva_i ; LeaRva s,s ; Cmp t,s ; Jcc eq → 块_i   ×K
// 任一环节不符 → 维持原 gate（保守底线零让步）；形态符合但无防御常数 →
// 以"疑似表形态但未检出防御常数"note 披露（G2-c 永久 gate 裁决）。

// 预扫描产物：模板锚点（Jmp 指令地址）→ 处置。
struct JumpTableHandle {
    bool ok = false;          // true = 已验证可展开（targets 有效）
    u64 table_rva = 0;        // 表体 RVA（diag 用）
    std::vector<u64> targets; // ok=true: 目标 RVA（∈ 区域、已 lift 指令地址）
    std::string gate_note;    // ok=false: 披露 note（触发 C1 gate，替代通用 skip note）
    // MIT-413 (G2): 形态参数（diag 披露 + MEM 源链展开锚）
    bool mem_source = false;  // jmp [mem] 直跳（无目标寄存器）
    u8 width = 4;             // 表项宽度 4/8
    u8 sem = 0;               // 表项语义 0=DeltaFromBase 1=DeltaFromJmp 2=AbsoluteVa
    ir::Reg base_reg = ir::Reg::Flags; // MEM 源: 表基址寄存器（lea/mov 载入）
    ir::Reg idx_reg = ir::Reg::Flags;  // MEM 源: 表索引寄存器
    u8 scale = 0;             // MEM 源: SIB scale（4/8）
    i64 disp = 0;             // MEM 源: 表读位移
    u64 anchor_rva = 0;       // delta 系锚定 RVA（DeltaFromBase=表基址 /
                              //   DeltaFromJmp=jmp 指令地址；MEM 源链展开用）
};

// 表项语义候选枚举值（JumpTableHandle.sem）。
enum : u8 { kJtSemDeltaBase = 0, kJtSemDeltaJmp = 1, kJtSemAbsVa = 2 };

// 表项 → 目标 RVA（候选语义逐一验证；失败返回 false）。
//   项宽 4B: 零扩展 u32（mov eax / jmp m32 读 4 字节语义）；8B: signed i64
//   （负 delta 两补码——表在 .rdata 晚于 .text 时 case−base < 0 常见）。
[[nodiscard]] bool jt_entry_to_rva(u8 width, u8 sem, u64 e, u64 base_rva,
                                   u64 jmp_rva, u64 image_base, u64& out) {
    if (width == 4) {
        const u64 e32 = static_cast<u32>(e);
        if (sem == kJtSemAbsVa) {
            if (e32 < image_base) return false;
            out = e32 - image_base;
        } else {
            const u64 anchor = (sem == kJtSemDeltaBase) ? base_rva : jmp_rva;
            // MIT-451 (X5b) B.3：4B delta = native dword 回绕加法语义（x86
            // `add edx, ecx` 32 位回绕；表在 .text 尾随函数时 case < 表址 →
            // delta 负值以 2 的补码存储——MSVC x86 布局常态）。旧 unsigned-only
            // 判（e32 > u32max − anchor → false）把负 delta 全拒，x86 4B
            // delta 表永不验证通过。8B 表维持 signed i64 语义（x64 面）。
            out = (anchor + e32) & 0xFFFF'FFFFull;
        }
    } else {
        const i64 es = static_cast<i64>(e);
        if (sem == kJtSemAbsVa) {
            if (image_base == 0 || es < 0) return false;
            const u64 eu = static_cast<u64>(es);
            if (eu < image_base) return false;
            out = eu - image_base;
        } else {
            const u64 anchor = (sem == kJtSemDeltaBase) ? base_rva : jmp_rva;
            if (es >= 0) {
                if (static_cast<u64>(es) > std::numeric_limits<u32>::max() - anchor)
                    return false;
                out = anchor + static_cast<u64>(es);
            } else {
                const u64 mag = static_cast<u64>(-(es + 1)) + 1; // 避开 INT64_MIN UB
                if (mag > anchor) return false;
                out = anchor - mag;
            }
        }
    }
    return out <= std::numeric_limits<u32>::max();
}

// 形态 diag 标签（如 "reg-8B-delta" / "mem-8B-abs"）。
[[nodiscard]] std::string jt_form_tag(const JumpTableHandle& h) {
    const char* sem_name =
        h.sem == kJtSemDeltaBase ? "delta"
        : h.sem == kJtSemDeltaJmp ? "djmp" : "abs";
    return std::string(h.mem_source ? "mem-" : "reg-") +
           std::to_string(h.width) + "B-" + sem_name;
}

// 前块尾部防御常数解析：MSVC `cmp idx,K-1; ja`（K=imm+1）与 GCC
// `cmp idx,K; jae`（K=imm）双编码；其余 → 无防御。被比较值链接校验：
// cmp dst 是 Reg → 必须同 idx；是 Mem → 必须与 idx 载入源同址（409 实测
// MSVC 形态：`mov idx,[m]` 与 `cmp [m],K-1` 共用同一内存槽）。
[[nodiscard]] bool parse_table_defense(const ir::BasicBlock& prev,
                                       const ir::Reg idx_reg,
                                       const ir::MemOperand& il_mem,
                                       const ir::Insn*& cmp_out, u64& k_out) {
    if (prev.insns.size() < 2) return false;
    const ir::Insn& jcc = prev.insns.back();
    const ir::Insn& cmp = prev.insns[prev.insns.size() - 2];
    if (jcc.op != ir::Op::Jcc || jcc.dst.kind != ir::Operand::Kind::Imm)
        return false;
    if (cmp.op != ir::Op::Cmp || cmp.src.kind != ir::Operand::Kind::Imm)
        return false;
    if (cmp.dst.kind == ir::Operand::Kind::Reg) {
        if (cmp.dst.reg != idx_reg) return false;
    } else if (cmp.dst.kind == ir::Operand::Kind::Mem) {
        const ir::MemOperand& cm = cmp.dst.mem;
        if (cm.base != il_mem.base || cm.index != il_mem.index ||
            cm.scale != il_mem.scale || cm.disp != il_mem.disp)
            return false;
    } else {
        return false;
    }
    if (cmp.src.imm < 0) return false;
    if (jcc.cond == ir::Cond::A) {          // cmp idx,K-1; ja → K = imm+1
        k_out = static_cast<u64>(cmp.src.imm) + 1;
    } else if (jcc.cond == ir::Cond::Ae) {  // cmp idx,K; jae → K = imm
        k_out = static_cast<u64>(cmp.src.imm);
    } else {
        return false;
    }
    if (k_out < 1) return false;
    cmp_out = &cmp;
    return true;
}

// 从两个槽位中分类基址载入（lea rip / mov imm64）与 idx 载入（Load）。
// 409 实证两序皆可；G2 (MIT-413) 加 movabs 基址形态（Mov imm64 与 Load
// 同现于两槽——按 dst 寄存器与 op 分类，禁按位置猜）。返回 false = 分类
// 失败（两槽不含各一 / 一槽两义）。
[[nodiscard]] bool classify_base_and_idx(const ir::Insn& a, const ir::Insn& b,
                                         ir::Reg idx_reg, const ir::Insn*& base_out,
                                         const ir::Insn*& il_out) {
    const ir::Insn* base_p = nullptr;
    const ir::Insn* il_p = nullptr;
    for (const ir::Insn* c : {&a, &b}) {
        const bool is_il = c->op == ir::Op::Load &&
                           c->dst.kind == ir::Operand::Kind::Reg &&
                           c->dst.reg == idx_reg;
        const bool is_base = c->op == ir::Op::Lea ||
                             (c->op == ir::Op::Mov &&
                              c->src.kind == ir::Operand::Kind::Imm);
        if (is_il && !il_p)
            il_p = c;
        else if (is_base && !base_p)
            base_p = c;
        else
            return false; // 同槽两义 / 槽位不足
    }
    if (base_p == nullptr || il_p == nullptr) return false;
    base_out = base_p;
    il_out = il_p;
    return true;
}

// 模板匹配 + 表验证。返回 nullopt = 非跳转表形态（维持原 gate note）；
// 返回 handle(ok=false) = 形态符合但验证失败（无防御常数 / 读表越界 /
// 目标出区 / 超预算），gate_note 披露原因。**gate_note 以 "jump-table-gate"
// 开头**——backend 的 diag 过滤只认 "jump-table @"（命中 note），gate
// note 必须留在 notes 通道触发 C1 gate（MIT-413 实测：过滤会静默吞掉
// gate note → 缺块字节码照常虚拟化 → 行为错）。
std::optional<JumpTableHandle> try_match_jump_table(
    const ir::BasicBlock& cur, const ir::BasicBlock& prev,
    const std::unordered_map<u64, u64>& next_ip_of,
    const std::unordered_set<u64>& insn_addrs, u64 begin_rva, u64 end_rva,
    const JumpTableReadFn& read_fn, u64 image_base, ir::Arch arch) {
    const auto& ins = cur.insns;
    // MIT-451 (X5b) B.3：匹配器尺寸判据按 arch 参数化（X5 实测修正 X4 交接
    // 注记"参数化仅步进 tag"——匹配器本体三点 S64 硬判未及）。指针宽 =
    // x64 S64 / x86 S32；表项读宽（4/8）判据与 scale 判据按既有口径不变
    // （x86 表 = 4B 项，8B 项 scale 判据自然排除）。
    const ir::Size ptr_sz = arch == ir::Arch::X86 ? ir::Size::S32 : ir::Size::S64;
    if (ins.size() < 3) return std::nullopt; // MEM 源最少 [il,lea,jmp] 3 条
    const ir::Insn& jmp = ins.back();
    if (jmp.op != ir::Op::Jmp) return std::nullopt;
    const bool mem_source = (jmp.dst.kind == ir::Operand::Kind::Mem);
    if (jmp.dst.kind != ir::Operand::Kind::Reg && !mem_source)
        return std::nullopt;

    // ---- ① 块尾形态骨架：源 / 表读 / add / lea+idx 载入 ----
    ir::Reg t = ir::Reg::Flags;    // REG 源: jmp 目标寄存器（= 表读 dst）
    ir::Reg b = ir::Reg::Flags;    // 表基址寄存器
    ir::Reg idx = ir::Reg::Flags;  // 表索引寄存器
    u8 width = 0;
    u8 scale = 0;
    i64 disp = 0;
    const ir::Insn* lea_p = nullptr; // 基址载入（lea rip / mov imm64）
    const ir::Insn* il_p = nullptr;  // idx 载入（mov <idx>, [mem]）
    if (mem_source) {
        const ir::MemOperand& jm = jmp.dst.mem;
        if (jm.base == ir::Reg::Flags || jm.index == ir::Reg::Flags ||
            jm.disp < 0)
            return std::nullopt; // rip 直 disp 无 index 非表形态（K 不可推）
        b = jm.base;
        idx = jm.index;
        scale = static_cast<u8>(jm.scale);
        disp = jm.disp;
        if (scale != 4 && scale != 8) return std::nullopt;
        width = (scale == 8) ? 8 : 4;
        if (ins.size() < 3) return std::nullopt;
        if (!classify_base_and_idx(ins[ins.size() - 2], ins[ins.size() - 3], idx,
                                   lea_p, il_p))
            return std::nullopt;
    } else {
        const ir::Insn& add = ins[ins.size() - 2];
        const ir::Insn& ld = ins[ins.size() - 3];
        if (add.op == ir::Op::Add) {
            // 带 add → delta 语义（409 原模板；G2-a 8B delta 同款）
            // MIT-451 (X5b) B.3：S64 硬判 → ptr_sz（x86 4B delta 表翻正面）
            if (add.size != ptr_sz ||
                add.dst.kind != ir::Operand::Kind::Reg ||
                add.src.kind != ir::Operand::Kind::Reg)
                return std::nullopt;
            t = add.dst.reg;
            b = add.src.reg;
            if (ld.op != ir::Op::Load || ld.dst.kind != ir::Operand::Kind::Reg ||
                ld.dst.reg != t || ld.src.kind != ir::Operand::Kind::Mem)
                return std::nullopt;
            const ir::MemOperand& lm = ld.src.mem;
            if (lm.base != b || lm.index == ir::Reg::Flags || lm.disp < 0)
                return std::nullopt;
            idx = lm.index;
            scale = static_cast<u8>(lm.scale);
            disp = lm.disp;
            if (scale != 4 && scale != 8) return std::nullopt;
            width = (scale == 8) ? 8 : 4;
            if (ld.size != (width == 8 ? ir::Size::S64 : ir::Size::S32))
                return std::nullopt;
            if (ins.size() < 5) return std::nullopt;
            if (!classify_base_and_idx(ins[ins.size() - 4], ins[ins.size() - 5],
                                       idx, lea_p, il_p))
                return std::nullopt;
        } else if (add.op == ir::Op::Load) {
            // 无 add → 绝对 VA 语义（G2-a 8B 绝对表 / u32 VA 表）
            if (add.dst.kind != ir::Operand::Kind::Reg ||
                add.src.kind != ir::Operand::Kind::Mem)
                return std::nullopt;
            t = add.dst.reg;
            const ir::MemOperand& lm = add.src.mem;
            if (lm.base == ir::Reg::Flags || lm.index == ir::Reg::Flags ||
                lm.disp < 0)
                return std::nullopt;
            b = lm.base;
            idx = lm.index;
            scale = static_cast<u8>(lm.scale);
            disp = lm.disp;
            if (scale != 4 && scale != 8) return std::nullopt;
            width = (scale == 8) ? 8 : 4;
            if (add.size != (width == 8 ? ir::Size::S64 : ir::Size::S32))
                return std::nullopt;
            if (ins.size() < 4) return std::nullopt;
            if (!classify_base_and_idx(ins[ins.size() - 3], ins[ins.size() - 4],
                                       idx, lea_p, il_p))
                return std::nullopt;
        } else {
            return std::nullopt;
        }
    }

    // ---- ② 基址载入：lea <b>,[rip+T]（指针宽）或 mov <b>, imm（x86 =
    //         `mov ecx, OFFSET tbl` imm32 绝对 VA / x64 movabs）----
    u64 base_rva = 0;
    bool have_base = false;
    if (lea_p != nullptr && lea_p->op == ir::Op::Lea) {
        // MIT-451 (X5b) B.3：S64 硬判 → ptr_sz（x86 无 rip 寻址，本形 x86
        // 不可达，参数化为对称面）。
        if (lea_p->size != ptr_sz ||
            lea_p->dst.kind != ir::Operand::Kind::Reg || lea_p->dst.reg != b ||
            lea_p->src.kind != ir::Operand::Kind::Mem ||
            lea_p->src.mem.base != ir::Reg::Rip)
            return std::nullopt;
        const auto it = next_ip_of.find(lea_p->addr);
        if (it == next_ip_of.end()) return std::nullopt;
        const i64 lea_tgt = static_cast<i64>(it->second) + lea_p->src.mem.disp;
        if (lea_tgt < 0 ||
            lea_tgt > static_cast<i64>(std::numeric_limits<u32>::max()))
            return std::nullopt;
        base_rva = static_cast<u64>(lea_tgt);
        have_base = true;
    } else if (lea_p != nullptr && lea_p->op == ir::Op::Mov &&
               lea_p->size == ptr_sz &&
               lea_p->dst.kind == ir::Operand::Kind::Reg &&
               lea_p->dst.reg == b &&
               lea_p->src.kind == ir::Operand::Kind::Imm) {
        // mov-abs 基址（x64 movabs imm64 / x86 mov imm32 OFFSET）：链接期 VA
        // → 减 image_base 还原 RVA。MIT-451 (X5b) B.3：S64 硬判 → ptr_sz
        // （x86 REG-abs/MEM-abs 两正形的翻正面）。
        if (image_base != 0 &&
            static_cast<u64>(lea_p->src.imm) >= image_base) {
            base_rva = static_cast<u64>(lea_p->src.imm) - image_base;
            have_base = true;
        }
    }
    if (!have_base) return std::nullopt;

    // ---- ③ idx 载入：mov <idx>, [mem]（防御 cmp 的链接桥）----
    if (il_p == nullptr || il_p->op != ir::Op::Load ||
        il_p->dst.kind != ir::Operand::Kind::Reg || il_p->dst.reg != idx ||
        il_p->src.kind != ir::Operand::Kind::Mem)
        return std::nullopt;

    // ---- ④ 前块尾部防御常数 → 表长 K（G2-c：无防御 = 永久 gate）----
    const u64 kJmpTableBudget = 32; // 比较链条目预算（D2：≤32，超预算披露后 gate）
    const ir::Insn* cmp_p = nullptr;
    u64 k = 0;
    JumpTableHandle h;
    h.table_rva = base_rva + static_cast<u64>(disp);
    if (h.table_rva > std::numeric_limits<u32>::max()) return std::nullopt;
    h.mem_source = mem_source;
    h.width = width;
    h.base_reg = b;
    h.idx_reg = idx;
    h.scale = scale;
    h.disp = disp;
    if (!parse_table_defense(prev, idx, il_p->src.mem, cmp_p, k)) {
        char note[192];
        std::snprintf(note, sizeof(note),
                      "jump-table-gate @ 0x%" PRIX64
                      ": 疑似表形态但未检出防御常数 (cmp idx,K-1; ja / cmp idx,K; "
                      "jae)，保守 gate（G2-c 永久裁决）",
                      h.table_rva);
        h.gate_note = note;
        return h;
    }
    (void)cmp_p; // 链接已由 parse_table_defense 校验（reg 同 idx / mem 同址）
    if (k > kJmpTableBudget) {
        char note[160];
        std::snprintf(note, sizeof(note),
                      "jump-table-gate @ 0x%" PRIX64
                      ": 表长 K=%llu 超出比较链预算 %llu，保守 gate",
                      h.table_rva, static_cast<unsigned long long>(k),
                      static_cast<unsigned long long>(kJmpTableBudget));
        h.gate_note = note;
        return h;
    }

    // ---- ⑤ 逐候选语义读表验证：首个全项通过者入选 ----
    //   候选序（首个通过者定稿；全不过 → gate）：
    //   REG 带 add:  [DeltaBase]；REG 无 add: [AbsVa]；
    //   MEM 源:      [DeltaBase, DeltaJmp, AbsVa]（GCC 变体双语义全试，
    //                区判据是唯一裁决者——§F.3）。
    //   表项语义全候选在"目标 ∈ 区域且为已 lift 指令地址"硬判据下天然
    //   互斥（错误语义的还原值必出区/落数据）。
    const u64 jmp_rva = jmp.addr;
    const u8 kSemsRegAdd[] = {kJtSemDeltaBase};
    const u8 kSemsRegNoAdd[] = {kJtSemAbsVa};
    const u8 kSemsMem[] = {kJtSemDeltaBase, kJtSemDeltaJmp, kJtSemAbsVa};
    const u8* sems = nullptr;
    size_t nsems = 0;
    if (mem_source) {
        sems = kSemsMem;
        nsems = sizeof(kSemsMem);
    } else if (ins[ins.size() - 2].op == ir::Op::Add) {
        sems = kSemsRegAdd;
        nsems = sizeof(kSemsRegAdd);
    } else {
        sems = kSemsRegNoAdd;
        nsems = sizeof(kSemsRegNoAdd);
    }
    std::vector<u64> targets;
    targets.reserve(k);
    std::string last_fail_note;
    for (size_t si = 0; si < nsems; ++si) {
        const u8 sem = sems[si];
        targets.clear();
        bool ok_all = true;
        for (u32 i = 0; i < k; ++i) {
            const auto e = read_fn(h.table_rva, i, width);
            if (!e) {
                char note[192];
                std::snprintf(note, sizeof(note),
                              "jump-table-gate @ 0x%" PRIX64 ": 读表项 %u 失败（越界），保守 gate",
                              h.table_rva, static_cast<unsigned>(i));
                last_fail_note = note;
                ok_all = false;
                break;
            }
            u64 target_rva = 0;
            if (!jt_entry_to_rva(width, sem, *e, base_rva, jmp_rva, image_base,
                                 target_rva) ||
                target_rva < begin_rva || target_rva >= end_rva ||
                insn_addrs.find(target_rva) == insn_addrs.end()) {
                char note[192];
                std::snprintf(note, sizeof(note),
                              "jump-table-gate @ 0x%" PRIX64 ": 目标 0x%" PRIX64
                              " 不在区域/非指令地址，保守 gate",
                              h.table_rva, target_rva);
                last_fail_note = note;
                ok_all = false;
                break;
            }
            targets.push_back(target_rva);
        }
        if (ok_all) {
            h.ok = true;
            h.sem = sem;
            h.targets = std::move(targets);
            if (sem == kJtSemDeltaBase) h.anchor_rva = base_rva;
            else if (sem == kJtSemDeltaJmp) h.anchor_rva = jmp_rva;
            return h;
        }
    }
    h.gate_note = std::move(last_fail_note);
    return h;
}

// 把 split_addrs（预扫描已验证为已 lift 指令地址）从所在块中切出为新块。
// fn.blocks 是冻结只读契约，翻译期在本地副本上切分：链跳转目标由此获得
// 块起点（block_of_addr 反查 + block_start 回填的既有机制零改动复用）。
std::vector<ir::BasicBlock> split_blocks(std::vector<ir::BasicBlock> blocks,
                                         const std::set<u64>& split_addrs) {
    if (split_addrs.empty()) return blocks;
    std::vector<ir::BasicBlock> out;
    out.reserve(blocks.size() + split_addrs.size());
    for (const ir::BasicBlock& b : blocks) {
        std::vector<u64> cuts;
        for (u64 a : split_addrs)
            if (a > b.addr) cuts.push_back(a); // 块首切分点 = 既有块起点，无操作
        if (cuts.empty()) {
            out.push_back(b);
            continue;
        }
        std::sort(cuts.begin(), cuts.end());
        size_t from = 0;
        u64 cur_start = b.addr;
        for (u64 c : cuts) {
            size_t ii = from;
            while (ii < b.insns.size() && b.insns[ii].addr < c) ++ii;
            if (ii >= b.insns.size() || b.insns[ii].addr != c) continue; // 防御
            if (ii == from) continue;
            ir::BasicBlock sub;
            sub.addr = cur_start;
            sub.insns.assign(b.insns.begin() + from, b.insns.begin() + ii);
            out.push_back(std::move(sub));
            from = ii;
            cur_start = c;
        }
        ir::BasicBlock tail;
        tail.addr = cur_start;
        tail.insns.assign(b.insns.begin() + from, b.insns.end());
        out.push_back(std::move(tail));
    }
    return out;
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

// 把 64 位立即数 v 拼进寄存器 d（4 条）：Mov s,hi32 / Shl s,32 / Mov d,lo32 /
// Or d,s。MIT-446 (X4) B.2 点位③：尺寸 tag 由调用方按 arch 传（x64 = S64
// 现形逐字节不动；x86 = S32 防御形——fits_aux 对 u32 值域恒真，x86 管道
// 本函数不可达，S32 形仅为"若可达也不折 no-op"的一致性兜底）。
void emit_imm64_split(Emitter& em, Scratch& sc, u8 d, u64 v, u8 sz_step) {
    const u8 s = sc.take();
    em.emit_ri(VmOp::Mov, s, static_cast<u32>(v >> 32), sz_step);
    em.emit_ri(VmOp::Shl, s, 32, sz_step);
    em.emit_ri(VmOp::Mov, d, static_cast<u32>(v), sz_step);
    em.emit_rr(VmOp::Or, d, s, sz_step);
}

// 地址计算：base(+index*scale)(+disp) -> acc。RIP 相对：base=Rip 时用
// next_ip + disp 算 RVA 直接发为立即数（带 index/disp 一律零相加；
// x64 [rip+disp32] 实际 = next_ip + disp32, next_ip = current_rva + insn_len,
// 由 caller 通过 next_ip_of_ 传入). 无效 scale/越界 RVA 返回 false.
// MIT-442 (X2a) B.2: 412 §2 五处 "S64 硬编码点" 复核结论 — 本函数 (rip 地址
// 拼装 + mem disp 两点) 与 emit_imm64_split / 跳转表表项宽共四处属**常量
// 误名**: S64 是 VM 64 位槽的内部宽度 (u64 槽上的地址/立即数算术), 与目标
// 架构地址宽无关 (x86 面槽值即 u32 零扩展, fits_aux 恒真 → imm64 拆条在
// x86 不可达); 真正的 arch 宽度分叉点 = 栈宽 (translate_push/translate_pop/
// leave 折条, 已分叉) 与 runtime pop 宽度 (build_ret, asmgen X3/X4 参数化
// 面)。x86 S64 槽算术的 native 编码可行性属 asmgen XL (X3) 范畴, 翻译层
// 不改 (x86 管道现网 rc=2 硬拒, 纸面级)。
// MIT-446 (X4) B.2 点位②：上述"纸面级"随 x86 全管道解锁翻正——本函数全部
// 地址算术的尺寸 tag 改由调用方按 arch 传 sz_step（x64 = S64 现形逐字节
// 不动；x86 = S32，x86 运行时 3 路尺寸链不再折防御 no-op 静默空转）。
[[nodiscard]] bool emit_address(Emitter& em, Scratch& sc, const ir::MemOperand& m,
                                u64 current_rva, u64 next_ip, u8 sz_step, u8& acc_out) {
    if (m.base == ir::Reg::Rip) {
        // rip-relative: RVA = next_ip + disp (disp 是 i64, 可负).
        // PE RVA 字段为 u32, 正常范围 [0, end_rva); 越界（极负 disp 跌出 image 起点）
        // 拒绝, 触发 C1 gate 拦截（保持原生）, 不作为 halt VM 的硬错误.
        const i64 rva_i = static_cast<i64>(next_ip) + m.disp;
        if (rva_i < 0 || rva_i > static_cast<i64>(std::numeric_limits<u32>::max()))
            return false;
        const u64 rva = static_cast<u64>(rva_i);
        const u8 acc = sc.take();
        if (fits_aux(rva_i)) {
            em.emit_ri(VmOp::Mov, acc, static_cast<u32>(rva_i), sz_step);
        } else {
            emit_imm64_split(em, sc, acc, rva, sz_step);
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
            em.emit_rr(VmOp::Mov, ix, isa::vm_reg_of(m.index), sz_step);
            if (shift_bits > 0)
                em.emit_ri(VmOp::Shl, ix, shift_bits, sz_step);
            em.emit_rr(VmOp::Add, acc, ix, sz_step);
        }
        (void)current_rva;
        acc_out = acc;
        return true;
    }
    const u8 acc = sc.take();
    if (m.base != ir::Reg::Flags) {
        em.emit_rr(VmOp::Mov, acc, isa::vm_reg_of(m.base), sz_step);
    } else {
        em.emit_ri(VmOp::Mov, acc, 0, sz_step); // 无 base：绝对 / 纯 index 形式，从 0 起算
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
        em.emit_rr(VmOp::Mov, ix, isa::vm_reg_of(m.index), sz_step);
        if (shift_bits > 0)
            em.emit_ri(VmOp::Shl, ix, shift_bits, sz_step);
        em.emit_rr(VmOp::Add, acc, ix, sz_step);
    }
    if (m.disp != 0) {
        if (fits_aux(m.disp)) {
            em.emit_ri(VmOp::Add, acc, static_cast<u32>(m.disp), sz_step);
        } else if (m.disp < 0) {
            // 负 disp：Sub |disp|（aux 零扩展放不下负数，减法等价，见头文件约定）。
            const u64 mag = static_cast<u64>(-(m.disp + 1)) + 1; // 避开 INT64_MIN 的 UB
            if (mag > 0xFFFF'FFFFull)
                return false; // 超大负 disp：x86 不可编码，防御拒绝
            em.emit_ri(VmOp::Sub, acc, static_cast<u32>(mag), sz_step);
        } else {
            const u8 t = sc.take();
            emit_imm64_split(em, sc, t, static_cast<u64>(m.disp), sz_step);
            em.emit_rr(VmOp::Add, acc, t, sz_step);
        }
    }
    (void)current_rva;
    acc_out = acc;
    return true;
}

// 读 [mem] 到 fresh scratch（Load s, [acc]，方向：a=Reg(s)，b=Reg(acc)）。
// 返回 false 的唯一原因（非法 scale / 越界 RVA）已由调用方先行检查。
// sz_step：地址算术尺寸 tag（MIT-446 X4 B.2 点位②，调用方按 arch 传）。
u8 emit_load(Emitter& em, Scratch& sc, const ir::MemOperand& m, ir::Size size,
             u64 current_rva, u64 next_ip, u8 sz_step) {
    u8 acc = 0;
    const bool ok = emit_address(em, sc, m, current_rva, next_ip, sz_step, acc);
    (void)ok;
    const u8 val = sc.take();
    const isa::VmOp load_op =
        (m.base == ir::Reg::Rip) ? isa::VmOp::LoadRva : isa::VmOp::Load;
    em.emit_rr(load_op, val, acc, isa::size_field(size));
    return val;
}

// MIT-408: SSE mem 形式访存宽度 (SDM Vol.2 宽度语义): ss=4B / sd=8B /
// ps,pd=16B 全量。ir::Op 冻结不可增枚举 → (op,Size::S64) 双语义:
// (Movss/Addss/Subss/Divss,S64) = scalar double (sd) 8B; packed (ps/pd)
// 恒 S64 = 16B; Ucomisd = 8B; 其余 S32 形式 = 4B。
[[nodiscard]] u32 sse_mem_width(ir::Op op, ir::Size sz) {
    if (sz == ir::Size::S32) return 4;
    switch (op) {
    case ir::Op::Movss: case ir::Op::Addss: case ir::Op::Subss: case ir::Op::Divss:
    case ir::Op::Ucomiss: case ir::Op::Ucomisd:
        return 8;  // (op,S64) = sd 标量双精度 / ucomisd
    default:
        return 16;  // ps/pd packed 全 128-bit
    }
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
    // MIT-407: 可选上界查询函数（捕获 PeImage 引用）。空 lambda = 不启用
    // ExitNative（维持 gate）。设置后 translate_jump 在目标块缺失时会额外
    // 检查是否落在 [end_rva, upper_bound_fn(begin_rva)) 内 → ExitNative。
    // 按值持有（v1 曾存指向调用方参数的指针，函数作用域内虽安全但脆弱）。
    FunctionUpperBoundFn upper_bound_of_;
    u64 begin_rva_ = 0;   // 区域起始（用于 ExitNative 上界查询）
    u64 end_rva_ = 0;     // 区域结束（用于 ExitNative 目标判定）
    // MIT-409: 跳转表处置表（锚点 jmp insn addr → 预扫描产物）。nullptr =
    // 未启用跳转表特化（维持原 gate）。translate_jump 命中时展开比较链。
    const std::unordered_map<u64, JumpTableHandle>* jump_tables_ = nullptr;
    // MIT-446 (X4) B.2：步进/地址算术尺寸 tag 的 arch 单一来源。x64 = S64
    // （VM 槽宽现形，逐字节不动）；x86 = S32（x86 运行时 3 路尺寸链走真
    // 块，不再折防御 no-op —— translate_push/pop 同批改 VmOp::Push/Pop 单
    // op 形）。translate_function 按 fn.arch 派生，禁止逐点位再各持分叉。
    ir::Arch arch_ = ir::Arch::X64;
    u8 sz_step_ = isa::size_field(ir::Size::S64);

    bool skip(const ir::Insn& in, std::string_view what, const ir::MemOperand* rip) {
        if (rip && rip->base == ir::Reg::Rip)
            what = "rip-relative 未支持";
        add_note(notes, in.addr, what);
        return false;
    }

    // MIT-408: SSE mem 操作数 → 地址槽折条。emit_address 出 acc (rip 形式为
    // RVA, 非 rip 为绝对 VA); rip 形式追加既有 LeaRva (RVA + image_base →
    // VA, 与 LoadRva/StoreRva 同通道), 统一后 XmmLoad/XmmStore 按绝对 VA 访存。
    // 返回 false = 非法 scale / 越界 RVA → caller skip → C1 gate 兜底.
    [[nodiscard]] bool emit_sse_mem_addr(Emitter& em, Scratch& sc,
                                         const ir::MemOperand& m,
                                         u64 current_rva, u64 next_ip, u8& acc_out) {
        u8 acc = 0;
        if (!emit_address(em, sc, m, current_rva, next_ip, sz_step_, acc)) return false;
        if (m.base == ir::Reg::Rip) {
            em.emit_rr(VmOp::LeaRva, acc, acc, sz_step_);  // RVA→VA (in-place, 读先于写)
        }
        acc_out = acc;
        return true;
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
        // MIT-419 (G4): lock 族挂点 — lifter 用 src2=imm(kLockXadd..kLockDec)
        // 标记 (与 string-op 的 src2=imm(0..4) 分域零碰撞)。统一在 run() 入口
        // 拦截: 先发 lock-strip note (D1 边界披露, 413 纪律 — "lock-strip @"
        // 前缀进 backend 过滤白名单, 不触发 gate), 再按族派发本体翻译。
        // ⚠️ 必须 op 限定 (is_lock_carrier_op): imul 3-op imm 也用 src2=imm
        // 且立即数任意 (exitnative 样本 imul ...,7 实证踩域, 见函数注释)。
        if (in.src2.kind == ir::Operand::Kind::Imm && is_lock_marker(in.src2.imm) &&
            is_lock_carrier_op(in.op)) {
            ok = translate_lock_family(em, sc, in, current_rva, next_ip);
        } else {
        switch (in.op) {
        case ir::Op::Mov: ok = translate_mov(em, sc, in); break;
        case ir::Op::Lea: ok = translate_lea(em, sc, in, current_rva, next_ip); break;
        case ir::Op::Load: ok = translate_load(em, sc, in, current_rva, next_ip); break;
        case ir::Op::Store: ok = translate_store(em, sc, in, current_rva, next_ip); break;
        case ir::Op::Push: ok = translate_push(em, in); break;
        case ir::Op::Pop: ok = translate_pop(em, in); break;
        case ir::Op::Ret:
            // MIT-438 (X1b): ret imm16 清栈语义——lifter 已把 imm 放进 in.src
            // (Imm 形, x86_translate.cpp translate_ret)，此处经 aux 槽传给运行时
            // (D2 选型 (i)：闲置参数槽，零新 VmOp)。imm = pop 返回地址后对 rsp
            // 追加的字节数 (SDM C2 iw, 0..0xFFFF, 无符号不加宽)；plain ret
            // in.src 为 None → aux=0，语义 ≡ ret (D3 边界)。x86/x64 双 arch
            // 共享此路径（imm 恒按字节数加 rsp；pop 宽度差异属 X4 asmgen 参数化面）。
            em.emit(VmOp::Ret, OpKind::None, 0, OpKind::None, 0,
                    in.src.kind == ir::Operand::Kind::Imm
                        ? static_cast<u32>(static_cast<u64>(in.src.imm) & 0xFFFFu)
                        : 0u,
                    isa::size_field(in.size));
            break;
        case ir::Op::Jmp:
        case ir::Op::Jcc: ok = translate_jump(em, sc, in); break;
        case ir::Op::Call:
            ok = translate_call(em, sc, in, current_rva, next_ip);
            break;
        case ir::Op::Nop:
            em.emit(VmOp::Nop, OpKind::None, 0, OpKind::None, 0, 0,
                    isa::size_field(in.size));
            break;
        default:
            if (in.op == ir::Op::Imul) {
                ok = translate_imul(em, sc, in, current_rva, next_ip);
            } else if (in.op == ir::Op::Mul && in.src2.kind == ir::Operand::Kind::Imm &&
                       is_sse_mul_marker(in.src2.imm)) {
                // MIT-425 (G1b): SSE 浮点乘 dispatch — (Op::Mul, src2=imm
                // 14..17) 载体标记, REG-REG emit 单条 VmOp::Mulss/Mulsd/
                // Mulps/Mulpd; MEM 源 (含 rip) 折条同 add。**必须先于 GP
                // mul 分支**且 op+标记双限定 (imul 3-op 的任意 src2 imm
                // 教训, 419 §B.1)。
                ok = translate_sse_mul(em, sc, in, current_rva, next_ip);
            } else if (in.op == ir::Op::Mul) {
                ok = translate_mul(em, in);
            } else if (in.op == ir::Op::Movsxd) {
                ok = translate_movsxd(em, sc, in, current_rva, next_ip);
            } else if (in.op == ir::Op::Movzx) {
                ok = translate_movzx(em, sc, in, current_rva, next_ip);
            } else if (in.op == ir::Op::Movsx && in.src2.kind == ir::Operand::Kind::Imm &&
                       is_cbw_marker(in.src2.imm)) {
                // MIT-442 (X2a) ⑥: cbw (66 98) 载体 dispatch — (Op::Movsx,
                // src2=Imm(28)) 判据 (op+标记双限定, movsx 常规构造从不写
                // src2 — 419 §B.1 纪律)。必须先于通用 Movsx 分支。
                ok = translate_cbw_carrier(em, sc, in);
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
            } else if (in.op == ir::Op::Addss || in.op == ir::Op::Addps || in.op == ir::Op::Addpd) {
                // MIT-371: SSE 浮点加 dispatch — REG-REG 形式 emit 单条
                // VmOp::Addss/Addps/Addpd; MEM 源 (MIT-408) emit
                // LeaRva?+XmmLoad(临时双槽)+ALU 三条 (translate_sse_add
                // 内部展开; (Addss,S64)=addsd → VmOp::Addsd)。
                ok = translate_sse_add(em, sc, in, current_rva, next_ip);
            } else if (in.op == ir::Op::Subss || in.op == ir::Op::Subps || in.op == ir::Op::Subpd) {
                // MIT-373: SSE 浮点减 dispatch — REG-REG emit 单条; MEM 源
                // (MIT-408) 折条同 add; (Subss,S64)=subsd → VmOp::Subsd。
                ok = translate_sse_sub(em, sc, in, current_rva, next_ip);
            } else if (in.op == ir::Op::Divss || in.op == ir::Op::Divps || in.op == ir::Op::Divpd) {
                // MIT-374: SSE 浮点除 dispatch — REG-REG emit 单条; MEM 源
                // (MIT-408) 折条同 add; (Divss,S64)=divsd → VmOp::Divsd。
                ok = translate_sse_div(em, sc, in, current_rva, next_ip);
            } else if (in.op == ir::Op::Movss && in.src2.kind == ir::Operand::Kind::Imm &&
                       is_bridge_marker(in.src2.imm)) {
                // MIT-427 (G1c): movd/movq GP↔xmm 桥 dispatch — (Op::Movss,
                // src2=imm 19..21) 载体标记。**必须先于 SSE mov 分支** (marker
                // 载体若落 translate_sse_mov 会错误 emit 真 movss; op+标记
                // 双限定, imul 3-op 教训 419 §B.1)。
                ok = translate_sse_bridge(em, sc, in, current_rva, next_ip);
            } else if (in.op == ir::Op::Movss || in.op == ir::Op::Movaps ||
                       in.op == ir::Op::Movapd || in.op == ir::Op::Movups ||
                       in.op == ir::Op::Movupd) {
                // MIT-375: SSE 浮点传送 dispatch — REG-REG load 形式 emit 单条
                // VmOp::Movss/Movaps/Movapd/Movups/Movupd; MEM load/store
                // (MIT-408) emit XmmLoad/XmmStore (translate_sse_mov 内部展开;
                // (Movss,S64)=movsd → VmOp::Movsd)。IR.dst.reg/IR.src.reg
                // 是 xmm0..xmm7 编号 (lifter 借用 ir::Reg 值 0..7), 翻译期
                // 加 24 偏移映射到 VmContext.regs[24..31] 保留槽位.
                ok = translate_sse_mov(em, sc, in, current_rva, next_ip);
            } else if (in.op == ir::Op::Xorps || in.op == ir::Op::Orps || in.op == ir::Op::Andps) {
                // MIT-376: SSE 浮点位运算 dispatch — REG-REG 形式 emit 单条
                // VmOp::Xorps/Orps/Andps; MEM 源 (MIT-408) 折条同 add。
                ok = translate_sse_bitwise(em, sc, in, current_rva, next_ip);
            } else if (in.op == ir::Op::Ucomiss || in.op == ir::Op::Ucomisd) {
                // MIT-376: SSE 浮点比较 dispatch — REG-REG 形式 emit 单条
                // VmOp::Ucomiss/Ucomisd; MEM 源 (MIT-408, D4 必做) 折条同 add。
                ok = translate_ucomis(em, sc, in, current_rva, next_ip);
            } else if (in.op == ir::Op::Cdq) {
                // MIT-404: cdq/cqo dispatch — 零操作数 (隐式 rax→rdx 符号扩展),
                // emit 单条 VmOp::Cdq, handler 按 size 选 native 99 / 48 99 直通。
                ok = translate_cdq(em, in);
            } else if (in.op == ir::Op::Div || in.op == ir::Op::Idiv) {
                // MIT-404: div/idiv dispatch — 隐式 dividend rdx:rax 不经字节码
                // 表达 (handler 内部拼装); reg_b = 除数槽 (REG 直发, MEM 经
                // emit_load 折条, rip 形式除数走既有 LoadRva 通路)。
                ok = translate_div_idiv(em, sc, in, current_rva, next_ip);
            } else if (in.op == ir::Op::Bswap) {
                ok = translate_bswap(em, in);
            } else if (in.op == ir::Op::Xchg) {
                // MIT-419 (G4): xchg dispatch — REG-REG 形式 emit 单条
                // VmOp::Xchg; MEM 形式 (xchg [m], r — InterlockedExchange 真
                // 产物, 裸 xchg 隐式锁) emit Load+Xchg+Store 三条拆条
                // (translate_xchg 内部展开, xchg 对称拆条语义等价)。
                ok = translate_xchg(em, sc, in, current_rva, next_ip);
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
            } else if (in.op == ir::Op::And && in.src2.kind == ir::Operand::Kind::Reg) {
                // MIT-434 (G8a): andn d==s2 载体 dispatch — (Op::And, src2=Reg)
                // 判据 (全仓 src2 写入点审计零碰撞, 见 is_bmi_* 域注)。
                // **必须先于通用 alu binop 分支** (And 常规路径不读 src2,
                // 载体会被吞掉展开成普通 And)。
                ok = translate_andn_carrier(em, sc, in);
            } else if (in.op == ir::Op::Sub && in.src2.kind == ir::Operand::Kind::Reg) {
                // MIT-434 (G8a): bzhi 载体 dispatch — (Op::Sub, src2=Reg(index))
                // 判据; 同上先于通用分支。
                ok = translate_bzhi_carrier(em, sc, in, current_rva, next_ip);
            } else if (is_bmi_shift_op(in.op) && in.src2.kind == ir::Operand::Kind::Imm &&
                       is_bmi_flagless_marker(in.src2.imm)) {
                // MIT-434 (G8a): rorx/shlx/sarx/shrx flagless 载体 dispatch —
                // (Op::{Shl..Ror}, src2=Imm(22)) 判据; 原生 shift count 走 src,
                // src2 恒 None → `ror eax,24` 不误拦。同上先于通用分支。
                ok = translate_flagless_shift(em, sc, in);
            } else if (is_alu_binop(in.op)) {
                ok = translate_alu_binop(em, sc, in, current_rva, next_ip);
            } else if (is_unary(in.op)) {
                ok = translate_unary(em, sc, in, current_rva, next_ip);
            } else {
                ok = skip(in, "未支持的操作码", nullptr);
            }
            break;
        }
        }  // else switch (lock 族挂点)
        if (ok)
            code.insert(code.end(), em.out.begin(), em.out.end());
    }

    // ---- 数据移动 ----

    // MIT-415 (G3): rep/repnz 串指令微程序展开 (D2 授权选型: 零新 VmOp 零新
    // handler, 全复用既有组合)。
    //
    // lifter 编码约定 (x86_translate.cpp translate_string_op 对账):
    //   op=Op::Mov + src2=imm(family 0..4) + cond (E=rep/repe, Ne=repne) +
    //   size=元素宽 (S8/S32/S64) + dst/src=语义寄存器形态。普通 mov 的 src2
    //   恒空; imul 的 src2 在 Op::Imul 上 — 零碰撞。
    //
    // 展开结构 (固定循环体, D4: 禁按 rcx 值展开代码; 运行时 rcx 语义保留):
    //   movs:    GetFlags s0; Cmp rcx,0; Jcc E→restore;
    //            loop { Load t,[rsi]; Store [rdi],t; Add rsi,w; Add rdi,w;
    //                   Sub rcx,1; Jcc Ne→loop } restore: SetFlags s0
    //   stos:    同 movs 无 Load (Store [rdi],Rax); lods: 同 movs 无 Store
    //            (Load Rax,[rsi])。movs/stos/lods 不写 flags (SDM) — 全路径
    //            恢复原 flags (含 rcx==0 空转路径)。
    //   scas/cmps (repe/repne): GetFlags s0; Cmp rcx,0; Jcc E→restore0;
    //            loop { Load t,[rdi] (+t2,[rsi] cmps); Cmp acc,t; GetFlags s1;
    //                   Jcc 早退→exit_adv (repne: ZF==1; repe: ZF==0);
    //                   Add 指针; Sub rcx,1; Jcc Ne→loop }
    //            SetFlags s1 (rcx==0 正常出口: flags=末次比较); Jmp→exit;
    //            exit_adv: Add 指针; Sub rcx,1; SetFlags s1; Jmp→exit;
    //            restore0: SetFlags s0 (rcx==0 预检出口: flags 原样 — 原生
    //            零次比较 flags 不变); exit: (jmp_a/jmp_b 汇合)。
    //   早退语义 (native 实测, E2E 对拍 + strlen `lea rax,[rdi-1]` 惯用法
    //   同证): 终止迭代**同样**推进指针并减计数 — repne scasb 命中后 RDI
    //   指向匹配元素**之后**、RCX 已含该次递减; SDM 的"条件不满足即停"
    //   仅指不再重复, 不含指针/计数副作用回滚。故早退 Jcc 跳到共享的
    //   exit_adv 块 (Add/Sub 与主路径重复, SetFlags s1 收尾 flags=末次比较)。
    //
    // 微程序内 Jcc/Jmp 的 aux 直接按 em.out 内位置差回填 (与 pending 块回填
    // 同一语义: 条数差, 负值补码入 u32), 不经过块表 — 循环回边是单条 IR
    // 指令的内部结构, 与区域块表/回跳 gate 链无交互 (B.2 实测项)。
    //
    // DF=0 假定 (D1 裁决, B.3): 微程序按 DF=0 (指针递增) 展开; VM flags 槽
    // 无 DF 位 (kFlagsMask 冻结), 翻译期无法静态证 DF — note 级披露, 与
    // backend 过滤白名单对账 (413 纪律): "string-op @" 前缀走 diag 通道,
    // 不触发 C1 gate。
    bool translate_string_op(Emitter& em, Scratch& sc, const ir::Insn& in) {
        const i64 marker = in.src2.imm;
        // MIT-442 (X2a) ②: plain 单发形 (域 23..27) 与 rep 形 (0..4) 同函数
        // 派发 — fam 归一后共用语义寄存器/宽度逻辑, 展开结构分叉见下。
        const bool plain = marker >= kStrPlainBase;
        const i64 family = plain ? marker - kStrPlainBase : marker;  // 0..4
        if (family < 0 || family > 4)
            return skip(in, "string-op family 标记非法，建议 gate", nullptr);
        const bool repne = !plain && (in.cond == ir::Cond::Ne);
        const u8 sz = isa::size_field(in.size);
        // MIT-446 (X4) B.2 点位⑤：G3 串微程序 rsi/rdi/rcx 步进与 flags 包裹
        // 的尺寸 tag = sz_step_（x64 S64 现形 / x86 S32 —— 步进与 rcx 计数
        // 走 3 路尺寸链真块，不再折防御 no-op；元素宽 sz 仍按 IR.size）。
        const u8 sz64 = sz_step_;
        const u8 rsi = isa::vm_reg_of(ir::Reg::Rsi);
        const u8 rdi = isa::vm_reg_of(ir::Reg::Rdi);
        const u8 rax = isa::vm_reg_of(ir::Reg::Rax);
        const u8 rcx = isa::vm_reg_of(ir::Reg::Rcx);
        const u8 inc = in.size == ir::Size::S64 ? 8u : in.size == ir::Size::S32 ? 4u : 1u;

        // ---- MIT-442 (X2a) ②: plain 单发形 — "循环一次" 展开 (X0 §A.2 预判
        // 实测成立: 415 微程序框架现成)。无 rcx 预检/无循环回边/无早退;
        // movs/stos/lods 原生不写 flags → 无 GetFlags/SetFlags 包裹 (体内
        // Load/Store/Add 全 flags-free); scas/cmps 单发 = 体内 Cmp 后直落,
        // flags = 末次比较 (原生语义, 不恢复)。DF=0 假定沿用 G3 D1 口径。
        if (plain) {
            if (family == 0) {            // movsd/movsb/movsq 单发: [rdi]←[rsi]
                const u8 t1 = sc.take();
                em.emit_rr(VmOp::Load, t1, rsi, sz);
                em.emit_rr(VmOp::Store, rdi, t1, sz);
                em.emit_ri(VmOp::Add, rsi, inc, sz64);
                em.emit_ri(VmOp::Add, rdi, inc, sz64);
            } else if (family == 1) {     // stos: [rdi] ← AL/EAX/RAX
                em.emit_rr(VmOp::Store, rdi, rax, sz);
                em.emit_ri(VmOp::Add, rdi, inc, sz64);
            } else if (family == 4) {     // lods: AL/EAX/RAX ← [rsi]
                em.emit_rr(VmOp::Load, rax, rsi, sz);
                em.emit_ri(VmOp::Add, rsi, inc, sz64);
            } else if (family == 2) {     // scas 单发: cmp acc, [rdi]
                const u8 t1 = sc.take();
                em.emit_rr(VmOp::Load, t1, rdi, sz);
                em.emit_rr(VmOp::Cmp, rax, t1, sz);
                em.emit_ri(VmOp::Add, rdi, inc, sz64);
            } else {                      // cmps 单发: cmp [rsi], [rdi]
                const u8 t1 = sc.take();
                const u8 t2 = sc.take();
                em.emit_rr(VmOp::Load, t1, rsi, sz);
                em.emit_rr(VmOp::Load, t2, rdi, sz);
                em.emit_rr(VmOp::Cmp, t1, t2, sz);
                em.emit_ri(VmOp::Add, rdi, inc, sz64);
                em.emit_ri(VmOp::Add, rsi, inc, sz64);
            }
            const char* fam_name_p = family == 0 ? "movs" : family == 1 ? "stos"
                                   : family == 2 ? "scas" : family == 3 ? "cmps" : "lods";
            const char suffix_p = inc == 1 ? 'b' : inc == 4 ? 'd' : 'q';
            char note_p[192];
            std::snprintf(note_p, sizeof(note_p),
                          "string-op @ 0x%" PRIX64 ": plain %s%c single-step (elem %uB) "
                          "DF=0 assumption (MIT-442 X2a ②, G3 D1 口径)",
                          in.addr, fam_name_p, suffix_p, inc);
            notes.emplace_back(note_p);
            return true;
        }

        // 预检: rcx==0 → 零次迭代 (movs/stos/lods: 不动内存; scas/cmps: 不比较)
        const u8 s0 = sc.take();  // 原 flags 保存槽 (rcx==0 路径恢复)
        em.emit(VmOp::GetFlags, OpKind::Reg, s0, OpKind::None, 0, 0, sz64);
        em.emit_ri(VmOp::Cmp, rcx, 0, sz64);
        const size_t jcc0 = em.out.size();
        em.emit(VmOp::Jcc, OpKind::None, 0, OpKind::None, 0, 0,
                static_cast<u8>(ir::Cond::E));
        const size_t loop_pos = em.out.size();

        const bool cmp_family = (family == 2 || family == 3);
        u8 s1 = 0;            // scas/cmps: 末次比较 flags 保存槽
        size_t jcc_early = 0; // scas/cmps: 早退出口 (repne: ZF==1 / repe: ZF==0)
        if (family == 0) {            // movs: t = [rsi]; [rdi] = t
            const u8 t1 = sc.take();
            em.emit_rr(VmOp::Load, t1, rsi, sz);
            em.emit_rr(VmOp::Store, rdi, t1, sz);
            em.emit_ri(VmOp::Add, rsi, inc, sz64);
            em.emit_ri(VmOp::Add, rdi, inc, sz64);
        } else if (family == 1) {     // stos: [rdi] = AL/EAX/RAX
            em.emit_rr(VmOp::Store, rdi, rax, sz);
            em.emit_ri(VmOp::Add, rdi, inc, sz64);
        } else if (family == 4) {     // lods: AL/EAX/RAX = [rsi]
            em.emit_rr(VmOp::Load, rax, rsi, sz);
            em.emit_ri(VmOp::Add, rsi, inc, sz64);
        } else {                      // scas / cmps: 每迭代 Cmp 真写 flags
            const u8 t1 = sc.take();
            if (family == 2) {
                em.emit_rr(VmOp::Load, t1, rdi, sz);      // t1 = [rdi]
                em.emit_rr(VmOp::Cmp, rax, t1, sz);       // flags = acc - [rdi]
            } else {
                const u8 t2 = sc.take();
                em.emit_rr(VmOp::Load, t1, rsi, sz);      // t1 = [rsi]
                em.emit_rr(VmOp::Load, t2, rdi, sz);      // t2 = [rdi]
                em.emit_rr(VmOp::Cmp, t1, t2, sz);        // flags = [rsi] - [rdi]
            }
            s1 = sc.take();
            em.emit(VmOp::GetFlags, OpKind::Reg, s1, OpKind::None, 0, 0, sz64);
            // 早退 (repne: ZF==1 命中; repe: ZF==0 失配) → 仍推进指针减计数 —
            // **native 实测语义** (E2E 对拍: repne scasb 命中后 RDI 指向匹配
            // 元素**之后**、RCX 已减, strlen `lea rax,[rdi-1]` 惯用法同证;
            // SDM 的 "条件不满足即停" 不适用于终止迭代的指针/计数副作用)。
            // 故早退目标跳到共享的 L_exit_adv (推进+减计数后 SetFlags s1)。
            jcc_early = em.out.size();
            em.emit(VmOp::Jcc, OpKind::None, 0, OpKind::None, 0, 0,
                    repne ? static_cast<u8>(ir::Cond::E)
                          : static_cast<u8>(ir::Cond::Ne));
            em.emit_ri(VmOp::Add, rdi, inc, sz64);
            if (family == 3) em.emit_ri(VmOp::Add, rsi, inc, sz64);
        }

        // 计数递减 (movs/stos/lods: flags 随后统一恢复; scas/cmps: 下一迭代
        // Cmp 覆写, 出口 SetFlags s1 恢复末次比较 flags)
        em.emit_ri(VmOp::Sub, rcx, 1, sz64);
        const size_t jcc_back = em.out.size();
        em.emit(VmOp::Jcc, OpKind::None, 0, OpKind::None, 0, 0,
                static_cast<u8>(ir::Cond::Ne));
        if (cmp_family) {
            // rcx==0 正常出口: flags = 末次比较
            em.emit(VmOp::SetFlags, OpKind::Reg, s1, OpKind::None, 0, 0, sz64);
            const size_t jmp_a = em.out.size();
            em.emit(VmOp::Jmp, OpKind::None, 0, OpKind::None, 0, 0, 0);
            // 早退出口 (jcc_early 目标): 终止迭代同样推进指针减计数 (native
            // 实测语义, 见上) — Add/Sub 与主路径重复, SetFlags s1 收尾。
            const size_t exit_adv = em.out.size();
            em.emit_ri(VmOp::Add, rdi, inc, sz64);
            if (family == 3) em.emit_ri(VmOp::Add, rsi, inc, sz64);
            em.emit_ri(VmOp::Sub, rcx, 1, sz64);
            em.emit(VmOp::SetFlags, OpKind::Reg, s1, OpKind::None, 0, 0, sz64);
            const size_t jmp_b = em.out.size();
            em.emit(VmOp::Jmp, OpKind::None, 0, OpKind::None, 0, 0, 0);
            const size_t restore0 = em.out.size();  // 预检出口 (jcc0 目标)
            em.emit(VmOp::SetFlags, OpKind::Reg, s0, OpKind::None, 0, 0, sz64);
            const size_t exit = em.out.size();      // jmp_a/jmp_b 目标
            em.out[jcc0].aux = static_cast<u32>(static_cast<i32>(restore0 - jcc0));
            em.out[jcc_early].aux = static_cast<u32>(static_cast<i32>(exit_adv - jcc_early));
            em.out[jcc_back].aux = static_cast<u32>(static_cast<i32>(loop_pos - jcc_back));
            em.out[jmp_a].aux = static_cast<u32>(static_cast<i32>(exit - jmp_a));
            em.out[jmp_b].aux = static_cast<u32>(static_cast<i32>(exit - jmp_b));
        } else {
            const size_t restore0 = em.out.size();  // 预检出口 == 循环自然出口
            em.emit(VmOp::SetFlags, OpKind::Reg, s0, OpKind::None, 0, 0, sz64);
            em.out[jcc0].aux = static_cast<u32>(static_cast<i32>(restore0 - jcc0));
            em.out[jcc_back].aux = static_cast<u32>(static_cast<i32>(loop_pos - jcc_back));
        }

        // DF=0 假定 note (B.3; 413 纪律: 前缀与 backend 过滤白名单对账 —
        // 命中 note 走 diag 通道, 不触发 C1 gate)
        const char* fam_name = family == 0 ? "movs" : family == 1 ? "stos"
                             : family == 2 ? "scas" : family == 3 ? "cmps" : "lods";
        const char suffix = inc == 1 ? 'b' : inc == 4 ? 'd' : 'q';
        char note[192];
        std::snprintf(note, sizeof(note),
                      "string-op @ 0x%" PRIX64 ": rep %s%c (elem %uB) DF=0 assumption, "
                      "ptr += %u (D1: DF=1 输入行为不保)",
                      in.addr, fam_name, suffix, inc, inc);
        notes.emplace_back(note);
        return true;
    }

    // ---- MIT-419 (G4): lock 前缀原子族 strip-and-execute ----
    //
    // lifter 编码约定 (x86_translate.cpp translate_lock_op 对账):
    //   src2=imm(kLockXadd..kLockDec, 5..13) 标记 (string family 0..4
    //   分域零碰撞)。run() 入口已拦截 (先发 lock-strip note 再按族派发),
    //   本函数 = 族派发本体:
    //     - kLockStripAlu      (Op::Add/Sub/Adc/Sbb/And/Or/Xor + dst=Mem):
    //        剥 F0 后与普通 mem-dst ALU 同折条 — emit_address + Load +
    //        ALU + Store (本体通路既有, 零新 VmOp; D1 折条原子性边界披露)
    //     - kLockStripCmpxchg  (Op::Cmpxchg + dst=Mem): 既有 mem 拆条
    //        (Load + Cmpxchg + Store)
    //     - kLockStripXchg     (Op::Xchg + dst=Mem): 本单新 mem 拆条
    //        (Load + Xchg + Store, xchg 对称拆条语义等价)
    //     - kLockXadd          (Op::Mov 载体 + dst=Mem + src=Reg): emit
    //        VmOp::Xadd 一条 (a=地址槽, b=源寄存器槽) — handler 内 native
    //        lock xadd [addr], reg 单指令直执行, **硬件原子性保真** (D1 折条
    //        妥协不适用本指令)
    //     - kLockBts/Btr/Btc  (Op::Mov 载体 + dst=Mem + src=Reg/Imm8): emit
    //        VmOp::Bts/Btr/Btc 一条 (a=地址槽; b_kind=Reg 位号槽 或 Imm aux=
    //        imm8) — handler 内 native lock bts [addr], reg 直执行
    //     - kLockInc/Dec       (Op::Inc/Dec + dst=Mem, MIT-423 G4b): 本体折条
    //        translate_unary mem 拆条 (Load/Rva + Inc/Dec + Store/Rva) — 零新
    //        VmOp, 撕裂窗口同 ALU 族 (D1; CF 保真由 build_incdec 既有 CF 保留
    //        语义逐位对齐 SDM "inc/dec 不写 CF")
    //   note 前缀 "lock-strip @" 与 backend 过滤白名单对账 (413 纪律:
    //   regvm_backend.cpp 过滤白名单, 命中不触发 C1 gate)。
    bool translate_lock_family(Emitter& em, Scratch& sc, const ir::Insn& in,
                               u64 current_rva, u64 next_ip) {
        const i64 m = in.src2.imm;
        const char* fam = m == kLockXadd       ? "xadd"
                          : m == kLockBts      ? "bts"
                          : m == kLockBtr      ? "btr"
                          : m == kLockBtc      ? "btc"
                          : m == kLockStripAlu ? "alu"
                          : m == kLockStripCmpxchg ? "cmpxchg"
                          : m == kLockStripXchg ? "xchg"
                          : m == kLockInc      ? "inc"
                          : m == kLockDec      ? "dec"
                                                : "?";
        // D1 边界披露 (GAPS G4 节): strip-and-execute, 多线程并发原子性不
        // 保证 (折条路径); MFENCE 全序不建模。xadd/bts 系单 VmOp 直执行
        // native lock 指令, 硬件原子性由 lock 前缀保真 — 不在本边界内。
        char note[192];
        std::snprintf(note, sizeof(note),
                      "lock-strip @ 0x%" PRIX64 ": %s (strip-and-execute, D1: "
                      "多线程并发原子性不保证, MFENCE 全序不建模)",
                      in.addr, fam);
        notes.emplace_back(note);
        switch (m) {
        case kLockStripAlu:
            if (!is_alu_binop(in.op) || in.dst.kind != ir::Operand::Kind::Mem)
                return skip(in, "lock ALU 操作数形态未支持", nullptr);
            return translate_alu_binop(em, sc, in, current_rva, next_ip);
        case kLockStripCmpxchg:
            return translate_cmpxchg(em, sc, in, current_rva, next_ip);
        case kLockStripXchg:
            return translate_xchg(em, sc, in, current_rva, next_ip);
        case kLockXadd:
            return translate_lock_xadd(em, sc, in, current_rva, next_ip);
        case kLockBts:
        case kLockBtr:
        case kLockBtc:
            return translate_lock_bit(em, sc, in, m, current_rva, next_ip);
        case kLockInc:
        case kLockDec:
            // MIT-423 (G4b): 本体折条 — translate_unary mem 拆条既有零改动
            // (emit_address + Load/Rva + Inc/Dec + Store/Rva; D1 零新 VmOp,
            // 撕裂窗口同 ALU 族披露段; _InterlockedIncrement 真产物 = lock
            // xadd +1 走 419 Xadd 硬件原子通路, 裸 lock inc/dec 无 MSVC 产物)。
            return translate_unary(em, sc, in, current_rva, next_ip);
        default:
            return skip(in, "lock family 标记非法，建议 gate", nullptr);
        }
    }

    // xadd [m], r (InterlockedAdd 真产物): [m] = [m] + r; r = 旧 [m]。
    // 单 VmOp::Xadd (a=地址槽, b=源寄存器槽), handler 内 native lock xadd
    // [addr], reg 一条指令完成读改写 — 硬件原子性保真 (不落 D1 折条边界)。
    // flags = add 语义, handler 走 zero5→native→setcc5→flags_tail。
    // rip-relative 目标: emit_address 出 RVA, 追加 LeaRva (RVA + image_base
    // → VA) 后 Xadd 按绝对 VA 访存 (与 LoadRva/StoreRva 同通道; 实测真产物:
    // 64 位全局 Interlocked* 直出 lock xadd/cmpxchg [rip+disp] 形态)。
    bool translate_lock_xadd(Emitter& em, Scratch& sc, const ir::Insn& in,
                             u64 current_rva, u64 next_ip) {
        // B.4：REG-REG 形（x86 专属；x64 REG-REG 照旧 gate — G4 残余面）。
        if (in.dst.kind == ir::Operand::Kind::Reg &&
            in.src.kind == ir::Operand::Kind::Reg) {
            // 同寄存器形 gate：handler 出口旧值写回 src 槽与 native xadd 的
            // dst 槽写同址，序上会以旧值覆盖 2*old（native xadd r,r = 2*old
            // 赢）——病态形保守 gate（宁窄勿宽）。
            if (arch_ != ir::Arch::X86 || in.dst.reg == in.src.reg)
                return skip(in, "lock xadd 操作数形态未支持", nullptr);
            em.emit(VmOp::Xadd, OpKind::Reg, isa::vm_reg_of(in.dst.reg),
                    OpKind::None, isa::vm_reg_of(in.src.reg), 0,
                    isa::size_field(in.size));
            return true;
        }
        if (in.dst.kind != ir::Operand::Kind::Mem ||
            in.src.kind != ir::Operand::Kind::Reg)
            return skip(in, "lock xadd 操作数形态未支持", nullptr);
        u8 acc = 0;
        if (!emit_address(em, sc, in.dst.mem, current_rva, next_ip, sz_step_, acc))
            return skip(in, "lock xadd 地址形态未支持", &in.dst.mem);
        if (in.dst.mem.base == ir::Reg::Rip) {
            em.emit_rr(VmOp::LeaRva, acc, acc, sz_step_);  // RVA→VA (in-place)
        }
        em.emit(VmOp::Xadd, OpKind::Reg, acc, OpKind::Reg, isa::vm_reg_of(in.src.reg),
                0, isa::size_field(in.size));
        return true;
    }

    // bts/btr/btc [m], r/imm8 (InterlockedBitTest* 真产物): CF = bit[位号];
    // [m] = 1/0/^1 (按族)。单 VmOp::Bts/Btr/Btc (a=地址槽; b_kind=Reg 位号
    // 槽低 8 位 或 Imm aux=imm8)。handler 内 native lock bts [addr], reg
    // 直执行 (imm 位号经 aux 装载进寄存器, reg 形式是超集语义一致)。
    //
    // MIT-451 (X5b) B.4：REG-REG 形（B.4 lifter 翻正面，x86 专属）——
    // dst=Reg 时 emit 单 VmOp::Bts/Btr/Btc/Xadd，**b_kind=None 判别**
    // （b_kind 0 值为编码合法域且 MEM 形从不使用——MEM 形恒 Reg/Imm；
    // reg_a = dst VM 槽索引、reg_b = src VM 槽索引，handler 据此 lea 出
    // dst 槽地址做 native RMW，xadd 旧值写回 src 槽）。零新 VmOp、零编码
    // 改动、vm_op.hpp 冻结面零触碰。x64 不走本分支（G4 残余 gate 面不变；
    // x64 handler 逐字节不动 = dump ffd47289 恒等约束）。REG-IMM（bts
    // reg, imm8）不在本单面内，照旧 gate。
    bool emit_lock_bit_reg_dst(Emitter& em, const ir::Insn& in, VmOp vop) {
        const u8 sz = isa::size_field(in.size);
        em.emit(vop, OpKind::Reg, isa::vm_reg_of(in.dst.reg), OpKind::None,
                isa::vm_reg_of(in.src.reg), 0, sz);
        return true;
    }
    bool translate_lock_bit(Emitter& em, Scratch& sc, const ir::Insn& in, i64 marker,
                            u64 current_rva, u64 next_ip) {
        const VmOp vop = marker == kLockBts ? VmOp::Bts
                         : marker == kLockBtr ? VmOp::Btr
                                              : VmOp::Btc;
        // B.4：REG-REG 形（lifter 翻正面仅产 x86 + 双 Reg 形；判别形见
        // emit_lock_bit_reg_dst 注）。arch 防御：x64 REG-REG 照旧 gate。
        if (in.dst.kind == ir::Operand::Kind::Reg &&
            in.src.kind == ir::Operand::Kind::Reg) {
            if (arch_ != ir::Arch::X86)
                return skip(in, "lock bit 操作数形态未支持", nullptr);
            return emit_lock_bit_reg_dst(em, in, vop);
        }
        if (in.dst.kind != ir::Operand::Kind::Mem)
            return skip(in, "lock bit 操作数形态未支持", nullptr);
        u8 acc = 0;
        if (!emit_address(em, sc, in.dst.mem, current_rva, next_ip, sz_step_, acc))
            return skip(in, "lock bit 地址形态未支持", &in.dst.mem);
        if (in.dst.mem.base == ir::Reg::Rip) {
            em.emit_rr(VmOp::LeaRva, acc, acc, sz_step_);  // RVA→VA (in-place)
        }
        const u8 sz = isa::size_field(in.size);
        if (in.src.kind == ir::Operand::Kind::Reg) {
            em.emit(vop, OpKind::Reg, acc, OpKind::Reg, isa::vm_reg_of(in.src.reg),
                    0, sz);
        } else if (in.src.kind == ir::Operand::Kind::Imm) {
            em.emit(vop, OpKind::Reg, acc, OpKind::Imm, 0,
                    static_cast<u32>(in.src.imm), sz);
        } else {
            return skip(in, "lock bit src 操作数形态未支持", nullptr);
        }
        return true;
    }

    // mov 不接 mem 操作数（lifter 已将 mem-src 拆为 Load, mem-dst 拆为 Store），
    // 故不需要 next_ip 参数.
    bool translate_mov(Emitter& em, Scratch& sc, const ir::Insn& in) {
        // MIT-415: rep 串指令经 Op::Mov + src2=imm(family) 编码 (lifter 约定)
        // — 普通 mov 的 src2 恒空, 零碰撞。
        if (in.src2.kind == ir::Operand::Kind::Imm)
            return translate_string_op(em, sc, in);
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
            emit_imm64_split(em, sc, d, static_cast<u64>(in.src.imm), sz_step_);
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
        if (!emit_address(em, sc, in.src.mem, current_rva, next_ip, sz_step_, acc))
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
        if (!emit_address(em, sc, in.src.mem, current_rva, next_ip, sz_step_, acc))
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
        if (!emit_address(em, sc, in.dst.mem, current_rva, next_ip, sz_step_, acc))
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
            emit_imm64_split(em, sc, src_reg, static_cast<u64>(in.src.imm), sz_step_);
        }
        // rip-relative 用 StoreRva（运行时 + image_base）；非 rip 用普通 Store.
        const isa::VmOp store_op =
            (in.dst.mem.base == ir::Reg::Rip) ? isa::VmOp::StoreRva : isa::VmOp::Store;
        em.emit_rr(store_op, acc, src_reg, isa::size_field(in.size));
        return true;
    }

    // ---- 栈 ----

    // MIT-442 (X2a) B.2: 栈宽 arch 分叉 —— 412 §2 复核后认定的**真 arch 宽度
    // 点** (412 时代五处 S64 硬编码点中唯一真分叉面; 其余四处 = VM 内部槽宽
    // 常量误名, 见 emit_address 域注)。x64 push/pop 恒 8B (S64), x86 恒 4B
    // (S32) — 宽度由 IR.size 携带 (lifter data_size: 子寄存器折叠 + 宽度入
    // size), stride 从 size 派生, 无需新 arch 侧信道 (B.1 "arch 参数已在链"
    // 纪律)。S16/S8 (66 50 push r16 — x64 合法编码, 栈推进 2B 不在 VM 栈模
    // 型内) → 保守 gate (修复既有静默错形: 旧码 S16 push 也走 8B stride)。
    // rsp 槽算术恒 S64 (VM 槽宽, 与 arch 无关)。
    bool translate_push(Emitter& em, const ir::Insn& in) {
        if (in.dst.kind != ir::Operand::Kind::Reg)
            return skip(in, "push 操作数形态未支持", nullptr); // push imm：lifter 不产出
        if (in.size == ir::Size::S16 || in.size == ir::Size::S8)
            return skip(in, "push 位宽未支持 (S16/S8 栈推进不在 VM 栈模型内)", nullptr);
        // MIT-446 (X4) B.2 点位①（444 X3b 挂账落地）：x86 栈步进改单
        // VmOp::Push（X3b 已备 4B handler，a_kind 双形 Reg/Imm；此路径恒
        // Reg 形）。旧形 Sub rsp (S64 tag) 在 x86 运行时折防御 no-op 静默
        // 空转；x64 路径维持 Sub+Store 现形逐字节不动（D2 恒等铁约束）。
        if (arch_ == ir::Arch::X86) {
            em.emit(VmOp::Push, OpKind::Reg, isa::vm_reg_of(in.dst.reg),
                    OpKind::None, 0, 0, isa::size_field(in.size));
            return true;
        }
        const u8 sz64 = isa::size_field(ir::Size::S64);
        const u8 rsp = isa::vm_reg_of(ir::Reg::Rsp);
        em.emit_ri(VmOp::Sub, rsp, in.size == ir::Size::S64 ? 8u : 4u, sz64);
        em.emit_rr(VmOp::Store, rsp, isa::vm_reg_of(in.dst.reg),
                   isa::size_field(in.size));
        return true;
    }

    bool translate_pop(Emitter& em, const ir::Insn& in) {
        if (in.dst.kind != ir::Operand::Kind::Reg)
            return skip(in, "pop 操作数形态未支持", nullptr);
        if (in.size == ir::Size::S16 || in.size == ir::Size::S8)
            return skip(in, "pop 位宽未支持 (S16/S8 栈推进不在 VM 栈模型内)", nullptr);
        // MIT-446 (X4) B.2 点位①：x86 栈步进改单 VmOp::Pop（X3b 4B handler，
        // 目的 = reg_a 槽）；x64 路径维持 Load+Add 现形逐字节不动。
        if (arch_ == ir::Arch::X86) {
            em.emit(VmOp::Pop, OpKind::Reg, isa::vm_reg_of(in.dst.reg),
                    OpKind::None, 0, 0, isa::size_field(in.size));
            return true;
        }
        const u8 sz64 = isa::size_field(ir::Size::S64);
        const u8 rsp = isa::vm_reg_of(ir::Reg::Rsp);
        em.emit_rr(VmOp::Load, isa::vm_reg_of(in.dst.reg), rsp,
                   isa::size_field(in.size));
        em.emit_ri(VmOp::Add, rsp, in.size == ir::Size::S64 ? 8u : 4u, sz64);
        return true;
    }

    // ---- 控制流 ----

    bool translate_jump(Emitter& em, Scratch& sc, const ir::Insn& in) {
        if (in.op == ir::Op::Jmp &&
            (in.dst.kind == ir::Operand::Kind::Reg ||
             in.dst.kind == ir::Operand::Kind::Mem)) {
            // MIT-409: 跳转表特化挂点（REG 源）；MIT-413 (G2-b): MEM 源
            // （`jmp [tbl+idx*8]`，lifter 409 起 lift 为 Jmp(dst=Mem)，非表
            // 形态照旧 gate）。预扫描命中（含"命中但 gate"）时按处置表走；
            // 未命中维持原 gate note（保守底线零让步）。
            if (jump_tables_) {
                const auto it = jump_tables_->find(in.addr);
                if (it != jump_tables_->end()) {
                    if (it->second.ok)
                        return translate_jump_table(em, sc, in, it->second);
                    return false; // 预扫描已披露 gate note，不追加通用 note
                }
            }
            return skip(in, "间接 jmp 未支持，建议 gate", nullptr);
        }
        if (in.dst.kind != ir::Operand::Kind::Imm)
            return skip(in, "跳转目标非立即数，未支持", nullptr);
        const auto it = block_of_addr.find(static_cast<u64>(in.dst.imm));
        if (it == block_of_addr.end()) {
            // MIT-407: 越区跳转 ExitNative 候选检查。条件全部满足时 emit
            //   VmOp::ExitNative (aux = target RVA)；
            //   否则维持原 C1 gate（保守正确，行为与修复前逐字节一致）。
            //   1) target >= end_rva（确实越出本区域）
            //   2) upper_bound_fn 可用且 target < upper_bound_fn(begin_rva)
            //      （落在同一函数 .pdata 真实边界内；lifter 检出回跳时
            //       upper_bound_fn 返回 nullopt → 维持 gate）
            //   3) 间接 jmp / ret 目标不入此路（维持 gate；C 双向分段不在本单）
            //   编码：无条件 (Jmp) 用 a_kind=Imm 标记（cond 字段仅 4 位无
            //   sentinel 可用，0xFF 会在 encode 端被 validate_insn 拒绝——
            //   v1 草案缺陷）；条件 (Jcc) 用 cond_or_size = ir::Cond 0..15。
            if ((in.op == ir::Op::Jmp || in.op == ir::Op::Jcc) && upper_bound_of_) {
                const u64 target = static_cast<u64>(in.dst.imm);
                const auto upper = upper_bound_of_(begin_rva_);
                if (target >= end_rva_ && upper.has_value() && target < *upper) {
                    if (fits_aux(static_cast<i64>(target))) {
                        const bool uncond = (in.op == ir::Op::Jmp);
                        em.emit(VmOp::ExitNative,
                                uncond ? OpKind::Imm : OpKind::None, 0,
                                OpKind::None, 0, static_cast<u32>(target),
                                uncond ? 0 : static_cast<u8>(in.cond));
                        char note[128];
                        if (uncond)
                            std::snprintf(note, sizeof(note),
                                          "exit-native @ 0x%" PRIX64 " -> 0x%" PRIX64
                                          " (unconditional)",
                                          in.addr, target);
                        else
                            std::snprintf(note, sizeof(note),
                                          "exit-native @ 0x%" PRIX64 " -> 0x%" PRIX64
                                          " (cond=%u)",
                                          in.addr, target,
                                          static_cast<unsigned>(in.cond));
                        notes.emplace_back(note);
                        return true;
                    }
                }
            }
            return skip(in, "跳转目标块未找到（区域外/未 lift）", nullptr);
        }
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

    // MIT-409 + MIT-413 (G2): 跳转表比较链展开（D2 决策：零新 VmOp 零新
    // handler）。目标 i：Mov s, target_rva_i (S64) → LeaRva s,s（RVA+
    // image_base→VA）→ Cmp t,s（S64, 写 VM flags）→ Jcc eq → 块_i（pending
    // 回填）。t = jmp 目标寄存器槽（REG 源，运行时值 = 表项(+基址) + 基址
    // 常量 = 目标 VA）或物化 scratch（MEM 源：Mov s,idx; Shl s,scale;
    // Add s,base; Add s,disp; Load t,[s]；delta 系再 Add t,anchor_rva +
    // LeaRva t,t 锚定到 VA 空间——与 REG 源同一比较链）。链全覆盖 + 防御
    // 约束 idx ≤ K-1 → 链尾不可达，兜底 Halt（不静默落入下一块代码）。
    // scratch：REG 源 1（s 逐项复用）；MEM 源 2（s 地址 / t 表项，链期 s
    // 复用为比较槽），预算内。
    bool translate_jump_table(Emitter& em, Scratch& sc, const ir::Insn& in,
                              const JumpTableHandle& h) {
        // MIT-446 (X4) B.2 点位②同族（地址算术）：表项物化/锚定/比较链全部
        // 走 sz_step_（x64 S64 现形 / x86 S32 真块）。
        const u8 sz64 = sz_step_;
        u8 t = 0;
        u8 s = 0;
        if (!h.mem_source) {
            t = isa::vm_reg_of(in.dst.reg);
            s = sc.take();
        } else {
            // 物化表项：s = idx << log2(scale) + base + disp；Load t, [s]
            s = sc.take();
            t = sc.take();
            em.emit_rr(VmOp::Mov, s, isa::vm_reg_of(h.idx_reg), sz64);
            if (h.scale == 8)
                em.emit_ri(VmOp::Shl, s, 3, sz64);
            else if (h.scale == 4)
                em.emit_ri(VmOp::Shl, s, 2, sz64);
            else
                return skip(in, "跳转表 scale 非 4/8，保守 gate", nullptr);
            em.emit_rr(VmOp::Add, s, isa::vm_reg_of(h.base_reg), sz64);
            if (h.disp > 0)
                em.emit_ri(VmOp::Add, s, static_cast<u32>(h.disp), sz64);
            em.emit_rr(VmOp::Load, t, s,
                       h.width == 8 ? sz64 : isa::size_field(ir::Size::S32));
            if (h.sem != kJtSemAbsVa) {
                // delta 系锚定：t += anchor_rva（RVA 恒 < 2^32，直接 imm；
                // 防御性超宽走 split 不丢语义）→ LeaRva 补 image_base
                if (fits_aux(static_cast<i64>(h.anchor_rva))) {
                    em.emit_ri(VmOp::Add, t, static_cast<u32>(h.anchor_rva), sz64);
                } else {
                    const u8 tmp = sc.take();
                    emit_imm64_split(em, sc, tmp, h.anchor_rva, sz_step_);
                    em.emit_rr(VmOp::Add, t, tmp, sz64);
                }
                em.emit_rr(VmOp::LeaRva, t, t, sz64);
            }
        }
        for (u64 target : h.targets) {
            const auto it = block_of_addr.find(target);
            if (it == block_of_addr.end())
                return skip(in, "跳转表目标块缺失，保守 gate", nullptr); // 防御（预扫描已验）
            em.emit_ri(VmOp::Mov, s, static_cast<u32>(target), sz64);
            em.emit_rr(VmOp::LeaRva, s, s, sz64);
            em.emit_rr(VmOp::Cmp, t, s, sz64);
            em.emit(VmOp::Jcc, OpKind::None, 0, OpKind::None, 0, 0,
                    static_cast<u8>(ir::Cond::E));
            pending.push_back({code.size() + em.out.size() - 1, it->second});
        }
        em.emit(VmOp::Halt, OpKind::None, 0, OpKind::None, 0, 0, 0);
        return true;
    }

    // Call（MIT-249 call gate + MIT-445 X3c B.1 reg 值目标收口）。
    //   - 间接 call（dst = Reg，如 call rax）：MIT-445 起 emit CallGate reg
    //     形（a_kind=Reg + reg_a=目标槽，handler 从槽读绝对 VA）——442 D4
    //     停手挂账翻案落地（asmgen build_callgate reg-target 双 arch 通路，
    //     x64 step 1 分支 + x86 build_callgate_x86 同协议）。
    //   - 内存间接 call（dst = Mem，含 rip 形 IAT thunk `call [__imp_x]`）：
    //     折条 = emit_load(目标值 → fresh scratch) + CallGate reg 形。载入
    //     宽度 = in.size（lifter pointer_size(arch)=S64）；rip 形经 LoadRva
    //     （b 槽 = RVA，handler 加 image_base 读表项），非 rip 形经 Load
    //     （b 槽 = 绝对地址）——载入的槽值 = 目标函数绝对 VA，与 reg 形槽
    //     语义一致（handler 不再二次加 base）。
    //   - 直接 call（dst = Imm，Capstone 解出 E8 + disp32 或 FF /2 imm32）：
    //     in.dst.imm = 绝对目标 RVA（lifter 约定，与 Jcc/Jmp 的 dst.imm
    //     语义一致——Capstone 给的是绝对地址，jcc/jmp 直接当块起点查）。
    //     emit VmOp::CallGate（aux = target RVA, cond_or_size = arg_count）。
    //   - 直接 call 目标 RVA 越界（同 rip-relative 越界判定）→ skip 触发
    //     C1 gate（保守判定不变）。
    bool translate_call(Emitter& em, Scratch& sc, const ir::Insn& in,
                        u64 current_rva, u64 next_ip) {
        if (in.dst.kind == ir::Operand::Kind::Reg) {
            // reg 形: 槽内值 = 绝对目标 VA（VM GP 槽语义, M2 模型）。
            const u8 slot = isa::vm_reg_of(in.dst.reg);
            em.emit(VmOp::CallGate, OpKind::Reg, slot, OpKind::None, 0, 0, 0);
            return true;
        }
        if (in.dst.kind == ir::Operand::Kind::Mem) {
            // mem 形折条: 目标值装入 fresh scratch（emit_load 内部自动选
            // LoadRva/Load 双通路）→ CallGate reg 形。
            const u8 val = emit_load(em, sc, in.dst.mem, in.size, current_rva, next_ip, sz_step_);
            em.emit(VmOp::CallGate, OpKind::Reg, val, OpKind::None, 0, 0, 0);
            return true;
        }
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

    // ---- MIT-434 (G8a): BMI1/2 折条展开 (零新 VmOp, D1 (i) 变体) ----

    // andn d==s2 载体形展开: dst = ~s1 & s2 (d==s2: dst 槽持有 AND 项,
    // ~s1 需独占临时 — C4b v18..v23 scratch 先例)。probe 实测 (2026-08-31):
    // 操作数映射 op[1]=NOT 项 (reg-only) / op[2]=AND 项; flags = Op::And
    // 全集 (CF=0/OF=0/ZF,SF,PF 按结果) — 尾行 And 天然对齐, 零特判。
    //   [Mov(s0, s1); Not(s0); And(d, s0)]
    // 载体约定: lifter 仅在 d==s2 形发射本载体 (d==s1 / d 独立走纯 IR 折叠,
    // 不经 translator)。d==s1 经此路径 = And(d, ~d) = 0, 非原生语义 —
    // 生产者唯一性由 lifter 分支保证 (单测钉死)。
    bool translate_andn_carrier(Emitter& em, Scratch& sc, const ir::Insn& in) {
        if (in.dst.kind != ir::Operand::Kind::Reg ||
            in.src.kind != ir::Operand::Kind::Reg ||
            in.src2.kind != ir::Operand::Kind::Reg)
            return skip(in, "andn 载体操作数形态未支持", nullptr);
        const u8 d = isa::vm_reg_of(in.dst.reg);
        const u8 s1 = isa::vm_reg_of(in.src.reg);
        const u8 s2 = isa::vm_reg_of(in.src2.reg);
        const u8 sz = isa::size_field(in.size);
        (void)s2;  // d==s2: dst 槽即 AND 项 (载体约定, 见上)
        const u8 s0 = sc.take();
        em.emit_rr(VmOp::Mov, s0, s1, sz);
        em.emit(VmOp::Not, OpKind::Reg, s0, OpKind::None, 0, 0, sz);
        em.emit_rr(VmOp::And, d, s0, sz);
        return true;
    }

    // bzhi 展开: dst = value & ((1<<idx)-1)。
    // 边界语义 (Zen5 probe 2026-08-31, 纠正 432 §2.1 "结果 0" 预判):
    //   - idx 用 SRC2[7:0] (0x105→5); idx=0 → 结果 0; OF=0 恒;
    //   - idx≥N → **结果 = value 原值不变 + CF=1**, ZF/SF/PF 按结果。
    // 展开 (N = 32/64 按 size; s_m=mask, s_c=clamp 源, s_i=idx 低 8 位):
    //   Mov(s_m,1); Shl(s_m, Reg idx); Sub(s_m,1)     ; mask (idx<N 域内正确;
    //     Shl 的 cl 掩码 &N-1 恰好 idx=0 时保持 1 → Sub → 0 = 原生 idx=0 语义)
    //   Mov(s_c,0); Sub(s_c,1)                        ; s_c = -1 (边界 clamp 源)
    //   Movzx(s_i, Reg idx, S8→S64)                   ; idx &= 0xFF (SRC2[7:0])
    //   Cmp(s_i, N); Cmovae(s_m, s_c)                 ; idx≥N → mask = -1
    //   [Mov/Load(d, value) — d≠value 时]             ; value 装载
    //   And(d, s_m)                                   ; 结果 + F(CF=0,ZF/SF/PF 按结果)
    //   GetFlags(s_f); Cmp(s_i, N); Sbb(s_x,s_x); Not(s_x); And(s_x,2);
    //     Or(s_f,s_x); SetFlags(s_f)                  ; 边界 CF=1 补丁 (probe
    //                                                 ; raw 0x287), 其余位不动
    // flags 净效果: 尾行 And 的 F 在边界被 Or 上 CF 位 — 五位全对齐含边界。
    // scratch 预算: 3 (+mem value 时 emit_load 用 acc+tmp 2) = 5 ≤ 6。
    bool translate_bzhi_carrier(Emitter& em, Scratch& sc, const ir::Insn& in,
                                u64 current_rva, u64 next_ip) {
        if (in.dst.kind != ir::Operand::Kind::Reg ||
            in.src2.kind != ir::Operand::Kind::Reg)
            return skip(in, "bzhi 载体操作数形态未支持", nullptr);
        if (in.src.kind != ir::Operand::Kind::Reg && in.src.kind != ir::Operand::Kind::Mem)
            return skip(in, "bzhi 载体操作数形态未支持", nullptr);
        if (in.size != ir::Size::S32 && in.size != ir::Size::S64)
            return skip(in, "bzhi 位宽未支持", nullptr);
        const u8 d = isa::vm_reg_of(in.dst.reg);
        const u8 ix = isa::vm_reg_of(in.src2.reg);
        const u8 sz = isa::size_field(in.size);
        // MIT-446 (X4) B.2 点位②同族：bzhi 载体的 clamp/边界 CF 补丁段全部
        // 走 sz_step_（x64 S64 现形 / x86 S32 真块）。
        const u8 sz64 = sz_step_;
        const u32 n = (in.size == ir::Size::S32) ? 32u : 64u;

        const u8 s_m = sc.take();
        const u8 s_c = sc.take();
        const u8 s_i = sc.take();
        em.emit_ri(VmOp::Mov, s_m, 1, sz);
        em.emit_rr(VmOp::Shl, s_m, ix, sz);
        em.emit_ri(VmOp::Sub, s_m, 1, sz);
        em.emit_ri(VmOp::Mov, s_c, 0, sz64);
        em.emit_ri(VmOp::Sub, s_c, 1, sz64);
        em.emit(VmOp::Movzx, OpKind::Reg, s_i, OpKind::Reg, ix, 0, sz64);
        em.emit_ri(VmOp::Cmp, s_i, n, sz);
        const u32 cond_aux = static_cast<u32>(ir::Cond::Ae) << 28;
        em.emit(VmOp::Cmovcc, OpKind::Reg, s_m, OpKind::Reg, s_c, cond_aux, sz);

        if (in.src.kind == ir::Operand::Kind::Reg) {
            const u8 v = isa::vm_reg_of(in.src.reg);
            if (v != d)
                em.emit_rr(VmOp::Mov, d, v, sz);
        } else {
            const u8 v = emit_load(em, sc, in.src.mem, in.size, current_rva, next_ip, sz_step_);
            if (v != d)
                em.emit_rr(VmOp::Mov, d, v, sz);
        }
        em.emit_rr(VmOp::And, d, s_m, sz);

        // 边界 CF 补丁: s_m 已死 → 复用作 s_f
        em.emit(VmOp::GetFlags, OpKind::Reg, s_m, OpKind::None, 0, 0, sz64);
        em.emit_ri(VmOp::Cmp, s_i, n, sz);            // CF=1 iff idx8 < N
        em.emit_rr(VmOp::Sbb, s_c, s_c, sz64);        // s_c = -CF
        em.emit(VmOp::Not, OpKind::Reg, s_c, OpKind::None, 0, 0, sz64);  // 边界→-1
        em.emit_ri(VmOp::And, s_c, 2, sz64);          // 边界→CF 位 (bit1)
        em.emit_rr(VmOp::Or, s_m, s_c, sz64);
        em.emit(VmOp::SetFlags, OpKind::Reg, s_m, OpKind::None, 0, 0, sz64);
        return true;
    }

    // rorx/shlx/sarx/shrx flagless 展开 (D1 (i) 变体): 五位 flags 全不写
    // (probe raw 0x247 全程, count=0 同)。G3 串指令 GetFlags s0/SetFlags s0
    // 包裹先例 — 中段既有 shift handler 的全量 flags 装配 (build_shift)
    // 被包裹抹平, 净效果 = 原样保留; build_setflags 同步 flags_ 活镜像
    // (asmgen 不变量), asmgen.cpp 零改动。
    //   [GetFlags(s); VmOp(d, b=src); SetFlags(s)]
    // count 骑 src: Imm=rorx (b=Imm aux, cl 掩码 &N-1 与原生 rorx 一致) /
    // Reg=shlx 族 (b=Reg, build_shift T7 通用槽读 — B.4 cnt-in-reg 通路)。
    bool translate_flagless_shift(Emitter& em, Scratch& sc, const ir::Insn& in) {
        VmOp vop{};
        if (!vm_op_of(in.op, vop))
            return skip(in, "未支持的操作码", nullptr);
        if (in.dst.kind != ir::Operand::Kind::Reg)
            return skip(in, "flagless shift 操作数形态未支持", nullptr);
        const u8 d = isa::vm_reg_of(in.dst.reg);
        const u8 sz = isa::size_field(in.size);
        // MIT-446 (X4) B.2 点位⑤同族（flags 包裹 tag）：Get/SetFlags 无尺寸
        // 链（x86 handler 直写 dword），tag 换 sz_step_ 为一致性归一，零行为差。
        const u8 sz64 = sz_step_;
        const u8 s = sc.take();
        em.emit(VmOp::GetFlags, OpKind::Reg, s, OpKind::None, 0, 0, sz64);
        if (in.src.kind == ir::Operand::Kind::Reg) {
            em.emit_rr(vop, d, isa::vm_reg_of(in.src.reg), sz);
        } else if (in.src.kind == ir::Operand::Kind::Imm) {
            if (!fits_aux(in.src.imm))
                return skip(in, "flagless shift 计数越界", nullptr);
            em.emit_ri(vop, d, static_cast<u32>(static_cast<u64>(in.src.imm)), sz);
        } else {
            return skip(in, "flagless shift 操作数形态未支持", nullptr);
        }
        em.emit(VmOp::SetFlags, OpKind::Reg, s, OpKind::None, 0, 0, sz64);
        return true;
    }

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
            if (!emit_address(em, sc, in.dst.mem, current_rva, next_ip, sz_step_, acc))
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
            const u8 s = emit_load(em, sc, in.src.mem, in.size, current_rva, next_ip, sz_step_);
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
        emit_imm64_split(em, sc, t, static_cast<u64>(in.src.imm), sz_step_);
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
        if (!emit_address(em, sc, in.dst.mem, current_rva, next_ip, sz_step_, acc))
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
            const u8 tmp = emit_load(em, sc, in.src.mem, in.size, current_rva, next_ip, sz_step_);
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
            if (!emit_address(em, sc, in.src.mem, current_rva, next_ip, sz_step_, acc))
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
            if (!emit_address(em, sc, in.src.mem, current_rva, next_ip, sz_step_, acc))
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
            if (!emit_address(em, sc, in.src.mem, current_rva, next_ip, sz_step_, acc))
                return skip(in, "movsx 地址形态未支持", &in.src.mem);
            em.emit(VmOp::MovsxMem, OpKind::Reg, d, OpKind::Reg, acc, src_size_aux, sz);
            return true;
        }
        return skip(in, "movsx 操作数形态未支持", nullptr);
    }

    // ---- MIT-442 (X2a) ⑥: cbw (66 98) 载体微程序 ----
    //
    // 语义 (SDM CBW): AX←SX(AL), 位 15:63 保持。64 位槽模型下 VmOp::Movsx
    // 恒 qword 写回 (build_movsx 直读: word/byte 源符号扩展进完整物理寄存器
    // → qword 落槽), 直折会把高 48 位污染成符号扩展 — 需 stash+合并补偿。
    // IR 层无 scratch 寄存器 (GP 全是 guest 态), 补偿必须在 VmOp 层用
    // scratch 槽 (v18..v23) 完成:
    //   [GetFlags s_f          (And/Shr/Shl/Or 全写 VM flags, 434 G8a 先例包裹)
    //    Mov s0←rax S64        (stash 原 64 位槽)
    //    Movsx rax←rax aux=0   (byte 源 → 槽 = sx64(al))
    //    Shr s0,16; Shl s0,16  (s0 = 原值 & ~0xFFFF — 无 imm64 拆条)
    //    And rax,0xFFFF        (rax = zext16(sx16(al)), 高位清零)
    //    Or rax,s0             (合并: (原值&~0xFFFF) | zext16(sx16(al)))
    //    SetFlags s_f]         (8 VmOp, 全既有 op; 原生 cbw 不写 flags → 包裹)
    // 低频面膨胀披露 (对齐 434 bzhi 16-17 op 先例口径)。
    bool translate_cbw_carrier(Emitter& em, Scratch& sc, const ir::Insn& in) {
        if (in.dst.kind != ir::Operand::Kind::Reg || in.src.kind != ir::Operand::Kind::Reg)
            return skip(in, "cbw 载体操作数形态未支持", nullptr);
        const u8 rax = isa::vm_reg_of(ir::Reg::Rax);
        // MIT-446 (X4) B.2 点位②同族：cbw 载体 stash/合并补偿段走 sz_step_
        // （x64 S64 现形——高 48 位保持语义不变；x86 S32——32 位槽内位
        // 31:16 保持 = 66 98 native EAX 语义，"槽高半字恒 0" 不变量相容）。
        const u8 sz64 = sz_step_;
        const u8 s_f = sc.take();
        const u8 s0 = sc.take();
        em.emit(VmOp::GetFlags, OpKind::Reg, s_f, OpKind::None, 0, 0, sz64);
        em.emit_rr(VmOp::Mov, s0, rax, sz64);
        em.emit(VmOp::Movsx, OpKind::Reg, rax, OpKind::Reg, rax, 0, sz64);  // aux=0 → byte 源
        em.emit_ri(VmOp::Shr, s0, 16, sz64);
        em.emit_ri(VmOp::Shl, s0, 16, sz64);
        em.emit_ri(VmOp::And, rax, 0xFFFF, sz64);
        em.emit_rr(VmOp::Or, rax, s0, sz64);
        em.emit(VmOp::SetFlags, OpKind::Reg, s_f, OpKind::None, 0, 0, sz64);
        return true;
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

    // ---- MIT-371: SSE 浮点加 addss/addps/addpd (+ MIT-408: addsd) ----
    //
    // lifter 用 IR.dst.reg / IR.src.reg 借用 ir::Reg 值 0..7 (Rax..Rdi),
    // 翻译期加 24 偏移映射到 VmContext.regs[24..31] 保留槽位 (vm_op.hpp
    // 注释 v24..v31 保留, 这里用作 xmm0..xmm7 VM 槽). 翻译器只负责 emit
    // 字节码, 真正 xmm 物理寄存器寻址在 handler (asmgen.cpp) 用 movups +
    // native addss/addps/addpd 完成.
    //
    // MIT-408 (C4b) MEM 源形式: `addss/addsd xmm, [mem]` → emit_address
    // (+ LeaRva 若 rip) → XmmLoad 把 [VA] 按宽度 (aux=4/8/16) 读进 **GP
    // scratch 双槽** (v18..v23 两两, 16B 覆盖 vN+vN+1, 指令边界后即死,
    // 不与 xmm 槽互踩) → ALU(xmm_dst_slot, gp_pair)。ALU handler 的 src
    // 读取 (load_src_slot_into_xmm1) 按 reg<24 走 GP 双槽寻址。
    // (Addss,S64) = addsd (ir::Op 冻结不可增枚举, (op,size) 组合旧 lifter
    // 从不产生, 无歧义)。
    //
    // 编码: a_kind=Reg reg_a=xmm_slot, b_kind=Reg reg_b=xmm_slot (REG-REG)
    //   或 gp_pair (MEM 源), aux=0 (REG-REG) / 4|8|16 (MEM 源, XmmLoad 宽度),
    //       cond_or_size=ir::Size。
    bool translate_sse_add(Emitter& em, Scratch& sc, const ir::Insn& in,
                           u64 current_rva, u64 next_ip) {
        if (in.op != ir::Op::Addss && in.op != ir::Op::Addps && in.op != ir::Op::Addpd)
            return false;
        if (in.dst.kind != ir::Operand::Kind::Reg)
            return skip(in, "SSE 浮点加 操作数形态未支持", nullptr);
        VmOp vop = (in.op == ir::Op::Addss) ?
                       (in.size == ir::Size::S32 ? VmOp::Addss : VmOp::Addsd) :
                   (in.op == ir::Op::Addps) ? VmOp::Addps : VmOp::Addpd;
        const u8 xmm_dst_slot = static_cast<u8>(in.dst.reg) + 24u;
        if (in.src.kind == ir::Operand::Kind::Mem) {
            // MEM 源: XmmLoad(临时双槽) + ALU(xmm_dst, 临时双槽)。
            // scratch 预算: emit_address ≤4 + 临时双槽 1 = ≤5, 在 6 预算内。
            u8 acc = 0;
            if (!emit_sse_mem_addr(em, sc, in.src.mem, current_rva, next_ip, acc))
                return skip(in, "SSE 浮点加 地址形态未支持", &in.src.mem);
            const u8 pair = sc.take();  // 占用 pair 与 pair+1 (16B GP 双槽)
            em.emit(VmOp::XmmLoad, OpKind::Reg, pair, OpKind::Reg, acc,
                    sse_mem_width(in.op, in.size), isa::size_field(ir::Size::S64));
            em.emit_rr(vop, xmm_dst_slot, pair, isa::size_field(in.size));
            return true;
        }
        if (in.src.kind != ir::Operand::Kind::Reg)
            return skip(in, "SSE 浮点加 操作数形态未支持", nullptr);
        const u8 xmm_src_slot = static_cast<u8>(in.src.reg) + 24u;
        em.emit_rr(vop, xmm_dst_slot, xmm_src_slot, isa::size_field(in.size));
        return true;
    }

    // ---- MIT-373: SSE 浮点减 subss/subps/subpd (+ MIT-408: subsd) ----
    //
    // 与 MIT-371 translate_sse_add 完全同构: lifter 用 IR.dst.reg / IR.src.reg
    // 借用 ir::Reg 值 0..7 (Rax..Rdi), 翻译期加 24 偏移映射到
    // VmContext.regs[24..31] 保留槽位 (这里用作 xmm0..xmm7 VM 槽). 翻译器只
    // emit 字节码, 真正 xmm 物理寄存器寻址在 handler (asmgen.cpp) 用 movups +
    // native subss/subps/subpd 完成. MEM 源折条同 translate_sse_add (MIT-408):
    // XmmLoad(临时双槽) + ALU(xmm_dst, 临时双槽)。(Subss,S64) = subsd。
    //
    // 编码: a_kind=Reg reg_a=xmm_slot, b_kind=Reg reg_b=xmm_slot (REG-REG)
    //   或 gp_pair (MEM 源), aux=0 / 4|8|16 (XmmLoad 宽度), cond_or_size=size。
    bool translate_sse_sub(Emitter& em, Scratch& sc, const ir::Insn& in,
                           u64 current_rva, u64 next_ip) {
        if (in.op != ir::Op::Subss && in.op != ir::Op::Subps && in.op != ir::Op::Subpd)
            return false;
        if (in.dst.kind != ir::Operand::Kind::Reg)
            return skip(in, "SSE 浮点减 操作数形态未支持", nullptr);
        VmOp vop = (in.op == ir::Op::Subss) ?
                       (in.size == ir::Size::S32 ? VmOp::Subss : VmOp::Subsd) :
                   (in.op == ir::Op::Subps) ? VmOp::Subps : VmOp::Subpd;
        const u8 xmm_dst_slot = static_cast<u8>(in.dst.reg) + 24u;
        if (in.src.kind == ir::Operand::Kind::Mem) {
            u8 acc = 0;
            if (!emit_sse_mem_addr(em, sc, in.src.mem, current_rva, next_ip, acc))
                return skip(in, "SSE 浮点减 地址形态未支持", &in.src.mem);
            const u8 pair = sc.take();
            em.emit(VmOp::XmmLoad, OpKind::Reg, pair, OpKind::Reg, acc,
                    sse_mem_width(in.op, in.size), isa::size_field(ir::Size::S64));
            em.emit_rr(vop, xmm_dst_slot, pair, isa::size_field(in.size));
            return true;
        }
        if (in.src.kind != ir::Operand::Kind::Reg)
            return skip(in, "SSE 浮点减 操作数形态未支持", nullptr);
        const u8 xmm_src_slot = static_cast<u8>(in.src.reg) + 24u;
        em.emit_rr(vop, xmm_dst_slot, xmm_src_slot, isa::size_field(in.size));
        return true;
    }

    // ---- MIT-374: SSE 浮点除 divss/divps/divpd (+ MIT-408: divsd) ----
    //
    // 与 MIT-373 translate_sse_sub 完全同构: lifter 用 IR.dst.reg / IR.src.reg
    // 借用 ir::Reg 值 0..7 (Rax..Rdi), 翻译期加 24 偏移映射到
    // VmContext.regs[24..31] 保留槽位 (这里用作 xmm0..xmm7 VM 槽). 翻译器只
    // emit 字节码, 真正 xmm 物理寄存器寻址在 handler (asmgen.cpp) 用 movups +
    // native divss/divps/divpd 完成. MEM 源折条同 translate_sse_add (MIT-408):
    // XmmLoad(临时双槽) + ALU(xmm_dst, 临时双槽)。(Divss,S64) = divsd。
    //
    // 编码: a_kind=Reg reg_a=xmm_slot, b_kind=Reg reg_b=xmm_slot (REG-REG)
    //   或 gp_pair (MEM 源), aux=0 / 4|8|16 (XmmLoad 宽度), cond_or_size=size。
    bool translate_sse_div(Emitter& em, Scratch& sc, const ir::Insn& in,
                           u64 current_rva, u64 next_ip) {
        if (in.op != ir::Op::Divss && in.op != ir::Op::Divps && in.op != ir::Op::Divpd)
            return false;
        if (in.dst.kind != ir::Operand::Kind::Reg)
            return skip(in, "SSE 浮点除 操作数形态未支持", nullptr);
        VmOp vop = (in.op == ir::Op::Divss) ?
                       (in.size == ir::Size::S32 ? VmOp::Divss : VmOp::Divsd) :
                   (in.op == ir::Op::Divps) ? VmOp::Divps : VmOp::Divpd;
        const u8 xmm_dst_slot = static_cast<u8>(in.dst.reg) + 24u;
        if (in.src.kind == ir::Operand::Kind::Mem) {
            u8 acc = 0;
            if (!emit_sse_mem_addr(em, sc, in.src.mem, current_rva, next_ip, acc))
                return skip(in, "SSE 浮点除 地址形态未支持", &in.src.mem);
            const u8 pair = sc.take();
            em.emit(VmOp::XmmLoad, OpKind::Reg, pair, OpKind::Reg, acc,
                    sse_mem_width(in.op, in.size), isa::size_field(ir::Size::S64));
            em.emit_rr(vop, xmm_dst_slot, pair, isa::size_field(in.size));
            return true;
        }
        if (in.src.kind != ir::Operand::Kind::Reg)
            return skip(in, "SSE 浮点除 操作数形态未支持", nullptr);
        const u8 xmm_src_slot = static_cast<u8>(in.src.reg) + 24u;
        em.emit_rr(vop, xmm_dst_slot, xmm_src_slot, isa::size_field(in.size));
        return true;
    }

    // ---- MIT-375: SSE 浮点传送 movss/movaps/movapd/movups/movupd
    //      (+ MIT-408: movsd 经 (Movss,S64) 编码, load/store 双向) ----
    //
    // 与 MIT-371 translate_sse_add / MIT-373 translate_sse_sub 同构: lifter 用
    // IR.dst.reg / IR.src.reg 借用 ir::Reg 值 0..7 代表 xmm0..7, 翻译期加 24
    // 偏移映射到 VmContext.regs[24..31] 保留槽位; 真正 xmm 物理寄存器搬运在
    // handler (vm/regvm/runtime/src/asmgen.cpp) 用 movss/movups 读写
    // VmContext.xmm[8] @ +0x140 完成.
    //
    // MIT-408 (C4b) MEM 形式 (派活单 §A.3 读/写两类必做):
    //   - load 方向 (dst=Reg, src=Mem):  emit_address (+ LeaRva 若 rip) →
    //     XmmLoad(dst_xmm_slot, addr, width) — 无需临时槽, dst 即落点;
    //     movss/movsd 内存源的清零语义由 XmmLoad handler 的 native
    //     movss/movsd 直产 (SDM: 内存源清零高位)。
    //   - store 方向 (dst=Mem, src=Reg):  emit_address (+ LeaRva 若 rip) →
    //     XmmStore(addr, src_xmm_slot, width)。
    //   - (Movss,S64) = movsd: REG-REG 走 VmOp::Movsd (F2 0F 10, 8B 搬,
    //     高位保持); MEM 宽度 8B。
    //
    // 防御: lifter 只产 0..7; 手写 IR / passthrough 路径兜底 >7 报错。
    bool translate_sse_mov(Emitter& em, Scratch& sc, const ir::Insn& in,
                           u64 current_rva, u64 next_ip) {
        if (in.op != ir::Op::Movss && in.op != ir::Op::Movaps && in.op != ir::Op::Movapd &&
            in.op != ir::Op::Movups && in.op != ir::Op::Movupd)
            return false;
        const u8 sz = isa::size_field(in.size);
        if (in.dst.kind == ir::Operand::Kind::Mem) {
            // store 方向: [mem], xmm — src 必为 xmm REG.
            if (in.src.kind != ir::Operand::Kind::Reg)
                return skip(in, "SSE 浮点传送 操作数形态未支持", nullptr);  // 双 mem 非法
            u8 acc = 0;
            if (!emit_sse_mem_addr(em, sc, in.dst.mem, current_rva, next_ip, acc))
                return skip(in, "SSE 浮点传送 地址形态未支持", &in.dst.mem);
            const u8 xmm_idx_src = static_cast<u8>(in.src.reg);
            if (xmm_idx_src > 7u)
                return skip(in, "SSE 浮点传送 xmm 索引越界 (仅支持 xmm0..xmm7)", nullptr);
            em.emit(VmOp::XmmStore, OpKind::Reg, acc, OpKind::Reg, xmm_idx_src + 24u,
                    sse_mem_width(in.op, in.size), sz);
            return true;
        }
        if (in.dst.kind != ir::Operand::Kind::Reg)
            return skip(in, "SSE 浮点传送 操作数形态未支持", nullptr);
        const u8 xmm_idx_dst = static_cast<u8>(in.dst.reg);
        if (xmm_idx_dst > 7u)
            return skip(in, "SSE 浮点传送 xmm 索引越界 (仅支持 xmm0..xmm7)", nullptr);
        if (in.src.kind == ir::Operand::Kind::Mem) {
            // load 方向: xmm, [mem] — XmmLoad(dst_slot, addr, width).
            u8 acc = 0;
            if (!emit_sse_mem_addr(em, sc, in.src.mem, current_rva, next_ip, acc))
                return skip(in, "SSE 浮点传送 地址形态未支持", &in.src.mem);
            em.emit(VmOp::XmmLoad, OpKind::Reg, xmm_idx_dst + 24u, OpKind::Reg, acc,
                    sse_mem_width(in.op, in.size), sz);
            return true;
        }
        if (in.src.kind != ir::Operand::Kind::Reg)
            return skip(in, "SSE 浮点传送 操作数形态未支持", nullptr);
        const u8 xmm_idx_src = static_cast<u8>(in.src.reg);
        if (xmm_idx_src > 7u)
            return skip(in, "SSE 浮点传送 xmm 索引越界 (仅支持 xmm0..xmm7)", nullptr);
        VmOp vop = (in.op == ir::Op::Movss) ?
                       (in.size == ir::Size::S32 ? VmOp::Movss : VmOp::Movsd) :
                   (in.op == ir::Op::Movaps) ? VmOp::Movaps :
                   (in.op == ir::Op::Movapd) ? VmOp::Movapd :
                   (in.op == ir::Op::Movups) ? VmOp::Movups : VmOp::Movupd;
        em.emit_rr(vop, xmm_idx_dst + 24u, xmm_idx_src + 24u, sz);
        return true;
    }

    // ---- MIT-376: SSE 浮点位运算 xorps/orps/andps (+ MIT-408: MEM 源) ----
    //
    // 与 MIT-375 translate_sse_mov 同构: lifter 用 IR.dst.reg / IR.src.reg
    // 借用 ir::Reg 值 0..7 代表 xmm0..7, 翻译期加 24 偏移映射到
    // VmContext.regs[24..31] 保留槽位; 真正 128-bit 按位运算在 handler
    // (asmgen.cpp build_xorps/orps/andps) 沿用 build_xmm_transfer 四步模板
    // (读 dst 槽 → 读 src 槽 → native xorps/orps/andps → 写回 dst 槽)。
    // MEM 源折条同 translate_sse_add (MIT-408): XmmLoad(临时双槽) + 位运算。
    //
    // 编码: a_kind=Reg reg_a=xmm_slot, b_kind=Reg reg_b=xmm_slot (REG-REG)
    //   或 gp_pair (MEM 源), aux=0 / 16 (XmmLoad 宽度, 全 128-bit 按位),
    //       cond_or_size=ir::Size::S64。
    bool translate_sse_bitwise(Emitter& em, Scratch& sc, const ir::Insn& in,
                               u64 current_rva, u64 next_ip) {
        if (in.op != ir::Op::Xorps && in.op != ir::Op::Orps && in.op != ir::Op::Andps)
            return false;
        if (in.dst.kind != ir::Operand::Kind::Reg)
            return skip(in, "SSE 浮点位运算 操作数形态未支持", nullptr);
        const u8 xmm_idx_dst = static_cast<u8>(in.dst.reg);
        if (xmm_idx_dst > 7u)
            return skip(in, "SSE 浮点位运算 xmm 索引越界 (仅支持 xmm0..xmm7)", nullptr);
        const u8 xmm_dst_slot = static_cast<u8>(xmm_idx_dst + 24u);
        // MIT-425 (G1b): andnps/andnpd/pandn — lifter 以 (Op::Andps,
        // src2=imm(kSseAndn=18)) 载体标记折叠到 VmOp::Andnps (dst=~dst&src,
        // 逐位同语义; op 必须限定 Andps, 见标记域碰撞对账)。
        VmOp vop = (in.op == ir::Op::Xorps) ? VmOp::Xorps :
                   (in.op == ir::Op::Orps)  ? VmOp::Orps  :
                   (in.src2.kind == ir::Operand::Kind::Imm &&
                    is_andn_marker(in.src2.imm)) ? VmOp::Andnps : VmOp::Andps;
        if (in.src.kind == ir::Operand::Kind::Mem) {
            u8 acc = 0;
            if (!emit_sse_mem_addr(em, sc, in.src.mem, current_rva, next_ip, acc))
                return skip(in, "SSE 浮点位运算 地址形态未支持", &in.src.mem);
            const u8 pair = sc.take();
            em.emit(VmOp::XmmLoad, OpKind::Reg, pair, OpKind::Reg, acc,
                    sse_mem_width(in.op, in.size), isa::size_field(ir::Size::S64));
            em.emit_rr(vop, xmm_dst_slot, pair, isa::size_field(in.size));
            return true;
        }
        if (in.src.kind != ir::Operand::Kind::Reg)
            return skip(in, "SSE 浮点位运算 操作数形态未支持", nullptr);
        const u8 xmm_idx_src = static_cast<u8>(in.src.reg);
        if (xmm_idx_src > 7u)
            return skip(in, "SSE 浮点位运算 xmm 索引越界 (仅支持 xmm0..xmm7)", nullptr);
        const u8 xmm_src_slot = static_cast<u8>(xmm_idx_src + 24u);
        em.emit_rr(vop, xmm_dst_slot, xmm_src_slot, isa::size_field(in.size));
        return true;
    }

    // ---- MIT-376: SSE 浮点比较 ucomiss/ucomisd (+ MIT-408: MEM 源) ----
    //
    // 与 translate_sse_bitwise 同构, 关键差异: ucomis* **只写 EFLAGS (ZF/PF/CF),
    // 不改 xmm 操作数**。handler (asmgen.cpp build_ucomiss/build_ucomisd) 走
    // ALU binop 同一条 flags 通路 (zero5 → native ucomis* → setcc5 →
    // flags_tail), 与 setcc/jcc handler 共享同一 flags_ 寄存器 (ctx+0x98,
    // 位布局 ZF/CF/OF/SF/PF=bit0..4) — 区域内紧随的 setcc/jcc 读到真比较
    // 结果 (派活单 §C 6 + §D D1.1, 禁止 decode+advance 空转, pitfall #79)。
    // MEM 源折条同 translate_sse_add (MIT-408, 派活单 D4 "ucomis src=mem 必做"):
    // XmmLoad(临时双槽) + Ucomis*(dst, 临时双槽)。
    //
    // 编码: a_kind=Reg reg_a=xmm_slot, b_kind=Reg reg_b=xmm_slot (REG-REG)
    //   或 gp_pair (MEM 源), aux=0 / 4|8 (XmmLoad 宽度), cond_or_size=size。
    bool translate_ucomis(Emitter& em, Scratch& sc, const ir::Insn& in,
                          u64 current_rva, u64 next_ip) {
        if (in.op != ir::Op::Ucomiss && in.op != ir::Op::Ucomisd)
            return false;
        if (in.dst.kind != ir::Operand::Kind::Reg)
            return skip(in, "SSE 浮点比较 操作数形态未支持", nullptr);
        const u8 xmm_idx_dst = static_cast<u8>(in.dst.reg);
        if (xmm_idx_dst > 7u)
            return skip(in, "SSE 浮点比较 xmm 索引越界 (仅支持 xmm0..xmm7)", nullptr);
        const u8 xmm_dst_slot = static_cast<u8>(xmm_idx_dst + 24u);
        VmOp vop = (in.op == ir::Op::Ucomiss) ? VmOp::Ucomiss : VmOp::Ucomisd;
        if (in.src.kind == ir::Operand::Kind::Mem) {
            u8 acc = 0;
            if (!emit_sse_mem_addr(em, sc, in.src.mem, current_rva, next_ip, acc))
                return skip(in, "SSE 浮点比较 地址形态未支持", &in.src.mem);
            const u8 pair = sc.take();
            em.emit(VmOp::XmmLoad, OpKind::Reg, pair, OpKind::Reg, acc,
                    sse_mem_width(in.op, in.size), isa::size_field(ir::Size::S64));
            em.emit_rr(vop, xmm_dst_slot, pair, isa::size_field(in.size));
            return true;
        }
        if (in.src.kind != ir::Operand::Kind::Reg)
            return skip(in, "SSE 浮点比较 操作数形态未支持", nullptr);
        const u8 xmm_idx_src = static_cast<u8>(in.src.reg);
        if (xmm_idx_src > 7u)
            return skip(in, "SSE 浮点比较 xmm 索引越界 (仅支持 xmm0..xmm7)", nullptr);
        const u8 xmm_src_slot = static_cast<u8>(xmm_idx_src + 24u);
        em.emit_rr(vop, xmm_dst_slot, xmm_src_slot, isa::size_field(in.size));
        return true;
    }

    // ---- MIT-425 (G1b): SSE 浮点乘 mulss/mulsd/mulps/mulpd ----
    //
    // 与 MIT-371 translate_sse_add 完全同构: lifter 用 IR.dst.reg /
    // IR.src.reg 借用 ir::Reg 值 0..7 代表 xmm0..7 (加 24 偏移 → ctx.xmm
    // 槽), MEM 源折条 XmmLoad(临时双槽) + mul(dst, 双槽)。IR 编码 =
    // (Op::Mul, src2=imm(kSseMulSs..kSseMulPd, 14..17)) 载体标记 (ir::Op
    // 冻结不可增枚举; GP Op::Mul 占用 (Mul,S32/S64) 使 (Op,Size) 双语义
    // 装不下 4 形态 — 选型披露见 translator.cpp 标记域注释)。
    // VmOp 选定后 mem 宽度由标记本地导出 (ss=4 / sd=8 / ps,pd=16), 不经
    // sse_mem_width (其 default 分支对未知 op 恒回 16, 对 ss/sd 会错)。
    //
    // 编码: a_kind=Reg reg_a=xmm_slot, b_kind=Reg reg_b=xmm_slot (REG-REG)
    //   或 gp_pair (MEM 源), aux=0 / 4|8|16 (XmmLoad 宽度), cond_or_size=size。
    bool translate_sse_mul(Emitter& em, Scratch& sc, const ir::Insn& in,
                           u64 current_rva, u64 next_ip) {
        if (in.op != ir::Op::Mul ||
            in.src2.kind != ir::Operand::Kind::Imm ||
            !is_sse_mul_marker(in.src2.imm))
            return false;
        if (in.dst.kind != ir::Operand::Kind::Reg)
            return skip(in, "SSE 浮点乘 操作数形态未支持", nullptr);
        const u8 xmm_dst_slot = static_cast<u8>(in.dst.reg) + 24u;
        VmOp vop = VmOp::Mulss;
        u32 mem_width = 4;
        switch (static_cast<int>(in.src2.imm)) {
        case kSseMulSs: vop = VmOp::Mulss; mem_width = 4;  break;
        case kSseMulSd: vop = VmOp::Mulsd; mem_width = 8;  break;
        case kSseMulPs: vop = VmOp::Mulps; mem_width = 16; break;
        case kSseMulPd: vop = VmOp::Mulpd; mem_width = 16; break;
        default: return skip(in, "SSE 浮点乘 标记非法，建议 gate", nullptr);
        }
        if (in.src.kind == ir::Operand::Kind::Mem) {
            // MEM 源: XmmLoad(临时双槽) + mul(xmm_dst, 临时双槽)。
            // scratch 预算: emit_address ≤4 + 临时双槽 1 = ≤5, 在 6 预算内。
            u8 acc = 0;
            if (!emit_sse_mem_addr(em, sc, in.src.mem, current_rva, next_ip, acc))
                return skip(in, "SSE 浮点乘 地址形态未支持", &in.src.mem);
            const u8 pair = sc.take();  // 占用 pair 与 pair+1 (16B GP 双槽)
            em.emit(VmOp::XmmLoad, OpKind::Reg, pair, OpKind::Reg, acc,
                    mem_width, isa::size_field(ir::Size::S64));
            em.emit_rr(vop, xmm_dst_slot, pair, isa::size_field(in.size));
            return true;
        }
        if (in.src.kind != ir::Operand::Kind::Reg)
            return skip(in, "SSE 浮点乘 操作数形态未支持", nullptr);
        const u8 xmm_src_slot = static_cast<u8>(in.src.reg) + 24u;
        em.emit_rr(vop, xmm_dst_slot, xmm_src_slot, isa::size_field(in.size));
        return true;
    }

    // ---- MIT-427 (G1c): movd/movq GP↔xmm 桥 (kBridgeFromGp/ToGp/FromXmm) ----
    //
    // lifter 载体 (Op::Movss, src2=imm 19..21, 见 is_bridge_marker 注释):
    //   kBridgeFromGp (19): (Movss,S32/S64, dst=xmm 借用, src=GP 真寄存器)
    //     → VmOp::XmmFromGp (reg_a=dst+24, reg_b=src 槽号, aux=宽度 4|8)
    //   kBridgeFromXmm (21): (Movss,S64, dst/src=xmm 借用) → VmOp::XmmFromGp
    //     (reg_a=dst+24, reg_b=src+24, aux=8 — handler xmm 源路径, 高 64 清零)
    //   kBridgeToGp (20): (Movss,S32/S64, dst=GP 真寄存器, src=xmm 借用)
    //     → VmOp::GpFromXmm (reg_a=dst 槽号, reg_b=src+24, aux=宽度)
    // 高位清零/截断语义全部在 handler (asmgen build_xmm_from_gp /
    // build_gp_from_xmm) 经 native movd/movq/movsd mem 形式直产 — 翻译器
    // 零拆条, 单条字节码 (派活单 §F.2 GP 双槽中转折法不取, 字节码零膨胀)。
    // mem 操作数形态不经本函数 — lifter 直接产 (Op::Movss, mem) 既有载体,
    // 由 translate_sse_mov 的 XmmLoad/XmmStore 通路处理 (408)。
    bool translate_sse_bridge(Emitter& em, Scratch& sc, const ir::Insn& in,
                              u64 current_rva, u64 next_ip) {
        if (in.op != ir::Op::Movss || in.src2.kind != ir::Operand::Kind::Imm ||
            !is_bridge_marker(in.src2.imm))
            return false;
        (void)sc;
        (void)current_rva;
        (void)next_ip;
        const i64 marker = in.src2.imm;
        if (in.size != ir::Size::S32 && in.size != ir::Size::S64)
            return skip(in, "movd/movq 桥 宽度非法", nullptr);
        const u32 width = in.size == ir::Size::S32 ? 4u : 8u;
        if (marker == kBridgeFromGp) {
            // GP→xmm: dst=xmm 借用 (0..7, +24), src=GP 真寄存器 (0..15 槽号)。
            if (in.dst.kind != ir::Operand::Kind::Reg || in.src.kind != ir::Operand::Kind::Reg)
                return skip(in, "movd/movq 桥 操作数形态未支持", nullptr);
            const u8 xmm_idx = static_cast<u8>(in.dst.reg);
            const u8 gp_slot = static_cast<u8>(in.src.reg);
            if (xmm_idx > 7u)
                return skip(in, "movd/movq 桥 xmm 索引越界 (仅支持 xmm0..xmm7)", nullptr);
            if (gp_slot > 15u)
                return skip(in, "movd/movq 桥 GP 槽号越界", nullptr);
            em.emit(VmOp::XmmFromGp, OpKind::Reg, static_cast<u8>(xmm_idx + 24u),
                    OpKind::Reg, gp_slot, width, isa::size_field(in.size));
            return true;
        }
        if (marker == kBridgeFromXmm) {
            // xmm→xmm 清零拷贝 (F3 0F 7E): dst/src 均借用 0..7, 固有 64 位。
            if (in.dst.kind != ir::Operand::Kind::Reg || in.src.kind != ir::Operand::Kind::Reg)
                return skip(in, "movd/movq 桥 操作数形态未支持", nullptr);
            const u8 xmm_dst = static_cast<u8>(in.dst.reg);
            const u8 xmm_src = static_cast<u8>(in.src.reg);
            if (xmm_dst > 7u || xmm_src > 7u)
                return skip(in, "movd/movq 桥 xmm 索引越界 (仅支持 xmm0..xmm7)", nullptr);
            em.emit(VmOp::XmmFromGp, OpKind::Reg, static_cast<u8>(xmm_dst + 24u),
                    OpKind::Reg, static_cast<u8>(xmm_src + 24u), 8u,
                    isa::size_field(in.size));
            return true;
        }
        // kBridgeToGp: xmm→GP: dst=GP 真寄存器 (0..15 槽号), src=xmm 借用 (+24)。
        if (in.dst.kind != ir::Operand::Kind::Reg || in.src.kind != ir::Operand::Kind::Reg)
            return skip(in, "movd/movq 桥 操作数形态未支持", nullptr);
        const u8 gp_slot = static_cast<u8>(in.dst.reg);
        const u8 xmm_idx = static_cast<u8>(in.src.reg);
        if (gp_slot > 15u)
            return skip(in, "movd/movq 桥 GP 槽号越界", nullptr);
        if (xmm_idx > 7u)
            return skip(in, "movd/movq 桥 xmm 索引越界 (仅支持 xmm0..xmm7)", nullptr);
        em.emit(VmOp::GpFromXmm, OpKind::Reg, gp_slot,
                OpKind::Reg, static_cast<u8>(xmm_idx + 24u), width,
                isa::size_field(in.size));
        return true;
    }

    // ---- MIT-404: cdq/cqo (隐式 rax→rdx 符号扩展) ----
    //
    // lifter 把 cdq (99) 与 cqo (48 99) 共用为 Op::Cdq, size 区分 S32/S64。
    // 零显式操作数 (全隐式): emit 单条 VmOp::Cdq, a/b/aux 全空,
    // cond_or_size=size。handler (asmgen build_cdq) 读 Rax 槽 → native
    // cdq/cqo 直通 → 写 Rdx 槽; 不影响 EFLAGS (零 flags 写回)。
    bool translate_cdq(Emitter& em, const ir::Insn& in) {
        if (in.op != ir::Op::Cdq) return false;
        em.emit(VmOp::Cdq, OpKind::None, 0, OpKind::None, 0, 0,
                isa::size_field(in.size));
        return true;
    }

    // ---- MIT-404: div/idiv (整数除法族) ----
    //
    // 隐式 dividend = rdx:rax (S32: edx:eax) 不经字节码表达 — handler 内部
    // 从 Rax/Rdx 双槽拼装 (对齐 build_mul 双结果槽协议)。emit 单条
    // VmOp::Div/Idiv:
    //   a_kind=Reg reg_a=Rdx 槽 tag (对齐 Mul, handler 不消费),
    //   b_kind=Reg reg_b=除数槽, aux=0, cond_or_size=size (S32/S64)。
    // 除数两种来源 (lifter 区分):
    //   - REG: 直接 emit (reg_b = 除数槽)。
    //   - MEM: emit_load 折条 (emit_address 算 acc + Load tmp), rip 形式
    //     除数在 emit_load 内自动走 LoadRva 通路 — 派活单 §B.4 的 LoadRva
    //     搭车覆盖。scratch 预算: emit_load 用 2, 在 6 预算内。
    // flags 按 Intel undefined, handler 照抄 build_imul 处置 (zero5 → native
    // → setcc5 → flags_tail); 除零/商溢出 = 真 #DE native 直通 (D2.1)。
    bool translate_div_idiv(Emitter& em, Scratch& sc, const ir::Insn& in,
                            u64 current_rva, u64 next_ip) {
        if (in.op != ir::Op::Div && in.op != ir::Op::Idiv) return false;
        if (in.dst.kind != ir::Operand::Kind::Reg)
            return skip(in, "div/idiv 操作数形态未支持", nullptr);
        const u8 sz = isa::size_field(in.size);
        const VmOp vop = (in.op == ir::Op::Div) ? VmOp::Div : VmOp::Idiv;
        u8 b = 0;
        if (in.src.kind == ir::Operand::Kind::Reg) {
            b = isa::vm_reg_of(in.src.reg);
        } else if (in.src.kind == ir::Operand::Kind::Mem) {
            b = emit_load(em, sc, in.src.mem, in.size, current_rva, next_ip, sz_step_);
        } else {
            return skip(in, "div/idiv 除数形态未支持", nullptr);
        }
        em.emit(vop, OpKind::Reg, isa::vm_reg_of(in.dst.reg), OpKind::Reg, b,
                0, sz);
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

    // ---- MIT-334 + MIT-419 (G4): xchg (寄存器/内存交换) ----
    //
    // xchg 是 2 操作数对称操作 (Intel SDM: xchg a, b == xchg b, a),
    // IR.dst/src 顺序不影响语义, 翻译器按 IR 直产 a=dst, b=src.
    //   - REG-REG: emit VmOp::Xchg 一条 (a=dst, b=src, aux=0,
    //     cond_or_size=size; S32/S64 由 REX.W 决定, lifter 已传过来).
    //   - MEM-REG (MIT-419 放开): xchg [m], r — InterlockedExchange 的 MSVC
    //     真产物是裸 `xchg [m], r` (87 /r 无 F0, xchg 访存隐式锁; probe
    //     实证 2026-08-30), lock xchg [m], r 同享本通路 (lifter 剥 F0 + src2
    //     标记发 lock-strip note)。拆条 (xchg 对称, 拆条语义等价):
    //       emit_address → acc; Load tmp, [acc]; Xchg(tmp, s); Store [acc], tmp
    //       语义: tmp=旧[m]; Xchg(tmp,s) → tmp=旧s, s=旧[m]; Store → [m]=旧s ✓
    //       scratch 预算 = emit_address(1) + tmp(1) = 2, 在 6 预算内。
    //     rip-relative 目标 (lock cmpxchg [rip+disp] 同族形态) 经
    //     LoadRva/StoreRva 通道。
    //
    // handler 在 asmgen.cpp 的 build_xchg: 按 cond_or_size 分 S32/S64 emit
    // native xchg eax,ebx (S32) 或 xchg rax,rbx (S64). S32 路径用 dword
    // 读写 (上 32 位 slot 保留), S64 路径用 qword 读写 (full 64 互换).
    //
    // 不更新 flags (xchg 不影响 CF/OF/SF/ZF/PF).
    bool translate_xchg(Emitter& em, Scratch& sc, const ir::Insn& in,
                        u64 current_rva, u64 next_ip) {
        if (in.op != ir::Op::Xchg) return false;
        // src 必为寄存器 (xchg r/m, r 第二操作数必是 r)
        if (in.src.kind != ir::Operand::Kind::Reg) return false;
        const u8 s = isa::vm_reg_of(in.src.reg);
        const u8 sz = isa::size_field(in.size);

        if (in.dst.kind == ir::Operand::Kind::Reg) {
            const u8 d = isa::vm_reg_of(in.dst.reg);
            em.emit_rr(VmOp::Xchg, d, s, sz);
            return true;
        }
        if (in.dst.kind != ir::Operand::Kind::Mem)
            return skip(in, "xchg 操作数形态未支持", nullptr);
        // MEM: xchg [m], r — Load tmp + Xchg(tmp, s) + Store 三条拆条。
        u8 acc = 0;
        if (!emit_address(em, sc, in.dst.mem, current_rva, next_ip, sz_step_, acc))
            return skip(in, "xchg 地址形态未支持", &in.dst.mem);
        const u8 tmp = sc.take();
        const isa::VmOp load_op =
            (in.dst.mem.base == ir::Reg::Rip) ? isa::VmOp::LoadRva : isa::VmOp::Load;
        em.emit_rr(load_op, tmp, acc, sz);  // Load tmp, [acc]
        em.emit_rr(VmOp::Xchg, tmp, s, sz); // Xchg(tmp, s): tmp=旧s, s=旧[m]
        const isa::VmOp store_op =
            (in.dst.mem.base == ir::Reg::Rip) ? isa::VmOp::StoreRva : isa::VmOp::Store;
        em.emit_rr(store_op, acc, tmp, sz); // Store [acc], tmp → [m] = 旧s
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
        if (!emit_address(em, sc, in.dst.mem, current_rva, next_ip, sz_step_, acc))
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
        if (!emit_address(em, sc, in.src.mem, current_rva, next_ip, sz_step_, acc))
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
        if (!emit_address(em, sc, in.dst.mem, current_rva, next_ip, sz_step_, acc))
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

// ============================================================================
// MIT-451 (X5b) B.2：翻译期栈深 walk（D1 路线 (i) 兜底层，双 arch 共享，D4）。
//
// 背景（X5 B.2 缺陷实录 → 442 规则升级为产品正确性边界）：真实 codegen 在
// 区域内发 push（mul64hi 的 call-arg push 形）时，guest push 从 ns（区域进
// 入时刻 esp = v4 初值）下探真实写内存；x86 stub 的 callee-saved 保存区
// [ns-4..ns-0x10] 与 ctx 区正位于此——写穿 → VM 退出还原垃圾 → 确定性 AV。
// X5b 起硬件侧由 entry guard 垫栈吸收（runtime_x86.hpp kX86GuardBytes，
// x64 无 guard）；本 walk = 逻辑侧守门：净栈深（字节）超 guard 预算的函数
// 整函数 C1 gate 保原生（note 通道既有机制，零新协议面）。
//
// 预算（bytes，guest 可下探深度上限）：
//   x86 = kX86GuardBytes（guard 区实际容量）；x64 = 0（无 guard，任何区内
//   push/sub rsp 即 gate——x64 prologue 常态 sub rsp/mov [rsp+8] 不命中，
//   X5 实测 wvmpTest x64 0 gate，本 walk 是手写/第三方 x64 形态的盲区预防）。
//
// 规则（线性地址序 over-approximation，宁窄勿宽，D5）：
//   1) 净深 d（有符号字节，v4 相对 ns 的偏移）：Push += stride(size)
//      （S64=8/S16=2/其余=4）、Pop -=；Op::Sub/Add dst=Rsp src=Imm → ±imm；
//      d > budget 任一点 → gate。
//   2) rsp 静态改写面：Mov/Lea dst=Rsp —— 源 = Rsp 自身/别名跟踪寄存器
//      （leave 链经 lifter 折条为 Mov Rsp<-Rbp + Pop Rbp，X2a ⑥）可跟踪；
//      其余（绝对改写 / 未知值源）→ gate（保守）。
//   3) 负位移 reach：Load/Store/Lea/ALU-mem/lock 载体的 mem 操作数
//      base=Rsp 或 base=别名寄存器（值 = v4+off，mov ebp,esp / lea 系标准
//      帧指针形态）且 disp<0 时，最深字节 = d - off + |disp| + 访存宽 >
//      budget → gate（guard 区是唯一安全区）。base 值未知（未跟踪寄存器）
//      的负位移不检查——静态不可判定，如实披露（预判 §F.2 折打面）。
//   4) 回边增长：Jcc/Jmp（Imm 目标在区内）目标地址 < 指令地址（回边/环）
//      且 d_branch > d_target → 无界增长 → gate；d_branch <= d_target 有界
//      （逐次不增）放行。前向边不查（线性 carry 已是任何路径的 over-approx）。
//   5) 出口平衡：ExitNative 候选（Imm 目标越区）与 Halt（末块 fallthrough
//      可达终态）点要求 d == 0——出口物理 esp = ns（stub 尾声 add esp,kCtxSize
//      + 4 pop + add esp,G 后终态 jmp；Ret 出口例外，物理 esp := v4' 自配
//      平），延续代码对 esp 敏感（/O2 esp 帧 [esp±X]）时 d!=0 即静默错。
//      mul64hi（call-arg push、清栈在区外延迟执行）由此保持 gate——行为
//      保真，esp-resync 前瞻（静态验证延续代码 mov esp,ebp 重同步）留档
//      GAPS X5b 节后续单。
//   6) 跳转表命中（Jmp Reg/Mem 预扫描 ok）：targets 逐个按 4) 检查；未命中
//      间接 jmp 不在此 gate（translate_jump 既有 note 兜底，避免双 note）。
//   7) Ret 不检查（出口自配平）；Call 不改 d（callgate 参数桥读 [v4+4i]，
//      窗在 v4 上方，callee 用独立窗口）。
//
// 别名跟踪（小规模、保守）：reg → 相对 v4 的偏移。建立 = Mov reg<-Rsp(=0) /
// Lea reg<-[Rsp+disp](=disp) / Mov reg<-别名(=off) / Add·Sub 别名 ±imm；
// 失效 = 其余任何写（Pop/Load/ALU 非跟踪源/Imul/移位族/一元族）与 Call 的
// caller-saved 清空（x86 eax/ecx/edx，x64 另含 r8-r11；callee-saved 跨
// callgate 存活 = ABI 事实，帧指针惯用面恰在其上）。
// ============================================================================

struct StackWalkVerdict {
    bool ok = true;
    // 首个违例描述（gate note 正文；含点位 RVA 与数值，不匹配 backend 过滤
    // 白名单前缀 —— 本 note 必须触发 C1 gate）。
    std::string violation;
};

[[nodiscard]] StackWalkVerdict walk_region_stack_depth(
    const ir::FunctionRegion& fn, i64 budget,
    const std::unordered_map<u64, JumpTableHandle>& jump_tables) {
    StackWalkVerdict v;
    const auto fail = [&](u64 addr, std::string_view what) {
        if (!v.ok) return;
        v.ok = false;
        char buf[160];
        std::snprintf(buf, sizeof(buf), "stack-depth-gate @ 0x%" PRIX64 ": %.*s",
                      addr, static_cast<int>(what.size()), what.data());
        v.violation = buf;
    };
    const auto stride_of = [](ir::Size sz) -> i64 {
        switch (sz) {
        case ir::Size::S64: return 8;
        case ir::Size::S16: return 2;
        case ir::Size::S8: return 1;
        default: return 4;
        }
    };
    const auto mem_width = [&](ir::Size sz) -> i64 {
        return stride_of(sz);  // 同宽表（S64=8/S16=2/S8=1/其余=4）
    };
    // caller-saved 别名失效集（ir::Reg 域）。
    const auto is_caller_saved = [&](ir::Reg r) {
        switch (r) {
        case ir::Reg::Rax: case ir::Reg::Rcx: case ir::Reg::Rdx:
            return true;
        case ir::Reg::R8: case ir::Reg::R9: case ir::Reg::R10:
        case ir::Reg::R11:
            return fn.arch == ir::Arch::X64;  // x86 无 r8+
        default:
            return false;
        }
    };

    i64 d = 0;                                  // 净深（字节，v4 相对 ns）
    i64 max_d = 0;
    std::unordered_map<ir::Reg, i64> alias;     // 寄存器 → 相对 v4 偏移
    std::unordered_map<u64, i64> d_at;          // 指令地址 → walk 时刻 d
    d_at.reserve(fn.blocks.size() * 8);

    const auto check_reach = [&](u64 addr, const ir::MemOperand& m, i64 width) {
        if (m.disp >= 0) return;
        // 地址 = v4 + off + disp（base=Rsp 时 off=0）；其相对 ns 的深度 =
        // d - off - disp，加访存宽 = 最深字节触碰面。
        i64 off = 0;
        if (m.base == ir::Reg::Rsp) {
            off = 0;
        } else if (m.base != ir::Reg::Rip) {
            const auto it = alias.find(m.base);
            if (it == alias.end()) return;  // 值未知基：披露面，不 gate（规则 3）
            off = it->second;
        } else {
            return;  // rip 无栈语义
        }
        const i64 reach = d - off - m.disp + width;
        if (reach > budget)
            fail(addr, "栈写下探超 guard 预算 (负位移 reach)");
    };

    for (const ir::BasicBlock& b : fn.blocks) {
        for (const ir::Insn& in : b.insns) {
            d_at[in.addr] = d;
            // --- 净深推进（规则 1/2）---
            // S16/S8 push/pop 不在本 walk 建模内（translate_push/pop 对该
            // 位宽既有 gate note 兜底——442 裁决"栈推进 2B 不在 VM 栈模型
            // 内"，walk 只建模翻译器真实发射的栈效应，避免双 note 噪声）。
            const bool stack_modeled =
                in.size == ir::Size::S32 || in.size == ir::Size::S64;
            if (in.op == ir::Op::Push && stack_modeled) {
                d += stride_of(in.size);
                max_d = std::max(max_d, d);
                if (d > budget) fail(in.addr, "区域内 push 净深超 guard 预算");
            } else if (in.op == ir::Op::Pop && stack_modeled) {
                d -= stride_of(in.size);
                if (in.dst.kind == ir::Operand::Kind::Reg)
                    alias.erase(in.dst.reg);
            } else if ((in.op == ir::Op::Sub || in.op == ir::Op::Add) &&
                       in.dst.kind == ir::Operand::Kind::Reg &&
                       in.dst.reg == ir::Reg::Rsp &&
                       in.src.kind == ir::Operand::Kind::Imm) {
                d += in.op == ir::Op::Sub ? in.src.imm : -in.src.imm;
                max_d = std::max(max_d, d);
                if (d > budget) fail(in.addr, "区域内 sub esp 净深超 guard 预算");
            } else if (in.dst.kind == ir::Operand::Kind::Reg &&
                       in.dst.reg == ir::Reg::Rsp &&
                       (in.op == ir::Op::Mov || in.op == ir::Op::Lea)) {
                // rsp 静态改写面（规则 2）。源 = 别名跟踪寄存器（leave 链
                // `mov esp,ebp` 形）可精确跟踪；未跟踪寄存器源按"良构帧
                // 指针 >= esp"假定处理（ebp = 帧基在 esp 上方，esp:=ebp 只
                // 上移 → 深度不增；违例形态 = 帧指针在栈顶之下，编译器不
                // 产——披露面 GAPS X5b 节）：d 保守维持原值（此后 reach/预算
                // 检查按更深的原 d 判，安全方向）。绝对不可跟踪形（立即数/
                // 计算地址）→ gate。
                bool tracked = false;
                if (in.op == ir::Op::Mov && in.src.kind == ir::Operand::Kind::Reg) {
                    if (in.src.reg == ir::Reg::Rsp) {
                        tracked = true;  // 自身搬移，no-op
                    } else {
                        const auto it = alias.find(in.src.reg);
                        if (it != alias.end()) {
                            d -= it->second;
                            tracked = true;
                        } else {
                            tracked = true;  // 帧上移假定：d 保守不变
                        }
                    }
                } else if (in.op == ir::Op::Lea &&
                           in.src.kind == ir::Operand::Kind::Mem &&
                           in.src.mem.base == ir::Reg::Rsp &&
                           in.src.mem.index == ir::Reg::Flags) {
                    d -= in.src.mem.disp;
                    tracked = true;
                }
                if (!tracked) fail(in.addr, "rsp 非静态可跟踪改写");
                max_d = std::max(max_d, d);
            }
            // --- 别名维护 ---
            if (in.dst.kind == ir::Operand::Kind::Reg &&
                in.dst.reg != ir::Reg::Rsp) {
                const ir::Reg rd = in.dst.reg;
                bool defined = false;
                if (in.op == ir::Op::Mov) {
                    if (in.src.kind == ir::Operand::Kind::Reg &&
                        in.src.reg == ir::Reg::Rsp) {
                        alias[rd] = 0; defined = true;
                    } else if (in.src.kind == ir::Operand::Kind::Reg) {
                        const auto it = alias.find(in.src.reg);
                        if (it != alias.end()) { alias[rd] = it->second; defined = true; }
                    }
                } else if (in.op == ir::Op::Lea &&
                           in.src.kind == ir::Operand::Kind::Mem) {
                    if (in.src.mem.base == ir::Reg::Rsp &&
                        in.src.mem.index == ir::Reg::Flags) {
                        alias[rd] = in.src.mem.disp; defined = true;
                    } else if (in.src.mem.index == ir::Reg::Flags) {
                        const auto it = alias.find(in.src.mem.base);
                        if (it != alias.end()) {
                            alias[rd] = it->second + in.src.mem.disp; defined = true;
                        }
                    }
                } else if ((in.op == ir::Op::Add || in.op == ir::Op::Sub) &&
                           in.src.kind == ir::Operand::Kind::Imm) {
                    const auto it = alias.find(rd);
                    if (it != alias.end()) {
                        // off = 值 − v4；值 ±imm 而 v4 不动 → off 同向跟随。
                        it->second += in.op == ir::Op::Add ? in.src.imm : -in.src.imm;
                        defined = true;
                    }
                }
                if (!defined) alias.erase(rd);
            }
            if (in.op == ir::Op::Call) {
                for (int r = 0; r < 32; ++r)
                    if (is_caller_saved(static_cast<ir::Reg>(r))) alias.erase(static_cast<ir::Reg>(r));
            }
            // --- 负位移 reach（规则 3）---
            const i64 width = mem_width(in.size);
            if (in.dst.kind == ir::Operand::Kind::Mem)
                check_reach(in.addr, in.dst.mem, width);
            if (in.src.kind == ir::Operand::Kind::Mem)
                check_reach(in.addr, in.src.mem, width);
            // --- 控制流检查（规则 4/5/6）---
            if (in.op == ir::Op::Jcc || in.op == ir::Op::Jmp) {
                if (in.dst.kind == ir::Operand::Kind::Imm) {
                    const u64 target = static_cast<u64>(in.dst.imm);
                    const bool in_region =
                        target >= fn.begin_rva && target < fn.end_rva;
                    if (!in_region) {
                        if (d != 0)
                            fail(in.addr, "ExitNative 出口栈不平衡 (d != 0)");
                    } else {
                        // lifter 不变量：区内分支目标必为已提升指令地址
                        // （块切分即分支目标）；d_at miss 仅见于合成 IR
                        // （测试 helper 固定 addr）——跳过不 gate。
                        const auto it = d_at.find(target);
                        if (it != d_at.end() && target < in.addr &&
                            d > it->second) {
                            fail(in.addr, "回边栈净深无界增长");
                        }
                    }
                } else if (in.op == ir::Op::Jmp) {
                    const auto h = jump_tables.find(in.addr);
                    if (h != jump_tables.end() && h->second.ok) {
                        for (const u64 target : h->second.targets) {
                            const auto it = d_at.find(target);
                            if (it != d_at.end() && target < in.addr &&
                                d > it->second) {
                                fail(in.addr, "跳表回边栈净深无界增长");
                            }
                        }
                    }
                    // 未命中表形态 → translate_jump 既有 gate note 兜底
                }
            }
            if (!v.ok) return v;  // 首违例即收（note 一次，门为函数粒度）
        }
    }
    // --- 终态平衡（规则 5）：末块 fallthrough 可达 Halt 时 d 必须为 0 ---
    if (!fn.blocks.empty()) {
        const ir::BasicBlock& last = fn.blocks.back();
        const bool falls_through =
            last.insns.empty() ||
            (last.insns.back().op != ir::Op::Jmp &&
             last.insns.back().op != ir::Op::Ret);
        if (falls_through && d != 0)
            fail(fn.end_rva, "Halt 出口栈不平衡 (d != 0，区外延迟清栈形态)");
    }
    (void)max_d;
    return v;
}

} // namespace

TranslateResult translate_function(const ir::FunctionRegion& fn) {
    // 无 .pdata 上界 → 维持原行为。FunctionUpperBoundFn 默认构造为 nullptr
    // 调用，等价于"无上界"，translate_jump 走原 C1 gate 路径。
    return translate_function(fn, FunctionUpperBoundFn{}, JumpTableReadFn{});
}

TranslateResult translate_function(const ir::FunctionRegion& fn,
                                 FunctionUpperBoundFn upper_bound_fn) {
    // 无跳转表读取函数 → 不启用跳转表特化（与双参数版行为一致）。
    return translate_function(fn, std::move(upper_bound_fn), JumpTableReadFn{});
}

TranslateResult translate_function(const ir::FunctionRegion& fn,
                                 FunctionUpperBoundFn upper_bound_fn,
                                 JumpTableReadFn table_read_fn) {
    // 无 image_base（调用方未提供）→ 绝对 VA 表项语义候选跳过（G2-a 的
    // AbsoluteVa 需要翻译期减 image_base 还原目标 RVA），其余照常。
    return translate_function(fn, std::move(upper_bound_fn),
                              std::move(table_read_fn), 0);
}

TranslateResult translate_function(const ir::FunctionRegion& fn,
                                 FunctionUpperBoundFn upper_bound_fn,
                                 JumpTableReadFn table_read_fn,
                                 u64 image_base) {
    TranslateResult result;

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
            // MIT-426 (G6a): VEX 三地址折叠的前置 Movaps 与主 insn 共享同一
            // 机器地址 (lifter 透传 pre_insns)。用 insert_or_assign 让**主
            // insn** (后出现者) 的 next 覆盖前置条的 A→A 占位 — rip-relative
            // 位移解析 (emit_address) 用的 next_ip = 原指令结束地址, 与
            // legacy 语义逐位一致。unique-addr 场景与 emplace 行为完全相同
            // (既有通路零变化)。
            next_ip_of.insert_or_assign(cur, nxt);
        }
    }

    // MIT-409 + MIT-413 (G2): 跳转表特化预扫描。对每个以 Jmp(Reg/Mem) 结尾
    // 的块跑模板匹配 + 表验证（读表经调用方提供的 JumpTableReadFn）；命中
    // 且验证通过 → 记 jump-table diag note（上层过滤，不触发 gate）+ 收集
    // 块切分点；命中但验证失败 → 披露 note（触发 gate）；模板不符 → 维持
    // 原 translate_jump 的通用 skip note。切分点在本地块副本上生效——
    // fn.blocks 是冻结只读契约不可原地改；切分后 block_of_addr 重建（链
    // 跳转目标由此进入块表，Jcc/Jmp rel 同款反查 + block_start 回填零新
    // 机制）。
    std::unordered_map<u64, JumpTableHandle> jump_tables;
    std::set<u64> split_addrs;
    if (table_read_fn) {
        std::unordered_set<u64> insn_addrs;
        insn_addrs.reserve(fn.blocks.size() * 8);
        for (const ir::BasicBlock& b : fn.blocks)
            for (const ir::Insn& in : b.insns) insn_addrs.insert(in.addr);
        for (size_t bi = 1; bi < fn.blocks.size(); ++bi) {
            const ir::BasicBlock& cur = fn.blocks[bi];
            const ir::BasicBlock& prev = fn.blocks[bi - 1];
            if (cur.insns.empty()) continue;
            const ir::Insn& last = cur.insns.back();
            if (last.op != ir::Op::Jmp ||
                (last.dst.kind != ir::Operand::Kind::Reg &&
                 last.dst.kind != ir::Operand::Kind::Mem))
                continue;
            auto h = try_match_jump_table(cur, prev, next_ip_of, insn_addrs,
                                          fn.begin_rva, fn.end_rva, table_read_fn,
                                          image_base, fn.arch);
            if (!h) continue; // 非跳转表形态 → 维持原 gate note
            if (h->ok) {
                char note[192];
                std::snprintf(note, sizeof(note),
                              "jump-table @ 0x%" PRIX64 " entries=%zu %s",
                              h->table_rva, h->targets.size(),
                              jt_form_tag(*h).c_str());
                result.notes.emplace_back(note);
                for (u64 tgt : h->targets) split_addrs.insert(tgt);
            } else {
                result.notes.emplace_back(std::move(h->gate_note));
            }
            jump_tables.emplace(last.addr, std::move(*h));
        }
    }

    // 本地块副本：按预扫描切分点切块（无命中时不切，行为与主 bbc93e6 全等）。
    // MIT-451 (X5b) B.2：栈深 walk（D1 (i) 兜底层，双 arch，D4）。跳表预扫描
    // 之后、翻译之前——违例即 gate note（整函数保原生，virtualize 既有 note
    // 通道消费），翻译照常完成（note 触发上层放弃，字节码仅诊断可见）。
    // 预算 = x86 kX86GuardBytes（guard 区实际容量，runtime_x86.hpp 单一来源）
    // / x64 0（无 guard，任何区内栈下探即 gate）。
    {
        const i64 budget =
            fn.arch == ir::Arch::X86
                ? static_cast<i64>(wvmp::regvm::runtime::kX86GuardBytes)
                : 0;
        StackWalkVerdict walk =
            walk_region_stack_depth(fn, budget, jump_tables);
        if (!walk.ok) result.notes.emplace_back(std::move(walk.violation));
    }
    std::vector<ir::BasicBlock> blocks = split_blocks(fn.blocks, split_addrs);

    // 地址 -> 块下标（块按向量顺序即布局顺序排放）。预扫描切分后重建。
    std::unordered_map<u64, size_t> block_of_addr;
    for (size_t i = 0; i < blocks.size(); ++i)
        block_of_addr.emplace(blocks[i].addr, i);

    std::vector<VmInsn> code;
    std::vector<PendingJump> pending;
    std::vector<size_t> block_start(blocks.size());
    Translator tr{code, pending, block_of_addr, result.notes, &next_ip_of};
    // MIT-446 (X4) B.2：步进/地址算术尺寸 tag 按 fn.arch 派生（x64 = S64
    // 现形逐字节不动 = D2 恒等铁约束；x86 = S32，五点位 + 同族残段不再折
    // x86 运行时 3 路尺寸链的防御 no-op）。
    tr.arch_ = fn.arch;
    tr.sz_step_ =
        isa::size_field(fn.arch == ir::Arch::X86 ? ir::Size::S32 : ir::Size::S64);
    // MIT-407: 把上界查询与区域端点写入 Translator, translate_jump 据此判定
    // 是否 emit ExitNative。upper_bound_fn 为空时 upper_bound_of_ 留空,
    // translate_jump 走原 gate 路径（与单参数版完全一致）。
    if (upper_bound_fn) {
        tr.upper_bound_of_ = std::move(upper_bound_fn);
        tr.begin_rva_ = fn.begin_rva;
        tr.end_rva_ = fn.end_rva;
    }
    // MIT-409: 跳转表处置表（可为空——未命中时 translate_jump 维持原 gate）。
    tr.jump_tables_ = &jump_tables;
    const u8 sz64 = isa::size_field(ir::Size::S64);

    for (size_t bi = 0; bi < blocks.size(); ++bi) {
        const ir::BasicBlock& b = blocks[bi];
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
