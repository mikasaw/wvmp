#pragma once
#include "vm_op.hpp"
#include "vm_reg.hpp"
#include "wvmp/common/types.hpp"
#include "wvmp/ir/insn.hpp"

#include <cstdint>
#include <vector>

namespace wvmp::regvm::isa {

enum class OpKind : u8 {
    None = 0,
    Reg = 1,
    Imm = 2,
    // 3 保留：编码中出现即非法
};

struct VmInsn {
    VmOp op = VmOp::Nop;
    OpKind a_kind = OpKind::None;
    OpKind b_kind = OpKind::None;
    // 4 位字段的双重语义（位图见下）：Jcc 存 ir::Cond 条件码（0..15）；
    // 其余所有操作存 ir::Size 操作数宽度（0..3），携带 sub-register 语义。
    u8 cond_or_size = 0;
    u8 reg_a = 0;     // 5 位 VM 寄存器号（kInvalidReg 表示未用）
    u8 reg_b = 0;
    u32 aux = 0;      // 立即数 / 相对偏移；>32 位立即数由翻译器拆条合成
};

// cond_or_size 字段的读写辅助。
[[nodiscard]] constexpr u8 size_field(ir::Size s) {
    return static_cast<u8>(s);  // ir::Size 枚举值 0..3
}
[[nodiscard]] constexpr ir::Size field_size(u8 f) {
    return static_cast<ir::Size>(f & 3);
}

// ---------------------------------------------------------------------------
// MIT-474 (T18) flags 活跃性消除：cond_or_size 位 2（值 4）= flags-dead 标
// 记。语义：该指令对 VM flags（[ctx+0x98] 五位组）的写入已被翻译期跨块
// liveness 证明在"下一个 flags 写入之前无任何读者"——运行时 handler 可整
// 段跳过 flags 捕获/装配（zero5/setcc5/flags_tail，x64 ~21 条动态指令）。
// size 语义 = f & 3（field_size 既有掩码，零改动兼容）；位 2 仅算术类使
// 用（Jcc 的 cond 域 0..15 全量占用，不参与标记）。
//
// ⚠️ 运行时契约（asmgen flags_tail / flags_tail_partial / flags_tail_x86 /
// flags_tail_partial_x86 四处 tail 均 honor）：标记 = 跳过整个 tail，VM
// flags 状态保持前值。正确性由翻译期 liveness 保证（见
// translator.cpp mark_dead_flag_writes）：标记允许"欠实现"（忽略标记 =
// 旧行为 = 仍正确），禁止"过实现"（非写 flags op 携带标记 = 未定义）。
inline constexpr u8 kFlagsDeadBit = 0x4;
[[nodiscard]] constexpr bool flags_dead_field(u8 f) {
    return (f & kFlagsDeadBit) != 0;
}
[[nodiscard]] constexpr u8 set_flags_dead(u8 f) {
    return static_cast<u8>(f | kFlagsDeadBit);
}

// flags 语义分类（单一来源：translator liveness 与 asmgen/文档共用）。
//   - kWrite：全量重算五位（handler 内 zero5(+setcc5)+flags_tail 重装），
//     不读旧状态 → 可标记（tail 可跳）。
//   - kWriteReadMerge：写新值但**合并旧状态位**（rol/ror 保 ZF/SF/PF、
//     inc/dec 保旧 CF）——旧位只流入 flags 输出（目的寄存器值与 flags 无
//     关）→ liveness 透传（live_in = live_out：前驱可观察性经合并延续）；
//     自身写可标记（结果无读者时 tail 跳过 = 状态保持前值，与合并等价）。
//   - kWriteReadReg：写 flags 且**读旧位进目的寄存器值**（adc/sbb 的
//     CF_in 流入 dst = a + b + CF_in——寄存器消费无条件可观察）→ 输入侧
//     恒为读者（live_in = 1，前驱写永不标记）；自身 flags 写仍可标记
//    （tail 跳过不影响块体的寄存器计算）。MIT-474 验收 B1 裁决。
//   - kRead：只读（Jcc/Setcc/Cmovcc/GetFlags 全量读；ExitNative 条件形式
//     经 cond_eval 读，无条件直退形保守同判）。
//   - kNone：与 VM flags 无交互。SetFlags 直写 flags 槽、不经 tail（无捕
//     获装配面），标记无消费点 → 归 kNone（永不标记、不杀、透传），后人
//     勿改。
enum class FlagSem { kNone, kRead, kWrite, kWriteReadMerge, kWriteReadReg };
[[nodiscard]] constexpr FlagSem flag_sem_of(VmOp op) {
    switch (op) {
        case VmOp::Jcc: case VmOp::Setcc: case VmOp::Cmovcc:
        case VmOp::GetFlags:
        case VmOp::ExitNative:
            return FlagSem::kRead;
        case VmOp::Adc: case VmOp::Sbb:                 // CF_in 流入 dst 寄存器值
            return FlagSem::kWriteReadReg;
        case VmOp::Rol: case VmOp::Ror:                 // 保 ZF/SF/PF（只进 flags）
        case VmOp::RolCl: case VmOp::RorCl:
        case VmOp::Inc: case VmOp::Dec:                 // 保旧 CF（只进 flags）
            return FlagSem::kWriteReadMerge;
        case VmOp::Add: case VmOp::Sub: case VmOp::And: case VmOp::Or:
        case VmOp::Xor: case VmOp::Neg: case VmOp::Cmp: case VmOp::Test:
        case VmOp::Shl: case VmOp::Shr: case VmOp::Sar:
        case VmOp::ShlCl: case VmOp::ShrCl: case VmOp::SarCl:
        case VmOp::Imul: case VmOp::Mul: case VmOp::Cmpxchg: case VmOp::Xadd:
        case VmOp::Bts: case VmOp::Btr: case VmOp::Btc:
        case VmOp::Ucomiss: case VmOp::Ucomisd:
        case VmOp::Div: case VmOp::Idiv:
            return FlagSem::kWrite;
        default:
            return FlagSem::kNone;
    }
}

// 8 字节定长编码：单条指令即一个 LE u64，64 位恰好用尽、无保留位。
//
//   bits 63..32   aux    (32)
//   bits 31..27   reg_b  (5)
//   bits 26..22   reg_a  (5)
//   bits 21..18   cond   (4)
//   bits 17..16   b_kind (2)
//   bits 15..14   a_kind (2)
//   bits 13..0    opcode (14)
[[nodiscard]] u64 encode(const VmInsn& insn);

// 任意 u64 解码；字段值非法（opcode=0/超界、kind=3、cond>15、reg>31）抛
// std::runtime_error。合法编码的 decode(encode(x)) == x 逐字段成立。
[[nodiscard]] VmInsn decode(u64 word);

[[nodiscard]] VmInsn make_insn(VmOp op, OpKind a_kind, u8 reg_a,
                               OpKind b_kind, u8 reg_b,
                               u32 aux = 0, u8 cond_or_size = 0);

// 指令流便捷操作：按 LE 追加 / 逐条读取。
void append_insn(std::vector<u8>& stream, const VmInsn& insn);

} // namespace wvmp::regvm::isa
