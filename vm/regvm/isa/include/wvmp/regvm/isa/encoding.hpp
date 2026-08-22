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
