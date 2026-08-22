#pragma once
#include "wvmp/ir/region.hpp"
#include "wvmp/vm/backend.hpp"

#include <string>
#include <vector>

namespace wvmp::regvm::translator {

// 翻译结果：
//   program.bytecode = ByteWriter 序列化后的 regvm blob（32 字节头 + 8xN 指令流），
//   program.entry_offset = 0（入口即指令流首条，见 blob 头 entry_offset 字段）。
//   notes = 未覆盖指令等提示（上层转 diag；非空不视为失败，由 gate 决定回退）。
struct TranslateResult {
    vm::VmProgram program;
    std::vector<std::string> notes;
};

// 纯函数：把一个函数区域的 IR 逐指令翻译为 regvm 字节码。
//   - 无跨指令分析、无状态残留；同输入同输出。
//   - 遇到 v1 未支持的形态（call / rip-relative / 间接 jmp / 目标块缺失等）
//     不抛异常：跳过该指令并写入 notes，交由上层 gate 回退。
//
// ============================ 翻译约定（与 runtime/isa 对齐） ============================
//
// 寄存器映射：ir::Reg -> isa::vm_reg_of()（号位恒等）。子寄存器语义由
// cond_or_size 携带的 ir::Size 在 handler 层经 alias_read/alias_write 应用，
// 翻译器只负责正确填 Size。
//
// cond_or_size 双重语义（见 isa/encoding.hpp）：Jcc 存 ir::Cond（0..15）；
// 其余所有操作存 isa::size_field(size) 的 ir::Size。合成指令（地址计算、
// 立即数拼装、栈调整、fallthrough 跳转、Halt）按下列规则填：
//   - 地址计算 / imm64 拼装 / push-pop 栈调整 / fallthrough Jmp：恒 S64；
//   - 数据操作（Load/Store/ALU）：原 IR 指令的 size；
//   - Halt：a/b 均 None、aux=0、cond_or_size=0。
//
// 立即数（b_kind=Imm）约定：aux 为 u32 **零扩展**语义（handler 不符号扩展）。
// 因此 ir 中不能通过 u32 零扩展往返的 64 位立即数（含负数，如 -1/-8）必须拆条
// （见下）；S32/S8/S16 操作数下直接截断填 aux，模 2^bits 运算结果不变，
// 目的写回经 alias 折叠后语义正确。
//
// imm64 拆条（mov rax, 0x1122334455667788 这类 size==S64 且超出 u32 零扩展
// 表示能力的立即数）：
//   Mov dst 场景（恰好 4 条，全部 S64）：
//     Mov  s, imm_hi32   ; s = 高 32 位（零扩展入 s）
//     Shl  s, 32         ; s = imm_hi32 << 32
//     Mov  d, imm_lo32   ; d = 低 32 位（零扩展入 d）
//     Or   d, s          ; d = 完整 64 位立即数
//   其余 ALU/Cmp/Test 场景：先用同样 4 条在 scratch 中拼出立即数，再以
//   b_kind=Reg 发原操作（共 5 条）。
//
// 移位类（Shl/Shr/Sar）的 src 语义：b_kind=Imm 时 aux 为移位计数；
// b_kind=Reg 时为计数寄存器（handler 取其低 6 位并按 x86 掩码规则）。
//
// Load / Store 的操作数方向（固定）：
//   Load  : a = Reg(目的数据寄存器)，b = Reg(地址 scratch)。语义
//           dst = [addr]，按 cond_or_size 的 Size 访存，写回经 alias 折叠。
//   Store : a = Reg(地址)，b = Reg(源数据寄存器)。语义 [addr] = src。
//
// 内存操作数展开（Load/Store 及 ALU 带 mem，lifter 约定 op 保留、mem 原样）：
// 地址计算进 scratch（isa::kScratchFirst 起轮转，每条 IR 指令局部重置）：
//   Mov acc, base -> (有 index 时) Mov ix, index + Shl ix, log2(scale) +
//   Add acc, ix -> (disp!=0 时) Add/Sub acc, |disp|。
//   注：disp<0 时发 Sub acc, (u32)(-disp)（负 disp 若零扩展填 aux 会得到
//   错误地址，故用减法；这是任务书 "Add scratch, imm" 在负 disp 下的等价改写）。
//   base=Rip 的 RIP 相对寻址：跳过整条指令并在 notes 记 "rip-relative 未支持"。
//   ALU 带 mem：Add rax,[m] -> 地址计算 + Load s,[m] + Add rax,s；
//   Add [m],rax -> 地址计算 + Load s,[m] + Add s,rax + Store [m],s
//   （Cmp/Test 无写回，不发 Store）。
//
// Push/Pop（x64 栈语义，Size 恒 S64；rsp = vm_reg_of(ir::Reg::Rsp)）：
//   Push r : Sub rsp, 8 ; Store a=Reg(rsp), b=Reg(r)
//   Pop  r : Load  a=Reg(r), b=Reg(rsp) ; Add rsp, 8
//
// 控制流（两遍翻译）：第一遍按块顺序排放并记录每块 VM 指令起始序号；
// Jmp/Jcc 的 aux = 目标块起始序号 - 本指令序号（**条数**，负值以二进制
// 补码存入 u32，解释器按 8 字节步进）。块末尾 IR 指令若非 Jmp/Ret，补
// Jmp +1（fallthrough 到布局中的下一块）。函数末尾恒补 Halt。
// Call v1 跳过并在 notes 记 "call 未支持，建议 gate"（重定位归 M2）。
// =====================================================================================
[[nodiscard]] TranslateResult translate_function(const ir::FunctionRegion& fn);

} // namespace wvmp::regvm::translator
