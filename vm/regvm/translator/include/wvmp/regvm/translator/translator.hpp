#pragma once
#include "wvmp/ir/region.hpp"
#include "wvmp/vm/backend.hpp"

#include <functional>
#include <optional>
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

// MIT-407: 区域外跳转 ExitNative 上界函数。
//   输入: 区域 begin_rva（即 marker_begin 落点 RVA）
//   输出: 该函数在 .pdata RUNTIME_FUNCTION 表里的 EndAddress；nullopt = 无
//         .pdata 条目 / 解析失败 / 调用方未提供 / lifter 检出越区目标回跳
//         （→ 维持 gate）。
//   实现：pe_loader::PeImage::find_function_end_rva；调用方构造 lambda
//   捕获 PeImage 引用传入，并叠加 lifter 的 exit_native_blocked 判定。
using FunctionUpperBoundFn = std::function<std::optional<u64>(u64 /*begin_rva*/)>;

// MIT-409: MSVC 跳转表条目读取函数。
//   输入: 表体 RVA + 条目下标 i；输出: 表项 u32（小端）；nullopt = 越界 /
//   不可读（表体落在未映射区间等）→ 触发 C1 gate。
//   实现：调用方捕获 PeImage 引用，rva_to_offset + 4 字节读。
using JumpTableReadFn = std::function<std::optional<u32>(u64 /*table_rva*/, u32 /*index*/)>;

// 纯函数：把一个函数区域的 IR 逐指令翻译为 regvm 字节码。
//   - 无跨指令分析、无状态残留；同输入同输出。
//   - 遇到 v1 未支持形态（call [mem] / 间接 call / 目标块缺失等）
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
//   base=Rip 的 RIP 相对寻址：RVA = next_ip + disp（next_ip 由 caller 从块布局推
//   算: 同块下一条 insn.addr / 下一块首地址 / fn.end_rva）。翻译期发
//   `Mov acc, imm(RVA)` (S64)；运行时 Load/Store 汇编 `add acc, [CTX+0x110]`
//   即 + image_base（VmContext.scratch_mem，由 stub_gen 从 PE optional header
//   取出写入）。rip 越界（disp 极端负跌出 image 起点）或 RVA > 0xFFFFFFFF
//   拒绝并记 note（触发 C1 gate，保持原生；不作为 halt VM 的硬错误）。
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
// 直接 call (dst = Imm) emit VmOp::CallGate（aux = target RVA, cond_or_size
// = arg_count, v1 固定 0）；间接 call / call [mem] 跳过并记 note 触发
// C1 gate（保持原生）。完整 ABI 透传 / 递归 / 浮点参数留给后续 issue。
//
// MIT-407: 越区跳转 ExitNative（当 upper_bound_fn 非空且 target ∈
// [end_rva, upper_bound_fn(begin_rva)) 时 emit VmOp::ExitNative, aux =
// target RVA, cond_or_size = ir::Cond；不满足 → 维持原 gate）。
//
// MIT-409: MSVC 跳转表特化（jmp reg 间接跳转的静态展开）。
//   翻译期在 translate_function 内做预扫描：对每个以 `Jmp(dst=Reg)` 结尾
//   的块，按受限四件套模板匹配 —— 前溯 `lea <b>,[rip+T]` → `mov <ix>,
//   [<b>+<idx>*4+off]`（u32）→ `add <t>,<b>` → `jmp <t>`，且 t==ix、idx
//   载入指令（`mov <idx>, [mem]`）在 lea 前一指令；表长 K 取前一块尾部
//   防御 `cmp <idx>, K-1; ja <越区>`（cond=A、被比较值链接 idx 载入源）。
//   命中后从 PE 镜像读 K 项（u32 delta，经 JumpTableReadFn），目标 RVA =
//   lea 目标 RVA + delta；全部目标 ∈ 区域且为已 lift 指令地址才展开：
//   运行时比较链 `Mov s,rva_i; LeaRva s,s; Cmp t,s; Jcc eq → 块_i` ×K
//   （零新 VmOp）。任一环节失败（模板不符 / 无防御常数 / 读表越界 / 目标
//   出区 / K>32 预算）→ 维持原 gate（保守底线零让步）。
// =====================================================================================

// 单参数版：保持原签名向后兼容（无 .pdata 上界 → 维持 gate 行为）。
[[nodiscard]] TranslateResult translate_function(const ir::FunctionRegion& fn);

// 双参数版：传 .pdata 上界查询函数；virtualize pass 构造捕获 PeImage 引用
// 的 lambda 传入。upper_bound_fn 为空 lambda 时与单参数版行为一致。
[[nodiscard]] TranslateResult translate_function(const ir::FunctionRegion& fn,
                                                 FunctionUpperBoundFn upper_bound_fn);

// 三参数版：MIT-409 跳转表读取函数。table_read_fn 为空 → 不启用跳转表
// 特化（与双参数版行为完全一致）；启用后跳转表特化仅在模板全命中且表
// 验证通过时展开，否则维持原 gate。
[[nodiscard]] TranslateResult translate_function(const ir::FunctionRegion& fn,
                                                 FunctionUpperBoundFn upper_bound_fn,
                                                 JumpTableReadFn table_read_fn);

} // namespace wvmp::regvm::translator
