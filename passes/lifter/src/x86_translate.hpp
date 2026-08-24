// x86/x64 单条指令 → ir::Insn 映射（lifter 私有，不属于契约）。
//
// 语义约定（与后端翻译的契约，见 docs 层泳道协调）：
//  * Load  = 内存 → 寄存器：mov rax,[..]        → Insn{op:Load,  dst:reg, src:mem}
//  * Store = 寄存器/立即数 → 内存：mov [..],rax  → Insn{op:Store, dst:mem,  src:reg/imm}
//  * 纯寄存器/立即数 mov → Mov。
//  * ALU（Add/Sub/Adc/Sbb/And/Or/Xor/Cmp/Test 等）的 src 为内存时**不**拆成
//    Load+ALU 两条：op 保持 Add 等，直接把内存操作数放在 src.mem，由后端
//    （vm/regvm translator）在翻译时展开为实际的 load-计算序列。dst 为内存
//    的 ALU（add [..],eax）同理，dst.mem 原样保留。
//  * 子寄存器（EAX/AX/AL/R8D/...）一律映射到对应全寄存器（Rax/R8/...），
//    实际访问宽度由 Insn::size 携带（1/2/4/8 → S8/S16/S32/S64）。
//  * RIP 相对寻址：MemOperand.base = Reg::Rip，disp 保留 capstone 报告的
//    原始位移（未加上指令自身的绝对地址）。
//  * 无 base/index 的内存操作数用 Reg::Flags 哨兵（见 ir::MemOperand）。
#pragma once

#include "wvmp/common/types.hpp"
#include "wvmp/ir/arch.hpp"
#include "wvmp/ir/insn.hpp"

#include <capstone/capstone.h>
#include <capstone/x86.h>

#include <optional>
#include <utility>
#include <vector>

namespace wvmp::passes::lifter {

// capstone x86_reg → ir::Reg（子寄存器折叠到全寄存器）。
// 返回 nullopt 表示无法映射（xmm/段寄存器/cr/dr 等）。
std::optional<ir::Reg> map_reg(x86_reg r);

// jcc 系列的 capstone 指令 id → ir::Cond（O,No,B,Ae,E,Ne,Be,A,S,Ns,P,Np,L,Ge,Le,G）。
std::optional<ir::Cond> map_cond(x86_insn id);

enum class TranslateStatus : u8 {
    Ok,          // 成功映射
    Unsupported, // 超出 v1 白名单，跳过并记 Note
    Todo,        // 属于规划内指令但 v1 未实现（如 cl 变体、rol/ror），跳过并记 TODO Note
};

struct TranslateResult {
    TranslateStatus status = TranslateStatus::Unsupported;
    ir::Insn insn; // 仅 status == Ok 时有效

    // MIT-249 follow-up (issue-09): 跳过指令 (status != Ok) 时, 记录
    // 跳过的字节范围 [rva, size). lifter 在函数级聚合到 LiftMetadata,
    // 下游 (translator / virtualize) 据此识别 IR 缺字节并触发 C1 gate。
    // status == Ok 时为空。
    std::vector<std::pair<u64, u64>> skipped_ranges;
};

// 把一条 capstone 已反汇编的指令映射为 ir::Insn。
// 线程不依赖任何全局状态；arch 只影响无尺寸信息指令（jmp/ret 等）的默认 size。
TranslateResult translate_insn(const cs_insn& ci, ir::Arch arch);

} // namespace wvmp::passes::lifter
