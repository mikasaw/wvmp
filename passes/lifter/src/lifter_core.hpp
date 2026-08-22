// 区域 lift 核心：线性反汇编 + 指令映射 + 基本块划分（lifter 私有）。
#pragma once

#include "capstone_session.hpp"

#include "wvmp/common/types.hpp"
#include "wvmp/framework/diagnostics.hpp"
#include "wvmp/ir/region.hpp"

#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace wvmp::passes::lifter {

// 反汇编产物中的单条指令（含控制流元数据，未支持的指令也保留位置信息）。
struct LiftedItem {
    u64 addr = 0;                  // RVA
    u32 raw_size = 0;              // 机器码长度（字节）
    std::optional<ir::Insn> insn;  // nullopt = 未支持/TODO，已跳过

    enum class Ctl : u8 { None, Jcc, Jmp, Call, Ret };
    Ctl ctl = Ctl::None;
    u64 target = 0;        // ctl∈{Jcc,Jmp,Call} 且目标为立即数时有效
    bool indirect = false; // jmp/call reg（目标未知）
};

// 基本块划分（纯函数，可独立测试）：
//   leader 集合 = 区域起点 + jcc/jmp/call 的立即目标 + jcc/call 之后的
//   fallthrough 点 + 区域终点（终点若无指令则不产生块）；按 leader 切块。
//   succs：块末条指令为 jcc → {目标, fallthrough}；jmp → {目标}（间接跳转
//   为空）；ret → 空；否则 → {顺序 fallthrough}（区域尾为空）。
//   preds 由 succs 反推，仅统计区域内块之间的边。
//   未支持指令占位（参与切块）但不进入 BasicBlock::insns。
void build_blocks(u64 begin_rva, u64 end_rva, std::span<const LiftedItem> items,
                  std::vector<ir::BasicBlock>& out);

// 一站式入口：对 [code, code+size)（对应函数区域 RVA [base_rva, end_rva)）
// 线性反汇编、逐条映射并填充 fr.blocks。capstone 会话由调用方按 arch
// 打开并复用。
//   - 未支持指令 / 无效字节：记 Note（函数名 + RVA + 助记符），不失败；
//   - 返回解码出的指令条数（含被跳过的指令）。
u64 disassemble_and_lift(CapstoneSession& session, const u8* code, size_t size, u64 begin_rva,
                         u64 end_rva, std::string_view func_name, std::string_view pass_name,
                         Diagnostics& diag, ir::FunctionRegion& fr);

} // namespace wvmp::passes::lifter
