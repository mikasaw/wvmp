// 区域 lift 核心：线性反汇编 + 指令映射 + 基本块划分（lifter 私有）。
#pragma once

#include "capstone_session.hpp"
#include "pe_map.hpp"

#include "wvmp/common/types.hpp"
#include "wvmp/framework/diagnostics.hpp"
#include "wvmp/ir/region.hpp"
#include "wvmp/passes/lifter/lift_metadata.hpp"

#include <functional>
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
    // MIT-426 (G6a): VEX 三地址折叠的前置 IR（TranslateResult.extra 透传，
    // 恒在 insn 之前执行；legacy 通路恒空）。addr 与主 insn 相同（共享
    // 机器指令地址），翻译器 next_ip_of 按"后者覆盖"重建映射（见
    // translator.cpp translate_function）。
    std::vector<ir::Insn> pre_insns;

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

// MIT-407: 越区跳转目标回跳检出（triage §5 反例形态 d1_back 的静态检查）。
// 从 target 起沿静态控制流边 BFS ≤3 层（jcc → {target, fallthrough}、
// jmp → {target}、call/其他 → 顺序续行；间接 jmp 无静态目标为死端；
// 分类失败按非分支处理，绝不虚造边），任何被到达的地址落入
// [begin_rva, end_rva) 即判危险（区域将被 stub 覆写，native 回跳 = 执行
// stub 代码）。返回值 true = 目标不可用 → 调用方置 exit_native_blocked。
// 防御边界：每节点至多反汇编 1 条、总预算 256 条、层数 >3 终止。
bool back_jump_reaches_region(CapstoneSession& session, std::span<const u8> image,
                              const PeSectionMap& pe, u64 target, u64 begin_rva, u64 end_rva);

// MIT-407: 越区跳转目标回跳检出回调（lifter_pass 构造，捕获 session/image/
// pe_map；true = 目标可达集回跳本区 → 该函数禁用 ExitNative）。
using ExitNativeGuardFn = std::function<bool(u64 target_rva)>;

// 一站式入口：对 [code, code+size)（对应函数区域 RVA [base_rva, end_rva)）
// 线性反汇编、逐条映射并填充 fr.blocks。capstone 会话由调用方按 arch
// 打开并复用。
//   - 未支持指令 / 无效字节：记 Note（函数名 + RVA + 助记符），不失败；
//     同时把字节范围 [rva, size) 追加到 meta_out.skipped_ranges（MIT-249
//     follow-up issue-09: 让下游 translator / virtualize 识别 IR 缺字节
//     并触发 C1 gate）。
//   - 返回解码出的指令条数（含被跳过的指令）。
u64 disassemble_and_lift(CapstoneSession& session, const u8* code, size_t size, u64 begin_rva,
                         u64 end_rva, std::string_view func_name, std::string_view pass_name,
                         Diagnostics& diag, ir::FunctionRegion& fr, LiftMetadata& meta_out,
                         const ExitNativeGuardFn& exit_guard = {});

} // namespace wvmp::passes::lifter
