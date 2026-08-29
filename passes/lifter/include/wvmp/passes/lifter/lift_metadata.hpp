// 跨函数 lift 的旁路 metadata（lifter 模块私有，不入冻结契约 FunctionRegion）。
//
// 用途：lifter 跳过 (Todo/Unsupported) 的指令不进入 ir::FunctionRegion.basic_blocks
// (函数合约冻结于 ir/include/wvmp/ir/region.hpp, 不能改), 但下游 translator /
// virtualize 需要识别"区域内 IR 缺字节"才能触发 C1 gate 兜底。本结构提供
// 旁路通道：
//   - skipped_ranges = [rva, size) 列表，标 lifter 跳过的指令字节区间。
//
// 不入 framework/keys.hpp 的 6 核心字段 —— 这是 lifter 模块局部常量。
// MIT-249 follow-up issue-09 引入。
#pragma once

#include "wvmp/common/types.hpp"

#include <string_view>
#include <utility>
#include <vector>

namespace wvmp::passes::lifter {

// 单函数 lift 产出的旁路 metadata。
struct LiftMetadata {
    // 区域内被 lifter 跳过 (Todo / Unsupported) 的指令字节范围。
    // 每项 = (rva, size)；不重叠；按 RVA 升序追加；当前实现下函数区域内
    // 这些字节未进入 ir::FunctionRegion.basic_blocks[].insns。
    std::vector<std::pair<u64, u64>> skipped_ranges;

    // MIT-407: 越区跳转目标回跳检出（triage §5 反例形态 d1_back）。
    // 区域内任一直接 jcc/jmp 的越区目标（target >= end_rva），其 ≤3 层
    // 静态可达集若落回 [begin_rva, end_rva)——区域字节将被 stub_link 覆写
    // 为 E9+INT3，native 回跳进区域 = 执行 stub 代码 → 行为错/崩溃。
    // 置位后 backend 的上界查询 lambda 返回 nullopt，整函数维持 C1 gate
    // （gate 本就是按函数粒度，无需逐目标记录）。
    bool exit_native_blocked = false;
};

// 跨 pass 通信槽 key（LifterPass 输出 / 下游 pass 输入）。
// 定义在 lifter 模块局部 header 而非 framework/keys.hpp，避免触碰冻结契约。
inline constexpr std::string_view kLiftedMetadata = "lifter.metadata";

} // namespace wvmp::passes::lifter