// WVmp CLI 配置模型（P8 泳道）。
//
// 保护任务用 TOML 描述（见 cli/configs/default.toml）：
//   input  / output : 输入与输出 PE 路径（必填）
//   seed            : 保护随机种子，0 = 默认（可省略）
//   [[passes]]      : 要装配的 pass 名单，按配置顺序书写；Pipeline 会
//                     按 Phase 稳定排序，同 Phase 内保持此处的顺序。
#pragma once

#include "wvmp/common/types.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace wvmp::cli {

// v1 无 pass 级参数，结构预留（后续 pass options 平铺进该结构）。
struct PassConfig {
    std::string name;
};

struct WvmpConfig {
    std::string input, output;
    wvmp::u64 seed = 0;
    std::vector<PassConfig> passes; // 配置顺序（Pipeline 会按 Phase 稳定排序）
};

// 轻量 Result<T>：ok=false 时 error 给出用户可读的失败描述（文件不存在 /
// 语法错（带行号）/ 字段缺失或类型不对）。
struct ConfigResult {
    bool ok = false;
    WvmpConfig value;
    std::string error;
};

ConfigResult parse_config(const std::filesystem::path& file);

} // namespace wvmp::cli
