#pragma once
#include <string_view>
namespace wvmp {
inline constexpr std::string_view kImage="image", kFunctions="functions", kLiftedIr="ir.lifted", kVmProgram="vm.program", kVmRuntime="vm.runtime", kNewSections="pe.new_sections";
// pe_loader 产出的 PE 结构模型（PeImage）所在扩展槽——M1 起为 marker_scan/lifter
// 等分析类 pass 的共享依赖（提供方：pe_loader）。
inline constexpr std::string_view kPeImage="pe.image_meta";
// MIT-457 配置系统 v1：保护规则集（CLI 解析 TOML 后写入；virtualize 等
// pass 消费）。模型见 framework/protect_levels.hpp。
inline constexpr std::string_view kProtectRules="config.protect_rules";
// MIT-458 crypt-v1：字节码加密计划（crypt pass 写入 → stub_link 消费）。
// 契约模型见 passes/crypt/include/wvmp/passes/crypt/crypt_plan.hpp。
inline constexpr std::string_view kCryptPlan="crypt.plan";
}
