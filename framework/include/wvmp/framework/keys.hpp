#pragma once
#include <string_view>
namespace wvmp {
inline constexpr std::string_view kImage="image", kFunctions="functions", kLiftedIr="ir.lifted", kVmProgram="vm.program", kVmRuntime="vm.runtime", kNewSections="pe.new_sections";
// pe_loader 产出的 PE 结构模型（PeImage）所在扩展槽——M1 起为 marker_scan/lifter
// 等分析类 pass 的共享依赖（提供方：pe_loader）。
inline constexpr std::string_view kPeImage="pe.image_meta";
}
