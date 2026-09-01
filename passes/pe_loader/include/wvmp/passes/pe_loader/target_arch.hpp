#pragma once
#include "wvmp/common/types.hpp"

#include <string_view>

namespace wvmp::passes {

// MIT-438 (X1b) B.5: CLI arch 声明 → pe_loader 校验挂点的最小基建。
//
// 槽类型 = u8（builtin 类型跨翻译单元 std::any 恒同型——CLI 与本头各自消费，
// 值域靠两侧测试对账钉死：cli 侧 parse 测试 + pe_loader 侧 gate 测试）。
// CLI 侧枚举 = cli/include/wvmp/cli/config.hpp 的 ArchOpt（Auto/X64/X86），
// main.cpp 经穷举 switch 映射到本常量——两侧禁止再增第三个定义面。
//
// 语义（MIT-438 派活单 §B.5 / §C D1；MIT-446 (X4) D1 解禁翻正）：
//   Auto = machine 推导（x64 通行；x86 自 X4 起通行——全管道
//          marker_scan/lifter/translator/runtime_x86/stub_link 承接）；
//   X64  = 显式声明：machine != 0x8664 → rc=2 显式拒（声明与目标不符）；
//   X86  = 显式声明：machine == 0x014C → 通行（X4 D1）；否则 rc=2 拒。
// 未知 machine（非 0x014C/0x8664）在解析层白名单即拒（pe_image.cpp），不回退。
inline constexpr std::string_view kTargetArchDecl = "target_arch_decl";
inline constexpr u8 kTargetArchAuto = 0;
inline constexpr u8 kTargetArchX64 = 1;
inline constexpr u8 kTargetArchX86 = 2;

} // namespace wvmp::passes
