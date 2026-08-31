#pragma once
#include "wvmp/common/types.hpp"

// WVmp 保护标记（用户侧）。
//
// 用法（在目标函数内成对使用，包裹需要保护的代码）：
//   void secret() {
//       WVMP_BEGIN(secret);
//       ... 敏感计算 ...
//       WVMP_END(secret);
//   }
//
// 两个宏展开为对桩函数 marker_begin/marker_end 的调用。桩函数体各含一个
// 唯一的 8 字节 magic 立即数（kBeginMagic / kEndMagic）；marker_scan pass
// 在被保护 PE 中定位这些 magic 字节模式，再通过 E8 rel32 调用点回溯用户
// 代码中的标记位置，生成保护区域。字节签名必须与本 SDK 同步编译链接——
// 不导出符号（静态链入，避免给用户 exe 平添导出表）。
//
// 限制（与 marker_scan pass 的 TODO 对应）：
//  - x86 (32 位) 目标上 MSVC 会把 64 位立即数拆成两条 imm32（magic 不连
//    续，/O1 /O2 lo→hi 紧邻、/Od hi→lo 间隔 3B，实测见 sdk.cpp 注释）。
//    X1a（MIT-437）起 marker_scan 双段识别已覆盖该形态（仅定位，虚拟化
//    管道在后续单接力）；扫描判据不钉 opcode，若未来 MSVC 改变物化形态
//    （间隔 > 8B 或出现第三种顺序），锚点将失配——改形态须同步
//    scan_core.hpp 的 kX86MaxHalfGap 并复跑 X1a 实测。
//  - 优化（O2+）下编译器可能把尾部 marker 调用变成 jmp（尾调用），配对
//    会失败；建议对含标记的翻译单元关闭优化或固定 /Od。

#define WVMP_BEGIN(fn) ::wvmp::sdk::marker_begin()
#define WVMP_END(fn)   ::wvmp::sdk::marker_end()

namespace wvmp::sdk {

inline constexpr int kApiVersion = 1;

// 扫描锚点：8 字节 magic 立即数（LE）。
//   kBeginMagic 字节序（LE）= "WVMPBEG1"
//   kEndMagic   字节序（LE）= "WVMPEND1"
// 选择为可打印 ASCII：在反汇编/十六进制转储中肉眼可辨，且不含 0xE8/0xE9
// （避免 magic 自身被 call/jmp 扫描误命中）。
// 注意：marker_scan 泳道在 scan_core.hpp 中复制了这两个模式（模块边界），
// 集成测试有同步性断言。
inline constexpr u64 kBeginMagic = 0x3147'4542'504D'5657ull; // "WVMPBEG1"
inline constexpr u64 kEndMagic   = 0x3144'4E45'504D'5657ull; // "WVMPEND1"

// 桩函数（禁止内联：magic 所在函数体必须作为独立实体存活到最终链接）。
// 无参：marker_scan 通过 magic 字节做锚点，与函数名无关；带 const char* 参数
// 会在 E8 调用点之前生成 `lea rcx,[rip+str]`，该 lea 是白名单外的 rip-relative
// 指令——C1 保守拦截会把含它的整段区域拦下，让虚拟化无法落地。
void marker_begin();
void marker_end();

// 非内联锚点，保证 SDK 总是作为真实库被链接。
int api_version();

} // namespace wvmp::sdk
