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

// MIT-460 (P7-names)：WVMP_BEGIN 把函数名令牌字符串化传给桩——编译器把
// 字面量放 .rdata 并在 begin 调用点之前物化其地址（x64 = lea rcx,[rip+disp]
// 紧邻 E8；x86 = push imm32 紧邻 E8），marker_scan 据此解析区域真名
// （FunctionRegion.name），供保护日志与配置系统 [[functions]] name= 选择器
// 使用。无名物化（旧产物/非常规代码序）回退地址名，行为与 MIT-460 前一致。
// ⚠️ 名字物化指令位于 begin 调用点**之前** = 标记区域之外，不进虚拟化管道。
#define WVMP_BEGIN(fn) ::wvmp::sdk::marker_begin(#fn)
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
// marker_scan 通过 magic 字节做锚点定位桩，桩本体与名字无关；MIT-460 起
// marker_begin 带 const char* 名字参数——名字物化（lea/push）在 E8 调用点
// 之前 = 标记区域之外，不进虚拟化管道（历史担忧的"C1 拦截"前提已随
// MIT-248 rip-relative 支持翻转，且物化本就在区域外）。
void marker_begin(const char* name);
void marker_end();

// 非内联锚点，保证 SDK 总是作为真实库被链接。
int api_version();

} // namespace wvmp::sdk
