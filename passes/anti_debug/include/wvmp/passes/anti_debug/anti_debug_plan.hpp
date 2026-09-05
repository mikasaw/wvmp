#pragma once
#include "wvmp/common/types.hpp"

#include <string_view>

namespace wvmp::passes::anti_debug {

// MIT-463 (anti_debug-v1)：anti_debug pass ↔ stub_link pass 契约
// （扩展槽 kAntiDebugPlan 传递；INTERFACE 头，同 crypt_plan 模式）。

// 检查技术位（append-only 位分配，禁重排/复用）。
//   v1 技术面 = PEB.BeingDebugged + PEB.NtGlobalFlag（零误报用户态检查，
//   无 syscall/无计时依赖——rdtsc 计时与 DRx 硬件断点检查需校准/CONTEXT
//   通路，留后续单）。
namespace tech {
inline constexpr u32 kBeingDebugged = 1u << 0;  // PEB+2 (byte) != 0
inline constexpr u32 kNtGlobalFlag  = 1u << 1;  // PEB+NtGlobalFlag & 0x70 != 0
//   x64: PEB = [gs:0x30 → TEB + 0x60]；NtGlobalFlag @ PEB+0xBC
//   x86: PEB = [fs:0x18 → TEB + 0x30]；NtGlobalFlag @ PEB+0x68
inline constexpr u32 kV1All = kBeingDebugged | kNtGlobalFlag;
} // namespace tech

// 命中响应策略（v1 恒 FailFast）：
//   FailFast = 检测到调试器 → 清零 rax/eax 后写 [0] → 确定性 AV 终止进程。
//   计划文档中的 silent_exit（ExitProcess）需 import 解析通路，后续单。
//   ⚠️ D1 披露：FailFast 崩溃形态与天然空指针崩溃不可区分——对用户表现为
//   "程序无提示退出"，无反调试行为泄露。
namespace response {
inline constexpr u32 kFailFast = 0;
} // namespace response

struct AntiDebugPlan {
    u32 techniques = tech::kV1All;
    u32 response = response::kFailFast;
    // MIT-467 (T10)：init 期检查位（TLS 回调执行面，早于进程入口——抓
    // 附加型调试器）。默认镜像 techniques（零误报面同源）；0 = 关闭。
    // rdtsc 计时/DRx 硬件断点面留 T10.1（误报校准 / CONTEXT 通路）。
    u32 init_techniques = tech::kV1All;
};

} // namespace wvmp::passes::anti_debug
