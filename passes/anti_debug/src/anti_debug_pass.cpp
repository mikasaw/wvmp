#include "wvmp/passes/anti_debug/anti_debug_pass.hpp"

#include "wvmp/passes/anti_debug/anti_debug_plan.hpp"
#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/registry.hpp"

namespace wvmp::passes {

// MIT-463 (anti_debug-v1)：反调试检查注入（stub 入口前缀面）。
//
// 本 pass 只产出策略（AntiDebugPlan：技术位 + 响应策略）写入
// kAntiDebugPlan 扩展槽；stub_link（Emit）消费并在每个入口 stub 的
// 序言之前织入检查块（stub_gen build_adb_asm_*，双 arch）。
//
// v1 技术面（零误报用户态 PEB 检查，命中响应 = FailFast 确定性崩溃，
// 无 syscall/计时依赖）：
//   - PEB.BeingDebugged（x64 PEB=[gs:0x30]+0x60 / x86 PEB=[fs:0x18]+0x30）
//   - PEB.NtGlobalFlag（& 0x70；x64 PEB+0xBC / x86 PEB+0x68）
//
// 边界披露（D1，详见 GAPS anti_debug 节）：
//   - 检查仅覆盖"入口 stub"面：被 C1 gate 的函数保持原生（无检查）；
//   - rdtsc 计时 / DRx 硬件断点 / NtQueryInformationProcess 面留后续单；
//   - 检查每次 stub 进入都执行（开销 = 十余条指令/调用）；
//   - 每函数粒度（[[functions]] anti_debug=false 豁免）留 T3 后续扩展。

void AntiDebugPass::run(ProtectionContext& ctx) {
    const anti_debug::AntiDebugPlan plan{
        anti_debug::tech::kV1All,
        anti_debug::response::kFailFast,
    };
    ctx.slot<anti_debug::AntiDebugPlan>(kAntiDebugPlan) = plan;
    ctx.diag.report(Severity::Note, name(),
                    "PEB.BeingDebugged + PEB.NtGlobalFlag 检查已启用"
                    "（stub 入口前缀，FailFast 响应）");
}

WVMP_REGISTER_PASS(AntiDebugPass)

} // namespace wvmp::passes
