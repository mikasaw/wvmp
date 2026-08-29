// MIT-417 (P0): 端到端正路径样本——区域内调用带 double/float 参数的
// native callee，验证 CallGate FP 参数/返回值通路 (xmm0..3 入参 + xmm0
// 返回) 修复后真虚拟化、行为与原生逐字节一致。
//
// 背景 (G5r triage §6.1): build_callgate 只搬 RCX/RDX/R8/R9 整数参数槽、
// 只回写 RAX——全程零 xmm 触点。区域内对带 FP 参数的 native 调用 (含纯
// SSE 实现) 虚拟化后**静默错乱** (g5r_p0: native fp_sum=15.00 → packed
// fp_sum=3.00, rc 0→1, 零告警)。本样本是 multiseed 池**第一份全 FP 参数
// 形态** callgate 样本 (回归盲区消灭: 既有 34 样本的 callgate 调用恰好
// 全整型参数)。
//
// 设计要点:
//   - fp_add4: 4 个 double 参数 = Win64 FP 参数槽 xmm0..3 **全槽**;
//     fp_addf: 2 个 float 参数 = xmm0..1 低部 (float 高 96 位 ABI 规定
//     undefined, 全 16B movups 搬运与原生精确一致)。
//   - callee 内部 (mulsd 等) 不属本单 (D3: callgate 边界 = ABI 契约,
//     callee 侧不模拟)。
//   - 返回值参与后续 VM 运算: s+s (addsd) / t+t (addss) —— handler 只
//     搬运不接线会直接反应为 stdout 错值 (非空转假阳性)。
//   - 四个可观察输出互相独立, 各自对应一条故障通路:
//       g_fp_sum = s          (callgate 入参 xmm0..3 断链 → 错值)
//       r (VM 函数返回) = s+s (callgate 返回值 xmm0 断链 → 错值)
//       g_fp_fsum = u = t+t   (float 参数/返回链路)
//   - main 用 %a (hex float) 打印逐位可比对 (无十进制舍入歧义)。
//
// 期望 (native == packed):
//   s = fp_add4(1.0, 2.0, 3.0, 4.0) = 10.0;  r = s + s = 20.0
//   t = fp_addf(1.5f, 2.5f) = 4.0f;          u = t + t = 8.0f
//
// REQUIRE_REAL: 主函数 fp_callgate_vm 真虚拟化 (stub ≥1), 非 C1 gate。

#include "wvmp/sdk/markers.hpp"

#include <cstdio>

volatile double g_fp_sum = 0.0;
volatile float g_fp_fsum = 0.0f;

// 未标记 native callee: 4 个 double 参数 → xmm0..3 全槽。
__declspec(noinline) static double fp_add4(double a, double b, double c, double d) {
    return a + b + c + d;  // 1.0+2.0+3.0+4.0 = 10.0
}

// 未标记 native callee: 2 个 float 参数 → xmm0..1 低部。
__declspec(noinline) static float fp_addf(float a, float b) {
    return a + b;  // 1.5f+2.5f = 4.0f
}

// 标记函数: 3 次 callgate (FP 入参) + 返回值参与 VM 内 SSE 运算。
__declspec(noinline) static double fp_callgate_vm() {
    WVMP_BEGIN(fp_callgate_vm);
    const double s = fp_add4(1.0, 2.0, 3.0, 4.0);  // xmm0..3 全槽入参
    const float t = fp_addf(1.5f, 2.5f);           // float 入参
    g_fp_sum = s;                                  // movsd store (XmmStore)
    const double r = s + s;                        // 返回值参与 VM 运算 (addsd)
    const float u = t + t;                         // 返回值参与 VM 运算 (addss)
    g_fp_fsum = u;                                 // movss store (XmmStore)
    WVMP_END(fp_callgate_vm);
    return r;
}

int main() {
    const double r = fp_callgate_vm();
    std::printf("fp4=%a sum=%a fsum=%a rc=%d\n", r,
                static_cast<double>(g_fp_sum), static_cast<double>(g_fp_fsum),
                (r == 20.0 && g_fp_sum == 10.0 && g_fp_fsum == 8.0f) ? 0 : 1);
    return (r == 20.0 && g_fp_sum == 10.0 && g_fp_fsum == 8.0f) ? 0 : 1;
}
