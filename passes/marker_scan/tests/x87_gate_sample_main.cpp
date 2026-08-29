// MIT-418 (G5r-R3): x87 永久 gate 回归样本主程序。
//
// 形态 (D1 决策): MASM 全族混合 + GP helper 真区, 单 exe 一箭双雕——
//   * wv_x87_gate_fn (MASM): 标记区域内 x87 五族 (fld/fadd/fstp/fcomip/fsin)
//     各 ≥1 条。lifter 未支持 → skipped_ranges → C1 gate → 整函数保持原生,
//     **零 stub**; packed 与 native byte-identical (416 §0 实测行为链钉死)。
//   * wv_gp_helper (MASM): 纯 GP 白名单真虚拟化区 (mov/add/[rsp+24] spill),
//     区域完整可翻译 → 真虚拟化 → stub 计数 = 1 (REQUIRE_REAL 满足源)。
//     stub 总数 1 = 仅 helper 虚拟化, "x87 区零 stub" 由计数相等钉死 (B.2 ③)。
//
// 行为校验 (B.2 ④): main 把 x87 区结果 (sum/cmp/sin) 与 helper 结果全部
// printf 出来, native vs packed 双跑 stdout+rc byte-exact 即 gate 行为一致
// 的逐字节证据。fsin 用 0.5 小角 (硬件 fsin 精确归约域), 断言用宽松界
// (1e-9) 而非逐位相等——gate 样本钉的是"行为一致"不是"fsin 的 ulp"。
// 3 轮迭代: 每轮 x87 函数与 VM 虚拟化 helper 交错调用 (gate 函数原生执行
// ↔ VM 进出), 钉死 x87 栈平衡 + FPU 状态在 VM 进出间保持 (asmgen 全程
// GP/SSE, 不触 x87 状态; 若 VM 破坏 x87 状态, 多轮调用必发散 → FAIL)。
// 区域外 (main) 全部是普通 C++ — 无 x87 指令, 不干扰 lifter 白名单。
//
// 验收面: multiseed (REQUIRE_REAL=1) 35 样本 × 5 = 175/175 — 本样本经
// helper 的 1 个 stub 通过 ≥1 stub 断言; 保护日志四件套 (B.2) 见报告。

#include "wvmp/sdk/markers.hpp"

#include <cmath>
#include <cstdio>

// x87 区输入/输出全局 (MASM 经 rip-relative 直读直写; volatile 防编译器
// 常量折叠; double 由 MSVC 对齐 8)。
extern "C" volatile double g_a = 1.5;
extern "C" volatile double g_b = 2.25;
extern "C" volatile double g_c = 7.0;
extern "C" volatile double g_d = 7.0;   // 相等对, fcomip 置 ZF
extern "C" volatile double g_e = 0.5;
extern "C" volatile double g_res_sum = 0.0;
extern "C" volatile double g_res_cmp = 0.0;
extern "C" volatile double g_res_sin = 0.0;

// MASM 侧实现 (x87_gate_sample_asm.asm)。
extern "C" void wv_x87_gate_fn(void);
extern "C" unsigned int wv_gp_helper(unsigned int n);

int main() {
    volatile unsigned long long ok = 1;

    for (int it = 0; it < 3; ++it) {
        // 每轮换值, 逼出"结果错但首轮恰好相等"的假阳性。
        g_a = 1.5 + it * 0.5;
        g_b = 2.25 + it * 0.25;
        g_c = 7.0 + it;
        g_d = 7.0 + it;   // 恒相等对 (fcomip 每轮同态)
        g_e = 0.5 + it * 0.1;
        wv_x87_gate_fn();                       // gate → 原生执行
        std::printf("it=%d x87_sum=%.17g\n", it, static_cast<double>(g_res_sum));
        std::printf("it=%d x87_cmp=%.17g\n", it, static_cast<double>(g_res_cmp));
        std::printf("it=%d x87_sin=%.17g\n", it, static_cast<double>(g_res_sin));
        const unsigned int h = wv_gp_helper(5 + it);  // 真虚拟化 (VM 进出交错)
        std::printf("it=%d gp_helper(%u)=%u\n", it, 5u + static_cast<unsigned int>(it), h);

        // 断言: sum/cmp 为二进制精确值; sin 用 1e-9 宽松界 (gate 样本钉行为
        // 一致性, 不钉 fsin 逐位值; native==packed 双跑一致才是主判据)。
        ok &= (g_res_sum == 3.75 + it * 0.75) && (g_res_cmp == 7.0 + it) &&
              (h == 105u + static_cast<unsigned int>(it));
        ok &= std::fabs(g_res_sin - std::sin(0.5 + it * 0.1)) < 1e-9;
    }
    std::printf("ok=%llu\n", ok);
    return ok == 1 ? 0 : 2;
}
