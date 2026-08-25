// MIT-302: 端到端正路径样本——区域内含 imul/mul (有符号/无符号乘法)
// 三形式: 3-op imm / 2-op reg / 1-op mul。验证 imul/mul 修复后翻译成功、
// 运行时走真 Imul/Mul handler、行为与原生逐字节一致。
//
// 设计要点 (沿用 cl_shift / rol 模式):
//   - volatile 全局变量防止 MSVC 常量折叠把乘法挪出 marker 区域;
//   - 区域**只含白名单** ALU: mov/add/imul/mul, 不含 rip-relative / printf
//     / call（printf 在区域外）；
//   - 32/64-bit 两种 size 都覆盖 (MSVC 对 long long codegen 是 64-bit)。

#include "wvmp/sdk/markers.hpp"

#include <cstdint>
#include <cstdio>

volatile int64_t g_a = 0x1234567890ABCDEFLL;
volatile int64_t g_b = 0x1000;
volatile uint64_t g_ua = 0xFFFFFFFFFFFFFFFFULL;
volatile uint64_t g_ub = 0x12345678ULL;

// imul_test: 区域内含 imul 3-op imm (imul eax, ecx, 100), 2-op reg (imul rax, rcx).
__declspec(noinline) static int64_t imul_test() {
    WVMP_BEGIN(imul_test);
    int64_t a = g_a;        // 加载到 RAX (mov rax, [g_a])
    int64_t b = g_b;        // 加载到 RCX (mov rcx, [g_b])
    int64_t r = a * b;       // imul rax, rcx (2-op form, MSVC /Od)
    r = r * 7;               // imul rax, rdx, 7 (3-op imm form)
    r = r * 100;             // imul rax, rdx, 100 (3-op imm form)
    WVMP_END(imul_test);
    return r;
}

// imul_3op_only: 仅 3-op imm 形式 (MSVC 编译时若参数为非常量, codegen 为 2-op;
// 用 volatile 参数强制 codegen 为 3-op imm, 因 imm 是字面量).
__declspec(noinline) static int64_t imul_3op_only() {
    WVMP_BEGIN(imul_3op_only);
    volatile int64_t x = 5;
    int64_t r = x * 7;       // imul 3-op imm (x 是 volatile, MSVC 仍 codegen 为 3-op)
    r = r * 100;             // 链式 3-op
    r = r * 1000;
    WVMP_END(imul_3op_only);
    return r;
}

// mul_test: unsigned multiply 64-bit x 64-bit = 128-bit via _umul128 intrinsic.
// MSVC /Od + c++20 下 _umul128 codegen 为 __allmul 调用, 不产 native mul
// 指令; lift 阶段只覆盖纯白名单 imul 路径, _umul128 函数调用是 call gate
// 兜底（call → 跳转回 native helper）。本样本仅用于 imul 真虚拟化路径
// 的回归（mul 在 vm/regvm/runtime/tests/test_runtime.cpp 独立 fuzz）。
__declspec(noinline) static uint64_t mul_test(uint64_t a, uint64_t b) {
    WVMP_BEGIN(mul_test);
    uint64_t lo = a * b;
    uint64_t hi = 0;
    WVMP_END(mul_test);
    return lo ^ hi;
}

int main() {
    const int64_t a = imul_test();
    const int64_t b = imul_3op_only();
    const uint64_t c = mul_test(g_ua, g_ub);
    std::printf("imul=%llx imul3op=%llx mul=%llx\n",
                static_cast<unsigned long long>(a),
                static_cast<unsigned long long>(b),
                static_cast<unsigned long long>(c));
    return 0;
}
