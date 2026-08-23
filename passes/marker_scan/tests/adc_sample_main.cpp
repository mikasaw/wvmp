// MIT-245: 端到端正路径样本——区域内含 adc（白名单内），验证 C2-Adc 修复后
// CF_in 链路正确传播。
//
// 设计要点：
//   - 用 MSVC `_addcarry_u64` 强制编译器 emit `add` + `adc` 两条 ALU 指令
//     在二进制中。MSVC codegen 典型为: add + (setb + movzx + add cl,0xFF) +
//     adc——中间桥接 (setb/movzx) lifter 未收录, C1 跳过, 但 add+adc 两条
//     ALU 仍落在区域内被翻译为 VmOp::Add/VmOp::Adc, regvm handler 真实执行。
//   - 输入挑 64+64 经典 case: 0xFFFFFFFFFFFFFFFF + 1 → 低 64 位 = 0, 高 64
//     位进 1。结果 hi=1, lo=0。stdout + 退出码双重断言。
//   - 区域内只让 add/adc 留下, mov 进出栈参数, ret; 配合 MIT-243 C1 gate 不会
//     被拦; rip-relative 留在区域外（std::printf 全局）。

#include "wvmp/sdk/markers.hpp"

#include <cstdio>
#include <intrin.h>

volatile unsigned long long g_a = 0xFFFFFFFFFFFFFFFFull;   // -1
volatile unsigned long long g_b = 0x0000000000000001ull;   //  1

// 64+64 → 128-bit 加法。MSVC 对 `_addcarry_u64` 典型 codegen:
//   add rax, [b_lo]                  ; lo = a_lo + b_lo, CF = carry out
//   setb cl                          ; cl = CF (lifter 跳过)
//   mov [rsp+xx], cl                 ; spill carry
//   movzx ecx, [rsp+xx]              ; reload carry (lifter 跳过)
//   add cl, 0xFF                     ; 转换: 0→0xFF (CF=0) 或 1→0 (CF=1)
//   adc rax, [b_hi]                  ; hi = a_hi + b_hi + CF
// 两条 ALU (add, adc) 都在 marker 区域内, 都被 lifter 翻译为 VmOp::Add/VmOp::Adc,
// regvm handler 真实执行——CF_in 通过 flags_ 寄存器跨指令传播。
__declspec(noinline) static void adc_chain(unsigned long long a_lo, unsigned long long a_hi, unsigned long long b_lo, unsigned long long b_hi, unsigned long long* out_lo, unsigned long long* out_hi) {
    WVMP_BEGIN(adc_chain);
    unsigned long long lo = 0;
    unsigned long long hi = 0;
    unsigned char carry = _addcarry_u64(0, a_lo, b_lo, &lo);
    _addcarry_u64(carry, 0, 0, &hi);
    WVMP_END(adc_chain);
    *out_lo = lo;
    *out_hi = hi;
}

int main() {
    const unsigned long long a_lo = g_a;     // rip-relative 留在区域外
    const unsigned long long a_hi = 0;
    const unsigned long long b_lo = g_b;
    const unsigned long long b_hi = 0;
    unsigned long long lo = 0;
    unsigned long long hi = 0;
    adc_chain(a_lo, a_hi, b_lo, b_hi, &lo, &hi);
    std::printf("lo=%llx hi=%llx\n",
                static_cast<unsigned long long>(lo),
                static_cast<unsigned long long>(hi));
    // 期望: -1 + 1 = 0 (lo), carry into hi → hi=1
    return (lo == 0 && hi == 1) ? 0 : 2;
}