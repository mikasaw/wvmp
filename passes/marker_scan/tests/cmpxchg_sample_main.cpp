// MIT-341: 端到端正路径样本——区域内含 cmpxchg (REG-REG 64-bit, S32/S64),
// 验证 cmpxchg 修复后翻译成功、运行时走真 Cmpxchg handler、行为与原生
// 逐字节一致（保护 → 运行 → stdout+退出码比对）。
//
// 设计要点 (沿用 MIT-335 xchg / MIT-337 setcc / MIT-339 cmovcc 模式):
//   - MSVC x64 **不支持 inline asm**, cmpxchg 字节由 cmpxchg_sample_asm.asm
//     (MASM) 直接 emit, 链接进本 sample. 区域内含 mov + cmpxchg + mov 真指令
//     字节（与 cmp + cmovcc/setcc 不同：cmpxchg 自带比较+条件赋值，无须 cmp 前置）。
//   - 区域**只含白名单** ALU: mov/cmpxchg/mov, 不含 rip-relative / printf / call
//     (printf 在区域外的 main 中)。
//   - 覆盖 S32 (eax, ebx) + S64 (rax, rcx) 两种 operand 形式, 验证 cmpxchg
//     跨宽度行为, 跑 byte-exact 比对。
//
// 测试用例覆盖典型 cmpxchg 语义:
//   cmpxchg rax, rcx:
//     if (rax == rcx) { rax = rcx (no-op); ZF=1 }     -- equal case (still rax)
//     else              { rax = rcx's original; ZF=0 } -- not-equal case
//   cmpxchg eax, ebx (32-bit):
//     if (eax == ebx) { eax = ebx (no-op); ZF=1 }
//     else              { eax = ebx's original; ZF=0 }
//
// 我们的 wrapper 用 rax/rcx 与 eax/ebx 做模拟，equal case 测 RAX 不变；
// not-equal case 测 RAX 被改成原 rcx/ebx 值。
//
// 关键: MSVC /Od 不会自然 emit cmpxchg (lock cmpxchg 主要由 atomic op codegen);
// 必须用 MASM (.asm) helper 强制 codegen 真 cmpxchg 字节 (pitfall #35)。

#include "wvmp/sdk/markers.hpp"

#include <cstdint>
#include <cstdio>

extern "C" uint64_t cmpxchg64_eq(int64_t expected, int64_t desired);
extern "C" uint64_t cmpxchg64_ne(int64_t initial, int64_t dst_val, int64_t desired);
extern "C" uint32_t cmpxchg32_eq(uint32_t expected, uint32_t desired);
extern "C" uint32_t cmpxchg32_ne(uint32_t initial, uint32_t dst_val, uint32_t desired);

int main() {
    // 区域外: 直接调函数 (printf 在区域外)。
    //
    // S64 equal case (expected == initial): cmpxchg 看到 rax(initial) == rcx(initial)，
    // 设 ZF=1, dst(desired) ← src... 这里我们的 wrapper 模拟：
    //   1. mov rax, [expected]
    //   2. mov rcx, [desired]
    //   3. cmpxchg rax, rcx (隐式累加器是 rax, 但我们已经设了 rax = expected)
    //
    // 等价模式: rax = expected; rcx = desired; cmpxchg rax, rcx; if equal rax不变, 不等则rax被改。
    //
    // S64 equal: expected=5, desired=5 → 5 (rax 没变, ZF=1)
    const uint64_t s64_eq_same = cmpxchg64_eq(5, 5);   // 5
    // S64 equal: expected=42, desired=99 → 42 (rax 没变, ZF=1, 但 dst 被改了)
    const uint64_t s64_eq_diff = cmpxchg64_eq(42, 99); // 42
    // S64 not-equal: rax=5, rcx=99; cmpxchg rax, rcx; rax was 5, rcx is 99,
    //    equal? no → rax = original rcx value (99); rcx still 99.
    //    但是我们的 wrapper 让 rax 看到的是 5 (从 wrapper 传入 initial=5)，
    //    dst 槽是 rax(初始 initial=5), src 是 rcx(desired=99)。
    //    cmpxchg 看到 rax==5 == initial(dst)==5 → equal → dst(src) 但这是 rcx。
    //    其实 wrapper 应该让 rcx 是 dst 值（模拟 dst 槽），再 cmpxchg rax, rcx。
    //    equal case: dst = src; not-equal case: rax = dst.
    //    我们的 wrapper: dst = rcx (= desired_val), src 是隐式或固定。
    //
    // 重新设计 wrapper 思路 (与实际 cmpxchg 字节流匹配):
    //   cmpxchg64_ne(initial, dst_val, desired):
    //     rax = initial
    //     rcx = dst_val  (这是 dst 操作数 — 与 rax 比较)
    //     rdx = desired  (这是 src 操作数 — 赋给 dst 如果 equal)
    //     cmpxchg rcx, rdx   ← 这里的关键!
    //     比较隐式累加器 (rax=initial) 与 rcx(dst_val):
    //       equal (initial == dst_val): rcx = rdx(desired); ZF=1; rax 不变
    //       not equal: rax = rcx(=dst_val); ZF=0; rcx 不变
    //     返回 rax (handler 后 Rax 槽的内容)
    const uint64_t s64_ne_eq = cmpxchg64_ne(5, 5, 99);    // rax=5, rcx=5, rdx=99; cmpxchg rcx, rdx; equal → rcx=99, rax=5 → return 5
    const uint64_t s64_ne_ne = cmpxchg64_ne(5, 100, 99);  // rax=5, rcx=100, rdx=99; not equal → rax=100, rcx=100 → return 100

    // S32 equal: eax=5, ebx=5 → 5 (ZF=1)
    const uint32_t s32_eq_same = cmpxchg32_eq(5, 5);
    // S32 not-equal: eax=5, ecx=100, edx=99 → 100 (rax 被改)
    const uint32_t s32_ne_ne = cmpxchg32_ne(5, 100, 99);

    std::printf(
        "cmpxchg s64_eq_same=%llu s64_eq_diff=%llu "
        "s64_ne_eq=%llu s64_ne_ne=%llu "
        "s32_eq_same=%u s32_ne_ne=%u\n",
        static_cast<unsigned long long>(s64_eq_same),
        static_cast<unsigned long long>(s64_eq_diff),
        static_cast<unsigned long long>(s64_ne_eq),
        static_cast<unsigned long long>(s64_ne_ne),
        static_cast<unsigned int>(s32_eq_same),
        static_cast<unsigned int>(s32_ne_ne));
    return 0;
}