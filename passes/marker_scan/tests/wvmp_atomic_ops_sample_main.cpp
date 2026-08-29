// MIT-419 (G4): lock 前缀原子族 strip-and-execute E2E 样本主程序。
//
// 形态 (派活单 §B.5):
//   * C++ 侧 (本文件): Interlocked* intrinsic 真产物形态 — /Od (本样本
//     CMake 档位) 下 MSVC 把 intrinsic 编成 **call 到编译器生成的 helper**
//     (helper 内含 lock xadd / lock and/or/xor imm / 裸 xchg mem / lock
//     cmpxchg 单指令; probe 实测 2026-08-30, 反汇编表见报告 §3)。区域内
//     call → callgate → helper 原生执行 lock 指令 (真内存原子操作), 语义
//     断言照旧; /O1 才直发内联 rip-relative lock 形态, 但 /O1 与 Debug
//     全局 /RTC1 硬冲突 (cl D8016) — 内联形态由 MASM 侧按 helper 字节
//     逐条拼写入区域 VM 化 (helper 即编译器真产物, 字节一致)。
//   * MASM 侧 (wvmp_atomic_ops_sample_asm.asm): 编译器 helper 同款字节的
//     全谱 — lock xadd 32/64、lock bts/btr imm8、lock btc reg 位号、裸
//     xchg mem、lock cmpxchg **rip-relative 目标** + cmpxchg 后 je 惯用法
//     (ZF 读回 flags 探针)。
//   * 负例 (不可执行): lock mov / lock nop 区域 → capstone 拒解码 →
//     C1 gate 整函数保持原生; 原生执行即 #UD (415 同款教训), **禁入可执行
//     路径** — 本文件只取函数地址 (链接保活) 不调用, gate 证据 = protect
//     日志 (lifter 跳过 note)。F0 F3 A4 由 lifter 单测覆盖 (415 已有)。
//
// 验收: multiseed (REQUIRE_REAL=1) 37 样本 × 5 = 185/185 — 本样本主函数
// 真虚拟化 (stub ≥1); e2e 日志含 "lock-strip @ ... strip-and-execute" 命中
// note ×6 (xadd32/xadd64/bts/btr/btc/cmpxchg_rip 各 1; 裸 xchg 无 lock 前缀
// 无 note) + 负例 gate note ×2; 双跑 stdout+rc byte-exact。

#include "wvmp/sdk/markers.hpp"

#include <intrin.h>
#include <cstdio>

// ---- MASM 侧全局 (rip-relative 目标) ----
extern "C" volatile long long g_at_cmpx = 7;

// MASM 侧实现 (wvmp_atomic_ops_sample_asm.asm)。
extern "C" unsigned long wv_at_xadd32(volatile long* p, long v);
extern "C" unsigned long long wv_at_xadd64(volatile long long* p, long long v);
extern "C" unsigned long wv_at_bts_imm(volatile long* p);
extern "C" unsigned long wv_at_btr_imm(volatile long* p);
extern "C" unsigned long wv_at_btc_reg(volatile long* p, long bit);
extern "C" unsigned long wv_at_xchg_mem(volatile long* p, long v);
extern "C" unsigned long long wv_at_cmpxchg_rip(long long old_v, long long new_v);
extern "C" void wv_at_neg_lock_mov(void);
extern "C" void wv_at_neg_lock_nop(void);

// ---- C++ Interlocked* 真产物形态的全局 ----
extern "C" volatile long g_cpp_add = 10;
extern "C" volatile long g_cpp_and = 0xFF;
extern "C" volatile long g_cpp_or = 0x100;
extern "C" volatile long g_cpp_xor = 0x200;
extern "C" volatile long g_cpp_ex = 1000;
extern "C" volatile long g_cpp_cmpx = 42;

// C++ 主区域: Interlocked* intrinsic 真产物 (/Od: call 编译器生成 helper,
// helper 内含 lock 单指令; 区域内 call → callgate → helper 原生执行 —
// 语义断言照旧, helper 字节见报告 §3 反汇编表)。全部带返回值使用,
// 旧值/命中语义由返回值和最终全局值双断言覆盖。
__declspec(noinline) unsigned long long cpp_atomic_region() {
    unsigned long long old_add = 0, old_ex = 0, old_cmpx = 0;
    WVMP_BEGIN(cpp_atomic_region);
    old_add = (unsigned long)_InterlockedExchangeAdd(&g_cpp_add, 5);   // → lock xadd
    _InterlockedAnd(&g_cpp_and, 0x0F);                                 // → lock and [m],imm
    _InterlockedOr(&g_cpp_or, 0x10);                                   // → lock or [m],imm
    _InterlockedXor(&g_cpp_xor, 0x20);                                 // → lock xor [m],imm
    old_ex = (unsigned long)_InterlockedExchange(&g_cpp_ex, 42);       // → xchg [m],r (裸)
    old_cmpx = (unsigned long)_InterlockedCompareExchange(&g_cpp_cmpx, 7, 9);  // → lock cmpxchg
    WVMP_END(cpp_atomic_region);
    return old_add + old_ex + old_cmpx;
}

int main() {
    volatile unsigned long long ok = 1;

    // ---- MASM 正例全谱 ----
    // ① lock xadd dword: 旧值返回
    volatile long g1 = 10;
    unsigned long r = wv_at_xadd32(&g1, 5);
    std::printf("xadd32: old=%lu new=%ld\n", r, (long)g1);
    ok &= (r == 10) && (g1 == 15);

    // ② lock xadd qword (REX.W)
    volatile long long g2 = 0x1000000000LL;  // 跨 32 位边界, 逼 64 位语义
    unsigned long long r2 = wv_at_xadd64(&g2, 0x2000000001LL);
    std::printf("xadd64: old=%llx new=%llx\n", r2, (long long)g2);
    ok &= (r2 == 0x1000000000LL) && (g2 == 0x3000000001LL);

    // ③ lock bts imm8: 旧位返回 (0→置位返回 0; 再置返回 1)
    volatile long g3 = 0;
    unsigned long b = wv_at_bts_imm(&g3);
    std::printf("bts(0): oldbit=%lu val=%lx\n", b, (long)g3);
    ok &= (b == 0) && (g3 == 8);
    b = wv_at_bts_imm(&g3);
    std::printf("bts(1): oldbit=%lu val=%lx\n", b, (long)g3);
    ok &= (b == 1) && (g3 == 8);

    // ④ lock btr imm8
    unsigned long b4 = wv_at_btr_imm(&g3);
    std::printf("btr(1): oldbit=%lu val=%lx\n", b4, (long)g3);
    ok &= (b4 == 1) && (g3 == 0);
    b4 = wv_at_btr_imm(&g3);
    std::printf("btr(0): oldbit=%lu val=%lx\n", b4, (long)g3);
    ok &= (b4 == 0) && (g3 == 0);

    // ⑤ lock btc reg 位号
    volatile long g5 = 0;
    unsigned long b5 = wv_at_btc_reg(&g5, 5);
    std::printf("btc(0): oldbit=%lu val=%lx\n", b5, (long)g5);
    ok &= (b5 == 0) && (g5 == 0x20);
    b5 = wv_at_btc_reg(&g5, 5);
    std::printf("btc(1): oldbit=%lu val=%lx\n", b5, (long)g5);
    ok &= (b5 == 1) && (g5 == 0);

    // ⑥ 裸 xchg [m], r (InterlockedExchange 形态)
    volatile long g6 = 0x1234;
    unsigned long r6 = wv_at_xchg_mem(&g6, 0xABCD);
    std::printf("xchg_mem: old=%lx new=%lx\n", r6, (long)g6);
    ok &= (r6 == 0x1234) && (g6 == 0xABCD);

    // ⑦ lock cmpxchg rip 目标 + je 惯用法 (ZF 读回): 命中 → [g]=new 返回 1
    g_at_cmpx = 7;
    unsigned long long h = wv_at_cmpxchg_rip(7, 77);   // 命中: old==7
    std::printf("cmpxchg_rip(hit): hit=%llu val=%lld\n", h, (long long)g_at_cmpx);
    ok &= (h == 1) && (g_at_cmpx == 77);
    h = wv_at_cmpxchg_rip(7, 88);                      // 未命中: [g]==77 != 7
    std::printf("cmpxchg_rip(miss): hit=%llu val=%lld\n", h, (long long)g_at_cmpx);
    ok &= (h == 0) && (g_at_cmpx == 77);

    // ---- C++ Interlocked* 真产物区域 ----
    unsigned long long acc = cpp_atomic_region();
    std::printf("cpp_region: old_add+old_ex+old_cmpx=%llx\n", acc);
    // xadd 旧值 10 + xchg 旧值 1000 + cmpxchg 旧值 42 (9 != 42 → 未命中 →
    // 返回旧值 42, [m] 不变); And/Or/Xor 无返回值 (折叠 lock and/or/xor),
    // 旧值语义由最终全局值断言覆盖
    unsigned long long expect = 10u + 1000u + 42u;
    ok &= (acc == expect);
    ok &= (g_cpp_add == 15) && (g_cpp_and == 0x0F) && (g_cpp_or == 0x110) &&
          (g_cpp_xor == 0x220) && (g_cpp_ex == 42) && (g_cpp_cmpx == 42);

    // ---- 负例: 只取地址保活, **不调用** (原生 #UD 禁入可执行路径) ----
    // (地址值受 ASLR 影响不可打印 — 会破坏 byte-exact 双跑; 只打印布尔)
    int neg_refs = ((void*)&wv_at_neg_lock_mov != nullptr) &&
                   ((void*)&wv_at_neg_lock_nop != nullptr);
    std::printf("neg_refs=%d\n", neg_refs);
    ok &= (neg_refs == 1);

    std::printf("ok=%llu\n", (unsigned long long)ok);
    return ok == 1 ? 0 : 2;
}
