// MIT-423 (G4b): lock inc/dec 原子补齐 E2E 样本主程序。
//
// 形态 (派活单 §B.5):
//   * MASM 侧 (wvmp_atomic_incdec_sample_asm.asm): 裸 lock inc/dec 全谱 —
//     dword/qword 双宽、rip-relative 目标、add→CF=1→lock inc→jc CF 保真
//     探针 (SDM: inc/dec 不写 CF)、dec r8d; jnz 循环计数惯用法。区域 VM 化
//     走本体折条 (D1: 零新 VmOp — Load→Inc/Dec→Store, note 披露)。
//   * C++ 侧 (本文件): _InterlockedIncrement/Decrement intrinsic 真产物。
//     **#33 实测推翻先验** (probe_incdec.cpp, cl v145 14.51 /O2 与 /Od 双档
//     /FAcs 实证): MSVC 对 _InterlockedIncrement/Decrement/64 产
//     **lock xadd [m],±1 + inc/dec reg** (返回值语义决定), **不产裸 lock
//     inc/dec** — 真产物路径 = 419 已收口的 VmOp::Xadd 硬件原子通路 + 普通
//     reg-dst inc/dec 本体通路; 本单补齐的裸 lock inc/dec 形态属手写/
//     第三方面 (MASM 侧直写覆盖)。派活单 §A.3 "f0 ff 06" 先验被实测推翻。
//   * 负例 (D2):
//     - wv_id_neg_lock_not: db F0 48 F7 11 (lock not qword ptr [rcx], F7 /2
//       modrm 11h) — SDM 合法编码 (capstone id=511 可解) 但无 MSVC 产物
//       (无 InterlockedNot intrinsic) → D2 裁决 gate; **可调用** (整函数
//       保持原生, 原生执行合法 — probe3 实测本机正常退出, C1 gate 行为
//       保真的正证)。
//     - wv_id_neg_lock_inc_reg: db F0 FF C1 (lock inc ecx, reg-dst 非法编码)
//       — capstone 拒解码 → skipped_ranges → gate; 原生执行 #UD **禁入可执行
//       路径** (只取地址, 419 负例同款)。
//
// 验收: multiseed 38 样本 × 5 = 190/190 — MASM 正例 5 函数 + C++ 区域
// 真虚拟化 (stub ≥1); lock-strip note 命中 ×7 (inc32/inc64/dec32/dec64/
// inc_rip/loop_inc/cf_inc 各 1); 双跑 stdout+rc byte-exact。

#include "wvmp/sdk/markers.hpp"

#include <intrin.h>
#include <cstdio>

// ---- MASM 侧全局 (rip-relative 目标) ----
extern "C" volatile long long g_id_rip = 0x4000000000LL;

// MASM 侧实现 (wvmp_atomic_incdec_sample_asm.asm)。
extern "C" void wv_id_inc32(volatile long* p);
extern "C" void wv_id_inc64(volatile long long* p);
extern "C" void wv_id_dec32(volatile long* p);
extern "C" void wv_id_dec64(volatile long long* p);
extern "C" unsigned long long wv_id_inc_rip();
extern "C" unsigned long long wv_id_loop_inc(volatile long* p);
extern "C" unsigned long long wv_id_inc_cf(volatile long* p);
extern "C" long long wv_id_neg_lock_not(volatile long long* p);
extern "C" void wv_id_neg_lock_inc_reg(void);

// ---- C++ _Interlocked* 真产物区域的全局 ----
extern "C" volatile long g_cpp_cnt32 = 100;
extern "C" volatile long long g_cpp_cnt64 = 0x1000000000LL;

// C++ 主区域: _InterlockedIncrement/Decrement 真产物 — /Od 下 intrinsic
// 内联展开 (probe /FAcs 实证): lock xadd [m],1 + inc reg。区域内 lock xadd
// 走 419 Xadd 硬件原子通路, inc reg 走普通一元通路 — 全区真虚拟化。
__declspec(noinline) long long cpp_incdec_region() {
    WVMP_BEGIN(cpp_incdec_region);
    const long v32 = _InterlockedIncrement(&g_cpp_cnt32);        // → xadd+inc
    const long d32 = _InterlockedDecrement(&g_cpp_cnt32);        // → xadd+dec
    const long long v64 = _InterlockedIncrement64(&g_cpp_cnt64); // → xadd+inc
    WVMP_END(cpp_incdec_region);
    return (static_cast<long long>(v32) << 32) ^
           (static_cast<long long>(static_cast<unsigned long>(d32)) << 8) ^ v64;
}

int main() {
    volatile unsigned long long ok = 1;

    // ---- MASM 正例全谱 ----
    // ① lock inc dword
    volatile long g1 = 41;
    wv_id_inc32(&g1);
    std::printf("inc32: %ld\n", (long)g1);
    ok &= (g1 == 42);

    // ② lock inc qword (REX.W, 跨 32 位边界)
    volatile long long g2 = 0xFFFFFFFFFFFFLL;
    wv_id_inc64(&g2);
    std::printf("inc64: %llx\n", (long long)g2);
    ok &= (g2 == 0x1000000000000LL);

    // ③ lock dec dword
    volatile long g3 = 43;
    wv_id_dec32(&g3);
    std::printf("dec32: %ld\n", (long)g3);
    ok &= (g3 == 42);

    // ④ lock dec qword
    volatile long long g4 = 0x1000000000000LL;
    wv_id_dec64(&g4);
    std::printf("dec64: %llx\n", (long long)g4);
    ok &= (g4 == 0xFFFFFFFFFFFFLL);

    // ⑤ lock inc qword [rip+disp] (rip 目标变体, 返回递增后全局值)
    g_id_rip = 0x4000000000LL;
    const unsigned long long r5 = wv_id_inc_rip();
    std::printf("inc_rip: %llx\n", r5);
    ok &= (r5 == 0x4000000001ULL) && (g_id_rip == 0x4000000001LL);

    // ⑥ 循环计数语义校验: lock inc 体 × 7 (dec r8d; jnz 循环惯用法)
    volatile long g6 = 0;
    const unsigned long long r6 = wv_id_loop_inc(&g6);
    std::printf("loop_inc: cnt=%ld rounds=%llu\n", (long)g6, r6);
    ok &= (g6 == 7) && (r6 == 7);

    // ⑦ CF 保真探针 (SDM: inc 不写 CF) — 返回位 0: CF=1 探针 (add 写 CF=1
    //    → lock inc → jc 必须命中), 位 1: CF=0 探针 (add CF=0 → lock inc →
    //    jc 必须不命中)。全 VM flags 槽往返 (Add 全量装配 → Inc 保留 CF →
    //    Jcc 读槽)。
    volatile long g7 = 0;
    const unsigned long long r7 = wv_id_inc_cf(&g7);
    std::printf("inc_cf: probe=%llx val=%ld\n", r7, (long)g7);
    ok &= (r7 == 3) && (g7 == 2);

    // ---- C++ _Interlocked* 真产物区域 (lock xadd +1 内联展开) ----
    const long long acc = cpp_incdec_region();
    std::printf("cpp_region: acc=%llx cnt32=%ld cnt64=%llx\n", acc,
                (long)g_cpp_cnt32, (long long)g_cpp_cnt64);
    // v32 = 101 (inc 返回新值), d32 = 100 (dec 返回新值 = 101-1),
    // v64 = 0x1000000001; 终值 cnt32 = 101-1 = 100
    // acc = (101<<32) ^ (100<<8) ^ 0x1000000001
    const long long expect =
        (101LL << 32) ^ (100LL << 8) ^ 0x1000000001LL;
    ok &= (acc == expect);
    ok &= (g_cpp_cnt32 == 100) && (g_cpp_cnt64 == 0x1000000001LL);

    // ---- D2 负例 ①: lock not — gate 保持原生, **可调用** (行为保真正证) ----
    volatile long long g8 = 0x0F0F0F0F0F0F0F0FLL;
    const long long r8 = wv_id_neg_lock_not(&g8);
    std::printf("neg_lock_not: val=%llx ret=%llx\n",
                (long long)g8, (long long)r8);
    ok &= (r8 == 0x0F0F0F0F0F0F0F0FLL) &&
          (g8 == ~0x0F0F0F0F0F0F0F0FLL);  // 原生执行结果 (gate 后原生跑)

    // ---- D2 负例 ②: lock inc ecx (reg-dst 非法) — 只取地址不调用
    // (原生 #UD 禁入可执行路径; gate 证据 = protect 日志) ----
    const int neg_reg = ((void*)&wv_id_neg_lock_inc_reg != nullptr);
    std::printf("neg_reg_refs=%d\n", neg_reg);
    ok &= (neg_reg == 1);

    std::printf("ok=%llu\n", (unsigned long long)ok);
    return ok == 1 ? 0 : 2;
}
