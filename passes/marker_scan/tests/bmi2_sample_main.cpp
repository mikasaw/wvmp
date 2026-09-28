// MIT-534 (G8b 通路 A): BMI2 样本 — mulx/pdep/pext 真虚拟化。
// 词面经 MSVC 内建 (_mulx_u64/_pdep_u64/_pext_u64) 直发 64 位形
// (手写 MASM 的 mulx 首目的=HIGH 与 keystone 相反、pdep/pext 会被汇编成
// 32 位形——两个 ml64 实测坑, 故本样本走内建; 语义判据不变)。
// REQUIRE_REAL: 正例区域真虚拟化 (stub ≥1); require_bmi2=false 的 gate 面
// 由 protect 配置驱动 (池外/E2E 验证)。
#include <cstdio>
#include <cstdint>
#include <intrin.h>

#include "wvmp/sdk/markers.hpp"

extern "C" void bmi2_reg(void* dst16x4, std::uint64_t a, std::uint64_t m);

__declspec(noinline) static void bmi2_mulx(std::uint64_t* dst, std::uint64_t src) {
    WVMP_BEGIN(bmi2_mulx);
    std::uint64_t hi = 0;
    const std::uint64_t lo = _mulx_u64(src, src, &hi);   // MULX 词
    dst[0] = lo;
    dst[1] = hi;
    WVMP_END(bmi2_mulx);
}

__declspec(noinline) static std::uint64_t bmi2_pdp(std::uint64_t* rt, std::uint64_t x,
                                                   std::uint64_t m) {
    WVMP_BEGIN(bmi2_pdp);
    const std::uint64_t pd = _pdep_u64(x, m);            // PDEP 词
    const std::uint64_t pe = _pext_u64(pd, m);           // PEXT 词 (往返)
    *rt = pe;
    WVMP_END(bmi2_pdp);
    return pd;
}

int main() {
    int fails = 0;

    // ① mulx: src × src 全积 (软件参考 _umul128)
    const std::uint64_t src = 0x1234'5678'9ABC'DEF0ull;
    std::uint64_t prod[2] = {0, 0};
    bmi2_mulx(prod, src);
    std::uint64_t hi_ref = 0;
    const std::uint64_t lo_ref = _umul128(src, src, &hi_ref);  // MSVC 64x64→128
    if (prod[0] != lo_ref || prod[1] != hi_ref) {
        std::printf("FAIL mulx got=%016llX:%016llX want=%016llX:%016llX\n",
                    (unsigned long long)prod[1], (unsigned long long)prod[0],
                    (unsigned long long)hi_ref, (unsigned long long)lo_ref);
        ++fails;
    }

    // ② pdep/pext 往返不变量: pdep 把 x 的连续低位装进掩码位, pext 抽回 ⇒
    // rt == x 的低 popcount(m) 位 (非 x&m —— 该"恒等"仅掩码低位连续时成立)。
    const std::uint64_t x = 0xF0F0'0F0F'55AA'55AAull;
    const std::uint64_t m = 0x00FF'00FF'00FF'00FFull;
    std::uint64_t rt = 0;
    const std::uint64_t pdep_val = bmi2_pdp(&rt, x, m);
    std::uint64_t pdep_ref = 0;
    std::uint64_t rt_ref = 0;
    {
        int pc = 0;
        for (int i = 0; i < 64; ++i)
            if ((m >> i) & 1u) ++pc;
        int n = 0;
        for (int i = 0; i < 64; ++i)
            if ((m >> i) & 1u) { pdep_ref |= ((x >> n) & 1u) << i; ++n; }
        // rt_ref = x 的低 popcount 位
        rt_ref = (pc == 64) ? x : (x & ((1ull << pc) - 1u));
    }
    if (pdep_val != pdep_ref) {
        std::printf("FAIL pdep got=%016llX want=%016llX\n",
                    (unsigned long long)pdep_val, (unsigned long long)pdep_ref);
        ++fails;
    }
    if (rt != rt_ref) { std::printf("FAIL pdep/pext 往返\n"); ++fails; }

    // ③ reg 形 (asm): mulx lo/hi + pdep + pext 往返 (词面真虚拟化载体)
    {
        const std::uint64_t a = 0x2468'ACE1'3579'BDF0ull;
        const std::uint64_t mm = 0x0F0F'0F0F'0F0F'0F0Full;
        std::uint64_t out[4] = {0, 0, 0, 0};
        bmi2_reg(out, a, mm);
        std::uint64_t h2 = 0;
        const std::uint64_t l2 = _umul128(a, a, &h2);
        std::uint64_t pd_ref = 0;
        int n2 = 0, pc2 = 0;
        for (int i = 0; i < 64; ++i)
            if ((mm >> i) & 1u) ++pc2;
        for (int i = 0; i < 64; ++i)
            if ((mm >> i) & 1u) { pd_ref |= ((a >> n2) & 1u) << i; ++n2; }
        const std::uint64_t rt_ref = a & ((1ull << pc2) - 1u);
        if (out[0] != l2 || out[1] != h2) {
            std::printf("FAIL reg mulx got=%016llX:%016llX want=%016llX:%016llX\n",
                        (unsigned long long)out[1], (unsigned long long)out[0],
                        (unsigned long long)h2, (unsigned long long)l2);
            ++fails;
        }
        if (out[2] != pd_ref) { std::printf("FAIL reg pdep\n"); ++fails; }
        if (out[3] != rt_ref) { std::printf("FAIL reg pext\n"); ++fails; }
    }

    if (fails == 0) std::printf("ALL OK\n");
    return fails;
}
