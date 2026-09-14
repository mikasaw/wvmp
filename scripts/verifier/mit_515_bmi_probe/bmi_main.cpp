// MIT-515 (T67) BMI G8b 决策备忘录实测探针 — main 驱动
//   1) CPU 识别 + BMI2 支持位
//   2) mulx CF/ZF 保持性 (stc+xor 预置 → mulx → pushfq 提取)
//   3) pdep/pext 值语义 vs 软件参考
#include <intrin.h>
#include <cstdio>
#include <cstring>

extern "C" {
    unsigned int mulx_cf_probe(unsigned int a, unsigned int b);
    unsigned int pdep_probe(unsigned int x, unsigned int mask);
    unsigned int pext_probe(unsigned int x, unsigned int mask);
}

int main() {
    char brand[49] = {};
    for (int leaf = 0x80000002; leaf <= 0x80000004; ++leaf) {
        int r[4];
        __cpuidex(r, leaf, 0);
        std::memcpy(brand + (leaf - 0x80000002) * 16, r, 16);
    }
    std::printf("brand: %s\n", brand);
    int info[4] = {};
    __cpuid(info, 0);
    std::printf("max leaf: 0x%X vendor: %.4s%.4s%.4s\n", info[0],
                (const char*)&info[1], (const char*)&info[3], (const char*)&info[2]);
    int f1[4] = {}, f7[4] = {};
    __cpuid(f1, 1);
    __cpuidex(f7, 7, 0);
    std::printf("BMI1=%d BMI2=%d ADX=%d AVX=%d AVX2=%d\n",
                (f7[1] >> 3) & 1, (f7[1] >> 8) & 1, (f7[1] >> 19) & 1,
                (f1[2] >> 28) & 1, (f7[1] >> 5) & 1);

    // mulx CF/ZF: 期望 (SDM: 不修改任何标志) = (CF=1 保持 << 1) | (ZF=1 保持) = 3
    struct { unsigned int a, b; } cases[] = {
        {0xFFFFFFFFu, 0xFFFFFFFFu}, {0x80000000u, 2u},
        {1u, 1u}, {0xDEADBEEFu, 0xCAFEBABEu},
    };
    for (const auto& c : cases) {
        const unsigned int r = mulx_cf_probe(c.a, c.b);
        std::printf("mulx a=%08X b=%08X -> CF_after=%u ZF_after=%u (期望 1/1 = SDM 不修改)\n",
                    c.a, c.b, (r >> 1) & 1, r & 1);
    }

    // pdep/pext 对拍
    struct { unsigned int x, m; } pc[] = {
        {0xFFFFFFFFu, 0x0000FFFFu}, {0x12345678u, 0x0000FF00u},
        {0xDEADBEEFu, 0x00FF00FFu}, {1u, 0x80000000u},
    };
    int fails = 0;
    for (const auto& c : pc) {
        const unsigned int got_dep = pdep_probe(c.x, c.m);
        const unsigned int got_ext = pext_probe(c.x, c.m);
        unsigned int want_dep = 0, ref_ext = 0, bn = 0;
        for (int i = 0; i < 32; ++i) {
            if (c.m & (1u << i)) {
                want_dep |= ((c.x >> bn) & 1u) << i;         // pdep: x 的 bit bn → 第 bn 个 mask=1 位 i
                if (c.x & (1u << i)) ref_ext |= 1u << bn;    // pext: mask=1 的 x 位压缩
                ++bn;
            }
        }
        std::printf("pdep x=%08X m=%08X got=%08X ref=%08X %s | pext got=%08X ref=%08X %s\n",
                    c.x, c.m, got_dep, want_dep, (got_dep == want_dep ? "OK" : "MISMATCH"),
                    got_ext, ref_ext, (got_ext == ref_ext ? "OK" : "MISMATCH"));
        if (got_dep != want_dep || got_ext != ref_ext) ++fails;
    }
    std::printf("pdep/pext fails=%d\n", fails);
    return fails;
}
