// MIT-404: 端到端主样本——区域内含整数除法族 cdq/cdqe/cqo + div/idiv
// (REG + MEM + rip 形式除数), 验证整数除法支持后翻译成功、运行时走真
// Cdq/Div/Idiv handler、行为与原生逐字节一致 (商/余/负数组合值正确)。
//
// 设计要点 (沿用 setcc/xchg 模式):
//   - MSVC x64 不支持 inline asm; C++ volatile 除法只能产 cdq+idiv MEM 形式,
//     REG 形式 / cdqe / rip 除数由 div_sample_asm.asm (MASM) 直接 emit。
//   - 区域**只含白名单**: mov/load/store/lea/cdq/cqo/cdqe/div/idiv/shift/or,
//     不含 printf / call（printf 在区域外）。
//   - 商/余双槽回读: div 后 rax=商 rdx=余, 32 位打包 (r<<32)|q 一并返回,
//     64 位经 out 数组双槽返回 — Div/Idiv handler 的 Rax/Rdx 双结果槽
//     写回一旦空转/错槽即与原生不一致 (FAIL)。
//   - 末尾 div_zero_crash: cdq + idiv [rsp+..] 除零 → 真 #DE native 直通
//     (D2.1 决策) — native 与 packed 同为 0xC0000094 形态崩溃, printf +
//     fflush 后触发, 满足 AC #5 除零对拍。

#include "wvmp/sdk/markers.hpp"

#include <cstdint>
#include <cstdio>

extern "C" uint64_t div32_reg(uint32_t a, uint32_t b);
extern "C" void     div64_reg(uint64_t a, uint64_t b, uint64_t out[2]);
extern "C" uint64_t div32_mem(uint32_t a, uint32_t b);
extern "C" void     idiv64_reg(int64_t a, int64_t b, int64_t out[2]);
extern "C" uint64_t idiv32_mem(int32_t a, int32_t b);
extern "C" int64_t  cdqe_probe(int32_t v);
extern "C" uint64_t div32_rip(uint32_t a);

// rip 形式除数的全局 (C 链接, MASM EXTERNDEF g_rip_divisor:DWORD)。
// 7 保证非零 — rip 形式覆盖只验证读通路, 除零对拍由 div_zero_crash 专职。
extern "C" volatile uint32_t g_rip_divisor = 7;

// 除零崩溃探针 (AC #5): volatile 强制 MSVC /Od 产 mov eax,imm + cdq +
// idiv dword ptr [rsp+..] (MEM 形式), 全在 marker 区域内 → 真虚拟化路径上
// native div 直通 #DE。放 main 末尾 printf+fflush 之后。
__declspec(noinline) static int div_zero_crash() {
    WVMP_BEGIN(div_zero_crash);
    volatile int32_t zero = 0;
    const int32_t q = static_cast<int32_t>(0x78563412) / zero;
    WVMP_END(div_zero_crash);
    return q;
}

int main() {
    // div32_reg: a=INT_MAX 为正, cdq → edx=0, 64 位被除数 = 0x7FFFFFFF,
    // ÷7 商 32 位内。⚠️ div32 配负数 a 会商溢出 #DE (0xC0000095) — cdq 把
    // 负 eax 扩成 0xFFFFFFFF 高位, 商必超 32 位; 负数语义属 idiv (D3.1)。
    const uint64_t d32 = div32_reg(0x7FFFFFFFu, 7);
    uint64_t d64[2] = {0, 0};
    div64_reg(0x123456789ABCDEFull, 1000, d64);
    const uint64_t d32m = div32_mem(1000000u, 7);
    // idiv 负数组合 (D3.1 截断向零): -7/2 → q=-3 r=-1。
    int64_t id64[2] = {0, 0};
    idiv64_reg(-7, 2, id64);
    const uint64_t id32m = idiv32_mem(-7, 2);
    // cdqe: -5 → 0xFFFFFFFFFFFFFFFB (X86_INS_CDQE 归一 Movsxd, D1.1)。
    const int64_t cqe = cdqe_probe(-5);
    // rip 形式除数: 100/7 → 商 14 余 2。
    const uint64_t drip = div32_rip(100u);

    std::printf(
        "div32=%016llx div64q=%016llx div64r=%016llx div32mem=%016llx\n",
        static_cast<unsigned long long>(d32),
        static_cast<unsigned long long>(d64[0]),
        static_cast<unsigned long long>(d64[1]),
        static_cast<unsigned long long>(d32m));
    std::printf(
        "idiv64q=%lld idiv64r=%lld idiv32mem=%016llx cdqe=%016llx divrip=%016llx\n",
        static_cast<long long>(id64[0]),
        static_cast<long long>(id64[1]),
        static_cast<unsigned long long>(id32m),
        static_cast<unsigned long long>(cqe),
        static_cast<unsigned long long>(drip));
    std::fflush(stdout);

    // 除零对拍 (AC #5): native 与 packed 均应 #DE 崩溃 (0xC0000094 形态)。
    (void)div_zero_crash();
    return 0;
}
