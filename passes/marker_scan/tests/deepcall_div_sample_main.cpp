// MIT-406 (MIT-E1): 组合形态样本 — 区域内 div/idiv (MIT-404 除法族路径,
// Rax/Rdx 商余双槽写回) 与深 call (MIT-406 callee 窗口) 共存, 验证窗口
// 切换与除法防护机制互不干扰 (派活单 §B.7 / §C D4.1)。
//
// 区域指令序: div MEM (xor edx,edx + div [mem]) → 深调用 CallGate (12 层
// x 0x60B = 0x480B 树深, 旧预算 0x1D8 下修复前必砸 ctx) → idiv MEM
// (cdq + idiv [mem], 负数截断向零) → call 之后再 div — 后半段的商余值
// 只有 VM 状态跨 native call 完整存活才能与原生一致:
//   - ctx 槽 (pc/flags/base/native_sp) 被砸 → CallGate 返回即毁 (修复前);
//   - 窗口修复后 callee 树在 host_rsp 下方, 与 ctx 零重叠 → byte-exact。
//
// 递归本体复用 deepcall_sample_asm.asm 的 deep_recurse (链接进本 target),
// MSVC x64 不支持 inline asm, volatile 除法由 /Od 稳定产 cdq/xor-edx +
// div/idiv MEM 形式 (同 div_sample 的 div32_mem/idiv32_mem 模式)。

#include "wvmp/sdk/markers.hpp"

#include <cstdint>
#include <cstdio>

extern "C" uint64_t deep_recurse(uint64_t levels, uint64_t acc);

__declspec(noinline) static unsigned long long deepcall_div_vm() {
    WVMP_BEGIN(deepcall_div_vm);
    volatile unsigned int a = 0x7FFFFFF0u;
    volatile unsigned int b = 7u;
    const unsigned int q1 = a / b;                        // div MEM: 商 0x124924D8 余 4
    const unsigned int r1 = a % b;
    // 深 call: levels=12, acc=q1 — CallGate native 执行 0x480B 递归树。
    const unsigned long long deep = deep_recurse(12, q1);
    volatile int m = -77;
    volatile int n = 6;
    const int iq = m / n;                                 // cdq + idiv MEM: q=-12 r=-5
    const int ir = m % n;
    volatile unsigned int c = 1000000u;
    volatile unsigned int d = 33u;
    const unsigned int q2 = c / d;                        // call 之后再 div
    WVMP_END(deepcall_div_vm);
    return deep ^ (static_cast<unsigned long long>(r1) << 32) ^
           static_cast<unsigned long long>(q1) ^
           (static_cast<unsigned long long>(static_cast<unsigned int>(iq)) << 16) ^
           static_cast<unsigned long long>(static_cast<unsigned int>(ir)) ^
           static_cast<unsigned long long>(q2);
}

int main() {
    const unsigned long long r = deepcall_div_vm();
    std::printf("deepcall_div=%016llx\n", r);
    std::fflush(stdout);
    return 0;
}
