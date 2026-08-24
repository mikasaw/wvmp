// MIT-301: 端到端正路径样本——区域内含 cl 变体 shift (D3 /5: shl/shr/sar),
// 验证 cl 变体 shift 修复后翻译成功、运行时走真 ShlCl/ShrCl/SarCl handler、
// 行为与原生逐字节一致。
//
// 设计要点 (沿用 sar_sample 模式):
//   - sar_sample 已实测: MSVC /Od 对 `>> n` / `<< n` (n = 函数参数, 非常量)
//     codegen 为 cl 变体 (D3 /5) —— 看 sar_sample 反汇编可见:
//       48 D3 F8   sar rax, cl
//   - count 参数**用 32 位整数** (unsigned int), MSVC 直接 `mov ecx, [rsp+xxh]`
//     不发 movzx (零扩展从 8 位到 32 位需要 movzx; 32 位到 32 位零扩展
//     只需 mov 即可)。这样区域内不引入未实现指令 movzx, 完整可虚拟化。
//   - cl 是 RCX/ECX 低 8 位, 32 位值入 ECX 后, shl rax, cl 仍按 cl (低 8 位)
//     工作, 行为与 sar_sample 等价 (count 自动 mod 32/64 按 host CPU 规则)。
//   - 用 volatile 防 MSVC 把 r 提升为常量（每次写都重新读 g_x）。
//
// 区域约束 (M2-4 沿用):
//   - 不含 rip-relative (g_x 是 volatile 读取, 编译器可能 codegen 为
//     [rip+disp] 全局访存——已 C1 gate 兜底; 但本样本移除了 volatile 全局
//     读取, 改用函数参数, 避免 rip-relative 混入区域)。
//   - 不含 printf / call / 内存访存: 纯白名单直算, 验证完整可虚拟化路径。

#include "wvmp/sdk/markers.hpp"

#include <cstdint>
#include <cstdio>

// shl_cl: r = x << count (count 来自函数参数, MSVC codegen 为 cl 变体)。
// MSVC /Od 下内联汇编:
//   mov ecx, dword ptr [rsp+xxh]   ; 加载 count (32 位, 无 movzx)
//   shl rax, cl                    ; D3 E0 (cl 变体)
__declspec(noinline) static unsigned long long shl_cl(unsigned long long x, unsigned int count) {
    WVMP_BEGIN(shl_cl);
    unsigned long long r = x << count;     // shl rax, cl
    r ^= 0xDEADBEEFCAFEBABEull;
    WVMP_END(shl_cl);
    return r;
}

// shr_cl: r = x >> count (MSVC codegen 为 shr rax, cl, D3 E8)。
__declspec(noinline) static unsigned long long shr_cl(unsigned long long x, unsigned int count) {
    WVMP_BEGIN(shr_cl);
    unsigned long long r = x >> count;     // shr rax, cl
    r ^= 0x123456789ABCDEF0ull;
    WVMP_END(shr_cl);
    return r;
}

// sar_cl: r = (signed)x >> count (MSVC codegen 为 sar rax, cl, D3 F8)。
__declspec(noinline) static long long sar_cl(long long x, unsigned int count) {
    WVMP_BEGIN(sar_cl);
    long long r = x >> count;              // sar rax, cl
    r &= 0xFFFFull;                        // 取低 16 位
    WVMP_END(sar_cl);
    return r;
}

// 多次 cl 变体串联: shl + shr + sar 验证完整链路。
// MSVC /Od 内联汇编 (实测同 sar_sample 模式):
//   48 D3 E0   shl rax, cl         ; D3 /4 (cl 变体)
//   48 D3 E8   shr rax, cl         ; D3 /5
//   48 D3 F8   sar rax, cl         ; D3 /7
__declspec(noinline) static unsigned long long shl_shr_sar_chain(unsigned long long x,
                                                                unsigned int c1,
                                                                unsigned int c2,
                                                                unsigned int c3) {
    WVMP_BEGIN(shl_shr_sar_chain);
    unsigned long long r = x << c1;        // shl rax, cl
    r = r >> c2;                           // shr rax, cl
    long long s = static_cast<long long>(r) >> c3; // sar rax, cl
    r = static_cast<unsigned long long>(s);
    WVMP_END(shl_shr_sar_chain);
    return r;
}

int main() {
    // 用函数参数传入 count —— MSVC codegen 为 cl 变体核心条件: count 不能
    // 是编译期常量 (用 literal 常量会让 MSVC 用 imm 形式 C1 /4 ib)。
    const unsigned long long a = shl_cl(0x12345678ull, 5);                  // 0x2468ACF0
    const unsigned long long b = shr_cl(0xCAFEBABEull, 8);                 // 0x00CAFEBB
    const long long c = sar_cl(-1024LL, 1);                                 // sar -1024, 1 = -512
    const unsigned long long d = shl_shr_sar_chain(0x1000ull, 4, 2, 1);    // 链式
    std::printf("a=%llx b=%llx c=%lld d=%llx\n",
                static_cast<unsigned long long>(a),
                static_cast<unsigned long long>(b),
                static_cast<long long>(c),
                static_cast<unsigned long long>(d));
    return 0;
}