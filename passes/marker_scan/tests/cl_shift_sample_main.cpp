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
// MIT-345: 区域内增加 movzx 8→16 / 16→64 验证 (0F B7 形式):
//   - movzx_8_16(unsigned char) -> unsigned short: MSVC /Od emit `movzx ax, cl`
//     (0x66 0F B6 C1 类字节, 3 字节含 0x66 prefix).
//   - movzx_16_64(unsigned short) -> unsigned long long: MSVC /Od emit
//     `movzx rax, bx` (REX.W + 0F B7, 4 字节).
//   - 用 volatile 接收返回值防 MSVC 优化掉。
//
// 区域约束 (M2-4 沿用):
//   - 不含 rip-relative (g_x 是 volatile 读取, 编译器可能 codegen 为
//     [rip+disp] 全局访存——已 C1 gate 兜底; 但本样本移除了 volatile 全局
//     读取, 改用函数参数, 避免 rip-relative 混入区域)。
//   - 不含 printf / call / 内存访存: 纯白名单直算, 验证完整可虚拟化路径。

#include "wvmp/sdk/markers.hpp"

#include <bit>        // std::popcount / std::countl_zero / std::countr_zero (C++20)
#include <cstdint>
#include <cstdio>

// popcnt 函数由 cl_shift_sample_asm.asm (MASM) 直接 emit 真 popcnt REG-REG
// 字节 (32-bit: F3 0F B8 C0, 64-bit: 48 F3 0F B8 C0). MSVC __popcnt 内部函数
// 在 /Od 下 emit MEM form (popcnt reg, [rsp+disp], 因 MSVC 把参数 spill 到栈),
// 派活单限定不支持 MEM form, 故用 MASM helper 强制 emit REG-REG form.
// 用 mangled C++ 名称声明 (Win64 名称修饰, 沿用 MIT-334 xchg_helper 模式).
extern "C" {
    unsigned int popcnt32_fn(unsigned int x);  // ?popcnt32_fn@@YAII@Z
    unsigned int popcnt64_fn(unsigned long long x);  // ?popcnt64_fn@@YAIX@Z
    // MIT-353: lzcnt/tzcnt BMI1 bit-scan 助手函数 (沿用 popcnt 派活单限定风格).
    // 用 MASM (.asm) helper 强制 emit REG-REG 字节 (lzcnt rax,rax / tzcnt rax,rax),
    // 因为 MSVC 没有 lzcnt/tzcnt 直接 intrinsic, 高层 _lzcnt_u32 / _tzcnt_u32
    // 在 /Od 下可能 emit MEM form (沿用 popcnt 派活单限定风格, 派活单限定不支持
    // MEM). 沿用 MIT-349 MASM helper 模式 + 64-NOP 填充 pitfall #39.
    // 函数参数用 RCX (Win64 ABI), 返回 RAX.
    unsigned int lzcnt32_fn(unsigned int x);  // ?lzcnt32_fn@@YAII@Z
    unsigned int lzcnt64_fn(unsigned long long x);  // ?lzcnt64_fn@@YAIX@Z
    unsigned int tzcnt32_fn(unsigned int x);  // ?tzcnt32_fn@@YAII@Z
    unsigned int tzcnt64_fn(unsigned long long x);  // ?tzcnt64_fn@@YAIX@Z
}

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

// MIT-345: movzx 8→16 (0x66 0F B6 + ModR/M, MSVC /Od codegen for
// `(unsigned short)(unsigned char)x`). 测试 movzx r16, r/m8 —
// 8 位源零扩展到 16 位目的. 区域里 r 用 volatile 接收防优化掉.
__declspec(noinline) static unsigned short movzx_8_16(unsigned char x) {
    WVMP_BEGIN(movzx_8_16);
    volatile unsigned short r = static_cast<unsigned short>(x); // movzx ax, cl (66 0F B6 C1 类)
    WVMP_END(movzx_8_16);
    return r;
}

// MIT-345: movzx 16→64 (REX.W + 0F B7 + ModR/M, MSVC /Od codegen for
// `(unsigned long long)(unsigned short)x`). 测试 movzx r64, r/m16 —
// 16 位源零扩展到 64 位目的. 同上 volatile 接收.
__declspec(noinline) static unsigned long long movzx_16_64(unsigned short x) {
    WVMP_BEGIN(movzx_16_64);
    volatile unsigned long long r = static_cast<unsigned long long>(x); // movzx rax, bx (48 0F B7 C3)
    WVMP_END(movzx_16_64);
    return r;
}

// MIT-347: movsx 8→32 (0F BE + ModR/M, MSVC /Od codegen for
// `int r = (signed char)x`). 测试 movsx r32, r/m8 —
// 8 位源符号扩展到 32 位目的. 区域里 r 用 volatile 接收防优化掉.
__declspec(noinline) static int movsx_8_32(signed char x) {
    WVMP_BEGIN(movsx_8_32);
    volatile int r = static_cast<int>(x);   // movsx eax, al (0F BE C0 类)
    WVMP_END(movsx_8_32);
    return r;
}

// MIT-347: movsx 8→64 (REX.W + 0F BE + ModR/M, MSVC /Od codegen for
// `long long r = (signed char)x`). 测试 movsx r64, r/m8 —
// 8 位源符号扩展到 64 位目的. 负数 (bit 7 = 1) 应填满上 56 位 1.
__declspec(noinline) static long long movsx_8_64(signed char x) {
    WVMP_BEGIN(movsx_8_64);
    volatile long long r = static_cast<long long>(x); // movsx rax, al (48 0F BE C0 类)
    WVMP_END(movsx_8_64);
    return r;
}

// MIT-347: movsx 16→32 (0F BF + ModR/M, MSVC /Od codegen for
// `int r = (signed short)x`). 测试 movsx r32, r/m16 —
// 16 位源符号扩展到 32 位目的.
__declspec(noinline) static int movsx_16_32(short x) {
    WVMP_BEGIN(movsx_16_32);
    volatile int r = static_cast<int>(x);   // movsx eax, ax (0F BF C0 类)
    WVMP_END(movsx_16_32);
    return r;
}

// MIT-347: movsx 16→64 (REX.W + 0F BF + ModR/M, MSVC /Od codegen for
// `long long r = (signed short)x`). 测试 movsx r64, r/m16 —
// 16 位源符号扩展到 64 位目的. 负数 (bit 15 = 1) 应填满上 48 位 1.
__declspec(noinline) static long long movsx_16_64(short x) {
    WVMP_BEGIN(movsx_16_64);
    volatile long long r = static_cast<long long>(x); // movsx rax, ax (48 0F BF C0 类)
    WVMP_END(movsx_16_64);
    return r;
}

// MIT-349: popcnt 32-bit (F3 0F B8 C0) SSE4.2 比特计数。
// 真 popcnt REG-REG 字节由 cl_shift_sample_asm.asm (MASM) emit, 链接进本 sample。
// 派活单限定仅 REG-REG (mod=11), 不支持 MEM form (沿用 movzx/movsx 派活单限定风格,
// 但完全不支持 MEM, 不像 movzx/movsx 沿用 MovzxMem/MovsxMem 单独处理)。
__declspec(noinline) static int popcnt_32(unsigned int x) {
    WVMP_BEGIN(popcnt_32);
    volatile int r = static_cast<int>(popcnt32_fn(x)); // MASM helper: popcnt eax, eax (F3 0F B8 C0)
    WVMP_END(popcnt_32);
    return r;
}

// MIT-349: popcnt 64-bit (48 F3 0F B8 C0) SSE4.2 比特计数。
// 真 popcnt REG-REG 字节由 cl_shift_sample_asm.asm (MASM) emit, 链接进本 sample。
__declspec(noinline) static int popcnt_64(unsigned long long x) {
    WVMP_BEGIN(popcnt_64);
    volatile int r = static_cast<int>(popcnt64_fn(x)); // MASM helper: popcnt rax, rax (48 F3 0F B8 C0)
    WVMP_END(popcnt_64);
    return r;
}

// MIT-353: lzcnt 32-bit (F3 0F BD C0) BMI1 前导零计数。
// 真 lzcnt REG-REG 字节由 cl_shift_sample_asm.asm (MASM) emit, 链接进本 sample。
// 派活单限定仅 REG-REG (mod=11), 不支持 MEM form (沿用 popcnt 派活单限定风格).
__declspec(noinline) static int lzcnt_32(unsigned int x) {
    WVMP_BEGIN(lzcnt_32);
    volatile int r = static_cast<int>(lzcnt32_fn(x)); // MASM helper: lzcnt eax, eax (F3 0F BD C0)
    WVMP_END(lzcnt_32);
    return r;
}

// MIT-353: lzcnt 64-bit (48 F3 0F BD C0) BMI1 前导零计数。
__declspec(noinline) static int lzcnt_64(unsigned long long x) {
    WVMP_BEGIN(lzcnt_64);
    volatile int r = static_cast<int>(lzcnt64_fn(x)); // MASM helper: lzcnt rax, rax (48 F3 0F BD C0)
    WVMP_END(lzcnt_64);
    return r;
}

// MIT-353: tzcnt 32-bit (F3 0F BC C0) BMI1 末尾零计数。
__declspec(noinline) static int tzcnt_32(unsigned int x) {
    WVMP_BEGIN(tzcnt_32);
    volatile int r = static_cast<int>(tzcnt32_fn(x)); // MASM helper: tzcnt eax, eax (F3 0F BC C0)
    WVMP_END(tzcnt_32);
    return r;
}

// MIT-353: tzcnt 64-bit (48 F3 0F BC C0) BMI1 末尾零计数。
__declspec(noinline) static int tzcnt_64(unsigned long long x) {
    WVMP_BEGIN(tzcnt_64);
    volatile int r = static_cast<int>(tzcnt64_fn(x)); // MASM helper: tzcnt rax, rax (48 F3 0F BC C0)
    WVMP_END(tzcnt_64);
    return r;
}

// MIT-355: cl_shift_sample 测试 fixture stdout 加 Python bit-count 注释说明。
//
// MIT-349 (popcnt) / MIT-353 (lzcnt/tzcnt) done + verifier 接受 + 错误方翻转
// 教训 (派活单 §D 决策 9, 🟡 MIT-353 实证): 派活单 §A 误读 hex 输出为十进制
// (例 k=20 被读作 20 而不是 hex 0x20=dec 32, 实际正确)。dumpbin 实证 MASM
// helpers (lzcnt32_fn/lzcnt64_fn/tzcnt32_fn/tzcnt64_fn) 已直接用
// `lzcnt eax, ecx` / `lzcnt rax, rcx` 寄存器传值 (MIT-353 commit ec74b3c
// 实际采用), popcnt32_fn/popcnt64_fn 用 save-then-read-back 等价模式。
//
// 派活单 §A pitfall #40 候选 "MASM helper C++ wrapper 寄存器传值不完整"
// (应该 `mov eax, ecx` 读 RCX 传参) 不成立 —— 现状已是正确寄存器传值。
//
// 本次 commit 只加 stdout 自描述 (派活单 §D 决策 2 模式), 不改 MASM
// helpers, 不改 compact 行为行 (派活单 §D 决策 3 "stdout 文本不变"), 不改
// 真虚拟化路径 (派活单 §A "native == protected byte-exact 真虚拟化达成")。
int main() {
    // 用函数参数传入 count —— MSVC codegen 为 cl 变体核心条件: count 不能
    // 是编译期常量 (用 literal 常量会让 MSVC 用 imm 形式 C1 /4 ib)。
    const unsigned long long a = shl_cl(0x12345678ull, 5);                  // 0x2468ACF0
    const unsigned long long b = shr_cl(0xCAFEBABEull, 8);                 // 0x00CAFEBB
    const long long c = sar_cl(-1024LL, 1);                                 // sar -1024, 1 = -512
    const unsigned long long d = shl_shr_sar_chain(0x1000ull, 4, 2, 1);    // 链式

    // MIT-345: movzx 8→16 / 16→64 测试 (沿用 MIT-314 cl_shift 模式, MSVC /Od
    // 自然 codegen movzx, 区域不含 rip-relative / call / printf)。
    // 期望: movzx_8_16(0xAB) = 0x00AB; movzx_16_64(0xABCD) = 0x000000000000ABCD
    const unsigned short e = movzx_8_16(0xABu);
    const unsigned long long f = movzx_16_64(0xABCDu);

    // MIT-347: movsx 4 形式测试 (与 movzx 对偶, sign-extend vs zero-extend).
    // 区域不含 rip-relative / call / printf, MSVC /Od 自然 codegen movsx.
    // 期望 (sign-extend, bit 7/15 = 1 时填满上 56/48 位):
    //   movsx_8_32(-1)  = 0xFFFFFFFF (signed char -1 → int -1)
    //   movsx_8_64(-1)  = 0xFFFFFFFFFFFFFFFF (signed char -1 → long long -1)
    //   movsx_16_32(-1) = 0xFFFFFFFF (signed short -1 → int -1)
    //   movsx_16_64(-1) = 0xFFFFFFFFFFFFFFFF (signed short -1 → long long -1)
    const int g = movsx_8_32(-1);
    const long long h = movsx_8_64(-1);
    const int i = movsx_16_32(-1);
    const long long j = movsx_16_64(-1);

    // MIT-349: popcnt 2 形式测试 (32-bit + 64-bit REG-REG)。
    // 区域不含 rip-relative / call / printf, MSVC /Od 配合 <intrin.h> 的
    // __popcnt / __popcnt64 emit 真 popcnt 字节 (F3 0F B8 / 48 F3 0F B8)。
    // 期望 (比特计数, Python bit-count = bin(x).count('1')):
    //   popcnt_32(0xFFFFFFFF)     = 32 (32 位全 1)
    //   popcnt_64(0xFFFFFFFFFFFF) = 48 (低 48 位全 1, 高 16 位 0)
    const unsigned int k_input = 0xFFFFFFFFu;
    const unsigned long long l_input = 0xFFFFFFFFFFFFull;
    const int k = popcnt_32(k_input);
    const int l = popcnt_64(l_input);

    // MIT-353: lzcnt + tzcnt 4 形式测试 (32-bit + 64-bit REG-REG)。
    // 区域不含 rip-relative / call / printf, MASM (.asm) helper 直接 emit 真
    // lzcnt/tzcnt REG-REG 字节 (F3 0F BD/BC / 48 F3 0F BD/BC).
    // 期望 (bit-scan, Python bit-count 公式):
    //   lzcnt_32(0x00010000)         = 15  (lzcnt bit 16, 32-16-1=15)
    //   lzcnt_64(0x0000000100000000) = 31  (lzcnt bit 32, 64-32-1=31)
    //   tzcnt_32(0x00010000)         = 16  (tzcnt bit 16)
    //   tzcnt_64(0x0000000100000000) = 32  (tzcnt bit 32)
    const unsigned int m_input = 0x00010000u;
    const unsigned long long n_input = 0x0000000100000000ull;
    const unsigned int o_input = 0x00010000u;
    const unsigned long long p_input = 0x0000000100000000ull;
    const int m = lzcnt_32(m_input);
    const int n = lzcnt_64(n_input);
    const int o = tzcnt_32(o_input);
    const int p = tzcnt_64(p_input);

    // MIT-355: 派活单 §D 决策 2 + 决策 9 — stdout 加 Python bit-count 公式
    // 校准注释, 便于未来 verifier 与人类 reviewer 理解 (避免 MIT-349/353 🟡
    // 错误方翻转教训重演)。原始紧凑行 (派活单 §D 决策 3 "stdout 文本不变"
    // 承诺) 在此行下方保留, E2E byte-exact 兼容。
    //
    // std::popcount / std::countl_zero / std::countr_zero 是 C++20 标准库
    // 函数, MSVC/GCC/Clang 通用, 等价于 Python bit-count 公式:
    //   popcount(x) = bin(x).count('1')
    //   countl_zero(x) = leading zeros before first '1' (for lzcnt)
    //   countr_zero(x) = trailing zeros before first '1' (for tzcnt)
    std::printf(
        "popcnt_32(0x%x)=%u (期望 %u, Python bit-count=%u) "
        "popcnt_64(0x%llx)=%u (期望 %u, Python bit-count=%u) "
        "lzcnt_32(0x%x)=%u (期望 %u, Python bit-count=%u) "
        "lzcnt_64(0x%llx)=%u (期望 %u, Python bit-count=%u) "
        "tzcnt_32(0x%x)=%u (期望 %u, Python bit-count=%u) "
        "tzcnt_64(0x%llx)=%u (期望 %u, Python bit-count=%u)\n",
        k_input, static_cast<unsigned int>(k),
        std::popcount(k_input), std::popcount(k_input),
        l_input, static_cast<unsigned int>(l),
        std::popcount(l_input), std::popcount(l_input),
        m_input, static_cast<unsigned int>(m),
        std::countl_zero(m_input), std::countl_zero(m_input),
        n_input, static_cast<unsigned int>(n),
        std::countl_zero(n_input), std::countl_zero(n_input),
        o_input, static_cast<unsigned int>(o),
        std::countr_zero(o_input), std::countr_zero(o_input),
        p_input, static_cast<unsigned int>(p),
        std::countr_zero(p_input), std::countr_zero(p_input));
    std::printf("a=%llx b=%llx c=%lld d=%llx e=%x f=%llx g=%x h=%llx i=%x j=%llx k=%x l=%x m=%x n=%x o=%x p=%x\n",
                static_cast<unsigned long long>(a),
                static_cast<unsigned long long>(b),
                static_cast<long long>(c),
                static_cast<unsigned long long>(d),
                static_cast<unsigned int>(e),
                static_cast<unsigned long long>(f),
                static_cast<unsigned int>(g),
                static_cast<unsigned long long>(h),
                static_cast<unsigned int>(i),
                static_cast<unsigned long long>(j),
                static_cast<unsigned int>(k),
                static_cast<unsigned int>(l),
                static_cast<unsigned int>(m),
                static_cast<unsigned int>(n),
                static_cast<unsigned int>(o),
                static_cast<unsigned int>(p));
    return 0;
}