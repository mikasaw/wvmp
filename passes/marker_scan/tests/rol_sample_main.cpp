// MIT-247: 端到端正路径样本——区域内含 rol/ror（白名单内），验证 C2-Rol/Ror
// 修复后翻译成功、运行时走真实 Rol/Ror handler、行为与原生逐字节一致。
//
// 设计要点：
//   - MSVC `_rotl64` / `_rotr64` 内部函数在 /Od 下 codegen 为真 `rol` / `ror`
//     指令（/Od 不做 shl+shr 模式合并——那是 /O1 /O2 才发生的优化）。这是
//     C2-Rol/Ror 的关键路径：翻译器+运行时必须正确处理循环移位。
//   - 用 64 位循环移位串联（CRC 风格：13 → 17 → 7 位移）与 ror+add+ror 复合
//     覆盖真实用例（CRC32 哈希、SP 网络、PRNG 等）。
//   - 输入用 volatile 防止 MSVC 常量折叠把运算挪出 marker 区域；运算结果
//     不强求具体值（依赖 codegen 与 intrinsic 形态），E2E 通过字节级 stdout +
//     退出码比对保证行为一致。
//   - 区域外只留 std::printf（rip-relative 在区域内会触发 C1 gate, 见
//     MIT-243）；xor/add 是白名单内指令, 与 rol/ror 一同被翻译。

#include "wvmp/sdk/markers.hpp"

#include <cstdio>
#include <intrin.h>   // _rotl64, _rotr64

volatile unsigned long long g_in = 0x123456789ABCDEF0ull;

// CRC 风格：三次循环移位 + xor 复合。MSVC /Od 对 _rotl64 codegen:
//   mov rax, [g_in]
//   rol rax, 13                ; ROL 13
//   xor rax, 0xDEADBEEFCAFEBABE ; XOR
//   rol rax, 17                ; ROL 17
//   rol rax, 7                 ; ROL 7
__declspec(noinline) static unsigned long long rol_chain(unsigned long long x) {
    WVMP_BEGIN(rol_chain);
    unsigned long long r = _rotl64(x, 13);
    r ^= 0xDEADBEEFCAFEBABEull;
    r = _rotl64(r, 17);
    r = _rotl64(r, 7);
    WVMP_END(rol_chain);
    return r;
}

// 反向：ror+add+ror 复合。MSVC /Od 对 _rotr64 codegen:
//   mov rax, [g_in]
//   ror rax, 29                ; ROR 29
//   add rax, 0x12345678         ; ADD
//   ror rax, 5                 ; ROR 5
__declspec(noinline) static unsigned long long ror_chain(unsigned long long x) {
    WVMP_BEGIN(ror_chain);
    unsigned long long r = _rotr64(x, 29);
    r += 0x12345678;
    r = _rotr64(r, 5);
    WVMP_END(ror_chain);
    return r;
}

int main() {
    const unsigned long long x = g_in;
    const unsigned long long rol_out = rol_chain(x);
    const unsigned long long ror_out = ror_chain(x);
    std::printf("rol=%llx ror=%llx\n",
                static_cast<unsigned long long>(rol_out),
                static_cast<unsigned long long>(ror_out));
    return 0;
}
