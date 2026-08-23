// MIT-244: 端到端正路径样本——区域内含 sar（在白名单内），
// 验证 C2-Sar 修复后: 翻译成功、运行时走真实 Sar handler、行为与
// 原生逐字节一致（保护 → 运行 → stdout+退出码比对）。
//
// 含 sar 的最小用例：i64 算术右移 x>>2（编译器在 MSVC /O0 下也用 sar，
// 即使正值 x 也按 sar 编译——sar/srh 在 codegen 选择上对 signed i64 一致）。
// 负值 x 强制 sar：位移计数 = 1 时仍按 sar 编码。

#include "wvmp/sdk/markers.hpp"

#include <cstdio>

volatile long long g_in = -1024;

// 两次 sar 串联 + 一次 sar 接 and 返回低 4 位（i64 % 16 等价）。
__declspec(noinline) static long long sar_chain(long long x, int n) {
    WVMP_BEGIN(sar_chain);
    long long y = x >> 2;        // sar
    long long z = y >> n;        // sar
    long long r = (z & 15);      // 取低 4 位（与 sar 解耦, 验证 sar 之外的指令仍走得通）
    WVMP_END(sar_chain);
    return r;
}

int main() {
    const long long n = g_in;    // rip-relative 留在区域外
    const long long r = sar_chain(n, 1);
    std::printf("r=%lld\n", r);
    // g_in=-1024, >>2 = -256, >>1 = -128, &15 = ?  -128 = 0xFFFFFFFFFFFFFF80
    // 低 4 位 = 0x0, 即 0
    return r == 0 ? 0 : 2;
}
