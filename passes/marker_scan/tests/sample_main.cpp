// 样例"用户程序"：真实链接 wvmp::sdk 的最小 exe，作为 marker_scan
// 集成测试的扫描对象（只读字节，从不运行）。
//
// 两个函数各用 WVMP_BEGIN/WVMP_END 包裹一段计算逻辑；期望 marker_scan
// 在其 .text 中找到恰好 2 个保护区域。构建固定 /Od /Ob0，避免 O2 尾调用
// 把 call marker_end 优化成 jmp（v1 已知限制）。

#include "wvmp/sdk/markers.hpp"

namespace {

volatile unsigned long long g_sink = 0;

unsigned long long compute_alpha(unsigned long long seed) {
    WVMP_BEGIN(compute_alpha);
    unsigned long long acc = seed ^ 0x9E37'7997'A2C5'BCB5ull;
    for (int i = 0; i < 8; ++i) acc = acc * 31 + static_cast<unsigned long long>(i);
    g_sink ^= acc;
    WVMP_END(compute_alpha);
    return acc;
}

unsigned long long compute_beta(unsigned long long seed) {
    WVMP_BEGIN(compute_beta);
    unsigned long long x = seed + 0xDEAD'BEEFull;
    x = (x << 7) | (x >> 57);
    x ^= x >> 13;
    g_sink += x;
    WVMP_END(compute_beta);
    return x;
}

} // namespace

int main() {
    volatile unsigned long long r = 0;
    r += compute_alpha(1);
    r += compute_beta(2);
    return r == 0 ? 1 : 0;
}
