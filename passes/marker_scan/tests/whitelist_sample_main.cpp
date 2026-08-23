// MIT-243：端到端正路径样本——区域内纯直算（Mov/Add），无 loop、无条件
// 跳转、无 rip-relative，全在翻译器白名单内。验证 C1 保守拦截**不会**
// 误杀可虚拟化区域，虚拟化路径仍可走通（入口 stub 生成、行为在 VM 内
// 执行、与原生逐字节一致）。

#include "wvmp/sdk/markers.hpp"

#include <cstdio>

volatile int g_n = 7;

// 三次 n 自加，结果 = n * 3 = 21。
__declspec(noinline) static int triple(int n) {
    WVMP_BEGIN(compute);
    int s = n;
    s = s + n;
    s = s + n;
    WVMP_END(compute);
    return s;
}

int main() {
    const int n = g_n; // rip-relative 读留在区域外
    const int s = triple(n);
    std::printf("triple=%d\n", s);
    return s == 21 ? 0 : 2;
}