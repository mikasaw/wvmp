// M2-4 端到端样例：保护区域只含翻译器白名单指令（/Od 下 32 位整型循环的
// 典型产物：mov/add/cmp/jcc/inc 与栈上 Load/Store），区域结束后读取栈上的
// 计算结果验证 VM 执行语义。sum=21（0+1+..+6）且退出码 0 = 虚拟化正确。
//
// C1（MIT-243）注意：
//   1. g_n 的 volatile 读必须在标记区域**外**——`mov eax,[rip+g_n]` 是白名单
//      外指令（C4），在区域内会让保守拦截放弃整个函数。
//   2. SDK 桩已无参（见 sdk/src/sdk.cpp），避免在 marker_end 调用点之前
//      生成 `lea rcx,[rip+name]` 这种 rip-relative 指令。

#include "wvmp/sdk/markers.hpp"

#include <cstdio>

volatile int g_n = 7;

// 区域只包住纯计算；n 由调用方读好传入。
static int sum_to(int n) {
    WVMP_BEGIN(compute);
    int s = 0;
    for (int i = 0; i < n; ++i) {
        s = s + i;
    }
    WVMP_END(compute);
    return s;
}

int main() {
    const int n = g_n; // rip-relative 读留在区域外
    const int s = sum_to(n);
    std::printf("sum=%d\n", s);
    return s == 21 ? 0 : 2;
}
