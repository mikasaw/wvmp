// M2-4 端到端样例：保护区域只含翻译器白名单指令（/Od 下 32 位整型循环的
// 典型产物：mov/add/cmp/jcc/inc 与栈上 Load/Store），区域结束后读取栈上的
// 计算结果验证 VM 执行语义。sum=21（0+1+..+6）且退出码 0 = 虚拟化正确。

#include "wvmp/sdk/markers.hpp"

#include <cstdio>

volatile int g_n = 7;

int main() {
    const int n = g_n;
    int s = 0;
    WVMP_BEGIN(compute);
    for (int i = 0; i < n; ++i) {
        s = s + i;
    }
    WVMP_END(compute);
    std::printf("sum=%d\n", s);
    return s == 21 ? 0 : 2;
}
