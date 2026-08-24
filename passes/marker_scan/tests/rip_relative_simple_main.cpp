// MIT-248 简化调试样本：单个 rip-relative load（无 spill 栈操作）。
// 排除多 insn 链可能引入的次生问题, 验证 loadrva / 整条链路最小版本.

#include "wvmp/sdk/markers.hpp"
#include <cstdio>

volatile unsigned long long g_counter = 0x1000;

__declspec(noinline) static unsigned long long read_counter() {
    WVMP_BEGIN(read_counter);
    unsigned long long r = g_counter;     // 单条 [rip+disp] load
    WVMP_END(read_counter);
    return r;
}

int main() {
    unsigned long long v = read_counter();
    std::printf("v=%llx\n", v);
    return v == 0x1000 ? 0 : 2;
}