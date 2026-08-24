// MIT-249: 极简调试样本——标记函数直接调 native helper，**不碰 rip-relative**
// 全局变量，避免与 M2-8 (rip-relative) 修复叠加。先单独验证 CallGate
// 路径通畅，再回头处理 rip + call 复合用例。
//
// 设计：
//   - native_helper_inc：把 g_count += 1，无参
//   - f1 标记区域：仅 call native_helper_inc + ret（极简）
//   - main 调用 f1 两次（验证 gate 重入），g_count 应为 2

#include "wvmp/sdk/markers.hpp"

#include <cstdio>

volatile unsigned long long g_count = 0;

__declspec(noinline) static void native_helper_inc() {
    g_count = g_count + 1ull;
}

__declspec(noinline) static void f1() {
    WVMP_BEGIN(f1);
    native_helper_inc();
    WVMP_END(f1);
}

int main() {
    g_count = 0;
    f1();
    f1();
    std::printf("count=%llx\n", g_count);
    return g_count == 2ull ? 0 : 2;
}
