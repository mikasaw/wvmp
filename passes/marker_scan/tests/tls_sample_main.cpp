// MIT-465 (T8): TLS 感知样本 —— 自带 .CRT$XLB 注册的用户 TLS 回调 + sdk
// marker 区域，供 scripts/tls_e2e.sh 验证 tls_hook 基建：
//   1. tls_hook 把「占位回调 + 原回调」合并进新回调数组（并入原回调 1 个）；
//   2. 打包后 loader 在入口前仍调用回调链（原回调 → "callback fired"）；
//   3. EB FE 挂起探针打在数组第 0 项（我们的占位回调）上 → 进程挂起
//      = 我们的回调确实被执行（E2E 脚本口径）；
//   4. 行为零回归：native vs packed stdout/rc byte-exact。
//
// 构建走 scripts/build_tls_sample.bat（plain cl 配方——本机实证该构建形态
// 的 TLS 回调会被 loader 调用；CMake 管产样本本体在本机存在 loader 侧
// 静默跳过现象，见 docs/GAPS.md MIT-465-G1）。
#include <cstdio>
#include <cstdint>
#include <windows.h>

#include "wvmp/sdk/markers.hpp"

static volatile uint32_t g_tls_hit = 0;
static volatile uint32_t g_tls_work = 0;

// import_protect v1 硬依赖：目标 IAT 须含 kernel32!VirtualProtect（TLS
// 回调回填原 IAT 页前需解除只读保护）。对 .data 页做一次等值改保护——
// 行为无害，仅保证导入面存在。
static void touch_virtual_protect() {
    DWORD oldp = 0;
    VirtualProtect(const_cast<uint32_t*>(&g_tls_hit), sizeof(g_tls_hit),
                   PAGE_READWRITE, &oldp);
}

// MIT-470：保证 IAT 含 kernel32!GetThreadContext（DRx 检查面硬依赖）。
// 对当前线程读一次 DEBUG_REGISTERS CONTEXT——行为无害（Dr0-3 恒 0）。
static void touch_get_thread_context() {
    CONTEXT c;
    c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &c);
}

// 用户 TLS 回调：进程附加时置哨兵。打包后本回调经 tls_hook 的新数组继续
// 被 loader 调用（合并面）。
static void NTAPI wvmp_tls_cb(PVOID, DWORD reason, PVOID) {
    if (reason == DLL_PROCESS_ATTACH) g_tls_hit = 0xC0C0BEEFu;
}

#pragma section(".CRT$XLB", long, read)
extern "C" __declspec(allocate(".CRT$XLB")) const PIMAGE_TLS_CALLBACK
    g_wvmp_tls_cbs[] = { wvmp_tls_cb, 0 };
// 链接器 TLS 目录标记符号名按架构不同：x86 带前置下划线装饰，x64 不带。
#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#endif

// 被虚拟化区域：整数算术小混合（mov/xor/add/shr 全在 VM 白名单内）。
static void rgn_tls(void) {
    WVMP_BEGIN(rgn_tls);
    uint32_t x = 0x5A5A1234u;
    x ^= x >> 3;
    x += 0x9E3779B9u;
    x *= 7u;
    x ^= x << 5;
    g_tls_work = x;
    WVMP_END(rgn_tls);
}

int main() {
    touch_virtual_protect();
    touch_get_thread_context();
    rgn_tls();
    std::printf("tls g=%08X hit=%08X\n",
                static_cast<uint32_t>(g_tls_work),
                static_cast<uint32_t>(g_tls_hit));
    return (g_tls_hit == 0xC0C0BEEFu && g_tls_work != 0) ? 0 : 1;
}
