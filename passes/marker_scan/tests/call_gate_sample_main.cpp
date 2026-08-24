// MIT-249: 端到端正路径样本——标记函数 f1 通过 call gate 调到
// 一个未标记的 native helper。验证：
//   - 直接 call (E8 disp32) 翻译期 emit VmOp::CallGate
//   - 运行时 handler 切 rsp 到 caller frame、调 native、ret 后 RAX 写回
//     regs[v0]、恢复解释器上下文、继续 dispatch
//   - helper 是普通 native 函数（非标记），call gate 走 native_call 路径
//
// 设计要点：
//   - 全局 g_sink (volatile uint64_t) 用来跨函数跨虚拟化边界传递可见状态。
//   - helper() 设 g_sink = 42，无参，ret（无返回值；call gate v1 不取 rax 写回
//     也无影响——VM 不读 v0 即可；这里只验证 call/ret 路径通畅）。
//   - f1 在区域里调用 helper，再加 g_sink += 1（验证 f1 真的继续执行）。
//   - main 调用 f1，期望 g_sink = 43（42 + 1）；stdout 与原生逐字节比对。
//   - 关键：f1 **完整可虚拟化**——区域内仅 mov/add/call/ret 全白名单，
//     call 是直接 call (E8 disp32) 翻译期已知 target RVA → emit CallGate，
//     helper 不标记 → stub_link 不为 helper 生成 stub → call gate 真跑 native。
//
// 注意：f1 调的是 helper（标记函数集外），不调其它标记函数——后者会触发
// 跨 stub 的递归 VM，目前 v1 不支持递归 stub-to-stub 调用（保留为后续 issue，
// 当前 E2E 走"callee 非 stub"的主路径）。

#include "wvmp/sdk/markers.hpp"

#include <cstdio>

volatile unsigned long long g_sink = 0;

// 未标记的 native 函数：call gate 命中后真跑 native。设 g_sink = 42。
__declspec(noinline) static void native_helper() {
    g_sink = 42ull;
}

// 标记函数 f1：call native_helper() (E8 disp32)，g_sink += 1，ret。
__declspec(noinline) static unsigned long long call_gate_vm() {
    WVMP_BEGIN(call_gate_vm);
    native_helper();         // E8 直接 call → CallGate
    g_sink = g_sink + 1;     // add（VM 内继续）
    unsigned long long r = g_sink;
    WVMP_END(call_gate_vm);
    return r;
}

int main() {
    g_sink = 0;
    const unsigned long long r = call_gate_vm();
    std::printf("r=%llx g_sink=%llx\n", r, g_sink);
    // 期望 r = g_sink = 43。
    return (r == 43ull && g_sink == 43ull) ? 0 : 2;
}
