// MIT-248: 端到端正路径样本——区域内含 rip-relative 真实全局读写 (mov rax,
// [rip+g_counter]; add [rip+g_counter], 5; mov [rip+g_counter], rax), 验证
// C4 修复后翻译期把 [rip+disp] 算成绝对 RVA、运行时 + image_base 还原 VA、
// 保护后行为与原生逐字节一致。
//
// 设计要点：
//   - 全局计数器 g_counter (uint64_t, .data 段)，证明虚拟化能安全碰 .data。
//   - 标记函数 rip_rw 内部:
//       1) 读 [rip+offset] g_counter → rax
//       2) add rax, 5
//       3) 写回 [rip+offset] g_counter (mov [rip+offset], rax)
//     三条都是 x64 [rip+disp32] 形态 (Capstone 解出 base=Rip), 不再依赖栈/
//     寄存器间接。
//   - 校验函数 main 调用前/调用后各读一次 g_counter, 差值必须 = 5, 退出码
//     0/2 区分 PASS/FAIL；与原生逐字节比对（e2e.sh 跑 cmp -s）。
//   - 关键：标记函数**完整可虚拟化**——除上述三条 ALU/Mov, 只允许 ret, 不含
//     call/jcc/loop；不触发 C1 gate 拦截。

#include "wvmp/sdk/markers.hpp"

#include <cstdio>

volatile unsigned long long g_counter = 0x1000;

// 标记函数：读 g_counter (+5) → 写回 g_counter. 全部以 [rip+disp] 访存.
__declspec(noinline) static void rip_rw() {
    WVMP_BEGIN(rip_rw);
    unsigned long long r = g_counter;     // mov rax, [rip+offset]
    r = r + 5;                             // add rax, 5
    g_counter = r;                         // mov [rip+offset], rax
    WVMP_END(rip_rw);
}

int main() {
    const unsigned long long before = g_counter;
    rip_rw();
    const unsigned long long after = g_counter;
    std::printf("before=%llx after=%llx delta=%llx\n", before, after,
                static_cast<unsigned long long>(after - before));
    // 期望 after - before = 5.
    return (after - before == 5ull) ? 0 : 2;
}