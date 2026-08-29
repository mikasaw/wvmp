// MIT-406 (MIT-E1): 深 call 递归链 E2E 样本 — callee 专用栈窗口的预算边界覆盖。
//
// 背景: 既有 call_gate 样本 callee 全浅帧 (<=0x30B), callgate 的 native
// callee 树与驻留同栈的 VmContext 只隔 ~0x1D8 预算, 从未被测过。wvmpTest
// sha256 (调用树 ~0x250B) 在 MIT-404 合入后砸穿 ctx → packed 双跑红。
// 本样本用静态可核算的 16 层递归链 (每层 0x60B, 总树深 0x600B >= 0x400B,
// 推导见 deepcall_sample_asm.asm 头注释) 复现预算边界:
//   - 修复前: 递归写入物理落进 VmContext 槽区 → CallGate 返回后解释器
//     状态毁坏 → packed 必崩 (0xC0000005 形态) — 验收 #8 反证;
//   - 修复后: callee 树在 host_rsp 下方 0x1000 专用窗口内生长, 与
//     ctx/stub 保存区零重叠 → packed 与 native stdout+rc byte-exact。
//
// deepcall_entry (MASM, 标记区域) 内 call deep_recurse (E8 直接 call →
// CallGate, callee 非 stub → native 主路径); 递归结果打印对拍。

#include <cstdint>
#include <cstdio>

extern "C" uint64_t deepcall_entry();

int main() {
    const unsigned long long r = deepcall_entry();
    std::printf("deepcall=%016llx\n", static_cast<unsigned long long>(r));
    std::fflush(stdout);
    return 0;
}
