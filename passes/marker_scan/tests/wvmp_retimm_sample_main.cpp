// MIT-438 (X1b): ret imm16 清栈语义端到端主样本。保护 → 运行 → stdout+退出码
// 逐字节比对 (native vs virtualized)。形态与分叉面详见
// wvmp_retimm_sample_asm.asm 头注 (3 区 x64 ret N 直写真编码: 10h / 0 / 90h;
// N ≡ 0 mod 16 = qword 参数 + 16 对齐垫的良构清栈量, imm=8 档由 runtime
// 语义电池 + translator 矩阵覆盖)。
//
// 期望值 (native = 修复后 packed, byte-exact):
//   bal1=0 ret1=36  bal2=0 ret2=6b  bal3=0 ret3=75
//   (平衡探针 bal* = caller R0 - 返回后 rsp；stdcall 仿清栈正确时恒 0;
//    ret* = 区内计算 eax = ecx + K + 栈参数, 2/3 区含第 2 轮/大 imm 区偏置)
// 修复前 (main f7a865c 旧 CLI 反证): VmOp::Ret 无 handler → Halt → stub 从死
//   分隔符续跑 → rax 被 marker_end 魔数覆写 (ret* 分叉) + caller rsp 失衡
//   (bal1=10h / bal3=90h；bal2 碰巧同但 ret2 分叉) → stdout 分叉必 FAIL。
// 哨兵初值 0xEE: caller 未执行即露形 (与 native 必分叉, 不静默)。

#include <cstdio>

extern "C" {
// 平衡探针 (caller R0 - 返回后 rsp) 与返回值落盘槽 (MASM EXTERNDEF 直引)。
unsigned long g_wv438_bal1 = 0xEEEEEEEE;
unsigned long g_wv438_ret1 = 0xEEEEEEEE;
unsigned long g_wv438_bal2 = 0xEEEEEEEE;
unsigned long g_wv438_ret2 = 0xEEEEEEEE;
unsigned long g_wv438_bal3 = 0xEEEEEEEE;
unsigned long g_wv438_ret3 = 0xEEEEEEEE;

void wv438_call_stdret8();
void wv438_call_retzero();
void wv438_call_retbig();
}

int main() {
    wv438_call_stdret8();
    wv438_call_retzero();
    wv438_call_retbig();
    std::printf("stdret8 bal=%lu ret=%lx retzero bal=%lu ret=%lx retbig bal=%lu ret=%lx\n",
                g_wv438_bal1, g_wv438_ret1, g_wv438_bal2, g_wv438_ret2,
                g_wv438_bal3, g_wv438_ret3);
    return 0;
}
