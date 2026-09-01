// MIT-442 (X2a): 形级 fork 面收口端到端主样本。保护 → 运行 → stdout+退出码
// 逐字节比对 (native vs virtualized)。区域形态与栈语义推演详见
// wvmp_forkface_sample_asm.asm 头注:
//   区1 leave 链 (真虚拟化)      : bal=0 (栈平衡哨兵, 438 形) ret=6b
//   区2 call [mem] IAT 形 (负例) : CallGate 协议仅吃 aux RVA → D4 停手 gate,
//                                  原生执行 → callmem=997 (target 落盘)
//   区2b call reg (负例)         : 同上 gate 原生 → callreg=998
//   区3 plain 串形 + cld (真虚拟化): dst 12B == src 12B (movsd×2 + lodsd 回写)
//   区4 p66 S16 + cwde/cbw (真虚拟化): s16a=8023 s16b=7fdc s16c=ff80
//                                      cwde=ffff8123
//   区5 std (负例 D5 gate)       : 原生 std/nop/cld 平衡 (无观察值, 恒同)
//   区6 67 前缀 (负例 B.4 gate)  : 禁调用 — main 只取地址 (463 禁调用负例
//                                  纪律; gate 证据 = protect 日志 note)
//
// 区2/2b/5/6 的 gate 证据 = protect 日志 gate note (multiseed 日志可审计);
// 行为面 native == packed byte-exact (gate = 整函数原生, 零逃逸纪律)。

#include <cstdio>

extern "C" {
// 区1 平衡探针/返回值落盘槽 (MASM EXTERNDEF 直引; 哨兵初值 0xEE 露形)。
unsigned long g_wvmp_ff_bal = 0xEEEEEEEE;
unsigned long g_wvmp_ff_ret = 0xEEEEEEEE;
// 区2/2b: 函数指针槽 (IAT thunk 同构: call [g_fnptr] = FF 15 rip 形)。
void (*g_wvmp_ff_fnptr)(int, int) = nullptr;
unsigned long g_wvmp_ff_callmem = 0xEEEEEEEE;
unsigned long g_wvmp_ff_callreg = 0xEEEEEEEE;
// 区3: plain 串形源/目的缓冲 (12B: movsd×2 拷 8B + lodsd 回写 4B)。
unsigned char g_wvmp_ff_src[12] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                                   0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC};
unsigned char g_wvmp_ff_dst[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
// 区4: S16/cwde/cbw 落盘槽。
unsigned short g_wvmp_ff_s16a = 0xEEEE;
unsigned short g_wvmp_ff_s16b = 0xEEEE;
unsigned short g_wvmp_ff_s16c = 0xEEEE;
unsigned long g_wvmp_ff_s32 = 0xEEEEEEEE;

// 区2/2b 各自 target (extern "C" — 区2b 的 mov rax, wvmp_ff_target_b 符号直引;
// 双 target 区分两条负例通路各自真实走到 callee, 单值不可混淆)。
void wvmp_ff_target_a(int a, int b) { g_wvmp_ff_callmem = 997u; (void)a; (void)b; }
void wvmp_ff_target_b(int a, int b) { g_wvmp_ff_callreg = 998u; (void)a; (void)b; }

// asm 入口 (caller PROC; 区域见 asm 文件)。
void wvmp_ff_call_leave();
void wvmp_ff_callmem();
void wvmp_ff_callreg();
void wvmp_ff_call_string();
void wvmp_ff_call_s16();
void wvmp_ff_stdgate();
void wvmp_ff_addr67();   // 禁调用 (67 负例)
}

int main() {
    g_wvmp_ff_fnptr = &wvmp_ff_target_a;
    wvmp_ff_call_leave();
    wvmp_ff_callmem();      // 区2: call [mem] 负例 (gate → 原生, target_a 997)
    wvmp_ff_callreg();      // 区2b: call reg 负例 (gate → 原生, target_b 998)
    wvmp_ff_stdgate();      // 区5: std 负例 (gate → 原生 DF 平衡)
    (void)&wvmp_ff_addr67;  // 区6: 只取地址, 禁调用 (67 指令不执行)
    wvmp_ff_call_string();
    wvmp_ff_call_s16();
    std::printf("leave bal=%lu ret=%lx callmem=%lu callreg=%lu str="
                "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x "
                "s16a=%04x s16b=%04x s16c=%04x cwde=%08lx\n",
                g_wvmp_ff_bal, g_wvmp_ff_ret, g_wvmp_ff_callmem, g_wvmp_ff_callreg,
                g_wvmp_ff_dst[0], g_wvmp_ff_dst[1], g_wvmp_ff_dst[2], g_wvmp_ff_dst[3],
                g_wvmp_ff_dst[4], g_wvmp_ff_dst[5], g_wvmp_ff_dst[6], g_wvmp_ff_dst[7],
                g_wvmp_ff_dst[8], g_wvmp_ff_dst[9], g_wvmp_ff_dst[10], g_wvmp_ff_dst[11],
                g_wvmp_ff_s16a, g_wvmp_ff_s16b, g_wvmp_ff_s16c, g_wvmp_ff_s32);
    return 0;
}
