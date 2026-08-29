// MIT-413 (G2): 跳转表残余形态 E2E 样本 — 5 真虚拟化 + 3 负例（gate）。
//
// 正样本（全部 REQUIRE_REAL 真虚拟化，MASM 手拼字节形态，派活单 §A.3）：
//   1) wv_jt8_abs   —— REG 源 8B 绝对表（无 add）：`mov rax,[rcx+rax*8]; jmp rax`，
//      表项 = 完整 VA → 翻译期减 image_base 还原 RVA（G2-a abs 语义）。
//   2) wv_jt8_delta —— REG 源 8B delta 表（带 add）：`mov rax,[rcx+rax*8];
//      add rax,rcx; jmp rax`，表项 = case − 表基址（负值两补码，G2-a delta）。
//   3) wv_jt8_djmp  —— REG 源 delta-from-jmp（GCC `.L4` 风格）：lea 基址 =
//      jmp 指令地址，表项 = case − jmp 指令地址；add 还原 → 与 delta-from-
//      base 在"基址即跳转点"时静态不可分（§F.3 实测裁决，取区判据通过者）。
//   4) wv_jtm_abs   —— MEM 源直跳（G2-b）：`jmp qword ptr [rcx+rax*8]`，
//      lea 表基址，表项 = 完整 VA（mem 源跳转的目标即表项——delta 表项在
//      x86 上原生即坏，实测只有绝对 VA 语义可进，如实披露）。
//   5) wv_jtm_movabs—— MEM 源 + movabs 基址（表基址 = disp 常量，派活单
//      §A.3 两基址形态之一）：`mov rcx, offset tbl; jmp [rcx+rax*8]`。
// 负样本（照旧 C1 gate，packed 与 native 逐字节一致；main 只传安全 idx）：
//   6) wv_jt_undef  —— 同 REG 8B delta 形态但无 `cmp idx,7; ja` 防御 → 表长
//      不可推 → "未检出防御常数" note → gate（G2-c 永久裁决，D2）。
//   7) wv_jt_oob    —— 8B 绝对表一项指向**另一函数**入口（区域外）→ 区判据
//      失败 → gate。
//   8) wv_jt_data   —— 8B 绝对表一项指向**数据段全局**（g_data_var）→ 目标
//      非已 lift 指令地址 → gate。
//
// 表长纪律（B.3 硬约束）：一切表长仅认防御常数（cmp idx,7; ja），禁扫填充/
// 非法值推导；负例披露原因链。影子样本：本单零 flags 面、比较链 409 影子
// 已覆盖（复用其结论，派活单 §B.4），不新增。
//
// 验收：multiseed REQUIRE_REAL=1（≥1 stub + byte-exact）；e2e 日志含
// "jump-table @ ... entries=8 reg-8B-abs/reg-8B-delta/mem-8B-abs" 五形态命中
// + 三负例 gate note（未检出防御常数 / 不在区域各 ≥1）。

#include "wvmp/sdk/markers.hpp"

#include <cstdio>

// MASM 侧实现（jmp_table8_sample_asm.asm）。
extern "C" unsigned long long wv_jt8_abs(unsigned long long idx);
extern "C" unsigned long long wv_jt8_delta(unsigned long long idx);
extern "C" unsigned long long wv_jt8_djmp(unsigned long long idx);
extern "C" unsigned long long wv_jtm_abs(unsigned long long idx);
extern "C" unsigned long long wv_jtm_movabs(unsigned long long idx);
extern "C" unsigned long long wv_jt_undef(unsigned long long idx);
extern "C" unsigned long long wv_jt_oob(unsigned long long idx);
extern "C" unsigned long long wv_jt_data(unsigned long long idx);

// 切换变量（MASM 经 rip-relative 直读；volatile 防编译器跨调用常量折叠）。
extern "C" volatile unsigned long long g_sel = 0;

// 负例的数据段目标：wv_jt_data 表项之一指向它（目标非指令地址 → gate）。
extern "C" volatile unsigned long long g_data_var = 0x7777;

// 负例的区域外目标：wv_jt_oob 表项之一指向本函数（另一函数的入口）。
extern "C" unsigned long long wv_other_fn(unsigned long long n) {
    return n * 5ull + 3ull;
}

static void run_all(const char* name,
                    unsigned long long (*fn)(unsigned long long),
                    unsigned long long skip) {
    for (unsigned long long i = 0; i < 16; ++i) {
        if (i == skip) continue; // 负例毒表项（指向区域外/数据段）——跳过该 idx
        g_sel = i;
        std::printf("%s(%llu)=0x%llX\n", name, i, fn(i));
    }
}

int main() {
    volatile unsigned long long ok = 1;
    // 正样本：表内 0..7 全路径 + 越界 8..15 走 default（ja 活防御）。
    run_all("jt8_abs", wv_jt8_abs, ~0ull);
    run_all("jt8_delta", wv_jt8_delta, ~0ull);
    run_all("jt8_djmp", wv_jt8_djmp, ~0ull);
    run_all("jtm_abs", wv_jtm_abs, ~0ull);
    run_all("jtm_movabs", wv_jtm_movabs, ~0ull);
    // 负例：idx=3 是毒表项（oob/data），跳过；undef 无防御（无 ja 兜底），
    // 只传表内 0..7（idx≥8 原生读表越界）。
    for (unsigned long long i = 0; i < 8; ++i) {
        g_sel = i;
        std::printf("jt_undef(%llu)=0x%llX\n", i, wv_jt_undef(i));
    }
    run_all("jt_oob", wv_jt_oob, 3ull);
    run_all("jt_data", wv_jt_data, 3ull);
    // 交叉验证：毒表项所在函数其余路径的值（负例 gate 后原生执行）。
    std::printf("other_fn(9)=0x%llX\n", wv_other_fn(9));
    g_sel = 3;
    ok &= (wv_jt8_abs(3) == 0x100 + 3) && (wv_jt8_delta(3) == 0x200 + 3) &&
          (wv_jt8_djmp(3) == 0x300 + 3) && (wv_jtm_abs(3) == 0x400 + 3) &&
          (wv_jtm_movabs(3) == 0x500 + 3) && (wv_jt_undef(3) == 0x600 + 3);
    g_sel = 2; // oob/data 的 idx=3 是毒表项，用 idx=2 交叉验证
    ok &= (wv_jt_oob(2) == 0x700 + 2) && (wv_jt_data(2) == 0x800 + 2);
    g_sel = 99;
    ok &= (wv_jt8_abs(99) == 0x1FF) && (wv_jtm_abs(99) == 0x4FF);
    std::printf("ok=%llu\n", ok);
    return ok == 1 ? 0 : 2;
}
