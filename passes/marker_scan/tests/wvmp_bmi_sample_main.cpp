// MIT-434 (G8a): BMI 折条款目端到端主样本。保护 → 运行 → stdout+退出码
// 逐字节比对 (native vs virtualized)。
//
// 16 正例区 (andn/bzhi/rorx/shlx/sarx/shrx × 三态 + mem 形) 真虚拟化 +
// flags 消费探针 (setcc → 区内 Store 落盘, 427 披露① 观察纪律): rorx 五位
// 保留 (setz/setc/sets/setp)、andn CF=0、bzhi 边界 CF=1/idx0 ZF=1 — 全部
// probe 实测期望, 分叉即 multiseed FAIL。1 负例区 (mulx/pdep/pext/blsr/
// bextr/blsi/blsmsk) C1 gate 整函数原生保持可调用。哨兵初值 0xEE: 区内
// Store 断链即露形 (与 native 必分叉, 不静默)。

#include <cstdio>

extern "C" {
unsigned int g_w434_andn_d1_v     = 0xEEEEEEEEu;
unsigned char g_w434_andn_d1_c    = 0xEE;
unsigned int g_w434_andn_d2_v     = 0xEEEEEEEEu;
unsigned char g_w434_andn_d2_z    = 0xEE;
unsigned int g_w434_andn_indep_v  = 0xEEEEEEEEu;
unsigned int g_w434_andn_mem_v    = 0xEEEEEEEEu;
unsigned char g_w434_andn_mem_z   = 0xEE;
unsigned int g_w434_bzhi_d1_v     = 0xEEEEEEEEu;
unsigned char g_w434_bzhi_d1_z    = 0xEE;
unsigned int g_w434_bzhi_indep_v  = 0xEEEEEEEEu;
unsigned int g_w434_bzhi_mem_v    = 0xEEEEEEEEu;
unsigned char g_w434_bzhi_mem_z   = 0xEE;
unsigned int g_w434_bzhi_bnd_v    = 0xEEEEEEEEu;
unsigned char g_w434_bzhi_bnd_c   = 0xEE;
unsigned char g_w434_bzhi_bnd_z   = 0xEE;
unsigned int g_w434_bzhi_idx0_v   = 0xEEEEEEEEu;
unsigned char g_w434_bzhi_idx0_z  = 0xEE;
unsigned int g_w434_rorx_d1_v     = 0xEEEEEEEEu;
unsigned int g_w434_rorx_indep_v  = 0xEEEEEEEEu;
unsigned int g_w434_rorx_mem_v    = 0xEEEEEEEEu;
unsigned int g_w434_rorx_fl_v     = 0xEEEEEEEEu;
unsigned char g_w434_rorx_fl_z    = 0xEE;
unsigned char g_w434_rorx_fl_c    = 0xEE;
unsigned char g_w434_rorx_fl_s    = 0xEE;
unsigned char g_w434_rorx_fl_p    = 0xEE;
unsigned int g_w434_shlx_v        = 0xEEEEEEEEu;
unsigned char g_w434_shlx_z       = 0xEE;
unsigned int g_w434_sarx_v        = 0xEEEEEEEEu;
unsigned int g_w434_shrx_v        = 0xEEEEEEEEu;
unsigned int g_w434_neg_v         = 0xEEEEEEEEu;

void wv434_andn_d1();
void wv434_andn_d2();
void wv434_andn_indep();
void wv434_andn_mem();
void wv434_bzhi_d1();
void wv434_bzhi_indep();
void wv434_bzhi_mem();
void wv434_bzhi_bnd();
void wv434_bzhi_idx0();
void wv434_rorx_d1();
void wv434_rorx_indep();
void wv434_rorx_mem();
void wv434_rorx_fl();
void wv434_shlx();
void wv434_sarx();
void wv434_shrx();
void wv434_neg();
}

int main() {
    wv434_andn_d1();
    wv434_andn_d2();
    wv434_andn_indep();
    wv434_andn_mem();
    wv434_bzhi_d1();
    wv434_bzhi_indep();
    wv434_bzhi_mem();
    wv434_bzhi_bnd();
    wv434_bzhi_idx0();
    wv434_rorx_d1();
    wv434_rorx_indep();
    wv434_rorx_mem();
    wv434_rorx_fl();
    wv434_shlx();
    wv434_sarx();
    wv434_shrx();
    wv434_neg();
    std::printf(
        "andn_d1=%08X c=%u andn_d2=%08X z=%u andn_indep=%08X andn_mem=%08X z=%u\n"
        "bzhi_d1=%08X z=%u bzhi_indep=%08X bzhi_mem=%08X z=%u\n"
        "bzhi_bnd=%08X c=%u z=%u bzhi_idx0=%08X z=%u\n"
        "rorx_d1=%08X rorx_indep=%08X rorx_mem=%08X\n"
        "rorx_fl=%08X z=%u c=%u s=%u p=%u\n"
        "shlx=%08X z=%u sarx=%08X shrx=%08X neg=%08X\n",
        g_w434_andn_d1_v, g_w434_andn_d1_c, g_w434_andn_d2_v, g_w434_andn_d2_z,
        g_w434_andn_indep_v, g_w434_andn_mem_v, g_w434_andn_mem_z,
        g_w434_bzhi_d1_v, g_w434_bzhi_d1_z, g_w434_bzhi_indep_v, g_w434_bzhi_mem_v,
        g_w434_bzhi_mem_z,
        g_w434_bzhi_bnd_v, g_w434_bzhi_bnd_c, g_w434_bzhi_bnd_z, g_w434_bzhi_idx0_v,
        g_w434_bzhi_idx0_z,
        g_w434_rorx_d1_v, g_w434_rorx_indep_v, g_w434_rorx_mem_v,
        g_w434_rorx_fl_v, g_w434_rorx_fl_z, g_w434_rorx_fl_c, g_w434_rorx_fl_s,
        g_w434_rorx_fl_p,
        g_w434_shlx_v, g_w434_shlx_z, g_w434_sarx_v, g_w434_shrx_v, g_w434_neg_v);
    return 0;
}
