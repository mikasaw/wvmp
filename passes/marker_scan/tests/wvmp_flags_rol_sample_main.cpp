// MIT-433 (MIT-P1): rol/ror flags partial-preserve 端到端主样本。保护 → 运行 →
// stdout+退出码逐字节比对 (native vs virtualized)。
//
// 形态来源: %TEMP%\p432 复现样本转正 (MIT-432 §6.1 项目主独立复现认定,
// 406 铁律; 自含 MASM marker 桩形保留, 不链 wvmp::sdk)。5 区结构 =
// 前态构造 → rotate → setcc 消费 → 区内 Store 落盘 (427 披露① 观察纪律),
// 分叉面详见 wvmp_flags_rol_sample_asm.asm 头注。
//
// 期望值 (native = 修复后 packed, byte-exact):
//   ror_zdiv=0 rol_zdiv=0 shl_zdiv=0 rol_sf=1 ror_pf=0
// 修复前 (main 0ac661a 旧 CLI 反证): ror_zdiv=1 rol_zdiv=1 rol_sf=0
//   ror_pf=1 → stdout 分叉必 FAIL (multiseed 逐字节比对捕获)。
// 哨兵初值 0xEE: 区内 Store 断链即露形 (与 native 必分叉, 不静默)。

#include <cstdio>

extern "C" {
// 区内 Store 落盘槽 (MASM EXTERNDEF g_wv433_* : BYTE 直引符号)。
unsigned char g_wv433_ror_z  = 0xEE;
unsigned char g_wv433_rol_z  = 0xEE;
unsigned char g_wv433_shl_z  = 0xEE;
unsigned char g_wv433_rol_sf = 0xEE;
unsigned char g_wv433_ror_pf = 0xEE;

void wv433_ror_z();
void wv433_rol_z();
void wv433_shl_z();
void wv433_rol_sf();
void wv433_ror_pf();
}

int main() {
    wv433_ror_z();
    wv433_rol_z();
    wv433_shl_z();
    wv433_rol_sf();
    wv433_ror_pf();
    std::printf("ror_zdiv=%d rol_zdiv=%d shl_zdiv=%d rol_sf=%d ror_pf=%d\n",
                static_cast<int>(g_wv433_ror_z), static_cast<int>(g_wv433_rol_z),
                static_cast<int>(g_wv433_shl_z), static_cast<int>(g_wv433_rol_sf),
                static_cast<int>(g_wv433_ror_pf));
    return 0;
}
