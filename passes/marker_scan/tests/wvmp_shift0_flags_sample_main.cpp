// MIT-492 (F3): CR-01 零次移位 flags 活跃性的 multiseed 入池样本。
// 保护 → 运行 → stdout+退出码逐字节比对 (native vs virtualized)。
//
// 形态来源: docs/CODE_REVIEW_2026-09-18.md CR-01 最小复现转正 (406 铁律:
// 案例必须转为回归资产)。自含 MASM marker 桩, 不链 wvmp::sdk (433 同款)。
// 7 区分档与逐区期望值详见 wvmp_shift0_flags_sample_asm.asm 头注。
//
// 期望值 (native = 修复后 packed, byte-exact):
//   shl0_z=1 shr0_z=1 sar0_z=1 shl0_nz=0 shlmask0_z=1 shlnz_z=0 shl0_jz=1
// 修复前 (main 基线旧 CLI 反证): shl0_z/shr0_z/sar0_z/shlmask0_z/shl0_jz
//   五区全为 0 → stdout 分叉必 FAIL (multiseed 逐字节比对捕获)。
// 哨兵初值 0xEE: 区内 Store 断链即露形 (与 native 必分叉, 不静默)。

#include <cstdio>

extern "C" {
// 区内 Store 落盘槽 (MASM EXTERNDEF g_wv492_* : BYTE 直引符号)。
unsigned char g_wv492_shl0_z     = 0xEE;
unsigned char g_wv492_shr0_z     = 0xEE;
unsigned char g_wv492_sar0_z     = 0xEE;
unsigned char g_wv492_shl0_nz    = 0xEE;
unsigned char g_wv492_shlmask0_z = 0xEE;
unsigned char g_wv492_shlnz_z    = 0xEE;
unsigned char g_wv492_shl0_jz    = 0xEE;

void wv492_shl0_z();
void wv492_shr0_z();
void wv492_sar0_z();
void wv492_shl0_nz();
void wv492_shlmask0_z();
void wv492_shlnz_z();
void wv492_shl0_jz();
}

int main() {
    wv492_shl0_z();
    wv492_shr0_z();
    wv492_sar0_z();
    wv492_shl0_nz();
    wv492_shlmask0_z();
    wv492_shlnz_z();
    wv492_shl0_jz();
    std::printf(
        "shl0_z=%d shr0_z=%d sar0_z=%d shl0_nz=%d shlmask0_z=%d shlnz_z=%d "
        "shl0_jz=%d\n",
        static_cast<int>(g_wv492_shl0_z), static_cast<int>(g_wv492_shr0_z),
        static_cast<int>(g_wv492_sar0_z), static_cast<int>(g_wv492_shl0_nz),
        static_cast<int>(g_wv492_shlmask0_z), static_cast<int>(g_wv492_shlnz_z),
        static_cast<int>(g_wv492_shl0_jz));
    return 0;
}
