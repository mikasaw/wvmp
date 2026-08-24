// MIT-249 follow-up (issue-09): 端到端验证 C1 gate 兜底——lifter 跳过的指令
// (Todo/Unsupported) 不进入 IR, virtualize 见 backend 注的 skip note 放弃
// 虚拟化, 整函数保持原生执行。
//
// 样本故意在 marker 区域内放一条 cpuid (Unsupported, 0F A2), lifter 会跳过
// 该指令并累积到 LiftMetadata.skipped_ranges。protection 走完:
//   marker_scan → lifter (记 cpuid skip) → backend (注 C1 gate note)
//   → virtualize (见 note 放弃) → stub_link (不覆写) → pe_writer。
//
// stdout 应输出 4 个 vendor 字符串中的任意一个 (cpuid 真实结果), 与原生
// 完全一致。如果 C1 gate 失败 (lifter skip 未联动), 区域会被覆写, cpuid
// 路径不再保留, 输出变成随机的填充字节, 测试断言失败。
//
// 参考:
//   cpuid with eax=0 → vendor string at [ebx, edx, ecx]
//   AMD:        "AuthenticAMD"
//   Intel:      "GenuineIntel"
//   Centaur:    "CentaurHauls"
//   其他:       vendor-specific 12-byte string

#include "wvmp/sdk/markers.hpp"

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <intrin.h>

static void cpuid_copy_vendor(char out[13]) {
    int regs[4] = {};
    // MSVC x64 内联汇编 (__asm 不支持 64 位, 用 <intrin.h> 的 __cpuid).
    int a = 0;
    __cpuid(regs, a);
    std::memcpy(out + 0, &regs[1], 4); // ebx
    std::memcpy(out + 4, &regs[3], 4); // edx
    std::memcpy(out + 8, &regs[2], 4); // ecx
    out[12] = '\0';
}

__declspec(noinline) static int region_check_vendor() {
    WVMP_BEGIN(region_check_vendor);
    char vendor[13] = {};
    cpuid_copy_vendor(vendor);
    WVMP_END(region_check_vendor);
    if (std::strcmp(vendor, "GenuineIntel") == 0) return 0;
    if (std::strcmp(vendor, "AuthenticAMD") == 0) return 1;
    if (std::strcmp(vendor, "CentaurHauls") == 0) return 2;
    return 3; // 其它 vendor
}

int main() {
    const int v = region_check_vendor();
    std::printf("vendor_class=%d\n", v);
    return 0;
}