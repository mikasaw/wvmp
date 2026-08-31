#include "wvmp/sdk/markers.hpp"

// marker 桩实现：函数体只做一件事——把唯一 magic 立即数落进指令流。
//
// 代码生成依据（x64 / MSVC /Od，已按任务要求以实际反汇编验证）：
//   volatile unsigned long long m = <imm64>;
//     → 48 B8 <8 字节 magic>        mov rax, imm64
//     → 48 89 44 24 XX              mov qword ptr [rsp+X], rax
// 即 magic 以 8 字节 LE 连续出现在 .text 中，是 marker_scan 的扫描锚点。
// volatile 保证读取/写入不被优化删除；不导出（dllexport 会给用户 exe 加
// 导出表），扫描完全依赖字节签名。
//
// x86 注意（X1a / MIT-437 实测，cl v19.51.36256 dumpbin /disasm）：
// 32 位编译把 64 位 magic 拆成两条 imm32（8 字节不连续），优化档位形态不同：
//   /O1 /O2: C7 <mem>,<lo4> ; C7 <mem>,<hi4>           （lo→hi，紧邻）
//   /Od    : B8 <hi4> ; C7 <mem>,<lo4> ; 89 <mem>,reg  （hi→lo，间隔 3B）
// 两方向均被 marker_scan 的双段识别覆盖（scan_core.hpp kBeginPatternX86，
// 间隔容忍窗 kX86MaxHalfGap=8）；magic 全部以立即数操作数形式物化，永不
// 被执行（无 412 §6 坑②的执行毁栈问题，无需 jmp skip）。
#if defined(_MSC_VER)
#define WVMP_SDK_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define WVMP_SDK_NOINLINE __attribute__((noinline))
#else
#define WVMP_SDK_NOINLINE
#endif

namespace wvmp::sdk {

WVMP_SDK_NOINLINE void marker_begin() {
    volatile unsigned long long m = kBeginMagic;
    (void)m;
}

WVMP_SDK_NOINLINE void marker_end() {
    volatile unsigned long long m = kEndMagic;
    (void)m;
}

int api_version() {
    return kApiVersion;
}

} // namespace wvmp::sdk
