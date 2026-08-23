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
// x86 注意：32 位编译会拆成两条 mov dword（magic 不连续）——v1 不支持，
// 见 markers.hpp 顶部注释。
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
