// targets/wvmp_protect.h - WVmp 虚拟化标记宏（MIT-379 新增）。
//
// 给需要虚拟化保护的内核提供统一的打标对，在实现文件里包裹函数体：
//   WV_TARGET_NOINLINE void kernel(...)
//   {
//       PROTECT_BEGIN("kernel");
//       ... 函数体 ...
//       PROTECT_END();      // <- 函数收尾处
//   }
//
// 实现方式与 wvmp 主仓 SDK 完全同源：两个宏展开为对非内联桩
// marker_begin / marker_end 的调用，桩体各含一个唯一的 8 字节 magic
// 立即数（"WVMPBEG1" / "WVMPEND1"）。marker_scan pass 在被保护 PE 的
// .text 中定位这些 magic 字节模式，再通过 E8 rel32 调用点回溯用户代码
// 中的标记位置，生成保护区域。
//
// magic 字节规格必须与下列两处保持同步（它们同样跨模块复制、集成测试
// 有同步性断言）：
//   * wvmp/sdk/include/wvmp/sdk/markers.hpp          （kBeginMagic/kEndMagic）
//   * wvmp/passes/marker_scan/.../scan_core.hpp      （kBeginPattern/kEndPattern）
//
// 刻意不 include 主仓 SDK 头、不依赖其库：本工程由单条 cl 命令直编全部
// 源文件（见根目录 build.bat），无法追加头搜索路径或额外链接库，因此此
// 处自包含复刻同一码型。字节级依据（x64 / MSVC /Od，源自 sdk.cpp 实测）：
//   volatile unsigned long long m = <imm64>;
//     -> 48 B8 <8 字节 magic>        mov rax, imm64
//     -> 48 89 44 24 XX              mov qword ptr [rsp+X], rax
// 即 magic 以 8 字节 LE 连续出现在 .text 中。
//
// 注意：含本头的翻译单元应关闭优化（或固定 /Od）——/O2 可能把收尾处
// 的 marker_end() 调用尾调用成 jmp（E8 消失），配对即失败；kernels.cpp
// 以 #pragma optimize("", off) 落实该要求。
#pragma once

#include <stdint.h>

#if defined(_MSC_VER)
#  define WVMP_PROTECT_NOINLINE __declspec(noinline)
#else
#  define WVMP_PROTECT_NOINLINE __attribute__((noinline))
#endif

namespace wvmp_protect {

// 扫描锚点：8 字节 magic 立即数（LE）。
//   kBeginMagic 字节序（LE）= "WVMPBEG1"
//   kEndMagic   字节序（LE）= "WVMPEND1"
inline constexpr unsigned long long kBeginMagic = 0x31474542504D5657ull;
inline constexpr unsigned long long kEndMagic   = 0x31444E45504D5657ull;

// 桩函数（禁止内联：magic 所在函数体必须作为独立实体存活到最终链接；
// static 保证符号不出本编译单元，与未来可能的真 SDK 链接互斥冲突）。
WVMP_PROTECT_NOINLINE static void marker_begin() {
    volatile unsigned long long m = kBeginMagic;
    (void)m;
}

WVMP_PROTECT_NOINLINE static void marker_end() {
    volatile unsigned long long m = kEndMagic;
    (void)m;
}

} // namespace wvmp_protect

// 用法约定（与 kernels.h 注释一致）：BEGIN 放函数体首条语句，END 放
// 函数收尾处（值返回函数放最后一条 return 之前）。name 参数仅为可读性
// 占位，字节签名识别不依赖名字。
#define PROTECT_BEGIN(name) (::wvmp_protect::marker_begin())
#define PROTECT_END()       (::wvmp_protect::marker_end())
