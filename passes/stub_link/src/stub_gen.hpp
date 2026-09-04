#pragma once
#include "wvmp/common/types.hpp"

#include <string>
#include <vector>

namespace wvmp::passes {

// MIT-446 (X4) B.1：stub 目标架构。x64 = Win64 现形（逐字节不动，D2 恒等
// 铁约束）；x86 = Win32 cdecl 形（4 callee-saved push / ctx 经栈参
// [esp+0x14] 对接 runtime_x86 entry / ExitNative 消费 kX86ExitSlotDepth）。
// stub_link pass 按 PeImage.machine 派发（machine=0x014C → X86）。
enum class StubArch { X64, X86 };

// MIT-463 (anti_debug-v1)：stub 入口反调试检查块参数（PEB 面）。
// techniques 位 = anti_debug::tech::*（BeingDebugged/NtGlobalFlag）；非空时
// generate_entry_stub 在解密块/序言之前织入检查块（gs/fs → TEB → PEB 读，
// 命中 = FailFast 写 [0] 确定性崩溃）。nullptr = 无检查（逐字节 v1 前现形）。
struct StubAntiDebug {
    u32 techniques;
};

// MIT-458 (crypt-v1)：stub 入口 one-shot 解密块参数（xor_chain）。
// 非空时 generate_entry_stub 在序言**之前**织入解密块（保存/恢复全部被蹭
// GP 寄存器与 esp 平衡；flags 不保全——序言 sub 既有先例）。nullptr = 无
// 加密（x64 stub 逐字节与 v1 前一致，D2 恒等铁约束）。
struct StubCrypt {
    u64 stream_va;    // 密文流 VA（image_base + blob_stream_rva）
    u64 flag_va;      // 尾区 VA（stream_va + stream_bytes；one-shot：1→0）
    u32 key0;         // xor_chain 初态（立即数嵌入 = 密钥每目标嵌入）
    u32 dword_count;  // 解密字数（stream_bytes / 4）
    // MIT-464: 密文 CRC32 完整性校验（integrity_crc pass 在管道时启用）。
    // 校验在解密**之前**（bitwise CRC32 over 密文，mismatch → FailFast）。
    bool verify_crc;
    u32 crc32;        // 期望值（尾区 [flag][crc32] 的 crc32 槽）
    u32 byte_count;   // 流字节数（= stream_bytes；CRC 逐字节计数）
};

// 生成单个被虚拟化函数的入口 stub（位置无关）。
//
// stub 运行时职责：
//   保存 callee-saved → 在栈上构造 VmContext → 预载全部 GP 虚拟寄存器
//   → 调用共享解释器入口 → HALT 返回后回写易失寄存器 → 恢复现场 →
//   jmp 回原区域 end_rva（恢复执行原 .text 中的 end 标记调用之后流程）。
//
// 地址约定（全 RVA 坐标，与镜像基址无关）：
//   - 以 at=stub_rva 汇编，`call <rt_entry_rva>` / `jmp <resume_rva>` 由
//     汇编器按相对位移编码（运行时随基址平移自动正确）；
//   - x64 唯一 rip 相对引用（blob 指令流指针）用占位 disp32 汇编后回填；
//     x86 无 rip 寻址，blob 指针 = image_base + RVA 立即数（PE32 VA 恒
//     < 4GB，imm32 可编码；ASLR 由 pe_writer 清 DYNAMIC_BASE 兜底）。
//
// image_base（PE optional header 的 ImageBase 字段）写入 VmContext+0x110
// （即 scratch_mem 槽 = 运行时 Load/Store/Push/Pop 用的内存基址）。rip-relative
// 翻译期把 [rip+disp] 算成绝对 RVA 存进字节码；运行时实际访存 = RVA + image_base。
// v1 测试用 image_base=0（绝对地址空间）；M2-8 真实 PE 保护时由 pe_loader
// 解析 PE optional header 取出，经 stub_link 传给本函数。
//
// 所有立即数经 hex() 生成——keystone 裸数字按 16 进制解析（P6 教训）。
//
// MIT-340 派活单目标（ASLR 兼容）未达成：M2-8 stub 仍写入 ImageBase 立即；
// Windows ASLR 重定位后 scratch_mem 错位导致 segfault。完整 ASLR 修复需在
// stub 端用 RIP-relative lea 算 actual_image_base 或在 stub 的 image_base
// 立即上发布 IMAGE_REL_BASED_DIR64 重定位——后者本派活单实测失败（pitfall
// #33 §A 假设错 #11，详见 passes/pe_writer/src/pe_writer_pass.cpp 注释）。
[[nodiscard]] std::vector<u8> generate_entry_stub(u64 stub_rva, u64 blob_stream_rva,
                                                  u64 rt_entry_rva, u64 resume_rva,
                                                  u64 image_base,
                                                  StubArch arch = StubArch::X64,
                                                  const StubCrypt* crypt = nullptr,
                                                  const StubAntiDebug* adb = nullptr);

} // namespace wvmp::passes