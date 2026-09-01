#pragma once
#include "wvmp/common/rng.hpp"
#include "wvmp/regvm/runtime/runtime.hpp"

namespace wvmp::regvm::runtime {

// =============================================================================
// MIT-443 (X3a)：x86 (KS_MODE_32) 解释器码体生成入口 —— asmgen 双模的 32 位面。
//
// generate_runtime（runtime.hpp，x64）零触碰：本头只新增 32 位入口。两者共用
// asmgen.cpp 内同一两遍法管线，差异全部由 AsmGen::HostArch 在生成期分叉：
//
//   - 寄存器模型：x86 可分配池 = kPhys[0..5]（eax/edx/ebx/ebp/esi/edi）6 个
//     （esp 恒不在池、ecx 保留 cl、r8-r15 无 REX 不可编码）；ctx_/base_ 各占
//     callee-saved {ebx,ebp,esi,edi} 之一，pc_/flags_ 内存常驻既有 ctx 槽
//     （+0x8 / +0x98，零新字段 —— D4 kCtxSize 冻结不破），临时 4 个（数据
//     临时 t_[0]/t_[1] 字节可编码约束：al/dl/bl 可用，bpl/sil/dil REX 专属）。
//   - entry BASE 取址 = call/pop idiom（D2 项目主拍板：push 1B + call rel32
//     5B 确定性偏移回指码基址，不涉 pe_writer reloc 面）。
//   - dispatch 跳表保 8B 表项（D3：x86 读表项低 dword，表字节格式与 x64
//     逐位一致，掩码/两遍法逻辑零改动）。
//   - handler 面 = X3a 电池集 19 项（Mov/Lea/Add/Sub/And/Or/Xor/Cmp/Test/
//     Inc/Dec/Load/Store/Jcc/Jmp/Nop/Halt/GetFlags/SetFlags），其余 VmOp 沿
//     既有机制折叠 Halt（跳表缺项 → halt，恢复友好）；全 95 op 批迁 = X3b。
//   - size：S8/S16/S32 三路（x86 翻译器不产 S64；handler 内 S64 块防御 no-op）。
//
// 验证通道 = 32 位测试进程（WOW64）真执行电池 tests/test_runtime_x86.cpp
// （CMake 以 CMAKE_SIZEOF_VOID_P EQUAL 4 门控；x64 码体不可在 64 位进程执行，
// 反向亦然，两层互斥）。x64 零扰动铁证 = 同 seed asm_dump 逐字节对账（D6）。
// =============================================================================

// 保护期生成一段位置无关的 x86 (32 位) 解释器机器码（Keystone KS_MODE_32 汇编）。
// 布局/两遍法/随机化机制与 generate_runtime 相同（runtime.hpp 注）；失败抛
// std::runtime_error。线程安全性：单线程保护管道内使用（Rng 非线程安全）。
[[nodiscard]] RuntimeGenResult generate_runtime_x86(wvmp::Rng& rng);

} // namespace wvmp::regvm::runtime
