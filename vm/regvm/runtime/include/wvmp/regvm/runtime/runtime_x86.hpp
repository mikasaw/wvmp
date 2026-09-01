#pragma once
#include "wvmp/common/rng.hpp"
#include "wvmp/regvm/runtime/runtime.hpp"

#include <span>

namespace wvmp::regvm::runtime {

// MIT-445 (X3c B.2) 定义、MIT-446 (X4) 迁移：x86 4B 退出槽深度（X0 §3.2-C(4)
// x86 形）。槽地址 = native_sp - kX86ExitSlotDepth（dword；native_sp =
// [ctx+0x120]，stub/电池预置）。x64 同构公式 kExitSlotDepth = stub push +
// kCtxSize + 0x80 余量，x86 侧 stub push 面 = 4（X4 stub 的 4 callee-saved
// push 对应面）；余量 0x80 同 x64（disp8 边界纪律）。runtime.hpp 冻结零触碰
// ——本常量 = x86 面私有单一来源（原定义在 asmgen.cpp 匿名 namespace，X4
// stub_gen 读侧对接需跨 TU 消费，按 B2 单一来源纪律上移本头；asmgen.cpp 保留
// static_assert 防漂移）。
//   stub 入口（esp = ns - 0x10 - kCtxSize）:  mov [esp - 0x80], <VA>
//   stub HALT 段（esp = ns）:                 jmp dword ptr [esp - 0x258]
//   ExitNative handler（native_sp 基准）:     [ns - 0x258]
inline constexpr u64 kX86ExitSlotDepth = 4 * 4 + kCtxSize + 0x80;  // 0x10+0x1C8+0x80 = 0x258
static_assert(kX86ExitSlotDepth == 0x258, "x86 exit slot depth regressed");

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
//   - handler 面 = X3b 起 57 项（X3a 电池集 19 + MIT-444 批迁 38：A 档整数
//     面 Not/Neg/Adc/Sbb/Imul/Mul/Cdq/Shift 族/Movzx·Movsx(+Mem)/Bswap/
//     Xchg/Setcc/Cmovcc/Popcnt/Lzcnt/Tzcnt/Cmpxchg + 锁原子 Xadd/Bts/Btr/
//     Btc + B 档 GP Push/Pop/RVA 族），其余 VmOp 沿既有机制折叠 Halt
//     （跳表缺项 → halt，恢复友好；残余纸面 = Div/Idiv D2 折叠 + Movsxd x86
//     不可达 + CallGate/ExitNative/Ret X3c 协议面 + SSE 族 32）。
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

// MIT-446 (X4)：x86 运行时跳表已登记的 opcode 集合（= asmgen.cpp x86 handler
// 表的 opcode 列，单一事实来源——表加行本函数自动跟随，禁第二份手抄清单）。
// 消费方 = stub_link pass 的 x86 白名单 gate：字节码含集合外 VmOp 的函数整函
// 数保持原生（跳表缺项折叠 Halt 的 C2 类静默错在覆写 .text 前拦截）。
// 返回值指向函数级 static 存储，进程期内有效；单线程管道内使用。
[[nodiscard]] std::span<const int> x86_handler_opcodes();

} // namespace wvmp::regvm::runtime
