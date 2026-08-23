#pragma once
#include "wvmp/common/rng.hpp"
#include "wvmp/common/types.hpp"
#include "wvmp/vm/backend.hpp"

#include <cstddef>
#include <string>

namespace wvmp::regvm::runtime {

// =============================================================================
// VmContext —— 解释器机器码与宿主之间唯一的运行时 ABI。
//
// 字段偏移即契约（解释器机器码按这些偏移硬编码访问），顺序/类型禁止改动：
//
//   +0x000  u8*  bytecode     指令流（8xN 字节，不含 blob 头）
//   +0x008  u64  pc           当前指令序号（按条数步进，取字节时 *8）
//   +0x010  u64  regs[32]     虚拟寄存器堆：v0..v15=GPR，v16=rip 占位，
//                             v17=flags（位布局 = isa::kFlag*），v18..v23 暂存
//   +0x110  u64  scratch_mem  Load/Store/Push/Pop 的默认内存基址
//                             （v1 测试用；M2 换真实进程内存基址）
//   +0x118  u64  ret_value    Halt 时写回 regs[v0]
//
// v4 = Rsp（Push/Pop 操作的栈指针，相对 scratch_mem 的偏移）。
// v17 偏移 = 0x10 + 17*8 = 0x98；v4 偏移 = 0x30。
// =============================================================================
struct VmContext {
    u8* bytecode = nullptr;   // +0x000
    u64 pc = 0;               // +0x008
    u64 regs[32] = {};        // +0x010
    u64 scratch_mem = 0;      // +0x110
    u64 ret_value = 0;        // +0x118
};
static_assert(sizeof(VmContext) == 0x120, "VmContext 布局即 ABI，禁止改动");
static_assert(offsetof(VmContext, bytecode) == 0x00);
static_assert(offsetof(VmContext, pc) == 0x08);
static_assert(offsetof(VmContext, regs) == 0x10);
static_assert(offsetof(VmContext, scratch_mem) == 0x110);
static_assert(offsetof(VmContext, ret_value) == 0x118);

// 生成结果。
struct RuntimeGenResult {
    vm::RuntimeImage image;  // code = 完整解释器机器码；vm_entry_offset = 0
                             //（入口即 code 首字节，Win64 调用约定第一参数 RCX=VmContext*）
    std::string asm_dump;    // 调试/回归用：最终汇编文本（含布局注释）
};

// 保护期生成一段位置无关的 x64 解释器机器码（Keystone 汇编）。
//   - 寄存器分配（VM 上下文/PC/flags/字节码基址/码基址 + 10 个临时）每次调用
//     由 rng 随机指派到物理寄存器（rsp 恒不参与，rcx 保留作移位计数 cl）；
//   - 跳转表两遍法：第一遍拿各 handler 偏移，第二遍回填表基址位移；
//   - 失败（汇编错误等）抛 std::runtime_error。
// 线程安全性：单线程保护管道内使用（Rng 非线程安全）。
[[nodiscard]] RuntimeGenResult generate_runtime(wvmp::Rng& rng);

} // namespace wvmp::regvm::runtime
