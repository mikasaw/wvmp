#pragma once
#include "wvmp/common/rng.hpp"
#include "wvmp/common/types.hpp"
#include "wvmp/vm/backend.hpp"

#include <array>
#include <cstddef>
#include <string>

namespace wvmp::regvm::runtime {

// callgate handler 跨 native call 必须保留 ctx_，因此 AsmGen::roll()
// 分配 ctx_ 时只能从 callee-saved 寄存器池里抽（Win64 ABI: callee 必须保留
// rbx, rbp, rsi, rdi, r12, r13, r14, r15）。如果 ctx_ 落到 caller-saved，
// callgate step 6 `call t_[0]` 调 native 时 callee 按 ABI clobber 掉 ctx_，
// step 9-10 用 r64(ctx_) 寻址 VmContext 会读到垃圾 → segfault。
// kPhys[] 索引: rax=0, rdx=1, rbx=2, rbp=3, rsi=4, rdi=5, r8=6, r9=7,
//                r10=8, r11=9, r12=10, r13=11, r14=12, r15=13.
// 注意：kPhys 顺序不含 rsp（始终不参与）和 rcx（移位计数保留）。
// 但本池指代的是 vm/regvm/runtime/src/asmgen.cpp 内 kPhys[14] 的下标，含义一致。
// 详见 .multica/issue-10-callgate-ctx-callee-saved.md.
inline constexpr std::array<int, 8> kCalleeSavedIdx = {2, 3, 4, 5, 10, 11, 12, 13};

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
//   +0x120  u64  native_sp    M2-9 call gate: caller 的原始 frame 基址
//                             （即进入 stub 时的 rsp），由 stub_gen 在构造
//                             VmContext 时一次性写入。CallGate handler 据此
//                             把 rsp 切到 native caller 栈帧跑 native call；
//                             native_sp 是 VM 跨指令稳定的值，VM 自身 push/
//                             pop 修改 regs[4] 而不动此字段。
//   +0x128  u64  host_rsp     M2-9 call gate: 解释器运行期间的 host rsp
//                             （= stub entry 完成 push+sub 后的栈顶）。解释器
//                             入口处一次性写入；CallGate handler 用来在 native
//                             call 返回后把 rsp 切回解释器栈。
//   +0x130  u64  base_save    M2-9 call gate: 解释器 BASE 寄存器（码基址）
//                             的暂存槽。CallGate 入口把 BASE 写到此处（BASE
//                             在随机分配中可能落在 caller-saved 寄存器，原生
//                             callee 会清掉）；ret 后从此槽恢复。
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
    u64 native_sp = 0;        // +0x120
    u64 host_rsp = 0;         // +0x128
    u64 base_save = 0;        // +0x130
};
static_assert(sizeof(VmContext) == 0x138, "VmContext 布局即 ABI，禁止改动");
static_assert(offsetof(VmContext, bytecode) == 0x00);
static_assert(offsetof(VmContext, pc) == 0x08);
static_assert(offsetof(VmContext, regs) == 0x10);
static_assert(offsetof(VmContext, scratch_mem) == 0x110);
static_assert(offsetof(VmContext, ret_value) == 0x118);
static_assert(offsetof(VmContext, native_sp) == 0x120);
static_assert(offsetof(VmContext, host_rsp) == 0x128);
static_assert(offsetof(VmContext, base_save) == 0x130);

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
