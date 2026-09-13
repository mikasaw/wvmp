// MIT-443 (X3a)：x86 runtime 真执行电池（32 位测试进程，WOW64 下 rc=0）。
//
// 核心思路：generate_runtime_x86 产出的 KS_MODE_32 码体拷入 VirtualAlloc 的
// RWX 页，以 `void entry(VmContext*)`（x86 cdecl：[esp+4]=ctx）在 32 位进程
// 内真执行；字节码程序用 isa::make_insn/append_insn 手工搭建（S8/S16/S32，
// x86 翻译器不产 S64）。
//
// 覆盖（派单 B.5：真执行语义 + capstone 反汇编 + 5 seed）：
//   (1) BootHaltIdleLoop：entry→dispatch→[Halt] 空转闭环（pc+1 写回/ret_value）
//   (2) MovSemantics：Mov/Lea 三宽度 × imm/reg，槽高半字恒 0 不变量
//   (3) AddSubFlags：add/sub 三宽度 + CF/ZF/SF/OF 位断言
//   (4) LogicOps：and/or/xor/test（test 无写回）
//   (5) CmpJcc：E/Ne/L/G/B/Ae 取/不取两路
//   (6) LoopSum：jne 回边求和 1..10（循环闭环 + Halt pc 语义）
//   (7) IncDecCF：inc/dec 值 + SDM "inc/dec 不写 CF" 保留探针
//   (8) LoadStore：绝对 VA 三宽度 roundtrip
//   (9) GetSetFlags：v17 位布局读写
//   (10) DisasmStaticGate：capstone CS_MODE_32 静态审 —— entry call/pop
//        idiom（D2）+ dispatch 掩码 0x7f（D3 8B 表项）+ ≥3 handler 特征指令
//   (11) FiveSeedStability：5 seed 重生成稳定性（442 模式平移）
//
// 仅 32 位工具链构建（CMake 以 CMAKE_SIZEOF_VOID_P EQUAL 4 门控）：x86 码体
// 不可在 64 位进程执行，反向 x64 电池不可在 32 位进程跑，两层互斥。

#include "wvmp/regvm/runtime/runtime_x86.hpp"

#include "wvmp/common/rng.hpp"
#include "wvmp/regvm/codecs/xor_chain.hpp"
#include "wvmp/regvm/isa/encoding.hpp"
#include "wvmp/regvm/isa/vm_op.hpp"
#include "wvmp/regvm/isa/vm_reg.hpp"
#include "wvmp/vm/backend.hpp"

#include <capstone/capstone.h>
#include <keystone/keystone.h>

#include <gtest/gtest.h>

#include <windows.h>

#include <setjmp.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

// 调试期：禁 WER 弹窗，崩溃直接以退出码显形。
struct DisableWerBoxX86 {
    DisableWerBoxX86() { ::SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX); }
};
static const DisableWerBoxX86 kNoWerBoxX86;

namespace {

namespace isa = wvmp::regvm::isa;
namespace rt = wvmp::regvm::runtime;
namespace ir = wvmp::ir;
namespace vm = wvmp::vm;
using wvmp::u8;
using wvmp::u32;
using wvmp::u64;

// ---------------------------------------------------------------------------
// 基础设施（test_runtime.cpp 32 位平移）
// ---------------------------------------------------------------------------
class RwxImage {
public:
    explicit RwxImage(const std::vector<u8>& code) {
        mem_ = VirtualAlloc(nullptr, code.size(), MEM_COMMIT | MEM_RESERVE,
                            PAGE_EXECUTE_READWRITE);
        if (!mem_) throw std::runtime_error("VirtualAlloc(RWX) failed");
        std::memcpy(mem_, code.data(), code.size());
    }
    ~RwxImage() {
        if (mem_) VirtualFree(mem_, 0, MEM_RELEASE);
    }
    RwxImage(const RwxImage&) = delete;
    RwxImage& operator=(const RwxImage&) = delete;

    // x86 cdecl：第一参数压栈，生成码读 [esp+4]。
    using Entry = void (*)(rt::VmContext*);
    Entry entry() const { return reinterpret_cast<Entry>(mem_); }

private:
    void* mem_ = nullptr;
};

// 指令便捷构造（x86 面：S8/S16/S32；S64 为 x86 翻译器不可达面，不用）。
isa::VmInsn mov_imm(u8 dst, u32 imm, ir::Size s = ir::Size::S32) {
    return isa::make_insn(isa::VmOp::Mov, isa::OpKind::Reg, dst, isa::OpKind::Imm, 0, imm,
                          isa::size_field(s));
}
isa::VmInsn bin(isa::VmOp op, u8 dst, u8 rhs, ir::Size s) {
    return isa::make_insn(op, isa::OpKind::Reg, dst, isa::OpKind::Reg, rhs, 0,
                          isa::size_field(s));
}
isa::VmInsn bin_imm(isa::VmOp op, u8 dst, u32 imm, ir::Size s) {
    return isa::make_insn(op, isa::OpKind::Reg, dst, isa::OpKind::Imm, 0, imm,
                          isa::size_field(s));
}
isa::VmInsn halt() {
    return isa::make_insn(isa::VmOp::Halt, isa::OpKind::None, 0, isa::OpKind::None, 0, 0, 0);
}
isa::VmInsn jcc(ir::Cond c, u32 rel) {
    return isa::make_insn(isa::VmOp::Jcc, isa::OpKind::None, 0, isa::OpKind::None, 0, rel,
                          u8(c));
}
isa::VmInsn load(u8 dst, u8 addr, ir::Size s) {
    return isa::make_insn(isa::VmOp::Load, isa::OpKind::Reg, dst, isa::OpKind::Reg, addr, 0,
                          isa::size_field(s));
}
isa::VmInsn store(u8 addr, u8 src, ir::Size s) {
    return isa::make_insn(isa::VmOp::Store, isa::OpKind::Reg, addr, isa::OpKind::Reg, src, 0,
                          isa::size_field(s));
}
isa::VmInsn getflags(u8 dst) {
    return isa::make_insn(isa::VmOp::GetFlags, isa::OpKind::Reg, dst, isa::OpKind::None, 0, 0,
                          isa::size_field(ir::Size::S32));
}

// 执行一段流，返回执行后的上下文。x86 面：Load/Store 直接绝对 VA（32 位）。
rt::VmContext run_stream(RwxImage::Entry entry, const std::vector<u8>& stream, u8* scratch) {
    rt::VmContext ctx;
    ctx.bytecode = const_cast<u8*>(stream.data());
    ctx.pc = 0;
    ctx.scratch_mem = 0;
    ctx.regs[isa::vm_reg_of(ir::Reg::Rsp)] = 0;   // v4（Push/Pop 为 X3b 面，电池不用）
    (void)scratch;
    entry(&ctx);
    return ctx;
}

// 槽高半字恒 0 不变量（x86 guest 值域 ≤32 位）断言。
void expect_slot32(const rt::VmContext& ctx, u8 slot, u32 expect) {
    EXPECT_EQ(ctx.regs[slot], static_cast<u64>(expect)) << "slot=" << int(slot);
}

// MIT-445 (X3c B.1)：CallGate 电池面。callee = 测试进程内真 native 函数
// （WOW64 32 位进程，fnptr 即 u32 VA）。g_xcg_calls 递增 = 真调用证据
// （非纸面/非折叠 Halt）；regs[0] 写回 = 返回值通路断言。
static unsigned long g_xcg_calls = 0;
static u32 __cdecl xcg_probe(void) {
    ++g_xcg_calls;
    return 0x5A5u;
}
// MIT-446 (X4) B.1：参数窗读取面 = guest [v4..v4+4*(N-1)]（固定预置，
// MIT-451 (X5b) B.2 起窗口 8 dword = [v4..v4+0x1C]）。电池 ctx 的 v4 必须指
// 向真实映射缓冲（旧用例 v4=0 在新协议下读 NULL 页）；0-arg callee 不读参
// 数，窗口内容无关，esp 由 host_rsp 重基统一回收。
static alignas(16) u8 g_xcg_stack[0x60];
isa::VmInsn callgate_rva(u32 rva) {
    return isa::make_insn(isa::VmOp::CallGate, isa::OpKind::None, 0,
                          isa::OpKind::None, 0, rva, 0);
}
isa::VmInsn callgate_reg(u8 slot) {
    return isa::make_insn(isa::VmOp::CallGate, isa::OpKind::Reg, slot,
                          isa::OpKind::None, 0, 0, 0);
}

} // namespace

// ---------------------------------------------------------------------------
// (1) 最小码体真跑：entry→dispatch→[Halt] 空转闭环
// ---------------------------------------------------------------------------
TEST(X86Battery, BootHaltIdleLoop) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    ASSERT_FALSE(gen.image.code.empty());
    ASSERT_EQ(gen.image.vm_entry_offset, 0u);
    EXPECT_NE(gen.asm_dump.find("arch: x86 (KS_MODE_32"), std::string::npos);

    RwxImage rwx(gen.image.code);
    std::vector<u8> s;
    isa::append_insn(s, halt());
    const auto ctx = run_stream(rwx.entry(), s, nullptr);
    EXPECT_EQ(ctx.pc, 1u);   // Halt 写回 pc+1（恢复友好）
    EXPECT_EQ(ctx.ret_value, 0u);

    // ret_value = regs[0]（低 dword）；预置非零值再空转验证写回。
    std::vector<u8> s2;
    isa::append_insn(s2, mov_imm(0, 0xDEADBEEFu));
    isa::append_insn(s2, halt());
    const auto ctx2 = run_stream(rwx.entry(), s2, nullptr);
    EXPECT_EQ(ctx2.ret_value, 0xDEADBEEFu);
    EXPECT_EQ(ctx2.pc, 2u);
}

// ---------------------------------------------------------------------------
// (2) Mov/Lea：三宽度 × imm/reg；槽高半字恒 0
// ---------------------------------------------------------------------------
TEST(X86Battery, MovSemantics) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();

    // S32 imm → slot；再 reg→reg 覆盖。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0x11223344));            // 0
        isa::append_insn(s, mov_imm(1, 0x55667788));            // 1
        isa::append_insn(s, bin(isa::VmOp::Mov, 0, 1, ir::Size::S32));  // 2
        isa::append_insn(s, halt());                            // 3
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0x55667788u);
        expect_slot32(ctx, 1, 0x55667788u);
        EXPECT_EQ(ctx.pc, 4u);
    }
    // S8：imm 别名合并（只改低 8 位，保 16..31 位）+ S16。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0xABCD1234));                     // 0
        isa::append_insn(s, bin_imm(isa::VmOp::Mov, 0, 0x61, ir::Size::S8));  // 1
        isa::append_insn(s, halt());                                     // 2
        const auto ctx = run_stream(entry, s, nullptr);
        // native 8 位写保 bits 8..31（= x64 alias_write 语义）：0x1234|0x61。
        EXPECT_EQ(ctx.regs[0], 0xABCD'1261ull);
    }
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0xABCD1234));                     // 0
        isa::append_insn(s, bin_imm(isa::VmOp::Mov, 0, 0xBEEF, ir::Size::S16));  // 1
        isa::append_insn(s, halt());                                     // 2
        const auto ctx = run_stream(entry, s, nullptr);
        EXPECT_EQ(ctx.regs[0], 0xABCD'BEEFull);
    }
    // Lea（v1=值传送）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(1, 0x00403020));             // 0
        isa::append_insn(s, isa::make_insn(isa::VmOp::Lea, isa::OpKind::Reg, 0,
                                           isa::OpKind::Reg, 1, 0,
                                           isa::size_field(ir::Size::S32)));  // 1
        isa::append_insn(s, halt());                             // 2
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0x00403020u);
    }
}

// ---------------------------------------------------------------------------
// (3) Add/Sub + flags：三宽度 + 位断言
// ---------------------------------------------------------------------------
TEST(X86Battery, AddSubFlags) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();

    // S32：add 0x7FFFFFFF + 1 → 0x80000000（OF=1 SF=1 ZF=0 CF=0）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0x7FFFFFFF));
        isa::append_insn(s, mov_imm(1, 1));
        isa::append_insn(s, bin(isa::VmOp::Add, 0, 1, ir::Size::S32));   // 2
        isa::append_insn(s, getflags(2));                                // 3
        isa::append_insn(s, halt());                                     // 4
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0x80000000u);
        // PF = 结果低字节 0x00 偶校验 = 1。
        EXPECT_EQ(ctx.regs[2] & isa::kFlagsMask,
                  isa::kFlagOF | isa::kFlagSF | isa::kFlagPF);
    }
    // S32：0xFFFFFFFF + 1 → 0（ZF=1 CF=1）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0xFFFFFFFFu));
        isa::append_insn(s, mov_imm(1, 1));
        isa::append_insn(s, bin(isa::VmOp::Add, 0, 1, ir::Size::S32));
        isa::append_insn(s, getflags(2));
        isa::append_insn(s, halt());
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0u);
        EXPECT_EQ(ctx.regs[2] & isa::kFlagsMask,
                  isa::kFlagZF | isa::kFlagCF | isa::kFlagPF);
    }
    // S32 sub 借位：1 - 2 → 0xFFFFFFFF（CF=1 SF=1，OF=0）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 1));
        isa::append_insn(s, mov_imm(1, 2));
        isa::append_insn(s, bin(isa::VmOp::Sub, 0, 1, ir::Size::S32));
        isa::append_insn(s, getflags(2));
        isa::append_insn(s, halt());
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0xFFFFFFFFu);
        EXPECT_EQ(ctx.regs[2] & isa::kFlagsMask,
                  isa::kFlagCF | isa::kFlagSF | isa::kFlagPF);
    }
    // S8：add 0x88 + 0x61 = 0xE9（CF=0 SF=1 OF=0 ZF=0；槽 16..31 位保留）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0x11223388));                     // 0
        isa::append_insn(s, mov_imm(1, 0x61));                           // 1
        isa::append_insn(s, bin(isa::VmOp::Add, 0, 1, ir::Size::S8));    // 2
        isa::append_insn(s, getflags(2));                                // 3
        isa::append_insn(s, halt());                                     // 4
        const auto ctx = run_stream(entry, s, nullptr);
        EXPECT_EQ(ctx.regs[0], 0x1122'33E9ull);
        EXPECT_EQ(ctx.regs[2] & isa::kFlagsMask, isa::kFlagSF);
    }
    // S16：sub 借位 0x0001 - 0x0002 → 0xFFFF（S16 RMW 写回，槽高 dword 保持 0）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0x0001));
        isa::append_insn(s, mov_imm(1, 0x0002));
        isa::append_insn(s, bin(isa::VmOp::Sub, 0, 1, ir::Size::S16));
        isa::append_insn(s, getflags(2));
        isa::append_insn(s, halt());
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0xFFFFu);
        // 0x0001-0x0002=0xFFFF：CF=1、SF=1（bit15）、PF=1（低字节 0xFF 偶校验）。
        EXPECT_EQ(ctx.regs[2] & isa::kFlagsMask,
                  isa::kFlagCF | isa::kFlagSF | isa::kFlagPF);
    }
}

// ---------------------------------------------------------------------------
// (4) And/Or/Xor/Test
// ---------------------------------------------------------------------------
TEST(X86Battery, LogicOps) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();

    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0xF0F0F0F0u));            // 0
        isa::append_insn(s, mov_imm(1, 0x0FF00FF0u));            // 1
        isa::append_insn(s, bin(isa::VmOp::And, 0, 1, ir::Size::S32));  // 2
        isa::append_insn(s, bin(isa::VmOp::Or, 0, 1, ir::Size::S32));   // 3
        isa::append_insn(s, bin(isa::VmOp::Xor, 0, 1, ir::Size::S32));  // 4
        isa::append_insn(s, halt());                             // 5
        u32 expect = 0xF0F0F0F0u;
        expect &= 0x0FF00FF0u;
        expect |= 0x0FF00FF0u;
        expect ^= 0x0FF00FF0u;
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, expect);
        EXPECT_EQ(ctx.pc, 6u);
    }
    // Test：无写回（dst 不变）+ ZF 落 flags。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0x1));                    // 0
        isa::append_insn(s, mov_imm(1, 0x2));                    // 1
        isa::append_insn(s, bin(isa::VmOp::Test, 0, 1, ir::Size::S32));  // 2
        isa::append_insn(s, getflags(2));                        // 3
        isa::append_insn(s, halt());                             // 4
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0x1u);   // test 不写回
        EXPECT_EQ(ctx.regs[2] & isa::kFlagsMask,
                  isa::kFlagZF | isa::kFlagPF);   // PF: 低字节 0x00 偶校验
    }
}

// ---------------------------------------------------------------------------
// (5) Cmp + Jcc：取/不取两路（含有符号/无符号边界）
// ---------------------------------------------------------------------------
TEST(X86Battery, CmpJcc) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();

    auto run_cmp_jcc = [&](ir::Cond c, u32 a, u32 b) {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, a));
        isa::append_insn(s, mov_imm(1, b));
        isa::append_insn(s, bin(isa::VmOp::Cmp, 0, 1, ir::Size::S32));   // 2
        isa::append_insn(s, jcc(c, 2));                                  // 3 → 5
        isa::append_insn(s, mov_imm(2, 222));                            // 4（不取路径）
        isa::append_insn(s, halt());                                     // 5
        return run_stream(entry, s, nullptr).regs[2];
    };
    // E/Ne。
    EXPECT_EQ(run_cmp_jcc(ir::Cond::E, 5, 5), 0u);       // 取 → 跳过赋值
    EXPECT_EQ(run_cmp_jcc(ir::Cond::E, 5, 6), 222u);
    EXPECT_EQ(run_cmp_jcc(ir::Cond::Ne, 5, 6), 0u);
    EXPECT_EQ(run_cmp_jcc(ir::Cond::Ne, 5, 5), 222u);
    // 有符号：0xFFFFFFFD(-3) < 1。
    EXPECT_EQ(run_cmp_jcc(ir::Cond::L, 0xFFFFFFFDu, 1), 0u);
    EXPECT_EQ(run_cmp_jcc(ir::Cond::L, 1, 0xFFFFFFFDu), 222u);
    EXPECT_EQ(run_cmp_jcc(ir::Cond::G, 1, 0xFFFFFFFDu), 0u);
    EXPECT_EQ(run_cmp_jcc(ir::Cond::G, 7, 7), 222u);     // 相等不取
    // 无符号：0xFFFFFFFD > 1。
    EXPECT_EQ(run_cmp_jcc(ir::Cond::B, 0xFFFFFFFDu, 1), 222u);
    EXPECT_EQ(run_cmp_jcc(ir::Cond::B, 1, 0xFFFFFFFDu), 0u);
    EXPECT_EQ(run_cmp_jcc(ir::Cond::Ae, 1, 1), 0u);      // 相等取（≥）
    EXPECT_EQ(run_cmp_jcc(ir::Cond::A, 1, 1), 222u);     // 相等不取（>）
}

// ---------------------------------------------------------------------------
// (6) 循环闭环：jne 回边求和 1..10
// ---------------------------------------------------------------------------
TEST(X86Battery, LoopSum) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    std::vector<u8> s;
    isa::append_insn(s, mov_imm(0, 0));                              // 0
    isa::append_insn(s, mov_imm(1, 10));                             // 1
    isa::append_insn(s, bin(isa::VmOp::Add, 0, 1, ir::Size::S32));   // 2 循环头
    isa::append_insn(s, bin(isa::VmOp::Dec, 1, 1, ir::Size::S32));   // 3
    isa::append_insn(s, jcc(ir::Cond::Ne, u32(-2)));                 // 4 → 回 2
    isa::append_insn(s, halt());                                     // 5
    const auto ctx = run_stream(rwx.entry(), s, nullptr);
    EXPECT_EQ(ctx.regs[0], 55u);
    EXPECT_EQ(ctx.regs[1], 0u);
    EXPECT_EQ(ctx.pc, 6u);
}

// ---------------------------------------------------------------------------
// (7) Inc/Dec：值 + SDM "inc/dec 不写 CF" 保留探针
// ---------------------------------------------------------------------------
TEST(X86Battery, IncDecCF) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();

    // 前置 sub 0-1 制造 CF=1 → inc 不动 CF（x64 build_incdec 同语义）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0));                              // 0
        isa::append_insn(s, mov_imm(1, 1));                              // 1
        isa::append_insn(s, bin(isa::VmOp::Sub, 0, 1, ir::Size::S32));   // 2  CF=1, v0=0xFFFFFFFF
        isa::append_insn(s, bin(isa::VmOp::Inc, 0, 0, ir::Size::S32));   // 3  v0=0, CF 应保留
        isa::append_insn(s, getflags(2));                                // 4
        isa::append_insn(s, halt());                                     // 5
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0u);   // 0xFFFFFFFF+1 回绕
        EXPECT_EQ(ctx.regs[2] & isa::kFlagCF, isa::kFlagCF);   // CF 保留
        EXPECT_EQ(ctx.regs[2] & isa::kFlagZF, isa::kFlagZF);   // inc 结果 0 → ZF=1
    }
    // dec 0xFFFF → 0xFFFE（S16）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0xFFFF));
        isa::append_insn(s, bin(isa::VmOp::Dec, 0, 0, ir::Size::S16));
        isa::append_insn(s, getflags(2));
        isa::append_insn(s, halt());
        const auto ctx = run_stream(entry, s, nullptr);
        EXPECT_EQ(ctx.regs[0], 0xFFFEu);
        EXPECT_EQ(ctx.regs[2] & isa::kFlagZF, 0u);
    }
}

// ---------------------------------------------------------------------------
// (8) Load/Store：绝对 VA 三宽度 roundtrip
// ---------------------------------------------------------------------------
TEST(X86Battery, LoadStore) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    alignas(4) std::array<u8, 0x100> scratch{};
    scratch.fill(0);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();
    const u32 data_addr = static_cast<u32>(reinterpret_cast<uintptr_t>(scratch.data())) + 0x10;

    // S32 store → load roundtrip；S8/S16 部分写后整读。
    std::vector<u8> s;
    isa::append_insn(s, mov_imm(5, data_addr));                      // 0  地址
    isa::append_insn(s, mov_imm(6, 0xABCD1234));                     // 1
    isa::append_insn(s, store(5, 6, ir::Size::S32));                 // 2
    isa::append_insn(s, load(7, 5, ir::Size::S32));                  // 3
    isa::append_insn(s, mov_imm(8, 0x5A));                           // 4
    isa::append_insn(s, store(5, 8, ir::Size::S8));                  // 5  低字节覆写
    isa::append_insn(s, load(9, 5, ir::Size::S32));                  // 6
    isa::append_insn(s, halt());                                     // 7
    const auto ctx = run_stream(entry, s, scratch.data());
    expect_slot32(ctx, 7, 0xABCD1234u);
    // S8 store 只写内存低字节：[data]=0x34 → 0x5A，slot 7 读回 0xABCD125A。
    expect_slot32(ctx, 9, 0xABCD125Au);
    EXPECT_EQ(scratch[0x10], 0x5A);
    EXPECT_EQ(scratch[0x13], 0xAB);
    EXPECT_EQ(ctx.pc, 8u);
}

// ---------------------------------------------------------------------------
// (9) GetFlags/SetFlags 位布局
// ---------------------------------------------------------------------------
TEST(X86Battery, GetSetFlags) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();

    // setflags 0x15（= 0b10101 = ZF|OF|PF）→ getflags 读回。
    std::vector<u8> s;
    isa::append_insn(s, mov_imm(0, 0x15));                           // 0
    isa::append_insn(s, isa::make_insn(isa::VmOp::SetFlags, isa::OpKind::Reg, 0,
                                       isa::OpKind::None, 0, 0,
                                       isa::size_field(ir::Size::S32)));  // 1
    isa::append_insn(s, getflags(1));                                // 2
    isa::append_insn(s, halt());                                     // 3
    const auto ctx = run_stream(entry, s, nullptr);
    EXPECT_EQ(ctx.regs[1] & isa::kFlagsMask, isa::kFlagZF | isa::kFlagOF | isa::kFlagPF);
    // v17 槽与 flags 缓存同址（ctx+0x98）。
    EXPECT_EQ(ctx.regs[17] & isa::kFlagsMask, isa::kFlagZF | isa::kFlagOF | isa::kFlagPF);
}

// ---------------------------------------------------------------------------
// (10) capstone CS_MODE_32 反汇编静态审（B.5 ②反汇编断言）
// ---------------------------------------------------------------------------
TEST(X86Battery, DisasmStaticGate) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);

    // 调试钩子（verify_x86_dump.py --code 消费面）：WVMP_X86_CODE_DUMP=<win
    // 路径> 时把 image.code 落盘。不影响断言。
    {
        char* cp = nullptr;
        size_t cp_len = 0;
        if (_dupenv_s(&cp, &cp_len, "WVMP_X86_CODE_DUMP") == 0 && cp && cp_len > 1) {
            FILE* f = nullptr;
            if (fopen_s(&f, cp, "wb") == 0 && f) {
                std::fwrite(gen.image.code.data(), 1, gen.image.code.size(), f);
                std::fclose(f);
            }
        }
        std::free(cp);
    }
    // 调试钩子（verify_x86_dump.py --asm 消费面）：WVMP_X86_ASM_DUMP=<win
    // 路径> 时把 asm_dump 文本落盘（MIT-X7 批二补齐，与 CODE_DUMP 同款；
    // 此前 --asm 只能从临时贴文本取，门不可独立复跑）。
    {
        char* ap = nullptr;
        size_t ap_len = 0;
        if (_dupenv_s(&ap, &ap_len, "WVMP_X86_ASM_DUMP") == 0 && ap && ap_len > 1) {
            FILE* f = nullptr;
            if (fopen_s(&f, ap, "wb") == 0 && f) {
                std::fwrite(gen.asm_dump.data(), 1, gen.asm_dump.size(), f);
                std::fclose(f);
            }
        }
        std::free(ap);
    }

    csh handle = 0;
    ASSERT_EQ(cs_open(CS_ARCH_X86, CS_MODE_32, &handle), CS_ERR_OK);
    struct CsCloser { csh h; ~CsCloser() { cs_close(&h); } } closer{handle};

    // dump 头解析 entry/dispatch/table 偏移（生成器单点输出）。
    u64 dispatch_off = 0, table_off = 0;
    {
        const size_t p = gen.asm_dump.find("dispatch=+0x");
        ASSERT_NE(p, std::string::npos);
        dispatch_off = std::strtoull(gen.asm_dump.c_str() + p + 12, nullptr, 16);
        const size_t q = gen.asm_dump.find("table=+0x");
        ASSERT_NE(q, std::string::npos);
        table_off = std::strtoull(gen.asm_dump.c_str() + q + 9, nullptr, 16);
        EXPECT_NE(dispatch_off, 0u);
        EXPECT_GT(table_off, dispatch_off);
    }

    // entry：push → call → pop → sub（D2 call/pop idiom，确定性 6 字节回指）。
    {
        cs_insn* insn = nullptr;
        const size_t n = cs_disasm(handle, gen.image.code.data(), 32, 0, 0, &insn);
        ASSERT_GE(n, 4u);
        EXPECT_STREQ(insn[0].mnemonic, "push");
        EXPECT_STREQ(insn[1].mnemonic, "call");
        EXPECT_STREQ(insn[2].mnemonic, "pop");
        EXPECT_STREQ(insn[3].mnemonic, "sub");
        EXPECT_NE(std::strstr(insn[3].op_str, "6"), nullptr)
            << "entry BASE 回指常量（push 1B + call rel32 5B）";
        EXPECT_EQ(insn[1].address + insn[1].size, 6u)
            << "call 后 .next 偏移 = 6（pop 取址点）";
        cs_free(insn, n);
    }

    // dispatch：and 0x7f（7 位掩码）+ 跳表 8B 表项读取（D3）+ jmp reg。
    {
        cs_insn* insn = nullptr;
        const size_t n = cs_disasm(handle, gen.image.code.data() + dispatch_off,
                                   48, dispatch_off, 0, &insn);
        ASSERT_GT(n, 0u);
        bool have_and = false, have_jmp_reg = false;
        for (size_t i = 0; i < n; ++i) {
            if (std::strcmp(insn[i].mnemonic, "and") == 0 &&
                std::strstr(insn[i].op_str, "0x7f") != nullptr)
                have_and = true;
            if (std::strcmp(insn[i].mnemonic, "jmp") == 0 &&
                insn[i].op_str[0] != '0' && std::strstr(insn[i].op_str, "e") != nullptr)
                have_jmp_reg = true;
        }
        EXPECT_TRUE(have_and) << "dispatch opcode 掩码 kTableEntries-1";
        EXPECT_TRUE(have_jmp_reg) << "dispatch 跳表间接跳转";
        cs_free(insn, n);
    }

    // handler 特征（≥3）：dump 逐 handler 文本定位 + 反汇编，特征指令在场。
    const struct { const char* name; const char* mnemonic; } kProbe[] = {
        {"add", "add"}, {"sub", "sub"}, {"mov", "movzx"}, {"halt", "ret"},
    };
    for (const auto& p : kProbe) {
        const std::string key = std::string("; ---- handler ") + p.name + " @ +0x";
        const size_t hp = gen.asm_dump.find(key);
        ASSERT_NE(hp, std::string::npos) << "handler " << p.name;
        const u64 off = std::strtoull(gen.asm_dump.c_str() + hp + key.size(), nullptr, 16);
        ASSERT_LT(off, table_off);
        cs_insn* insn = nullptr;
        const size_t n = cs_disasm(handle, gen.image.code.data() + off,
                                   size_t(table_off - off), off, 0, &insn);
        ASSERT_GT(n, 0u);
        bool found = false;
        for (size_t i = 0; i < n; ++i)
            if (std::strcmp(insn[i].mnemonic, p.mnemonic) == 0) { found = true; break; }
        EXPECT_TRUE(found) << "handler " << p.name << " 缺特征指令 " << p.mnemonic;
        cs_free(insn, n);
    }
}

// ---------------------------------------------------------------------------
// (11) 5 seed 随机化重生成稳定性（442 模式平移：同组语义全过）
// ---------------------------------------------------------------------------
namespace {

void run_core_battery(const vm::RuntimeImage& image) {
    RwxImage rwx(image.code);
    const auto entry = rwx.entry();

    // 空转闭环。
    {
        std::vector<u8> s;
        isa::append_insn(s, halt());
        EXPECT_EQ(run_stream(entry, s, nullptr).pc, 1u);
    }
    // 算术 + flags。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0x7FFFFFFF));
        isa::append_insn(s, mov_imm(1, 1));
        isa::append_insn(s, bin(isa::VmOp::Add, 0, 1, ir::Size::S32));
        isa::append_insn(s, getflags(2));
        isa::append_insn(s, halt());
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0x80000000u);
        EXPECT_EQ(ctx.regs[2] & isa::kFlagsMask,
                  isa::kFlagOF | isa::kFlagSF | isa::kFlagPF);
    }
    // 循环。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0));
        isa::append_insn(s, mov_imm(1, 10));
        isa::append_insn(s, bin(isa::VmOp::Add, 0, 1, ir::Size::S32));
        isa::append_insn(s, bin(isa::VmOp::Dec, 1, 1, ir::Size::S32));
        isa::append_insn(s, jcc(ir::Cond::Ne, u32(-2)));
        isa::append_insn(s, halt());
        const auto ctx = run_stream(entry, s, nullptr);
        EXPECT_EQ(ctx.regs[0], 55u);
    }
    // —— X3b 批迁面抽样（B.4：≥15 op 稳定性抽查，非全乘）——
    alignas(4) std::array<u8, 0x40> scratch{};
    scratch.fill(0);
    const u32 data_va = static_cast<u32>(reinterpret_cast<uintptr_t>(scratch.data())) + 0x10;
    const u8 rsp_slot = isa::vm_reg_of(ir::Reg::Rsp);
    const u8 rax_slot = isa::vm_reg_of(ir::Reg::Rax);
    const u8 rdx_slot = isa::vm_reg_of(ir::Reg::Rdx);
    const u8 rcx_slot = isa::vm_reg_of(ir::Reg::Rcx);
    auto run_x = [&](const std::vector<u8>& stream, u32 rsp, u64 base) {
        rt::VmContext ctx;
        ctx.bytecode = const_cast<u8*>(stream.data());
        ctx.pc = 0;
        ctx.scratch_mem = base;
        ctx.regs[rsp_slot] = rsp;
        entry(&ctx);
        return ctx;
    };
    auto setfl = [](u8 d) {
        return isa::make_insn(isa::VmOp::SetFlags, isa::OpKind::Reg, d,
                              isa::OpKind::None, 0, 0, isa::size_field(ir::Size::S32));
    };
    auto push_i = [](u32 v) {
        return isa::make_insn(isa::VmOp::Push, isa::OpKind::Imm, 0, isa::OpKind::None, 0, v,
                              isa::size_field(ir::Size::S32));
    };
    auto pop_r = [](u8 d) {
        return isa::make_insn(isa::VmOp::Pop, isa::OpKind::Reg, d, isa::OpKind::None, 0, 0,
                              isa::size_field(ir::Size::S32));
    };
    // 链一：adc→not→neg→shl→imul→bswap→xchg→popcnt（值传播逐站断言终点）。
    //   CF=1: adc(0xFFFFFFFF,0)→0；not→0xFFFFFFFF；neg→1；shl 3→8；
    //   imul(8)→64；bswap(0x40)→0x40000000；xchg v1=0x12000004 → v0=4；
    //   popcnt(0x40000000)=1。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(3, 2));
        isa::append_insn(s, setfl(3));
        isa::append_insn(s, mov_imm(0, 0xFFFFFFFFu));
        isa::append_insn(s, mov_imm(1, 0));
        isa::append_insn(s, bin(isa::VmOp::Adc, 0, 1, ir::Size::S32));
        isa::append_insn(s, bin(isa::VmOp::Not, 0, 0, ir::Size::S32));
        isa::append_insn(s, bin(isa::VmOp::Neg, 0, 0, ir::Size::S32));
        isa::append_insn(s, bin_imm(isa::VmOp::Shl, 0, 3, ir::Size::S32));
        isa::append_insn(s, bin(isa::VmOp::Imul, 0, 0, ir::Size::S32));
        isa::append_insn(s, bin(isa::VmOp::Bswap, 0, 0, ir::Size::S32));
        isa::append_insn(s, mov_imm(1, 0x12000004u));
        isa::append_insn(s, bin(isa::VmOp::Xchg, 0, 1, ir::Size::S32));
        isa::append_insn(s, bin(isa::VmOp::Popcnt, 0, 1, ir::Size::S32));
        isa::append_insn(s, halt());
        const auto ctx = run_x(s, 0, 0);
        expect_slot32(ctx, 0, 1u);
        expect_slot32(ctx, 1, 0x40000000u);
    }
    // 链二：mul 双槽 + cdq 符号位（Rax=0x80000000 × 2 → Rdx:Rax = 1:0）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(rax_slot, 0x80000000u));
        isa::append_insn(s, mov_imm(1, 2));
        isa::append_insn(s, bin(isa::VmOp::Mul, rdx_slot, 1, ir::Size::S32));
        isa::append_insn(s, halt());
        const auto ctx = run_x(s, 0, 0);
        expect_slot32(ctx, rax_slot, 0u);
        expect_slot32(ctx, rdx_slot, 1u);
    }
    // 链三：rolcl→shr→sar(0)→tzcnt→cmp/setcc→cmovcc（flags 通路）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0x80000001u));
        isa::append_insn(s, mov_imm(rcx_slot, 1));
        isa::append_insn(s, isa::make_insn(isa::VmOp::RolCl, isa::OpKind::Reg, 0,
                                           isa::OpKind::Reg, rcx_slot, 0,
                                           isa::size_field(ir::Size::S32)));
        isa::append_insn(s, bin_imm(isa::VmOp::Shr, 0, 1, ir::Size::S32));
        isa::append_insn(s, bin_imm(isa::VmOp::Sar, 0, 0, ir::Size::S32));
        isa::append_insn(s, bin(isa::VmOp::Tzcount, 0, 0, ir::Size::S32));
        isa::append_insn(s, bin(isa::VmOp::Cmp, 0, 0, ir::Size::S32));
        isa::append_insn(s, isa::make_insn(isa::VmOp::Setcc, isa::OpKind::Reg, 2,
                                           isa::OpKind::None, 0, 0,
                                           static_cast<u8>(ir::Cond::E)));
        isa::append_insn(s, mov_imm(3, 0x77u));
        isa::append_insn(s, isa::make_insn(isa::VmOp::Cmovcc, isa::OpKind::Reg, 0,
                                           isa::OpKind::Reg, 3, 0x50000000u,
                                           isa::size_field(ir::Size::S32)));
        isa::append_insn(s, halt());
        const auto ctx = run_x(s, 0, 0);
        expect_slot32(ctx, 0, 0u);            // cmovcc(Ne) 不取（ZF=1）
        expect_slot32(ctx, 2, 1u);
    }
    // 链四：xadd/bts 真内存 + push/pop 栈闭环。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(1, data_va));
        isa::append_insn(s, mov_imm(2, 5));
        isa::append_insn(s, isa::make_insn(isa::VmOp::Xadd, isa::OpKind::Reg, 1,
                                           isa::OpKind::Reg, 2, 0,
                                           isa::size_field(ir::Size::S32)));
        isa::append_insn(s, isa::make_insn(isa::VmOp::Bts, isa::OpKind::Reg, 1,
                                           isa::OpKind::Imm, 0, 7,
                                           isa::size_field(ir::Size::S32)));
        isa::append_insn(s, push_i(0xBEEF1234u));
        isa::append_insn(s, pop_r(5));
        isa::append_insn(s, halt());
        const auto ctx = run_x(s, data_va + 0x10, 0);
        expect_slot32(ctx, 2, 0u);
        expect_slot32(ctx, 5, 0xBEEF1234u);
        EXPECT_EQ(ctx.regs[rsp_slot], static_cast<u64>(data_va + 0x10));
        u32 mem;
        std::memcpy(&mem, scratch.data() + 0x10, 4);
        EXPECT_EQ(mem, 0x85u);
    }
    // 链五：storerva/loadrva/learva（base = scratch-0x1000，VA=base+RVA）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(1, 0x1000u));
        isa::append_insn(s, mov_imm(2, 0x5Au));
        isa::append_insn(s, isa::make_insn(isa::VmOp::StoreRva, isa::OpKind::Reg, 1,
                                           isa::OpKind::Reg, 2, 0,
                                           isa::size_field(ir::Size::S32)));
        isa::append_insn(s, isa::make_insn(isa::VmOp::LoadRva, isa::OpKind::Reg, 3,
                                           isa::OpKind::Reg, 1, 0,
                                           isa::size_field(ir::Size::S32)));
        isa::append_insn(s, isa::make_insn(isa::VmOp::LeaRva, isa::OpKind::Reg, 4,
                                           isa::OpKind::Reg, 1, 0,
                                           isa::size_field(ir::Size::S32)));
        isa::append_insn(s, halt());
        const u64 base = reinterpret_cast<u64>(scratch.data()) - 0x1000;
        const auto ctx = run_x(s, 0, base);
        expect_slot32(ctx, 3, 0x5Au);
        expect_slot32(ctx, 4, static_cast<u32>(base + 0x1000));
    }
}

} // namespace

TEST(X86Battery, FiveSeedStability) {
    const u64 seeds[] = {1, 12345, 99999, 3735928559ull, 3405691582ull};
    for (u64 seed : seeds) {
        wvmp::Rng rng(seed);
        const auto gen = rt::generate_runtime_x86(rng);
        ASSERT_FALSE(gen.image.code.empty()) << "seed=" << seed;
        EXPECT_NE(gen.asm_dump.find("vm_entry:"), std::string::npos);
        EXPECT_NE(gen.asm_dump.find("dispatch:"), std::string::npos);
        run_core_battery(gen.image) ;
    }
}

// ---------------------------------------------------------------------------
// (12) X3b 批次一：Not/Neg（一元 + neg flags 语义）
// ---------------------------------------------------------------------------
TEST(X86Battery, NotNegOps) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();

    // not S32：按位取反，无 flags。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0x0F0F0F0Fu));                 // 0
        isa::append_insn(s, bin(isa::VmOp::Not, 0, 0, ir::Size::S32));  // 1
        isa::append_insn(s, halt());                                  // 2
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0xF0F0F0F0u);
    }
    // not S8：低 8 位取反，槽 8..31 位保留（alias_write 语义）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0xABCD1200));                     // 0
        isa::append_insn(s, bin(isa::VmOp::Not, 0, 0, ir::Size::S8));    // 1
        isa::append_insn(s, halt());                                     // 2
        const auto ctx = run_stream(entry, s, nullptr);
        EXPECT_EQ(ctx.regs[0], 0xABCD'12FFull);
    }
    // neg S32：5 → 0xFFFFFFFB，CF=1（SDM: neg 非 0 → CF=1）、SF=1；PF=0
    //（低字节 0xFB = 7 个 1，奇校验）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 5));                              // 0
        isa::append_insn(s, bin(isa::VmOp::Neg, 0, 0, ir::Size::S32));   // 1
        isa::append_insn(s, getflags(2));                                // 2
        isa::append_insn(s, halt());                                     // 3
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0xFFFFFFFBu);
        EXPECT_EQ(ctx.regs[2] & isa::kFlagsMask,
                  isa::kFlagCF | isa::kFlagSF);
    }
    // neg S32 0 → 0：CF=0 ZF=1 PF=1（0x00 偶校验）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0));                              // 0
        isa::append_insn(s, bin(isa::VmOp::Neg, 0, 0, ir::Size::S32));   // 1
        isa::append_insn(s, getflags(2));                                // 2
        isa::append_insn(s, halt());                                     // 3
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0u);
        EXPECT_EQ(ctx.regs[2] & isa::kFlagsMask, isa::kFlagZF | isa::kFlagPF);
    }
    // neg S16：0x0005 → 0xFFFB（S16 RMW 保高位）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0x1234'0005ull));                 // 0
        isa::append_insn(s, bin(isa::VmOp::Neg, 0, 0, ir::Size::S16));   // 1
        isa::append_insn(s, halt());                                     // 2
        const auto ctx = run_stream(entry, s, nullptr);
        EXPECT_EQ(ctx.regs[0], 0x1234'FFFBull);
    }
}

// ---------------------------------------------------------------------------
// (13) X3b 批次一：Adc/Sbb（CF_in 链路 —— SetFlags 布 CF 后真执行）
// ---------------------------------------------------------------------------
TEST(X86Battery, AdcSbbCarry) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();

    auto setflags = [&](u8 dst) {
        return isa::make_insn(isa::VmOp::SetFlags, isa::OpKind::Reg, dst,
                              isa::OpKind::None, 0, 0, isa::size_field(ir::Size::S32));
    };

    // adc + CF_in=1：0xFFFFFFFF + 0 + 1 = 0（CF_out=1 ZF=1）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(3, 2));                              // 0  CF=1
        isa::append_insn(s, setflags(3));                                // 1
        isa::append_insn(s, mov_imm(0, 0xFFFFFFFFu));                    // 2
        isa::append_insn(s, mov_imm(1, 0));                              // 3
        isa::append_insn(s, bin(isa::VmOp::Adc, 0, 1, ir::Size::S32));   // 4
        isa::append_insn(s, getflags(2));                                // 5
        isa::append_insn(s, halt());                                     // 6
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0u);
        EXPECT_EQ(ctx.regs[2] & isa::kFlagsMask,
                  isa::kFlagZF | isa::kFlagCF | isa::kFlagPF);
    }
    // adc + CF_in=0：1 + 2 = 3（CF=0，SF=0）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(3, 0));                              // 0  CF=0
        isa::append_insn(s, setflags(3));                                // 1
        isa::append_insn(s, mov_imm(0, 1));                              // 2
        isa::append_insn(s, mov_imm(1, 2));                              // 3
        isa::append_insn(s, bin(isa::VmOp::Adc, 0, 1, ir::Size::S32));   // 4
        isa::append_insn(s, getflags(2));                                // 5
        isa::append_insn(s, halt());                                     // 6
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 3u);
        EXPECT_EQ(ctx.regs[2] & isa::kFlagCF, 0u);
    }
    // adc 双精度链：低 32 add 进位 → 高 32 adc（x64 侧 adc 的经典用途）。
    // low = 0xFFFFFFFF + 1 = 0 (CF=1)；high = 0 + 0 + 1 = 1。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0xFFFFFFFFu));                    // 0  lo_a
        isa::append_insn(s, mov_imm(1, 1));                              // 1  lo_b
        isa::append_insn(s, bin(isa::VmOp::Add, 0, 1, ir::Size::S32));   // 2  lo, CF=1
        isa::append_insn(s, mov_imm(3, 0));                              // 3  hi_a
        isa::append_insn(s, mov_imm(4, 0));                              // 4  hi_b
        isa::append_insn(s, bin(isa::VmOp::Adc, 3, 4, ir::Size::S32));   // 5  hi, CF_in=1
        isa::append_insn(s, halt());                                     // 6
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0u);
        expect_slot32(ctx, 3, 1u);
    }
    // sbb + CF_in=1：5 - 3 - 1 = 1（CF=0）；SDM 借位语义。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(3, 2));                              // 0  CF=1
        isa::append_insn(s, setflags(3));                                // 1
        isa::append_insn(s, mov_imm(0, 5));                              // 2
        isa::append_insn(s, mov_imm(1, 3));                              // 3
        isa::append_insn(s, bin(isa::VmOp::Sbb, 0, 1, ir::Size::S32));   // 4
        isa::append_insn(s, getflags(2));                                // 5
        isa::append_insn(s, halt());                                     // 6
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 1u);
        EXPECT_EQ(ctx.regs[2] & isa::kFlagCF, 0u);
    }
    // sbb + CF_in=0 下溢：3 - 5 = 0xFFFFFFFE（CF=1 SF=1）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(3, 0));                              // 0  CF=0
        isa::append_insn(s, setflags(3));                                // 1
        isa::append_insn(s, mov_imm(0, 3));                              // 2
        isa::append_insn(s, mov_imm(1, 5));                              // 3
        isa::append_insn(s, bin(isa::VmOp::Sbb, 0, 1, ir::Size::S32));   // 4
        isa::append_insn(s, getflags(2));                                // 5
        isa::append_insn(s, halt());                                     // 6
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0xFFFFFFFEu);
        EXPECT_EQ(ctx.regs[2] & isa::kFlagsMask & ~(isa::kFlagZF | isa::kFlagOF),
                  isa::kFlagCF | isa::kFlagSF);
    }
    // sbb S8 别名合并：0x33_05 - 0x33_03 - 1(CF) = 0x33_01（槽 8..31 保 0x33）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(3, 2));                              // 0  CF=1
        isa::append_insn(s, setflags(3));                                // 1
        isa::append_insn(s, mov_imm(0, 0x3305));                         // 2
        isa::append_insn(s, mov_imm(1, 0x3303));                         // 3
        isa::append_insn(s, bin(isa::VmOp::Sbb, 0, 1, ir::Size::S8));    // 4
        isa::append_insn(s, halt());                                     // 5
        const auto ctx = run_stream(entry, s, nullptr);
        EXPECT_EQ(ctx.regs[0], 0x3301ull);
    }
}

// ---------------------------------------------------------------------------
// (14) X3b 批次一：Imul/Mul（乘法边界 + 双结果槽协议）
// ---------------------------------------------------------------------------
TEST(X86Battery, ImulMulEdges) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();
    const u8 rax_slot = isa::vm_reg_of(ir::Reg::Rax);  // 0
    const u8 rdx_slot = isa::vm_reg_of(ir::Reg::Rdx);  // 2

    // imul 2-op 有符号：(-3) * 7 = -21（CF=OF=0，低半=高半）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, static_cast<u32>(-3)));               // 0
        isa::append_insn(s, mov_imm(1, 7));                                  // 1
        isa::append_insn(s, bin(isa::VmOp::Imul, 0, 1, ir::Size::S32));      // 2
        isa::append_insn(s, getflags(2));                                    // 3
        isa::append_insn(s, halt());                                         // 4
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0xFFFFFFEBu);
        EXPECT_EQ(ctx.regs[2] & (isa::kFlagCF | isa::kFlagOF), 0u);
    }
    // imul 溢出边界：0x10000 * 0x10000 = 2^32 → 槽值 0，高半 ≠ 低半 → CF=OF=1。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0x10000u));                           // 0
        isa::append_insn(s, mov_imm(1, 0x10000u));                           // 1
        isa::append_insn(s, bin(isa::VmOp::Imul, 0, 1, ir::Size::S32));      // 2
        isa::append_insn(s, getflags(2));                                    // 3
        isa::append_insn(s, halt());                                         // 4
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0u);
        EXPECT_EQ(ctx.regs[2] & (isa::kFlagCF | isa::kFlagOF),
                  isa::kFlagCF | isa::kFlagOF);
    }
    // mul 0xFFFFFFFF * 2 = EDX:EAX = 1:0xFFFFFFFE → Rax/Rdx 双槽 + CF=OF=1。
    //（flags 读回落 slot 5 —— Rdx 槽 = 2，getflags(2) 会覆写双槽断言面。）
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(rax_slot, 0xFFFFFFFFu));                 // 0  被乘数
        isa::append_insn(s, mov_imm(1, 2));                                  // 1  乘数
        isa::append_insn(s, bin(isa::VmOp::Mul, rdx_slot, 1, ir::Size::S32));  // 2
        isa::append_insn(s, getflags(5));                                    // 3
        isa::append_insn(s, halt());                                         // 4
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, rax_slot, 0xFFFFFFFEu);
        expect_slot32(ctx, rdx_slot, 1u);
        EXPECT_EQ(ctx.regs[5] & (isa::kFlagCF | isa::kFlagOF),
                  isa::kFlagCF | isa::kFlagOF);
    }
    // mul 0x80000000 * 2 = EDX:EAX = 1:0（无符号溢出边界）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(rax_slot, 0x80000000u));                 // 0
        isa::append_insn(s, mov_imm(1, 2));                                  // 1
        isa::append_insn(s, bin(isa::VmOp::Mul, rdx_slot, 1, ir::Size::S32));  // 2
        isa::append_insn(s, halt());                                         // 3
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, rax_slot, 0u);
        expect_slot32(ctx, rdx_slot, 1u);
    }
    // mul 无溢出：7 * 6 = 42（Rdx=0，CF=OF=0）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(rax_slot, 7));                           // 0
        isa::append_insn(s, mov_imm(1, 6));                                  // 1
        isa::append_insn(s, bin(isa::VmOp::Mul, rdx_slot, 1, ir::Size::S32));  // 2
        isa::append_insn(s, getflags(5));                                    // 3
        isa::append_insn(s, halt());                                         // 4
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, rax_slot, 42u);
        expect_slot32(ctx, rdx_slot, 0u);
        EXPECT_EQ(ctx.regs[5] & (isa::kFlagCF | isa::kFlagOF), 0u);
    }
}

// ---------------------------------------------------------------------------
// (15) X3b 批次一：Cdq（eax → edx 符号扩展，双槽协议）
// ---------------------------------------------------------------------------
TEST(X86Battery, CdqSignExt) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();
    const u8 rax_slot = isa::vm_reg_of(ir::Reg::Rax);  // 0
    const u8 rdx_slot = isa::vm_reg_of(ir::Reg::Rdx);  // 2
    auto cdq = []() {
        return isa::make_insn(isa::VmOp::Cdq, isa::OpKind::None, 0, isa::OpKind::None, 0, 0,
                              isa::size_field(ir::Size::S32));
    };

    // eax = 0x80000000（INT_MIN）→ edx = 0xFFFFFFFF。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(rax_slot, 0x80000000u));                 // 0
        isa::append_insn(s, cdq());                                          // 1
        isa::append_insn(s, halt());                                         // 2
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, rdx_slot, 0xFFFFFFFFu);
        expect_slot32(ctx, rax_slot, 0x80000000u);   // cdq 不改 eax
    }
    // eax = 0x7FFFFFFF → edx = 0。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(rax_slot, 0x7FFFFFFFu));                 // 0
        isa::append_insn(s, cdq());                                          // 1
        isa::append_insn(s, halt());                                         // 2
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, rdx_slot, 0u);
    }
}

// ---------------------------------------------------------------------------
// (15b) X7 批二：Div/Idiv（32 位真 handler，build_div_idiv 镜像 —— 453 b59b
// 残面收口）。商/余双槽协议（Rax/Rdx 槽）+ #DE 直通面（除零不在电池内
// 执行 —— 真 #DE 会杀进程，行为面由样本负例/native 对齐口径披露）。
// flags 按 Intel undefined（SDM：DIV/IDIV 后 flags 无定义）—— 不做断言，
// 与 x64 build_div_idiv 的 setcc5 捕真值口径一致（不预期具体值）。
// ---------------------------------------------------------------------------
TEST(X86Battery, DivIdivQuotRem) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();
    const u8 rax_slot = isa::vm_reg_of(ir::Reg::Rax);  // 0
    const u8 rdx_slot = isa::vm_reg_of(ir::Reg::Rdx);  // 2
    auto cdq = []() {
        return isa::make_insn(isa::VmOp::Cdq, isa::OpKind::None, 0, isa::OpKind::None, 0, 0,
                              isa::size_field(ir::Size::S32));
    };

    // div 100 / 7 → 商 14 余 2。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(rax_slot, 100));                            // 0
        isa::append_insn(s, mov_imm(1, 7));                                     // 1
        isa::append_insn(s, bin(isa::VmOp::Div, rdx_slot, 1, ir::Size::S32));   // 2
        isa::append_insn(s, halt());                                            // 3
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, rax_slot, 14u);
        expect_slot32(ctx, rdx_slot, 2u);
    }
    // div 0xFFFFFFFF / 0x10 → 商 0x0FFFFFFF 余 0xF（无符号满值边界）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(rax_slot, 0xFFFFFFFFu));                    // 0
        isa::append_insn(s, mov_imm(1, 0x10u));                                 // 1
        isa::append_insn(s, bin(isa::VmOp::Div, rdx_slot, 1, ir::Size::S32));   // 2
        isa::append_insn(s, halt());                                            // 3
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, rax_slot, 0x0FFFFFFFu);
        expect_slot32(ctx, rdx_slot, 0xFu);
    }
    // idiv -100 / 7（cdq 前置：edx = sext(eax) = 0xFFFFFFFF）→ 商 -14 余 -2。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(rax_slot, static_cast<u32>(-100)));         // 0
        isa::append_insn(s, cdq());                                             // 1
        isa::append_insn(s, mov_imm(1, 7));                                     // 2
        isa::append_insn(s, bin(isa::VmOp::Idiv, rdx_slot, 1, ir::Size::S32));  // 3
        isa::append_insn(s, halt());                                            // 4
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, rax_slot, static_cast<u32>(-14));
        expect_slot32(ctx, rdx_slot, static_cast<u32>(-2));
    }
    // idiv 100 / -7（cdq: edx=0，正被除数）→ 商 -14 余 2（C 语义截断向零）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(rax_slot, 100));                            // 0
        isa::append_insn(s, cdq());                                             // 1
        isa::append_insn(s, mov_imm(1, static_cast<u32>(-7)));                  // 2
        isa::append_insn(s, bin(isa::VmOp::Idiv, rdx_slot, 1, ir::Size::S32));  // 3
        isa::append_insn(s, halt());                                            // 4
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, rax_slot, static_cast<u32>(-14));
        expect_slot32(ctx, rdx_slot, 2u);
    }
    // div by 1 → 商 = 被除数 余 0（identity 边界）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(rax_slot, 0xDEADBEEFu));                    // 0
        isa::append_insn(s, mov_imm(1, 1));                                     // 1
        isa::append_insn(s, bin(isa::VmOp::Div, rdx_slot, 1, ir::Size::S32));   // 2
        isa::append_insn(s, halt());                                            // 3
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, rax_slot, 0xDEADBEEFu);
        expect_slot32(ctx, rdx_slot, 0u);
    }
    // 被除数槽不受除数槽选取影响：div 后 Rax/Rdx 之外的槽原样（ts ∉ {eax,
    // edx} 静态保证的旁证 —— 除数临时不复用 dividend 物理位）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(rax_slot, 1000));                           // 0
        isa::append_insn(s, mov_imm(3, 0xABCDu));                               // 1  观察槽
        isa::append_insn(s, mov_imm(1, 10));                                    // 2
        isa::append_insn(s, bin(isa::VmOp::Div, rdx_slot, 1, ir::Size::S32));   // 3
        isa::append_insn(s, halt());                                            // 4
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, rax_slot, 100u);
        expect_slot32(ctx, rdx_slot, 0u);
        expect_slot32(ctx, 3, 0xABCDu);
    }
}

// ---------------------------------------------------------------------------
// (16) X3b 批次二：Shl/Shr/Sar（imm 形 + 32 位模式计数掩码 0x1F 实测钉）
// ---------------------------------------------------------------------------
TEST(X86Battery, ShiftImmMask) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();

    // shl S32：1 << 4 = 16（CF=0，PF: 0x10 = 1 个 1 → 奇 → PF=0）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 1));                              // 0
        isa::append_insn(s, bin_imm(isa::VmOp::Shl, 0, 4, ir::Size::S32));  // 1
        isa::append_insn(s, getflags(5));                                // 2
        isa::append_insn(s, halt());                                     // 3
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 16u);
        EXPECT_EQ(ctx.regs[5] & isa::kFlagsMask, 0u);
    }
    // **掩码实测钉（0x1F）**：count=0x20（32）→ 计数 0 → 值与 flags 均不变。
    // 若沿用 x64 S32 档的 0x3F 掩码，计数 32 会漏进 native（内部再掩 0，值
    // 恰好不变）但 flags 被宿主 and 污染 —— 双断言钉死区分。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0xABCD1234u));                    // 0
        isa::append_insn(s, mov_imm(3, 0x15));                           // 1  flags 已知值
        isa::append_insn(s, isa::make_insn(isa::VmOp::SetFlags, isa::OpKind::Reg, 3,
                                           isa::OpKind::None, 0, 0,
                                           isa::size_field(ir::Size::S32)));  // 2
        isa::append_insn(s, bin_imm(isa::VmOp::Shl, 0, 0x20, ir::Size::S32));  // 3
        isa::append_insn(s, getflags(5));                                // 4
        isa::append_insn(s, halt());                                     // 5
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0xABCD1234u);
        EXPECT_EQ(ctx.regs[5] & isa::kFlagsMask, 0x15u);
    }
    // count=0x21（33）→ 33 & 0x1F = 1 → 1 << 1 = 2。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 1));                              // 0
        isa::append_insn(s, bin_imm(isa::VmOp::Shl, 0, 0x21, ir::Size::S32));  // 1
        isa::append_insn(s, halt());                                     // 2
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 2u);
    }
    // shr S32：0xC0000000 >> 31 = 1，CF=原 bit30=1（右移 CF = 最后移出的低位，
    // 首版把 MSB 误当 CF 源 —— 期望算错非 VM 错，#33 同案）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0xC0000000u));                    // 0
        isa::append_insn(s, bin_imm(isa::VmOp::Shr, 0, 31, ir::Size::S32));  // 1
        isa::append_insn(s, getflags(5));                                // 2
        isa::append_insn(s, halt());                                     // 3
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 1u);
        EXPECT_EQ(ctx.regs[5] & isa::kFlagCF, isa::kFlagCF);
    }
    // sar S32：0xC0000000 算术右移 31 → 0xFFFFFFFF（符号填充），CF=bit30=1。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0xC0000000u));                    // 0
        isa::append_insn(s, bin_imm(isa::VmOp::Sar, 0, 31, ir::Size::S32));  // 1
        isa::append_insn(s, getflags(5));                                // 2
        isa::append_insn(s, halt());                                     // 3
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0xFFFFFFFFu);
        EXPECT_EQ(ctx.regs[5] & isa::kFlagCF, isa::kFlagCF);
    }
    // count=0 → 整条 no-op（flags 不变 —— SDM: count 0 不更新 flags）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0x1234u));                        // 0
        isa::append_insn(s, mov_imm(3, 0x15));                           // 1
        isa::append_insn(s, isa::make_insn(isa::VmOp::SetFlags, isa::OpKind::Reg, 3,
                                           isa::OpKind::None, 0, 0,
                                           isa::size_field(ir::Size::S32)));  // 2
        isa::append_insn(s, bin_imm(isa::VmOp::Shl, 0, 0, ir::Size::S32));  // 3
        isa::append_insn(s, getflags(5));                                // 4
        isa::append_insn(s, halt());                                     // 5
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0x1234u);
        EXPECT_EQ(ctx.regs[5] & isa::kFlagsMask, 0x15u);
    }
    // S8 宽度：0x11 << 4 = 0x10（低 8 位内移位，alias 合并保高位）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0xABCD1211ull));                  // 0
        isa::append_insn(s, bin_imm(isa::VmOp::Shl, 0, 4, ir::Size::S8));  // 1
        isa::append_insn(s, halt());                                     // 2
        const auto ctx = run_stream(entry, s, nullptr);
        EXPECT_EQ(ctx.regs[0], 0xABCD'1210ull);
    }
    // S8 计数掩码钉：count=0x21 → &0x1F = 1（8 位档同为 5 位掩码）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0x51));                           // 0
        isa::append_insn(s, bin_imm(isa::VmOp::Shl, 0, 0x21, ir::Size::S8));  // 1
        isa::append_insn(s, halt());                                     // 2
        const auto ctx = run_stream(entry, s, nullptr);
        EXPECT_EQ(ctx.regs[0], 0xA2ull);
    }
}

// ---------------------------------------------------------------------------
// (17) X3b 批次二：cl 变体（ShlCl/ShrCl/SarCl —— 计数源自 RCX 槽低 8 位）
// ---------------------------------------------------------------------------
TEST(X86Battery, ShiftClReg) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();
    const u8 rcx_slot = isa::vm_reg_of(ir::Reg::Rcx);

    // shlcl：RCX 槽 = 0x104 → 计数取低 8 位 = 4 → 3 << 4 = 48。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 3));                                  // 0
        isa::append_insn(s, mov_imm(rcx_slot, 0x104));                       // 1
        isa::append_insn(s, isa::make_insn(isa::VmOp::ShlCl, isa::OpKind::Reg, 0,
                                           isa::OpKind::Reg, rcx_slot, 0,
                                           isa::size_field(ir::Size::S32)));  // 2
        isa::append_insn(s, halt());                                         // 3
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 48u);
    }
    // shrcl + sarcl：0x80000000 逻辑/算术右移 4。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0x80000000u));                        // 0
        isa::append_insn(s, mov_imm(rcx_slot, 4));                           // 1
        isa::append_insn(s, isa::make_insn(isa::VmOp::SarCl, isa::OpKind::Reg, 0,
                                           isa::OpKind::Reg, rcx_slot, 0,
                                           isa::size_field(ir::Size::S32)));  // 2
        isa::append_insn(s, halt());                                         // 3
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0xF8000000ull);
    }
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0x80000000u));                        // 0
        isa::append_insn(s, mov_imm(rcx_slot, 4));                           // 1
        isa::append_insn(s, isa::make_insn(isa::VmOp::ShrCl, isa::OpKind::Reg, 0,
                                           isa::OpKind::Reg, rcx_slot, 0,
                                           isa::size_field(ir::Size::S32)));  // 2
        isa::append_insn(s, halt());                                         // 3
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0x08000000ull);
    }
}

// ---------------------------------------------------------------------------
// (18) X3b 批次二：Rol/Ror(+cl)（partial 装配 —— ZF/SF/PF 保留 + CF/OF 装配）
// ---------------------------------------------------------------------------
TEST(X86Battery, RolRorFlags) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();
    const u8 rcx_slot = isa::vm_reg_of(ir::Reg::Rcx);

    // rol S32 count=1：0x80000001 → 0x00000003，CF=旧 MSB=1，
    // OF = MSB(res) xor CF = 0 xor 1 = 1。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0x80000001u));                    // 0
        isa::append_insn(s, bin_imm(isa::VmOp::Rol, 0, 1, ir::Size::S32));  // 1
        isa::append_insn(s, getflags(5));                                // 2
        isa::append_insn(s, halt());                                     // 3
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 3u);
        EXPECT_EQ(ctx.regs[5] & isa::kFlagsMask,
                  isa::kFlagCF | isa::kFlagOF);
    }
    // **partial 保留钉（MIT-433 p432 案 32 位平移）**：cmp 1,2 → flags =
    // CF|SF|PF（0xFFFFFFFF：SF=1、CF=1 借位、PF=1 低字节 0xFF 偶、ZF=0），
    // 随后 rol 只写 CF/OF —— ZF/SF/PF 必须**原样保留**（旧值 0b11010 →
    // 新值 = 0b11000 | CF<<1 | OF<<2）。rol 1 on 0x80000001 → CF=1, OF=1
    // → 期望 0b11110 = 30。若走全量装配（x64 修前缺陷形态），zero5 等价
    // 的宿主污染会把 ZF 覆写成 1。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 1));                              // 0
        isa::append_insn(s, mov_imm(1, 2));                              // 1
        isa::append_insn(s, bin(isa::VmOp::Cmp, 0, 1, ir::Size::S32));   // 2  flags=0b11010
        isa::append_insn(s, mov_imm(0, 0x80000001u));                    // 3
        isa::append_insn(s, bin_imm(isa::VmOp::Rol, 0, 1, ir::Size::S32));  // 4
        isa::append_insn(s, getflags(5));                                // 5
        isa::append_insn(s, halt());                                     // 6
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 3u);
        EXPECT_EQ(ctx.regs[5] & isa::kFlagsMask, 30u);
    }
    // ror S32 count=1：0x80000001 → 0xC0000000，CF=移出 LSB=1。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0x80000001u));                    // 0
        isa::append_insn(s, bin_imm(isa::VmOp::Ror, 0, 1, ir::Size::S32));  // 1
        isa::append_insn(s, getflags(5));                                // 2
        isa::append_insn(s, halt());                                     // 3
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0xC0000000ull);
        EXPECT_EQ(ctx.regs[5] & isa::kFlagCF, isa::kFlagCF);
    }
    // rol S8 循环宽度：0x81 rol 4 → 0x18（8 位内闭环）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0xABCD1281ull));                  // 0
        isa::append_insn(s, bin_imm(isa::VmOp::Rol, 0, 4, ir::Size::S8));  // 1
        isa::append_insn(s, halt());                                     // 2
        const auto ctx = run_stream(entry, s, nullptr);
        EXPECT_EQ(ctx.regs[0], 0xABCD'1218ull);
    }
    // rolcl：计数来自 RCX 槽（0x104 → 低 8 位 = 4）；0x10000001 rol 4 →
    // 0x00000018，CF = 最后移出位（SDM: 循环 N 位后 CF = 最后一次 wrap 位）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0x10000001u));                    // 0
        isa::append_insn(s, mov_imm(rcx_slot, 0x104));                   // 1
        isa::append_insn(s, isa::make_insn(isa::VmOp::RolCl, isa::OpKind::Reg, 0,
                                           isa::OpKind::Reg, rcx_slot, 0,
                                           isa::size_field(ir::Size::S32)));  // 2
        isa::append_insn(s, getflags(5));                                // 3
        isa::append_insn(s, halt());                                     // 4
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0x11u);
    }
    // rorcl + partial 保留（cl 形态同面钉）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 1));                              // 0
        isa::append_insn(s, mov_imm(1, 2));                              // 1
        isa::append_insn(s, bin(isa::VmOp::Cmp, 0, 1, ir::Size::S32));   // 2  flags=0b11010
        isa::append_insn(s, mov_imm(0, 0x80000001u));                    // 3
        isa::append_insn(s, mov_imm(rcx_slot, 1));                       // 4
        isa::append_insn(s, isa::make_insn(isa::VmOp::RorCl, isa::OpKind::Reg, 0,
                                           isa::OpKind::Reg, rcx_slot, 0,
                                           isa::size_field(ir::Size::S32)));  // 5
        isa::append_insn(s, getflags(5));                                // 6
        isa::append_insn(s, halt());                                     // 7
        const auto ctx = run_stream(entry, s, nullptr);
        // ror 1: 0x80000001 → 0xC0000000，CF=旧 LSB=1，OF 未定义（count=1 实
        // 值可断但保守不断言）→ flags = 0b11000 | CF = 0b11010 = 26。
        EXPECT_EQ(ctx.regs[5] & (isa::kFlagZF | isa::kFlagSF | isa::kFlagPF),
                  isa::kFlagSF | isa::kFlagPF);
        EXPECT_EQ(ctx.regs[5] & isa::kFlagCF, isa::kFlagCF);
    }
}

// ---------------------------------------------------------------------------
// (19) X3b 批次三：Movzx/Movsx (+Mem)（aux[0] 源宽位，S8/S16 → S32 扩展）
// ---------------------------------------------------------------------------
TEST(X86Battery, ExtendOps) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();

    auto extend = [](isa::VmOp op, u8 dst, u8 src, u32 src_size) {
        return isa::make_insn(op, isa::OpKind::Reg, dst, isa::OpKind::Reg, src, src_size,
                              isa::size_field(ir::Size::S32));
    };

    // movzx aux=0（byte 源）：0xABCD0080 低字节 0x80 → 0x00000080。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(1, 0xABCD0080u));                    // 0
        isa::append_insn(s, extend(isa::VmOp::Movzx, 0, 1, 0));          // 1
        isa::append_insn(s, halt());                                     // 2
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0x80u);
    }
    // movzx aux=1（word 源）：0xABCD1234 低字 0x1234 → 0x00001234。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(1, 0xABCD1234u));                    // 0
        isa::append_insn(s, extend(isa::VmOp::Movzx, 0, 1, 1));          // 1
        isa::append_insn(s, halt());                                     // 2
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0x1234u);
    }
    // movsx aux=0：0x80 → 0xFFFFFF80（符号扩展落满槽 dword）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(1, 0x80u));                          // 0
        isa::append_insn(s, extend(isa::VmOp::Movsx, 0, 1, 0));          // 1
        isa::append_insn(s, halt());                                     // 2
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0xFFFFFF80u);
    }
    // movsx aux=1：0x8234 → 0xFFFF8234。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(1, 0x8234u));                        // 0
        isa::append_insn(s, extend(isa::VmOp::Movsx, 0, 1, 1));          // 1
        isa::append_insn(s, halt());                                     // 2
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0xFFFF8234u);
    }
    // Mem 形：movzxmem/movsxmem —— reg_b = 地址槽（绝对 VA），内存 byte/word 读。
    {
        alignas(4) std::array<u8, 0x40> scratch{};
        scratch.fill(0);
        scratch[0] = 0x34; scratch[1] = 0x82;   // word @0 = 0x8234（小端）
        const u32 data_addr = static_cast<u32>(reinterpret_cast<uintptr_t>(scratch.data()));
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(1, data_addr));                          // 0
        isa::append_insn(s, extend(isa::VmOp::MovzxMem, 0, 1, 0));           // 1  byte @0
        isa::append_insn(s, extend(isa::VmOp::MovsxMem, 2, 1, 1));           // 2  word @0
        isa::append_insn(s, halt());                                         // 3
        const auto ctx = run_stream(entry, s, scratch.data());
        expect_slot32(ctx, 0, 0x34u);
        expect_slot32(ctx, 2, 0xFFFF8234u);
    }
}

// ---------------------------------------------------------------------------
// (20) X3b 批次三：Bswap/Xchg（S32 真面 + S8/S16 防御 no-op 钉）
// ---------------------------------------------------------------------------
TEST(X86Battery, BswapXchg) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();

    // bswap S32：0x12345678 → 0x78563412。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0x12345678u));                        // 0
        isa::append_insn(s, bin(isa::VmOp::Bswap, 0, 0, ir::Size::S32));     // 1
        isa::append_insn(s, halt());                                         // 2
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0x78563412u);
    }
    // bswap S8 防御 no-op：值不变（bswap 无 8 位形式，SDM）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0x12345678u));                        // 0
        isa::append_insn(s, bin(isa::VmOp::Bswap, 0, 0, ir::Size::S8));      // 1
        isa::append_insn(s, halt());                                         // 2
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0x12345678u);
    }
    // xchg S32：双槽互换。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0xAAAABBBBu));                        // 0
        isa::append_insn(s, mov_imm(1, 0xCCCCDDDDu));                        // 1
        isa::append_insn(s, bin(isa::VmOp::Xchg, 0, 1, ir::Size::S32));      // 2
        isa::append_insn(s, halt());                                         // 3
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0xCCCCDDDDu);
        expect_slot32(ctx, 1, 0xAAAABBBBu);
    }
    // xchg S16 防御 no-op（lifter REG-REG 强制 S32，防御面钉语义）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0xAAAABBBBu));                        // 0
        isa::append_insn(s, mov_imm(1, 0xCCCCDDDDu));                        // 1
        isa::append_insn(s, bin(isa::VmOp::Xchg, 0, 1, ir::Size::S16));      // 2
        isa::append_insn(s, halt());                                         // 3
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0xAAAABBBBu);
        expect_slot32(ctx, 1, 0xCCCCDDDDu);
    }
}

// ---------------------------------------------------------------------------
// (21) X3b 批次四：Setcc（16 条件 + reads-only flags 钉）
// ---------------------------------------------------------------------------
TEST(X86Battery, SetccCond) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();

    auto setcc = [](u8 dst, ir::Cond c) {
        return isa::make_insn(isa::VmOp::Setcc, isa::OpKind::Reg, dst,
                              isa::OpKind::None, 0, 0, static_cast<u8>(c));
    };

    // cmp 5,5（相等）→ sete=1；槽高位保留钉（预置 0xA00 → 0xA01）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 5));                              // 0
        isa::append_insn(s, mov_imm(1, 5));                              // 1
        isa::append_insn(s, bin(isa::VmOp::Cmp, 0, 1, ir::Size::S32));   // 2
        isa::append_insn(s, mov_imm(2, 0xA00));                          // 3
        isa::append_insn(s, setcc(2, ir::Cond::E));                      // 4
        isa::append_insn(s, getflags(4));                                // 5
        isa::append_insn(s, halt());                                     // 6
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 2, 0xA01u);
        EXPECT_EQ(ctx.regs[4] & isa::kFlagZF, isa::kFlagZF);
    }
    // cmp 1,2（无符号 below）→ setb=1 / setae=0 / seta=0。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 1));                              // 0
        isa::append_insn(s, mov_imm(1, 2));                              // 1
        isa::append_insn(s, bin(isa::VmOp::Cmp, 0, 1, ir::Size::S32));   // 2
        isa::append_insn(s, setcc(2, ir::Cond::B));                      // 3
        isa::append_insn(s, setcc(3, ir::Cond::Ae));                     // 4
        isa::append_insn(s, setcc(4, ir::Cond::A));                      // 5
        isa::append_insn(s, halt());                                     // 6
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 2, 1u);
        expect_slot32(ctx, 3, 0u);
        expect_slot32(ctx, 4, 0u);
    }
    // 有符号：cmp 0xFFFFFFFD(-3), 1 → setl=1 / setg=0 / sets=1。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0xFFFFFFFDu));                    // 0
        isa::append_insn(s, mov_imm(1, 1));                              // 1
        isa::append_insn(s, bin(isa::VmOp::Cmp, 0, 1, ir::Size::S32));   // 2
        isa::append_insn(s, setcc(2, ir::Cond::L));                      // 3
        isa::append_insn(s, setcc(3, ir::Cond::G));                      // 4
        isa::append_insn(s, setcc(4, ir::Cond::S));                      // 5
        isa::append_insn(s, halt());                                     // 6
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 2, 1u);
        expect_slot32(ctx, 3, 0u);
        expect_slot32(ctx, 4, 1u);
    }
    // setcc 不改 flags：cmp 后 getflags 两次夹断言（中间隔 setcc）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 1));                              // 0
        isa::append_insn(s, mov_imm(1, 2));                              // 1
        isa::append_insn(s, bin(isa::VmOp::Cmp, 0, 1, ir::Size::S32));   // 2
        isa::append_insn(s, getflags(4));                                // 3  flags ①
        isa::append_insn(s, setcc(2, ir::Cond::B));                      // 4
        isa::append_insn(s, getflags(5));                                // 5  flags ②
        isa::append_insn(s, halt());                                     // 6
        const auto ctx = run_stream(entry, s, nullptr);
        EXPECT_EQ(ctx.regs[4] & isa::kFlagsMask, ctx.regs[5] & isa::kFlagsMask);
    }
}

// ---------------------------------------------------------------------------
// (22) X3b 批次四：Cmovcc（cond ∈ aux[31..28]，取/不取两路 + flags 不变）
// ---------------------------------------------------------------------------
TEST(X86Battery, CmovccCond) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();

    auto cmovcc = [](u8 dst, u8 src, ir::Cond c) {
        return isa::make_insn(isa::VmOp::Cmovcc, isa::OpKind::Reg, dst,
                              isa::OpKind::Reg, src, static_cast<u32>(c) << 28,
                              isa::size_field(ir::Size::S32));
    };

    // 取：cmp 非等 → cmovcc(Ne) dst ← src。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 111));                            // 0
        isa::append_insn(s, mov_imm(1, 222));                            // 1
        isa::append_insn(s, mov_imm(2, 7));                              // 2
        isa::append_insn(s, bin(isa::VmOp::Cmp, 1, 2, ir::Size::S32));   // 3  非等
        isa::append_insn(s, cmovcc(0, 1, ir::Cond::Ne));                 // 4
        isa::append_insn(s, halt());                                     // 5
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 222u);
    }
    // 不取：cmp 相等 → cmovcc(Ne) dst 不变。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 111));                            // 0
        isa::append_insn(s, mov_imm(1, 222));                            // 1
        isa::append_insn(s, bin(isa::VmOp::Cmp, 1, 1, ir::Size::S32));   // 2  相等
        isa::append_insn(s, cmovcc(0, 1, ir::Cond::Ne));                 // 3
        isa::append_insn(s, halt());                                     // 4
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 111u);
    }
    // 有符号：cmp -3, 1 → cmovcc(L) 取。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 111));                            // 0
        isa::append_insn(s, mov_imm(1, 0xFFFFFFFDu));                    // 1
        isa::append_insn(s, mov_imm(2, 1));                              // 2
        isa::append_insn(s, bin(isa::VmOp::Cmp, 1, 2, ir::Size::S32));   // 3
        isa::append_insn(s, cmovcc(0, 1, ir::Cond::L));                  // 4
        isa::append_insn(s, halt());                                     // 5
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0xFFFFFFFDu);
    }
    // cmovcc 不改 flags：cmp 后 getflags 两点夹断言。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 111));                            // 0
        isa::append_insn(s, mov_imm(1, 222));                            // 1
        isa::append_insn(s, bin(isa::VmOp::Cmp, 1, 1, ir::Size::S32));   // 2
        isa::append_insn(s, getflags(4));                                // 3
        isa::append_insn(s, cmovcc(0, 1, ir::Cond::E));                  // 4（取）
        isa::append_insn(s, getflags(5));                                // 5
        isa::append_insn(s, halt());                                     // 6
        const auto ctx = run_stream(entry, s, nullptr);
        EXPECT_EQ(ctx.regs[4] & isa::kFlagsMask, ctx.regs[5] & isa::kFlagsMask);
    }
}

// ---------------------------------------------------------------------------
// (23) X3b 批次五：Popcnt/Lzcnt/Tzcnt（S32 真面 + 源保留纪律 + 0 全库边界）
// ---------------------------------------------------------------------------
TEST(X86Battery, BitCountOps) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();

    auto bitcount = [](isa::VmOp op, u8 dst, u8 src) {
        return isa::make_insn(op, isa::OpKind::Reg, dst, isa::OpKind::Reg, src, 0,
                              isa::size_field(ir::Size::S32));
    };

    // popcnt：0xF0F0F0F0 → 16（src 消耗面：dst ≠ src 时 src 不变语义钉）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(1, 0xF0F0F0F0u));                    // 0
        isa::append_insn(s, bitcount(isa::VmOp::Popcnt, 0, 1));          // 1
        isa::append_insn(s, halt());                                     // 2
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 16u);
        expect_slot32(ctx, 1, 0xF0F0F0F0u);   // dst≠src：src 槽不被触碰
    }
    // popcnt 边界：0 → 0；0xFFFFFFFF → 32。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(1, 0));                              // 0
        isa::append_insn(s, bitcount(isa::VmOp::Popcnt, 0, 1));          // 1
        isa::append_insn(s, mov_imm(1, 0xFFFFFFFFu));                    // 2
        isa::append_insn(s, bitcount(isa::VmOp::Popcnt, 2, 1));          // 3
        isa::append_insn(s, halt());                                     // 4
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 0u);
        expect_slot32(ctx, 2, 32u);
    }
    // lzcnt：0x00010000 → 15；0 → 32（BMI1 语义）；0xFFFFFFFF → 0；src 保留。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(1, 0x00010000u));                    // 0
        isa::append_insn(s, bitcount(isa::VmOp::Lzcount, 0, 1));         // 1
        isa::append_insn(s, mov_imm(3, 0));                              // 2
        isa::append_insn(s, bitcount(isa::VmOp::Lzcount, 2, 3));         // 3
        isa::append_insn(s, mov_imm(1, 0xFFFFFFFFu));                    // 4
        isa::append_insn(s, bitcount(isa::VmOp::Lzcount, 2, 1));         // 5
        isa::append_insn(s, halt());                                     // 6
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 15u);
        expect_slot32(ctx, 2, 0u);
        expect_slot32(ctx, 1, 0xFFFFFFFFu);   // 源保留（pitfall #37 钉）
    }
    // tzcnt：0x00010000 → 16；0 → 32（BMI1 语义）；0xFFFFFFF0 → 4；src 保留。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(1, 0x00010000u));                    // 0
        isa::append_insn(s, bitcount(isa::VmOp::Tzcount, 0, 1));         // 1
        isa::append_insn(s, mov_imm(3, 0));                              // 2
        isa::append_insn(s, bitcount(isa::VmOp::Tzcount, 2, 3));         // 3
        isa::append_insn(s, mov_imm(1, 0xFFFFFFF0u));                    // 4
        isa::append_insn(s, bitcount(isa::VmOp::Tzcount, 4, 1));         // 5
        isa::append_insn(s, halt());                                     // 6
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 0, 16u);
        expect_slot32(ctx, 2, 32u);
        expect_slot32(ctx, 4, 4u);
        expect_slot32(ctx, 1, 0xFFFFFFF0u);   // 源保留
    }
}

// ---------------------------------------------------------------------------
// (24) X3b 批次五：Cmpxchg（隐式 Rax 累加器，等/不等两路 + S8 形）
// ---------------------------------------------------------------------------
TEST(X86Battery, CmpxchgAcc) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();
    const u8 rax_slot = isa::vm_reg_of(ir::Reg::Rax);

    // 等路：acc == dst → ZF=1、dst ← src、acc 不变。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(rax_slot, 0x1234u));                 // 0  acc
        isa::append_insn(s, mov_imm(1, 0x1234u));                        // 1  dst
        isa::append_insn(s, mov_imm(2, 0x5678u));                        // 2  src
        isa::append_insn(s, bin(isa::VmOp::Cmpxchg, 1, 2, ir::Size::S32));  // 3
        isa::append_insn(s, getflags(4));                                // 4
        isa::append_insn(s, halt());                                     // 5
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 1, 0x5678u);       // dst = src
        expect_slot32(ctx, rax_slot, 0x1234u);   // acc 原样
        EXPECT_EQ(ctx.regs[4] & isa::kFlagZF, isa::kFlagZF);
    }
    // 不等路：acc ≠ dst → ZF=0、acc ← 旧 dst、dst 不变。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(rax_slot, 5));                       // 0  acc
        isa::append_insn(s, mov_imm(1, 7));                              // 1  dst
        isa::append_insn(s, mov_imm(2, 9));                              // 2  src
        isa::append_insn(s, bin(isa::VmOp::Cmpxchg, 1, 2, ir::Size::S32));  // 3
        isa::append_insn(s, getflags(4));                                // 4
        isa::append_insn(s, halt());                                     // 5
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 1, 7u);            // dst 不变
        expect_slot32(ctx, rax_slot, 7u);     // acc = 旧 dst
        EXPECT_EQ(ctx.regs[4] & isa::kFlagZF, 0u);
    }
    // S8 形：acc 低字节 == dst 低字节 → ZF=1、dst 低字节 ← src 低字节（保高位）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(rax_slot, 0xAB00'33ull));            // 0  acc（低字节 0x33）
        isa::append_insn(s, mov_imm(1, 0xCD00'33ull));                   // 1  dst（低字节相等）
        isa::append_insn(s, mov_imm(2, 0x11'44ull));                     // 2  src
        isa::append_insn(s, bin(isa::VmOp::Cmpxchg, 1, 2, ir::Size::S8));   // 3
        isa::append_insn(s, halt());                                     // 4
        const auto ctx = run_stream(entry, s, nullptr);
        expect_slot32(ctx, 1, 0xCD0044ull);   // dst 低字节 = 0x44，高位保留
        expect_slot32(ctx, rax_slot, 0xAB0033ull);   // acc 原样
    }
}

// ---------------------------------------------------------------------------
// (25) X3b 批次五：Xadd/Bts/Btr/Btc（lock 原子族真内存 + CF 面）
// ---------------------------------------------------------------------------
TEST(X86Battery, XaddBitOps) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    alignas(4) std::array<u8, 0x40> scratch{};
    scratch.fill(0);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();
    const u32 data_addr = static_cast<u32>(reinterpret_cast<uintptr_t>(scratch.data()));

    auto xadd = [](u8 addr, u8 src, ir::Size s) {
        return isa::make_insn(isa::VmOp::Xadd, isa::OpKind::Reg, addr,
                              isa::OpKind::Reg, src, 0, isa::size_field(s));
    };
    auto bitop_imm = [](isa::VmOp op, u8 addr, u32 bit) {
        return isa::make_insn(op, isa::OpKind::Reg, addr, isa::OpKind::Imm, 0, bit,
                              isa::size_field(ir::Size::S32));
    };
    auto bitop_reg = [](isa::VmOp op, u8 addr, u8 bit_slot) {
        return isa::make_insn(op, isa::OpKind::Reg, addr, isa::OpKind::Reg, bit_slot, 0,
                              isa::size_field(ir::Size::S32));
    };

    // xadd S32：[addr]=10、src=5 → [addr]=15、src=10（旧值）；flags=add。
    {
        scratch[0] = 10; scratch[1] = 0; scratch[2] = 0; scratch[3] = 0;
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(1, data_addr));                      // 0  地址槽
        isa::append_insn(s, mov_imm(2, 5));                              // 1  src
        isa::append_insn(s, xadd(1, 2, ir::Size::S32));                  // 2
        isa::append_insn(s, getflags(3));                                // 3
        isa::append_insn(s, halt());                                     // 4
        const auto ctx = run_stream(entry, s, scratch.data());
        expect_slot32(ctx, 1, data_addr);
        expect_slot32(ctx, 2, 10u);           // src = 旧值
        EXPECT_EQ(scratch[0], 15u);           // [addr] = 15
        EXPECT_EQ(ctx.regs[3] & isa::kFlagZF, 0u);
        EXPECT_EQ(ctx.regs[3] & isa::kFlagCF, 0u);
    }
    // xadd S8 回绕：[addr]=0xFF、src=2 → [addr]=0x01、旧 0xFF；CF=1（8 位进位）。
    {
        scratch[0] = 0xFF;
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(1, data_addr));                      // 0
        isa::append_insn(s, mov_imm(2, 2));                              // 1
        isa::append_insn(s, xadd(1, 2, ir::Size::S8));                   // 2
        isa::append_insn(s, getflags(3));                                // 3
        isa::append_insn(s, halt());                                     // 4
        const auto ctx = run_stream(entry, s, scratch.data());
        expect_slot32(ctx, 2, 0xFFu);         // 旧值
        EXPECT_EQ(scratch[0], 1u);
        EXPECT_EQ(ctx.regs[3] & isa::kFlagCF, isa::kFlagCF);
    }
    // bts imm：bit=3 on [addr]=0 → CF=0、[addr]=8；再 bts bit=3 → CF=1、值不变。
    {
        scratch[0] = 0;
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(1, data_addr));                      // 0
        isa::append_insn(s, bitop_imm(isa::VmOp::Bts, 1, 3));            // 1
        isa::append_insn(s, bitop_imm(isa::VmOp::Bts, 1, 3));            // 2（已置 → CF=1）
        isa::append_insn(s, getflags(3));                                // 3
        isa::append_insn(s, halt());                                     // 4
        const auto ctx = run_stream(entry, s, scratch.data());
        EXPECT_EQ(scratch[0], 8u);
        EXPECT_EQ(ctx.regs[3] & isa::kFlagCF, isa::kFlagCF);
    }
    // btr reg：位号来自 reg_b 槽 → 清位 + CF=1（位原为 1）。
    {
        scratch[0] = 0xFF;
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(1, data_addr));                      // 0
        isa::append_insn(s, mov_imm(2, 6));                              // 1  位号槽
        isa::append_insn(s, bitop_reg(isa::VmOp::Btr, 1, 2));            // 2
        isa::append_insn(s, getflags(3));                                // 3
        isa::append_insn(s, halt());                                     // 4
        const auto ctx = run_stream(entry, s, scratch.data());
        EXPECT_EQ(scratch[0], 0xFFu & ~0x40u);
        EXPECT_EQ(ctx.regs[3] & isa::kFlagCF, isa::kFlagCF);
    }
    // btc imm：位取反 + CF = 原位值。
    {
        scratch[0] = 0x04;   // bit2 = 1
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(1, data_addr));                      // 0
        isa::append_insn(s, bitop_imm(isa::VmOp::Btc, 1, 2));            // 1
        isa::append_insn(s, getflags(3));                                // 2
        isa::append_insn(s, halt());                                     // 3
        const auto ctx = run_stream(entry, s, scratch.data());
        EXPECT_EQ(scratch[0], 0u);            // bit2 取反 → 0
        EXPECT_EQ(ctx.regs[3] & isa::kFlagCF, isa::kFlagCF);   // 原位 = 1
    }
}

// ---------------------------------------------------------------------------
// (29b) MIT-451 (X5b) B.4：Xadd/Bts/Btr/Btc REG-dst 形真执行（b_kind=None
//       判别 — reg_a = dst VM 槽索引、reg_b = src VM 槽索引，native RMW 落
//       ctx 槽内存）。xadd = 旧值写回 src 槽 + add 全量 flags；bts 系 =
//       CF 有定义。同寄存器 xadd 形 translator 已 gate（写序冲突），电池
//       不覆盖。
// ---------------------------------------------------------------------------
TEST(X86Battery, XaddBitOpsRegDstForm) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    alignas(4) std::array<u8, 0x40> scratch{};
    scratch.fill(0);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();

    auto bitop_regdst = [](isa::VmOp op, u8 dst, u8 src, ir::Size s) {
        return isa::make_insn(op, isa::OpKind::Reg, dst, isa::OpKind::None, src, 0,
                              isa::size_field(s));
    };
    // REG-dst 形槽 = VM 寄存器槽（槽高半字恒 0 不变量下 dword 读即全值）。
    const u8 v1 = 1, v2 = 2;

    // xadd REG-REG S32：v1=10、v2=5 → v1=15、v2=10（旧值）；flags=add 语义。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(v1, 10));
        isa::append_insn(s, mov_imm(v2, 5));
        isa::append_insn(s, bitop_regdst(isa::VmOp::Xadd, v1, v2, ir::Size::S32));
        isa::append_insn(s, getflags(3));
        isa::append_insn(s, halt());
        const auto ctx = run_stream(entry, s, scratch.data());
        expect_slot32(ctx, v1, 15u);
        expect_slot32(ctx, v2, 10u);
        EXPECT_EQ(ctx.regs[3] & isa::kFlagZF, 0u);
        EXPECT_EQ(ctx.regs[3] & isa::kFlagCF, 0u);
        EXPECT_EQ(ctx.regs[v1] >> 32, 0u);    // 槽高半字恒 0
    }
    // xadd REG-REG S8：v1 低字节 0xFF、v2=2 → v1 低字节 0x01（高 7 字节保持
    // —— 字节 RMW）、v2=0xFF；CF=1（8 位进位）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(v1, 0xFF));
        isa::append_insn(s, mov_imm(v2, 2));
        isa::append_insn(s, bitop_regdst(isa::VmOp::Xadd, v1, v2, ir::Size::S8));
        isa::append_insn(s, getflags(3));
        isa::append_insn(s, halt());
        const auto ctx = run_stream(entry, s, scratch.data());
        expect_slot32(ctx, v1, 0x01u);
        expect_slot32(ctx, v2, 0xFFu);
        EXPECT_EQ(ctx.regs[3] & isa::kFlagCF, isa::kFlagCF);
    }
    // bts REG-REG：v1=0、v2=3 → v1=8、CF=0；重复 → v1 不变、CF=1。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(v1, 0));
        isa::append_insn(s, mov_imm(v2, 3));
        isa::append_insn(s, bitop_regdst(isa::VmOp::Bts, v1, v2, ir::Size::S32));
        isa::append_insn(s, getflags(3));
        isa::append_insn(s, halt());
        const auto ctx = run_stream(entry, s, scratch.data());
        expect_slot32(ctx, v1, 8u);
        EXPECT_EQ(ctx.regs[3] & isa::kFlagCF, 0u);
    }
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(v1, 8));
        isa::append_insn(s, mov_imm(v2, 3));
        isa::append_insn(s, bitop_regdst(isa::VmOp::Bts, v1, v2, ir::Size::S32));
        isa::append_insn(s, getflags(3));
        isa::append_insn(s, halt());
        const auto ctx = run_stream(entry, s, scratch.data());
        expect_slot32(ctx, v1, 8u);
        EXPECT_EQ(ctx.regs[3] & isa::kFlagCF, isa::kFlagCF);
    }
    // btr REG-REG：v1=0xFF、v2=6 → 清位、CF=1。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(v1, 0xFF));
        isa::append_insn(s, mov_imm(v2, 6));
        isa::append_insn(s, bitop_regdst(isa::VmOp::Btr, v1, v2, ir::Size::S32));
        isa::append_insn(s, getflags(3));
        isa::append_insn(s, halt());
        const auto ctx = run_stream(entry, s, scratch.data());
        expect_slot32(ctx, v1, 0xFFu & ~0x40u);
        EXPECT_EQ(ctx.regs[3] & isa::kFlagCF, isa::kFlagCF);
    }
    // btc REG-REG：v1=0x04、v2=2 → 取反、CF=1（原位）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(v1, 0x04));
        isa::append_insn(s, mov_imm(v2, 2));
        isa::append_insn(s, bitop_regdst(isa::VmOp::Btc, v1, v2, ir::Size::S32));
        isa::append_insn(s, getflags(3));
        isa::append_insn(s, halt());
        const auto ctx = run_stream(entry, s, scratch.data());
        expect_slot32(ctx, v1, 0u);
        EXPECT_EQ(ctx.regs[3] & isa::kFlagCF, isa::kFlagCF);
    }
    // 位号 >31：CPU 按宽度掩码（bts dword 位号 &31）— v1=0、v2=32+3=35 →
    // 置 bit3、CF=0。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(v1, 0));
        isa::append_insn(s, mov_imm(v2, 35));
        isa::append_insn(s, bitop_regdst(isa::VmOp::Bts, v1, v2, ir::Size::S32));
        isa::append_insn(s, getflags(3));
        isa::append_insn(s, halt());
        const auto ctx = run_stream(entry, s, scratch.data());
        expect_slot32(ctx, v1, 8u);
        EXPECT_EQ(ctx.regs[3] & isa::kFlagCF, 0u);
    }
}

// ---------------------------------------------------------------------------
// (26) X3b 批次六：Push/Pop（4B 槽裁决 —— esp 步进 4B / ctx 槽 8B，LIFO 闭环）
// ---------------------------------------------------------------------------
TEST(X86Battery, PushPopStack) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    alignas(4) std::array<u8, 0x40> scratch{};
    scratch.fill(0);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();
    const u32 stack_top = static_cast<u32>(reinterpret_cast<uintptr_t>(scratch.data())) + 0x20;
    const u8 rsp_slot = isa::vm_reg_of(ir::Reg::Rsp);

    auto run_rsp = [&](const std::vector<u8>& stream) {
        rt::VmContext ctx;
        ctx.bytecode = const_cast<u8*>(stream.data());
        ctx.pc = 0;
        ctx.scratch_mem = 0;
        ctx.regs[rsp_slot] = stack_top;   // 栈顶预置在 scratch 高位
        entry(&ctx);
        return ctx;
    };
    auto push_imm = [](u32 v) {
        return isa::make_insn(isa::VmOp::Push, isa::OpKind::Imm, 0, isa::OpKind::None, 0, v,
                              isa::size_field(ir::Size::S32));
    };

    // LIFO 闭环：push 0x11223344(imm) → push 0xAABBCCDD(reg) → pop v5 → pop v6。
    {
        std::vector<u8> s;
        isa::append_insn(s, push_imm(0x11223344u));                      // 0
        isa::append_insn(s, mov_imm(2, 0xAABBCCDDu));                    // 1
        isa::append_insn(s, isa::make_insn(isa::VmOp::Push, isa::OpKind::Reg, 2,
                                           isa::OpKind::None, 0, 0,
                                           isa::size_field(ir::Size::S32)));  // 2
        isa::append_insn(s, isa::make_insn(isa::VmOp::Pop, isa::OpKind::Reg, 5,
                                           isa::OpKind::None, 0, 0,
                                           isa::size_field(ir::Size::S32)));  // 3
        isa::append_insn(s, isa::make_insn(isa::VmOp::Pop, isa::OpKind::Reg, 6,
                                           isa::OpKind::None, 0, 0,
                                           isa::size_field(ir::Size::S32)));  // 4
        isa::append_insn(s, halt());                                     // 5
        const auto ctx = run_rsp(s);
        // LIFO：后 push 的先弹出。
        expect_slot32(ctx, 5, 0xAABBCCDDu);
        expect_slot32(ctx, 6, 0x11223344u);
        // esp 步进 4B：两次 push 两次 pop → 回到 stack_top。
        EXPECT_EQ(ctx.regs[rsp_slot], static_cast<u64>(stack_top));
        // 内存内容：[stack_top-4] = 首推 0x11223344、[stack_top-8] = 次推
        // 0xAABBCCDD（esp 先减 4 再写）。
        u32 lo, hi;
        std::memcpy(&lo, scratch.data() + 0x1C, 4);
        std::memcpy(&hi, scratch.data() + 0x18, 4);
        EXPECT_EQ(lo, 0x11223344u);
        EXPECT_EQ(hi, 0xAABBCCDDu);
    }
    // push S16 防御 no-op：esp 槽不动（translator 对 ir::Op::Push S16/S8 gate
    // —— 442 裁决面；VmOp 直发防御钉）。
    {
        scratch.fill(0);   // 前段用例已写栈内存
        std::vector<u8> s;
        isa::append_insn(s, isa::make_insn(isa::VmOp::Push, isa::OpKind::Imm, 0,
                                           isa::OpKind::None, 0, 0x42,
                                           isa::size_field(ir::Size::S16)));  // 0
        isa::append_insn(s, halt());                                     // 1
        const auto ctx = run_rsp(s);
        EXPECT_EQ(ctx.regs[rsp_slot], static_cast<u64>(stack_top));
        EXPECT_EQ(scratch[0x1C], 0u);
    }
}

// (26b) MIT-454 (X6 B.1): Push-Imm 真执行边界专测 —— push 0 / 负值 sext 形 /
//       3 连 imm push 的 esp 步进 12B + 栈内存值逐 dword 断言（X6 派单 B.1
//       "电池 Push-Imm 真执行 esp 步进+值断言" 验收锚；PushPopStack 已有
//       LIFO 闭环混推，本用例补 imm-only 面 + push 0 边界）。
// ---------------------------------------------------------------------------
TEST(X86Battery, PushImmMultiValueStack) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    alignas(4) std::array<u8, 0x40> scratch{};
    scratch.fill(0);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();
    const u32 stack_top = static_cast<u32>(reinterpret_cast<uintptr_t>(scratch.data())) + 0x20;
    const u8 rsp_slot = isa::vm_reg_of(ir::Reg::Rsp);

    rt::VmContext ctx;
    ctx.bytecode = nullptr;  // 装配于下
    std::vector<u8> s;
    auto push_imm = [&s](u32 v) {
        isa::append_insn(s, isa::make_insn(isa::VmOp::Push, isa::OpKind::Imm, 0,
                                           isa::OpKind::None, 0, v,
                                           isa::size_field(ir::Size::S32)));
    };
    push_imm(0u);            // 0  push 0（X6 新样本边界形）
    push_imm(0xDEADBEEFu);   // 1  imm32 大值
    push_imm(0xFFFFFFFBu);   // 2  6A imm8 sext -5 的 32 位存储形
    isa::append_insn(s, halt());                                             // 3

    ctx.bytecode = const_cast<u8*>(s.data());
    ctx.pc = 0;
    ctx.scratch_mem = 0;
    ctx.regs[rsp_slot] = stack_top;
    entry(&ctx);

    // esp 步进 4B×3 = 12B。
    EXPECT_EQ(ctx.regs[rsp_slot], static_cast<u64>(stack_top) - 12u);
    // 栈内存逐 dword（push 先减后写，LIFO：首推最高址、末推最低址）：
    // [top-4]=0、[top-8]=0xDEADBEEF、[top-12]=0xFFFFFFFB。
    u32 v0, v1, v2;
    std::memcpy(&v0, scratch.data() + 0x1C, 4);
    std::memcpy(&v1, scratch.data() + 0x18, 4);
    std::memcpy(&v2, scratch.data() + 0x14, 4);
    EXPECT_EQ(v0, 0u);
    EXPECT_EQ(v1, 0xDEADBEEFu);
    EXPECT_EQ(v2, 0xFFFFFFFBu);
}

// ---------------------------------------------------------------------------
// (26d) MIT-456 (push-mem): push [mem] 真执行 —— 内存源值经地址槽 + Load 值槽
//       推入 guest 栈（translator 折条 Load+Push 的语义闭环；handler 既有
//       Reg 分支零新码）。esp 步进 + 栈内存 LIFO 逐 dword 断言，镜像 26a/26b 形。
//       覆盖三面: [reg] 直接形 / [reg+disp] IAT 栈窗惯用形 / push 顺序语义
//       （地址读取发生在减 esp 之前 —— 数据预置在栈低址侧, 减序不影响读值）。
// ---------------------------------------------------------------------------
TEST(X86Battery, PushMemFromMemory) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    alignas(4) std::array<u8, 0x40> scratch{};
    scratch.fill(0);
    // 数据预置（读源）: [base+0x00]=0xAAAA1111、[base+0x04]=0xBBBB2222。
    const u32 base_addr = static_cast<u32>(reinterpret_cast<uintptr_t>(scratch.data())) + 0x00;
    const u32 val_a = 0xAAAA1111u, val_b = 0xBBBB2222u;
    std::memcpy(scratch.data() + 0x00, &val_a, 4);
    std::memcpy(scratch.data() + 0x04, &val_b, 4);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();
    const u32 stack_top = static_cast<u32>(reinterpret_cast<uintptr_t>(scratch.data())) + 0x20;
    const u8 rsp_slot = isa::vm_reg_of(ir::Reg::Rsp);

    rt::VmContext ctx;
    ctx.bytecode = nullptr;  // 装配于下
    std::vector<u8> s;
    // ⚠️ 槽位纪律: VM 槽 0..7 = 客机 GPR 槽 1:1 (ir::Reg 序, 槽 4 = RSP
    // 槽!)——数据槽只能用 2(Rdx)/5(Rsi)/6(Rdi)/8+(scratch 域), 误用槽 4
    // 会把 Load 值写进 esp 槽, 下一次 Push 即以值地址访存 (cdb 实录
    // mov [ebx],edx @ bbbb221e)。PushImmMultiValueStack 用 5/6 同纪律。
    isa::append_insn(s, mov_imm(2, base_addr));                              // 0
    isa::append_insn(s, isa::make_insn(isa::VmOp::Load, isa::OpKind::Reg, 5,
                                       isa::OpKind::Reg, 2, 0,
                                       isa::size_field(ir::Size::S32)));     // 1  v5 = [base]
    isa::append_insn(s, isa::make_insn(isa::VmOp::Push, isa::OpKind::Reg, 5,
                                       isa::OpKind::None, 0, 0,
                                       isa::size_field(ir::Size::S32)));     // 2  push [base]
    // [base+4] 形: 地址槽 +4 后再 Load（translator push [reg+disp] 展开的
    // 等价 VmOp 序: Add acc,disp → Load val,[acc] → Push val）。
    isa::append_insn(s, isa::make_insn(isa::VmOp::Add, isa::OpKind::Reg, 2,
                                       isa::OpKind::Imm, 0, 0x04,
                                       isa::size_field(ir::Size::S32)));     // 3
    isa::append_insn(s, isa::make_insn(isa::VmOp::Load, isa::OpKind::Reg, 6,
                                       isa::OpKind::Reg, 2, 0,
                                       isa::size_field(ir::Size::S32)));     // 4  v6 = [base+4]
    isa::append_insn(s, isa::make_insn(isa::VmOp::Push, isa::OpKind::Reg, 6,
                                       isa::OpKind::None, 0, 0,
                                       isa::size_field(ir::Size::S32)));     // 5  push [base+4]
    isa::append_insn(s, isa::make_insn(isa::VmOp::Pop, isa::OpKind::Reg, 7,
                                       isa::OpKind::None, 0, 0,
                                       isa::size_field(ir::Size::S32)));     // 6
    isa::append_insn(s, isa::make_insn(isa::VmOp::Pop, isa::OpKind::Reg, 8,
                                       isa::OpKind::None, 0, 0,
                                       isa::size_field(ir::Size::S32)));     // 7
    isa::append_insn(s, halt());                                             // 8

    ctx.bytecode = const_cast<u8*>(s.data());
    ctx.pc = 0;
    ctx.scratch_mem = 0;
    ctx.regs[rsp_slot] = stack_top;
    entry(&ctx);

    // LIFO: 后推的 [base+4]=0xBBBB2222 先弹出。
    expect_slot32(ctx, 7, val_b);
    expect_slot32(ctx, 8, val_a);
    // esp 步进: 两 push 两 pop → 回 stack_top。
    EXPECT_EQ(ctx.regs[rsp_slot], static_cast<u64>(stack_top));
    // 栈内存逐 dword（push 先减后写 = 首推在最高址）:
    // [top-4]=val_a（首推）、[top-8]=val_b（次推）。
    u32 m0, m1;
    std::memcpy(&m0, scratch.data() + 0x1C, 4);
    std::memcpy(&m1, scratch.data() + 0x18, 4);
    EXPECT_EQ(m0, val_a);
    EXPECT_EQ(m1, val_b);
}

// ---------------------------------------------------------------------------
// (26c) MIT-454 (X6 A=X3d) 批次二：x86 SSE 面 —— 算术/传送/位运算/mem 原语/
//       GP↔xmm 桥真执行语义（x64 SSE 电池的 32 位镜像；ctx.xmm 读回可观察
//       —— 影子纪律：仅 stdout 不构成验收）。
// ---------------------------------------------------------------------------
namespace {
isa::VmInsn sse_rr(isa::VmOp op, u8 dst, u8 src) {
    return isa::make_insn(op, isa::OpKind::Reg, dst, isa::OpKind::Reg, src, 0,
                          isa::size_field(ir::Size::S32));
}
isa::VmInsn xmm_load(u8 dst, u8 addr, u32 width) {
    return isa::make_insn(isa::VmOp::XmmLoad, isa::OpKind::Reg, dst,
                          isa::OpKind::Reg, addr, width, isa::size_field(ir::Size::S64));
}
isa::VmInsn xmm_store(u8 addr, u8 src, u32 width) {
    return isa::make_insn(isa::VmOp::XmmStore, isa::OpKind::Reg, addr,
                          isa::OpKind::Reg, src, width, isa::size_field(ir::Size::S64));
}
rt::VmContext run_stream_ctx(RwxImage::Entry entry, const std::vector<u8>& stream,
                             rt::VmContext preset) {
    preset.bytecode = const_cast<u8*>(stream.data());
    preset.pc = 0;
    preset.scratch_mem = 0;
    preset.regs[isa::vm_reg_of(ir::Reg::Rsp)] = 0;
    entry(&preset);
    return preset;
}
} // namespace

TEST(X86Battery, X86SseArithRealExec) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();

    // addss/subss/mulss 链：标量低 32 位运算、dst 高 96 位保持（SDM: 常规
    // SSE 标量运算 bits 127:32 无变化 —— dst 预读模板的语义必要性锚）。
    {
        std::vector<u8> s;
        isa::append_insn(s, sse_rr(isa::VmOp::Addss, 24, 25));   // 0
        isa::append_insn(s, sse_rr(isa::VmOp::Subss, 26, 27));   // 1
        isa::append_insn(s, sse_rr(isa::VmOp::Mulss, 28, 29));   // 2
        isa::append_insn(s, halt());                             // 3
        rt::VmContext ctx;
        ctx.xmm[0].xmm_lo = 0x3FC00000u;                          // 1.5f
        ctx.xmm[0].xmm_hi = 0xAABBCCDDEEFF0011ull;                // 高 96 哨兵
        ctx.xmm[1].xmm_lo = 0x40200000u;                          // 2.5f
        ctx.xmm[2].xmm_lo = 0x3FC00000u;                          // 1.5f
        ctx.xmm[2].xmm_hi = 0x1122334455667788ull;
        ctx.xmm[3].xmm_lo = 0x3F000000u;                          // 0.5f
        ctx.xmm[4].xmm_lo = 0x3FC00000u;                          // 1.5f
        ctx.xmm[4].xmm_hi = 0xDEADBEEFCAFEBABEull;
        ctx.xmm[5].xmm_lo = 0x40200000u;                          // 2.5f
        const auto r = run_stream_ctx(entry, s, std::move(ctx));
        EXPECT_EQ(r.xmm[0].xmm_lo, 0x40800000u);                  // 4.0f
        EXPECT_EQ(r.xmm[0].xmm_hi, 0xAABBCCDDEEFF0011ull);        // 高 96 保持
        EXPECT_EQ(r.xmm[2].xmm_lo, 0x3F800000u);                  // 1.0f
        EXPECT_EQ(r.xmm[2].xmm_hi, 0x1122334455667788ull);
        EXPECT_EQ(r.xmm[4].xmm_lo, 0x40700000u);                  // 3.75f
        EXPECT_EQ(r.xmm[4].xmm_hi, 0xDEADBEEFCAFEBABEull);
    }
    // divss 真除 + 除零 IEEE inf 语义（非 #DE —— G8 GP Div 例外不适用，
    // x64 电池先例平移）。
    {
        std::vector<u8> s;
        isa::append_insn(s, sse_rr(isa::VmOp::Divss, 24, 25));   // 0
        isa::append_insn(s, sse_rr(isa::VmOp::Divss, 26, 27));   // 1
        isa::append_insn(s, halt());                             // 2
        rt::VmContext ctx;
        ctx.xmm[0].xmm_lo = 0x3FC00000u;   // 1.5f
        ctx.xmm[1].xmm_lo = 0x40400000u;   // 3.0f → 0.5f
        ctx.xmm[2].xmm_lo = 0x3F800000u;   // 1.0f
        ctx.xmm[3].xmm_lo = 0x00000000u;   // 0.0f → +inf（IEEE）
        const auto r = run_stream_ctx(entry, s, std::move(ctx));
        EXPECT_EQ(r.xmm[0].xmm_lo, 0x3F000000u);                  // 0.5f
        EXPECT_EQ(r.xmm[2].xmm_lo, 0x7F800000u);                  // +inf
    }
    // addsd/subsd（F2 标量双精度，(op,S64) 载体族）。
    {
        std::vector<u8> s;
        isa::append_insn(s, isa::make_insn(isa::VmOp::Addsd, isa::OpKind::Reg, 24,
                                           isa::OpKind::Reg, 25, 0,
                                           isa::size_field(ir::Size::S64)));  // 0
        isa::append_insn(s, isa::make_insn(isa::VmOp::Subsd, isa::OpKind::Reg, 26,
                                           isa::OpKind::Reg, 27, 0,
                                           isa::size_field(ir::Size::S64)));  // 1
        isa::append_insn(s, halt());                                       // 2
        rt::VmContext ctx;
        ctx.xmm[0].xmm_lo = 0x3FF8000000000000ull;   // 1.5
        ctx.xmm[1].xmm_lo = 0x4004000000000000ull;   // 2.5 → 4.0
        ctx.xmm[2].xmm_lo = 0x4004000000000000ull;   // 2.5
        ctx.xmm[3].xmm_lo = 0x3FF8000000000000ull;   // 1.5 → 1.0
        const auto r = run_stream_ctx(entry, s, std::move(ctx));
        EXPECT_EQ(r.xmm[0].xmm_lo, 0x4010000000000000ull);        // 4.0
        EXPECT_EQ(r.xmm[2].xmm_lo, 0x3FF0000000000000ull);        // 1.0
    }
    // ALU mem 源折条 = GP 双槽 src（load_src_slot_into_xmm1_x86 GP 分支）：
    // XmmLoad w4 → v18 双槽 + Addss dst=24 src=18（< 24 → GP 公式）。
    {
        alignas(16) std::array<u8, 0x20> scratch{};
        const u32 f_bits = 0x3F000000u;   // 0.5f
        std::memcpy(scratch.data(), &f_bits, 4);
        const u32 addr = static_cast<u32>(reinterpret_cast<uintptr_t>(scratch.data()));
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(19, addr));                   // 0
        isa::append_insn(s, xmm_load(18, 19, 4));                 // 1 (GP 双槽落点)
        isa::append_insn(s, sse_rr(isa::VmOp::Addss, 24, 18));    // 2
        isa::append_insn(s, halt());                              // 3
        rt::VmContext ctx;
        ctx.xmm[0].xmm_lo = 0x3FC00000u;   // 1.5f + 0.5f → 2.0f
        const auto r = run_stream_ctx(entry, s, std::move(ctx));
        EXPECT_EQ(r.xmm[0].xmm_lo, 0x40000000u);                  // 2.0f
        expect_slot32(r, 19, 0u);   // 双槽高 dword = XmmLoad 清零面
    }
}

TEST(X86Battery, X86SseMovBitwiseBridgeRealExec) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    alignas(16) std::array<u8, 0x40> scratch{};
    scratch.fill(0);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();

    // movss 只改 lane0（高 96 保持）+ movaps 全量搬。
    {
        std::vector<u8> s;
        isa::append_insn(s, sse_rr(isa::VmOp::Movss, 24, 25));   // 0
        isa::append_insn(s, sse_rr(isa::VmOp::Movaps, 26, 27));  // 1
        isa::append_insn(s, halt());                             // 2
        rt::VmContext ctx;
        ctx.xmm[0].xmm_lo = 0x1122334444556677ull;
        ctx.xmm[0].xmm_hi = 0x9988776655443322ull;
        ctx.xmm[1].xmm_lo = 0x40200000u;                          // 2.5f
        ctx.xmm[3].xmm_lo = 0xAAAAAAAAAAAAAAAAull;
        ctx.xmm[3].xmm_hi = 0x5555555555555555ull;
        const auto r = run_stream_ctx(entry, s, std::move(ctx));
        EXPECT_EQ(r.xmm[0].xmm_lo, 0x1122334440200000ull);        // lane0 替换
        EXPECT_EQ(r.xmm[0].xmm_hi, 0x9988776655443322ull);        // 高保持
        EXPECT_EQ(r.xmm[2].xmm_lo, 0xAAAAAAAAAAAAAAAAull);        // movaps 全量
        EXPECT_EQ(r.xmm[2].xmm_hi, 0x5555555555555555ull);
    }
    // xorps/orps/andps/andnps 位真值（andnps = ~dst & src，SDM 0F 55）。
    {
        struct OpCase { isa::VmOp op; u8 dst, src; u8 dslot, sslot; };
        const OpCase cases[] = {
            {isa::VmOp::Xorps, 24, 25, 0, 1},
            {isa::VmOp::Andps, 26, 27, 2, 3},
            {isa::VmOp::Orps, 28, 29, 4, 5},
            {isa::VmOp::Andnps, 30, 31, 6, 7},
        };
        for (const auto& tc : cases) {
            std::vector<u8> s;
            isa::append_insn(s, sse_rr(tc.op, tc.dst, tc.src));
            isa::append_insn(s, halt());
            rt::VmContext ctx;
            ctx.xmm[tc.dslot] = {0xAAAAAAAAAAAAAAAAull, 0x5555555555555555ull};
            ctx.xmm[tc.sslot] = {0xFFFFFFFFFFFFFFFFull, 0x0000000000000000ull};
            const auto r = run_stream_ctx(entry, s, std::move(ctx));
            if (tc.op == isa::VmOp::Xorps) {
                EXPECT_EQ(r.xmm[tc.dslot].xmm_lo, 0x5555555555555555ull);
                EXPECT_EQ(r.xmm[tc.dslot].xmm_hi, 0x5555555555555555ull);
            } else if (tc.op == isa::VmOp::Andps) {
                EXPECT_EQ(r.xmm[tc.dslot].xmm_lo, 0xAAAAAAAAAAAAAAAAull);
                EXPECT_EQ(r.xmm[tc.dslot].xmm_hi, 0x0000000000000000ull);
            } else if (tc.op == isa::VmOp::Orps) {
                EXPECT_EQ(r.xmm[tc.dslot].xmm_lo, 0xFFFFFFFFFFFFFFFFull);
                EXPECT_EQ(r.xmm[tc.dslot].xmm_hi, 0x5555555555555555ull);
            } else {
                EXPECT_EQ(r.xmm[tc.dslot].xmm_lo, 0x5555555555555555ull);  // ~a & b
                EXPECT_EQ(r.xmm[tc.dslot].xmm_hi, 0x0000000000000000ull);
            }
        }
    }
    // XmmLoad/XmmStore 三宽（4/8/16）+ XmmFromGp/GpFromXmm 桥（x86 可达形
    // = w4 GP + w8 xmm-src（F3 0F 7E）；GP w8 = movq r64 REX.W 专属，32 位
    // 结构性不可达，handler 保留防御分支）。
    {
        const u32 addr = static_cast<u32>(reinterpret_cast<uintptr_t>(scratch.data()));
        // 源内存: [0..3]=0xDEADBEEF、[4..F]=0、[10..17]=1.5 f64 形
        const u32 d0 = 0xDEADBEEFu;
        std::memcpy(scratch.data(), &d0, 4);
        const u64 d10 = 0x3FF8000000000000ull;
        std::memcpy(scratch.data() + 0x10, &d10, 8);
        // (a) XmmLoad 16B
        {
            std::vector<u8> s;
            isa::append_insn(s, mov_imm(19, addr));
            isa::append_insn(s, xmm_load(24, 19, 16));
            isa::append_insn(s, halt());
            rt::VmContext ctx;
            const auto r = run_stream_ctx(entry, s, std::move(ctx));
            EXPECT_EQ(r.xmm[0].xmm_lo, 0x00000000DEADBEEFull);
            EXPECT_EQ(r.xmm[0].xmm_hi, 0ull);
        }
        // (b) XmmStore 16B
        {
            std::vector<u8> s;
            isa::append_insn(s, mov_imm(20, addr + 0x20));
            isa::append_insn(s, xmm_store(20, 24, 16));
            isa::append_insn(s, halt());
            rt::VmContext ctx;
            ctx.xmm[0].xmm_lo = 0x00000000DEADBEEFull;
            const auto r = run_stream_ctx(entry, s, std::move(ctx));
            u32 back = 0;
            std::memcpy(&back, scratch.data() + 0x20, 4);
            EXPECT_EQ(back, 0xDEADBEEFu);
            u64 back8 = 0;
            std::memcpy(&back8, scratch.data() + 0x28, 8);
            EXPECT_EQ(back8, 0u);
        }
        // (c) XmmLoad 8B/4B（w4 取 [addr] = 0xDEADBEEF 形 —— [addr+0x10] 的
        //     f64 1.5 低 dword 恒 0，钉"低宽度截取低址 dword"语义）
        {
            std::vector<u8> s;
            isa::append_insn(s, mov_imm(21, addr + 0x10));
            isa::append_insn(s, mov_imm(22, addr));
            isa::append_insn(s, xmm_load(25, 21, 8));
            isa::append_insn(s, xmm_load(26, 22, 4));
            isa::append_insn(s, halt());
            rt::VmContext ctx;
            const auto r = run_stream_ctx(entry, s, std::move(ctx));
            EXPECT_EQ(r.xmm[1].xmm_lo, 0x3FF8000000000000ull);
            EXPECT_EQ(r.xmm[1].xmm_hi, 0ull);
            EXPECT_EQ(r.xmm[2].xmm_lo, 0x00000000DEADBEEFull);
            EXPECT_EQ(r.xmm[2].xmm_hi, 0ull);
        }
        // (d) 桥 XmmFromGp w4 / GpFromXmm w4（x86 可达形）
        {
            std::vector<u8> s;
            isa::append_insn(s, mov_imm(6, 0x12345678u));
            isa::append_insn(s, isa::make_insn(isa::VmOp::XmmFromGp,
                                               isa::OpKind::Reg, 27, isa::OpKind::Reg, 6,
                                               4, isa::size_field(ir::Size::S64)));
            isa::append_insn(s, isa::make_insn(isa::VmOp::GpFromXmm,
                                               isa::OpKind::Reg, 7, isa::OpKind::Reg, 24,
                                               4, isa::size_field(ir::Size::S64)));
            isa::append_insn(s, halt());
            rt::VmContext ctx;
            ctx.xmm[0].xmm_lo = 0x00000000DEADBEEFull;   // GpFromXmm 源
            ctx.xmm[3].xmm_lo = 0xFFFFFFFFFFFFFFFFull;   // XmmFromGp dst 哨兵
            const auto r = run_stream_ctx(entry, s, std::move(ctx));
            EXPECT_EQ(r.xmm[3].xmm_lo, 0x12345678ull);
            EXPECT_EQ(r.xmm[3].xmm_hi, 0ull);
            expect_slot32(r, 7, 0xDEADBEEFu);
        }
    }
}

// X6 A 逐 op 编码双平台断言（#33 纪律：别整体信 X0 —— 26 mnemonics 逐条
// Keystone KS_MODE_32/64 双模装配同字节 + capstone CS_MODE_32/64 双解同
// mnemonic/op_str，SSE 基础编码无 REX 依赖的机器证明）。
TEST(X86Battery, DisasmX86SseEncodingDualMode) {
    const char* kMn[] = {"addss", "addps", "addpd", "subss", "subps", "subpd",
                         "mulss", "mulsd", "mulps", "mulpd", "divss", "divsd",
                         "divps", "divpd", "addsd", "subsd",
                         "movss", "movsd", "movaps", "movapd", "movups", "movupd",
                         "xorps", "orps", "andps", "andnps"};
    ks_engine* ks32 = nullptr;
    ks_engine* ks64 = nullptr;
    ASSERT_EQ(ks_open(KS_ARCH_X86, KS_MODE_32, &ks32), KS_ERR_OK);
    ASSERT_EQ(ks_open(KS_ARCH_X86, KS_MODE_64, &ks64), KS_ERR_OK);
    ks_option(ks32, KS_OPT_SYNTAX, KS_OPT_SYNTAX_INTEL);
    ks_option(ks64, KS_OPT_SYNTAX, KS_OPT_SYNTAX_INTEL);
    csh cs32 = 0, cs64 = 0;
    ASSERT_EQ(cs_open(CS_ARCH_X86, CS_MODE_32, &cs32), CS_ERR_OK);
    ASSERT_EQ(cs_open(CS_ARCH_X86, CS_MODE_64, &cs64), CS_ERR_OK);
    for (const char* mn : kMn) {
        const std::string text = std::string(mn) + " xmm0, xmm1\n";
        unsigned char* enc32 = nullptr;
        unsigned char* enc64 = nullptr;
        size_t size32 = 0, size64 = 0, count = 0;
        ASSERT_EQ(ks_asm(ks32, text.c_str(), 0x1000, &enc32, &size32, &count), 0) << mn;
        ASSERT_EQ(ks_asm(ks64, text.c_str(), 0x1000, &enc64, &size64, &count), 0) << mn;
        ASSERT_EQ(size32, size64) << mn;
        ASSERT_EQ(std::memcmp(enc32, enc64, size32), 0) << mn << " enc differs";
        // capstone 双解：同 mnemonic + 同 op_str（CS_MODE_32/64 无 REX 歧义）。
        cs_insn* insn32 = nullptr;
        cs_insn* insn64 = nullptr;
        ASSERT_EQ(cs_disasm(cs32, enc32, size32, 0x1000, 1, &insn32), size_t(1)) << mn;
        const std::string mn32 = insn32->mnemonic;
        const std::string op32 = insn32->op_str;
        ASSERT_EQ(cs_disasm(cs64, enc64, size64, 0x1000, 1, &insn64), size_t(1)) << mn;
        EXPECT_EQ(mn32, std::string(insn64->mnemonic)) << mn;
        EXPECT_EQ(op32, std::string(insn64->op_str)) << mn;
        cs_free(insn32, 1);
        cs_free(insn64, 1);
        ks_free(enc32);
        ks_free(enc64);
    }
    cs_close(&cs32);
    cs_close(&cs64);
    ks_close(ks32);
    ks_close(ks64);
}

// X6 A 五种子稳定性（442 模式）：重生成 × 5 seed，SSE 链逐 seed 真执行。
TEST(X86Battery, X86SseFiveSeed) {
    const u64 seeds[] = {1, 12345, 99999, 3735928559ull, 3405691582ull};
    for (u64 seed : seeds) {
        wvmp::Rng rng(seed);
        const auto gen = rt::generate_runtime_x86(rng);
        RwxImage rwx(gen.image.code);
        const auto entry = rwx.entry();
        std::vector<u8> s;
        isa::append_insn(s, sse_rr(isa::VmOp::Addss, 24, 25));   // 0
        isa::append_insn(s, sse_rr(isa::VmOp::Mulps, 26, 27));   // 1
        isa::append_insn(s, halt());                             // 2
        rt::VmContext ctx;
        ctx.xmm[0].xmm_lo = 0x3FC00000u;   // 1.5f
        ctx.xmm[1].xmm_lo = 0x40200000u;   // 2.5f → 4.0f
        ctx.xmm[2].xmm_lo = 0x3F800000u;   // packed lanes 0..3
        ctx.xmm[3].xmm_lo = 0x00000000u;
        const auto r = run_stream_ctx(entry, s, std::move(ctx));
        EXPECT_EQ(r.xmm[0].xmm_lo, 0x40800000u) << "seed=" << seed;
        // mulps lane0: 1.0f * 0.0f = 0.0f
        EXPECT_EQ(r.xmm[2].xmm_lo, 0u) << "seed=" << seed;
    }
}

// X6 A 批次三：ucomiss/ucomisd flags 面（SDM 真值表四象限：greater/less/
// equal/unordered — ZF/CF/OF/SF/PF = bit0..4 全量读回断言）。
TEST(X86Battery, X86SseUcomisFlagsRealExec) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();

    struct Case { float a, b; u32 want; };
    const Case cases[] = {
        {2.0f, 1.0f, 0x00u},                      // greater: 全 0
        {1.0f, 2.0f, isa::kFlagCF},               // less: CF
        {1.0f, 1.0f, isa::kFlagZF},               // equal: ZF
        {std::numeric_limits<float>::quiet_NaN(), 1.0f,
         isa::kFlagZF | isa::kFlagPF | isa::kFlagCF},  // unordered: ZF|PF|CF
    };
    for (const auto& tc : cases) {
        std::vector<u8> s;
        isa::append_insn(s, isa::make_insn(isa::VmOp::Ucomiss, isa::OpKind::Reg, 24,
                                           isa::OpKind::Reg, 25, 0,
                                           isa::size_field(ir::Size::S32)));  // 0
        isa::append_insn(s, getflags(2));                                       // 1
        isa::append_insn(s, halt());                                            // 2
        rt::VmContext ctx;
        u32 a_bits, b_bits;
        std::memcpy(&a_bits, &tc.a, 4);
        std::memcpy(&b_bits, &tc.b, 4);
        ctx.xmm[0].xmm_lo = a_bits;
        ctx.xmm[1].xmm_lo = b_bits;
        const auto r = run_stream_ctx(entry, s, std::move(ctx));
        expect_slot32(r, 2, tc.want);
    }
    // ucomisd（F2 0F 2E，(Ucomiss,S64) 载体）双精度 equal/less 两象限。
    {
        std::vector<u8> s;
        isa::append_insn(s, isa::make_insn(isa::VmOp::Ucomisd, isa::OpKind::Reg, 24,
                                           isa::OpKind::Reg, 25, 0,
                                           isa::size_field(ir::Size::S64)));  // 0
        isa::append_insn(s, getflags(2));                                     // 1
        isa::append_insn(s, halt());                                          // 2
        rt::VmContext ctx;
        ctx.xmm[0].xmm_lo = 0x4000000000000000ull;   // 2.0
        ctx.xmm[1].xmm_lo = 0x3FF8000000000000ull;   // 1.5 → greater
        const auto r = run_stream_ctx(entry, s, std::move(ctx));
        expect_slot32(r, 2, 0x00u);
    }
}

// ---------------------------------------------------------------------------
// (31.7) MIT-506/507 (T60): x87 L0 电池 —— 物理FPU驻留直执行真跑。
// 全部用例栈配平 (fld/fstp 成对), 测试间物理 FPU 状态零残留。
// ---------------------------------------------------------------------------
alignas(8) static double g_x87_a = 1.5, g_x87_b = 2.5, g_x87_out = 0.0;
alignas(8) static int32_t g_x87_i = 42, g_x87_io = 0;
alignas(4) static uint16_t g_x87_cw = 0x027F, g_x87_cwo = 0;

static isa::VmInsn x87_mem(u8 addr_slot, isa::VmOp op, u32 width) {
    return isa::make_insn(op, isa::OpKind::Reg, addr_slot, isa::OpKind::None,
                          0, width, isa::size_field(ir::Size::S64));
}

TEST(X86Battery, X87MemArithStoreRoundTrip) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    g_x87_a = 1.5; g_x87_b = 2.5; g_x87_out = 0.0;
    std::vector<u8> s;
    isa::append_insn(s, mov_imm(5, static_cast<u32>(reinterpret_cast<uintptr_t>(&g_x87_a))));
    isa::append_insn(s, x87_mem(5, isa::VmOp::Fld87Mem, 8));    // st0 = 1.5
    isa::append_insn(s, mov_imm(6, static_cast<u32>(reinterpret_cast<uintptr_t>(&g_x87_b))));
    isa::append_insn(s, x87_mem(6, isa::VmOp::Fadd87, 8));      // st0 += 2.5
    isa::append_insn(s, mov_imm(7, static_cast<u32>(reinterpret_cast<uintptr_t>(&g_x87_out))));
    isa::append_insn(s, x87_mem(7, isa::VmOp::Fstp87Mem, 8));   // out = 4.0
    isa::append_insn(s, halt());
    rt::VmContext ctx;
    ctx.bytecode = s.data();
    ctx.pc = 0;
    rwx.entry()(&ctx);
    EXPECT_EQ(g_x87_out, 4.0);
}

TEST(X86Battery, X87FchsFsqrtFildFistp) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    g_x87_a = 4.0; g_x87_out = 0.0; g_x87_i = 42; g_x87_io = 0;
    std::vector<u8> s;
    isa::append_insn(s, mov_imm(5, static_cast<u32>(reinterpret_cast<uintptr_t>(&g_x87_a))));
    isa::append_insn(s, x87_mem(5, isa::VmOp::Fld87Mem, 8));    // st0 = 4.0
    isa::append_insn(s, isa::make_insn(isa::VmOp::Fsqrt87, isa::OpKind::None,
                                       0, isa::OpKind::None, 0, 0, 0));
    isa::append_insn(s, mov_imm(6, static_cast<u32>(reinterpret_cast<uintptr_t>(&g_x87_out))));
    isa::append_insn(s, x87_mem(6, isa::VmOp::Fstp87Mem, 8));   // out = 2.0
    isa::append_insn(s, mov_imm(5, static_cast<u32>(reinterpret_cast<uintptr_t>(&g_x87_i))));
    isa::append_insn(s, x87_mem(5, isa::VmOp::Fild87Mem, 4));   // st0 = 42
    isa::append_insn(s, mov_imm(6, static_cast<u32>(reinterpret_cast<uintptr_t>(&g_x87_io))));
    isa::append_insn(s, x87_mem(6, isa::VmOp::Fistp87Mem, 4));  // io = 42
    isa::append_insn(s, halt());
    rt::VmContext ctx;
    ctx.bytecode = s.data();
    ctx.pc = 0;
    rwx.entry()(&ctx);
    EXPECT_EQ(g_x87_out, 2.0);
    EXPECT_EQ(g_x87_io, 42);
}

TEST(X86Battery, X87ComiFlagsAndStTree) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    g_x87_a = 2.5; g_x87_b = 1.5; g_x87_out = 0.0;
    // fld a(2.5); fld b(1.5) → st0=1.5, st1=2.5;
    // fcomi st, st(1) → 1.5 vs 2.5 = less → CF; getflags 断言;
    // fstp st(0) 清; fld st(1)?? — 栈树: fst st(3) 存 st0 → st3;
    // fld a; fadd st(0), st(3)?? — 简化: fstp st(0) 后 st0=2.5;
    // fadd87 reg {a=Imm 0, b=Imm 3} = st0 += st3(=2.5 存的) → 5.0。
    std::vector<u8> s;
    isa::append_insn(s, mov_imm(5, static_cast<u32>(reinterpret_cast<uintptr_t>(&g_x87_a))));
    isa::append_insn(s, x87_mem(5, isa::VmOp::Fld87Mem, 8));    // st0=2.5
    isa::append_insn(s, mov_imm(6, static_cast<u32>(reinterpret_cast<uintptr_t>(&g_x87_b))));
    isa::append_insn(s, x87_mem(6, isa::VmOp::Fld87Mem, 8));    // st0=1.5 st1=2.5
    isa::append_insn(s, isa::make_insn(isa::VmOp::Fcomi87, isa::OpKind::None,
                                       0, isa::OpKind::Imm, 1, 0,
                                       isa::size_field(ir::Size::S32)));
    isa::append_insn(s, getflags(2));
    // st(3) 树面: fst st(3) (st0=1.5 → st3); fstp st(0) (清 1.5, st0=2.5);
    // fadd87 {a=Imm 0, b=Imm 3} → st0 = 2.5 + st3(1.5) = 4.0; fstp out。
    isa::append_insn(s, isa::make_insn(isa::VmOp::Fst87St, isa::OpKind::Imm, 3,
                                       isa::OpKind::None, 0, 0, 0));
    isa::append_insn(s, isa::make_insn(isa::VmOp::Fstp87St, isa::OpKind::Imm, 0,
                                       isa::OpKind::None, 0, 0, 0));
    isa::append_insn(s, isa::make_insn(isa::VmOp::Fadd87, isa::OpKind::Imm, 0,
                                       isa::OpKind::Imm, 3, 0,
                                       isa::size_field(ir::Size::S32)));
    isa::append_insn(s, mov_imm(7, static_cast<u32>(reinterpret_cast<uintptr_t>(&g_x87_out))));
    isa::append_insn(s, x87_mem(7, isa::VmOp::Fstp87Mem, 8));
    isa::append_insn(s, halt());
    rt::VmContext ctx;
    ctx.bytecode = s.data();
    ctx.pc = 0;
    rwx.entry()(&ctx);
    expect_slot32(ctx, 2, isa::kFlagCF);   // 1.5 < 2.5 → CF
    EXPECT_EQ(g_x87_out, 4.0);             // st 树面: 2.5 + st3(1.5)
}

TEST(X86Battery, X87ControlWordRoundTrip) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    g_x87_cw = 0x027F; g_x87_cwo = 0;
    std::vector<u8> s;
    isa::append_insn(s, mov_imm(5, static_cast<u32>(reinterpret_cast<uintptr_t>(&g_x87_cw))));
    isa::append_insn(s, x87_mem(5, isa::VmOp::Fldcw87, 16));
    isa::append_insn(s, mov_imm(6, static_cast<u32>(reinterpret_cast<uintptr_t>(&g_x87_cwo))));
    isa::append_insn(s, x87_mem(6, isa::VmOp::Fnstcw87, 16));
    isa::append_insn(s, halt());
    rt::VmContext ctx;
    ctx.bytecode = s.data();
    ctx.pc = 0;
    rwx.entry()(&ctx);
    EXPECT_EQ(g_x87_cwo, 0x027F);
}

// ---------------------------------------------------------------------------
// (27) X3b 批次六：RVA 族（LoadRva/StoreRva/LeaRva —— base+RVA 公式钉，非
//      identity：base ≠ 0 时 VA ≠ RVA）
// ---------------------------------------------------------------------------
TEST(X86Battery, RvaFamily) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    alignas(4) std::array<u8, 0x40> scratch{};
    scratch.fill(0);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();
    constexpr u64 kFakeBase = 0x400000;
    const u32 data_va = static_cast<u32>(reinterpret_cast<uintptr_t>(scratch.data())) + 0x10;
    const u32 data_rva = data_va - static_cast<u32>(kFakeBase);

    auto run_base = [&](const std::vector<u8>& stream) {
        rt::VmContext ctx;
        ctx.bytecode = const_cast<u8*>(stream.data());
        ctx.pc = 0;
        ctx.scratch_mem = kFakeBase;   // image_base ≠ 0 —— identity 假设反证锚
        ctx.regs[isa::vm_reg_of(ir::Reg::Rsp)] = 0;
        entry(&ctx);
        return ctx;
    };
    auto storer = [](u8 addr, u8 src) {
        return isa::make_insn(isa::VmOp::StoreRva, isa::OpKind::Reg, addr,
                              isa::OpKind::Reg, src, 0, isa::size_field(ir::Size::S32));
    };
    auto loadr = [](u8 dst, u8 addr, ir::Size s) {
        return isa::make_insn(isa::VmOp::LoadRva, isa::OpKind::Reg, dst,
                              isa::OpKind::Reg, addr, 0, isa::size_field(s));
    };

    // StoreRva S32 → LoadRva S32 roundtrip（经 base+RVA）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(1, data_rva));                       // 0  RVA 槽
        isa::append_insn(s, mov_imm(2, 0xABCD1234u));                    // 1  数据
        isa::append_insn(s, storer(1, 2));                               // 2
        isa::append_insn(s, loadr(3, 1, ir::Size::S32));                 // 3
        isa::append_insn(s, halt());                                     // 4
        const auto ctx = run_base(s);
        expect_slot32(ctx, 3, 0xABCD1234u);
        EXPECT_EQ(scratch[0x10], 0x34u);     // 落在 data_va（base+RVA），非 data_rva
    }
    // LoadRva S8：宽度读（低字节）+ S16。
    {
        scratch[0x10] = 0x5A;
        scratch[0x11] = 0x33;
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(1, data_rva));                       // 0
        isa::append_insn(s, loadr(2, 1, ir::Size::S8));                  // 1
        isa::append_insn(s, loadr(3, 1, ir::Size::S16));                 // 2
        isa::append_insn(s, halt());                                     // 3
        const auto ctx = run_base(s);
        expect_slot32(ctx, 2, 0x5Au);
        expect_slot32(ctx, 3, 0x335Au);
    }
    // LeaRva：dst = base + RVA = data_va（不访存）。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(1, data_rva));                       // 0
        isa::append_insn(s, isa::make_insn(isa::VmOp::LeaRva, isa::OpKind::Reg, 2,
                                           isa::OpKind::Reg, 1, 0,
                                           isa::size_field(ir::Size::S32)));  // 1
        isa::append_insn(s, halt());                                     // 2
        const auto ctx = run_base(s);
        expect_slot32(ctx, 2, data_va);
    }
}

// ---------------------------------------------------------------------------
// (28) X3b 批次六：Jmp/Jcc S32 目标回归（far-forward aux > 127 dword 路径）
// ---------------------------------------------------------------------------
TEST(X86Battery, JmpJccFarTarget) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();
    constexpr u32 kFar = 0x100;   // aux = 256（> 127，S32 dword 路径非短跳）

    // jmp far-forward：jmp +0x100 → 0x100 处 halt（0x100 = 256 条 nop 后）。
    {
        std::vector<u8> s;
        isa::append_insn(s, isa::make_insn(isa::VmOp::Jmp, isa::OpKind::None, 0,
                                           isa::OpKind::None, 0, kFar, 0));  // 0
        for (u32 i = 1; i < kFar; ++i) isa::append_insn(s, bin(isa::VmOp::Nop, 0, 0, ir::Size::S32));
        isa::append_insn(s, halt());                                     // 0x100
        const auto ctx = run_stream(entry, s, nullptr);
        EXPECT_EQ(ctx.pc, kFar + 1u);
    }
    // jcc far-forward 取/不取两路：cmp 相等取远目标 / 不等顺延。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 7));                              // 0
        isa::append_insn(s, mov_imm(1, 7));                              // 1
        isa::append_insn(s, bin(isa::VmOp::Cmp, 0, 1, ir::Size::S32));   // 2
        // taken 目标 = jcc 自身 pc(3) + aux → aux = kFar - 3 落 0x100。
        isa::append_insn(s, jcc(ir::Cond::E, kFar - 3));                 // 3 → 0x100
        for (u32 i = 4; i < kFar; ++i) isa::append_insn(s, bin(isa::VmOp::Nop, 0, 0, ir::Size::S32));
        isa::append_insn(s, halt());                                     // 0x100
        const auto ctx = run_stream(entry, s, nullptr);
        EXPECT_EQ(ctx.pc, kFar + 1u);
    }
}

// ---------------------------------------------------------------------------
// (29) X3c B.1：CallGate RVA 形真调用（aux + image_base，base≠0 非 identity）
// ---------------------------------------------------------------------------
TEST(X86Battery, CallGateRvaFormRealCall) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    // base≠0（RvaFamily 同款纪律）：aux = fnptr - kFakeBase，handler 加
    // [ctx+0x110] 低 dword 还原 VA —— identity 假设反证。
    constexpr u64 kFakeBase = 0x400000;
    const u32 fn_rva = static_cast<u32>(reinterpret_cast<uintptr_t>(&xcg_probe)) -
                       static_cast<u32>(kFakeBase);
    std::vector<u8> s;
    isa::append_insn(s, callgate_rva(fn_rva));                           // 0
    isa::append_insn(s, halt());                                         // 1
    rt::VmContext ctx;
    ctx.bytecode = s.data();
    ctx.pc = 0;
    ctx.scratch_mem = kFakeBase;
    ctx.regs[isa::vm_reg_of(ir::Reg::Rsp)] =
        reinterpret_cast<u64>(g_xcg_stack + 0x20);  // X4 参数窗: v4 = 真实映射栈
                                     // （X5b 8 dword 窗 = [v4..v4+0x1C] 落缓冲内）
    g_xcg_calls = 0;
    rwx.entry()(&ctx);
    EXPECT_EQ(g_xcg_calls, 1u);          // 真调用（ callee 执行）
    expect_slot32(ctx, 0, 0x5A5u);       // callee 返回值 → regs[0] 低 dword
    EXPECT_EQ(ctx.ret_value, 0x5A5u);    // Halt 写回 ret_value = regs[0]
    EXPECT_EQ(ctx.pc, 2u);               // callgate 后 advance，Halt pc+1
}

// ---------------------------------------------------------------------------
// (30) X3c B.1：CallGate reg 形真调用（a_kind=Reg 目标槽 → 绝对 VA 直调）。
//      x86 协议面核心断言：目标值经 reg 槽传入的 callee 真调用 + esp 跨
//      handler 稳定 + 返回值写回。
// ---------------------------------------------------------------------------
TEST(X86Battery, CallGateRegFormRealCall) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    const u32 fn_abs = static_cast<u32>(reinterpret_cast<uintptr_t>(&xcg_probe));
    std::vector<u8> s;
    isa::append_insn(s, mov_imm(1, fn_abs));                             // 0  v1 = 目标 VA
    isa::append_insn(s, callgate_reg(1));                                // 1  a_kind=Reg, reg_a=1
    isa::append_insn(s, halt());                                         // 2
    rt::VmContext ctx;
    ctx.bytecode = s.data();
    ctx.pc = 0;
    ctx.scratch_mem = 0;
    ctx.regs[isa::vm_reg_of(ir::Reg::Rsp)] =
        reinterpret_cast<u64>(g_xcg_stack + 0x20);  // X4 参数窗: v4 = 真实映射栈
                                     // （X5b 8 dword 窗 = [v4..v4+0x1C] 落缓冲内）
    g_xcg_calls = 0;
    rwx.entry()(&ctx);
    EXPECT_EQ(g_xcg_calls, 1u);          // 真调用
    expect_slot32(ctx, 0, 0x5A5u);       // 返回值写回
    EXPECT_EQ(ctx.pc, 3u);
}

// ---------------------------------------------------------------------------
// (31) X3c B.1：CallGate reg 形 + 前序槽算术（目标值 = 运行时算出, 非立即
//      数直装 —— call [mem] 折条的 Load 语义等价形: 槽间 Mov 加偏移）。
// ---------------------------------------------------------------------------
TEST(X86Battery, CallGateRegFormComputedTarget) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    constexpr u64 kFakeBase = 0x400000;
    const u32 fn_rva = static_cast<u32>(reinterpret_cast<uintptr_t>(&xcg_probe)) -
                       static_cast<u32>(kFakeBase);
    std::vector<u8> s;
    isa::append_insn(s, mov_imm(1, fn_rva));                             // 0  v1 = RVA
    isa::append_insn(s, isa::make_insn(isa::VmOp::LeaRva, isa::OpKind::Reg, 2,
                                       isa::OpKind::Reg, 1, 0,
                                       isa::size_field(ir::Size::S32)));  // 1  v2 = VA
    isa::append_insn(s, callgate_reg(2));                                // 2  reg 形 v2 槽
    isa::append_insn(s, halt());                                         // 3
    rt::VmContext ctx;
    ctx.bytecode = s.data();
    ctx.pc = 0;
    ctx.scratch_mem = kFakeBase;
    ctx.regs[isa::vm_reg_of(ir::Reg::Rsp)] =
        reinterpret_cast<u64>(g_xcg_stack + 0x20);  // X4 参数窗: v4 = 真实映射栈
                                     // （X5b 8 dword 窗 = [v4..v4+0x1C] 落缓冲内）
    g_xcg_calls = 0;
    rwx.entry()(&ctx);
    EXPECT_EQ(g_xcg_calls, 1u);
    expect_slot32(ctx, 0, 0x5A5u);
    EXPECT_EQ(ctx.pc, 4u);
}

// ---------------------------------------------------------------------------
// (31.5) MIT-498 (T51)：寄存器参数桥。fastcall callee 经 ecx/edx 取参——
//       guest 槽 → 桥入物理（step 2.7）→ callee 读参 → eax（+ edx:eax 64
//       位返回对）写回（step 5/5.5）。此前物理 ecx/edx = 垃圾（wv_mul64hi
//       E2E 错值根因，GAPS MIT-497/498）。
static u32 __fastcall xcg_fast(u32 a, u32 b) {
    ++g_xcg_calls;
    return (a << 16) | (b & 0xFFFFu);
}
static u64 __fastcall xcg_pair(u32 a, u32 b) {
    ++g_xcg_calls;
    return (static_cast<u64>(a) << 32) | b;
}

TEST(X86Battery, CallGateRegisterArgBridge) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    constexpr u64 kFakeBase = 0x400000;
    const u32 fn_rva = static_cast<u32>(reinterpret_cast<uintptr_t>(&xcg_fast)) -
                       static_cast<u32>(kFakeBase);
    std::vector<u8> s;
    isa::append_insn(s, callgate_rva(fn_rva));                           // 0
    isa::append_insn(s, halt());                                         // 1
    rt::VmContext ctx;
    ctx.bytecode = s.data();
    ctx.pc = 0;
    ctx.scratch_mem = kFakeBase;
    ctx.regs[isa::vm_reg_of(ir::Reg::Rsp)] =
        reinterpret_cast<u64>(g_xcg_stack + 0x20);
    ctx.regs[isa::vm_reg_of(ir::Reg::Rcx)] = 0x1234;   // fastcall arg0 (ecx)
    ctx.regs[isa::vm_reg_of(ir::Reg::Rdx)] = 0x5678;   // fastcall arg1 (edx)
    g_xcg_calls = 0;
    rwx.entry()(&ctx);
    EXPECT_EQ(g_xcg_calls, 1u);            // 真调用
    expect_slot32(ctx, 0, (0x1234u << 16) | 0x5678u);  // callee 收到桥入值
    EXPECT_EQ(ctx.pc, 2u);
}

TEST(X86Battery, CallGateEdxReturnPairBridge) {
    // edx:eax 64 位返回对（step 5.5 写回；__allmul/移位 helper 半积通路）。
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    constexpr u64 kFakeBase = 0x400000;
    const u32 fn_rva = static_cast<u32>(reinterpret_cast<uintptr_t>(&xcg_pair)) -
                       static_cast<u32>(kFakeBase);
    std::vector<u8> s;
    isa::append_insn(s, callgate_rva(fn_rva));                           // 0
    isa::append_insn(s, halt());                                         // 1
    rt::VmContext ctx;
    ctx.bytecode = s.data();
    ctx.pc = 0;
    ctx.scratch_mem = kFakeBase;
    ctx.regs[isa::vm_reg_of(ir::Reg::Rsp)] =
        reinterpret_cast<u64>(g_xcg_stack + 0x20);
    ctx.regs[isa::vm_reg_of(ir::Reg::Rcx)] = 0xDEAD;   // fastcall arg0
    ctx.regs[isa::vm_reg_of(ir::Reg::Rdx)] = 0xBEEF;   // fastcall arg1
    g_xcg_calls = 0;
    rwx.entry()(&ctx);
    EXPECT_EQ(g_xcg_calls, 1u);
    expect_slot32(ctx, 0, 0xBEEFu);        // regs[0] = 返回低 dword (eax)
    expect_slot32(ctx, 2, 0xDEADu);        // regs[2] = 返回高 dword (edx, step 5.5)
    EXPECT_EQ(ctx.pc, 2u);
}

TEST(X86Battery, CallGateBridgeSeedSweep) {
    // T51 验收 C 修复钉：call 载体选择对 roll 随机性的不变量——{t0=eax,
    // t1=ebx} 混合对分支使 t_[2] 可为易失（首版转存被桥接覆写 → call
    // guest edx 槽值，seed 67 真执行复现）。扫 0..63 + 首个坏 seed 67 +
    // 远端样本：每 seed 重生成 runtime 后跑 fastcall 场景，callee 被调
    // 且返回值正确 = 载体选择跨 roll 正确。
    constexpr u64 kFakeBase = 0x400000;
    const u32 fn_rva = static_cast<u32>(reinterpret_cast<uintptr_t>(&xcg_fast)) -
                       static_cast<u32>(kFakeBase);
    const u64 seeds[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                         16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 63,
                         67, 128, 999, 0xDEADBEEF, 0xCAFEBABE};
    for (const u64 seed : seeds) {
        wvmp::Rng rng(seed);
        const auto gen = rt::generate_runtime_x86(rng);
        RwxImage rwx(gen.image.code);
        std::vector<u8> s;
        isa::append_insn(s, callgate_rva(fn_rva));
        isa::append_insn(s, halt());
        rt::VmContext ctx;
        ctx.bytecode = s.data();
        ctx.pc = 0;
        ctx.scratch_mem = kFakeBase;
        ctx.regs[isa::vm_reg_of(ir::Reg::Rsp)] =
            reinterpret_cast<u64>(g_xcg_stack + 0x20);
        ctx.regs[isa::vm_reg_of(ir::Reg::Rcx)] = 0x1234;
        ctx.regs[isa::vm_reg_of(ir::Reg::Rdx)] = 0x5678;
        g_xcg_calls = 0;
        rwx.entry()(&ctx);
        EXPECT_EQ(g_xcg_calls, 1u) << "seed=" << seed << " callee 未被调用";
        EXPECT_EQ(ctx.regs[isa::vm_reg_of(ir::Reg::Rax)],
                  static_cast<u64>((0x1234u << 16) | 0x5678u))
            << "seed=" << seed << " 桥入返回值错";
    }
}

// ---------------------------------------------------------------------------
// (32) X3c B.2：ExitNative 无条件直退 + 4B 退出槽协议（真执行断言）。
//      槽地址 = native_sp - kX86ExitSlotDepth（X4 stub_gen 读侧对接
//      锚）；槽内容 = aux + image_base（目标 VA dword）。epilogue（帧回收 +
//      4 callee-saved pop + ret）后控制返回测试进程。
// ---------------------------------------------------------------------------
// 退出槽承载区：静态缓冲（native_sp = 缓冲末端，槽 = 末端 - kX86ExitSlotDepth
// 落缓冲内 ——电池无 stub，native_sp 由测试预置 [ctx+0x120]）。MIT-451 (X5b)
// B.2：kX86ExitSlotDepth 0x258→0x2D8（guard 垫栈派生），缓冲随之扩容。
static unsigned long g_xen_area[0x2E0 / sizeof(unsigned long)];

static isa::VmInsn exitnative_uncond(u32 rva) {
    return isa::make_insn(isa::VmOp::ExitNative, isa::OpKind::Imm, 0,
                          isa::OpKind::None, 0, rva, 0);
}
static isa::VmInsn exitnative_cond(ir::Cond c, u32 rva) {
    return isa::make_insn(isa::VmOp::ExitNative, isa::OpKind::None, 0,
                          isa::OpKind::None, 0, rva, u8(c));
}
static isa::VmInsn setflags(u8 slot) {
    return isa::make_insn(isa::VmOp::SetFlags, isa::OpKind::Reg, slot,
                          isa::OpKind::None, 0, 0,
                          isa::size_field(ir::Size::S32));
}

TEST(X86Battery, ExitNativeUncondSlotProtocol) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    constexpr u64 kFakeBase = 0x400000;
    const u64 kNs = reinterpret_cast<u64>(g_xen_area) + sizeof(g_xen_area);
    const u64 kSlot = kNs - rt::kX86ExitSlotDepth;  // 单一来源（runtime_x86.hpp）
    std::vector<u8> s;
    isa::append_insn(s, exitnative_uncond(0x1234));                      // 0
    isa::append_insn(s, halt());                                         // 1 (不可达)
    rt::VmContext ctx;
    ctx.bytecode = s.data();
    ctx.pc = 0;
    ctx.scratch_mem = kFakeBase;
    ctx.native_sp = kNs;
    ctx.regs[isa::vm_reg_of(ir::Reg::Rsp)] = 0;
    *reinterpret_cast<unsigned long*>(kSlot) = 0xBBBBBBBBul;             // 哨兵
    rwx.entry()(&ctx);
    // 4B 槽协议：目标 VA = aux + image_base 落 [ns - kX86ExitSlotDepth]。
    EXPECT_EQ(*reinterpret_cast<unsigned long*>(kSlot), 0x401234ul);
    // 退出路径不 advance（pc 不写回；x64 build_exitnative 同语义）。
    EXPECT_EQ(ctx.pc, 0u);
}

// ---------------------------------------------------------------------------
// (33) X3c B.2：ExitNative 条件形双路——满足退出（槽落账）/ 不满足继续 VM。
// ---------------------------------------------------------------------------
TEST(X86Battery, ExitNativeCondTakenAndFallthrough) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    constexpr u64 kFakeBase = 0x400000;
    const u64 kNs = reinterpret_cast<u64>(g_xen_area) + sizeof(g_xen_area);
    const u64 kSlot = kNs - rt::kX86ExitSlotDepth;  // 单一来源（runtime_x86.hpp）
    // 路 1: ZF=1（SetFlags v2=1）→ cond E 满足 → 退出。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(2, 0x1));                            // 0 ZF 位
        isa::append_insn(s, setflags(2));                                // 1
        isa::append_insn(s, exitnative_cond(ir::Cond::E, 0x1234));       // 2
        isa::append_insn(s, halt());                                     // 3 (不可达)
        rt::VmContext ctx;
        ctx.bytecode = s.data();
        ctx.pc = 0;
        ctx.scratch_mem = kFakeBase;
        ctx.native_sp = kNs;
        ctx.regs[isa::vm_reg_of(ir::Reg::Rsp)] = 0;
        *reinterpret_cast<unsigned long*>(kSlot) = 0xBBBBBBBBul;
        rwx.entry()(&ctx);
        EXPECT_EQ(*reinterpret_cast<unsigned long*>(kSlot), 0x401234ul);
        EXPECT_EQ(ctx.pc, 2u);   // 退出路径不 advance（pc 停在 ExitNative 本条）
    }
    // 路 2: ZF=0（SetFlags v2=0x1E: CF/OF/SF/PF 置位、ZF 清零）→ 不满足 →
    // advance 继续 VM → Halt；槽哨兵不变。
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(2, 0x1E));                           // 0
        isa::append_insn(s, setflags(2));                                // 1
        isa::append_insn(s, exitnative_cond(ir::Cond::E, 0x1234));       // 2
        isa::append_insn(s, halt());                                     // 3
        rt::VmContext ctx;
        ctx.bytecode = s.data();
        ctx.pc = 0;
        ctx.scratch_mem = kFakeBase;
        ctx.native_sp = kNs;
        ctx.regs[isa::vm_reg_of(ir::Reg::Rsp)] = 0;
        *reinterpret_cast<unsigned long*>(kSlot) = 0xBBBBBBBBul;
        rwx.entry()(&ctx);
        EXPECT_EQ(*reinterpret_cast<unsigned long*>(kSlot), 0xBBBBBBBBul);
        EXPECT_EQ(ctx.pc, 4u);   // ExitNative advance + Halt pc+1
        EXPECT_EQ(ctx.ret_value, 0u);
    }
}

// ---------------------------------------------------------------------------
// (34)(35) X3c B.3：Ret 4B 清栈返回真执行断言——handler 出口 jmp 到 guest
//      返回地址（naked landing 捕获物理 esp/eax 后 longjmp 回测试），栈平衡
//      与易失写回 (eax) 双断言。guest 栈 = 静态缓冲（零宿主栈碰撞）。
// ---------------------------------------------------------------------------
static unsigned long g_xret_stack[64];            // guest 栈缓冲
static unsigned long g_xret_land_esp = 0;
static unsigned long g_xret_land_eax = 0;
static jmp_buf g_xret_env;
static void xret_guest_land_cpp(void);   // 前置声明（naked asm jmp 目标）

// naked landing：Ret handler `jmp [esp-4]` 进入时物理 esp = v4'（guest 栈），
// 无 prologue 直接捕获（普通函数 prologue 会先压栈破坏 v4' 观察）。
static void __declspec(naked) xret_guest_land(void) {
    __asm {
        mov g_xret_land_esp, esp
        mov g_xret_land_eax, eax
        jmp xret_guest_land_cpp
    }
}
static void xret_guest_land_cpp(void) {
    longjmp(g_xret_env, 42);
}

// MSVC: setjmp 与 C++ 对象交互为非可移植面 (/WX C4611)——本文件的 setjmp/
// longjmp 域内无带析构的 C++ 局部对象（见各用例结构注），显式屏蔽。
#pragma warning(disable : 4611)
static isa::VmInsn ret_insn(u32 imm) {
    return isa::make_insn(isa::VmOp::Ret, isa::OpKind::None, 0,
                          isa::OpKind::None, 0, imm, isa::size_field(ir::Size::S64));
}
static isa::VmInsn push_reg(u8 slot) {
    return isa::make_insn(isa::VmOp::Push, isa::OpKind::Reg, slot,
                          isa::OpKind::None, 0, 0, isa::size_field(ir::Size::S32));
}

TEST(X86Battery, RetPlainStackBalance) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    const u32 guest_top = reinterpret_cast<u32>(g_xret_stack + 48);
    const u32 land = reinterpret_cast<u32>(&xret_guest_land);
    std::vector<u8> s;
    isa::append_insn(s, mov_imm(4, guest_top));                          // 0  v4 = top
    isa::append_insn(s, mov_imm(5, land));                               // 1  v5 = &land
    isa::append_insn(s, push_reg(5));                                    // 2  [top-4]=land, v4=top-4
    isa::append_insn(s, mov_imm(0, 0xBEEF));                             // 3  v0 = 返回值
    isa::append_insn(s, ret_insn(0));                                    // 4  plain ret
    rt::VmContext ctx;
    ctx.bytecode = s.data();
    ctx.pc = 0;
    ctx.scratch_mem = 0;
    ctx.regs[isa::vm_reg_of(ir::Reg::Rsp)] = 0;
    memset(g_xret_stack, 0, sizeof(g_xret_stack));
    g_xret_land_esp = 0;
    g_xret_land_eax = 0;
    if (setjmp(g_xret_env) == 0) {
        rwx.entry()(&ctx);
        FAIL() << "Ret handler did not exit to guest caller";
    }
    EXPECT_EQ(g_xret_land_esp, guest_top);   // v4' = top-4+4+0 = top（平衡）
    EXPECT_EQ(g_xret_land_eax, 0xBEEFu);     // 易失写回 eax ← regs[0]
    // v4' 持久化 [ctx+0x30]（低 dword；高半字 0 不变量）。
    EXPECT_EQ(ctx.regs[isa::vm_reg_of(ir::Reg::Rsp)], static_cast<u64>(guest_top));
}

TEST(X86Battery, RetImm16StackBalance) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    RwxImage rwx(gen.image.code);
    const u32 guest_top = reinterpret_cast<u32>(g_xret_stack + 48);
    const u32 land = reinterpret_cast<u32>(&xret_guest_land);
    std::vector<u8> s;
    // stdcall 栈序：caller 先压参数（高位地址）、`call` 最后压 retaddr
    // （[v4]）；被调方 `ret 8` 弹 retaddr 后再丢弃 8B 参数 → esp 回到压参前。
    const u32 work_top = guest_top + 8;                                  // 预留 2 个参数槽
    isa::append_insn(s, mov_imm(4, work_top));                           // 0  v4 = work_top
    isa::append_insn(s, mov_imm(5, land));                               // 1
    isa::append_insn(s, mov_imm(6, 0x77));                               // 2  arg 1
    isa::append_insn(s, push_reg(6));                                    // 3  [work_top-4]=0x77, v4=work_top-4
    isa::append_insn(s, mov_imm(6, 0x99));                               // 4  arg 2
    isa::append_insn(s, push_reg(6));                                    // 5  [work_top-8]=0x99, v4=work_top-8
    isa::append_insn(s, push_reg(5));                                    // 6  [work_top-0xC]=land, v4=work_top-0xC
    isa::append_insn(s, ret_insn(8));                                    // 7  ret 8 清栈
    rt::VmContext ctx;
    ctx.bytecode = s.data();
    ctx.pc = 0;
    ctx.scratch_mem = 0;
    ctx.regs[isa::vm_reg_of(ir::Reg::Rsp)] = 0;
    memset(g_xret_stack, 0, sizeof(g_xret_stack));
    g_xret_land_esp = 0;
    g_xret_land_eax = 0;
    if (setjmp(g_xret_env) == 0) {
        rwx.entry()(&ctx);
        FAIL() << "Ret handler did not exit to guest caller";
    }
    // v4' = (work_top-0xC)+4+8 = work_top = guest_top+8 —— 弹 retaddr + 丢
    // 2 个参数槽：被调方清栈（stdcall 形）后 esp 回到压参前原点（栈平衡）。
    EXPECT_EQ(g_xret_land_esp, work_top);
    EXPECT_EQ(ctx.regs[isa::vm_reg_of(ir::Reg::Rsp)], static_cast<u64>(work_top));
}

// ---------------------------------------------------------------------------
// (36) MIT-446 (X4) B.2/D5：改形正反用例 —— 3 路尺寸链真块证据 + S64 防御
//      出口回归防护（"S64 no-op 复辟探测器"的运行时层面）。
//      正例：S32 tag 的地址算术/esp 步进真生效（值推进 + 内存真写）；
//      反例：444 时代错形 S64 tag 同形发射 = 链尾顺延 no-op（esp 槽不动、
//      内存不写）——若未来有人把步进 tag 改回 S64（或 x86 翻译器重新产
//      S64 VmOp），本断言把"静默空转"变成电池当场炸。
// ---------------------------------------------------------------------------
TEST(X86Battery, StepTagS32LiveAndS64NoopGuard) {
    wvmp::Rng rng(12345);
    const auto gen = rt::generate_runtime_x86(rng);
    alignas(4) std::array<u8, 0x40> scratch{};
    scratch.fill(0);
    RwxImage rwx(gen.image.code);
    const auto entry = rwx.entry();
    const u8 rsp_slot = isa::vm_reg_of(ir::Reg::Rsp);
    const u32 top = 0x20;   // 用相对偏移做栈指针（scratch 绝对 VA 无需知道）
    const u32 planted = 0x00C0FFEEu;
    std::memcpy(scratch.data() + (top - 4), &planted, 4);

    auto run = [&](const std::vector<u8>& s) {
        rt::VmContext ctx;
        ctx.bytecode = const_cast<u8*>(s.data());
        ctx.pc = 0;
        ctx.scratch_mem = 0;
        ctx.regs[rsp_slot] = reinterpret_cast<uintptr_t>(scratch.data()) + top;
        entry(&ctx);
        return ctx;
    };

    // 反例（S64 防御 no-op 钉死）：Sub rsp 槽, 4 @ S64 → esp 不推进、内存
    // 不写；Load [rsp] @ S64 → 同样链尾顺延（dst 槽保持清零值）。
    {
        std::vector<u8> s;
        isa::append_insn(s, bin_imm(isa::VmOp::Sub, rsp_slot, 4, ir::Size::S64));  // 0
        isa::append_insn(s, isa::make_insn(isa::VmOp::Load, isa::OpKind::Reg, 5,
                                           isa::OpKind::Reg, rsp_slot, 0,
                                           isa::size_field(ir::Size::S64)));       // 1
        isa::append_insn(s, halt());                                              // 2
        const auto ctx = run(s);
        EXPECT_EQ(ctx.regs[rsp_slot],
                  static_cast<u64>(reinterpret_cast<uintptr_t>(scratch.data()) + top))
            << "S64 tag must stay a defensive no-op (chain-tail), esp unchanged";
        expect_slot32(ctx, 5, 0);
    }

    // 正例（S32 真块）：同一 Sub rsp 槽 @ S32 → esp 真推进 4；Load [esp]
    // @ S32 → 读到栽好的值（地址算术 + 访存全链真块）。
    {
        std::vector<u8> s;
        isa::append_insn(s, bin_imm(isa::VmOp::Sub, rsp_slot, 4, ir::Size::S32));  // 0
        isa::append_insn(s, isa::make_insn(isa::VmOp::Load, isa::OpKind::Reg, 5,
                                           isa::OpKind::Reg, rsp_slot, 0,
                                           isa::size_field(ir::Size::S32)));       // 1
        isa::append_insn(s, halt());                                              // 2
        const auto ctx = run(s);
        EXPECT_EQ(ctx.regs[rsp_slot],
                  static_cast<u64>(reinterpret_cast<uintptr_t>(scratch.data()) + top - 4))
            << "S32 tag must take the real size-chain block, esp advances 4B";
        expect_slot32(ctx, 5, planted);
    }

    // 正例（S32 地址算术复合形：base 槽拷贝 + 常量加减——emit_address 的
    // x86 展开形）：Mov v18, rsp 槽值; Add v18, 8; Load v19, [v18]。
    {
        std::vector<u8> s;
        isa::append_insn(s, isa::make_insn(isa::VmOp::Mov, isa::OpKind::Reg, 18,
                                           isa::OpKind::Reg, rsp_slot, 0,
                                           isa::size_field(ir::Size::S32)));       // 0
        isa::append_insn(s, bin_imm(isa::VmOp::Add, 18, 8, ir::Size::S32));        // 1
        isa::append_insn(s, bin_imm(isa::VmOp::Sub, 18, 4, ir::Size::S32));        // 2
        isa::append_insn(s, isa::make_insn(isa::VmOp::Load, isa::OpKind::Reg, 19,
                                           isa::OpKind::Reg, 18, 0,
                                           isa::size_field(ir::Size::S32)));       // 3
        isa::append_insn(s, halt());                                              // 4
        const auto ctx = run(s);
        expect_slot32(ctx, 18,
                      static_cast<u32>(reinterpret_cast<uintptr_t>(scratch.data()) + top + 4));
        expect_slot32(ctx, 19, 0);  // scratch 高位未栽值 → 0（真访存证据）
        // 栽值到 top+4 再跑一遍，读回验证。
        const u32 planted2 = 0x13572468u;
        std::memcpy(scratch.data() + (top + 4), &planted2, 4);
        const auto ctx2 = run(s);
        expect_slot32(ctx2, 19, planted2);
    }
}

// ---------------------------------------------------------------------------
// MIT-473 (C 点取指级加密)：x86 fetch 模式语义对等（同 x64 口径）。
// 明文流 fetch=false 基线 vs encrypt_fetch_with_key 加密 + fetch=true 运行
// 时，终态逐位一致。S32 域：回边循环求和、取/不取分支、RVA 访存往返。
// ---------------------------------------------------------------------------
TEST(X86Battery, FetchDecryptSemanticParity) {
    namespace codecs = wvmp::regvm::codecs;
    const u8 sz32 = isa::size_field(ir::Size::S32);
    std::vector<u8> plain;
    isa::append_insn(plain, bin_imm(isa::VmOp::Mov, 0, 0, ir::Size::S32));   // 0: v0 = 0
    isa::append_insn(plain, bin_imm(isa::VmOp::Mov, 1, 5, ir::Size::S32));   // 1: v1 = 5
    isa::append_insn(plain, bin(isa::VmOp::Add, 0, 1, ir::Size::S32));       // 2 循环头
    isa::append_insn(plain, bin(isa::VmOp::Dec, 1, 1, ir::Size::S32));       // 3
    isa::append_insn(plain, jcc(ir::Cond::Ne, u32(-2)));                     // 4 → 回 2
    isa::append_insn(plain, bin(isa::VmOp::Mov, 4, 0, ir::Size::S32));       // 5: v4 = v0
    isa::append_insn(plain, bin_imm(isa::VmOp::And, 4, 1, ir::Size::S32));   // 6: v4 &= 1
    isa::append_insn(plain, jcc(ir::Cond::Ne, 2));                           // 7: 奇 → 跳过
    isa::append_insn(plain, bin_imm(isa::VmOp::Add, 0, 100, ir::Size::S32)); // 8 不执行
    isa::append_insn(plain, bin_imm(isa::VmOp::Mov, 2, 0x1234, ir::Size::S32));  // 9
    isa::append_insn(plain, isa::make_insn(isa::VmOp::StoreRva, isa::OpKind::Reg, 2,
                                           isa::OpKind::Reg, 2, 0, sz32));   // 10
    isa::append_insn(plain, isa::make_insn(isa::VmOp::LoadRva, isa::OpKind::Reg, 3,
                                           isa::OpKind::Reg, 2, 0, sz32));   // 11
    isa::append_insn(plain, bin(isa::VmOp::Add, 0, 3, ir::Size::S32));       // 12
    isa::append_insn(plain, halt());                                         // 13
    ASSERT_EQ(plain.size() % 8, 0u);

    alignas(16) std::array<u8, 0x10000> scratch{};
    const u32 scratch_va = static_cast<u32>(reinterpret_cast<uintptr_t>(scratch.data()));

    auto run_once = [&](const rt::RuntimeGenResult& gen, u8* bytecode) {
        rt::VmContext ctx;
        ctx.bytecode = bytecode;
        ctx.pc = 0;
        ctx.scratch_mem = scratch_va;
        ctx.regs[isa::vm_reg_of(ir::Reg::Rsp)] = 0;
        RwxImage rwx(gen.image.code);
        rwx.entry()(&ctx);
        return ctx;
    };

    // 明文基线（fetch=false）。MIT-494t 验收 SH1：种子集 {1,7,0xC0FFEE}
    // 对 roll 状态空间（t_[1..3] 是否含 eax）覆盖 ≈0——fetch-decrypt 别名
    // 回归曾 37% 种子失败而本测试全绿。扩为 0..49 连续 50 seed（eax 命中
    // 期望 ~17 次，别名缺陷必然检出）。
    std::vector<u64> base_regs;
    u64 base_ret = 0, base_pc = 0;
    for (u32 seed = 0; seed < 50; ++seed) {
        wvmp::Rng rng(seed);
        const auto gen = rt::generate_runtime_x86(rng, false);
        std::vector<u8> stream = plain;
        const auto ctx = run_once(gen, stream.data());
        if (base_regs.empty()) {
            base_regs.assign(std::begin(ctx.regs), std::end(ctx.regs));
            base_ret = ctx.ret_value;
            base_pc = ctx.pc;
        } else {
            EXPECT_EQ(std::vector<u64>(std::begin(ctx.regs), std::end(ctx.regs)), base_regs);
        }
    }
    EXPECT_EQ(base_regs[0], 15ull + 0x1234ull);
    EXPECT_EQ(base_regs[3], 0x1234ull);
    EXPECT_EQ(base_regs[1], 0ull);

    // 加密态（fetch=true）：位置键流 + dispatch 织入解密，终态须逐位一致。
    for (u32 seed = 0; seed < 50; ++seed) {
        wvmp::Rng rng(seed);
        const auto gen = rt::generate_runtime_x86(rng, true);
        std::vector<u8> blob(codecs::kBlobHeaderBytes, 0);
        blob.insert(blob.end(), plain.begin(), plain.end());
        const u32 key0 = 0x5A5AC3C3u + seed;
        codecs::XorChainCodec::encrypt_fetch_with_key(key0, blob);
        u32 seed_hdr = 0;
        std::memcpy(&seed_hdr, blob.data() + 16, 4);
        ASSERT_EQ(seed_hdr, key0);
        const auto ctx = run_once(gen, blob.data() + codecs::kBlobHeaderBytes);
        EXPECT_EQ(std::vector<u64>(std::begin(ctx.regs), std::end(ctx.regs)), base_regs)
            << "seed=" << seed;
        EXPECT_EQ(ctx.ret_value, base_ret);
        EXPECT_EQ(ctx.pc, base_pc);
    }
}
