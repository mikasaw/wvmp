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
#include "wvmp/regvm/isa/encoding.hpp"
#include "wvmp/regvm/isa/vm_op.hpp"
#include "wvmp/regvm/isa/vm_reg.hpp"
#include "wvmp/vm/backend.hpp"

#include <capstone/capstone.h>

#include <gtest/gtest.h>

#include <windows.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
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
