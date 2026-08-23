// P6：regvm 运行时语义测试。
//
// 核心思路：generate_runtime 产出的 code 拷入 VirtualAlloc 的 RWX 页，
// 以 `void entry(VmContext*)`（Win64，RCX=ctx）直接调用；字节码程序用
// isa::make_insn/append_insn 手工搭建（不依赖 translator）。
//
// 覆盖：
//   (a) 算术组合（S32 零扩展 + and/or/xor/shl/sub 终值对照）
//   (b) 子寄存器写合并（S8 add 保高 56 位）
//   (c) flags + jcc（E/Ne/L/G，取/不取两路）
//   (d) 循环回跳求和（Ne 回边）
//   (e) Load/Store（scratch_mem 基址 + Size 缩放，回读一致）
//   (f) Push/Pop（v4=Rsp 递减/递增、LIFO、栈内容落位）
//   (g) Halt 返回路径 + callee-saved 现场保持（rbx/rbp/r12-r15/rdi/rsi
//       经一段测试自汇编 driver 检查）+ ret_value/pc 写回
//   (h) Test/GetFlags/SetFlags 的 flags 位布局
//   稳定性：≥5 个不同 Rng 种子全部重生成并通过同一组语义；
//   asm_dump 非空且含 dispatch/codec 标记（防空生成退化）。

#include "wvmp/regvm/runtime/runtime.hpp"

#include "wvmp/common/rng.hpp"
#include "wvmp/regvm/isa/encoding.hpp"
#include "wvmp/regvm/isa/vm_op.hpp"
#include "wvmp/regvm/isa/vm_reg.hpp"
#include "wvmp/vm/backend.hpp"

#include <keystone/keystone.h>

#include <gtest/gtest.h>

#include <windows.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

namespace isa = wvmp::regvm::isa;
namespace rt = wvmp::regvm::runtime;
namespace ir = wvmp::ir;
namespace vm = wvmp::vm;
using wvmp::u8;
using wvmp::u32;
using wvmp::u64;

// ---------------------------------------------------------------------------
// 基础设施
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

    using Entry = void (*)(rt::VmContext*);
    Entry entry() const { return reinterpret_cast<Entry>(mem_); }

private:
    void* mem_ = nullptr;
};

// 汇编一段测试辅助机器码（driver 等）。
std::vector<u8> assemble_or_throw(const std::string& src) {
    ks_engine* ks = nullptr;
    if (ks_open(KS_ARCH_X86, KS_MODE_64, &ks) != KS_ERR_OK)
        throw std::runtime_error("ks_open failed");
    ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_INTEL);
    unsigned char* enc = nullptr;
    size_t size = 0, count = 0;
    const int rc = ks_asm(ks, src.c_str(), 0, &enc, &size, &count);
    std::vector<u8> out;
    if (rc == 0 && enc) out.assign(enc, enc + size);
    if (enc) ks_free(enc);
    const ks_err err = ks_errno(ks);
    ks_close(ks);
    if (rc != 0) throw std::runtime_error("ks_asm failed: " + std::to_string(int(err)));
    return out;
}

// 指令便捷构造（默认 S64 / 寄存器-寄存器）。
isa::VmInsn mov_imm(u8 dst, u32 imm, ir::Size s = ir::Size::S64) {
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

// 执行一段流，返回执行后的上下文（scratch 由调用方提供并可在其后检查）。
rt::VmContext run_stream(RwxImage::Entry entry, const std::vector<u8>& stream, u8* scratch,
                         u64 init_rsp = 0) {
    rt::VmContext ctx;
    ctx.bytecode = const_cast<u8*>(stream.data());
    ctx.pc = 0;
    ctx.scratch_mem = reinterpret_cast<u64>(scratch);
    ctx.regs[isa::vm_reg_of(ir::Reg::Rsp)] = init_rsp;   // v4 = Rsp
    entry(&ctx);
    return ctx;
}

// ---------------------------------------------------------------------------
// 语义测试组（对一次生成结果完整跑一遍；seed 稳定性复用同一函数）
// ---------------------------------------------------------------------------
void run_semantic_battery(const vm::RuntimeImage& image, const std::string& dump) {
    ASSERT_FALSE(image.code.empty());
    ASSERT_EQ(image.vm_entry_offset, 0u);
    // asm_dump 结构标记（防退化成空生成）。
    EXPECT_NE(dump.find("vm_entry:"), std::string::npos);
    EXPECT_NE(dump.find("dispatch:"), std::string::npos);
    EXPECT_NE(dump.find("codec: none"), std::string::npos);

    RwxImage rwx(image.code);
    const auto entry = rwx.entry();
    alignas(16) std::array<u8, 0x10000> scratch{};

    // 调试：WVMP_ASM_DUMP=<win 路径> 时落盘最终汇编文本。
    char* dp = nullptr;
    size_t dp_len = 0;
    if (_dupenv_s(&dp, &dp_len, "WVMP_ASM_DUMP") == 0 && dp && dp_len > 1) {
        FILE* f = nullptr;
        if (fopen_s(&f, dp, "wb") == 0 && f) {
            std::fwrite(dump.data(), 1, dump.size(), f);
            std::fclose(f);
        }
    }
    std::free(dp);

    // ---- (a) 算术组合：S32 零扩展 + and/or/xor/shl/sub 终值 ----
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0x11223344));            // 0
        isa::append_insn(s, mov_imm(1, 0x100, ir::Size::S32));  // 1
        isa::append_insn(s, bin(isa::VmOp::Add, 0, 1, ir::Size::S32));  // 2
        isa::append_insn(s, mov_imm(2, 0xFF));                  // 3
        isa::append_insn(s, bin(isa::VmOp::And, 0, 2, ir::Size::S64));  // 4
        isa::append_insn(s, mov_imm(3, 0x31));                  // 5
        isa::append_insn(s, bin(isa::VmOp::Or, 0, 3, ir::Size::S64));   // 6
        isa::append_insn(s, bin(isa::VmOp::Xor, 0, 3, ir::Size::S64));  // 7
        isa::append_insn(s, bin_imm(isa::VmOp::Shl, 0, 16, ir::Size::S64));  // 8
        isa::append_insn(s, bin(isa::VmOp::Sub, 0, 2, ir::Size::S64));  // 9
        isa::append_insn(s, halt());                            // 10
        const auto ctx = run_stream(entry, s, scratch.data());
        u64 expect = 0x11223344ull;
        expect = (expect + 0x100) & 0xFFFF'FFFFull;  // S32：零扩展写回
        expect = (expect & 0xFF) | 0x31;             // and + or
        expect ^= 0x31;                              // xor
        expect <<= 16;                               // shl
        expect -= 0xFF;                              // sub
        EXPECT_EQ(ctx.regs[0], expect);
        EXPECT_EQ(ctx.pc, 11u);
    }

    // ---- (b) 子寄存器写合并：S8 add 保高 56 位 + flags 位 ----
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0x11223344));                     // 0
        isa::append_insn(s, bin_imm(isa::VmOp::Shl, 0, 32, ir::Size::S64));  // 1
        isa::append_insn(s, mov_imm(1, 0x55667788));                      // 2
        isa::append_insn(s, bin(isa::VmOp::Or, 0, 1, ir::Size::S64));     // 3
        isa::append_insn(s, mov_imm(1, 0x61));                            // 4
        isa::append_insn(s, bin(isa::VmOp::Add, 0, 1, ir::Size::S8));     // 5
        isa::append_insn(s,
                         isa::make_insn(isa::VmOp::GetFlags, isa::OpKind::Reg, 2,
                                        isa::OpKind::None, 0));           // 6
        isa::append_insn(s, halt());                                      // 7
        const auto ctx = run_stream(entry, s, scratch.data());
        // 低 8 位 0x88+0x61=0xE9（进位丢弃），高 56 位保留。
        EXPECT_EQ(ctx.regs[0], 0x1122'3344'5566'77E9ull);
        // S8 add 的 flags：CF=1（无符号进位）、SF=1（0xE9 bit7）、OF=0、ZF=0、
        // PF=0（0xE9 有 5 个 1，奇）。kFlag 布局：CF=bit1、SF=bit3。
        EXPECT_EQ(ctx.regs[2], (isa::kFlagCF | isa::kFlagSF));
        EXPECT_EQ(ctx.regs[17] & isa::kFlagsMask, (isa::kFlagCF | isa::kFlagSF));
    }

    // ---- (c) flags + jcc：两路终值 ----
    {
        // E 取：cmp 5,5 → ZF=1 → jcc E 跳过赋值。
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 5));
        isa::append_insn(s, mov_imm(1, 5));
        isa::append_insn(s, bin(isa::VmOp::Cmp, 0, 1, ir::Size::S32));  // 2
        isa::append_insn(s, jcc(ir::Cond::E, 2));                       // 3 → 5
        isa::append_insn(s, mov_imm(2, 222));                           // 4
        isa::append_insn(s, halt());                                    // 5
        EXPECT_EQ(run_stream(entry, s, scratch.data()).regs[2], 0u);

        // Ne 取：同程序换 Ne → 赋值执行。
        s.clear();
        isa::append_insn(s, mov_imm(0, 5));
        isa::append_insn(s, mov_imm(1, 5));
        isa::append_insn(s, bin(isa::VmOp::Cmp, 0, 1, ir::Size::S32));
        isa::append_insn(s, jcc(ir::Cond::Ne, 2));
        isa::append_insn(s, mov_imm(2, 222));
        isa::append_insn(s, halt());
        EXPECT_EQ(run_stream(entry, s, scratch.data()).regs[2], 222u);

        // L（有符号小于，32 位）：0xFFFFFFFD(-3) < 1 → 取。
        s.clear();
        isa::append_insn(s, mov_imm(0, 0xFFFFFFFD, ir::Size::S32));
        isa::append_insn(s, mov_imm(1, 1, ir::Size::S32));
        isa::append_insn(s, bin(isa::VmOp::Cmp, 0, 1, ir::Size::S32));
        isa::append_insn(s, jcc(ir::Cond::L, 2));
        isa::append_insn(s, mov_imm(2, 222));
        isa::append_insn(s, halt());
        EXPECT_EQ(run_stream(entry, s, scratch.data()).regs[2], 0u);

        // G（有符号大于）：1 > -3 → 取。
        s.clear();
        isa::append_insn(s, mov_imm(0, 1, ir::Size::S32));
        isa::append_insn(s, mov_imm(1, 0xFFFFFFFD, ir::Size::S32));
        isa::append_insn(s, bin(isa::VmOp::Cmp, 0, 1, ir::Size::S32));
        isa::append_insn(s, jcc(ir::Cond::G, 2));
        isa::append_insn(s, mov_imm(2, 222));
        isa::append_insn(s, halt());
        EXPECT_EQ(run_stream(entry, s, scratch.data()).regs[2], 0u);

        // L 在相等时不取。
        s.clear();
        isa::append_insn(s, mov_imm(0, 7));
        isa::append_insn(s, mov_imm(1, 7));
        isa::append_insn(s, bin(isa::VmOp::Cmp, 0, 1, ir::Size::S64));
        isa::append_insn(s, jcc(ir::Cond::L, 2));
        isa::append_insn(s, mov_imm(2, 222));
        isa::append_insn(s, halt());
        EXPECT_EQ(run_stream(entry, s, scratch.data()).regs[2], 222u);
    }

    // ---- (d) 循环：jne 回跳求和 1..10 ----
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0));                    // 0
        isa::append_insn(s, mov_imm(1, 10));                   // 1
        isa::append_insn(s, bin(isa::VmOp::Add, 0, 1, ir::Size::S64));  // 2 循环头
        isa::append_insn(s, bin(isa::VmOp::Dec, 1, 1, ir::Size::S64));  // 3
        isa::append_insn(s, jcc(ir::Cond::Ne, u32(-2)));       // 4 → 回 2
        isa::append_insn(s, halt());                           // 5
        const auto ctx = run_stream(entry, s, scratch.data());
        EXPECT_EQ(ctx.regs[0], 55u);
        EXPECT_EQ(ctx.regs[1], 0u);
        EXPECT_EQ(ctx.pc, 5u);
    }

    // ---- (e) Load/Store：经 scratch_mem，Size 缩放 ----
    {
        scratch.fill(0);
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(5, 0x10));                            // 0
        isa::append_insn(s, mov_imm(6, 0xABCD1234));                      // 1
        isa::append_insn(s, store(5, 6, ir::Size::S32));                  // 2 → +0x10
        isa::append_insn(s, load(7, 5, ir::Size::S32));                   // 3
        isa::append_insn(s, load(8, 5, ir::Size::S8));                    // 4
        isa::append_insn(s, mov_imm(9, 0x11));                            // 5
        isa::append_insn(s, store(9, 6, ir::Size::S8));                   // 6 → +0x11
        isa::append_insn(s, halt());                                      // 7
        const auto ctx = run_stream(entry, s, scratch.data());
        EXPECT_EQ(ctx.regs[7], 0xABCD1234ull);
        EXPECT_EQ(ctx.regs[8], 0x34ull);
        // LE：S32 存 0xABCD1234 → 34 12 CD AB；S8 存低字节覆盖 +0x11 仍为 0x34。
        EXPECT_EQ(scratch[0x10], 0x34);
        EXPECT_EQ(scratch[0x11], 0x34);
        EXPECT_EQ(scratch[0x12], 0xCD);
        EXPECT_EQ(scratch[0x13], 0xAB);
        EXPECT_EQ(scratch[0x14], 0);
    }

    // ---- (f) Push/Pop：v4=Rsp 递减/递增、LIFO ----
    {
        scratch.fill(0);
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(1, 0xAA));
        isa::append_insn(s, mov_imm(2, 0xBB));
        isa::append_insn(s, isa::make_insn(isa::VmOp::Push, isa::OpKind::Reg, 1,
                                           isa::OpKind::None, 0));
        isa::append_insn(s, isa::make_insn(isa::VmOp::Push, isa::OpKind::Reg, 2,
                                           isa::OpKind::None, 0));
        isa::append_insn(s, isa::make_insn(isa::VmOp::Pop, isa::OpKind::Reg, 3,
                                           isa::OpKind::None, 0));
        isa::append_insn(s, isa::make_insn(isa::VmOp::Pop, isa::OpKind::Reg, 4,
                                           isa::OpKind::None, 0));
        isa::append_insn(s, halt());
        const auto ctx = run_stream(entry, s, scratch.data(), 0x800);
        EXPECT_EQ(ctx.regs[3], 0xBBull);   // LIFO：后进先出
        EXPECT_EQ(ctx.regs[4], 0xAAull);
        EXPECT_EQ(ctx.regs[isa::vm_reg_of(ir::Reg::Rsp)], 0x800ull);   // 栈回原位
        EXPECT_EQ(*reinterpret_cast<u64*>(&scratch[0x800 - 8]), 0xAAull);
        EXPECT_EQ(*reinterpret_cast<u64*>(&scratch[0x800 - 16]), 0xBBull);
    }

    // ---- (h) Test/GetFlags/SetFlags 位布局 ----
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0xF0));                            // 0
        isa::append_insn(s, bin(isa::VmOp::Test, 0, 0, ir::Size::S8));    // 1
        isa::append_insn(s, isa::make_insn(isa::VmOp::GetFlags, isa::OpKind::Reg, 5,
                                           isa::OpKind::None, 0));        // 2
        isa::append_insn(s, mov_imm(6, 0x1F));                            // 3
        isa::append_insn(s, isa::make_insn(isa::VmOp::SetFlags, isa::OpKind::Reg, 6,
                                           isa::OpKind::None, 0));        // 4
        isa::append_insn(s, isa::make_insn(isa::VmOp::GetFlags, isa::OpKind::Reg, 7,
                                           isa::OpKind::None, 0));        // 5
        isa::append_insn(s, halt());                                      // 6
        const auto ctx = run_stream(entry, s, scratch.data());
        // test 0xF0,0xF0（8 位）：ZF=0、SF=1、PF=1（4 个 1，偶）、CF=OF=0。
        EXPECT_EQ(ctx.regs[5], (isa::kFlagSF | isa::kFlagPF));
        EXPECT_EQ(ctx.regs[7], isa::kFlagsMask);
        EXPECT_EQ(ctx.regs[17] & isa::kFlagsMask, isa::kFlagsMask);
    }

    // ---- (g) Halt 返回路径 + callee-saved 现场保持 + ret_value/pc ----
    {
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 77));
        isa::append_insn(s, halt());

        // driver(store=RCX, vmentry=RDX, ctx=R8)：预置 callee-saved 魔数、
        // 调 VM 入口、回读 8 个寄存器 → store[0..8)。
        const std::string driver_asm =
            "push rcx\n"
            "mov rbx, 0x1111111111111111\n"
            "mov rbp, 0x2222222222222222\n"
            "mov r12, 0x3333333333333333\n"
            "mov r13, 0x4444444444444444\n"
            "mov r14, 0x5555555555555555\n"
            "mov r15, 0x6666666666666666\n"
            "mov rdi, 0x7777777777777777\n"
            "mov rsi, 0x8888888888888888\n"
            "mov rcx, r8\n"
            "call rdx\n"
            "pop rcx\n"
            "mov [rcx], rbx\n"
            "mov [rcx+8], rbp\n"
            "mov [rcx+16], r12\n"
            "mov [rcx+24], r13\n"
            "mov [rcx+32], r14\n"
            "mov [rcx+40], r15\n"
            "mov [rcx+48], rdi\n"
            "mov [rcx+56], rsi\n"
            "ret\n";
        RwxImage driver(assemble_or_throw(driver_asm));
        using DriverFn = void (*)(u64*, void*, void*);
        const auto drv = reinterpret_cast<DriverFn>(driver.entry());

        rt::VmContext ctx;
        ctx.bytecode = s.data();
        ctx.pc = 0;
        ctx.scratch_mem = reinterpret_cast<u64>(scratch.data());
        alignas(16) std::array<u64, 8> store{};
        drv(store.data(), rwx.entry(), &ctx);

        static const u64 kMagics[8] = {0x1111111111111111ull, 0x2222222222222222ull,
                                       0x3333333333333333ull, 0x4444444444444444ull,
                                       0x5555555555555555ull, 0x6666666666666666ull,
                                       0x7777777777777777ull, 0x8888888888888888ull};
        for (int i = 0; i < 8; ++i)
            EXPECT_EQ(store[i], kMagics[i]) << "callee-saved reg slot " << i;
        EXPECT_EQ(ctx.ret_value, 77u);   // regs[v0] 写回
        EXPECT_EQ(ctx.pc, 2u);           // Halt 写回停机指令序号
    }
}

} // namespace

// ---------------------------------------------------------------------------
// 测试入口
// ---------------------------------------------------------------------------
TEST(Interpreter, SemanticBattery) {
    wvmp::Rng rng(0xC0FFEE);
    const auto result = rt::generate_runtime(rng);
    ASSERT_NO_FATAL_FAILURE(run_semantic_battery(result.image, result.asm_dump));
}

TEST(Interpreter, FiveSeedStability) {
    // 不同种子的寄存器随机化重生成必须全部语义正确。
    for (u64 seed : {1ull, 2ull, 3ull, 4ull, 5ull}) {
        wvmp::Rng rng(seed);
        const auto result = rt::generate_runtime(rng);
        ASSERT_NO_FATAL_FAILURE(run_semantic_battery(result.image, result.asm_dump))
            << "seed " << seed;
    }
}

TEST(Interpreter, AsmDumpStructure) {
    wvmp::Rng rng(0xABCDEF);
    const auto result = rt::generate_runtime(rng);
    EXPECT_FALSE(result.asm_dump.empty());
    // 跳转表必须存在且码尺寸 = 表偏移 + 64*8（布局自洽）。
    const size_t total = result.image.code.size();
    EXPECT_GT(total, size_t(512 + 64 * 8));   // 25 个 handler 不可能小于此
    EXPECT_EQ(total % 8, 0u);                 // 表尾 8 对齐 → 总长 8 的倍数
}
