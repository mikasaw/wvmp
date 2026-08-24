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

// 调试期：禁 WER 弹窗，崩溃直接以退出码显形（排查 g 段疑似 AV）。
struct DisableWerBox { DisableWerBox() { ::SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX); } };
static const DisableWerBox kNoWerBox;

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
// mov_imm64：拆条生成 64-bit 立即数（与 translator 一致: hi 写入 scratch /
// Shl 32 / Mov lo / Or）. scratch 是中间高 32 位寄存器, 不能与 dst 冲突.
void mov_imm64_into(std::vector<u8>& s, u8 dst, u8 scratch_reg, u64 imm) {
    const u8 sz = isa::size_field(ir::Size::S64);
    isa::append_insn(s, isa::make_insn(isa::VmOp::Mov, isa::OpKind::Reg, scratch_reg,
                                       isa::OpKind::Imm, 0,
                                       static_cast<u32>(imm >> 32), sz));
    isa::append_insn(s, isa::make_insn(isa::VmOp::Shl, isa::OpKind::Reg, scratch_reg,
                                       isa::OpKind::Imm, 0, 32, sz));
    isa::append_insn(s, isa::make_insn(isa::VmOp::Mov, isa::OpKind::Reg, dst, isa::OpKind::Imm,
                                       0, static_cast<u32>(imm & 0xFFFFFFFFu), sz));
    isa::append_insn(s, isa::make_insn(isa::VmOp::Or, isa::OpKind::Reg, dst,
                                       isa::OpKind::Reg, scratch_reg, 0, sz));
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
// M2-8 起：scratch_mem 不再设默认值——Load/Store 直接用绝对 VA 寻址，
// 不再加 scratch_mem；LoadRva/StoreRva 才加。测试按需自行 ctx.scratch_mem = ...
rt::VmContext run_stream(RwxImage::Entry entry, const std::vector<u8>& stream, u8* scratch,
                         u64 init_rsp = 0) {
    rt::VmContext ctx;
    ctx.bytecode = const_cast<u8*>(stream.data());
    ctx.pc = 0;
    ctx.scratch_mem = 0;  // Load/Store 直接用绝对 VA；调用方按需覆写（LoadRva）
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
        // 低 8 位 0x88+0x61=0xE9=233<256，无进位：CF=0（原期望 CF=1 是算错——
        // 233 未超 255）；SF=1（0xE9 bit7）、OF=0（-120+97=-23 不溢出）、ZF=0、
        // PF=0（0xE9 有 5 个 1，奇）。kFlag 布局：CF=bit1、SF=bit3 → 仅 SF。
        EXPECT_EQ(ctx.regs[2], isa::kFlagSF);
        EXPECT_EQ(ctx.regs[17] & isa::kFlagsMask, isa::kFlagSF);
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
        EXPECT_EQ(ctx.pc, 6u);   // halt+1 语义：pc 指向 halt 之后
    }

    // ---- (e) Load/Store：M2-8 直接对绝对地址访存；addr reg 持绝对 VA ----
    //   Load/Store 不再加 scratch_mem；addr reg 由 mov_imm64_into 装入 scratch 绝对
    //   地址. 此用例无 sub/sbb 等 flag 依赖, mov_imm64_into 的 Shl 副作用可接受.
    {
        scratch.fill(0);
        const u64 data_addr = reinterpret_cast<u64>(scratch.data()) + 0x10;
        std::vector<u8> s;
        mov_imm64_into(s, /*dst*/5, /*scratch*/isa::kScratchFirst, data_addr);  // 0..3
        isa::append_insn(s, mov_imm(6, 0xABCD1234));                      // 4
        isa::append_insn(s, store(5, 6, ir::Size::S32));                  // 5 → scratch[0x10]
        isa::append_insn(s, load(7, 5, ir::Size::S32));                   // 6
        isa::append_insn(s, load(8, 5, ir::Size::S8));                    // 7
        mov_imm64_into(s, /*dst*/9, /*scratch*/isa::kScratchFirst + 1, data_addr + 1);  // 8..11
        isa::append_insn(s, store(9, 6, ir::Size::S8));                   // 12 → +0x11
        isa::append_insn(s, halt());                                      // 13
        const auto ctx = run_stream(entry, s, scratch.data());
        EXPECT_EQ(ctx.regs[7], 0xABCD1234ull);
        EXPECT_EQ(ctx.regs[8], 0x34ull);
        // LE：S32 存 0xABCD1234 → 34 12 CD AB；S8 存低字节覆盖 +0x11 仍为 0x34。
        EXPECT_EQ(scratch[0x10], 0x34);
        EXPECT_EQ(scratch[0x11], 0x34);
        EXPECT_EQ(scratch[0x12], 0xCD);
        EXPECT_EQ(scratch[0x13], 0xAB);
        EXPECT_EQ(scratch[0x14], 0);
        EXPECT_EQ(ctx.pc, 14u);
    }

    // ---- (e2) M2-8: LoadRva/StoreRva 走 scratch_mem=image_base 加基址还原 VA ----
    //   翻译期算的 RVA 进 reg[T1]; 实际 VA = RVA + scratch_mem. 把数据预置到
    //   scratch + 0x8000 + RVA (模拟真实进程 VA 布局), 验证 LoadRva/StoreRva 真的
    //   加 [CTX+0x110].
    {
        scratch.fill(0);
        constexpr u64 kImageBase = 0x8000;  // 模拟 image_base
        scratch[0x8010] = 0x34; scratch[0x8011] = 0x12;
        scratch[0x8012] = 0xCD; scratch[0x8013] = 0xAB;
        std::vector<u8> s;
        // RVA 0x10 → scratch_mem + 0x10 = scratch+0x8010
        isa::append_insn(s, mov_imm(5, 0x10));                          // 0: RVA
        isa::append_insn(s, isa::make_insn(isa::VmOp::LoadRva, isa::OpKind::Reg, 7,
                                           isa::OpKind::Reg, 5, 0,
                                           isa::size_field(ir::Size::S32)));  // 1
        isa::append_insn(s, mov_imm(6, 0xCAFEBABEul));                   // 2
        isa::append_insn(s, isa::make_insn(isa::VmOp::StoreRva, isa::OpKind::Reg, 5,
                                           isa::OpKind::Reg, 6, 0,
                                           isa::size_field(ir::Size::S32)));  // 3
        isa::append_insn(s, isa::make_insn(isa::VmOp::LoadRva, isa::OpKind::Reg, 8,
                                           isa::OpKind::Reg, 5, 0,
                                           isa::size_field(ir::Size::S32)));  // 4
        isa::append_insn(s, halt());                                    // 5
        rt::VmContext ctx;
        ctx.bytecode = s.data();
        ctx.pc = 0;
        ctx.scratch_mem = reinterpret_cast<u64>(scratch.data()) + kImageBase;
        entry(&ctx);
        // LoadRva: RVA 0x10 + image_base 0x8000 = scratch+0x8010 → 0xABCD1234
        EXPECT_EQ(ctx.regs[7], 0xABCD1234ull);
        // StoreRva: scratch[0x8010..0x8014] = 0xCAFEBABE
        EXPECT_EQ(scratch[0x8010], 0xBE); EXPECT_EQ(scratch[0x8011], 0xBA);
        EXPECT_EQ(scratch[0x8012], 0xFE); EXPECT_EQ(scratch[0x8013], 0xCA);
        // LoadRva 回读
        EXPECT_EQ(ctx.regs[8], 0xCAFEBABEull);
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
        isa::append_insn(s, // 弹出目的用 v10：v4 是 Rsp 槽位，弹入 v4 会覆盖栈指针（原测试自摆乌龙）。
        isa::make_insn(isa::VmOp::Pop, isa::OpKind::Reg, 10,
                                           isa::OpKind::None, 0));
        isa::append_insn(s, halt());
        // M2-8 起 Push/Pop 不再加 scratch_mem, rsp 即 host 栈地址。把 init_rsp
        // 设到 scratch.data() + 0x800, 让 push/pop 写入 scratch 内部.
        const u64 init_rsp = reinterpret_cast<u64>(scratch.data()) + 0x800;
        const auto ctx = run_stream(entry, s, scratch.data(), init_rsp);
        EXPECT_EQ(ctx.regs[3], 0xBBull);   // LIFO：后进先出
        EXPECT_EQ(ctx.regs[10], 0xAAull);
        EXPECT_EQ(ctx.regs[isa::vm_reg_of(ir::Reg::Rsp)], init_rsp);   // 栈回原位
        EXPECT_EQ(*reinterpret_cast<u64*>(init_rsp - 8), 0xAAull);
        EXPECT_EQ(*reinterpret_cast<u64*>(init_rsp - 16), 0xBBull);
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
            // 位移必须 0x 前缀：keystone Intel 裸数字按 16 进制解析（16→0x16=22），
            // 错位写穿 store 数组（slot2-7 全坏而 0/1 幸存的根因）。
            "mov [rcx], rbx\n"
            "mov [rcx+8], rbp\n"
            "mov [rcx+0x10], r12\n"
            "mov [rcx+0x18], r13\n"
            "mov [rcx+0x20], r14\n"
            "mov [rcx+0x28], r15\n"
            "mov [rcx+0x30], rdi\n"
            "mov [rcx+0x38], rsi\n"
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

    // ---- (i) Sar：算术右移、符号扩展、CF 末位移出、count=0 no-op ----
    // Sar 语义要点（x86）：
    //   - 算术右移：高位补符号位
    //   - CF = 末位移出位（pre-shift bit[count-1]）；count==0 不动 flags
    //   - OF = 0（count==1 时）；count>=2 时 OF 未定义，CPU 仍写一个值，本实现照样捕获
    //   - SF/ZF/PF = 结果的低位/全 0/低 8 奇偶
    // 任意 count>=64 都按 x86 规范被 AND 0x3F 掩成 0..63；count=0 整条 no-op。
    {
        // (i.1) 正值 S64：基本右移（imm 限于 u32，取 256 → sar 4 = 16）
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0x100u));
        isa::append_insn(s, bin_imm(isa::VmOp::Sar, 0, 4, ir::Size::S64));
        isa::append_insn(s, halt());
        const auto ctx = run_stream(entry, s, scratch.data());
        EXPECT_EQ(ctx.regs[0], 0x10ull);
        EXPECT_EQ(ctx.pc, 3u);

        // (i.2) 负值 S64：符号扩展。构造 -16 = 0 - 16, 然后 sar 2 = -4 = 0xFFFFFFFFFFFFFFFC
        s.clear();
        isa::append_insn(s, mov_imm(0, 0));                  // v0 = 0
        isa::append_insn(s, mov_imm(1, 16));                 // v1 = 16
        isa::append_insn(s, bin(isa::VmOp::Sub, 0, 1, ir::Size::S64));  // v0 = -16
        isa::append_insn(s, bin_imm(isa::VmOp::Sar, 0, 2, ir::Size::S64));  // sar 2 → -4
        isa::append_insn(s, halt());
        EXPECT_EQ(run_stream(entry, s, scratch.data()).regs[0], u64(-4));

        // (i.3) CF = bit shifted out（count=1 时即原 LSB）：
        // -1 sar 1 → -1, CF=1（LSB=1 被移出）, SF=1
        s.clear();
        isa::append_insn(s, mov_imm(0, 0));
        isa::append_insn(s, mov_imm(1, 1));
        isa::append_insn(s, bin(isa::VmOp::Sub, 0, 1, ir::Size::S64));  // v0 = -1
        isa::append_insn(s, mov_imm(2, 0));
        isa::append_insn(s, isa::make_insn(isa::VmOp::SetFlags,
                                           isa::OpKind::Reg, 2, isa::OpKind::None, 0));
        isa::append_insn(s, bin_imm(isa::VmOp::Sar, 0, 1, ir::Size::S64));
        isa::append_insn(s, isa::make_insn(isa::VmOp::GetFlags,
                                           isa::OpKind::Reg, 3, isa::OpKind::None, 0));
        isa::append_insn(s, halt());
        const auto ctx3 = run_stream(entry, s, scratch.data());
        EXPECT_EQ(ctx3.regs[0], 0xFFFF'FFFF'FFFF'FFFFull);
        EXPECT_EQ(ctx3.regs[3] & isa::kFlagCF, isa::kFlagCF);
        EXPECT_EQ(ctx3.regs[3] & isa::kFlagSF, isa::kFlagSF);
        EXPECT_EQ(ctx3.regs[3] & isa::kFlagZF, 0u);

        // (i.4) count=0 no-op（值/flags 均不变——通过 adv_lbl 跳转验证）
        s.clear();
        isa::append_insn(s, mov_imm(0, 0x12345u));
        isa::append_insn(s, mov_imm(2, u32(isa::kFlagCF | isa::kFlagSF)));
        isa::append_insn(s, isa::make_insn(isa::VmOp::SetFlags,
                                           isa::OpKind::Reg, 2, isa::OpKind::None, 0));
        isa::append_insn(s, bin_imm(isa::VmOp::Sar, 0, 0, ir::Size::S64));
        isa::append_insn(s, isa::make_insn(isa::VmOp::GetFlags,
                                           isa::OpKind::Reg, 3, isa::OpKind::None, 0));
        isa::append_insn(s, halt());
        const auto ctx4 = run_stream(entry, s, scratch.data());
        EXPECT_EQ(ctx4.regs[0], 0x12345ull);
        EXPECT_EQ(ctx4.regs[3] & isa::kFlagsMask,
                  u64(isa::kFlagCF | isa::kFlagSF));

        // (i.5) S32 算术扩展：高 32 位保留不变, 低 32 位算术右移 + S32 内符号扩展
        // 0x80000000 在 S32 下是 INT32_MIN；先写到 v0 全 64 位（高 32=0），S32 sar 4
        // 后低 32 = 0xF8000000，高 32 仍为 0（i.e., 全 64 位 = 0x00000000F8000000）
        s.clear();
        isa::append_insn(s, mov_imm(0, 0x80000000u, ir::Size::S32));
        isa::append_insn(s, bin_imm(isa::VmOp::Sar, 0, 4, ir::Size::S32));
        isa::append_insn(s, halt());
        EXPECT_EQ(run_stream(entry, s, scratch.data()).regs[0],
                  0xF8000000ull);

        // (i.6) S64 大位移：负值右移 60 位仍全符号填充（-2 sar 60 = -1）
        // 构造 -2 = 0 - 2: mov v0, 0; sub v0, 2; sar v0, 60
        s.clear();
        isa::append_insn(s, mov_imm(0, 0));
        isa::append_insn(s, mov_imm(1, 2));
        isa::append_insn(s, bin(isa::VmOp::Sub, 0, 1, ir::Size::S64));  // v0 = -2
        isa::append_insn(s, bin_imm(isa::VmOp::Sar, 0, 60, ir::Size::S64));
        isa::append_insn(s, halt());
        EXPECT_EQ(run_stream(entry, s, scratch.data()).regs[0],
                  0xFFFF'FFFF'FFFF'FFFFull);
    }

    // ---- (j) Adc：带 CF_in 的全加（含 carry 链、signed overflow、size 变体） ----
    // Adc 语义要点（Intel SDM Vol. 2 ADC）：
    //   - dst = dst + src + CF_in（CF_in 必须真实参与计算）
    //   - CF = 全加最高位 carry-out
    //   - OF = 仅当两操作数符号同且结果符号异（signed overflow 顶端）
    //   - SF/ZF/PF = 结果 MSB / 全 0 / 低 8 偶校验
    //   - flags 全量由 setcc5 捕 host CPU 真值
    // 关键 catch 路径：build_binary 的 zero5() 用 xor 清 CF；build_adc 必须在
    // zero5 前把 CF_in 读到 T3，zero5 后用 `bt T3, 0` 还原宿主 CF。
    {
        // (j.1) S64, CF_in=0：基本 0x10 + 0x20 = 0x30, CF=0, SF=ZF=0
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0x10));
        isa::append_insn(s, mov_imm(1, 0x20));
        isa::append_insn(s, mov_imm(2, 0));    // CF=0
        isa::append_insn(s, isa::make_insn(isa::VmOp::SetFlags,
                                           isa::OpKind::Reg, 2, isa::OpKind::None, 0));
        isa::append_insn(s, bin(isa::VmOp::Adc, 0, 1, ir::Size::S64));
        isa::append_insn(s, isa::make_insn(isa::VmOp::GetFlags,
                                           isa::OpKind::Reg, 3, isa::OpKind::None, 0));
        isa::append_insn(s, halt());
        const auto ctx = run_stream(entry, s, scratch.data());
        EXPECT_EQ(ctx.regs[0], 0x30ull);
        EXPECT_EQ(ctx.regs[3] & isa::kFlagCF, 0u);
        EXPECT_EQ(ctx.regs[3] & isa::kFlagZF, 0u);
        EXPECT_EQ(ctx.regs[3] & isa::kFlagSF, 0u);

        // (j.2) S64, CF_in=1：基本 0x10 + 0x20 + 1 = 0x31, CF=0（无进位）
        s.clear();
        isa::append_insn(s, mov_imm(0, 0x10));
        isa::append_insn(s, mov_imm(1, 0x20));
        isa::append_insn(s, mov_imm(2, u32(isa::kFlagCF)));    // CF=1
        isa::append_insn(s, isa::make_insn(isa::VmOp::SetFlags,
                                           isa::OpKind::Reg, 2, isa::OpKind::None, 0));
        isa::append_insn(s, bin(isa::VmOp::Adc, 0, 1, ir::Size::S64));
        isa::append_insn(s, isa::make_insn(isa::VmOp::GetFlags,
                                           isa::OpKind::Reg, 3, isa::OpKind::None, 0));
        isa::append_insn(s, halt());
        const auto ctx2 = run_stream(entry, s, scratch.data());
        EXPECT_EQ(ctx2.regs[0], 0x31ull);
        EXPECT_EQ(ctx2.regs[3] & isa::kFlagCF, 0u);

        // (j.3) S64 carry, CF_in=0：-1 + 1 = 0, CF=1（典型 64-bit 进位）
        // 用 sub 构造 -1（sub CF 路径不影响本测试，因显式 SetFlags 覆盖）
        s.clear();
        isa::append_insn(s, mov_imm(0, 0));                     // v0 = 0
        isa::append_insn(s, mov_imm(1, 1));                     // v1 = 1
        isa::append_insn(s, bin(isa::VmOp::Sub, 0, 1, ir::Size::S64));  // v0 = -1
        isa::append_insn(s, mov_imm(2, 0));                     // CF_in=0
        isa::append_insn(s, isa::make_insn(isa::VmOp::SetFlags,
                                           isa::OpKind::Reg, 2, isa::OpKind::None, 0));
        isa::append_insn(s, mov_imm(1, 1));                     // v1 = 1
        isa::append_insn(s, bin(isa::VmOp::Adc, 0, 1, ir::Size::S64));  // v0 = -1+1+0 = 0, CF=1
        isa::append_insn(s, isa::make_insn(isa::VmOp::GetFlags,
                                           isa::OpKind::Reg, 3, isa::OpKind::None, 0));
        isa::append_insn(s, halt());
        const auto ctx3 = run_stream(entry, s, scratch.data());
        EXPECT_EQ(ctx3.regs[0], 0ull);
        EXPECT_EQ(ctx3.regs[3] & isa::kFlagCF, isa::kFlagCF);

        // (j.4) **CF 链路关键 catch**：-1 + 1 + CF_in(from prev sub borrow)=1 = 1
        // 不显式 SetFlags；让 sub 留下的 CF=1（borrow）作为下一条 adc 的 CF_in。
        // 若 build_adc 把 CF_in 在 zero5 中清零，则退化为 -1 + 1 + 0 = 0。
        s.clear();
        isa::append_insn(s, mov_imm(0, 0));                     // v0 = 0
        isa::append_insn(s, mov_imm(1, 1));                     // v1 = 1
        isa::append_insn(s, bin(isa::VmOp::Sub, 0, 1, ir::Size::S64));  // v0 = -1, CF=1
        isa::append_insn(s, mov_imm(1, 1));                     // v1 = 1
        isa::append_insn(s, bin(isa::VmOp::Adc, 0, 1, ir::Size::S64));  // v0 = -1+1+1 = 1
        isa::append_insn(s, isa::make_insn(isa::VmOp::GetFlags,
                                           isa::OpKind::Reg, 3, isa::OpKind::None, 0));
        isa::append_insn(s, halt());
        const auto ctx4 = run_stream(entry, s, scratch.data());
        // 关键断言：CF_in=1 路径区分。若 CF_in 被 zero5 清零（=0），v0 = 0；正确 v0 = 1
        EXPECT_EQ(ctx4.regs[0], 1ull);

        // (j.5) S32 signed overflow：0x80000000 + 0x80000000 + CF_in=0 = 0 (S32),
        // CF=1 (carry), OF=1 (同负 + 结果正 = signed overflow 顶端)
        s.clear();
        isa::append_insn(s, mov_imm(0, 0x80000000u, ir::Size::S32));
        isa::append_insn(s, mov_imm(1, 0x80000000u, ir::Size::S32));
        isa::append_insn(s, mov_imm(2, 0));
        isa::append_insn(s, isa::make_insn(isa::VmOp::SetFlags,
                                           isa::OpKind::Reg, 2, isa::OpKind::None, 0));
        isa::append_insn(s, bin(isa::VmOp::Adc, 0, 1, ir::Size::S32));
        isa::append_insn(s, isa::make_insn(isa::VmOp::GetFlags,
                                           isa::OpKind::Reg, 3, isa::OpKind::None, 0));
        isa::append_insn(s, halt());
        const auto ctx5 = run_stream(entry, s, scratch.data());
        EXPECT_EQ(ctx5.regs[0], 0ull);                              // S32 truncate
        EXPECT_EQ(ctx5.regs[3] & isa::kFlagCF, isa::kFlagCF);      // CF=1
        EXPECT_EQ(ctx5.regs[3] & isa::kFlagOF, isa::kFlagOF);      // OF=1
        EXPECT_EQ(ctx5.regs[3] & isa::kFlagZF, isa::kFlagZF);      // ZF=1

        // (j.6) S32 unsigned 边界：0xFFFFFFFF + 0x00000001 + CF_in=0 = 0, CF=1, OF=0
        // （异号相加，无 signed overflow；CF=1 表 32-bit carry）
        s.clear();
        isa::append_insn(s, mov_imm(0, 0xFFFFFFFFu, ir::Size::S32));
        isa::append_insn(s, mov_imm(1, 0x00000001u, ir::Size::S32));
        isa::append_insn(s, mov_imm(2, 0));
        isa::append_insn(s, isa::make_insn(isa::VmOp::SetFlags,
                                           isa::OpKind::Reg, 2, isa::OpKind::None, 0));
        isa::append_insn(s, bin(isa::VmOp::Adc, 0, 1, ir::Size::S32));
        isa::append_insn(s, isa::make_insn(isa::VmOp::GetFlags,
                                           isa::OpKind::Reg, 3, isa::OpKind::None, 0));
        isa::append_insn(s, halt());
        const auto ctx6 = run_stream(entry, s, scratch.data());
        EXPECT_EQ(ctx6.regs[0], 0ull);
        EXPECT_EQ(ctx6.regs[3] & isa::kFlagCF, isa::kFlagCF);
        EXPECT_EQ(ctx6.regs[3] & isa::kFlagOF, 0u);               // 异号相加，OF=0
    }

    // ---- (k) Sbb：带 CF_in 的全减（含 borrow 链、signed underflow、size 变体） ----
    // Sbb 语义要点（Intel SDM Vol. 2 SBB）：
    //   - dst = dst - src - CF_in（CF_in 必须真实参与计算）
    //   - CF = 借位 (CF=1 表 borrow 发生, 含义与 add 的 carry **反转**——CF=1 表下溢)
    //   - OF = 仅当两操作数符号**异**且结果符号与 dst 符号**异** (signed underflow
    //         顶端；与 Adc 的"两操作数同号"形成 XOR 对称)
    //   - SF/ZF/PF = 结果 MSB / 全 0 / 低 8 偶校验
    //   - flags 全量由 setcc5 捕 host CPU 真值（native sbb CF_out 直读）
    // 关键 catch 路径：build_binary("sub") 用 zero5 把宿主 CF 清零；build_sbb
    // 必须在 zero5 前/后正确保 CF_in（与 build_adc 同构, 仅 native op 不同）。
    {
        // (k.1) S64, CF_in=0：基本 0x30 - 0x10 - 0 = 0x20, CF=0（无借位）
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0x30));
        isa::append_insn(s, mov_imm(1, 0x10));
        isa::append_insn(s, mov_imm(2, 0));    // CF=0
        isa::append_insn(s, isa::make_insn(isa::VmOp::SetFlags,
                                           isa::OpKind::Reg, 2, isa::OpKind::None, 0));
        isa::append_insn(s, bin(isa::VmOp::Sbb, 0, 1, ir::Size::S64));
        isa::append_insn(s, isa::make_insn(isa::VmOp::GetFlags,
                                           isa::OpKind::Reg, 3, isa::OpKind::None, 0));
        isa::append_insn(s, halt());
        const auto ctx = run_stream(entry, s, scratch.data());
        EXPECT_EQ(ctx.regs[0], 0x20ull);
        EXPECT_EQ(ctx.regs[3] & isa::kFlagCF, 0u);   // 无借位

        // (k.2) S64, CF_in=1：基本 0x30 - 0x10 - 1 = 0x1F, CF=0（仍无借位）
        s.clear();
        isa::append_insn(s, mov_imm(0, 0x30));
        isa::append_insn(s, mov_imm(1, 0x10));
        isa::append_insn(s, mov_imm(2, u32(isa::kFlagCF)));    // CF=1
        isa::append_insn(s, isa::make_insn(isa::VmOp::SetFlags,
                                           isa::OpKind::Reg, 2, isa::OpKind::None, 0));
        isa::append_insn(s, bin(isa::VmOp::Sbb, 0, 1, ir::Size::S64));
        isa::append_insn(s, isa::make_insn(isa::VmOp::GetFlags,
                                           isa::OpKind::Reg, 3, isa::OpKind::None, 0));
        isa::append_insn(s, halt());
        const auto ctx2 = run_stream(entry, s, scratch.data());
        EXPECT_EQ(ctx2.regs[0], 0x1Full);
        EXPECT_EQ(ctx2.regs[3] & isa::kFlagCF, 0u);

        // (k.3) S64 borrow, CF_in=0：0 - 1 - 0 = -1 (0xFFFFFFFFFFFFFFFF), CF=1
        // 典型 64-bit 借位 (unsigned underflow)。
        s.clear();
        isa::append_insn(s, mov_imm(0, 0));                     // v0 = 0
        isa::append_insn(s, mov_imm(1, 1));                     // v1 = 1
        isa::append_insn(s, mov_imm(2, 0));                     // CF_in=0
        isa::append_insn(s, isa::make_insn(isa::VmOp::SetFlags,
                                           isa::OpKind::Reg, 2, isa::OpKind::None, 0));
        isa::append_insn(s, bin(isa::VmOp::Sbb, 0, 1, ir::Size::S64));  // v0 = 0-1-0 = -1, CF=1
        isa::append_insn(s, isa::make_insn(isa::VmOp::GetFlags,
                                           isa::OpKind::Reg, 3, isa::OpKind::None, 0));
        isa::append_insn(s, halt());
        const auto ctx3 = run_stream(entry, s, scratch.data());
        EXPECT_EQ(ctx3.regs[0], 0xFFFF'FFFF'FFFF'FFFFull);
        EXPECT_EQ(ctx3.regs[3] & isa::kFlagCF, isa::kFlagCF);   // 借位发生

        // (k.4) **CF 链路关键 catch**：sub 留下 CF=1 (borrow), 作下一条 sbb 的 CF_in。
        // 0 - 1 - CF_in(from prev sub borrow)=1 = 0 - 1 - 1 = -2 (0xFFFFFFFFFFFFFFFE)
        // 不显式 SetFlags, 让 sub 留下的 CF=1 作为 sbb 的 CF_in。
        // 若 build_sbb 把 CF_in 在 zero5 中清零, 则退化为 0 - 1 - 0 = -1 (0xFFFFFFFFFFFFFFFF)；
        // 而正确值 v0 = 0xFFFFFFFFFFFFFFFE。
        s.clear();
        isa::append_insn(s, mov_imm(0, 0));                     // v0 = 0
        isa::append_insn(s, mov_imm(1, 1));                     // v1 = 1
        isa::append_insn(s, bin(isa::VmOp::Sub, 0, 1, ir::Size::S64));  // v0 = -1, CF=1 (borrow)
        isa::append_insn(s, bin(isa::VmOp::Sbb, 0, 1, ir::Size::S64));  // v0 = -1-1-1 = -3, CF=1
        // 注: v0 经 sub 后已 = 0xFFFFFFFFFFFFFFFF (-1), 再 sbb 0xFFFFFFFFFFFFFFFF - 1 - 1
        //   = 0xFFFFFFFFFFFFFFFD (-3, 单条 sbb 不会 borrow——只是从满值 -2)
        // 关键区分：若 CF_in 被 zero5 清零 (=0), v0 = -1 - 1 - 0 = -2 (0xFFFFFFFFFFFFFFFE)；
        //           正确 v0 = -1 - 1 - 1 = -3 (0xFFFFFFFFFFFFFFFD)。
        isa::append_insn(s, isa::make_insn(isa::VmOp::GetFlags,
                                           isa::OpKind::Reg, 3, isa::OpKind::None, 0));
        isa::append_insn(s, halt());
        const auto ctx4 = run_stream(entry, s, scratch.data());
        // 关键断言：CF_in=1 路径区分
        EXPECT_EQ(ctx4.regs[0], 0xFFFF'FFFF'FFFF'FFFDull);   // -3, CF_in=1 链路正确

        // (k.5) S32 signed underflow：0x80000000 - 0x00000001 - CF_in=0 = 0x7FFFFFFF
        // 0x80000000 - 1 在 unsigned 下 A=0x80000000 ≥ B=1, 不触发 borrow out, CF=0
        // （关键澄清：borrow 仅在 A < B 时出 32-bit 边界；此处借位全程在内部传播, 不出
        // MSB）。但 signed 下从 -2^31 跳到 +2^31-1 跨越整个负→正边界, OF=1。
        // SF=0 (结果 MSB=0), ZF=0。
        s.clear();
        isa::append_insn(s, mov_imm(0, 0x80000000u, ir::Size::S32));
        isa::append_insn(s, mov_imm(1, 0x00000001u, ir::Size::S32));
        isa::append_insn(s, mov_imm(2, 0));
        isa::append_insn(s, isa::make_insn(isa::VmOp::SetFlags,
                                           isa::OpKind::Reg, 2, isa::OpKind::None, 0));
        isa::append_insn(s, bin(isa::VmOp::Sbb, 0, 1, ir::Size::S32));
        isa::append_insn(s, isa::make_insn(isa::VmOp::GetFlags,
                                           isa::OpKind::Reg, 3, isa::OpKind::None, 0));
        isa::append_insn(s, halt());
        const auto ctx5 = run_stream(entry, s, scratch.data());
        EXPECT_EQ(ctx5.regs[0], 0x7FFFFFFFull);                       // S32 truncate
        EXPECT_EQ(ctx5.regs[3] & isa::kFlagCF, 0u);                  // CF=0 (A>=B, 无 borrow out)
        EXPECT_EQ(ctx5.regs[3] & isa::kFlagOF, isa::kFlagOF);        // OF=1 (signed underflow)

        // (k.6) S32 unsigned underflow：0x00000000 - 0x00000001 - CF_in=0 = 0xFFFFFFFF
        // 0 < 1 → borrow out 32-bit, CF=1。符号位 dst=0, src=0（同正）, 结果 MSB=1。
        // SBB OF 公式: (signA XOR signB) AND (signR XOR signA) = 0 AND 1 = 0；
        // 异号 src-dst 不成立, OF=0 (无 signed overflow, 只是 |result| 跨了边界)。
        // SF=1 (结果 MSB=1), ZF=0。
        s.clear();
        isa::append_insn(s, mov_imm(0, 0x00000000u, ir::Size::S32));
        isa::append_insn(s, mov_imm(1, 0x00000001u, ir::Size::S32));
        isa::append_insn(s, mov_imm(2, 0));
        isa::append_insn(s, isa::make_insn(isa::VmOp::SetFlags,
                                           isa::OpKind::Reg, 2, isa::OpKind::None, 0));
        isa::append_insn(s, bin(isa::VmOp::Sbb, 0, 1, ir::Size::S32));
        isa::append_insn(s, isa::make_insn(isa::VmOp::GetFlags,
                                           isa::OpKind::Reg, 3, isa::OpKind::None, 0));
        isa::append_insn(s, halt());
        const auto ctx6 = run_stream(entry, s, scratch.data());
        EXPECT_EQ(ctx6.regs[0], 0xFFFFFFFFull);
        EXPECT_EQ(ctx6.regs[3] & isa::kFlagCF, isa::kFlagCF);        // CF=1 (borrow out)
        EXPECT_EQ(ctx6.regs[3] & isa::kFlagSF, isa::kFlagSF);
        EXPECT_EQ(ctx6.regs[3] & isa::kFlagOF, 0u);                  // OF=0 (同符号减)
    }

    // ---- (l) Rol/Ror：循环移位、CF=循环移出位、count=0 no-op、S32/S64 全循环 ----
    // Rol/Ror 语义要点（Intel SDM Vol. 2 ROL/ROR, felixcloutier.com/x86/rol/ror）：
    //   - 循环移位：无 CF_in 概念（单条指令内闭环）
    //   - CF = 循环移出位 (looped-out bit)
    //   - OF: count==1 时 (CF XOR result MSB) [ROL] / (result bit[N-1] XOR
    //         result bit[N-2]) [ROR]; count>1 时 undefined
    //   - SF/ZF/PF = 按结果
    // 任意 count>=32 (S32) / count>=64 (S64) 都按 x86 规范被 AND 0x1F/0x3F 掩。
    // count=0 整条 no-op（值/flags 都不变）。
    // 本测试段聚焦循环移位的**值**正确性 + count=0 路径 + count=1 OF 边界。
    // 完整 flags 语义（含 SF/ZF/PF 多位组合 + CF 边带验证）由 RolFuzzTenThousand
    // / RorFuzzTenThousand 5 万条 fuzz 承担, 每条都核对 CF=循环移出位 + value。
    {
        // (l.1) ROL S32 by 1：0x80000001 → 0x00000003
        std::vector<u8> s;
        isa::append_insn(s, mov_imm(0, 0x80000001u, ir::Size::S32));
        isa::append_insn(s, bin_imm(isa::VmOp::Rol, 0, 1, ir::Size::S32));
        isa::append_insn(s, halt());
        EXPECT_EQ(run_stream(entry, s, scratch.data()).regs[0], 0x00000003ull);

        // (l.2) ROR S32 by 1：0x80000001 → 0xC0000000
        s.clear();
        isa::append_insn(s, mov_imm(0, 0x80000001u, ir::Size::S32));
        isa::append_insn(s, bin_imm(isa::VmOp::Ror, 0, 1, ir::Size::S32));
        isa::append_insn(s, halt());
        EXPECT_EQ(run_stream(entry, s, scratch.data()).regs[0], 0xC0000000ull);

        // (l.3) ROL count=0 no-op：值不变（flags 不变由 SetFlags+GetFlags 守, 见下）
        s.clear();
        isa::append_insn(s, mov_imm(0, 0x12345u, ir::Size::S32));
        isa::append_insn(s, mov_imm(2, u32(isa::kFlagCF | isa::kFlagSF | isa::kFlagPF)));
        isa::append_insn(s, isa::make_insn(isa::VmOp::SetFlags,
                                           isa::OpKind::Reg, 2, isa::OpKind::None, 0));
        isa::append_insn(s, bin_imm(isa::VmOp::Rol, 0, 0, ir::Size::S32));
        isa::append_insn(s, isa::make_insn(isa::VmOp::GetFlags,
                                           isa::OpKind::Reg, 3, isa::OpKind::None, 0));
        isa::append_insn(s, halt());
        const auto ctx3 = run_stream(entry, s, scratch.data());
        EXPECT_EQ(ctx3.regs[0], 0x12345ull);   // 值不变
        EXPECT_EQ(ctx3.regs[3] & isa::kFlagsMask,
                  u64(isa::kFlagCF | isa::kFlagSF | isa::kFlagPF));   // flags 全保留

        // (l.4) ROR count=0 no-op：值与 flags 均不变
        s.clear();
        isa::append_insn(s, mov_imm(0, 0xABCDu, ir::Size::S32));
        isa::append_insn(s, mov_imm(2, u32(isa::kFlagZF | isa::kFlagOF)));
        isa::append_insn(s, isa::make_insn(isa::VmOp::SetFlags,
                                           isa::OpKind::Reg, 2, isa::OpKind::None, 0));
        isa::append_insn(s, bin_imm(isa::VmOp::Ror, 0, 0, ir::Size::S32));
        isa::append_insn(s, isa::make_insn(isa::VmOp::GetFlags,
                                           isa::OpKind::Reg, 3, isa::OpKind::None, 0));
        isa::append_insn(s, halt());
        const auto ctx4 = run_stream(entry, s, scratch.data());
        EXPECT_EQ(ctx4.regs[0], 0xABCDull);
        EXPECT_EQ(ctx4.regs[3] & isa::kFlagsMask,
                  u64(isa::kFlagZF | isa::kFlagOF));

        // (l.5) ROL S32 by 31 大位移：0x00000001 → 0x80000000
        s.clear();
        isa::append_insn(s, mov_imm(0, 0x00000001u, ir::Size::S32));
        isa::append_insn(s, bin_imm(isa::VmOp::Rol, 0, 31, ir::Size::S32));
        isa::append_insn(s, halt());
        EXPECT_EQ(run_stream(entry, s, scratch.data()).regs[0], 0x80000000ull);

        // (l.6) ROR S32 by 31 大位移：0x00000001 → 0x00000002
        s.clear();
        isa::append_insn(s, mov_imm(0, 0x00000001u, ir::Size::S32));
        isa::append_insn(s, bin_imm(isa::VmOp::Ror, 0, 31, ir::Size::S32));
        isa::append_insn(s, halt());
        EXPECT_EQ(run_stream(entry, s, scratch.data()).regs[0], 0x00000002ull);

        // (l.7) S32 全循环：0x12345678 ROL 4 → 0x23456781
        s.clear();
        isa::append_insn(s, mov_imm(0, 0x12345678u, ir::Size::S32));
        isa::append_insn(s, bin_imm(isa::VmOp::Rol, 0, 4, ir::Size::S32));
        isa::append_insn(s, halt());
        EXPECT_EQ(run_stream(entry, s, scratch.data()).regs[0], 0x23456781ull);

        // (l.8) S32 全循环：0x12345678 ROR 4 → 0x81234567
        s.clear();
        isa::append_insn(s, mov_imm(0, 0x12345678u, ir::Size::S32));
        isa::append_insn(s, bin_imm(isa::VmOp::Ror, 0, 4, ir::Size::S32));
        isa::append_insn(s, halt());
        EXPECT_EQ(run_stream(entry, s, scratch.data()).regs[0], 0x81234567ull);

        // (l.9) ZF=1 边界：0x00000000 ROL 1 → 0x00000000 (全程 0, ZF=1)
        s.clear();
        isa::append_insn(s, mov_imm(0, 0, ir::Size::S32));
        isa::append_insn(s, bin_imm(isa::VmOp::Rol, 0, 1, ir::Size::S32));
        isa::append_insn(s, halt());
        EXPECT_EQ(run_stream(entry, s, scratch.data()).regs[0], 0ull);

        // (l.10) ROR count=1 ZF 边界: 0x00000001 → 0x80000000
        s.clear();
        isa::append_insn(s, mov_imm(0, 0x00000001u, ir::Size::S32));
        isa::append_insn(s, bin_imm(isa::VmOp::Ror, 0, 1, ir::Size::S32));
        isa::append_insn(s, halt());
        EXPECT_EQ(run_stream(entry, s, scratch.data()).regs[0], 0x80000000ull);

        // (l.11) ROL count=1: 0x40000000 → 0x80000000
        s.clear();
        isa::append_insn(s, mov_imm(0, 0x40000000u, ir::Size::S32));
        isa::append_insn(s, bin_imm(isa::VmOp::Rol, 0, 1, ir::Size::S32));
        isa::append_insn(s, halt());
        EXPECT_EQ(run_stream(entry, s, scratch.data()).regs[0], 0x80000000ull);
    }
}

TEST(Interpreter, SbbE2EMirrorChain) {
    // 模拟 MIT-246 E2E 中间操作：sub → store → load → sbb
    // 验证 CF_in 在 Load/Store 链后仍被正确传递。
    // M2-8 起 Load/Store 不再加 scratch_mem, addr reg 必须为绝对 VA；
    // 此用例通过 scratch_mem（=image_base）+ LoadRva 间接用小 RVA,
    // 避免 mov_imm64_into 的 Shl 副作用污染 flags_.
    wvmp::Rng rng(0xC0FFEE);
    const auto result = rt::generate_runtime(rng);
    RwxImage rwx(result.image.code);
    const auto entry = rwx.entry();
    alignas(16) std::array<u8, 0x10000> scratch{};
    // 准备 scratch[0] = 1（模拟 a_hi）
    uint64_t* sp64 = reinterpret_cast<uint64_t*>(scratch.data());
    sp64[0] = 1;  // scratch[0] = 1
    std::vector<u8> s;
    isa::append_insn(s, mov_imm(0, 0));                                // v0 = 0
    isa::append_insn(s, mov_imm(1, 1));                                // v1 = 1
    isa::append_insn(s, bin(isa::VmOp::Sub, 0, 1, ir::Size::S64));     // v0 = -1, CF=1
    // Store + Load 中间操作: RVA=0 经 LoadRva/StoreRva (image_base 加基址)
    isa::append_insn(s, mov_imm(5, 0));                                // v5 = RVA 0
    isa::append_insn(s, isa::make_insn(isa::VmOp::StoreRva, isa::OpKind::Reg, 5,
                                       isa::OpKind::Reg, 0, 0,
                                       isa::size_field(ir::Size::S64)));    // scratch[0] = -1
    isa::append_insn(s, isa::make_insn(isa::VmOp::LoadRva, isa::OpKind::Reg, 0,
                                       isa::OpKind::Reg, 5, 0,
                                       isa::size_field(ir::Size::S64)));    // v0 = -1
    isa::append_insn(s, mov_imm(0, 1));                                // v0 = 1
    isa::append_insn(s, mov_imm(1, 0));                                // v1 = 0
    isa::append_insn(s, bin(isa::VmOp::Sbb, 0, 1, ir::Size::S64));     // v0 = 1 - 0 - CF
    isa::append_insn(s, isa::make_insn(isa::VmOp::GetFlags,
                                       isa::OpKind::Reg, 6, isa::OpKind::None, 0));
    isa::append_insn(s, halt());
    rt::VmContext ctx;
    ctx.bytecode = const_cast<u8*>(s.data());
    ctx.pc = 0;
    ctx.scratch_mem = reinterpret_cast<u64>(scratch.data());  // image_base = scratch
    entry(&ctx);
    // CF_in=1 链路正确: v0 = 1 - 0 - 1 = 0
    EXPECT_EQ(ctx.regs[0], 0ull) << "Sbb lost CF_in across LoadRva/StoreRva (got " << ctx.regs[0] << ")";
    EXPECT_EQ(ctx.regs[6] & isa::kFlagCF, 0u);
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

// MIT-249 follow-up (issue-08): callgate step 5 此前硬编码 r14 寻址
// VmContext 槽位 0xD0..0xE8，依赖 seed=12345 下 ctx_ 寄存器恰好是 pool[0]=r14
// 的"巧合"。修复后用 r64(ctx_)。本测试：
//   (a) 多 seed 生成 runtime 全部成功（防回退偶发崩溃）
//   (b) callgate handler 输出**绝大多数 seed** 不含硬编码 "[r14 + 0xD0"——
//       ctx_ ∈ 14 GPR 池（MIT-299 后缩为 8 个 callee-saved），等概率 →
//       13/14 ≈ 93% (MIT-299 后 7/8 ≈ 88%) seed 应不含。任意一 seed 含
//       "[r14 +" 即视为硬编码回归。
//   (c) MIT-299 起删除 seed=12345 → r14 特定断言：roll() 重写后 seed=12345
//       不再保证 ctx_=r14（callee-saved 池 uniform 取, RNG 状态前移）。
//       改由新单测 CallgateCtxAlwaysCalleeSaved / AsmGenCtxAlwaysCalleeSaved
//       覆盖 "ctx_ 必为 callee-saved" 的不变量。
TEST(Interpreter, CallGateScratchRegisterIndependence) {
    auto extract_callgate = [](const std::string& dump) -> std::string {
        const std::string marker = "handler callgate @ +";
        const auto pos = dump.find(marker);
        if (pos == std::string::npos) return {};
        const auto end_marker = dump.find("; ---- handler", pos + marker.size());
        const auto end = (end_marker != std::string::npos) ? end_marker : dump.size();
        return dump.substr(pos, end - pos);
    };

    // (a)+(b) 扫一批 seed，统计 callgate dump 是否仍含 [r14 + 0xD0]
    int total = 0, with_r14 = 0;
    for (u64 seed : {1ull, 2ull, 3ull, 4ull, 5ull, 6ull, 7ull, 8ull, 9ull, 10ull,
                     100ull, 1000ull, 10000ull, 99999ull, 0xDEADBEEFull,
                     0xCAFEBABEull, 0xC0FFEEull, 0xABCDEFull, 0xBABEF00Dull,
                     0xFEEDFACEull}) {
        wvmp::Rng rng(seed);
        const auto result = rt::generate_runtime(rng);
        ASSERT_FALSE(result.image.code.empty()) << "seed=" << seed << " 码空";
        const std::string cg = extract_callgate(result.asm_dump);
        ASSERT_FALSE(cg.empty()) << "seed=" << seed << " 缺 callgate handler 段";
        if (cg.find("[r14 + 0xD0") != std::string::npos) ++with_r14;
        ++total;
    }
    // 修复后: 任意含 "[r14 + 0xD0" 的 seed 即硬编码回归（ctx_=r14 是 1/14
    // 巧合, MIT-299 后 1/8, 不应影响判断——若**所有** seed 都含, 说明仍
    // 是硬编码字面量）。
    // 期望: 大多数 seed 不含（≈ 13/20，约 65% 仍可能出现，但全含为回归）。
    EXPECT_LT(with_r14, total)
        << "callgate dump 全 seed 都含 [r14 + 0xD0]，疑似硬编码回归";
}

// MIT-299 follow-up (issue-10): 验证 AsmGen::roll() 分配 ctx_ 时
// 永远落在 callee-saved 池里（Win64 ABI：rbx, rbp, rsi, rdi, r12-r15）。
// 否则 callgate step 6 `call t_[0]` 跨 native call 时，callee 按 ABI
// clobber 掉 caller-saved ctx_，step 9-10 用 r64(ctx_) 寻址 VmContext
// 会读到垃圾 → segfault（rc=139 SIGSEGV）。
//
// 验证策略：callgate 步骤 5 把 reserved slots (regs[24..27]) 抬到物理
// rcx/rdx/r8/r9，访问模式必是 `[<ctx_> + 0xD0/D8/E0/E8]`。扫 dump 中
// 哪个 callee-saved 寄存器名 + 0xD0..0xE8 出现 — 该寄存器即为 ctx_。
// （任何 callee-saved 出现即可；若 caller-saved 出现 = 硬编码回归 = 测试失败。）
TEST(Interpreter, AsmGenCtxAlwaysCalleeSaved) {
    auto extract_callgate = [](const std::string& dump) -> std::string {
        const std::string marker = "handler callgate @ +";
        const auto pos = dump.find(marker);
        if (pos == std::string::npos) return {};
        const auto end_marker = dump.find("; ---- handler", pos + marker.size());
        const auto end = (end_marker != std::string::npos) ? end_marker : dump.size();
        return dump.substr(pos, end - pos);
    };
    const std::array<const char*, 8> kCalleeSavedNames = {
        "rbx", "rbp", "rsi", "rdi", "r12", "r13", "r14", "r15"
    };
    const std::array<const char*, 4> kOffsets = {"0xD0", "0xD8", "0xE0", "0xE8"};

    // 跑 50 个不同 seed，每个 seed 验证 ctx_ 落在 callee-saved 池里。
    int total = 0, ok = 0;
    for (u64 seed = 1; seed <= 50; ++seed) {
        wvmp::Rng rng(seed);
        const auto result = rt::generate_runtime(rng);
        const std::string cg = extract_callgate(result.asm_dump);
        ASSERT_FALSE(cg.empty()) << "seed=" << seed << " 缺 callgate handler 段";

        // 找出 dump 中真正作为 ctx_ 使用的寄存器名（任一 callee-saved + 0xD0..0xE8）。
        std::string found_reg;
        for (const auto* name : kCalleeSavedNames) {
            for (const auto* off : kOffsets) {
                if (cg.find(std::string("[") + name + " + " + off + "]")
                    != std::string::npos) {
                    found_reg = name;
                    break;
                }
            }
            if (!found_reg.empty()) break;
        }
        ASSERT_FALSE(found_reg.empty())
            << "seed=" << seed << " callgate 段未找到任何 callee-saved + 0xD0..0xE8";

        // 同时确保无 caller-saved 寄存器被用作 ctx_ (硬编码回归)。
        const std::array<const char*, 7> kCallerSaved = {
            "rax", "rcx", "rdx", "r8", "r9", "r10", "r11"
        };
        std::string caller_reg;
        for (const auto* name : kCallerSaved) {
            for (const auto* off : kOffsets) {
                if (cg.find(std::string("[") + name + " + " + off + "]")
                    != std::string::npos) {
                    caller_reg = name;
                    break;
                }
            }
            if (!caller_reg.empty()) break;
        }
        ++total;
        if (caller_reg.empty()) ++ok;
        EXPECT_TRUE(caller_reg.empty())
            << "seed=" << seed << " callgate 用 caller-saved [" << caller_reg
            << " + 0xD0..0xE8] 寻址 VmContext，跨 native call 会 segfault";
    }
    EXPECT_EQ(ok, total) << "ctx_ 池约束违反 " << (total - ok) << "/" << total;
}

// 升级版 CallGateScratchRegisterIndependence：现在 callgate dump 里
// [reg + 0xD0..0xE8] 必须**总是** callee-saved 寄存器名（任何 seed）。
// 20 seed 覆盖：seed=12345 等。MIT-299 修复后，所有 seed 应一致。
TEST(Interpreter, CallgateCtxAlwaysCalleeSaved) {
    auto extract_callgate = [](const std::string& dump) -> std::string {
        const std::string marker = "handler callgate @ +";
        const auto pos = dump.find(marker);
        if (pos == std::string::npos) return {};
        const auto end_marker = dump.find("; ---- handler", pos + marker.size());
        const auto end = (end_marker != std::string::npos) ? end_marker : dump.size();
        return dump.substr(pos, end - pos);
    };
    // callgate 步骤 5 必须用同一个 ctx_ 寄存器寻址 0xD0..0xE8 四个 slot。
    // 扫 callgate 段，检查所有形如 "[<reg> + 0xD0/D8/E0/E8]" 的引用都用 callee-saved 寄存器名。
    const std::array<const char*, 8> kCalleeSavedNames = {
        "rbx", "rbp", "rsi", "rdi", "r12", "r13", "r14", "r15"
    };
    const std::array<const char*, 4> kOffsets = {"0xD0", "0xD8", "0xE0", "0xE8"};

    int total = 0, ok = 0;
    for (u64 seed : {1ull, 2ull, 3ull, 5ull, 10ull, 12345ull, 99999ull, 0xDEADBEEFull,
                     0xCAFEBABEull, 0xC0FFEEull, 0xABCDEFull, 0xBABEF00Dull,
                     0xFEEDFACEull, 4ull, 6ull, 7ull, 8ull, 100ull,
                     1000ull, 10000ull}) {
        wvmp::Rng rng(seed);
        const auto result = rt::generate_runtime(rng);
        const std::string cg = extract_callgate(result.asm_dump);
        ASSERT_FALSE(cg.empty()) << "seed=" << seed << " 缺 callgate handler 段";
        ++total;
        // 至少应找到一处含 callee-saved 寄存器 + 0xD0..0xE8 的引用。
        bool found_callee = false;
        for (const auto* name : kCalleeSavedNames) {
            for (const auto* off : kOffsets) {
                if (cg.find(std::string("[") + name + " + " + off + "]")
                    != std::string::npos) {
                    found_callee = true;
                    break;
                }
            }
            if (found_callee) break;
        }
        // 同时断言：不含 caller-saved 寄存器名 + 0xD0/D8/E0/E8 的引用。
        const std::array<const char*, 7> kCallerSaved = {
            "rax", "rcx", "rdx", "r8", "r9", "r10", "r11"
        };
        bool found_caller = false;
        std::string found_caller_reg;
        for (const auto* name : kCallerSaved) {
            for (const auto* off : kOffsets) {
                if (cg.find(std::string("[") + name + " + " + off + "]")
                    != std::string::npos) {
                    found_caller = true;
                    found_caller_reg = name;
                    break;
                }
            }
            if (found_caller) break;
        }
        EXPECT_FALSE(found_caller)
            << "seed=" << seed << " callgate 用 caller-saved [" << found_caller_reg
            << " + 0xD0..0xE8] 寻址 VmContext，跨 native call 会 segfault";
        if (found_callee && !found_caller) ++ok;
    }
    EXPECT_EQ(ok, total) << "callgate dump 校验失败 " << (total - ok) << "/" << total;
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

// Sar 真执行 fuzz：1 万条随机 (value, count) → 与 C++ 算术右移参考值逐位比对。
// 覆盖 5 个不同 Rng 种子, 每颗种子跑 10000 次 = 5 万条样本。
// 参考实现严格按 Intel SDM: count=0 不动, count∈[1,63] 算术右移, count≥64 全符号位。
namespace {
// 静态函数定义在 namespace scope 避 MSVC C2267（局部静态函数禁止）。
static u64 ref_sar_64(u64 v, u32 count) {
    if (count >= 64) return (v >> 63) ? ~0ull : 0ull;
    if (count == 0) return v;
    // 算术右移语义：通过 unsigned shift 拼手动符号填充避免 C++17 实现定义。
    const u64 fill = (v >> 63) ? (~0ull << (64 - count)) : 0;
    return (v >> count) | fill;
}
} // namespace

TEST(Interpreter, SarFuzzTenThousand) {
    for (u64 seed : {0xC0FFEEull, 0xBABEF00Dull, 0xDEADBEEFull, 0xCAFEBABEull, 0xFEEDFACEull}) {
        wvmp::Rng rng(seed);
        const auto result = rt::generate_runtime(rng);
        RwxImage rwx(result.image.code);
        const auto entry = rwx.entry();
        alignas(16) std::array<u8, 0x10000> scratch{};
        for (int i = 0; i < 10000; ++i) {
            // 取 u32 输入：mov_imm aux 是 u32，这等价于零扩展到 u64（高 32=0, 符号位=0）。
            // reference 也用同一原始，避免截断/扩展错位。
            const u32 value32 = static_cast<u32>(rng.next());
            const u32 count = static_cast<u32>(rng.uniform(0, 63));
            const u64 value64 = value32;        // zero-extend (matches vm state)
            std::vector<u8> s;
            isa::append_insn(s, mov_imm(0, value32));
            isa::append_insn(s, bin_imm(isa::VmOp::Sar, 0, count, ir::Size::S64));
            isa::append_insn(s, halt());
            const auto ctx = run_stream(entry, s, scratch.data());
            const u64 expected = ref_sar_64(value64, count);
            ASSERT_EQ(ctx.regs[0], expected)
                << "seed=" << std::hex << seed << " iter=" << std::dec << i
                << " val=" << std::hex << value32 << " cnt=" << std::dec << count;
            ASSERT_EQ(ctx.pc, 3u) << "Sar should halt at instruction 3";
        }
    }
}

// Adc 真执行 fuzz：1 万条随机 (a, b, cf_in) → 与 C++ 参考全加 bit-exact 比对，
// 同时验证 CF_out（64-bit 最高位 carry）。覆盖 5 个不同 Rng 种子, 每颗 10000 次
// = 5 万条。a/b 在 u32 范围内零扩展到 u64（与 mov_imm aux u32 限制一致），
// cf_in ∈ {0, 1}。参考实现严格按 Intel SDM ADC：sum = a + b + cf_in, CF=1 iff
// sum > 0xFFFFFFFF（32-bit 进位到高位）。
namespace {
// 静态函数定义在 namespace scope 避 MSVC C2267（局部静态函数禁止）。
struct AdcRef { u64 sum; u64 cf; };
// 参考实现严格按 Intel SDM ADC（u64 全宽）：
//   sum = a + b + cf_in (wrap on u64 overflow)
//   CF = carry out of bit 63 = (sum < a) [wraparound 标记]
// 注意：本 fuzz 用 u32 输入零扩展到 u64（与 mov_imm aux u32 限制一致），
// 32 位值加和最大 0x1FFFFFFFF < 2^64 → CF=0 总是。这是 fuzz 的"安全路径"，
// 测试实现**不该**意外把 CF 置位。CF=1 的 carry 链路场景在语义电池 (j.3-j.6)
// 单独覆盖。
static AdcRef ref_adc(u64 a, u64 b, u64 cf) {
    const u64 sum = a + b + cf;
    const u64 cf_out = (sum < a) ? 1 : 0;
    return {sum, cf_out};
}
} // namespace

TEST(Interpreter, AdcFuzzTenThousand) {
    for (u64 seed : {0xC0FFEEull, 0xBABEF00Dull, 0xDEADBEEFull, 0xCAFEBABEull, 0xFEEDFACEull}) {
        wvmp::Rng rng(seed);
        const auto result = rt::generate_runtime(rng);
        RwxImage rwx(result.image.code);
        const auto entry = rwx.entry();
        alignas(16) std::array<u8, 0x10000> scratch{};
        for (int i = 0; i < 10000; ++i) {
            const u32 a32 = static_cast<u32>(rng.next());
            const u32 b32 = static_cast<u32>(rng.next());
            const u32 cf_in = static_cast<u32>(rng.uniform(0, 1));
            const u64 a64 = a32;          // zero-extend (matches vm state)
            const u64 b64 = b32;
            const u64 cf64 = cf_in;
            std::vector<u8> s;
            isa::append_insn(s, mov_imm(0, a32));
            isa::append_insn(s, mov_imm(1, b32));
            isa::append_insn(s, mov_imm(2, cf_in ? u32(isa::kFlagCF) : 0u));
            isa::append_insn(s, isa::make_insn(isa::VmOp::SetFlags,
                                               isa::OpKind::Reg, 2, isa::OpKind::None, 0));
            isa::append_insn(s, bin(isa::VmOp::Adc, 0, 1, ir::Size::S64));
            isa::append_insn(s, isa::make_insn(isa::VmOp::GetFlags,
                                               isa::OpKind::Reg, 3, isa::OpKind::None, 0));
            isa::append_insn(s, halt());
            const auto ctx = run_stream(entry, s, scratch.data());
            const auto ref = ref_adc(a64, b64, cf64);
            ASSERT_EQ(ctx.regs[0], ref.sum)
                << "seed=" << std::hex << seed << " iter=" << std::dec << i
                << " a=" << std::hex << a32 << " b=" << std::hex << b32
                << " cf_in=" << std::dec << cf_in;
            // CF 标志位（bit 1 = kFlagCF）。v3 & kFlagCF = 0 (CF=0) 或 2 (CF=1)。
            const u64 got_cf = (ctx.regs[3] & isa::kFlagCF) ? 1 : 0;
            ASSERT_EQ(got_cf, ref.cf)
                << "CF mismatch seed=" << std::hex << seed << " iter=" << std::dec << i
                << " a=" << std::hex << a32 << " b=" << std::hex << b32
                << " cf_in=" << std::dec << cf_in;
            ASSERT_EQ(ctx.pc, 7u) << "Adc test stream halts at instruction 7";
        }
    }
}

// Sbb 真执行 fuzz：1 万条随机 (a, b, cf_in) → 与 C++ 参考全减 bit-exact 比对，
// 同时验证 CF_out（CF=1 表 borrow, 64-bit 最高位借位；与 add 反转）。
// 覆盖 5 个不同 Rng 种子, 每颗 10000 次 = 5 万条。a/b 在 u32 范围内零扩展到 u64
//（与 mov_imm aux u32 限制一致），cf_in ∈ {0, 1}。参考实现严格按 Intel SDM SBB：
//   diff = a - b - cf_in (wrap on u64 underflow)
//   CF = borrow = (a < b + cf_in)，与 add 的 CF=carry 含义相反。
// 注意：本 fuzz 用 u32 输入零扩展到 u64（与 mov_imm aux u32 限制一致），
// 32 位值减法最小 0 - 0xFFFFFFFF - 1 = -(0x100000000) > -2^63 → 不触发 u64 underflow，
// CF=0 总是。这是 fuzz 的"安全路径", 测试实现**不该**意外把 CF 置位。
// CF=1 的 borrow 链路场景在语义电池 (k.3-k.6) 单独覆盖。
namespace {
struct SbbRef { u64 diff; u64 cf; };
static SbbRef ref_sbb(u64 a, u64 b, u64 cf) {
    const u64 sub2 = b + cf;
    const u64 diff = a - sub2;
    const u64 cf_out = (a < sub2) ? 1 : 0;
    return {diff, cf_out};
}
} // namespace

// MIT-246 E2E 限制说明（v1 lifter 局限）：
// MSVC 对 _subborrow_u64 第二参数 codegen 包含 `add cl, 0xFF` 桥接（把 0/1
// 转换为 0xFF/0x00 用作 addend），该指令被 lifter 翻译为 VM Add 并触发
// flags_tail, 污染 flags_ 寄存器中的 CF——导致 sub→sbb 链路 CF_in 丢失。
// ADC E2E 凑巧工作（a_lo=0xFFFFFFFFFFFFFFFF 使 0xFFFFFFFFFFFFFFFF+0xFF 回绕
// 触发进位, CF 仍然为 1）；SBB E2E 由于 a_lo=0 + 0xFF = 0xFF 无进位, CF 变成 0,
// 链路失效。修复 C2-Sbb handler 本身正确性已由 unit tests (k.1-k.6 语义电池
// + SbbFuzzTenThousand 5 万条 + SbbE2EMirrorChain Load/Store 链路) 充分覆盖,
// E2E 样本的 v1 lifter 桥接局限属于 M3 扩展 lifter 白名单 (setb/movzx) 的
// 待办, 不在 C2 任务范围。
TEST(Interpreter, SbbFuzzTenThousand) {
    for (u64 seed : {0xC0FFEEull, 0xBABEF00Dull, 0xDEADBEEFull, 0xCAFEBABEull, 0xFEEDFACEull}) {
        wvmp::Rng rng(seed);
        const auto result = rt::generate_runtime(rng);
        RwxImage rwx(result.image.code);
        const auto entry = rwx.entry();
        alignas(16) std::array<u8, 0x10000> scratch{};
        for (int i = 0; i < 10000; ++i) {
            const u32 a32 = static_cast<u32>(rng.next());
            const u32 b32 = static_cast<u32>(rng.next());
            const u32 cf_in = static_cast<u32>(rng.uniform(0, 1));
            const u64 a64 = a32;
            const u64 b64 = b32;
            const u64 cf64 = cf_in;
            std::vector<u8> s;
            isa::append_insn(s, mov_imm(0, a32));
            isa::append_insn(s, mov_imm(1, b32));
            isa::append_insn(s, mov_imm(2, cf_in ? u32(isa::kFlagCF) : 0u));
            isa::append_insn(s, isa::make_insn(isa::VmOp::SetFlags,
                                               isa::OpKind::Reg, 2, isa::OpKind::None, 0));
            isa::append_insn(s, bin(isa::VmOp::Sbb, 0, 1, ir::Size::S64));
            isa::append_insn(s, isa::make_insn(isa::VmOp::GetFlags,
                                               isa::OpKind::Reg, 3, isa::OpKind::None, 0));
            isa::append_insn(s, halt());
            const auto ctx = run_stream(entry, s, scratch.data());
            const auto ref = ref_sbb(a64, b64, cf64);
            ASSERT_EQ(ctx.regs[0], ref.diff)
                << "seed=" << std::hex << seed << " iter=" << std::dec << i
                << " a=" << std::hex << a32 << " b=" << std::hex << b32
                << " cf_in=" << std::dec << cf_in;
            const u64 got_cf = (ctx.regs[3] & isa::kFlagCF) ? 1 : 0;
            ASSERT_EQ(got_cf, ref.cf)
                << "CF mismatch (borrow) seed=" << std::hex << seed << " iter=" << std::dec << i
                << " a=" << std::hex << a32 << " b=" << std::hex << b32
                << " cf_in=" << std::dec << cf_in;
            ASSERT_EQ(ctx.pc, 7u) << "Sbb test stream halts at instruction 7";
        }
    }
}

// Rol/Ror 真执行 fuzz：1 万条随机 (value, count) → 与 C++ 参考循环移位参考
// bit-exact 比对, 同时验证 CF=循环移出位。覆盖 5 个不同 Rng 种子, 每颗
// 种子跑 10000 次 = 5 万条样本。参考实现严格按 Intel SDM 64 位语义
// （本 fuzz 的指令 bin_imm 用 S64, 测试寄存器全宽 64 位 rotate）。
namespace {
// 静态函数定义在 namespace scope 避 MSVC C2267（局部静态函数禁止）。
struct RolRef { u64 value; u64 cf; };
// 参考实现严格按 Intel SDM ROL (u64 全宽):
//   count=0 → value 不变, CF=旧 CF（本 fuzz 验证 CF_out, 不依赖 CF_in）
//   count∈[1,63] → value = ((v << count) | (v >> (64 - count))) (u64 全宽)
//   CF = bit[(64 - count) mod 64] of original v (looped-out bit; 与 SHR 末位
//        carry 不同——ROL 是闭环的对端位)
//   OF: count==1 → (CF XOR result MSB); count!=1 → undefined (本 fuzz 不验)
// 注意：本 fuzz 用 u32 输入零扩展到 u64（与 mov_imm aux u32 限制一致）。
static RolRef ref_rol(u64 v, u32 count) {
    if (count == 0 || count >= 64) return {v, 0};
    const u64 rotated = (v << count) | (v >> (64 - count));
    const u64 cf = (v >> (64 - count)) & 1ull;
    return {rotated, cf};
}
struct RorRef { u64 value; u64 cf; };
// 参考实现严格按 Intel SDM ROR (u64 全宽):
//   count=0 → value 不变, CF=旧 CF（本 fuzz 验证 CF_out, 不依赖 CF_in）
//   count∈[1,63] → value = ((v >> count) | (v << (64 - count))) (u64 全宽)
//   CF = bit[(count - 1) mod 64] of original v (looped-out bit; 从低端移出)
//   OF: count==1 → result bit[63] XOR result bit[62]
// 注意：本 fuzz 用 u32 输入零扩展到 u64（与 mov_imm aux u32 限制一致）。
static RorRef ref_ror(u64 v, u32 count) {
    if (count == 0 || count >= 64) return {v, 0};
    const u64 rotated = (v >> count) | (v << (64 - count));
    const u64 cf = (v >> (count - 1)) & 1ull;
    return {rotated, cf};
}
} // namespace

TEST(Interpreter, RolFuzzTenThousand) {
    for (u64 seed : {0xC0FFEEull, 0xBABEF00Dull, 0xDEADBEEFull, 0xCAFEBABEull, 0xFEEDFACEull}) {
        wvmp::Rng rng(seed);
        const auto result = rt::generate_runtime(rng);
        RwxImage rwx(result.image.code);
        const auto entry = rwx.entry();
        alignas(16) std::array<u8, 0x10000> scratch{};
        for (int i = 0; i < 10000; ++i) {
            const u32 value32 = static_cast<u32>(rng.next());
            const u32 count = static_cast<u32>(rng.uniform(0, 38));  // 包含 count>=32 边界
            const u64 value64 = value32;   // zero-extend (matches vm state)
            std::vector<u8> s;
            isa::append_insn(s, mov_imm(0, value32));
            isa::append_insn(s, bin_imm(isa::VmOp::Rol, 0, count, ir::Size::S64));
            isa::append_insn(s, isa::make_insn(isa::VmOp::GetFlags,
                                               isa::OpKind::Reg, 3, isa::OpKind::None, 0));
            isa::append_insn(s, halt());
            const auto ctx = run_stream(entry, s, scratch.data());
            const auto ref = ref_rol(value64, count);
            ASSERT_EQ(ctx.regs[0], ref.value)
                << "seed=" << std::hex << seed << " iter=" << std::dec << i
                << " val=" << std::hex << value32 << " cnt=" << std::dec << count;
            // CF 标志位（bit 1 = kFlagCF）。
            const u64 got_cf = (ctx.regs[3] & isa::kFlagCF) ? 1 : 0;
            ASSERT_EQ(got_cf, ref.cf)
                << "CF mismatch seed=" << std::hex << seed << " iter=" << std::dec << i
                << " val=" << std::hex << value32 << " cnt=" << std::dec << count;
            ASSERT_EQ(ctx.pc, 4u) << "Rol test stream halts at instruction 4";
        }
    }
}

TEST(Interpreter, RorFuzzTenThousand) {
    for (u64 seed : {0xC0FFEEull, 0xBABEF00Dull, 0xDEADBEEFull, 0xCAFEBABEull, 0xFEEDFACEull}) {
        wvmp::Rng rng(seed);
        const auto result = rt::generate_runtime(rng);
        RwxImage rwx(result.image.code);
        const auto entry = rwx.entry();
        alignas(16) std::array<u8, 0x10000> scratch{};
        for (int i = 0; i < 10000; ++i) {
            const u32 value32 = static_cast<u32>(rng.next());
            const u32 count = static_cast<u32>(rng.uniform(0, 38));  // 包含 count>=32 边界
            const u64 value64 = value32;
            std::vector<u8> s;
            isa::append_insn(s, mov_imm(0, value32));
            isa::append_insn(s, bin_imm(isa::VmOp::Ror, 0, count, ir::Size::S64));
            isa::append_insn(s, isa::make_insn(isa::VmOp::GetFlags,
                                               isa::OpKind::Reg, 3, isa::OpKind::None, 0));
            isa::append_insn(s, halt());
            const auto ctx = run_stream(entry, s, scratch.data());
            const auto ref = ref_ror(value64, count);
            ASSERT_EQ(ctx.regs[0], ref.value)
                << "seed=" << std::hex << seed << " iter=" << std::dec << i
                << " val=" << std::hex << value32 << " cnt=" << std::dec << count;
            const u64 got_cf = (ctx.regs[3] & isa::kFlagCF) ? 1 : 0;
            ASSERT_EQ(got_cf, ref.cf)
                << "CF mismatch seed=" << std::hex << seed << " iter=" << std::dec << i
                << " val=" << std::hex << value32 << " cnt=" << std::dec << count;
            ASSERT_EQ(ctx.pc, 4u) << "Ror test stream halts at instruction 4";
        }
    }
}
