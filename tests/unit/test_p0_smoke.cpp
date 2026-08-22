// P0 smoke tests for the frozen contract surfaces (common / framework / ir).
// registry + pipeline are P1 stubs and are deliberately not exercised here.

#include "wvmp/common/bytes.hpp"
#include "wvmp/common/rng.hpp"
#include "wvmp/framework/context.hpp"
#include "wvmp/framework/phase.hpp"
#include "wvmp/ir/insn.hpp"
#include "wvmp/ir/operand.hpp"
#include "wvmp/ir/reg.hpp"

#include <gtest/gtest.h>

#include <stdexcept>
#include <vector>

namespace {

TEST(Rng, SameSeedSameSequence) {
    wvmp::Rng a(0x1234'5678'9abc'def0);
    wvmp::Rng b(0x1234'5678'9abc'def0);
    for (int i = 0; i < 64; ++i) {
        ASSERT_EQ(a.next(), b.next());
    }
}

TEST(Rng, ReseedReplaysSequence) {
    wvmp::Rng a(1);
    wvmp::Rng b(99);
    a.reseed(42);
    b.reseed(42);
    EXPECT_EQ(a.next(), b.next());
    EXPECT_EQ(a.next(), b.next());
}

TEST(Rng, UniformShuffleChance) {
    wvmp::Rng a(7);
    wvmp::Rng b(7);
    EXPECT_EQ(a.uniform(0, 1000), b.uniform(0, 1000));

    std::vector<int> va{1, 2, 3, 4, 5, 6, 7, 8};
    std::vector<int> vb{1, 2, 3, 4, 5, 6, 7, 8};
    a.shuffle(va.begin(), va.end());
    b.shuffle(vb.begin(), vb.end());
    EXPECT_EQ(va, vb);

    EXPECT_FALSE(a.chance(0.0));
    EXPECT_TRUE(a.chance(1.0));
}

TEST(Bytes, LittleEndianRoundtrip) {
    std::vector<wvmp::u8> buf;
    wvmp::ByteWriter w(buf);
    w.write_u8(0xAB);
    w.write_u16(0xCDEF);
    w.write_u32(0x1122'3344);
    w.write_u64(0x0102'0304'0506'0708);
    const std::vector<wvmp::u8> tail{9, 8, 7};
    w.write_bytes(tail);

    ASSERT_EQ(buf.size(), static_cast<size_t>(18));
    // Exact little-endian byte order.
    EXPECT_EQ(buf[0], 0xAB);
    EXPECT_EQ(buf[1], 0xEF);
    EXPECT_EQ(buf[2], 0xCD);
    EXPECT_EQ(buf[3], 0x44);
    EXPECT_EQ(buf[4], 0x33);
    EXPECT_EQ(buf[5], 0x22);
    EXPECT_EQ(buf[6], 0x11);
    EXPECT_EQ(buf[7], 0x08);
    EXPECT_EQ(buf[8], 0x07);
    EXPECT_EQ(buf[9], 0x06);
    EXPECT_EQ(buf[10], 0x05);
    EXPECT_EQ(buf[11], 0x04);
    EXPECT_EQ(buf[12], 0x03);
    EXPECT_EQ(buf[13], 0x02);
    EXPECT_EQ(buf[14], 0x01);
    EXPECT_EQ(buf[15], 9);
    EXPECT_EQ(buf[16], 8);
    EXPECT_EQ(buf[17], 7);

    wvmp::ByteReader r(buf.data(), buf.size());
    EXPECT_EQ(r.remaining(), buf.size());
    EXPECT_EQ(r.read_u8(), 0xAB);
    EXPECT_EQ(r.read_u16(), 0xCDEF);
    EXPECT_EQ(r.read_u32(), 0x1122'3344);
    EXPECT_EQ(r.read_u64(), 0x0102'0304'0506'0708);
    EXPECT_EQ(r.remaining(), static_cast<size_t>(3));
    r.skip(2);
    EXPECT_EQ(r.read_u8(), 7);
    EXPECT_EQ(r.remaining(), static_cast<size_t>(0));
}

TEST(Bytes, OutOfRangeThrows) {
    const std::vector<wvmp::u8> small{1, 2};
    wvmp::ByteReader r(small.data(), small.size());
    EXPECT_EQ(r.read_u16(), 0x0201);
    EXPECT_THROW(r.read_u8(), std::out_of_range);
    EXPECT_THROW(r.skip(1), std::out_of_range);
    EXPECT_THROW(r.read_u64(), std::out_of_range);
}

TEST(Bytes, Patch) {
    std::vector<wvmp::u8> buf;
    wvmp::ByteWriter w(buf);
    w.write_u32(0);
    w.write_u64(0);
    w.patch_u32(0, 0xdead'beef);
    w.patch_u64(4, 0xfeed'face'cafe'beef);

    wvmp::ByteReader r(buf.data(), buf.size());
    EXPECT_EQ(r.read_u32(), 0xdead'beef);
    EXPECT_EQ(r.read_u64(), 0xfeed'face'cafe'beef);

    EXPECT_THROW(w.patch_u32(9, 0), std::out_of_range);
    EXPECT_THROW(w.patch_u64(8, 0), std::out_of_range);
}

TEST(Context, ExtensionSlots) {
    wvmp::ProtectionContext ctx;
    EXPECT_FALSE(ctx.has_slot("counter"));
    EXPECT_EQ(ctx.find_slot<int>("counter"), nullptr);

    ctx.slot<int>("counter") = 42;
    EXPECT_TRUE(ctx.has_slot("counter"));
    EXPECT_EQ(ctx.slot<int>("counter"), 42);

    int* mut = ctx.find_slot<int>("counter");
    ASSERT_NE(mut, nullptr);
    *mut += 1;
    EXPECT_EQ(ctx.slot<int>("counter"), 43);

    const wvmp::ProtectionContext& cctx = ctx;
    const int* cst = cctx.find_slot<int>("counter");
    ASSERT_NE(cst, nullptr);
    EXPECT_EQ(*cst, 43);

    ctx.drop_slot("counter");
    EXPECT_FALSE(ctx.has_slot("counter"));
    EXPECT_EQ(ctx.find_slot<int>("counter"), nullptr);
}

TEST(Context, CoreFields) {
    wvmp::ProtectionContext ctx;
    ctx.seed = 5;
    ctx.rng.reseed(ctx.seed);
    EXPECT_EQ(ctx.rng.next(), wvmp::Rng(5).next());
    ctx.image = {1, 2, 3};
    EXPECT_EQ(ctx.image.size(), static_cast<size_t>(3));
    EXPECT_TRUE(ctx.functions.empty());
    EXPECT_FALSE(ctx.diag.has_errors());
    ctx.diag.report(wvmp::Severity::Warning, "test_pass", "hello");
    EXPECT_FALSE(ctx.diag.has_errors());
    ctx.diag.report(wvmp::Severity::Error, "test_pass", "boom");
    EXPECT_TRUE(ctx.diag.has_errors());
    ASSERT_EQ(ctx.diag.items().size(), static_cast<size_t>(2));
    EXPECT_EQ(ctx.diag.items()[1].pass, "test_pass");
    EXPECT_EQ(ctx.diag.items()[1].message, "boom");
}

TEST(Naming, Phase) {
    using wvmp::Phase;
    EXPECT_EQ(wvmp::to_string(Phase::Load), "Load");
    EXPECT_EQ(wvmp::to_string(Phase::Analyze), "Analyze");
    EXPECT_EQ(wvmp::to_string(Phase::Transform), "Transform");
    EXPECT_EQ(wvmp::to_string(Phase::Emit), "Emit");
    EXPECT_EQ(wvmp::to_string(Phase::Write), "Write");
}

TEST(Naming, Reg) {
    namespace ir = wvmp::ir;
    EXPECT_EQ(ir::to_string(ir::Reg::Rax), "rax");
    EXPECT_EQ(ir::to_string(ir::Reg::R8), "r8");
    EXPECT_EQ(ir::to_string(ir::Reg::R15), "r15");
    EXPECT_EQ(ir::to_string(ir::Reg::Rip), "rip");
    EXPECT_EQ(ir::to_string(ir::Reg::Flags), "flags");
    static_assert(ir::is_gpr(ir::Reg::Rax));
    static_assert(!ir::is_gpr(ir::Reg::Rip));
}

TEST(Naming, Insn) {
    namespace ir = wvmp::ir;
    EXPECT_EQ(ir::to_string(ir::Op::Mov), "mov");
    EXPECT_EQ(ir::to_string(ir::Op::Load), "load");
    EXPECT_EQ(ir::to_string(ir::Op::Store), "store");
    EXPECT_EQ(ir::to_string(ir::Op::Nop), "nop");
    EXPECT_EQ(ir::to_string(ir::Size::S8), "s8");
    EXPECT_EQ(ir::to_string(ir::Size::S16), "s16");
    EXPECT_EQ(ir::to_string(ir::Size::S32), "s32");
    EXPECT_EQ(ir::to_string(ir::Size::S64), "s64");
    EXPECT_EQ(ir::to_string(ir::Cond::O), "o");
    EXPECT_EQ(ir::to_string(ir::Cond::Ge), "ge");
    EXPECT_EQ(ir::to_string(ir::Cond::G), "g");
    static_assert(ir::bits(ir::Size::S8) == 8);
    static_assert(ir::bits(ir::Size::S64) == 64);
}

TEST(Ir, OperandFactories) {
    namespace ir = wvmp::ir;
    EXPECT_EQ(ir::Operand::none().kind, ir::Operand::Kind::None);

    ir::Operand r = ir::Operand::reg_(ir::Reg::Rdx);
    EXPECT_EQ(r.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.reg, ir::Reg::Rdx);

    ir::Operand i = ir::Operand::imm_(-5);
    EXPECT_EQ(i.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(i.imm, -5);

    ir::MemOperand m;
    m.base = ir::Reg::Rbp;
    m.index = ir::Reg::Rax;
    m.scale = 2;
    m.disp = 0x20;
    ir::Operand mm = ir::Operand::mem_(m);
    EXPECT_EQ(mm.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(mm.mem.base, ir::Reg::Rbp);
    EXPECT_EQ(mm.mem.index, ir::Reg::Rax);
    EXPECT_EQ(mm.mem.scale, 2);
    EXPECT_EQ(mm.mem.disp, 0x20);
}

} // namespace
