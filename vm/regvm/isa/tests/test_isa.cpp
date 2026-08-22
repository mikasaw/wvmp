// P4：regvm ISA 的编码往返 fuzz、位图精确性、子寄存器别名矩阵与 blob 往返测试。

#include "wvmp/common/bytes.hpp"
#include "wvmp/common/rng.hpp"
#include "wvmp/regvm/isa/alias.hpp"
#include "wvmp/regvm/isa/blob.hpp"
#include "wvmp/regvm/isa/encoding.hpp"
#include "wvmp/regvm/isa/vm_reg.hpp"

#include <gtest/gtest.h>

#include <cstring>
#include <stdexcept>

namespace {

namespace isa = wvmp::regvm::isa;
namespace ir = wvmp::ir;

const isa::VmOp kAllOps[] = {
    isa::VmOp::Mov, isa::VmOp::Lea, isa::VmOp::Add, isa::VmOp::Sub,
    isa::VmOp::Adc, isa::VmOp::Sbb, isa::VmOp::And, isa::VmOp::Or,
    isa::VmOp::Xor, isa::VmOp::Not, isa::VmOp::Neg, isa::VmOp::Inc,
    isa::VmOp::Dec, isa::VmOp::Shl, isa::VmOp::Shr, isa::VmOp::Sar,
    isa::VmOp::Rol, isa::VmOp::Ror, isa::VmOp::Cmp, isa::VmOp::Test,
    isa::VmOp::Push, isa::VmOp::Pop, isa::VmOp::Jmp, isa::VmOp::Jcc,
    isa::VmOp::Call, isa::VmOp::Ret, isa::VmOp::Load, isa::VmOp::Store,
    isa::VmOp::Nop, isa::VmOp::Halt, isa::VmOp::GetFlags, isa::VmOp::SetFlags,
};
constexpr size_t kAllOpsCount = sizeof(kAllOps) / sizeof(kAllOps[0]);

TEST(Encoding, KnownBytesExactBitmap) {
    // Mov、a=Reg(v0)、b=Imm、aux=0x11223344：
    //   word = 1 | (1<<14) | (2<<16) | (0x11223344<<32)
    const wvmp::u64 word = isa::encode(
        isa::make_insn(isa::VmOp::Mov, isa::OpKind::Reg, 0, isa::OpKind::Imm, 0, 0x11223344));
    ASSERT_EQ(word, 0x1122'3344'0002'4001ull);
    // LE 字节序。
    std::vector<wvmp::u8> stream;
    isa::append_insn(stream, isa::decode(word));
    const wvmp::u8 expected[] = {0x01, 0x40, 0x02, 0x00, 0x44, 0x33, 0x22, 0x11};
    ASSERT_EQ(stream.size(), static_cast<size_t>(8));
    for (int i = 0; i < 8; ++i) EXPECT_EQ(stream[i], expected[i]);
}

TEST(Encoding, AllFieldsRoundtrip) {
    const isa::VmInsn insn = isa::make_insn(isa::VmOp::Jcc, isa::OpKind::Imm, 31,
                                            isa::OpKind::Reg, 17, 0xDEAD'BE00, 15);
    const isa::VmInsn back = isa::decode(isa::encode(insn));
    EXPECT_EQ(back.op, isa::VmOp::Jcc);
    EXPECT_EQ(back.a_kind, isa::OpKind::Imm);
    EXPECT_EQ(back.b_kind, isa::OpKind::Reg);
    EXPECT_EQ(back.cond, 15);
    EXPECT_EQ(back.reg_a, 31);
    EXPECT_EQ(back.reg_b, 17);
    EXPECT_EQ(back.aux, 0xDEAD'BE00u);
}

TEST(Encoding, FuzzRoundtripTenThousand) {
    wvmp::Rng rng(0xC0FFEE);
    const isa::OpKind kinds[] = {isa::OpKind::None, isa::OpKind::Reg, isa::OpKind::Imm};
    for (int i = 0; i < 10000; ++i) {
        isa::VmInsn insn;
        insn.op = kAllOps[rng.uniform(0, kAllOpsCount - 1)];
        insn.a_kind = kinds[rng.uniform(0, 2)];
        insn.b_kind = kinds[rng.uniform(0, 2)];
        insn.cond = static_cast<wvmp::u8>(rng.uniform(0, 15));
        insn.reg_a = static_cast<wvmp::u8>(rng.uniform(0, isa::kRegCount - 1));
        insn.reg_b = static_cast<wvmp::u8>(rng.uniform(0, isa::kRegCount - 1));
        insn.aux = static_cast<wvmp::u32>(rng.next());
        const isa::VmInsn back = isa::decode(isa::encode(insn));
        ASSERT_EQ(back.op, insn.op);
        ASSERT_EQ(back.a_kind, insn.a_kind);
        ASSERT_EQ(back.b_kind, insn.b_kind);
        ASSERT_EQ(back.cond, insn.cond);
        ASSERT_EQ(back.reg_a, insn.reg_a);
        ASSERT_EQ(back.reg_b, insn.reg_b);
        ASSERT_EQ(back.aux, insn.aux) << "iteration " << i;
    }
}

TEST(Encoding, DecodeRejectsIllegalFields) {
    // kind=3（保留值）。
    EXPECT_THROW((void)isa::decode(3ull << 14), std::runtime_error);
    EXPECT_THROW((void)isa::decode(3ull << 16), std::runtime_error);
    // opcode = 0。
    EXPECT_THROW((void)isa::decode(0), std::runtime_error);
    // opcode 在 14 位空间内但超出当前枚举界（如 0x3FFF、kVmOpMax+1）。
    EXPECT_THROW((void)isa::decode((1ull << 14) - 1), std::runtime_error);
    EXPECT_THROW((void)isa::decode(wvmp::u64{1} << 0 | (wvmp::u64(isa::kVmOpMax + 1))), std::runtime_error);
    // reg>31 / cond>15 在 5/4 位位域中不可表示（位精确编码天然排除），
    // 无需也无法通过 decode 测试——故不设断言。
}

TEST(VmReg, MappingAndValidity) {
    EXPECT_EQ(isa::vm_reg_of(ir::Reg::Rax), 0);
    EXPECT_EQ(isa::vm_reg_of(ir::Reg::R15), 15);
    EXPECT_EQ(isa::vm_reg_of(ir::Reg::Flags), isa::kRegFlags);
    EXPECT_EQ(isa::vm_reg_of(ir::Reg::Rip), isa::kRegRip);
    EXPECT_EQ(isa::ir_reg_of(15), ir::Reg::R15);
    EXPECT_TRUE(isa::is_valid_vm_reg(31));
    EXPECT_FALSE(isa::is_valid_vm_reg(32));
    EXPECT_EQ(isa::kScratchFirst + isa::kScratchCount - 1, 23);
}

TEST(Alias, ReadMatrix) {
    const wvmp::u64 full = 0x1234'5678'9ABC'DEF0;
    EXPECT_EQ(isa::alias_read(full, ir::Size::S8), 0xF0ull);
    EXPECT_EQ(isa::alias_read(full, ir::Size::S16), 0xDEF0ull);
    EXPECT_EQ(isa::alias_read(full, ir::Size::S32), 0x9ABC'DEF0ull);
    EXPECT_EQ(isa::alias_read(full, ir::Size::S64), full);
    // 读出值一律落在对应位宽内（零扩展语义的自然结果）。
    const wvmp::u64 all = ~0ull;
    EXPECT_EQ(isa::alias_read(all, ir::Size::S8), 0xFFull);
    EXPECT_EQ(isa::alias_read(all, ir::Size::S16), 0xFFFFull);
    EXPECT_EQ(isa::alias_read(all, ir::Size::S32), 0xFFFF'FFFFull);
}

TEST(Alias, WriteMatrix) {
    using ir::Size;
    const wvmp::u64 old = 0x1234'5678'9ABC'DEF0;
    const wvmp::u64 ones = ~0ull;

    // S8/S16：低位替换、高位保留。
    EXPECT_EQ(isa::alias_write(old, 0xAB, Size::S8), 0x1234'5678'9ABC'DEAB);
    EXPECT_EQ(isa::alias_write(old, 0xABCD, Size::S16), 0x1234'5678'9ABC'ABCD);
    EXPECT_EQ(isa::alias_write(ones, 0x00, Size::S8), 0xFFFF'FFFF'FFFF'FF00);
    EXPECT_EQ(isa::alias_write(ones, 0x0000, Size::S16), 0xFFFF'FFFF'FFFF'0000);

    // S32：零扩展（x86-64 规则）——高 32 位必须清零。
    EXPECT_EQ(isa::alias_write(old, 0xAB, Size::S32), 0x0000'0000'0000'00AB);
    EXPECT_EQ(isa::alias_write(ones, 0x1, Size::S32), 0x0000'0000'0000'0001ull);

    // S64：整体替换。
    EXPECT_EQ(isa::alias_write(old, 0x42, Size::S64), 0x42ull);
    EXPECT_EQ(isa::alias_write(old, ones, Size::S64), ones);

    // 值超过目标位宽时按位宽截断。
    EXPECT_EQ(isa::alias_write(old, 0x1FF, Size::S8), 0x1234'5678'9ABC'DEFF);
}

TEST(Blob, RoundtripAndValidation) {
    std::vector<wvmp::u8> stream;
    isa::append_insn(stream, isa::make_insn(isa::VmOp::Mov, isa::OpKind::Reg, 0,
                                            isa::OpKind::Imm, 0, 42));
    isa::append_insn(stream, isa::make_insn(isa::VmOp::Halt, isa::OpKind::None, 0,
                                            isa::OpKind::None, 0));
    const auto blob = isa::make_blob(ir::Arch::X64, 0, stream);

    std::vector<wvmp::u8> buf;
    wvmp::ByteWriter w(buf);
    isa::write_blob(w, blob);
    ASSERT_EQ(buf.size(), static_cast<size_t>(32 + 16));

    wvmp::ByteReader r(buf.data(), buf.size());
    const auto back = isa::read_blob(r);
    EXPECT_EQ(back.header.version, blob.header.version);
    EXPECT_EQ(back.header.arch, blob.header.arch);
    EXPECT_EQ(back.header.entry_offset, blob.header.entry_offset);
    EXPECT_EQ(back.header.insn_count, blob.header.insn_count);
    EXPECT_EQ(back.stream, blob.stream);
    EXPECT_EQ(r.remaining(), static_cast<size_t>(0));

    // 损坏 magic。
    buf[0] = 'X';
    wvmp::ByteReader bad(buf.data(), buf.size());
    EXPECT_THROW((void)isa::read_blob(bad), std::runtime_error);

    // 截断：声明 2 条但流只剩 1 条。
    std::vector<wvmp::u8> short_buf(buf.size() - 8);
    std::memcpy(short_buf.data(), buf.data(), short_buf.size());
    wvmp::ByteReader trunc(short_buf.data(), short_buf.size());
    EXPECT_THROW((void)isa::read_blob(trunc), std::runtime_error);
}

TEST(Blob, MakeBlobRejectsBadArgs) {
    std::vector<wvmp::u8> odd{1, 2, 3};
    EXPECT_THROW((void)isa::make_blob(ir::Arch::X64, 0, odd), std::runtime_error);
    std::vector<wvmp::u8> ok(16, 0);
    EXPECT_THROW((void)isa::make_blob(ir::Arch::X64, 4, ok), std::runtime_error);  // 非 8 倍数
    EXPECT_THROW((void)isa::make_blob(ir::Arch::X64, 24, ok), std::runtime_error); // 越界
}

} // namespace
