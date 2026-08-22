// P5：regvm 翻译器测试 —— 逐类指令快照、imm64 拆条、整函数块布局与相对
// 偏移、blob 往返、notes 路径，以及内嵌小型参考解释器的两个端到端用例。

#include "wvmp/common/bytes.hpp"
#include "wvmp/regvm/isa/alias.hpp"
#include "wvmp/regvm/isa/blob.hpp"
#include "wvmp/regvm/isa/encoding.hpp"
#include "wvmp/regvm/isa/vm_op.hpp"
#include "wvmp/regvm/isa/vm_reg.hpp"
#include "wvmp/regvm/translator/translator.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <vector>

namespace {

namespace isa = wvmp::regvm::isa;
namespace ir = wvmp::ir;
using wvmp::i64;
using wvmp::u8;
using wvmp::u16;
using wvmp::u32;
using wvmp::u64;
using isa::OpKind;
using isa::VmInsn;
using isa::VmOp;

// ---------------- IR 构造便捷函数 ----------------

ir::Insn I(ir::Op op, ir::Size sz) {
    ir::Insn i;
    i.op = op;
    i.size = sz;
    i.addr = 0x401000;
    return i;
}

ir::Insn mov(ir::Reg d, ir::Reg s, ir::Size sz) {
    ir::Insn i = I(ir::Op::Mov, sz);
    i.dst = ir::Operand::reg_(d);
    i.src = ir::Operand::reg_(s);
    return i;
}
ir::Insn mov_imm(ir::Reg d, i64 v, ir::Size sz) {
    ir::Insn i = I(ir::Op::Mov, sz);
    i.dst = ir::Operand::reg_(d);
    i.src = ir::Operand::imm_(v);
    return i;
}
ir::Insn alu(ir::Op op, ir::Operand d, ir::Operand s, ir::Size sz, bool flags = true) {
    ir::Insn i = I(op, sz);
    i.dst = d;
    i.src = s;
    i.updates_flags = flags;
    return i;
}
ir::Insn jump(ir::Op op, u64 target, ir::Cond c = ir::Cond::Ne) {
    ir::Insn i = I(op, ir::Size::S64);
    i.cond = c;
    i.dst = ir::Operand::imm_(static_cast<i64>(target));
    return i;
}

ir::MemOperand m(ir::Reg base, ir::Reg index = ir::Reg::Flags, u8 scale = 0, i64 disp = 0) {
    ir::MemOperand o;
    o.base = base;
    o.index = index;
    o.scale = scale;
    o.disp = disp;
    return o;
}

ir::BasicBlock blk(u64 addr, std::vector<ir::Insn> insns) {
    ir::BasicBlock b;
    b.addr = addr;
    b.insns = std::move(insns);
    return b;
}

ir::FunctionRegion fn_of(std::vector<ir::BasicBlock> blocks) {
    ir::FunctionRegion fn;
    fn.name = "test_fn";
    fn.arch = ir::Arch::X64;
    fn.begin_rva = 0x1000;
    fn.end_rva = 0x3000;
    fn.blocks = std::move(blocks);
    return fn;
}

// 产出解码：bytecode -> read_blob -> 逐条 decode（隐含一轮 encode/decode 往返）。
struct Decoded {
    isa::VmBlob blob;
    std::vector<VmInsn> insns;
};

Decoded decode_program(const wvmp::vm::VmProgram& p) {
    wvmp::ByteReader r(p.bytecode.data(), p.bytecode.size());
    Decoded d;
    d.blob = isa::read_blob(r);
    for (size_t off = 0; off < d.blob.stream.size(); off += 8) {
        wvmp::u64 w = 0;
        for (int k = 0; k < 8; ++k)
            w |= static_cast<wvmp::u64>(d.blob.stream[off + k]) << (8 * k);
        d.insns.push_back(isa::decode(w));
    }
    EXPECT_EQ(r.remaining(), static_cast<size_t>(0)); // 头+流恰好耗尽
    return d;
}

// 逐字段断言（op / a_kind / reg_a / b_kind / reg_b / aux / cond_or_size）。
void expect_is(const VmInsn& g, VmOp op, OpKind ak, u8 ra, OpKind bk, u8 rb, u32 aux,
               u8 cs) {
    EXPECT_EQ(g.op, op);
    EXPECT_EQ(g.a_kind, ak);
    EXPECT_EQ(g.reg_a, ra);
    EXPECT_EQ(g.b_kind, bk);
    EXPECT_EQ(g.reg_b, rb);
    EXPECT_EQ(g.aux, aux);
    EXPECT_EQ(g.cond_or_size, cs);
}

const u8 kRax = isa::vm_reg_of(ir::Reg::Rax);
const u8 kRcx = isa::vm_reg_of(ir::Reg::Rcx);
const u8 kRdx = isa::vm_reg_of(ir::Reg::Rdx);
const u8 kRbx = isa::vm_reg_of(ir::Reg::Rbx);
const u8 kRsp = isa::vm_reg_of(ir::Reg::Rsp);
const u8 kRbp = isa::vm_reg_of(ir::Reg::Rbp);
const u8 kS32 = isa::size_field(ir::Size::S32);
const u8 kS64 = isa::size_field(ir::Size::S64);

// 单条指令函数的产出（含块尾 fallthrough Jmp + 函数尾 Halt）。
Decoded one_insn(const ir::Insn& i) {
    const auto r = wvmp::regvm::translator::translate_function(
        fn_of({blk(0x1000, {i})}));
    EXPECT_TRUE(r.notes.empty());
    EXPECT_EQ(r.program.entry_offset, 0u);
    return decode_program(r.program);
}

// ---------------- 逐类指令快照 ----------------

TEST(Translate, MovRegImm) {
    const Decoded d = one_insn(mov_imm(ir::Reg::Rax, 0x41, ir::Size::S32));
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(3)); // Mov + Jmp+1 + Halt
    expect_is(d.insns[0], VmOp::Mov, OpKind::Reg, kRax, OpKind::Imm, 0, 0x41, kS32);
    expect_is(d.insns[1], VmOp::Jmp, OpKind::None, 0, OpKind::None, 0, 1, kS64);
    expect_is(d.insns[2], VmOp::Halt, OpKind::None, 0, OpKind::None, 0, 0, 0);
}

TEST(Translate, MovRegReg) {
    const Decoded d = one_insn(mov(ir::Reg::Rbx, ir::Reg::Rax, ir::Size::S64));
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(3));
    expect_is(d.insns[0], VmOp::Mov, OpKind::Reg, kRbx, OpKind::Reg, kRax, 0, kS64);
}

TEST(Translate, AddRegRegS32) { // 验证 Size 传递
    const Decoded d = one_insn(alu(ir::Op::Add, ir::Operand::reg_(ir::Reg::Rcx),
                                   ir::Operand::reg_(ir::Reg::Rdx), ir::Size::S32));
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(3));
    expect_is(d.insns[0], VmOp::Add, OpKind::Reg, kRcx, OpKind::Reg, kRdx, 0, kS32);
}

TEST(Translate, AddRegMemScratchExpansion) {
    // add rax, [rbx + rcx*8 + 0x10]（S64）
    const ir::Insn i = alu(ir::Op::Add, ir::Operand::reg_(ir::Reg::Rax),
                           ir::Operand::mem_(m(ir::Reg::Rbx, ir::Reg::Rcx, 8, 0x10)),
                           ir::Size::S64);
    const Decoded d = one_insn(i);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(9)); // 7 + Jmp + Halt
    expect_is(d.insns[0], VmOp::Mov, OpKind::Reg, isa::kScratchFirst, OpKind::Reg, kRbx,
              0, kS64);
    expect_is(d.insns[1], VmOp::Mov, OpKind::Reg, isa::kScratchFirst + 1, OpKind::Reg,
              kRcx, 0, kS64);
    expect_is(d.insns[2], VmOp::Shl, OpKind::Reg, isa::kScratchFirst + 1, OpKind::Imm, 0,
              3, kS64);
    expect_is(d.insns[3], VmOp::Add, OpKind::Reg, isa::kScratchFirst, OpKind::Reg,
              isa::kScratchFirst + 1, 0, kS64);
    expect_is(d.insns[4], VmOp::Add, OpKind::Reg, isa::kScratchFirst, OpKind::Imm, 0,
              0x10, kS64);
    expect_is(d.insns[5], VmOp::Load, OpKind::Reg, isa::kScratchFirst + 2, OpKind::Reg,
              isa::kScratchFirst, 0, kS64);
    expect_is(d.insns[6], VmOp::Add, OpKind::Reg, kRax, OpKind::Reg,
              isa::kScratchFirst + 2, 0, kS64);
}

TEST(Translate, StoreRegToMemNegativeDispUsesSub) {
    // IR Store（lifter 约定：mov [rbp-0x18], rax -> Store dst=mem, src=reg）。
    // 负 disp 以 Sub |disp| 展开（aux 零扩展放不下负数）。
    ir::Insn st = I(ir::Op::Store, ir::Size::S64);
    st.dst = ir::Operand::mem_(m(ir::Reg::Rbp, ir::Reg::Flags, 0, -0x18));
    st.src = ir::Operand::reg_(ir::Reg::Rax);
    const Decoded d = one_insn(st);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(5)); // 3 + Jmp + Halt
    expect_is(d.insns[0], VmOp::Mov, OpKind::Reg, isa::kScratchFirst, OpKind::Reg, kRbp,
              0, kS64);
    expect_is(d.insns[1], VmOp::Sub, OpKind::Reg, isa::kScratchFirst, OpKind::Imm, 0,
              0x18, kS64);
    expect_is(d.insns[2], VmOp::Store, OpKind::Reg, isa::kScratchFirst, OpKind::Reg, kRax,
              0, kS64); // 方向：a=addr，b=src
}

TEST(Translate, PushPopExpansion) {
    const auto r = wvmp::regvm::translator::translate_function(
        fn_of({blk(0x1000, [] {
                   std::vector<ir::Insn> v;
                   ir::Insn p = I(ir::Op::Push, ir::Size::S64);
                   p.dst = ir::Operand::reg_(ir::Reg::Rax);
                   v.push_back(p);
                   ir::Insn q = I(ir::Op::Pop, ir::Size::S64);
                   q.dst = ir::Operand::reg_(ir::Reg::Rbx);
                   v.push_back(q);
                   return v;
               }())}));
    EXPECT_TRUE(r.notes.empty());
    const Decoded d = decode_program(r.program);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(6)); // 4 + Jmp + Halt
    expect_is(d.insns[0], VmOp::Sub, OpKind::Reg, kRsp, OpKind::Imm, 0, 8, kS64);
    expect_is(d.insns[1], VmOp::Store, OpKind::Reg, kRsp, OpKind::Reg, kRax, 0, kS64);
    expect_is(d.insns[2], VmOp::Load, OpKind::Reg, kRbx, OpKind::Reg, kRsp, 0, kS64);
    expect_is(d.insns[3], VmOp::Add, OpKind::Reg, kRsp, OpKind::Imm, 0, 8, kS64);
}

TEST(Translate, LeaExpansion) {
    // lea rax, [rbx + rcx*4 + 0x20]（S64，纯寄存器形式，无访存）
    const ir::Insn i = I(ir::Op::Lea, ir::Size::S64);
    ir::Insn lea = i;
    lea.dst = ir::Operand::reg_(ir::Reg::Rax);
    lea.src = ir::Operand::mem_(m(ir::Reg::Rbx, ir::Reg::Rcx, 4, 0x20));
    const Decoded d = one_insn(lea);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(8)); // 6 + Jmp + Halt
    expect_is(d.insns[0], VmOp::Mov, OpKind::Reg, isa::kScratchFirst, OpKind::Reg, kRbx,
              0, kS64);
    expect_is(d.insns[1], VmOp::Mov, OpKind::Reg, isa::kScratchFirst + 1, OpKind::Reg,
              kRcx, 0, kS64);
    expect_is(d.insns[2], VmOp::Shl, OpKind::Reg, isa::kScratchFirst + 1, OpKind::Imm, 0,
              2, kS64);
    expect_is(d.insns[3], VmOp::Add, OpKind::Reg, isa::kScratchFirst, OpKind::Reg,
              isa::kScratchFirst + 1, 0, kS64);
    expect_is(d.insns[4], VmOp::Add, OpKind::Reg, isa::kScratchFirst, OpKind::Imm, 0,
              0x20, kS64);
    expect_is(d.insns[5], VmOp::Mov, OpKind::Reg, kRax, OpKind::Reg, isa::kScratchFirst,
              0, kS64);
}

// ---------------- imm64 拆条 ----------------

TEST(Translate, Imm64SplitExactlyFourInsns) {
    // mov rax, 0x1122334455667788：恰好 Mov hi / Shl 32 / Mov lo / Or（全 S64）。
    const Decoded d = one_insn(mov_imm(ir::Reg::Rax, 0x1122334455667788ll, ir::Size::S64));
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(6)); // 4 + Jmp + Halt
    expect_is(d.insns[0], VmOp::Mov, OpKind::Reg, isa::kScratchFirst, OpKind::Imm, 0,
              0x11223344, kS64);
    expect_is(d.insns[1], VmOp::Shl, OpKind::Reg, isa::kScratchFirst, OpKind::Imm, 0, 32,
              kS64);
    expect_is(d.insns[2], VmOp::Mov, OpKind::Reg, kRax, OpKind::Imm, 0, 0x55667788,
              kS64);
    expect_is(d.insns[3], VmOp::Or, OpKind::Reg, kRax, OpKind::Reg, isa::kScratchFirst,
              0, kS64);
}

TEST(Translate, MovImm32NegativeStaysSingleInsn) {
    // mov ecx, -1：sub-64 负立即数不拆条（aux 截断 + S32 写回零扩展即正确）。
    const Decoded d = one_insn(mov_imm(ir::Reg::Rcx, -1, ir::Size::S32));
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(3));
    expect_is(d.insns[0], VmOp::Mov, OpKind::Reg, kRcx, OpKind::Imm, 0, 0xFFFF'FFFFu,
              kS32);
}

// ---------------- 整函数：块布局 / fallthrough / 相对偏移 ----------------

TEST(Translate, TwoBlockLayoutAndOffsets) {
    // b0@0x1000: mov ecx,5 ; jne 0x2000   b1@0x2000: add eax,2
    // 手算布局：
    //   [0] Mov ecx,5        (b0 起点 0)
    //   [1] Jcc aux=3-1=2    (目标 b1 起点 3)
    //   [2] Jmp +1           (b0 fallthrough 补跳)
    //   [3] Add eax,2        (b1 起点 3)
    //   [4] Jmp +1           (b1 fallthrough 补跳)
    //   [5] Halt
    const auto r = wvmp::regvm::translator::translate_function(fn_of({
        blk(0x1000,
            {mov_imm(ir::Reg::Rcx, 5, ir::Size::S32), jump(ir::Op::Jcc, 0x2000)}),
        blk(0x2000,
            {alu(ir::Op::Add, ir::Operand::reg_(ir::Reg::Rax), ir::Operand::imm_(2),
                 ir::Size::S32)}),
    }));
    EXPECT_TRUE(r.notes.empty());
    const Decoded d = decode_program(r.program);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(6));
    expect_is(d.insns[0], VmOp::Mov, OpKind::Reg, kRcx, OpKind::Imm, 0, 5, kS32);
    expect_is(d.insns[1], VmOp::Jcc, OpKind::None, 0, OpKind::None, 0, 2,
              static_cast<u8>(ir::Cond::Ne)); // cond_or_size = ir::Cond
    expect_is(d.insns[2], VmOp::Jmp, OpKind::None, 0, OpKind::None, 0, 1, kS64);
    expect_is(d.insns[3], VmOp::Add, OpKind::Reg, kRax, OpKind::Imm, 0, 2, kS32);
    expect_is(d.insns[4], VmOp::Jmp, OpKind::None, 0, OpKind::None, 0, 1, kS64);
    expect_is(d.insns[5], VmOp::Halt, OpKind::None, 0, OpKind::None, 0, 0, 0);
}

TEST(Translate, RetTerminatorNeedsNoFallthrough) {
    // b0: jne 0x2000  b1: ret —— Jcc 之后补 Jmp+1，Ret 之后不补，末尾 Halt。
    const auto r = wvmp::regvm::translator::translate_function(fn_of({
        blk(0x1000, {jump(ir::Op::Jcc, 0x2000)}),
        blk(0x2000, {I(ir::Op::Ret, ir::Size::S64)}),
    }));
    const Decoded d = decode_program(r.program);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(4));
    expect_is(d.insns[0], VmOp::Jcc, OpKind::None, 0, OpKind::None, 0, 2,
              static_cast<u8>(ir::Cond::Ne));
    expect_is(d.insns[1], VmOp::Jmp, OpKind::None, 0, OpKind::None, 0, 1, kS64);
    expect_is(d.insns[2], VmOp::Ret, OpKind::None, 0, OpKind::None, 0, 0, kS64);
    expect_is(d.insns[3], VmOp::Halt, OpKind::None, 0, OpKind::None, 0, 0, 0);
}

TEST(Translate, BackwardJccEncodesNegativeRelAsU32) {
    // 自回跳：cmp rcx,0 ; jne 本块起点 -> aux = 0 - 1 = -1（补码 0xFFFFFFFF）。
    const auto r = wvmp::regvm::translator::translate_function(fn_of({blk(0x1000, {
        alu(ir::Op::Cmp, ir::Operand::reg_(ir::Reg::Rcx), ir::Operand::imm_(0),
            ir::Size::S32),
        jump(ir::Op::Jcc, 0x1000),
    })}));
    const Decoded d = decode_program(r.program);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(4)); // Cmp + Jcc + Jmp+1 + Halt
    expect_is(d.insns[1], VmOp::Jcc, OpKind::None, 0, OpKind::None, 0, 0xFFFF'FFFFu,
              static_cast<u8>(ir::Cond::Ne));
}

// ---------------- blob 往返 ----------------

TEST(Translate, BlobRoundtripByteExact) {
    const auto r = wvmp::regvm::translator::translate_function(fn_of({
        blk(0x1000,
            {mov_imm(ir::Reg::Rax, 0x1122334455667788ll, ir::Size::S64),
             alu(ir::Op::Add, ir::Operand::reg_(ir::Reg::Rax),
                 ir::Operand::mem_(m(ir::Reg::Rbx, ir::Reg::Flags, 0, 8)),
                 ir::Size::S64)}),
        blk(0x2000, {I(ir::Op::Ret, ir::Size::S64)}),
    }));
    ASSERT_TRUE(r.notes.empty());
    EXPECT_EQ(r.program.entry_offset, 0u);

    const Decoded d = decode_program(r.program);
    EXPECT_EQ(d.blob.header.magic[0], 'W');
    EXPECT_EQ(d.blob.header.version, 1);
    EXPECT_EQ(d.blob.header.arch, static_cast<u16>(ir::Arch::X64));
    EXPECT_EQ(d.blob.header.entry_offset, 0u);
    ASSERT_EQ(d.blob.header.insn_count, d.insns.size());
    EXPECT_EQ(d.blob.stream.size(), d.insns.size() * 8);

    // 与翻译器产出逐条一致：手工以同一批 VmInsn 重编 blob，字节完全相同。
    std::vector<wvmp::u8> expect_stream;
    for (const VmInsn& i : d.insns)
        isa::append_insn(expect_stream, i);
    const isa::VmBlob expect_blob = isa::make_blob(ir::Arch::X64, 0, std::move(expect_stream));
    std::vector<wvmp::u8> expect_bytes;
    wvmp::ByteWriter w(expect_bytes);
    isa::write_blob(w, expect_blob);
    EXPECT_EQ(r.program.bytecode, expect_bytes);
    EXPECT_EQ(r.program.bytecode.size(), 32 + d.insns.size() * 8);
}

// ---------------- notes 路径（不失败） ----------------

TEST(Translate, CallSkippedWithNote) {
    const auto r = wvmp::regvm::translator::translate_function(
        fn_of({blk(0x1000, {jump(ir::Op::Call, 0x5000)})}));
    ASSERT_EQ(r.notes.size(), static_cast<size_t>(1));
    EXPECT_NE(r.notes[0].find("call 未支持"), std::string::npos);
    const Decoded d = decode_program(r.program); // 仍产出合法流（Jmp+1 + Halt）
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(2));
    expect_is(d.insns[0], VmOp::Jmp, OpKind::None, 0, OpKind::None, 0, 1, kS64);
    expect_is(d.insns[1], VmOp::Halt, OpKind::None, 0, OpKind::None, 0, 0, 0);
}

TEST(Translate, RipRelativeSkippedWithNote) {
    // mov rax, [rip+8] -> IR Load（base=Rip）。
    ir::Insn ld = I(ir::Op::Load, ir::Size::S64);
    ld.dst = ir::Operand::reg_(ir::Reg::Rax);
    ld.src = ir::Operand::mem_(m(ir::Reg::Rip, ir::Reg::Flags, 0, 8));
    const auto r = wvmp::regvm::translator::translate_function(fn_of({blk(0x1000, {ld})}));
    ASSERT_EQ(r.notes.size(), static_cast<size_t>(1));
    EXPECT_NE(r.notes[0].find("rip-relative 未支持"), std::string::npos);
    const Decoded d = decode_program(r.program);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(2));
}

// ---------------- 参考解释器（~150 行） ----------------
// 只支持 Mov/Add/Sub/And/Or/Xor/Shl/Cmp/Jcc/Jmp/Halt + Load/Store，
// alias_read/alias_write 复用 isa 实现，flags 维护 ZF/SF/CF/OF/PF。

struct RefVm {
    wvmp::u64 regs[isa::kRegCount] = {};
    bool zf = false, sf = false, cf = false, of = false, pf = false;
    std::map<wvmp::u64, wvmp::u8> mem;
    long steps = 0;

    static wvmp::u64 mask_of(ir::Size s) {
        return ir::bits(s) == 64 ? ~wvmp::u64{0} : (~wvmp::u64{0}) >> (64 - ir::bits(s));
    }
    static wvmp::u64 sign_of(ir::Size s) {
        const wvmp::u64 m = mask_of(s);
        return m ^ (m >> 1);
    }
    static bool even_parity(wvmp::u64 v) { // PF：低 8 位中 1 的个数为偶
        int ones = 0;
        for (wvmp::u8 b = static_cast<wvmp::u8>(v); b != 0; b >>= 1)
            ones += (b & 1);
        return ones % 2 == 0;
    }

    wvmp::u64 read_a(const VmInsn& i, ir::Size s) const {
        return isa::alias_read(regs[i.reg_a], s);
    }
    wvmp::u64 read_b(const VmInsn& i, ir::Size s) const {
        if (i.b_kind == OpKind::Imm)
            return i.aux; // aux 零扩展（翻译器约定）
        if (i.b_kind == OpKind::Reg)
            return isa::alias_read(regs[i.reg_b], s);
        return 0;
    }
    void write_a(const VmInsn& i, ir::Size s, wvmp::u64 v) {
        regs[i.reg_a] = isa::alias_write(regs[i.reg_a], v, s);
    }
    void set_logic_flags(wvmp::u64 res, ir::Size s) {
        const wvmp::u64 sign = sign_of(s);
        zf = res == 0;
        sf = (res & sign) != 0;
        cf = of = false;
        pf = even_parity(res);
    }
    void add_flags(wvmp::u64 x, wvmp::u64 y, ir::Size s) {
        const wvmp::u64 mask = mask_of(s), sign = sign_of(s);
        const wvmp::u64 full = x + y;
        const wvmp::u64 res = full & mask;
        cf = full > mask;
        of = (~(x ^ y) & (x ^ res) & sign) != 0;
        zf = res == 0;
        sf = (res & sign) != 0;
        pf = even_parity(res);
    }
    void sub_flags(wvmp::u64 x, wvmp::u64 y, ir::Size s) {
        const wvmp::u64 mask = mask_of(s), sign = sign_of(s);
        const wvmp::u64 res = (x - y) & mask;
        cf = x < y;
        of = ((x ^ y) & (x ^ res) & sign) != 0;
        zf = res == 0;
        sf = (res & sign) != 0;
        pf = even_parity(res);
    }

    wvmp::u64 mem_load(wvmp::u64 addr, ir::Size s) {
        wvmp::u64 v = 0;
        for (unsigned b = 0; b < ir::bits(s) / 8; ++b) {
            const auto it = mem.find(addr + b);
            if (it != mem.end())
                v |= static_cast<wvmp::u64>(it->second) << (8 * b);
        }
        return v;
    }
    void mem_store(wvmp::u64 addr, wvmp::u64 v, ir::Size s) {
        for (unsigned b = 0; b < ir::bits(s) / 8; ++b)
            mem[addr + b] = static_cast<wvmp::u8>(v >> (8 * b));
    }

    bool cond_pass(ir::Cond c) const {
        switch (c) {
        case ir::Cond::O: return of;       case ir::Cond::No: return !of;
        case ir::Cond::B: return cf;       case ir::Cond::Ae: return !cf;
        case ir::Cond::E: return zf;       case ir::Cond::Ne: return !zf;
        case ir::Cond::Be: return cf || zf; case ir::Cond::A: return !(cf || zf);
        case ir::Cond::S: return sf;       case ir::Cond::Ns: return !sf;
        case ir::Cond::P: return pf;       case ir::Cond::Np: return !pf;
        case ir::Cond::L: return sf != of; case ir::Cond::Ge: return sf == of;
        case ir::Cond::Le: return zf || sf != of;
        case ir::Cond::G: return !zf && sf == of;
        }
        return false;
    }

    void run(const std::vector<VmInsn>& code) {
        wvmp::i64 pc = 0;
        while (true) {
            ASSERT_GE(pc, 0);
            ASSERT_LT(static_cast<wvmp::u64>(pc), code.size());
            ASSERT_LT(steps, 100000) << "reference VM runaway";
            ++steps;
            const VmInsn& i = code[static_cast<size_t>(pc)];
            bool jumped = false;
            switch (i.op) {
            case VmOp::Halt:
                return;
            case VmOp::Jmp:
                pc += static_cast<wvmp::i32>(i.aux);
                jumped = true;
                break;
            case VmOp::Jcc:
                if (cond_pass(static_cast<ir::Cond>(i.cond_or_size))) {
                    pc += static_cast<wvmp::i32>(i.aux);
                    jumped = true;
                }
                break;
            default: {
                const ir::Size s = isa::field_size(i.cond_or_size);
                const wvmp::u64 a = read_a(i, s), b = read_b(i, s);
                switch (i.op) {
                case VmOp::Mov: write_a(i, s, b); break;
                case VmOp::Add: add_flags(a, b, s); write_a(i, s, a + b); break;
                case VmOp::Sub: sub_flags(a, b, s); write_a(i, s, (a - b) & mask_of(s)); break;
                case VmOp::And: set_logic_flags(a & b, s); write_a(i, s, a & b); break;
                case VmOp::Or:  set_logic_flags(a | b, s); write_a(i, s, a | b); break;
                case VmOp::Xor: set_logic_flags(a ^ b, s); write_a(i, s, a ^ b); break;
                case VmOp::Shl: {
                    const unsigned cnt = static_cast<unsigned>(b) & 63;
                    const wvmp::u64 res = cnt >= 64 ? 0 : ((a << cnt) & mask_of(s));
                    if (cnt > 0 && cnt <= ir::bits(s))
                        cf = ((a >> (ir::bits(s) - cnt)) & 1) != 0;
                    else if (cnt > ir::bits(s))
                        cf = false;
                    set_logic_flags(res, s);
                    write_a(i, s, res);
                    break;
                }
                case VmOp::Cmp: sub_flags(a, b, s); break;
                case VmOp::Load: write_a(i, s, mem_load(regs[i.reg_b], s)); break;
                case VmOp::Store: mem_store(regs[i.reg_a], b, s); break;
                default:
                    FAIL() << "ref VM: unsupported op " << isa::to_string(i.op);
                }
                break;
            }
            }
            if (!jumped)
                ++pc;
        }
    }
};

RefVm run_fn(const ir::FunctionRegion& fn) {
    const auto r = wvmp::regvm::translator::translate_function(fn);
    EXPECT_TRUE(r.notes.empty());
    const Decoded d = decode_program(r.program);
    RefVm vm;
    vm.run(d.insns);
    return vm;
}

TEST(RefVmE2E, SingleBlockArithmetic) {
    // 单块算术序列终值手算对照（含 imm64 拆条、S64 负立即数、S8 写合并、
    // S32 写零扩展）。
    auto vm = run_fn(fn_of({blk(0x1000, {
        mov_imm(ir::Reg::Rax, 0x1122334455667788ll, ir::Size::S64), // rax=0x1122334455667788
        alu(ir::Op::Add, ir::Operand::reg_(ir::Reg::Rax), ir::Operand::imm_(-1),
            ir::Size::S64),                                          // rax=0x1122334455667787
        alu(ir::Op::Add, ir::Operand::reg_(ir::Reg::Rax), ir::Operand::imm_(1),
            ir::Size::S8),                                           // al+1 -> 0x...7788（高位保留）
        mov_imm(ir::Reg::Rdx, static_cast<i64>(0xDEADBEEFCAFEBABEull), ir::Size::S64),
        mov_imm(ir::Reg::Rdx, 2, ir::Size::S32),                     // S32 写零扩展 -> 2
        alu(ir::Op::Xor, ir::Operand::reg_(ir::Reg::Rcx), ir::Operand::reg_(ir::Reg::Rcx),
            ir::Size::S64),                                          // rcx=0
        alu(ir::Op::Or, ir::Operand::reg_(ir::Reg::Rcx), ir::Operand::imm_(0x1234),
            ir::Size::S64),                                          // rcx=0x1234
    })}));
    EXPECT_EQ(vm.regs[kRax], 0x1122334455667788ull); // S8 写合并：高位未被破坏
    EXPECT_EQ(vm.regs[kRdx], 2ull);                  // S32 写零扩展
    EXPECT_EQ(vm.regs[kRcx], 0x1234ull);
}

TEST(RefVmE2E, LoopSumWithBackwardJcc) {
    // 循环求和：rcx=5 倒数到 0，rax 累加 5+4+3+2+1=15。
    auto vm = run_fn(fn_of({
        blk(0x1000,
            {mov_imm(ir::Reg::Rcx, 5, ir::Size::S32),
             mov_imm(ir::Reg::Rax, 0, ir::Size::S32),
             jump(ir::Op::Jmp, 0x2000, ir::Cond::Ne)}),
        blk(0x2000,
            {alu(ir::Op::Add, ir::Operand::reg_(ir::Reg::Rax),
                 ir::Operand::reg_(ir::Reg::Rcx), ir::Size::S32),
             alu(ir::Op::Sub, ir::Operand::reg_(ir::Reg::Rcx), ir::Operand::imm_(1),
                 ir::Size::S32),
             alu(ir::Op::Cmp, ir::Operand::reg_(ir::Reg::Rcx), ir::Operand::imm_(0),
                 ir::Size::S32),
             jump(ir::Op::Jcc, 0x2000)}),
    }));
    EXPECT_EQ(vm.regs[kRax], 15ull);
    EXPECT_EQ(vm.regs[kRcx], 0ull);
    EXPECT_GT(vm.steps, 5 * 4); // 确认回跳真实执行了多轮
}

} // namespace
