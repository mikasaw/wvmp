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
    // MIT-451 (X5b) B.2：x64 栈深 walk budget=0（无 guard）——区内 push 即
    // gate note（D4 双 arch 对称；展开形本身不变，本用例继续钉字节码形状）。
    ASSERT_EQ(r.notes.size(), static_cast<size_t>(1));
    EXPECT_NE(r.notes[0].find("stack-depth-gate"), std::string::npos);
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

// MIT-438 (X1b) B.3: ret imm16 清栈语义 — translator 层派发矩阵。
// lifter 已把 imm 放进 IR.src（x86/x64 双 arch 共享 translate_ret），translator
// 经 aux 槽传运行时（D2 选型 (i)），imm=0 ≡ plain ret。双 arch = S64（x64
// pointer 宽）与 S32（x86 pointer 宽）两个 size 形态同路径。
namespace {
ir::Insn ret_imm(i64 v, ir::Size sz) {
    ir::Insn i = I(ir::Op::Ret, sz);
    i.src = ir::Operand::imm_(v);
    return i;
}
}  // namespace

TEST(Translate, RetImmCarriedInAux) {
    // x64 形（S64）：ret 8 → aux=8，其余槽同 plain ret。
    const auto r = wvmp::regvm::translator::translate_function(fn_of({
        blk(0x1000, {ret_imm(8, ir::Size::S64)}),
    }));
    EXPECT_TRUE(r.notes.empty());
    const Decoded d = decode_program(r.program);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(2));  // Ret + 尾部 Halt
    expect_is(d.insns[0], VmOp::Ret, OpKind::None, 0, OpKind::None, 0, 8, kS64);
    expect_is(d.insns[1], VmOp::Halt, OpKind::None, 0, OpKind::None, 0, 0, 0);
}

TEST(Translate, RetImmX86ShapeS32Dispatch) {
    // x86 形（S32，pointer_size(X86)）：ret 0x1234 → aux 同值。imm 恒按字节
    // 加 rsp（SDM C2 iw），arch 差异仅在 pop 宽度（X4 asmgen 参数化面）。
    const auto r = wvmp::regvm::translator::translate_function(fn_of({
        blk(0x1000, {ret_imm(0x1234, ir::Size::S32)}),
    }));
    EXPECT_TRUE(r.notes.empty());
    const Decoded d = decode_program(r.program);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(2));
    expect_is(d.insns[0], VmOp::Ret, OpKind::None, 0, OpKind::None, 0, 0x1234, kS32);
}

TEST(Translate, RetImmZeroAndMaxBoundary) {
    // D3 边界：imm=0 ≡ plain ret（aux=0）；imm=0xFFFF（C2 iw 上界）全宽保留。
    {
        const auto r = wvmp::regvm::translator::translate_function(fn_of({
            blk(0x1000, {ret_imm(0, ir::Size::S64)}),
        }));
        const Decoded d = decode_program(r.program);
        ASSERT_EQ(d.insns.size(), static_cast<size_t>(2));
        expect_is(d.insns[0], VmOp::Ret, OpKind::None, 0, OpKind::None, 0, 0, kS64);
    }
    {
        const auto r = wvmp::regvm::translator::translate_function(fn_of({
            blk(0x1000, {ret_imm(0xFFFF, ir::Size::S64)}),
        }));
        const Decoded d = decode_program(r.program);
        ASSERT_EQ(d.insns.size(), static_cast<size_t>(2));
        expect_is(d.insns[0], VmOp::Ret, OpKind::None, 0, OpKind::None, 0, 0xFFFF, kS64);
    }
}

TEST(Translate, RetImmMaskedToImm16Width) {
    // 防御性掩码：编码域只有 imm16（C2 iw），>0xFFFF 的 IR.src（不可能由
    // capstone 产生）按 16 位掩码保留低 16 位——与硬件编码域行为一致
    // （运行时加幅永不超 SDM 定义域）。
    const auto r = wvmp::regvm::translator::translate_function(fn_of({
        blk(0x1000, {ret_imm(0x1'2345, ir::Size::S64)}),
    }));
    const Decoded d = decode_program(r.program);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(2));
    expect_is(d.insns[0], VmOp::Ret, OpKind::None, 0, OpKind::None, 0, 0x2345, kS64);
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

// MIT-249: 直接 call emit CallGate 不记 note（CallDirectEmitsCallGate）。
// MIT-445 (X3c B.1): 间接 call（dst=Reg）442 D4 停手 skip 翻案 —— emit
// CallGate reg 形（a_kind=Reg + reg_a=目标槽），零 note 零 gate。
TEST(Translate, CallIndirectRegEmitsCallGateRegForm) {
    ir::Insn c = I(ir::Op::Call, ir::Size::S64);
    c.dst = ir::Operand::reg_(ir::Reg::Rax); // 间接 call：目标 = 槽内绝对 VA
    const auto r = wvmp::regvm::translator::translate_function(
        fn_of({blk(0x1000, {c})}));
    EXPECT_TRUE(r.notes.empty());
    const Decoded d = decode_program(r.program);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(3));  // 1 + Jmp + Halt
    expect_is(d.insns[0], VmOp::CallGate, OpKind::Reg,
              isa::vm_reg_of(ir::Reg::Rax), OpKind::None, 0, 0u, 0u);
}

// ---------------- rip-relative (M2-8 支持：RVA = next_ip + disp) ----------------
// 块内单条 [rip+disp]：翻译期算出绝对 RVA，立即数进字节码（运行时
// Load/Store 汇编加 VmContext.scratch_mem=image_base 还原 VA）。
TEST(Translate, RipRelativeEncodesAbsoluteRVA) {
    // mov rax, [rip+8] -> IR Load（base=Rip）。
    //   insn.addr = 0x1000; 单块单条; next_ip = fn.end_rva = 0x3000
    //   disp = +8; RVA = 0x3000 + 8 = 0x3008
    ir::Insn ld = I(ir::Op::Load, ir::Size::S64);
    ld.dst = ir::Operand::reg_(ir::Reg::Rax);
    ld.src = ir::Operand::mem_(m(ir::Reg::Rip, ir::Reg::Flags, 0, 8));
    const auto r = wvmp::regvm::translator::translate_function(
        fn_of({blk(0x1000, {ld})}));
    EXPECT_TRUE(r.notes.empty()) << "rip-relative M2-8 起翻译期不记 skip note";
    const Decoded d = decode_program(r.program);
    // 第一条应是 `Mov acc, imm(0x3008)`: 发射绝对 RVA, 运行时 [acc + image_base].
    ASSERT_GE(d.insns.size(), static_cast<size_t>(2));
    expect_is(d.insns[0], VmOp::Mov, OpKind::Reg, isa::kScratchFirst, OpKind::Imm, 0,
              0x3008, kS64);
}

TEST(Translate, RipRelativeNegativeDisp) {
    // 块内两条: insn0 @0x1000 ([rip-4] 读) + insn1 @0x1004 (ret).
    // insn0 next_ip = 0x1004; disp=-4; RVA = 0x1000; 直接进 aux.
    ir::Insn ld = I(ir::Op::Load, ir::Size::S64);
    ld.addr = 0x1000;
    ld.dst = ir::Operand::reg_(ir::Reg::Rax);
    ld.src = ir::Operand::mem_(m(ir::Reg::Rip, ir::Reg::Flags, 0, -4));
    ir::Insn ret = I(ir::Op::Ret, ir::Size::S64);
    ret.addr = 0x1004;
    const auto r = wvmp::regvm::translator::translate_function(
        fn_of({blk(0x1000, {ld, ret})}));
    EXPECT_TRUE(r.notes.empty());
    const Decoded d = decode_program(r.program);
    ASSERT_GE(d.insns.size(), static_cast<size_t>(3));
    expect_is(d.insns[0], VmOp::Mov, OpKind::Reg, isa::kScratchFirst, OpKind::Imm, 0,
              0x1000, kS64);  // base=0x1000 = next_ip(0x1004) + disp(-4)
}

// MIT-322: rip-relative lea 翻译期发 RVA, 运行时用 VmOp::LeaRva 自动加
// image_base 还原 VA. 修复前 `lea rcx, [rip+disp]` 翻译后只发 RVA 进
// rcx, 后续非 rip `[rcx + ...]` Load 把 rcx 当绝对 VA 访存 (M2-8 起
// Load/Store 不再加 scratch_mem), 读到低地址 → SIGSEGV.
// 翻译后两条: `Mov acc, imm(RVA)` + `LeaRva rcx, acc` —— 第二条让运行时
// 把 RVA 转 VA 后写回 rcx 槽.
TEST(Translate, LeaRipRelativeEmitsLeaRva) {
    // lea rcx, [rip + 0x1234] -> IR Lea (base=Rip, disp=0x1234).
    //   insn.addr = 0x1000; 单块单条; next_ip = fn.end_rva = 0x3000
    //   RVA = 0x3000 + 0x1234 = 0x4234
    ir::Insn lea = I(ir::Op::Lea, ir::Size::S64);
    lea.dst = ir::Operand::reg_(ir::Reg::Rcx);
    lea.src = ir::Operand::mem_(m(ir::Reg::Rip, ir::Reg::Flags, 0, 0x1234));
    const auto r = wvmp::regvm::translator::translate_function(
        fn_of({blk(0x1000, {lea})}));
    EXPECT_TRUE(r.notes.empty()) << "rip-relative lea M2-8 起翻译期不记 skip note";
    const Decoded d = decode_program(r.program);
    // 第一条: Mov acc, imm(0x4234) —— acc 持有 RVA
    ASSERT_GE(d.insns.size(), static_cast<size_t>(2));
    expect_is(d.insns[0], VmOp::Mov, OpKind::Reg, isa::kScratchFirst, OpKind::Imm, 0,
              0x4234, kS64);
    // 第二条: LeaRva rcx, acc —— 运行时 acc + image_base → VA 写回 rcx 槽
    expect_is(d.insns[1], VmOp::LeaRva, OpKind::Reg, kRcx, OpKind::Reg,
              isa::kScratchFirst, 0, kS64);
}

// 非 rip lea 保持原 `Mov dst, acc` 路径 (acc 已是 VA).
TEST(Translate, LeaNonRipStaysPlainMov) {
    // lea rax, [rbx + rcx*4 + 0x20] (S64, 纯寄存器, 无访存)
    ir::Insn lea = I(ir::Op::Lea, ir::Size::S64);
    lea.dst = ir::Operand::reg_(ir::Reg::Rax);
    lea.src = ir::Operand::mem_(m(ir::Reg::Rbx, ir::Reg::Rcx, 4, 0x20));
    const Decoded d = one_insn(lea);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(8)); // 6 + Jmp + Halt
    // 末条 `Mov rax, scratch0`: 非 rip lea 不走 LeaRva (acc 已是 VA).
    expect_is(d.insns[5], VmOp::Mov, OpKind::Reg, kRax, OpKind::Reg,
              isa::kScratchFirst, 0, kS64);
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

// ---------------- Call (MIT-249 call gate) ----------------

// 直接 call <imm>：aux = target RVA, cond_or_size = 0（arg_count v1 固定 0）。
// 2 块布局: b0@0x1000 (call), b1@0x2000 (ret) → next_ip(call) = 0x2000。
// dst.imm = 绝对目标 RVA（lifter 约定与 jcc/jmp 一致，Capstone 给的是绝对地址
// 不是位移——这是 Capstone 默认行为，jcc/jmp 都按绝对目标处理）；
// 这里 dst.imm = 0x2000 即直接 target = b1@0x2000；运行时 handler 加
// image_base 还原 VA。
TEST(Translate, CallDirectEmitsCallGate) {
    ir::Insn c = I(ir::Op::Call, ir::Size::S64);
    c.dst = ir::Operand::imm_(0x2000);
    const auto r = wvmp::regvm::translator::translate_function(
        fn_of({blk(0x1000, {c}),
               blk(0x2000, {[] {
                   ir::Insn r = I(ir::Op::Ret, ir::Size::S64);
                   return r;
               }()})}));
    EXPECT_TRUE(r.notes.empty());
    const Decoded d = decode_program(r.program);
    ASSERT_GE(d.insns.size(), static_cast<size_t>(1));
    expect_is(d.insns[0], VmOp::CallGate, OpKind::None, 0, OpKind::None, 0,
              0x2000u, 0u);
}

// MIT-445 (X3c B.1): call [mem] rip 形（IAT thunk 同构）折条 =
// Mov acc,RVA + LoadRva val←acc + CallGate reg 形。载入槽值 = 表项内容 =
// 目标函数绝对 VA（handler reg 形不再二次加 base）。
TEST(Translate, CallMemRipFoldsLoadRvaCallGateRegForm) {
    // 单块: next_ip = fn.end_rva = 0x3000 → RVA = 0x3000 + 8 = 0x3008
    ir::Insn c = I(ir::Op::Call, ir::Size::S64);
    c.dst = ir::Operand::mem_(m(ir::Reg::Rip, ir::Reg::Flags, 0, 8));
    const auto r = wvmp::regvm::translator::translate_function(
        fn_of({blk(0x1000, {c})}));
    EXPECT_TRUE(r.notes.empty());
    const Decoded d = decode_program(r.program);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(5));  // 3 + Jmp + Halt
    expect_is(d.insns[0], VmOp::Mov, OpKind::Reg, isa::kScratchFirst,
              OpKind::Imm, 0, 0x3008u, kS64);
    expect_is(d.insns[1], VmOp::LoadRva, OpKind::Reg, isa::kScratchFirst + 1,
              OpKind::Reg, isa::kScratchFirst, 0u, kS64);
    expect_is(d.insns[2], VmOp::CallGate, OpKind::Reg, isa::kScratchFirst + 1,
              OpKind::None, 0, 0u, 0u);
}

// MIT-445 (X3c B.1): call [mem] 非 rip 形（call [rbx+0x10]）折条 =
// Mov acc←rbx + Add acc,disp + Load val←acc + CallGate reg 形。
TEST(Translate, CallMemBaseFoldsLoadCallGateRegForm) {
    ir::Insn c = I(ir::Op::Call, ir::Size::S64);
    c.dst = ir::Operand::mem_(m(ir::Reg::Rbx, ir::Reg::Flags, 0, 0x10));
    const auto r = wvmp::regvm::translator::translate_function(
        fn_of({blk(0x1000, {c})}));
    EXPECT_TRUE(r.notes.empty());
    const Decoded d = decode_program(r.program);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(6));  // 4 + Jmp + Halt
    expect_is(d.insns[0], VmOp::Mov, OpKind::Reg, isa::kScratchFirst,
              OpKind::Reg, isa::vm_reg_of(ir::Reg::Rbx), 0u, kS64);
    expect_is(d.insns[1], VmOp::Add, OpKind::Reg, isa::kScratchFirst,
              OpKind::Imm, 0, 0x10u, kS64);
    expect_is(d.insns[2], VmOp::Load, OpKind::Reg, isa::kScratchFirst + 1,
              OpKind::Reg, isa::kScratchFirst, 0u, kS64);
    expect_is(d.insns[3], VmOp::CallGate, OpKind::Reg, isa::kScratchFirst + 1,
              OpKind::None, 0, 0u, 0u);
}

// ---------------- MIT-413 (G2): 跳转表残余形态匹配器 ----------------

// 设置 insn 地址（I() 默认 0x401000；本组测试的 next_ip_of 依赖块内布局）。
ir::Insn at(ir::Insn i, u64 a) {
    i.addr = a;
    return i;
}

// G2 测试夹具：区域 [0x1000, 0x3000)，表体 RVA 0x2000（测试内表位置不影响
// 匹配——read_fn 是假读，仅目标 RVA 参与区判据）。块布局（布局序 = 地址序）：
//   b0 @0x1000 防御: [mov rax,[rsp+8]; cmp rax,7; ja 0x2008]（尾部 cmp+ja）
//   b1 @0x1020 表块:  形态由测试自定（il@0x1020 7B / lea@0x1027 7B →
//                      lea 目标 = 0x102E+disp = 0x2000 / 表读 / [add] / jmp）
//   b2..b9 case body @0x1100..0x1170（每块 16 字节错开）
//   b10 @0x2008 default；b11 @0x2010 join（nop 收尾 → fallthrough → Halt）
struct G2JtFixture {
    ir::FunctionRegion fn;
    G2JtFixture(ir::BasicBlock tail_block, ir::BasicBlock prev_block) {
        std::vector<ir::BasicBlock> blocks;
        blocks.push_back(std::move(prev_block));
        blocks.push_back(std::move(tail_block));
        for (u64 a = 0x1100; a < 0x1180; a += 0x10)
            blocks.push_back(blk(a, {at(mov_imm(ir::Reg::Rax, 0x10 + a, ir::Size::S64), a),
                                    at(jump(ir::Op::Jmp, 0x2010), a + 0xE)}));
        blocks.push_back(blk(0x2008,
                             {at(mov_imm(ir::Reg::Rax, 0xA5, ir::Size::S64), 0x2008),
                              at(jump(ir::Op::Jmp, 0x2010), 0x2010 - 2)}));
        blocks.push_back(blk(0x2010, {at(I(ir::Op::Nop, ir::Size::S64), 0x2010)}));
        fn = fn_of(std::move(blocks));
    }
};

// 防御块（idx=rax）：mov rax,[rsp+8] + cmp rax,7 + ja default。
ir::BasicBlock g2_defense_block() {
    return blk(0x1000, {at(mov(ir::Reg::Rax, ir::Reg::Rsp, ir::Size::S64), 0x1000),
                        at(alu(ir::Op::Cmp, ir::Operand::reg_(ir::Reg::Rax),
                               ir::Operand::imm_(7), ir::Size::S64),
                           0x1003),
                        at(jump(ir::Op::Jcc, 0x2008, ir::Cond::A), 0x1006)});
}

// 8B delta 表块（REG 源带 add；G2-a delta 语义）。
ir::BasicBlock g2_delta8_tail_block() {
    const ir::Insn il = at([] {
        ir::Insn i = I(ir::Op::Load, ir::Size::S64);
        i.dst = ir::Operand::reg_(ir::Reg::Rax);
        i.src = ir::Operand::mem_(m(ir::Reg::Rsp, ir::Reg::Flags, 0, 8));
        return i;
    }(), 0x1020);
    ir::Insn lea_i = I(ir::Op::Lea, ir::Size::S64);
    lea_i.addr = 0x1027;
    lea_i.dst = ir::Operand::reg_(ir::Reg::Rcx);
    lea_i.src = ir::Operand::mem_(m(ir::Reg::Rip, ir::Reg::Flags, 0, 0xFD2));
    const ir::Insn ld = at([] {
        ir::Insn i = I(ir::Op::Load, ir::Size::S64);
        i.dst = ir::Operand::reg_(ir::Reg::Rax);
        i.src = ir::Operand::mem_(m(ir::Reg::Rcx, ir::Reg::Rax, 8, 0));
        return i;
    }(), 0x102E);
    const ir::Insn add_i = at(alu(ir::Op::Add, ir::Operand::reg_(ir::Reg::Rax),
                                  ir::Operand::reg_(ir::Reg::Rcx), ir::Size::S64),
                              0x1033);
    const ir::Insn j = at([] {
        ir::Insn i = I(ir::Op::Jmp, ir::Size::S64);
        i.dst = ir::Operand::reg_(ir::Reg::Rax);
        return i;
    }(), 0x1036);
    return blk(0x1020, {il, lea_i, ld, add_i, j});
}

// 8B 绝对 VA 表块（REG 源无 add；G2-a abs 语义）。
ir::BasicBlock g2_abs8_tail_block() {
    const ir::Insn il = at([] {
        ir::Insn i = I(ir::Op::Load, ir::Size::S64);
        i.dst = ir::Operand::reg_(ir::Reg::Rax);
        i.src = ir::Operand::mem_(m(ir::Reg::Rsp, ir::Reg::Flags, 0, 8));
        return i;
    }(), 0x1020);
    ir::Insn lea_i = I(ir::Op::Lea, ir::Size::S64);
    lea_i.addr = 0x1027;
    lea_i.dst = ir::Operand::reg_(ir::Reg::Rcx);
    lea_i.src = ir::Operand::mem_(m(ir::Reg::Rip, ir::Reg::Flags, 0, 0xFD2));
    const ir::Insn ld = at([] {
        ir::Insn i = I(ir::Op::Load, ir::Size::S64);
        i.dst = ir::Operand::reg_(ir::Reg::Rax);
        i.src = ir::Operand::mem_(m(ir::Reg::Rcx, ir::Reg::Rax, 8, 0));
        return i;
    }(), 0x102E);
    const ir::Insn j = at([] {
        ir::Insn i = I(ir::Op::Jmp, ir::Size::S64);
        i.dst = ir::Operand::reg_(ir::Reg::Rax);
        return i;
    }(), 0x1033);
    return blk(0x1020, {il, lea_i, ld, j});
}

// MEM 源表块（G2-b）：il + lea + jmp [rcx+rax*8]。
ir::BasicBlock g2_mem_tail_block() {
    const ir::Insn il = at([] {
        ir::Insn i = I(ir::Op::Load, ir::Size::S64);
        i.dst = ir::Operand::reg_(ir::Reg::Rax);
        i.src = ir::Operand::mem_(m(ir::Reg::Rsp, ir::Reg::Flags, 0, 8));
        return i;
    }(), 0x1020);
    ir::Insn lea_i = I(ir::Op::Lea, ir::Size::S64);
    lea_i.addr = 0x1027;
    lea_i.dst = ir::Operand::reg_(ir::Reg::Rcx);
    lea_i.src = ir::Operand::mem_(m(ir::Reg::Rip, ir::Reg::Flags, 0, 0xFD2));
    const ir::Insn j = at([] {
        ir::Insn i = I(ir::Op::Jmp, ir::Size::S64);
        i.dst = ir::Operand::mem_(m(ir::Reg::Rcx, ir::Reg::Rax, 8, 0));
        return i;
    }(), 0x102E);
    return blk(0x1020, {il, lea_i, j});
}

// 假表读取：rva 必须 0x2000，越界即 nullopt（保守 gate 路径）。
wvmp::regvm::translator::JumpTableReadFn g2_read_fn(std::vector<u64> tbl) {
    return [tbl = std::move(tbl)](u64 rva, u32 i, u8 width)
               -> std::optional<u64> {
        if (rva != 0x2000 || i >= tbl.size()) return std::nullopt;
        if (width == 8) return tbl[i];
        if (width == 4) return static_cast<u32>(tbl[i]);
        return std::nullopt;
    };
}

// 表目标：0x1100 + i*0x10（8 项，∈ [0x1000,0x3000) 且为 case body 块首）。
std::vector<u64> g2_targets() {
    std::vector<u64> v;
    for (u64 t = 0x1100; t < 0x1180; t += 0x10) v.push_back(t);
    return v;
}

// ---- MIT-451 (X5b) B.3: x86 S32 匹配器翻正单测 -----------------------
// x86 尾块形态（MSVC x86 布局）：il(S32) + mov ecx, imm32 绝对 VA 基址 +
// 表读(S32) [+ add edx,ecx] + jmp edx。防御块同构 S32。

ir::BasicBlock g2x_defense_block() {
    return blk(0x1000, {at(mov(ir::Reg::Rax, ir::Reg::Rsp, ir::Size::S32), 0x1000),
                        at(alu(ir::Op::Cmp, ir::Operand::reg_(ir::Reg::Rax),
                               ir::Operand::imm_(7), ir::Size::S32),
                           0x1003),
                        at(jump(ir::Op::Jcc, 0x2008, ir::Cond::A), 0x1006)});
}

// x86 delta 4B 尾块：mov ecx, VA(0x402000) / mov edx,[ecx+eax*4] /
// add edx,ecx / jmp edx。
ir::BasicBlock g2x_delta4_tail_block() {
    const ir::Insn il = at([] {
        ir::Insn i = I(ir::Op::Load, ir::Size::S32);
        i.dst = ir::Operand::reg_(ir::Reg::Rax);
        i.src = ir::Operand::mem_(m(ir::Reg::Rsp, ir::Reg::Flags, 0, 8));
        return i;
    }(), 0x1020);
    const ir::Insn base = at(mov_imm(ir::Reg::Rcx, 0x402000, ir::Size::S32), 0x1027);
    const ir::Insn ld = at([] {
        ir::Insn i = I(ir::Op::Load, ir::Size::S32);
        i.dst = ir::Operand::reg_(ir::Reg::Rdx);
        i.src = ir::Operand::mem_(m(ir::Reg::Rcx, ir::Reg::Rax, 4, 0));
        return i;
    }(), 0x102c);
    const ir::Insn add_i = at(alu(ir::Op::Add, ir::Operand::reg_(ir::Reg::Rdx),
                                  ir::Operand::reg_(ir::Reg::Rcx), ir::Size::S32),
                              0x1031);
    const ir::Insn j = at([] {
        ir::Insn i = I(ir::Op::Jmp, ir::Size::S32);
        i.dst = ir::Operand::reg_(ir::Reg::Rdx);
        return i;
    }(), 0x1034);
    return blk(0x1020, {il, base, ld, add_i, j});
}

// x86 abs 4B 尾块（无 add）。
ir::BasicBlock g2x_abs4_tail_block() {
    const ir::Insn il = at([] {
        ir::Insn i = I(ir::Op::Load, ir::Size::S32);
        i.dst = ir::Operand::reg_(ir::Reg::Rax);
        i.src = ir::Operand::mem_(m(ir::Reg::Rsp, ir::Reg::Flags, 0, 8));
        return i;
    }(), 0x1020);
    const ir::Insn base = at(mov_imm(ir::Reg::Rcx, 0x402000, ir::Size::S32), 0x1027);
    const ir::Insn ld = at([] {
        ir::Insn i = I(ir::Op::Load, ir::Size::S32);
        i.dst = ir::Operand::reg_(ir::Reg::Rdx);
        i.src = ir::Operand::mem_(m(ir::Reg::Rcx, ir::Reg::Rax, 4, 0));
        return i;
    }(), 0x102c);
    const ir::Insn j = at([] {
        ir::Insn i = I(ir::Op::Jmp, ir::Size::S32);
        i.dst = ir::Operand::reg_(ir::Reg::Rdx);
        return i;
    }(), 0x1031);
    return blk(0x1020, {il, base, ld, j});
}

ir::FunctionRegion g2x_fn_of(ir::BasicBlock tail, ir::BasicBlock prev) {
    ir::FunctionRegion fn = fn_of({std::move(prev), std::move(tail)});
    // case body / default / join 块复用 x64 夹具布局（x86 匹配器只看尾块
    // 形态 + 目标区判据；case body 指令尺寸不参与匹配）。
    std::vector<ir::BasicBlock> blocks;
    blocks.push_back(fn.blocks[0]);
    blocks.push_back(fn.blocks[1]);
    for (u64 a = 0x1100; a < 0x1180; a += 0x10)
        blocks.push_back(blk(a, {at(mov_imm(ir::Reg::Rax, 0x10 + a, ir::Size::S32), a),
                                 at(jump(ir::Op::Jmp, 0x2010), a + 0xE)}));
    blocks.push_back(blk(0x2008,
                         {at(mov_imm(ir::Reg::Rax, 0xA5, ir::Size::S32), 0x2008),
                          at(jump(ir::Op::Jmp, 0x2010), 0x2010 - 2)}));
    blocks.push_back(blk(0x2010, {at(I(ir::Op::Nop, ir::Size::S32), 0x2010)}));
    fn.blocks = std::move(blocks);
    fn.arch = ir::Arch::X86;
    return fn;
}

TEST(Translate, JumpTableX86Delta4RegExpandsChain) {
    // B.3 翻正面①：x86 4B delta 表（负 delta = dword 回绕，MSVC .text 尾
    // 随表布局）→ 匹配 + 8 拍比较链；X4 交接注记"匹配器 S64 硬判"修正面。
    ir::FunctionRegion fn = g2x_fn_of(g2x_delta4_tail_block(), g2x_defense_block());
    std::vector<u64> tbl;
    for (u64 t : g2_targets())
        tbl.push_back(static_cast<u32>(t - 0x2000));  // 负 delta 2 的补码
    const auto r = wvmp::regvm::translator::translate_function(
        fn, wvmp::regvm::translator::FunctionUpperBoundFn{}, g2_read_fn(tbl),
        0x400000);
    ASSERT_EQ(r.notes.size(), static_cast<size_t>(1));
    EXPECT_NE(r.notes[0].find("jump-table @ 0x2000 entries=8 reg-4B-delta"),
              std::string::npos);
    const Decoded d = decode_program(r.program);
    size_t first = d.insns.size();
    for (size_t i = 0; i < d.insns.size(); ++i)
        if (d.insns[i].op == VmOp::Mov && d.insns[i].b_kind == OpKind::Imm &&
            d.insns[i].aux == 0x1100) {
            first = i;
            break;
        }
    ASSERT_LT(first, d.insns.size());
    const auto& g = d.insns;
    size_t jcc_e = 0;
    for (size_t i = first; i + 4 <= g.size() && jcc_e < 8; i += 4) {
        if (g[i].op == VmOp::Mov && g[i + 1].op == VmOp::LeaRva &&
            g[i + 2].op == VmOp::Cmp && g[i + 3].op == VmOp::Jcc &&
            g[i + 3].cond_or_size == static_cast<u8>(ir::Cond::E))
            ++jcc_e;
    }
    EXPECT_EQ(jcc_e, 8u);
    EXPECT_EQ(g.back().op, VmOp::Halt);
}

TEST(Translate, JumpTableX86Abs4RegExpandsChain) {
    // B.3 翻正面②：x86 4B 绝对 VA 表（无 add）→ AbsVa 语义（项 − image_base）。
    ir::FunctionRegion fn = g2x_fn_of(g2x_abs4_tail_block(), g2x_defense_block());
    std::vector<u64> tbl;
    for (u64 t : g2_targets()) tbl.push_back(0x400000 + t);  // 绝对 VA 项
    const auto r = wvmp::regvm::translator::translate_function(
        fn, wvmp::regvm::translator::FunctionUpperBoundFn{}, g2_read_fn(tbl),
        0x400000);
    ASSERT_EQ(r.notes.size(), static_cast<size_t>(1));
    EXPECT_NE(r.notes[0].find("jump-table @ 0x2000 entries=8 reg-4B-abs"),
              std::string::npos);
}

TEST(Translate, JumpTableX64Delta4WrapStaysS64Face) {
    // 对账面：x64 8B delta signed 语义不受 4B 回绕修正影响（既有用例
    // JumpTable8DeltaRegExpandsChain 继续钉 x64 面；本用例钉 4B 回绕只在
    // width==4 分支）。
    ir::FunctionRegion fn = g2x_fn_of(g2x_delta4_tail_block(), g2x_defense_block());
    fn.arch = ir::Arch::X64;  // x64 匹配器要求 S64 形态 → S32 尾块不匹配
    std::vector<u64> tbl;
    for (u64 t : g2_targets()) tbl.push_back(static_cast<u32>(t - 0x2000));
    const auto r = wvmp::regvm::translator::translate_function(
        fn, wvmp::regvm::translator::FunctionUpperBoundFn{}, g2_read_fn(tbl),
        0x400000);
    // S32 add 不满足 x64 ptr_sz → 匹配器 nullopt → 间接 jmp 既有 gate note
    // （x64 形态面零变化对账）。
    ASSERT_GE(r.notes.size(), static_cast<size_t>(1));
    EXPECT_NE(r.notes[0].find("间接 jmp 未支持"), std::string::npos);
}


TEST(Translate, JumpTable8DeltaRegExpandsChain) {
    // G2-a: 8B delta（REG 源带 add）。表项 = 目标 − 表基址(0x2000)（负值
    // 两补码——8B signed 语义）。验证: ok note + 8×[Mov s,rva; LeaRva;
    // Cmp t,s; Jcc eq] + 链尾 Halt。
    G2JtFixture fx(g2_delta8_tail_block(), g2_defense_block());
    std::vector<u64> tbl;
    for (u64 t : g2_targets()) tbl.push_back(t - 0x2000); // 8B signed 负 delta
    const auto r = wvmp::regvm::translator::translate_function(
        fx.fn, wvmp::regvm::translator::FunctionUpperBoundFn{}, g2_read_fn(tbl), 0);
    ASSERT_EQ(r.notes.size(), static_cast<size_t>(1));
    EXPECT_NE(r.notes[0].find("jump-table @ 0x2000 entries=8 reg-8B-delta"),
              std::string::npos);
    const Decoded d = decode_program(r.program);
    // 链首：Mov s,0x1100（首个 aux==0x1100 的 Mov-imm；il/lea/地址计算的
    // Mov-imm aux 分别为 0x2000/位移等，均不冲突）
    size_t first = d.insns.size();
    for (size_t i = 0; i < d.insns.size(); ++i)
        if (d.insns[i].op == VmOp::Mov && d.insns[i].b_kind == OpKind::Imm &&
            d.insns[i].aux == 0x1100) {
            first = i;
            break;
        }
    ASSERT_LT(first, d.insns.size());
    const auto& g = d.insns;
    // 从链首按 4 拍步进，逐拍核对 [Mov s,rva; LeaRva s,s; Cmp t,s; Jcc eq]
    size_t jcc_e = 0;
    for (size_t i = first; i + 4 <= g.size() && jcc_e < 8; i += 4) {
        if (g[i].op == VmOp::Mov && g[i].b_kind == OpKind::Imm &&
            g[i + 1].op == VmOp::LeaRva && g[i + 2].op == VmOp::Cmp &&
            g[i + 3].op == VmOp::Jcc &&
            g[i + 3].cond_or_size == static_cast<u8>(ir::Cond::E))
            ++jcc_e;
    }
    EXPECT_EQ(jcc_e, 8u);
    EXPECT_EQ(g[first + 1].op, VmOp::LeaRva);
    EXPECT_EQ(g[first + 2].op, VmOp::Cmp);
    EXPECT_EQ(g[first + 3].op, VmOp::Jcc);
    EXPECT_EQ(g.back().op, VmOp::Halt);
}

TEST(Translate, JumpTable8AbsRegExpandsChain) {
    // G2-a: 8B 绝对 VA（REG 源无 add）。表项 = 完整 VA → 目标 RVA = 表项
    // − image_base(0x140000000)。验证 ok note + 8 条 Jcc(E) + Halt。
    G2JtFixture fx(g2_abs8_tail_block(), g2_defense_block());
    const u64 kImageBase = 0x140000000ull;
    std::vector<u64> tbl;
    for (u64 t : g2_targets()) tbl.push_back(kImageBase + t);
    const auto r = wvmp::regvm::translator::translate_function(
        fx.fn, wvmp::regvm::translator::FunctionUpperBoundFn{}, g2_read_fn(tbl),
        kImageBase);
    ASSERT_EQ(r.notes.size(), static_cast<size_t>(1));
    EXPECT_NE(r.notes[0].find("jump-table @ 0x2000 entries=8 reg-8B-abs"),
              std::string::npos);
    const Decoded d = decode_program(r.program);
    size_t jcc_e = 0;
    for (const VmInsn& g : d.insns)
        if (g.op == VmOp::Jcc && g.cond_or_size == static_cast<u8>(ir::Cond::E))
            ++jcc_e;
    EXPECT_EQ(jcc_e, 8u);
    EXPECT_EQ(d.insns.back().op, VmOp::Halt);
}

TEST(Translate, JumpTableMemAbsExpandsChain) {
    // G2-b: `jmp [rcx+rax*8]` mem 源直跳 + 绝对 VA 表项。链前缀须物化表项：
    // Mov s,rax; Shl s,3; Add s,rcx; Load t,[s]（无 add/无锚定——表项即 VA）。
    G2JtFixture fx(g2_mem_tail_block(), g2_defense_block());
    const u64 kImageBase = 0x140000000ull;
    std::vector<u64> tbl;
    for (u64 t : g2_targets()) tbl.push_back(kImageBase + t);
    const auto r = wvmp::regvm::translator::translate_function(
        fx.fn, wvmp::regvm::translator::FunctionUpperBoundFn{}, g2_read_fn(tbl),
        kImageBase);
    ASSERT_EQ(r.notes.size(), static_cast<size_t>(1));
    EXPECT_NE(r.notes[0].find("jump-table @ 0x2000 entries=8 mem-8B-abs"),
              std::string::npos);
    const Decoded d = decode_program(r.program);
    const auto& g = d.insns;
    // 指令流前缀：b0 防御块 4 拍（Mov rax,rsp; Cmp rax,7; Jcc ja + 块尾
    // fallthrough Jmp+1）→ insns[4..6] = il 翻译（Mov acc,rsp; Add acc,8;
    // Load rax,acc），insns[7..8] = lea 翻译（Mov acc,0x2000; LeaRva
    // rcx,acc——直接进 dst 槽），insns[9..12] = 物化（Mov s,rax; Shl s,3;
    // Add s,rcx; Load t,[s]）。
    ASSERT_GE(g.size(), static_cast<size_t>(17));
    expect_is(g[9], VmOp::Mov, OpKind::Reg, isa::kScratchFirst, OpKind::Reg, kRax, 0,
              kS64);
    expect_is(g[10], VmOp::Shl, OpKind::Reg, isa::kScratchFirst, OpKind::Imm, 0, 3,
              kS64);
    expect_is(g[11], VmOp::Add, OpKind::Reg, isa::kScratchFirst, OpKind::Reg, kRcx, 0,
              kS64);
    expect_is(g[12], VmOp::Load, OpKind::Reg, isa::kScratchFirst + 1, OpKind::Reg,
              isa::kScratchFirst, 0, kS64);
    // 链首（s 复用为比较槽）：Mov s,0x1100; LeaRva s,s; Cmp t,s; Jcc(E)
    expect_is(g[13], VmOp::Mov, OpKind::Reg, isa::kScratchFirst, OpKind::Imm, 0,
              0x1100, kS64);
    expect_is(g[14], VmOp::LeaRva, OpKind::Reg, isa::kScratchFirst, OpKind::Reg,
              isa::kScratchFirst, 0, kS64);
    expect_is(g[15], VmOp::Cmp, OpKind::Reg, isa::kScratchFirst + 1, OpKind::Reg,
              isa::kScratchFirst, 0, kS64);
    // Jcc 的 aux 是回填后的相对偏移（非 0），只断言 op + cond。
    EXPECT_EQ(g[16].op, VmOp::Jcc);
    EXPECT_EQ(g[16].cond_or_size, static_cast<u8>(ir::Cond::E));
    size_t jcc_e = 0;
    for (const VmInsn& v : g)
        if (v.op == VmOp::Jcc && v.cond_or_size == static_cast<u8>(ir::Cond::E))
            ++jcc_e;
    EXPECT_EQ(jcc_e, 8u);
    EXPECT_EQ(g.back().op, VmOp::Halt);
}

TEST(Translate, JumpTableMemDeltaJmpExpandsChain) {
    // G2-b: mem 源 + delta-from-jmp 表项（GCC `.L4` 风格：项 = 目标 − jmp
    // 指令地址）。链前缀须物化 + 锚定：Add t,0x102E; LeaRva t,t 后与 REG 源
    // 共用同一条 LeaRva 比较链。
    G2JtFixture fx(g2_mem_tail_block(), g2_defense_block());
    const u64 kJmpRva = 0x102E;
    std::vector<u64> tbl;
    for (u64 t : g2_targets()) tbl.push_back(t - kJmpRva);
    const auto r = wvmp::regvm::translator::translate_function(
        fx.fn, wvmp::regvm::translator::FunctionUpperBoundFn{}, g2_read_fn(tbl), 0);
    ASSERT_EQ(r.notes.size(), static_cast<size_t>(1));
    EXPECT_NE(r.notes[0].find("jump-table @ 0x2000 entries=8 mem-8B-djmp"),
              std::string::npos);
    const Decoded d = decode_program(r.program);
    const auto& g = d.insns;
    // b0 防御块 4 拍 + il 3 拍 + lea 2 拍 + 物化 4 拍（g[9..12]）后，delta
    // 系追加锚定两拍（g[13..14]）：
    ASSERT_GE(g.size(), static_cast<size_t>(17));
    expect_is(g[13], VmOp::Add, OpKind::Reg, isa::kScratchFirst + 1, OpKind::Imm, 0,
              0x102E, kS64);
    expect_is(g[14], VmOp::LeaRva, OpKind::Reg, isa::kScratchFirst + 1, OpKind::Reg,
              isa::kScratchFirst + 1, 0, kS64);
    expect_is(g[15], VmOp::Mov, OpKind::Reg, isa::kScratchFirst, OpKind::Imm, 0,
              0x1100, kS64);
    size_t jcc_e = 0;
    for (const VmInsn& v : g)
        if (v.op == VmOp::Jcc && v.cond_or_size == static_cast<u8>(ir::Cond::E))
            ++jcc_e;
    EXPECT_EQ(jcc_e, 8u);
    EXPECT_EQ(g.back().op, VmOp::Halt);
}

TEST(Translate, JumpTableUndefendedGates) {
    // G2-c: 形态齐全但前块尾部无防御常数（无 cmp/ja）→ 表长不可推 →
    // 永久 gate；以"未检出防御常数"note 披露原因链（D2 裁决），不展开。
    // 防御块改为单条 mov（无 cmp+ja 尾部）。
    G2JtFixture fx(g2_delta8_tail_block(),
                   blk(0x1000, {at(mov(ir::Reg::Rax, ir::Reg::Rsp, ir::Size::S64),
                                   0x1000)}));
    const auto r = wvmp::regvm::translator::translate_function(
        fx.fn, wvmp::regvm::translator::FunctionUpperBoundFn{}, g2_read_fn({}), 0);
    ASSERT_FALSE(r.notes.empty());
    EXPECT_NE(r.notes[0].find("未检出防御常数"), std::string::npos);
    // gate：jmp 处无展开 → 无 Jcc(E) 比较链（lea 自身的 LeaRva 不受影响）
    const Decoded d = decode_program(r.program);
    EXPECT_EQ(d.insns.back().op, VmOp::Halt);
    for (const VmInsn& v : d.insns)
        if (v.op == VmOp::Jcc)
            EXPECT_NE(v.cond_or_size, static_cast<u8>(ir::Cond::E));
}

TEST(Translate, JumpTableOutOfRegionGates) {
    // 负例: 绝对 VA 表一项指向区域外（0x9000 ∈ .data）→ 全部候选不过区
    // 判据 → gate note（"不在区域/非指令地址"），不展开。
    G2JtFixture fx(g2_abs8_tail_block(), g2_defense_block());
    const u64 kImageBase = 0x140000000ull;
    std::vector<u64> tbl;
    const auto ts = g2_targets();
    for (size_t i = 0; i < ts.size(); ++i)
        tbl.push_back(kImageBase + (i == 3 ? 0x9000 : ts[i]));
    const auto r = wvmp::regvm::translator::translate_function(
        fx.fn, wvmp::regvm::translator::FunctionUpperBoundFn{}, g2_read_fn(tbl),
        kImageBase);
    ASSERT_FALSE(r.notes.empty());
    EXPECT_NE(r.notes[0].find("不在区域/非指令地址"), std::string::npos);
    // gate：无 Jcc(E) 比较链
    const Decoded d = decode_program(r.program);
    for (const VmInsn& v : d.insns)
        if (v.op == VmOp::Jcc)
            EXPECT_NE(v.cond_or_size, static_cast<u8>(ir::Cond::E));
}

// =============================================================================
// MIT-415 (G3): rep/repnz 串指令微程序展开 (D2: 零新 VmOp)
// =============================================================================
// lifter 编码约定: Op::Mov + src2=imm(family 0..4) + cond (E=rep/repe,
// Ne=repne) + size (元素宽) + dst/src 语义寄存器形态。展开 = 既有 VmOp
// 组合微循环: 预检 rcx==0 → 循环体 → 计数递减回边; scas/cmps 带末次比较
// flags 保存/恢复 + repne/repe 早退 (早退迭代不推进指针不减计数)。

// 串指令 IR 构造 (与 lifter translate_string_op 的编码对账)。
// MIT-442 (X2a): family ≥ 23 = plain 单发域 (kStrPlainBase), 操作数/flags 按
// 归一后 fam 选择 — 与 lifter 域值约定逐位对账。
ir::Insn str_op(int family, ir::Size sz, ir::Cond c = ir::Cond::E) {
    ir::Insn i = I(ir::Op::Mov, sz);
    i.cond = c;
    i.src2 = ir::Operand::imm_(family);
    const int norm = family >= 23 ? family - 23 : family;
    i.updates_flags = (norm == 2 || norm == 3);
    const ir::MemOperand rsi_m{ir::Reg::Rsi, ir::Reg::Flags, 0, 0};
    const ir::MemOperand rdi_m{ir::Reg::Rdi, ir::Reg::Flags, 0, 0};
    switch (norm) {
    case 0: i.dst = ir::Operand::mem_(rdi_m); i.src = ir::Operand::mem_(rsi_m); break;  // movs
    case 1: i.dst = ir::Operand::mem_(rdi_m); i.src = ir::Operand::reg_(ir::Reg::Rax); break;  // stos
    case 2: i.dst = ir::Operand::reg_(ir::Reg::Rax); i.src = ir::Operand::mem_(rdi_m); break;  // scas
    case 3: i.dst = ir::Operand::mem_(rsi_m); i.src = ir::Operand::mem_(rdi_m); break;  // cmps
    case 4: i.dst = ir::Operand::reg_(ir::Reg::Rax); i.src = ir::Operand::mem_(rsi_m); break;  // lods
    default: break;
    }
    return i;
}

// 单条指令函数产出（允许 notes — 串指令的 DF=0 披露 note 是预期产物）。
Decoded one_insn_n(const ir::Insn& i, std::vector<std::string>* notes_out = nullptr) {
    const auto r = wvmp::regvm::translator::translate_function(fn_of({blk(0x1000, {i})}));
    if (notes_out != nullptr) *notes_out = r.notes;
    EXPECT_EQ(r.program.entry_offset, 0u);
    return decode_program(r.program);
}

// 相对跳转 aux 断言 (条数差; 负值补码)。
void expect_rel(const VmInsn& v, i64 expect) {
    EXPECT_EQ(static_cast<int>(v.aux), static_cast<int>(expect));
}

// Jcc/Jmp 的 aux 是回填的相对条数差 — 与 expect_is 的 aux==0 断言互斥,
// 单独断言 (op + cond + rel 一并)。
void expect_jcc(const VmInsn& v, ir::Cond c, i64 rel) {
    EXPECT_EQ(v.op, VmOp::Jcc);
    EXPECT_EQ(v.cond_or_size, static_cast<u8>(c));
    expect_rel(v, rel);
}
void expect_jmp(const VmInsn& v, i64 rel) {
    EXPECT_EQ(v.op, VmOp::Jmp);
    expect_rel(v, rel);
}

TEST(Translate, StringMovsExpandsToMicroLoop) {
    // rep movsb (family 0, S8): GetFlags s0; Cmp rcx,0; Jcc E→restore;
    // loop{ Load t,[rsi]; Store [rdi],t; Add rsi,1; Add rdi,1; Sub rcx,1;
    //       Jcc Ne→loop } restore: SetFlags s0 (+ 块尾 Jmp+1 + Halt)。
    // 回边 aux = loop_pos - jcc_back (负); 预检 aux = restore0 - jcc0 (正)。
    const Decoded d = one_insn_n(str_op(0, ir::Size::S8));
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(12));  // 10 + Jmp + Halt
    const u8 s18 = isa::kScratchFirst;
    const u8 s19 = isa::kScratchFirst + 1;
    expect_is(d.insns[0], VmOp::GetFlags, OpKind::Reg, s18, OpKind::None, 0, 0, kS64);
    expect_is(d.insns[1], VmOp::Cmp, OpKind::Reg, kRcx, OpKind::Imm, 0, 0, kS64);
    expect_jcc(d.insns[2], ir::Cond::E, 7);  // 预检 → restore0 (idx 9)
    expect_is(d.insns[3], VmOp::Load, OpKind::Reg, s19, OpKind::Reg, isa::vm_reg_of(ir::Reg::Rsi), 0,
              static_cast<u8>(ir::Size::S8));
    expect_is(d.insns[4], VmOp::Store, OpKind::Reg, isa::vm_reg_of(ir::Reg::Rdi), OpKind::Reg, s19, 0,
              static_cast<u8>(ir::Size::S8));
    expect_is(d.insns[5], VmOp::Add, OpKind::Reg, isa::vm_reg_of(ir::Reg::Rsi), OpKind::Imm, 0, 1, kS64);
    expect_is(d.insns[6], VmOp::Add, OpKind::Reg, isa::vm_reg_of(ir::Reg::Rdi), OpKind::Imm, 0, 1, kS64);
    expect_is(d.insns[7], VmOp::Sub, OpKind::Reg, kRcx, OpKind::Imm, 0, 1, kS64);
    expect_jcc(d.insns[8], ir::Cond::Ne, -5);  // 回边 → loop_pos (idx 3)
    expect_is(d.insns[9], VmOp::SetFlags, OpKind::Reg, s18, OpKind::None, 0, 0, kS64);
    expect_jmp(d.insns[10], 1);                // fallthrough
    expect_is(d.insns[11], VmOp::Halt, OpKind::None, 0, OpKind::None, 0, 0, 0);
}

TEST(Translate, StringMovsqUsesWidth8) {
    // rep movsq (family 0, S64): 元素宽 8 — Load/Store S64, 指针步长 8。
    const Decoded d = one_insn_n(str_op(0, ir::Size::S64));
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(12));
    expect_is(d.insns[3], VmOp::Load, OpKind::Reg, isa::kScratchFirst + 1,
              OpKind::Reg, isa::vm_reg_of(ir::Reg::Rsi), 0, kS64);
    expect_is(d.insns[4], VmOp::Store, OpKind::Reg, isa::vm_reg_of(ir::Reg::Rdi),
              OpKind::Reg, isa::kScratchFirst + 1, 0, kS64);
    expect_is(d.insns[5], VmOp::Add, OpKind::Reg, isa::vm_reg_of(ir::Reg::Rsi),
              OpKind::Imm, 0, 8, kS64);
    expect_is(d.insns[6], VmOp::Add, OpKind::Reg, isa::vm_reg_of(ir::Reg::Rdi),
              OpKind::Imm, 0, 8, kS64);
}

TEST(Translate, StringScasRepneEarlyExit) {
    // repne scasb (family 2, S8, cond Ne): loop{ Load t,[rdi]; Cmp rax,t;
    // GetFlags s1; Jcc E→exit_adv (早退: ZF==1); Add rdi,1; Sub rcx,1;
    // Jcc Ne→loop } SetFlags s1; Jmp→exit; exit_adv: Add rdi,1; Sub rcx,1;
    // SetFlags s1; Jmp→exit; restore0: SetFlags s0。
    // 早退迭代同样推进指针减计数 (native 实测语义 — RDI 指向匹配元素之后,
    // strlen `lea rax,[rdi-1]` 惯用法同证)。
    const Decoded d = one_insn_n(str_op(2, ir::Size::S8, ir::Cond::Ne));
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(19));  // 17 + Jmp + Halt
    const u8 s18 = isa::kScratchFirst;
    const u8 s19 = isa::kScratchFirst + 1;
    const u8 s20 = isa::kScratchFirst + 2;
    expect_is(d.insns[0], VmOp::GetFlags, OpKind::Reg, s18, OpKind::None, 0, 0, kS64);
    expect_is(d.insns[1], VmOp::Cmp, OpKind::Reg, kRcx, OpKind::Imm, 0, 0, kS64);
    expect_jcc(d.insns[2], ir::Cond::E, 14);  // 预检 → restore0 (idx 16)
    expect_is(d.insns[3], VmOp::Load, OpKind::Reg, s19, OpKind::Reg, isa::vm_reg_of(ir::Reg::Rdi), 0,
              static_cast<u8>(ir::Size::S8));
    expect_is(d.insns[4], VmOp::Cmp, OpKind::Reg, kRax, OpKind::Reg, s19, 0,
              static_cast<u8>(ir::Size::S8));
    expect_is(d.insns[5], VmOp::GetFlags, OpKind::Reg, s20, OpKind::None, 0, 0, kS64);
    expect_jcc(d.insns[6], ir::Cond::E, 6);   // repne 早退: ZF==1 → exit_adv (idx 12)
    expect_is(d.insns[7], VmOp::Add, OpKind::Reg, isa::vm_reg_of(ir::Reg::Rdi), OpKind::Imm, 0, 1, kS64);
    expect_is(d.insns[8], VmOp::Sub, OpKind::Reg, kRcx, OpKind::Imm, 0, 1, kS64);
    expect_jcc(d.insns[9], ir::Cond::Ne, -6); // 回边 → loop_pos (idx 3)
    expect_is(d.insns[10], VmOp::SetFlags, OpKind::Reg, s20, OpKind::None, 0, 0, kS64);
    expect_jmp(d.insns[11], 6);               // rcx==0 正常出口 → exit (idx 17)
    expect_is(d.insns[12], VmOp::Add, OpKind::Reg, isa::vm_reg_of(ir::Reg::Rdi), OpKind::Imm, 0, 1, kS64);
    expect_is(d.insns[13], VmOp::Sub, OpKind::Reg, kRcx, OpKind::Imm, 0, 1, kS64);
    expect_is(d.insns[14], VmOp::SetFlags, OpKind::Reg, s20, OpKind::None, 0, 0, kS64);
    expect_jmp(d.insns[15], 2);               // 早退出口 → exit (idx 17)
    expect_is(d.insns[16], VmOp::SetFlags, OpKind::Reg, s18, OpKind::None, 0, 0, kS64);
    expect_jmp(d.insns[17], 1);               // fallthrough
    expect_is(d.insns[18], VmOp::Halt, OpKind::None, 0, OpKind::None, 0, 0, 0);
}

TEST(Translate, StringCmpsRepeStructure) {
    // repe cmpsb (family 3, S8, cond E): loop{ Load t1,[rsi]; Load t2,[rdi];
    // Cmp t1,t2; GetFlags s1; Jcc Ne→exit_adv (repe 早退: ZF==0); Add rdi,1;
    // Add rsi,1; Sub rcx,1; Jcc Ne→loop } SetFlags s1; Jmp→exit;
    // exit_adv: Add rdi,1; Add rsi,1; Sub rcx,1; SetFlags s1; Jmp→exit;
    // restore0: SetFlags s0。scratch 4 槽 (s0/t1/t2/s1) 在预算内。
    const Decoded d = one_insn_n(str_op(3, ir::Size::S8, ir::Cond::E));
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(22));  // 20 + Jmp + Halt
    const u8 s18 = isa::kScratchFirst;
    const u8 s19 = isa::kScratchFirst + 1;
    const u8 s20 = isa::kScratchFirst + 2;
    const u8 s21 = isa::kScratchFirst + 3;
    expect_is(d.insns[3], VmOp::Load, OpKind::Reg, s19, OpKind::Reg, isa::vm_reg_of(ir::Reg::Rsi), 0,
              static_cast<u8>(ir::Size::S8));
    expect_is(d.insns[4], VmOp::Load, OpKind::Reg, s20, OpKind::Reg, isa::vm_reg_of(ir::Reg::Rdi), 0,
              static_cast<u8>(ir::Size::S8));
    expect_is(d.insns[5], VmOp::Cmp, OpKind::Reg, s19, OpKind::Reg, s20, 0,
              static_cast<u8>(ir::Size::S8));
    expect_is(d.insns[6], VmOp::GetFlags, OpKind::Reg, s21, OpKind::None, 0, 0, kS64);
    expect_jcc(d.insns[7], ir::Cond::Ne, 7);  // repe 早退: ZF==0 → exit_adv (idx 14)
    expect_is(d.insns[8], VmOp::Add, OpKind::Reg, isa::vm_reg_of(ir::Reg::Rdi), OpKind::Imm, 0, 1, kS64);
    expect_is(d.insns[9], VmOp::Add, OpKind::Reg, isa::vm_reg_of(ir::Reg::Rsi), OpKind::Imm, 0, 1, kS64);
    expect_is(d.insns[10], VmOp::Sub, OpKind::Reg, kRcx, OpKind::Imm, 0, 1, kS64);
    expect_jcc(d.insns[11], ir::Cond::Ne, -8); // 回边 → loop_pos (idx 3)
    expect_is(d.insns[12], VmOp::SetFlags, OpKind::Reg, s21, OpKind::None, 0, 0, kS64);
    expect_jmp(d.insns[13], 7);                // rcx==0 正常出口 → exit (idx 20)
    expect_is(d.insns[14], VmOp::Add, OpKind::Reg, isa::vm_reg_of(ir::Reg::Rdi), OpKind::Imm, 0, 1, kS64);
    expect_is(d.insns[15], VmOp::Add, OpKind::Reg, isa::vm_reg_of(ir::Reg::Rsi), OpKind::Imm, 0, 1, kS64);
    expect_is(d.insns[16], VmOp::Sub, OpKind::Reg, kRcx, OpKind::Imm, 0, 1, kS64);
    expect_is(d.insns[17], VmOp::SetFlags, OpKind::Reg, s21, OpKind::None, 0, 0, kS64);
    expect_jmp(d.insns[18], 2);                // 早退出口 → exit (idx 20)
    expect_is(d.insns[19], VmOp::SetFlags, OpKind::Reg, s18, OpKind::None, 0, 0, kS64);
}

TEST(Translate, StringStosAndLodsSimpleLoops) {
    // rep stosb (family 1): loop{ Store [rdi],Rax; Add rdi,1; Sub rcx,1; Jcc }
    const Decoded d = one_insn_n(str_op(1, ir::Size::S8));
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(10));  // 8 + Jmp + Halt
    expect_is(d.insns[3], VmOp::Store, OpKind::Reg, isa::vm_reg_of(ir::Reg::Rdi),
              OpKind::Reg, kRax, 0, static_cast<u8>(ir::Size::S8));
    expect_is(d.insns[4], VmOp::Add, OpKind::Reg, isa::vm_reg_of(ir::Reg::Rdi),
              OpKind::Imm, 0, 1, kS64);
    expect_is(d.insns[5], VmOp::Sub, OpKind::Reg, kRcx, OpKind::Imm, 0, 1, kS64);
    expect_jcc(d.insns[6], ir::Cond::Ne, -3); // 回边 → loop_pos (idx 3)
    expect_is(d.insns[7], VmOp::SetFlags, OpKind::Reg, isa::kScratchFirst,
              OpKind::None, 0, 0, kS64);

    // rep lodsb (family 4): loop{ Load Rax,[rsi]; Add rsi,1; Sub rcx,1; Jcc }
    const Decoded e = one_insn_n(str_op(4, ir::Size::S8));
    ASSERT_EQ(e.insns.size(), static_cast<size_t>(10));
    expect_is(e.insns[3], VmOp::Load, OpKind::Reg, kRax, OpKind::Reg,
              isa::vm_reg_of(ir::Reg::Rsi), 0, static_cast<u8>(ir::Size::S8));
    expect_is(e.insns[4], VmOp::Add, OpKind::Reg, isa::vm_reg_of(ir::Reg::Rsi),
              OpKind::Imm, 0, 1, kS64);
}

TEST(Translate, StringOpEmitsDfAssumptionNote) {
    // B.3: DF=0 假定 note 级披露 — "string-op @" 前缀与 backend 过滤白名单
    // 对账 (413 纪律): 命中 note 走 diag 通道不触发 C1 gate。
    std::vector<std::string> notes;
    const Decoded d = one_insn_n(str_op(0, ir::Size::S64), &notes);
    ASSERT_EQ(notes.size(), 1u);
    EXPECT_NE(notes[0].find("string-op @ 0x401000"), std::string::npos);
    EXPECT_NE(notes[0].find("DF=0 assumption"), std::string::npos);
    EXPECT_NE(notes[0].find("movsq"), std::string::npos);
    EXPECT_EQ(d.insns.back().op, VmOp::Halt);
}

// ==================== MIT-419 (G4): lock 前缀原子族 ====================
//
// src2 标记分域 (与 lifter translate_lock_op 对账): 5..8 = Op::Mov 载体族
// (xadd/bts/btr/btc), 9..11 = 本体 op 族 (alu/cmpxchg/xchg), 12..13 = 本体
// op 族 (inc/dec — MIT-423 G4b)。统一挂点在
// run() 入口: 先发 lock-strip note ("lock-strip @" 前缀与 backend 过滤
// 白名单对账, 413 纪律) 再按族派发。

// 辅助: lock 载体族 IR (Op::Mov + dst=Mem + src + src2=imm(marker)).
ir::Insn lock_carrier(i64 marker, ir::Operand d, ir::Operand s, ir::Size sz) {
    ir::Insn i = I(ir::Op::Mov, sz);
    i.dst = d;
    i.src = s;
    i.src2 = ir::Operand::imm_(marker);
    i.updates_flags = true;
    return i;
}

TEST(Translate, LockXaddEmitsSingleVmOpWithNote) {
    // lock xadd [rax], ebx (InterlockedAdd 真产物): 单 VmOp::Xadd —
    // a=地址槽 (emit_address 产出), b=源寄存器槽, handler 内 native
    // lock xadd [addr], reg 单指令直执行 (硬件原子性保真)。
    const ir::MemOperand mem{ir::Reg::Rax, ir::Reg::Flags, 0, 0};
    std::vector<std::string> notes;
    const Decoded d = one_insn_n(
        lock_carrier(5, ir::Operand::mem_(mem), ir::Operand::reg_(ir::Reg::Rbx),
                     ir::Size::S32),
        &notes);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(4));  // Mov+Xadd+Jmp+Halt
    const u8 s18 = isa::kScratchFirst;
    expect_is(d.insns[0], VmOp::Mov, OpKind::Reg, s18, OpKind::Reg, kRax, 0, kS64);
    expect_is(d.insns[1], VmOp::Xadd, OpKind::Reg, s18, OpKind::Reg, kRbx, 0, kS32);
    expect_is(d.insns[2], VmOp::Jmp, OpKind::None, 0, OpKind::None, 0, 1, kS64);
    expect_is(d.insns[3], VmOp::Halt, OpKind::None, 0, OpKind::None, 0, 0, 0);
    ASSERT_EQ(notes.size(), 1u);
    EXPECT_NE(notes[0].find("lock-strip @ 0x401000"), std::string::npos);
    EXPECT_NE(notes[0].find("xadd"), std::string::npos);
    EXPECT_NE(notes[0].find("strip-and-execute"), std::string::npos);
}

TEST(Translate, LockXadd64RipTarget) {
    // lock xadd qword ptr [rip+disp], rbx — rip 目标经 emit_address 出 RVA,
    // 与 LoadRva/StoreRva 同通道 (Xadd handler 直接以 acc 槽值作地址 — RVA
    // 需先 LeaRva 转 VA? 否: Xadd 访存的是**绝对 VA**, 与 Load/Store 同语义,
    // 故翻译器对 rip 目标在 Xadd 前插入 LeaRva 把 RVA→VA)。
    const ir::MemOperand mem{ir::Reg::Rip, ir::Reg::Flags, 0, 0x20};
    std::vector<std::string> notes;
    const Decoded d = one_insn_n(
        lock_carrier(5, ir::Operand::mem_(mem), ir::Operand::reg_(ir::Reg::Rbx),
                     ir::Size::S64),
        &notes);
    // Mov acc, (next_ip+disp) [next_ip = fn.end_rva = 0x3000] → LeaRva
    // acc, acc → Xadd acc, rbx → Jmp → Halt = 5 条。
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(5));
    const u8 s18 = isa::kScratchFirst;
    expect_is(d.insns[0], VmOp::Mov, OpKind::Reg, s18, OpKind::Imm, 0, 0x3020, kS64);
    expect_is(d.insns[1], VmOp::LeaRva, OpKind::Reg, s18, OpKind::Reg, s18, 0, kS64);
    expect_is(d.insns[2], VmOp::Xadd, OpKind::Reg, s18, OpKind::Reg, kRbx, 0, kS64);
    expect_is(d.insns[3], VmOp::Jmp, OpKind::None, 0, OpKind::None, 0, 1, kS64);
    expect_is(d.insns[4], VmOp::Halt, OpKind::None, 0, OpKind::None, 0, 0, 0);
}

TEST(Translate, LockStripAluFoldsLikePlainAluMem) {
    // lock add [rax], ebx — 剥 F0 后与普通 mem-dst ALU 同折条 (D1:
    // strip-and-execute, 零新 VmOp): Mov acc,rax; Load s,[acc]; Add s,ebx;
    // Store [acc],s。note 前缀 lock-strip @。
    const ir::MemOperand mem{ir::Reg::Rax, ir::Reg::Flags, 0, 0};
    ir::Insn i = I(ir::Op::Add, ir::Size::S32);
    i.dst = ir::Operand::mem_(mem);
    i.src = ir::Operand::reg_(ir::Reg::Rbx);
    i.src2 = ir::Operand::imm_(9);  // kLockStripAlu
    i.updates_flags = true;
    std::vector<std::string> notes;
    const Decoded d = one_insn_n(i, &notes);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(6));  // Mov+Load+Add+Store+Jmp+Halt
    const u8 s18 = isa::kScratchFirst;
    expect_is(d.insns[0], VmOp::Mov, OpKind::Reg, s18, OpKind::Reg, kRax, 0, kS64);
    expect_is(d.insns[1], VmOp::Load, OpKind::Reg, s18 + 1, OpKind::Reg, s18, 0, kS32);
    expect_is(d.insns[2], VmOp::Add, OpKind::Reg, s18 + 1, OpKind::Reg, kRbx, 0, kS32);
    expect_is(d.insns[3], VmOp::Store, OpKind::Reg, s18, OpKind::Reg, s18 + 1, 0, kS32);
    expect_is(d.insns[4], VmOp::Jmp, OpKind::None, 0, OpKind::None, 0, 1, kS64);
    expect_is(d.insns[5], VmOp::Halt, OpKind::None, 0, OpKind::None, 0, 0, 0);
    ASSERT_EQ(notes.size(), 1u);
    EXPECT_NE(notes[0].find("lock-strip @ 0x401000"), std::string::npos);
    EXPECT_NE(notes[0].find("alu"), std::string::npos);
}

TEST(Translate, LockBtsImmEmitsSingleVmOp) {
    // lock bts [rax], 5 (InterlockedBitTest* 真产物 imm8 形式): 单
    // VmOp::Bts — a=地址槽, b_kind=Imm aux=5。
    const ir::MemOperand mem{ir::Reg::Rax, ir::Reg::Flags, 0, 0};
    std::vector<std::string> notes;
    const Decoded d = one_insn_n(
        lock_carrier(6, ir::Operand::mem_(mem), ir::Operand::imm_(5), ir::Size::S32),
        &notes);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(4));  // Mov+Bts+Jmp+Halt
    const u8 s18 = isa::kScratchFirst;
    expect_is(d.insns[0], VmOp::Mov, OpKind::Reg, s18, OpKind::Reg, kRax, 0, kS64);
    expect_is(d.insns[1], VmOp::Bts, OpKind::Reg, s18, OpKind::Imm, 0, 5, kS32);
    expect_is(d.insns[2], VmOp::Jmp, OpKind::None, 0, OpKind::None, 0, 1, kS64);
    expect_is(d.insns[3], VmOp::Halt, OpKind::None, 0, OpKind::None, 0, 0, 0);
    ASSERT_EQ(notes.size(), 1u);
    EXPECT_NE(notes[0].find("lock-strip @ 0x401000"), std::string::npos);
    EXPECT_NE(notes[0].find("bts"), std::string::npos);
}

TEST(Translate, LockBtcRegEmitsSingleVmOp) {
    // lock btc [rax], ebx — reg 位号形式: b_kind=Reg reg_b=ebx。
    const ir::MemOperand mem{ir::Reg::Rax, ir::Reg::Flags, 0, 0};
    const Decoded d = one_insn_n(
        lock_carrier(8, ir::Operand::mem_(mem), ir::Operand::reg_(ir::Reg::Rbx),
                     ir::Size::S64));
    const u8 s18 = isa::kScratchFirst;
    expect_is(d.insns[1], VmOp::Btc, OpKind::Reg, s18, OpKind::Reg, kRbx, 0, kS64);
}

TEST(Translate, LockStripCmpxchgMemReusesFolding) {
    // lock cmpxchg [rax], ebx — 既有 mem 拆条 (Load+Cmpxchg+Store) 复用
    // (B.3: dst=Mem 覆盖实测, 零改动)。note 前缀 lock-strip @。
    const ir::MemOperand mem{ir::Reg::Rax, ir::Reg::Flags, 0, 0};
    ir::Insn i = I(ir::Op::Cmpxchg, ir::Size::S32);
    i.dst = ir::Operand::mem_(mem);
    i.src = ir::Operand::reg_(ir::Reg::Rbx);
    i.src2 = ir::Operand::imm_(10);  // kLockStripCmpxchg
    i.updates_flags = true;
    std::vector<std::string> notes;
    const Decoded d = one_insn_n(i, &notes);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(6));  // Mov+Load+Cmpxchg+Store+Jmp+Halt
    const u8 s18 = isa::kScratchFirst;
    expect_is(d.insns[0], VmOp::Mov, OpKind::Reg, s18, OpKind::Reg, kRax, 0, kS64);
    expect_is(d.insns[1], VmOp::Load, OpKind::Reg, s18 + 1, OpKind::Reg, s18, 0, kS32);
    expect_is(d.insns[2], VmOp::Cmpxchg, OpKind::Reg, s18 + 1, OpKind::Reg, kRbx, 0, kS32);
    expect_is(d.insns[3], VmOp::Store, OpKind::Reg, s18, OpKind::Reg, s18 + 1, 0, kS32);
    ASSERT_EQ(notes.size(), 1u);
    EXPECT_NE(notes[0].find("lock-strip @ 0x401000"), std::string::npos);
    EXPECT_NE(notes[0].find("cmpxchg"), std::string::npos);
}

TEST(Translate, XchgMemFoldsWithoutNote) {
    // 裸 xchg [rax], ebx (InterlockedExchange 真产物, 无 F0) — mem 折条
    // Load+Xchg+Store; **无 lock-strip note** (无 lock 前缀, one_insn 断言
    // notes 空)。xchg 对称, 拆条语义等价: tmp=旧[m]; Xchg(tmp,ebx) →
    // tmp=旧ebx, ebx=旧[m]; Store → [m]=旧ebx。
    const ir::MemOperand mem{ir::Reg::Rax, ir::Reg::Flags, 0, 0};
    ir::Insn i = I(ir::Op::Xchg, ir::Size::S32);
    i.dst = ir::Operand::mem_(mem);
    i.src = ir::Operand::reg_(ir::Reg::Rbx);
    const Decoded d = one_insn(i);  // one_insn 断言 r.notes.empty()
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(6));  // Mov+Load+Xchg+Store+Jmp+Halt
    const u8 s18 = isa::kScratchFirst;
    expect_is(d.insns[0], VmOp::Mov, OpKind::Reg, s18, OpKind::Reg, kRax, 0, kS64);
    expect_is(d.insns[1], VmOp::Load, OpKind::Reg, s18 + 1, OpKind::Reg, s18, 0, kS32);
    expect_is(d.insns[2], VmOp::Xchg, OpKind::Reg, s18 + 1, OpKind::Reg, kRbx, 0, kS32);
    expect_is(d.insns[3], VmOp::Store, OpKind::Reg, s18, OpKind::Reg, s18 + 1, 0, kS32);
    expect_is(d.insns[4], VmOp::Jmp, OpKind::None, 0, OpKind::None, 0, 1, kS64);
    expect_is(d.insns[5], VmOp::Halt, OpKind::None, 0, OpKind::None, 0, 0, 0);
}

TEST(Translate, ImulThreeOpImmInLockMarkerRangeNotIntercepted) {
    // 回归 (exitnative_pos_sample 实测踩域): imul 3-op imm 也用 src2=imm
    // 且立即数任意 — `imul rax, rax, 7` 的 src2=imm(7) 恰落在 lock 标记域
    // (kLockBtr=7)。lock 族拦截必须 op 限定 (is_lock_carrier_op), 否则
    // imul 被误路由到 translate_lock_family → skip → 整函数 gate。
    // 期望: 按 imul 3-op REG 路径翻译 (Mov scratch,7 + Imul), notes 空。
    ir::Insn i = I(ir::Op::Imul, ir::Size::S64);
    i.dst = ir::Operand::reg_(ir::Reg::Rax);
    i.src = ir::Operand::reg_(ir::Reg::Rax);
    i.src2 = ir::Operand::imm_(7);  // 恰在 lock 标记域 (5..11)
    const Decoded d = one_insn(i);  // 断言 notes 空 (未被 lock 拦截)
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(4));  // Mov+Mov+Imul+Jmp+Halt
    const u8 s18 = isa::kScratchFirst;
    expect_is(d.insns[0], VmOp::Mov, OpKind::Reg, s18, OpKind::Imm, 0, 7, kS64);
    expect_is(d.insns[1], VmOp::Imul, OpKind::Reg, kRax, OpKind::Reg, s18, 0, kS64);
    expect_is(d.insns[2], VmOp::Jmp, OpKind::None, 0, OpKind::None, 0, 1, kS64);
    expect_is(d.insns[3], VmOp::Halt, OpKind::None, 0, OpKind::None, 0, 0, 0);
}

// ==================== MIT-423 (G4b): lock inc/dec 载体 ====================

TEST(Translate, LockIncFoldsLikePlainUnaryMem) {
    // lock inc [rax] (kLockInc=12): 先发 lock-strip note, 再派发回本体
    // translate_unary mem 拆条 — Mov acc,rax; Load s,[acc]; Inc s; Store
    // [acc],s (D1: 零新 VmOp, 与普通 mem-dst inc 同折条)。
    const ir::MemOperand mem{ir::Reg::Rax, ir::Reg::Flags, 0, 0};
    ir::Insn i = I(ir::Op::Inc, ir::Size::S32);
    i.dst = ir::Operand::mem_(mem);
    i.src2 = ir::Operand::imm_(12);  // kLockInc
    i.updates_flags = true;
    std::vector<std::string> notes;
    const Decoded d = one_insn_n(i, &notes);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(6));  // Mov+Load+Inc+Store+Jmp+Halt
    const u8 s18 = isa::kScratchFirst;
    expect_is(d.insns[0], VmOp::Mov, OpKind::Reg, s18, OpKind::Reg, kRax, 0, kS64);
    expect_is(d.insns[1], VmOp::Load, OpKind::Reg, s18 + 1, OpKind::Reg, s18, 0, kS32);
    expect_is(d.insns[2], VmOp::Inc, OpKind::Reg, s18 + 1, OpKind::None, 0, 0, kS32);
    expect_is(d.insns[3], VmOp::Store, OpKind::Reg, s18, OpKind::Reg, s18 + 1, 0, kS32);
    expect_is(d.insns[4], VmOp::Jmp, OpKind::None, 0, OpKind::None, 0, 1, kS64);
    expect_is(d.insns[5], VmOp::Halt, OpKind::None, 0, OpKind::None, 0, 0, 0);
    ASSERT_EQ(notes.size(), 1u);
    EXPECT_NE(notes[0].find("lock-strip @ 0x401000"), std::string::npos);
    EXPECT_NE(notes[0].find("inc"), std::string::npos);
    EXPECT_NE(notes[0].find("strip-and-execute"), std::string::npos);
}

TEST(Translate, LockDecRipTargetFoldsViaRvaChannel) {
    // lock dec qword ptr [rip+0x20] (kLockDec=13): rip 目标经 emit_address
    // 出 RVA, LoadRva/StoreRva 同通道 (与普通 mem-dst dec 拆条一致)。
    const ir::MemOperand mem{ir::Reg::Rip, ir::Reg::Flags, 0, 0x20};
    ir::Insn i = I(ir::Op::Dec, ir::Size::S64);
    i.dst = ir::Operand::mem_(mem);
    i.src2 = ir::Operand::imm_(13);  // kLockDec
    i.updates_flags = true;
    std::vector<std::string> notes;
    const Decoded d = one_insn_n(i, &notes);
    // Mov acc,(next_ip+0x20) [next_ip = fn.end_rva = 0x3000] → LoadRva →
    // Dec → StoreRva → Jmp → Halt = 6 条。
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(6));
    const u8 s18 = isa::kScratchFirst;
    expect_is(d.insns[0], VmOp::Mov, OpKind::Reg, s18, OpKind::Imm, 0, 0x3020, kS64);
    expect_is(d.insns[1], VmOp::LoadRva, OpKind::Reg, s18 + 1, OpKind::Reg, s18, 0, kS64);
    expect_is(d.insns[2], VmOp::Dec, OpKind::Reg, s18 + 1, OpKind::None, 0, 0, kS64);
    expect_is(d.insns[3], VmOp::StoreRva, OpKind::Reg, s18, OpKind::Reg, s18 + 1, 0, kS64);
    ASSERT_EQ(notes.size(), 1u);
    EXPECT_NE(notes[0].find("lock-strip @ 0x401000"), std::string::npos);
    EXPECT_NE(notes[0].find("dec"), std::string::npos);
}

TEST(Translate, PlainIncDecMemNoNote) {
    // 对偶面: 普通 (无 lock) inc/dec [m] 走同一 translate_unary 折条但
    // **不发 lock-strip note** (src2.kind=None 不满足拦截条件 — 与 lifter
    // 侧 LockIncDecNegative ⑤⑥ 对账)。
    const ir::MemOperand mem{ir::Reg::Rax, ir::Reg::Flags, 0, 0};
    ir::Insn i = I(ir::Op::Dec, ir::Size::S32);
    i.dst = ir::Operand::mem_(mem);
    i.updates_flags = true;
    const Decoded d = one_insn(i);  // one_insn 断言 notes 空
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(6));
    const u8 s18 = isa::kScratchFirst;
    expect_is(d.insns[2], VmOp::Dec, OpKind::Reg, s18 + 1, OpKind::None, 0, 0, kS32);
}

TEST(Translate, ImulThreeOpImmAtNewMarkerValuesNotIntercepted) {
    // MIT-423 回归固化: 标记域扩到 12..13 (kLockInc/kLockDec) 后, imul
    // 3-op imm 的 12/13 立即数 (合法乘数, 可由编译器真实产出) 不得误拦 —
    // 419 的 op 限定对账面延伸到新值域 (第 4 次载体域教训的固化用例)。
    for (const i64 v : {12, 13}) {
        ir::Insn i = I(ir::Op::Imul, ir::Size::S64);
        i.dst = ir::Operand::reg_(ir::Reg::Rax);
        i.src = ir::Operand::reg_(ir::Reg::Rax);
        i.src2 = ir::Operand::imm_(v);  // 恰在新 lock 标记域 (12..13)
        const Decoded d = one_insn(i);  // 断言 notes 空 (未被 lock 拦截)
        ASSERT_EQ(d.insns.size(), static_cast<size_t>(4));  // Mov+Mov+Imul+Jmp+Halt
        const u8 s18 = isa::kScratchFirst;
        expect_is(d.insns[0], VmOp::Mov, OpKind::Reg, s18, OpKind::Imm, 0,
                  static_cast<u32>(v), kS64);
        expect_is(d.insns[1], VmOp::Imul, OpKind::Reg, kRax, OpKind::Reg, s18, 0, kS64);
        expect_is(d.insns[2], VmOp::Jmp, OpKind::None, 0, OpKind::None, 0, 1, kS64);
        expect_is(d.insns[3], VmOp::Halt, OpKind::None, 0, OpKind::None, 0, 0, 0);
    }
}

// ---------------- MIT-425 (G1b): SSE mul 族 + andnps/pandn 折叠 ----------------

namespace {
constexpr u8 kXmm0 = 24;  // ctx.xmm 槽 = xmm 索引 + 24 (MIT-371 编码约定)
constexpr u8 kXmm1 = 25;
constexpr u8 kXmm2 = 26;
constexpr i64 kSseMulSs = 14, kSseMulSd = 15, kSseMulPs = 16, kSseMulPd = 17,
              kSseAndn = 18;  // 与 lifter x86_translate.cpp / translator.cpp 对账

ir::Insn sse_mul(i64 marker, ir::Size sz, ir::Operand src) {
    ir::Insn i = I(ir::Op::Mul, sz);
    i.dst = ir::Operand::reg_(ir::Reg::Rax);   // xmm0 (0..7 借用)
    i.src = std::move(src);
    i.src2 = ir::Operand::imm_(marker);
    i.updates_flags = false;
    return i;
}
} // namespace

TEST(Translate, SseMulRegRegFourFormsEmitMulVmOps) {
    // (Op::Mul, src2=imm 14..17) 载体 → VmOp::Mulss/Mulsd/Mulps/Mulpd 单条。
    const struct { i64 marker; VmOp vop; ir::Size sz; } forms[] = {
        {kSseMulSs, VmOp::Mulss, ir::Size::S32},
        {kSseMulSd, VmOp::Mulsd, ir::Size::S64},
        {kSseMulPs, VmOp::Mulps, ir::Size::S64},
        {kSseMulPd, VmOp::Mulpd, ir::Size::S64},
    };
    for (const auto& f : forms) {
        const Decoded d = one_insn(sse_mul(f.marker, f.sz,
                                           ir::Operand::reg_(ir::Reg::Rcx)));  // xmm1
        ASSERT_EQ(d.insns.size(), static_cast<size_t>(3));  // mul + Jmp+1 + Halt
        expect_is(d.insns[0], f.vop, OpKind::Reg, kXmm0, OpKind::Reg, kXmm1, 0,
                  isa::size_field(f.sz));
    }
}

TEST(Translate, SseMulMemSourceFoldsXmmLoad) {
    // MEM 源: emit_sse_mem_addr (rip → Mov+LeaRva) + XmmLoad(临时双槽) +
    // mul(dst, 双槽)。宽度由标记本地导出: ss=4 / sd=8 / ps,pd=16 —
    // sse_mem_width 的 default=16 对 ss/sd 会错, 本用例钉死本地表。
    const struct { i64 marker; VmOp vop; u32 width; } forms[] = {
        {kSseMulSs, VmOp::Mulss, 4},
        {kSseMulSd, VmOp::Mulsd, 8},
        {kSseMulPs, VmOp::Mulps, 16},
        {kSseMulPd, VmOp::Mulpd, 16},
    };
    for (const auto& f : forms) {
        ir::MemOperand mem = m(ir::Reg::Rip, ir::Reg::Flags, 0, 0x20);
        const Decoded d = one_insn(sse_mul(f.marker, ir::Size::S64,
                                           ir::Operand::mem_(mem)));
        // Mov(rva) + LeaRva + XmmLoad + mul + Jmp + Halt
        // (next_ip: 单块末条 = fn.end_rva = 0x3000 → rva = 0x3000 + disp 0x20)
        ASSERT_EQ(d.insns.size(), static_cast<size_t>(6));
        const u8 acc = isa::kScratchFirst;
        expect_is(d.insns[0], VmOp::Mov, OpKind::Reg, acc, OpKind::Imm, 0,
                  0x3020, kS64);
        expect_is(d.insns[1], VmOp::LeaRva, OpKind::Reg, acc, OpKind::Reg, acc, 0, kS64);
        expect_is(d.insns[2], VmOp::XmmLoad, OpKind::Reg, acc + 1, OpKind::Reg, acc,
                  f.width, kS64);
        expect_is(d.insns[3], f.vop, OpKind::Reg, kXmm0, OpKind::Reg, acc + 1, 0, kS64);
    }
}

TEST(Translate, GpMulUnaffectedByMarkerDomain) {
    // 回归固化 (419 op 限定对账延伸): GP Op::Mul (src2 恒空) 仍走 VmOp::Mul
    // 通路; imul 3-op 的 14..17 立即数 (恰在新 SSE mul 标记域) 不得误拦。
    {
        ir::Insn i = I(ir::Op::Mul, ir::Size::S64);
        i.dst = ir::Operand::reg_(ir::Reg::Rdx);  // GP mul 约定 dst=Rdx
        i.src = ir::Operand::reg_(ir::Reg::Rcx);
        i.updates_flags = true;
        const Decoded d = one_insn(i);
        ASSERT_EQ(d.insns.size(), static_cast<size_t>(3));
        expect_is(d.insns[0], VmOp::Mul, OpKind::Reg, kRdx, OpKind::Reg, kRcx, 0, kS64);
    }
    for (const i64 v : {14, 15, 16, 17, 18}) {
        ir::Insn i = I(ir::Op::Imul, ir::Size::S64);
        i.dst = ir::Operand::reg_(ir::Reg::Rax);
        i.src = ir::Operand::reg_(ir::Reg::Rcx);
        i.src2 = ir::Operand::imm_(v);  // 恰在新标记域 (14..18) 的合法 imul 乘数
        const Decoded d = one_insn(i);  // notes 空 = 未被 SSE/lock 拦截
        const u8 s18 = isa::kScratchFirst;
        expect_is(d.insns[1], VmOp::Imul, OpKind::Reg, kRax, OpKind::Reg, s18, 0, kS64);
    }
}

TEST(Translate, AndnCarrierFoldsToAndnpsVmOp) {
    // (Op::Andps, src2=imm(18)=kSseAndn) → VmOp::Andnps (andnps/andnpd/
    // pandn 折叠); 常规 Andps (src2 空) 不受影响。
    {
        ir::Insn i = I(ir::Op::Andps, ir::Size::S64);
        i.dst = ir::Operand::reg_(ir::Reg::Rax);
        i.src = ir::Operand::reg_(ir::Reg::Rcx);
        i.src2 = ir::Operand::imm_(kSseAndn);
        const Decoded d = one_insn(i);
        ASSERT_EQ(d.insns.size(), static_cast<size_t>(3));
        expect_is(d.insns[0], VmOp::Andnps, OpKind::Reg, kXmm0, OpKind::Reg, kXmm1, 0, kS64);
    }
    {
        ir::Insn i = I(ir::Op::Andps, ir::Size::S64);
        i.dst = ir::Operand::reg_(ir::Reg::Rax);
        i.src = ir::Operand::reg_(ir::Reg::Rcx);
        const Decoded d = one_insn(i);
        expect_is(d.insns[0], VmOp::Andps, OpKind::Reg, kXmm0, OpKind::Reg, kXmm1, 0, kS64);
    }
}

TEST(Translate, PandPorPxorReusePsBitwiseVmOps) {
    // SSE2 整数位运算族 (R2 档①) 零新 VmOp 折叠: pand→Andps / por→Orps /
    // pxor→Xorps (IR 层 lifter 直接产 Op::Andps/Orps/Xorps)。
    const struct { ir::Op op; VmOp vop; } forms[] = {
        {ir::Op::Andps, VmOp::Andps},
        {ir::Op::Orps,  VmOp::Orps},
        {ir::Op::Xorps, VmOp::Xorps},
    };
    for (const auto& f : forms) {
        ir::Insn i = I(f.op, ir::Size::S64);
        i.dst = ir::Operand::reg_(ir::Reg::Rax);
        i.src = ir::Operand::reg_(ir::Reg::Rcx);
        const Decoded d = one_insn(i);
        ASSERT_EQ(d.insns.size(), static_cast<size_t>(3));
        expect_is(d.insns[0], f.vop, OpKind::Reg, kXmm0, OpKind::Reg, kXmm1, 0, kS64);
    }
}

TEST(Translate, AndnMemSourceFoldsXmmLoad) {
    // andnps mem 源: XmmLoad(临时双槽, 16B) + Andnps(dst, 双槽)。
    ir::MemOperand mem = m(ir::Reg::Rip, ir::Reg::Flags, 0, 0x30);
    ir::Insn i = I(ir::Op::Andps, ir::Size::S64);
    i.dst = ir::Operand::reg_(ir::Reg::Rax);
    i.src = ir::Operand::mem_(mem);
    i.src2 = ir::Operand::imm_(kSseAndn);
    const Decoded d = one_insn(i);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(6));
    const u8 acc = isa::kScratchFirst;
    expect_is(d.insns[2], VmOp::XmmLoad, OpKind::Reg, acc + 1, OpKind::Reg, acc, 16, kS64);
    expect_is(d.insns[3], VmOp::Andnps, OpKind::Reg, kXmm0, OpKind::Reg, acc + 1, 0, kS64);
}

// ==================== MIT-434 (G8a): BMI 折条 dispatch ====================

TEST(Translate, BmiAndnCarrierExpandsMovNotAnd) {
    // andn d==s2 载体: (Op::And, dst=eax, src=ecx(NOT 项), src2=Reg(eax)=AND 项)
    // → [Mov(s0, ecx); Not(s0); And(eax, s0)] — ~NOT 项 需独占临时。
    ir::Insn i = I(ir::Op::And, ir::Size::S32);
    i.dst = ir::Operand::reg_(ir::Reg::Rax);
    i.src = ir::Operand::reg_(ir::Reg::Rcx);
    i.src2 = ir::Operand::reg_(ir::Reg::Rax);
    const Decoded d = one_insn(i);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(5)); // 3 展开 + Jmp+1 + Halt
    const u8 s0 = isa::kScratchFirst;
    expect_is(d.insns[0], VmOp::Mov, OpKind::Reg, s0, OpKind::Reg, kRcx, 0, kS32);
    expect_is(d.insns[1], VmOp::Not, OpKind::Reg, s0, OpKind::None, 0, 0, kS32);
    expect_is(d.insns[2], VmOp::And, OpKind::Reg, kRax, OpKind::Reg, s0, 0, kS32);
}

TEST(Translate, BmiPlainAndSubUnaffectedByCarrierKind) {
    // 载体判据 = src2.kind≠None — 常规 And/Sub (src2 空) 照旧单条展开
    // (全仓 src2 写入点审计的回归钉)。
    {
        const Decoded d = one_insn(alu(ir::Op::And, ir::Operand::reg_(ir::Reg::Rax),
                                       ir::Operand::reg_(ir::Reg::Rcx), ir::Size::S32));
        ASSERT_EQ(d.insns.size(), static_cast<size_t>(3));
        expect_is(d.insns[0], VmOp::And, OpKind::Reg, kRax, OpKind::Reg, kRcx, 0, kS32);
    }
    {
        const Decoded d = one_insn(alu(ir::Op::Sub, ir::Operand::reg_(ir::Reg::Rax),
                                       ir::Operand::reg_(ir::Reg::Rcx), ir::Size::S32));
        ASSERT_EQ(d.insns.size(), static_cast<size_t>(3));
        expect_is(d.insns[0], VmOp::Sub, OpKind::Reg, kRax, OpKind::Reg, kRcx, 0, kS32);
    }
}

TEST(Translate, BmiBzhiCarrierExpandsFullSequence) {
    // bzhi 载体: (Op::Sub, dst=eax, src=Reg(ebx)=value, src2=Reg(ecx)=index)
    // → mask + clamp(-1) + And + 边界 CF 补丁 (probe raw 0x287) — 16 op。
    ir::Insn i = I(ir::Op::Sub, ir::Size::S32);
    i.dst = ir::Operand::reg_(ir::Reg::Rax);
    i.src = ir::Operand::reg_(ir::Reg::Rbx);
    i.src2 = ir::Operand::reg_(ir::Reg::Rcx);
    const Decoded d = one_insn(i);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(19)); // 17 展开 + Jmp+1 + Halt
    const u8 s_m = isa::kScratchFirst, s_c = s_m + 1, s_i = s_m + 2;
    const u32 ae28 = static_cast<u32>(ir::Cond::Ae) << 28;
    expect_is(d.insns[0], VmOp::Mov, OpKind::Reg, s_m, OpKind::Imm, 0, 1, kS32);
    expect_is(d.insns[1], VmOp::Shl, OpKind::Reg, s_m, OpKind::Reg, kRcx, 0, kS32);
    expect_is(d.insns[2], VmOp::Sub, OpKind::Reg, s_m, OpKind::Imm, 0, 1, kS32);
    expect_is(d.insns[3], VmOp::Mov, OpKind::Reg, s_c, OpKind::Imm, 0, 0, kS64);
    expect_is(d.insns[4], VmOp::Sub, OpKind::Reg, s_c, OpKind::Imm, 0, 1, kS64);
    expect_is(d.insns[5], VmOp::Movzx, OpKind::Reg, s_i, OpKind::Reg, kRcx, 0, kS64);
    expect_is(d.insns[6], VmOp::Cmp, OpKind::Reg, s_i, OpKind::Imm, 0, 32, kS32);
    expect_is(d.insns[7], VmOp::Cmovcc, OpKind::Reg, s_m, OpKind::Reg, s_c, ae28, kS32);
    expect_is(d.insns[8], VmOp::Mov, OpKind::Reg, kRax, OpKind::Reg, kRbx, 0, kS32);
    expect_is(d.insns[9], VmOp::And, OpKind::Reg, kRax, OpKind::Reg, s_m, 0, kS32);
    expect_is(d.insns[10], VmOp::GetFlags, OpKind::Reg, s_m, OpKind::None, 0, 0, kS64);
    expect_is(d.insns[11], VmOp::Cmp, OpKind::Reg, s_i, OpKind::Imm, 0, 32, kS32);
    expect_is(d.insns[12], VmOp::Sbb, OpKind::Reg, s_c, OpKind::Reg, s_c, 0, kS64);
    expect_is(d.insns[13], VmOp::Not, OpKind::Reg, s_c, OpKind::None, 0, 0, kS64);
    expect_is(d.insns[14], VmOp::And, OpKind::Reg, s_c, OpKind::Imm, 0, 2, kS64);
    expect_is(d.insns[15], VmOp::Or, OpKind::Reg, s_m, OpKind::Reg, s_c, 0, kS64);
    expect_is(d.insns[16], VmOp::SetFlags, OpKind::Reg, s_m, OpKind::None, 0, 0, kS64);
}

TEST(Translate, BmiBzhiDstEqualsValueSkipsPreload) {
    // d==value: 无前置 Mov (And(d, mask) 直读 dst 槽)。
    ir::Insn i = I(ir::Op::Sub, ir::Size::S64);
    i.dst = ir::Operand::reg_(ir::Reg::Rax);
    i.src = ir::Operand::reg_(ir::Reg::Rax);
    i.src2 = ir::Operand::reg_(ir::Reg::Rcx);
    const Decoded d = one_insn(i);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(18));
    expect_is(d.insns[8], VmOp::And, OpKind::Reg, kRax, OpKind::Reg,
              isa::kScratchFirst, 0, kS64);   // 无 [9]=Mov → And 直落
    expect_is(d.insns[7], VmOp::Cmovcc, OpKind::Reg, isa::kScratchFirst,
              OpKind::Reg, isa::kScratchFirst + 1, static_cast<u32>(ir::Cond::Ae) << 28,
              kS64);
}

TEST(Translate, BmiFlaglessShiftWrapPreservesFlags) {
    // rorx 载体: (Op::Ror, dst=eax, src=Imm(7)=count, src2=Imm(22)=kFlagless)
    // → [GetFlags(s); Ror(eax, Imm 7); SetFlags(s)] — build_shift 全量装配
    // 被包裹抹平, 净效果 = 五位原样保留 (D1 (i) 变体, asmgen 零改动)。
    ir::Insn i = I(ir::Op::Ror, ir::Size::S32);
    i.dst = ir::Operand::reg_(ir::Reg::Rax);
    i.src = ir::Operand::imm_(7);
    i.src2 = ir::Operand::imm_(22);
    const Decoded d = one_insn(i);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(5));
    const u8 s = isa::kScratchFirst;
    expect_is(d.insns[0], VmOp::GetFlags, OpKind::Reg, s, OpKind::None, 0, 0, kS64);
    expect_is(d.insns[1], VmOp::Ror, OpKind::Reg, kRax, OpKind::Imm, 0, 7, kS32);
    expect_is(d.insns[2], VmOp::SetFlags, OpKind::Reg, s, OpKind::None, 0, 0, kS64);
}

TEST(Translate, BmiFlaglessShlxCountInRegChannel) {
    // shlx 载体: (Op::Shl, dst=eax, src=Reg(ecx)=cnt, src2=Imm(22)) —
    // b=Reg 通用计数通路 (build_shift T7 任意槽, B.4)。
    ir::Insn i = I(ir::Op::Shl, ir::Size::S64);
    i.dst = ir::Operand::reg_(ir::Reg::Rax);
    i.src = ir::Operand::reg_(ir::Reg::Rcx);
    i.src2 = ir::Operand::imm_(22);
    const Decoded d = one_insn(i);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(5));
    const u8 s = isa::kScratchFirst;
    expect_is(d.insns[0], VmOp::GetFlags, OpKind::Reg, s, OpKind::None, 0, 0, kS64);
    expect_is(d.insns[1], VmOp::Shl, OpKind::Reg, kRax, OpKind::Reg, kRcx, 0, kS64);
    expect_is(d.insns[2], VmOp::SetFlags, OpKind::Reg, s, OpKind::None, 0, 0, kS64);
}

TEST(Translate, BmiNativeShiftImmNotIntercepted) {
    // 陷阱② 回归钉 (translator 侧): 原生 ror eax,24 → (Op::Ror, src=Imm(24),
    // src2=None) — 无载体 → 单条 Ror (count=0 出口/flags 全量 = P1 面,
    // 逐字节不变)。
    ir::Insn i = I(ir::Op::Ror, ir::Size::S32);
    i.dst = ir::Operand::reg_(ir::Reg::Rax);
    i.src = ir::Operand::imm_(24);
    const Decoded d = one_insn(i);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(3));
    expect_is(d.insns[0], VmOp::Ror, OpKind::Reg, kRax, OpKind::Imm, 0, 24, kS32);
}

// ==================== MIT-442 (X2a): 形级 fork 面 translator 矩阵 ====================

TEST(Translate, PushPopArchForkX86) {
    // B.2 栈宽分叉: x86 (S32 push/pop) → stride 4 + S32 访存; rsp 算术恒 S64。
    // x64 (S64) 路径已由 PushPopExpansion 钉死 (8/S64, 逐字节不变)。
    // MIT-451 (X5b) B.2：本用例 arch = x64（fn_of 默认），S32 push 走 4B 下探
    // → walk budget=0 gate note（x64 无 guard，任何区内栈下探即 gate）。
    const auto r = wvmp::regvm::translator::translate_function(
        fn_of({blk(0x1000, [] {
                   std::vector<ir::Insn> v;
                   ir::Insn p = I(ir::Op::Push, ir::Size::S32);
                   p.dst = ir::Operand::reg_(ir::Reg::Rax);
                   v.push_back(p);
                   ir::Insn q = I(ir::Op::Pop, ir::Size::S32);
                   q.dst = ir::Operand::reg_(ir::Reg::Rbx);
                   v.push_back(q);
                   return v;
               }())}));
    ASSERT_EQ(r.notes.size(), static_cast<size_t>(1));
    EXPECT_NE(r.notes[0].find("stack-depth-gate"), std::string::npos);
    const Decoded d = decode_program(r.program);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(6));
    expect_is(d.insns[0], VmOp::Sub, OpKind::Reg, kRsp, OpKind::Imm, 0, 4, kS64);
    expect_is(d.insns[1], VmOp::Store, OpKind::Reg, kRsp, OpKind::Reg, kRax, 0, kS32);
    expect_is(d.insns[2], VmOp::Load, OpKind::Reg, kRbx, OpKind::Reg, kRsp, 0, kS32);
    expect_is(d.insns[3], VmOp::Add, OpKind::Reg, kRsp, OpKind::Imm, 0, 4, kS64);
}

TEST(Translate, PushS16Gated) {
    // B.4: S16 push (66 50, 栈推进 2B 不在 VM 栈模型内) → gate (修复旧静默
    // 错形: 旧码 S16 push 也走 8B stride)。
    ir::Insn p = I(ir::Op::Push, ir::Size::S16);
    p.dst = ir::Operand::reg_(ir::Reg::Rax);
    const auto r = wvmp::regvm::translator::translate_function(fn_of({blk(0x1000, {p})}));
    ASSERT_FALSE(r.notes.empty());
    EXPECT_NE(r.notes[0].find("push 位宽未支持"), std::string::npos);
}

TEST(Translate, LeaveFoldTwoInsnWords) {
    // ③ leave 折条: [Mov rsp←rbp S64; Pop rbp S64] (lifter extra 通道产出,
    // translator 侧两既有通路直发, 零新机制):
    //   [0] Mov r4←r5 S64          (rsp := rbp)
    //   [1] Load r5←[r4] S64       (rbp := [rsp])
    //   [2] Add r4, 8 S64          (rsp += 8)
    ir::Insn pp = I(ir::Op::Pop, ir::Size::S64);
    pp.dst = ir::Operand::reg_(ir::Reg::Rbp);
    const auto r = wvmp::regvm::translator::translate_function(fn_of({blk(
        0x1000, {mov(ir::Reg::Rsp, ir::Reg::Rbp, ir::Size::S64), pp})}));
    // MIT-451 (X5b) B.2：本用例为合成截断形（leave 无 ret 落 Halt，d=-8）——
    // 出口平衡规则双向生效（物理 esp = ns，d 任意非 0 皆失配），gate note 为
    // 预期；折条字节码形状照旧钉死。真实形态 leave;ret 走 Ret 出口自配平，
    // 不触发本 note（见 RetTerminatorNeedsNoFallthrough 形状）。
    ASSERT_EQ(r.notes.size(), static_cast<size_t>(1));
    EXPECT_NE(r.notes[0].find("stack-depth-gate"), std::string::npos);
    const Decoded d = decode_program(r.program);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(5));  // 3 + Jmp + Halt
    expect_is(d.insns[0], VmOp::Mov, OpKind::Reg, kRsp, OpKind::Reg, kRbp, 0, kS64);
    expect_is(d.insns[1], VmOp::Load, OpKind::Reg, kRbp, OpKind::Reg, kRsp, 0, kS64);
    expect_is(d.insns[2], VmOp::Add, OpKind::Reg, kRsp, OpKind::Imm, 0, 8, kS64);
}

TEST(Translate, PlainStringSingleStepFolds) {
    // ② plain 单发形 (域 23..27): "循环一次" — 无 rcx 预检/无回边/无 flags 包裹。
    // plain movsd (23, S32): Load t,[rsi]; Store [rdi],t; Add rsi,4; Add rdi,4
    const Decoded d1 = one_insn_n(str_op(23, ir::Size::S32));
    ASSERT_EQ(d1.insns.size(), static_cast<size_t>(6));  // 4 + Jmp + Halt
    const u8 s18 = isa::kScratchFirst;
    const u8 kRsi = isa::vm_reg_of(ir::Reg::Rsi);
    const u8 kRdi = isa::vm_reg_of(ir::Reg::Rdi);
    expect_is(d1.insns[0], VmOp::Load, OpKind::Reg, s18, OpKind::Reg, kRsi, 0, kS32);
    expect_is(d1.insns[1], VmOp::Store, OpKind::Reg, kRdi, OpKind::Reg, s18, 0, kS32);
    expect_is(d1.insns[2], VmOp::Add, OpKind::Reg, kRsi, OpKind::Imm, 0, 4, kS64);
    expect_is(d1.insns[3], VmOp::Add, OpKind::Reg, kRdi, OpKind::Imm, 0, 4, kS64);

    // plain lodsd (27, S32): Load rax,[rsi]; Add rsi,4 — 无 flags 包裹 (原生
    // lods 不写 flags)。
    const Decoded d2 = one_insn_n(str_op(27, ir::Size::S32));
    ASSERT_EQ(d2.insns.size(), static_cast<size_t>(4));  // 2 + Jmp + Halt
    expect_is(d2.insns[0], VmOp::Load, OpKind::Reg, kRax, OpKind::Reg, kRsi, 0, kS32);
    expect_is(d2.insns[1], VmOp::Add, OpKind::Reg, kRsi, OpKind::Imm, 0, 4, kS64);

    // plain scasd (25, S32): Load t,[rdi]; Cmp rax,t; Add rdi,4 — Cmp 后直落,
    // flags = 末次比较 (原生), 无 GetFlags/SetFlags。
    const Decoded d3 = one_insn_n(str_op(25, ir::Size::S32));
    ASSERT_EQ(d3.insns.size(), static_cast<size_t>(5));  // 3 + Jmp + Halt
    expect_is(d3.insns[0], VmOp::Load, OpKind::Reg, s18, OpKind::Reg, kRdi, 0, kS32);
    expect_is(d3.insns[1], VmOp::Cmp, OpKind::Reg, kRax, OpKind::Reg, s18, 0, kS32);
    expect_is(d3.insns[2], VmOp::Add, OpKind::Reg, kRdi, OpKind::Imm, 0, 4, kS64);

    // plain cmpsd (26, S32): Load t1,[rsi]; Load t2,[rdi]; Cmp t1,t2; Add rdi;
    // Add rsi — 双指针推进。
    const Decoded d4 = one_insn_n(str_op(26, ir::Size::S32));
    ASSERT_EQ(d4.insns.size(), static_cast<size_t>(7));  // 5 + Jmp + Halt
    expect_is(d4.insns[0], VmOp::Load, OpKind::Reg, s18, OpKind::Reg, kRsi, 0, kS32);
    expect_is(d4.insns[1], VmOp::Load, OpKind::Reg, s18 + 1, OpKind::Reg, kRdi, 0, kS32);
    expect_is(d4.insns[2], VmOp::Cmp, OpKind::Reg, s18, OpKind::Reg, s18 + 1, 0, kS32);
    expect_is(d4.insns[3], VmOp::Add, OpKind::Reg, kRdi, OpKind::Imm, 0, 4, kS64);
    expect_is(d4.insns[4], VmOp::Add, OpKind::Reg, kRsi, OpKind::Imm, 0, 4, kS64);

    // plain movsq (23, S64): 步长 8。
    const Decoded d5 = one_insn_n(str_op(23, ir::Size::S64));
    ASSERT_EQ(d5.insns.size(), static_cast<size_t>(6));
    expect_is(d5.insns[2], VmOp::Add, OpKind::Reg, kRsi, OpKind::Imm, 0, 8, kS64);
}

TEST(Translate, PlainStringEmitsSingleStepNote) {
    std::vector<std::string> notes;
    (void)one_insn_n(str_op(23, ir::Size::S32), &notes);
    ASSERT_EQ(notes.size(), static_cast<size_t>(1));
    // "string-op @" 前缀 = backend 过滤白名单 (413 纪律, 命中不触发 gate)
    EXPECT_NE(notes[0].find("string-op @"), std::string::npos);
    EXPECT_NE(notes[0].find("plain movsd single-step"), std::string::npos);
}

TEST(Translate, CbwCarrierMicroProgramWords) {
    // ⑥ cbw 载体 (Op::Movsx + src2=28): GetFlags s_f; Mov s0←rax; Movsx
    // rax←rax (aux=0 byte 源); Shr s0,16; Shl s0,16; And rax,0xFFFF;
    // Or rax,s0; SetFlags s_f — 8 VmOp, 高 48 位保持 + flags 包裹 (G8a 先例)。
    ir::Insn i = I(ir::Op::Movsx, ir::Size::S16);
    i.src_size = ir::Size::S8;
    i.dst = ir::Operand::reg_(ir::Reg::Rax);
    i.src = ir::Operand::reg_(ir::Reg::Rax);
    i.src2 = ir::Operand::imm_(28);
    const Decoded d = one_insn_n(i);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(10));  // 8 + Jmp + Halt
    const u8 s_f = isa::kScratchFirst;
    const u8 s0 = isa::kScratchFirst + 1;
    expect_is(d.insns[0], VmOp::GetFlags, OpKind::Reg, s_f, OpKind::None, 0, 0, kS64);
    expect_is(d.insns[1], VmOp::Mov, OpKind::Reg, s0, OpKind::Reg, kRax, 0, kS64);
    expect_is(d.insns[2], VmOp::Movsx, OpKind::Reg, kRax, OpKind::Reg, kRax, 0, kS64);
    expect_is(d.insns[3], VmOp::Shr, OpKind::Reg, s0, OpKind::Imm, 0, 16, kS64);
    expect_is(d.insns[4], VmOp::Shl, OpKind::Reg, s0, OpKind::Imm, 0, 16, kS64);
    expect_is(d.insns[5], VmOp::And, OpKind::Reg, kRax, OpKind::Imm, 0, 0xFFFF, kS64);
    expect_is(d.insns[6], VmOp::Or, OpKind::Reg, kRax, OpKind::Reg, s0, 0, kS64);
    expect_is(d.insns[7], VmOp::SetFlags, OpKind::Reg, s_f, OpKind::None, 0, 0, kS64);
}

TEST(Translate, CwdeFoldTranslateWords) {
    // ⑥ cwde 两 IR 折条: [Movsx{rax←rax, aux=1(S16 源), S32}; Mov{rax←rax,
    // S32}] — 第二条 "mov eax,eax" 零扩展 idiom 清槽高位 (build_mov S32
    // writeback 零扩展), 槽终态 = zext32(sx32(ax)) = 原生 cwde。
    ir::Insn sx = I(ir::Op::Movsx, ir::Size::S32);
    sx.src_size = ir::Size::S16;
    sx.dst = ir::Operand::reg_(ir::Reg::Rax);
    sx.src = ir::Operand::reg_(ir::Reg::Rax);
    ir::Insn zx = I(ir::Op::Mov, ir::Size::S32);
    zx.dst = ir::Operand::reg_(ir::Reg::Rax);
    zx.src = ir::Operand::reg_(ir::Reg::Rax);
    const auto r = wvmp::regvm::translator::translate_function(
        fn_of({blk(0x1000, {sx, zx})}));
    EXPECT_TRUE(r.notes.empty());
    const Decoded d = decode_program(r.program);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(4));  // 2 + Jmp + Halt
    expect_is(d.insns[0], VmOp::Movsx, OpKind::Reg, kRax, OpKind::Reg, kRax, 1, kS32);
    expect_is(d.insns[1], VmOp::Mov, OpKind::Reg, kRax, OpKind::Reg, kRax, 0, kS32);
}

TEST(Translate, CallMemNegDispFoldsLoadCallGateRegForm) {
    // MIT-445 (X3c B.1) 翻案 442 D4 停手钉（原 CallMemGateNoteX3）:
    // call [rbp-8]（FF 55 F8, 栈槽函数指针形）折条 = Mov acc←rbp +
    // Sub acc,|disp|（负 disp 零扩展限制 → 减法等价, pitfall #6）+
    // Load val←acc + CallGate reg 形。
    ir::Insn c = I(ir::Op::Call, ir::Size::S64);
    c.dst = ir::Operand::mem_(m(ir::Reg::Rbp, ir::Reg::Flags, 0, -8));
    const auto r = wvmp::regvm::translator::translate_function(fn_of({blk(0x1000, {c})}));
    EXPECT_TRUE(r.notes.empty());
    const Decoded d = decode_program(r.program);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(6));  // 4 + Jmp + Halt
    expect_is(d.insns[0], VmOp::Mov, OpKind::Reg, isa::kScratchFirst,
              OpKind::Reg, isa::vm_reg_of(ir::Reg::Rbp), 0u, kS64);
    expect_is(d.insns[1], VmOp::Sub, OpKind::Reg, isa::kScratchFirst,
              OpKind::Imm, 0, 8u, kS64);
    expect_is(d.insns[2], VmOp::Load, OpKind::Reg, isa::kScratchFirst + 1,
              OpKind::Reg, isa::kScratchFirst, 0u, kS64);
    expect_is(d.insns[3], VmOp::CallGate, OpKind::Reg, isa::kScratchFirst + 1,
              OpKind::None, 0, 0u, 0u);
}

} // namespace

// ==================== MIT-446 (X4) B.2/D5: S64 tag 改形防回归 ====================

ir::Insn push_insn(ir::Reg r, ir::Size sz) {
    ir::Insn i = I(ir::Op::Push, sz);
    i.dst = ir::Operand::reg_(r);
    return i;
}
ir::Insn pop_insn(ir::Reg r, ir::Size sz) {
    ir::Insn i = I(ir::Op::Pop, sz);
    i.dst = ir::Operand::reg_(r);
    return i;
}

TEST(Translate, X86PushPopSingleOpForm) {
    // B.2 点位①：x86 push/pop → 单 VmOp::Push/Pop（X3b 4B handler，a_kind=
    // Reg）。若改形回退为 Sub/Add rsp（S64 tag），x86 运行时 3 路尺寸链折
    // 防御 no-op 静默空转——本用例即 D5 "S64 no-op 复辟探测器" 的翻译层面。
    ir::FunctionRegion fn = fn_of({
        blk(0x1000, {push_insn(ir::Reg::Rax, ir::Size::S32),
                     pop_insn(ir::Reg::Rbx, ir::Size::S32)}),
    });
    fn.arch = ir::Arch::X86;
    const auto r = wvmp::regvm::translator::translate_function(fn);
    EXPECT_TRUE(r.notes.empty());
    const Decoded d = decode_program(r.program);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(4));  // 2 + Jmp(+1) + Halt
    expect_is(d.insns[0], VmOp::Push, OpKind::Reg, kRax, OpKind::None, 0, 0, kS32);
    expect_is(d.insns[1], VmOp::Pop, OpKind::Reg, kRbx, OpKind::None, 0, 0, kS32);
}

// ==================== MIT-451 (X5b) B.2: 栈深 walk 正反例 ====================

namespace {
ir::FunctionRegion fn86_of(std::vector<ir::BasicBlock> blocks) {
    ir::FunctionRegion fn = fn_of(std::move(blocks));
    fn.arch = ir::Arch::X86;
    return fn;
}
ir::Insn alu_ri(ir::Op op, ir::Reg d, i64 imm, ir::Size sz) {
    return alu(op, ir::Operand::reg_(d), ir::Operand::imm_(imm), sz);
}
ir::Insn store_mem(ir::Reg base, i64 disp, ir::Reg src, ir::Size sz) {
    ir::Insn i = I(ir::Op::Store, sz);
    i.dst = ir::Operand::mem_(m(base, ir::Reg::Flags, 0, disp));
    i.src = ir::Operand::reg_(src);
    return i;
}
bool has_stack_depth_gate(const wvmp::regvm::translator::TranslateResult& r) {
    for (const auto& n : r.notes)
        if (n.find("stack-depth-gate") != std::string::npos) return true;
    return false;
}
// ---- MIT-451 (X5b) B.4: REG-REG 位测试族翻译层用例 ---------------------
// 载体 IR（lifter B.4 产物：Op::Mov + src2=族标记 + dst/src Reg）→ 单
// VmOp::Xadd/Bts/Btr/Btc，b_kind=None 判别（reg_a = dst 槽、reg_b = src 槽）。

ir::Insn bitreg_carrier(i64 marker, ir::Reg d, ir::Reg sr, ir::Size sz) {
    ir::Insn i = I(ir::Op::Mov, sz);
    i.dst = ir::Operand::reg_(d);
    i.src = ir::Operand::reg_(sr);
    i.src2 = ir::Operand::imm_(marker);
    i.updates_flags = true;
    return i;
}

TEST(Translate, BitRegRegX86EmitsBKindNoneSingleOp) {
    // x86 xadd ebx, eax（载体 5）→ 单 VmOp::Xadd，b_kind=None、reg_a=ebx 槽、
    // reg_b=eax 槽；lock-strip note 照发（载体族既有 note 通道）。
    ir::FunctionRegion fn = fn86_of({blk(0x1000, {
        bitreg_carrier(5, ir::Reg::Rbx, ir::Reg::Rax, ir::Size::S32)})});
    const auto r = wvmp::regvm::translator::translate_function(fn);
    ASSERT_EQ(r.notes.size(), static_cast<size_t>(1));
    EXPECT_NE(r.notes[0].find("lock-strip"), std::string::npos);
    const Decoded d = decode_program(r.program);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(3));  // 1 + Jmp + Halt
    expect_is(d.insns[0], VmOp::Xadd, OpKind::Reg,
              isa::vm_reg_of(ir::Reg::Rbx), OpKind::None,
              isa::vm_reg_of(ir::Reg::Rax), 0, kS32);
}

TEST(Translate, BitRegRegX86BitOpsBKindNone) {
    // bts/btr/btc（载体 6/7/8）同构单 op 形。
    const std::pair<i64, VmOp> fams[] = {{6, VmOp::Bts}, {7, VmOp::Btr},
                                         {8, VmOp::Btc}};
    for (const auto& [marker, vop] : fams) {
        ir::FunctionRegion fn = fn86_of({blk(0x1000, {
            bitreg_carrier(marker, ir::Reg::Rbx, ir::Reg::Rax, ir::Size::S32)})});
        const auto r = wvmp::regvm::translator::translate_function(fn);
        ASSERT_EQ(r.notes.size(), static_cast<size_t>(1));
        const Decoded d = decode_program(r.program);
        ASSERT_EQ(d.insns.size(), static_cast<size_t>(3));
        expect_is(d.insns[0], vop, OpKind::Reg,
                  isa::vm_reg_of(ir::Reg::Rbx), OpKind::None,
                  isa::vm_reg_of(ir::Reg::Rax), 0, kS32);
    }
}

TEST(Translate, BitRegRegX64StaysGated) {
    // x64 载体 REG-REG（lifter 不产，防御面）→ 照旧 skip gate。
    ir::FunctionRegion fn = fn_of({blk(0x1000, {
        bitreg_carrier(6, ir::Reg::Rbx, ir::Reg::Rax, ir::Size::S64)})});
    const auto r = wvmp::regvm::translator::translate_function(fn);
    // notes = [lock-strip 载体 note, skip gate note]（run() 入口先发 strip 披露）。
    ASSERT_EQ(r.notes.size(), static_cast<size_t>(2));
    EXPECT_NE(r.notes[1].find("lock bit 操作数形态未支持"), std::string::npos);
}

TEST(Translate, BitRegRegSameRegXaddStaysGated) {
    // 同寄存器 xadd（写序冲突面）→ translator gate（宁窄勿宽）。
    ir::FunctionRegion fn = fn86_of({blk(0x1000, {
        bitreg_carrier(5, ir::Reg::Rax, ir::Reg::Rax, ir::Size::S32)})});
    const auto r = wvmp::regvm::translator::translate_function(fn);
    ASSERT_EQ(r.notes.size(), static_cast<size_t>(2));
    EXPECT_NE(r.notes[1].find("lock xadd 操作数形态未支持"), std::string::npos);
}

} // namespace

TEST(Translate, StackWalkX86BalancedPushesPass) {
    // 正例：平衡 push/pop（真实 /Od spill 形）在 guard 预算内 → 无 note。
    // 覆盖 mul64hi 之外的 4 个 wvmpTest 翻正区的静态形态。
    ir::FunctionRegion fn = fn86_of({blk(0x1000, {
        push_insn(ir::Reg::Rbx, ir::Size::S32),
        push_insn(ir::Reg::Rsi, ir::Size::S32),
        pop_insn(ir::Reg::Rsi, ir::Size::S32),
        pop_insn(ir::Reg::Rbx, ir::Size::S32),
    })});
    const auto r = wvmp::regvm::translator::translate_function(fn);
    EXPECT_TRUE(r.notes.empty());
}

TEST(Translate, StackWalkX86SubEspOverBudgetGates) {
    // 反例①：sub esp,0x200 净深 512 > kX86GuardBytes(128) → 整函数 gate。
    const auto r = wvmp::regvm::translator::translate_function(
        fn86_of({blk(0x1000, {alu_ri(ir::Op::Sub, ir::Reg::Rsp, 0x200, ir::Size::S32)})}));
    EXPECT_TRUE(has_stack_depth_gate(r));
}

TEST(Translate, StackWalkX86FrameReachOverBudgetGates) {
    // 反例②：mov ebp,esp + [ebp-0x200] 别名 reach 0x204 > 预算 → gate。
    const auto r = wvmp::regvm::translator::translate_function(
        fn86_of({blk(0x1000, {mov(ir::Reg::Rbp, ir::Reg::Rsp, ir::Size::S32),
                              store_mem(ir::Reg::Rbp, -0x200, ir::Reg::Rax, ir::Size::S32)})}));
    EXPECT_TRUE(has_stack_depth_gate(r));
}

TEST(Translate, StackWalkX86FrameReachWithinBudgetPass) {
    // 正例：mov ebp,esp + [ebp-0x28]（mul64hi 局部帧形态）reach 0x2C ≤ 预算
    // → 无 note（guard 区吸收）。
    const auto r = wvmp::regvm::translator::translate_function(
        fn86_of({blk(0x1000, {mov(ir::Reg::Rbp, ir::Reg::Rsp, ir::Size::S32),
                              store_mem(ir::Reg::Rbp, -0x28, ir::Reg::Rax, ir::Size::S32)})}));
    EXPECT_TRUE(r.notes.empty());
}

TEST(Translate, StackWalkX86BackEdgeGrowthGates) {
    // 反例③：回边净深无界增长（循环体内 push 不配平）→ gate（D5 宁窄勿宽）。
    // b0@0x1000: push eax; add eax,1; jne 0x1000（回边时 d=4 > 目标 d=0）。
    // ⚠️ 显式真实 addr：回边检查按 d_at（insn.addr → d）对账，测试 helper
    // 默认固定 addr 会令目标 miss 而跳过（lifter 不变量下真实 IR 无此形态）。
    ir::Insn p = push_insn(ir::Reg::Rax, ir::Size::S32);
    ir::Insn a = alu_ri(ir::Op::Add, ir::Reg::Rax, 1, ir::Size::S32);
    ir::Insn j = jump(ir::Op::Jcc, 0x1000, ir::Cond::Ne);
    p.addr = 0x1000;
    a.addr = 0x1004;
    j.addr = 0x1007;
    const auto r = wvmp::regvm::translator::translate_function(
        fn86_of({blk(0x1000, {p, a, j})}));
    EXPECT_TRUE(has_stack_depth_gate(r));
}

TEST(Translate, StackWalkX86BalancedLoopPass) {
    // 正例：环内 push/pop 配平（回边 d == 目标 d）→ 无 note。
    // b0@0x1000: push; pop; add; jne 0x1000（回边 d=0）。
    ir::Insn p = push_insn(ir::Reg::Rax, ir::Size::S32);
    ir::Insn q = pop_insn(ir::Reg::Rax, ir::Size::S32);
    ir::Insn a = alu_ri(ir::Op::Add, ir::Reg::Rax, 1, ir::Size::S32);
    ir::Insn j = jump(ir::Op::Jcc, 0x1000, ir::Cond::Ne);
    p.addr = 0x1000;
    q.addr = 0x1004;
    a.addr = 0x1008;
    j.addr = 0x100b;
    const auto r = wvmp::regvm::translator::translate_function(
        fn86_of({blk(0x1000, {p, q, a, j})}));
    EXPECT_TRUE(r.notes.empty());
}

TEST(Translate, StackWalkX86ExitNativeUnbalancedGates) {
    // 反例④：ExitNative 出口 d != 0（出口物理 esp = ns，真实 = ns-d）→ gate。
    // push 后 jcc 0x8000（越区，begin=0x1000/end=0x3000 外）。
    const auto r = wvmp::regvm::translator::translate_function(fn86_of({
        blk(0x1000, {push_insn(ir::Reg::Rax, ir::Size::S32),
                     jump(ir::Op::Jcc, 0x8000, ir::Cond::Ne)})}));
    EXPECT_TRUE(has_stack_depth_gate(r));
}

TEST(Translate, StackWalkX86HaltUnbalancedGatesMul64hiShape) {
    // 反例⑤：mul64hi 形（call-arg push ×N、清栈在区外延迟执行）→ Halt 出口
    // d=0x40 ≠ 0 → gate（行为保真：修复前该形写穿保存区确定性 AV）。
    std::vector<ir::Insn> v;
    for (int i = 0; i < 16; ++i) v.push_back(push_insn(ir::Reg::Rax, ir::Size::S32));
    const auto r = wvmp::regvm::translator::translate_function(
        fn86_of({blk(0x1000, v)}));
    EXPECT_TRUE(has_stack_depth_gate(r));
}

TEST(Translate, StackWalkX64ZeroBudgetGatesAnyPush) {
    // D4 双 arch 对称：x64 无 guard（budget=0）→ 任何区内 push 即 gate
    // （手写/第三方 x64 形态的现网盲区预防；MSVC x64 产物 sub rsp 形不受扰
    // —— sub rsp 仅在净深 > 0 时由本 walk 记账，budget=0 下同样 gate，
    // wvmpTest x64 0 gate 基线由 multiseed 双跑对账）。
    const auto r = wvmp::regvm::translator::translate_function(
        fn_of({blk(0x1000, {push_insn(ir::Reg::Rax, ir::Size::S64)})}));
    EXPECT_TRUE(has_stack_depth_gate(r));
}

TEST(Translate, X64PushPopLegacyShapeUnchanged) {
    // D2 恒等铁约束：x64 push/pop 维持 Sub rsp/Load+Add 现形（S64 tag）。
    // MIT-451 (X5b) B.2：x64 walk budget=0 → 区内 push 附 gate note（展开形
    // 逐字节不变；gate 语义见 PushPopExpansion 注）。
    const auto r = wvmp::regvm::translator::translate_function(fn_of({
        blk(0x1000, {push_insn(ir::Reg::Rax, ir::Size::S64),
                     pop_insn(ir::Reg::Rbx, ir::Size::S64)}),
    }));
    ASSERT_EQ(r.notes.size(), static_cast<size_t>(1));
    EXPECT_NE(r.notes[0].find("stack-depth-gate"), std::string::npos);
    const Decoded d = decode_program(r.program);
    const u8 rsp = isa::vm_reg_of(ir::Reg::Rsp);
    ASSERT_EQ(d.insns.size(), static_cast<size_t>(6));  // Sub,Store,Load,Add,Jmp,Halt
    expect_is(d.insns[0], VmOp::Sub, OpKind::Reg, rsp, OpKind::Imm, 0, 8, kS64);
    expect_is(d.insns[1], VmOp::Store, OpKind::Reg, rsp, OpKind::Reg, kRax, 0, kS64);
    expect_is(d.insns[2], VmOp::Load, OpKind::Reg, kRbx, OpKind::Reg, rsp, 0, kS64);
    expect_is(d.insns[3], VmOp::Add, OpKind::Reg, rsp, OpKind::Imm, 0, 8, kS64);
}

TEST(Translate, X86AddressArithmeticUsesS32StepTag) {
    // B.2 点位②：x86 地址算术（base+disp 拼装）走 S32 步进 tag——x86 运行
    // 时 3 路尺寸链走真块；x64 对照组维持 S64（同函数双 arch 快照钉死）。
    ir::Insn ld = I(ir::Op::Load, ir::Size::S32);
    ld.dst = ir::Operand::reg_(ir::Reg::Rax);
    ld.src = ir::Operand::mem_(m(ir::Reg::Rbx, ir::Reg::Flags, 0, 0x10));
    ir::FunctionRegion fn86 = fn_of({blk(0x1000, {ld})});
    fn86.arch = ir::Arch::X86;
    const auto r86 = wvmp::regvm::translator::translate_function(fn86);
    EXPECT_TRUE(r86.notes.empty());
    const Decoded d86 = decode_program(r86.program);
    ASSERT_EQ(d86.insns.size(), static_cast<size_t>(5));  // Mov,Add,Load,Jmp,Halt
    expect_is(d86.insns[0], VmOp::Mov, OpKind::Reg, d86.insns[0].reg_a,
              OpKind::Reg, kRbx, 0, kS32);
    expect_is(d86.insns[1], VmOp::Add, OpKind::Reg, d86.insns[1].reg_a,
              OpKind::Imm, 0, 0x10, kS32);
    expect_is(d86.insns[2], VmOp::Load, OpKind::Reg, kRax, OpKind::Reg,
              d86.insns[2].reg_b, 0, kS32);

    const auto r64 = wvmp::regvm::translator::translate_function(fn_of({
        blk(0x1000, {ld})}));
    const Decoded d64 = decode_program(r64.program);
    ASSERT_EQ(d64.insns.size(), static_cast<size_t>(5));
    expect_is(d64.insns[0], VmOp::Mov, OpKind::Reg, d64.insns[0].reg_a,
              OpKind::Reg, kRbx, 0, kS64);
    expect_is(d64.insns[1], VmOp::Add, OpKind::Reg, d64.insns[1].reg_a,
              OpKind::Imm, 0, 0x10, kS64);
}
