// Lifter lane 单元测试：寄存器/指令映射、ALU+内存约定、基本块划分、
// RVA↔文件偏移映射与 LifterPass::run() 端到端（合成 PE）。

#include "capstone_session.hpp"
#include "lifter_core.hpp"
#include "pe_map.hpp"
#include "x86_translate.hpp"

#include "wvmp/common/bytes.hpp"
#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/ir/insn.hpp"
#include "wvmp/ir/operand.hpp"
#include "wvmp/ir/reg.hpp"
#include "wvmp/passes/lifter/lifter_pass.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <span>
#include <vector>

namespace {

namespace lifter = wvmp::passes::lifter;
namespace ir = wvmp::ir;

// 反汇编 bytes 的第一条指令；失败返回 nullptr。
const cs_insn* decode_first(lifter::CapstoneSession& s, std::span<const wvmp::u8> bytes,
                            wvmp::u64 at = 0) {
    const wvmp::u8* p = bytes.data();
    size_t left = bytes.size();
    wvmp::u64 addr = at;
    return s.next(p, left, addr);
}

lifter::TranslateResult translate_bytes(lifter::CapstoneSession& s,
                                        std::span<const wvmp::u8> bytes, ir::Arch arch,
                                        wvmp::u64 at = 0) {
    const cs_insn* ci = decode_first(s, bytes, at);
    if (ci == nullptr) {
        ADD_FAILURE() << "capstone 无法反汇编测试字节";
        return lifter::TranslateResult{};
    }
    return lifter::translate_insn(*ci, arch);
}

TEST(LifterRegMap, SubRegistersFoldToFullReg) {
    EXPECT_EQ(lifter::map_reg(X86_REG_RAX), ir::Reg::Rax);
    EXPECT_EQ(lifter::map_reg(X86_REG_EAX), ir::Reg::Rax);
    EXPECT_EQ(lifter::map_reg(X86_REG_AX), ir::Reg::Rax);
    EXPECT_EQ(lifter::map_reg(X86_REG_AL), ir::Reg::Rax);
    EXPECT_EQ(lifter::map_reg(X86_REG_AH), ir::Reg::Rax);
    EXPECT_EQ(lifter::map_reg(X86_REG_R15D), ir::Reg::R15);
    EXPECT_EQ(lifter::map_reg(X86_REG_R10W), ir::Reg::R10);
    EXPECT_EQ(lifter::map_reg(X86_REG_R8B), ir::Reg::R8);
    EXPECT_EQ(lifter::map_reg(X86_REG_RSP), ir::Reg::Rsp);
    EXPECT_EQ(lifter::map_reg(X86_REG_BPL), ir::Reg::Rbp);
    EXPECT_EQ(lifter::map_reg(X86_REG_RIP), ir::Reg::Rip);
    EXPECT_EQ(lifter::map_reg(X86_REG_EIP), ir::Reg::Rip);
    EXPECT_EQ(lifter::map_reg(X86_REG_XMM0), std::nullopt);
    EXPECT_EQ(lifter::map_reg(X86_REG_FS), std::nullopt);
    EXPECT_EQ(lifter::map_reg(X86_REG_EFLAGS), std::nullopt);
}

TEST(LifterCondMap, AllSixteenJcc) {
    EXPECT_EQ(lifter::map_cond(X86_INS_JO), ir::Cond::O);
    EXPECT_EQ(lifter::map_cond(X86_INS_JNO), ir::Cond::No);
    EXPECT_EQ(lifter::map_cond(X86_INS_JB), ir::Cond::B);
    EXPECT_EQ(lifter::map_cond(X86_INS_JAE), ir::Cond::Ae);
    EXPECT_EQ(lifter::map_cond(X86_INS_JE), ir::Cond::E);
    EXPECT_EQ(lifter::map_cond(X86_INS_JNE), ir::Cond::Ne);
    EXPECT_EQ(lifter::map_cond(X86_INS_JBE), ir::Cond::Be);
    EXPECT_EQ(lifter::map_cond(X86_INS_JA), ir::Cond::A);
    EXPECT_EQ(lifter::map_cond(X86_INS_JS), ir::Cond::S);
    EXPECT_EQ(lifter::map_cond(X86_INS_JNS), ir::Cond::Ns);
    EXPECT_EQ(lifter::map_cond(X86_INS_JP), ir::Cond::P);
    EXPECT_EQ(lifter::map_cond(X86_INS_JNP), ir::Cond::Np);
    EXPECT_EQ(lifter::map_cond(X86_INS_JL), ir::Cond::L);
    EXPECT_EQ(lifter::map_cond(X86_INS_JGE), ir::Cond::Ge);
    EXPECT_EQ(lifter::map_cond(X86_INS_JLE), ir::Cond::Le);
    EXPECT_EQ(lifter::map_cond(X86_INS_JG), ir::Cond::G);
    EXPECT_EQ(lifter::map_cond(X86_INS_JECXZ), std::nullopt);
}

// ---------------- 指令映射：每类至少一条 ----------------

class LifterTranslate : public ::testing::Test {
protected:
    lifter::CapstoneSession x64{ir::Arch::X64};
    lifter::CapstoneSession x86{ir::Arch::X86};
};

TEST_F(LifterTranslate, MovImmToReg) {
    // B8 01 00 00 00: mov eax, 1
    const wvmp::u8 b[] = {0xB8, 0x01, 0x00, 0x00, 0x00};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Mov);
    EXPECT_EQ(r.insn.size, ir::Size::S32); // 子寄存器宽度由 size 携带
    EXPECT_FALSE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax); // EAX 折叠到 Rax
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r.insn.src.imm, 1);
    EXPECT_EQ(r.insn.addr, 0u);
}

// MIT-249 关联修复: movabs（mov reg, imm64）必须被 lifter 接住——否则区域内
// 含 imm64 load 会被静默跳过、且 C1 gate 只看翻译器 notes 不看 lifter notes，
// 函数仍被虚拟化，原区域 movabs 字节被 stub_link 覆写后字节码缺一块、行为错。
// 字节: 48 B8 BE BA FE CA EF BE AD DE = movabs rax, 0xDEADBEEFCAFEBABE
TEST_F(LifterTranslate, MovAbsImm64ToReg) {
    const wvmp::u8 b[] = {0x48, 0xB8, 0xBE, 0xBA, 0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Mov);
    EXPECT_EQ(r.insn.size, ir::Size::S64);
    EXPECT_FALSE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(static_cast<wvmp::u64>(r.insn.src.imm), 0xDEADBEEFCAFEBABEull);
}

TEST_F(LifterTranslate, MovRegToReg64) {
    // 48 89 C1: mov rcx, rax
    const wvmp::u8 b[] = {0x48, 0x89, 0xC1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Mov);
    EXPECT_EQ(r.insn.size, ir::Size::S64);
    EXPECT_FALSE(r.insn.updates_flags);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rcx);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rax);
}

TEST_F(LifterTranslate, AddRegReg) {
    // 01 D8: add eax, ebx
    const wvmp::u8 b[] = {0x01, 0xD8};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Add);
    EXPECT_EQ(r.insn.size, ir::Size::S32);
    EXPECT_TRUE(r.insn.updates_flags);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rbx);
}

TEST_F(LifterTranslate, AluSrcMemKeepsAluOp) {
    // 03 06: add eax, dword ptr [rsi]
    // v1 约定：ALU 的 src 为内存时不拆 Load，op 保持 Add，src.mem 原样保留，
    // 由后端（vm translator）翻译时展开。
    const wvmp::u8 b[] = {0x03, 0x06};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Add);
    EXPECT_EQ(r.insn.size, ir::Size::S32);
    EXPECT_TRUE(r.insn.updates_flags);
    EXPECT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.src.mem.base, ir::Reg::Rsi);
    EXPECT_EQ(r.insn.src.mem.index, ir::Reg::Flags); // 哨兵=无 index
    EXPECT_EQ(r.insn.src.mem.scale, 0);
    EXPECT_EQ(r.insn.src.mem.disp, 0);
}

TEST_F(LifterTranslate, AluDstMem) {
    // 01 00: add dword ptr [rax], eax
    const wvmp::u8 b[] = {0x01, 0x00};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Add);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.dst.mem.base, ir::Reg::Rax);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rax);
    EXPECT_TRUE(r.insn.updates_flags);
}

TEST_F(LifterTranslate, LoadFromAbsoluteAddress) {
    // 48 8B 04 25 00 10 00 00: mov rax, qword ptr [0x1000]
    const wvmp::u8 b[] = {0x48, 0x8B, 0x04, 0x25, 0x00, 0x10, 0x00, 0x00};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Load); // 内存 → 寄存器
    EXPECT_EQ(r.insn.size, ir::Size::S64);
    EXPECT_FALSE(r.insn.updates_flags);
    EXPECT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.src.mem.base, ir::Reg::Flags); // 无 base
    EXPECT_EQ(r.insn.src.mem.index, ir::Reg::Flags); // 无 index
    EXPECT_EQ(r.insn.src.mem.scale, 0);
    EXPECT_EQ(r.insn.src.mem.disp, 0x1000);
}

TEST_F(LifterTranslate, LoadWithIndexScale) {
    // 8B 04 83: mov eax, dword ptr [rbx + rax*4]
    const wvmp::u8 b[] = {0x8B, 0x04, 0x83};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Load);
    EXPECT_EQ(r.insn.size, ir::Size::S32);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.src.mem.base, ir::Reg::Rbx);
    EXPECT_EQ(r.insn.src.mem.index, ir::Reg::Rax);
    EXPECT_EQ(r.insn.src.mem.scale, 4);
    EXPECT_EQ(r.insn.src.mem.disp, 0);
}

TEST_F(LifterTranslate, StoreImmToMem) {
    // C6 00 01: mov byte ptr [rax], 1
    const wvmp::u8 b[] = {0xC6, 0x00, 0x01};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Store); // 寄存器/立即数 → 内存
    EXPECT_EQ(r.insn.size, ir::Size::S8);
    EXPECT_FALSE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.dst.mem.base, ir::Reg::Rax);
    EXPECT_EQ(r.insn.dst.mem.index, ir::Reg::Flags);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r.insn.src.imm, 1);
}

TEST_F(LifterTranslate, StoreRegToMem) {
    // 48 89 08: mov qword ptr [rax], rcx
    const wvmp::u8 b[] = {0x48, 0x89, 0x08};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Store);
    EXPECT_EQ(r.insn.size, ir::Size::S64);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Mem);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rcx);
}

TEST_F(LifterTranslate, LeaRipRelativeKeepsRawDisp) {
    // 48 8D 0D 34 12 00 00: lea rcx, [rip + 0x1234]
    const wvmp::u8 b[] = {0x48, 0x8D, 0x0D, 0x34, 0x12, 0x00, 0x00};
    auto r = translate_bytes(x64, b, ir::Arch::X64, 0x401000);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Lea);
    EXPECT_EQ(r.insn.size, ir::Size::S64);
    EXPECT_FALSE(r.insn.updates_flags);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rcx);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.src.mem.base, ir::Reg::Rip);
    EXPECT_EQ(r.insn.src.mem.disp, 0x1234); // 保留原始位移（未加绝对地址）
    EXPECT_EQ(r.insn.addr, 0x401000u);
}

TEST_F(LifterTranslate, JccRelative) {
    // 74 05: je +5（@0 → 目标 7）
    const wvmp::u8 b[] = {0x74, 0x05};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Jcc);
    EXPECT_EQ(r.insn.cond, ir::Cond::E);
    EXPECT_EQ(r.insn.size, ir::Size::S64); // 控制流指令按 arch 取指针宽
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r.insn.dst.imm, 7);
    EXPECT_FALSE(r.insn.updates_flags);
}

TEST_F(LifterTranslate, JmpRelative) {
    // E9 01 00 00 00: jmp +1（@0 → 目标 6）
    const wvmp::u8 b[] = {0xE9, 0x01, 0x00, 0x00, 0x00};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Jmp);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r.insn.dst.imm, 6);
}

TEST_F(LifterTranslate, JmpRegister) {
    // FF E0: jmp rax
    const wvmp::u8 b[] = {0xFF, 0xE0};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Jmp);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);
}

TEST_F(LifterTranslate, CallRelative) {
    // E8 00 00 00 00: call +0（@0 → 目标 5）
    const wvmp::u8 b[] = {0xE8, 0x00, 0x00, 0x00, 0x00};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Call);
    EXPECT_EQ(r.insn.size, ir::Size::S64);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r.insn.dst.imm, 5);
}

TEST_F(LifterTranslate, Ret) {
    // C3: ret
    const wvmp::u8 b[] = {0xC3};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Ret);
    EXPECT_EQ(r.insn.size, ir::Size::S64);
    EXPECT_EQ(r.insn.dst.kind, ir::Operand::Kind::None);
    EXPECT_EQ(r.insn.src.kind, ir::Operand::Kind::None);
}

TEST_F(LifterTranslate, RetImm) {
    // C2 08 00: ret 8
    const wvmp::u8 b[] = {0xC2, 0x08, 0x00};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Ret);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r.insn.src.imm, 8);
}

TEST_F(LifterTranslate, PushPop) {
    // 50: push rax
    const wvmp::u8 pb[] = {0x50};
    auto p = translate_bytes(x64, pb, ir::Arch::X64);
    ASSERT_EQ(p.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(p.insn.op, ir::Op::Push);
    EXPECT_FALSE(p.insn.updates_flags);
    ASSERT_EQ(p.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(p.insn.dst.reg, ir::Reg::Rax);

    // 5B: pop rbx
    const wvmp::u8 qb[] = {0x5B};
    auto q = translate_bytes(x64, qb, ir::Arch::X64);
    ASSERT_EQ(q.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(q.insn.op, ir::Op::Pop);
    ASSERT_EQ(q.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(q.insn.dst.reg, ir::Reg::Rbx);
}

TEST_F(LifterTranslate, CmpTest) {
    // 39 C8: cmp eax, ecx
    const wvmp::u8 cb[] = {0x39, 0xC8};
    auto c = translate_bytes(x64, cb, ir::Arch::X64);
    ASSERT_EQ(c.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(c.insn.op, ir::Op::Cmp);
    EXPECT_TRUE(c.insn.updates_flags);
    EXPECT_EQ(c.insn.dst.reg, ir::Reg::Rax);
    EXPECT_EQ(c.insn.src.reg, ir::Reg::Rcx);

    // 85 C0: test eax, eax
    const wvmp::u8 tb[] = {0x85, 0xC0};
    auto t = translate_bytes(x64, tb, ir::Arch::X64);
    ASSERT_EQ(t.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(t.insn.op, ir::Op::Test);
    EXPECT_TRUE(t.insn.updates_flags);
    EXPECT_EQ(t.insn.dst.reg, ir::Reg::Rax);
    EXPECT_EQ(t.insn.src.reg, ir::Reg::Rax);
}

TEST_F(LifterTranslate, ShiftsAndUnary) {
    // C1 E0 03: shl eax, 3
    const wvmp::u8 sb[] = {0xC1, 0xE0, 0x03};
    auto s = translate_bytes(x64, sb, ir::Arch::X64);
    ASSERT_EQ(s.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(s.insn.op, ir::Op::Shl);
    EXPECT_TRUE(s.insn.updates_flags);
    EXPECT_EQ(s.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(s.insn.src.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(s.insn.src.imm, 3);

    // D1 E0: shl eax（隐式计数 1）
    const wvmp::u8 ib[] = {0xD1, 0xE0};
    auto i = translate_bytes(x64, ib, ir::Arch::X64);
    ASSERT_EQ(i.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(i.insn.op, ir::Op::Shl);
    ASSERT_EQ(i.insn.src.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(i.insn.src.imm, 1);

    // F7 D8: neg eax（一元）
    const wvmp::u8 nb[] = {0xF7, 0xD8};
    auto n = translate_bytes(x64, nb, ir::Arch::X64);
    ASSERT_EQ(n.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(n.insn.op, ir::Op::Neg);
    EXPECT_TRUE(n.insn.updates_flags);
    EXPECT_EQ(n.insn.dst.reg, ir::Reg::Rax);

    // F7 D0: not eax（NOT 不影响标志）
    const wvmp::u8 ob[] = {0xF7, 0xD0};
    auto o = translate_bytes(x64, ob, ir::Arch::X64);
    ASSERT_EQ(o.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(o.insn.op, ir::Op::Not);
    EXPECT_FALSE(o.insn.updates_flags);

    // 48 FF C1: inc rcx
    const wvmp::u8 ub[] = {0x48, 0xFF, 0xC1};
    auto u = translate_bytes(x64, ub, ir::Arch::X64);
    ASSERT_EQ(u.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(u.insn.op, ir::Op::Inc);
    EXPECT_TRUE(u.insn.updates_flags);
    EXPECT_EQ(u.insn.dst.reg, ir::Reg::Rcx);

    // 90: nop
    const wvmp::u8 pb[] = {0x90};
    auto p = translate_bytes(x64, pb, ir::Arch::X64);
    ASSERT_EQ(p.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(p.insn.op, ir::Op::Nop);
    EXPECT_FALSE(p.insn.updates_flags);
}

// MIT-302: imul 三形式 (3-op imm / 2-op reg / 1-op F7/5) + mul 单操作数 (F7 /4)
// 都被 x86_translate 接住——snake 根因之一（MSVC /Od 的 Magic Number 乘法）。
// imm 形式 src=Reg + src2=Imm（src2 字段是 MIT-302 新增的第三操作数槽）；
// 其余形式只用 dst/src；mul 单操作数 dst 硬编码为 Rdx（Rax 是隐式被乘数）。
TEST_F(LifterTranslate, ImulThreeOperandImm) {
    // 69 C1 64 00 00 00: imul eax, ecx, 100 — 3-op imm 形式
    const wvmp::u8 b[] = {0x69, 0xC1, 0x64, 0x00, 0x00, 0x00};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Imul);
    EXPECT_EQ(r.insn.size, ir::Size::S32);        // imm 形式默认 S32
    EXPECT_TRUE(r.insn.updates_flags);             // OF/CF 当低半 != 高半
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rcx);
    ASSERT_EQ(r.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r.insn.src2.imm, 100);
    EXPECT_EQ(r.insn.addr, 0u);
}

TEST_F(LifterTranslate, ImulTwoOperandReg) {
    // 0F AF C1: imul eax, ecx — 2-op reg 形式
    const wvmp::u8 b[] = {0x0F, 0xAF, 0xC1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Imul);
    EXPECT_EQ(r.insn.size, ir::Size::S32);        // 32 位默认（eax 操作）
    EXPECT_TRUE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rcx);
    // 2-op 形式 src2 不应被设置（按 Imm 区分）
    EXPECT_NE(r.insn.src2.kind, ir::Operand::Kind::Imm);
}

TEST_F(LifterTranslate, ImulTwoOperandReg64) {
    // 48 0F AF C9: imul rcx, rcx — REX.W 触发 64 位 size
    const wvmp::u8 b[] = {0x48, 0x0F, 0xAF, 0xC9};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Imul);
    EXPECT_EQ(r.insn.size, ir::Size::S64);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rcx);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rcx);
}

TEST_F(LifterTranslate, ImulOneOperand) {
    // F7 E9: imul ecx — 1-op F7 /5 形式（极少见, lifter 转 Op::Mul 兜底）
    const wvmp::u8 b[] = {0xF7, 0xE9};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    // 1-op 形式被 lift 为 Op::Mul（与 mul 同形态：dst=Rdx 上半, src=乘数）
    EXPECT_EQ(r.insn.op, ir::Op::Mul);
    EXPECT_EQ(r.insn.size, ir::Size::S32);
    EXPECT_TRUE(r.insn.updates_flags);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rdx);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rcx);
}

TEST_F(LifterTranslate, MulOneOperand) {
    // F7 E1: mul ecx — 1-op F7 /4 形式（unsigned rdx:rax = rax * ecx）
    const wvmp::u8 b[] = {0xF7, 0xE1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Mul);
    EXPECT_EQ(r.insn.size, ir::Size::S32);
    EXPECT_TRUE(r.insn.updates_flags);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rdx);  // upper half
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rcx);
}

TEST_F(LifterTranslate, MulOneOperand64) {
    // 48 F7 E1: mul rcx — REX.W 触发 64 位 size
    const wvmp::u8 b[] = {0x48, 0xF7, 0xE1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Mul);
    EXPECT_EQ(r.insn.size, ir::Size::S64);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rdx);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rcx);
}

// MIT-306: imul MEM 形式 (MSVC /Od 实际 codegen, MIT-302 仅接 REG-REG, 导致
// wvmp_imul_sample 0% 真虚拟化)。字节编码来自项目主反汇编（派活单 §A）：
//   - 2-op REG-MEM: 48 0F AF 44 24 28 = imul rax, [rsp+0x28]
//   - 2-op REG-MEM: 48 0F AF 44 24 48 = imul rax, [rsp+0x48]
//   - 3-op imm 短:  48 6B 44 24 30 07 = imul rax, [rsp+0x30], 7
//   - 3-op imm 短:  48 6B 44 24 30 64 = imul rax, [rsp+0x30], 100
//   - 3-op imm 短:  48 6B 44 24 28 64 = imul rax, [rsp+0x28], 100
//   - 3-op imm 长:  48 69 44 24 28 E8 03 00 00 = imul rax, [rsp+0x28], 1000
// lifter 在 MEM 形式上 emit Operand::mem_(...); 翻译器层折成 Load + Imul。
TEST_F(LifterTranslate, ImulRegMem2Op) {
    // 48 0F AF 44 24 28: imul rax, [rsp+0x28] — 2-op REG-MEM
    const wvmp::u8 b[] = {0x48, 0x0F, 0xAF, 0x44, 0x24, 0x28};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Imul);
    EXPECT_EQ(r.insn.size, ir::Size::S64); // REX.W -> 64 位
    EXPECT_TRUE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);
    // src 必须是 MEM 形式, base=Rsp, disp=0x28
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.src.mem.base, ir::Reg::Rsp);
    EXPECT_EQ(r.insn.src.mem.index, ir::Reg::Flags); // 无 index
    EXPECT_EQ(r.insn.src.mem.disp, 0x28);
    EXPECT_EQ(r.insn.addr, 0u);
    // 2-op 形式 src2 不应被设置
    EXPECT_NE(r.insn.src2.kind, ir::Operand::Kind::Imm);
}

TEST_F(LifterTranslate, ImulRegMemImmShort7) {
    // 48 6B 44 24 30 07: imul rax, [rsp+0x30], 7 — 3-op imm 短 (sign-ext imm8)
    const wvmp::u8 b[] = {0x48, 0x6B, 0x44, 0x24, 0x30, 0x07};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Imul);
    EXPECT_EQ(r.insn.size, ir::Size::S64);
    EXPECT_TRUE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.src.mem.base, ir::Reg::Rsp);
    EXPECT_EQ(r.insn.src.mem.disp, 0x30);
    ASSERT_EQ(r.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r.insn.src2.imm, 7);
}

TEST_F(LifterTranslate, ImulRegMemImmShort100) {
    // 48 6B 44 24 30 64: imul rax, [rsp+0x30], 100 — 3-op imm 短
    const wvmp::u8 b[] = {0x48, 0x6B, 0x44, 0x24, 0x30, 0x64};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Imul);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.src.mem.disp, 0x30);
    ASSERT_EQ(r.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r.insn.src2.imm, 100);
}

TEST_F(LifterTranslate, ImulRegMemImmShortDifferentBase) {
    // 48 6B 44 24 28 64: imul rax, [rsp+0x28], 100 — base disp 不同
    const wvmp::u8 b[] = {0x48, 0x6B, 0x44, 0x24, 0x28, 0x64};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Imul);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.src.mem.disp, 0x28);
    EXPECT_EQ(r.insn.src2.imm, 100);
}

TEST_F(LifterTranslate, ImulRegMemImmLong) {
    // 48 69 44 24 28 E8 03 00 00: imul rax, [rsp+0x28], 1000 — 3-op imm 长 (imm32)
    const wvmp::u8 b[] = {0x48, 0x69, 0x44, 0x24, 0x28, 0xE8, 0x03, 0x00, 0x00};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Imul);
    EXPECT_EQ(r.insn.size, ir::Size::S64);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.src.mem.disp, 0x28);
    ASSERT_EQ(r.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r.insn.src2.imm, 1000);
}

TEST_F(LifterTranslate, ImulRegMem2OpDifferentDisp) {
    // 48 0F AF 44 24 48: imul rax, [rsp+0x48] — 2-op 不同 disp
    const wvmp::u8 b[] = {0x48, 0x0F, 0xAF, 0x44, 0x24, 0x48};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Imul);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.src.mem.disp, 0x48);
}

TEST_F(LifterTranslate, ImulRegRegImmShortRegression) {
    // 48 6B C0 07: imul rax, rax, 7 — MIT-302 老路径回归 (src=Reg)
    const wvmp::u8 b[] = {0x48, 0x6B, 0xC0, 0x07};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Imul);
    EXPECT_EQ(r.insn.size, ir::Size::S64); // REX.W -> S64 (验证 MIT-306 改 data_size)
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rax);
    ASSERT_EQ(r.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r.insn.src2.imm, 7);
}

// MIT-307: movsxd (REX.W + 0x63 /r) 32→64 位符号扩展，x64 专用。
// 字节编码来自项目主反汇编（派活单 §A，wvmp_snake_sample.exe capstone 输出）：
//   - REG-REG (3 字节, 无 SIB/disp):  48 63 D2 = movsxd rdx, edx
//                                    48 63 C1 = movsxd rax, ecx
//   - REG-REG REX.B (R8-R15):         49 63 E8 = movsxd rbp, r8d
//   - REG-MEM RSP+disp8 (SIB 必有):   48 63 44 24 24 = movsxd rax, [rsp+0x24]
//   - REG-MEM base+disp8 (无 SIB):    48 63 40 3C = movsxd rax, [rax+0x3c]
// lifter 对 REG-REG / REG-MEM 都直接 emit（不折 Load + SignExt）。
// size 恒为 S64；updates_flags=false；movsxd 不影响 flags。
TEST_F(LifterTranslate, MovsxdRegToReg) {
    // 48 63 D2: movsxd rdx, edx — REG-REG 形式（同寄存器）
    const wvmp::u8 b[] = {0x48, 0x63, 0xD2};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Movsxd);
    EXPECT_EQ(r.insn.size, ir::Size::S64);        // 必 S64
    EXPECT_FALSE(r.insn.updates_flags);           // 不改 flags
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rdx);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rdx);
    EXPECT_EQ(r.insn.addr, 0u);
}

TEST_F(LifterTranslate, MovsxdRegToRegDifferentReg) {
    // 48 63 C1: movsxd rax, ecx — REG-REG 不同寄存器
    const wvmp::u8 b[] = {0x48, 0x63, 0xC1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Movsxd);
    EXPECT_EQ(r.insn.size, ir::Size::S64);
    EXPECT_FALSE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rcx);
}

TEST_F(LifterTranslate, MovsxdRexB) {
    // 49 63 E8: movsxd rbp, r8d — REX.B 让 reg 映射到 R8-R15
    // 49 (REX.W+REX.B) | 63 (movsxd opcode) | E8 (ModR/M: mod=11, reg=5=Rbp, r/m=0)
    // REX.B 把 r/m 字段从 0 扩展到 8 (R8)。lifter 必须正确处理。
    const wvmp::u8 b[] = {0x49, 0x63, 0xE8};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Movsxd);
    EXPECT_EQ(r.insn.size, ir::Size::S64);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rbp);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::R8);
    EXPECT_FALSE(r.insn.updates_flags);
}

TEST_F(LifterTranslate, MovsxdMemRspDisp8) {
    // 48 63 44 24 24: movsxd rax, [rsp+0x24] — REG-MEM 含 SIB (5 字节)
    // 48 (REX.W) | 63 | 44 (ModR/M: mod=01, reg=0=Rax, r/m=100=SIB)
    //    | 24 (SIB: scale=00, index=100=none, base=100=Rsp) | 24 (disp8)
    const wvmp::u8 b[] = {0x48, 0x63, 0x44, 0x24, 0x24};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Movsxd);
    EXPECT_EQ(r.insn.size, ir::Size::S64);
    EXPECT_FALSE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.src.mem.base, ir::Reg::Rsp);
    EXPECT_EQ(r.insn.src.mem.index, ir::Reg::Flags); // SIB index=100=none
    EXPECT_EQ(r.insn.src.mem.disp, 0x24);
}

TEST_F(LifterTranslate, MovsxdMemBaseDisp8) {
    // 48 63 40 3C: movsxd rax, [rax+0x3c] — REG-MEM 无 SIB (4 字节)
    // 48 (REX.W) | 63 | 40 (ModR/M: mod=01, reg=0=Rax, r/m=000=Rax)
    //    | 3C (disp8)
    const wvmp::u8 b[] = {0x48, 0x63, 0x40, 0x3C};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Movsxd);
    EXPECT_EQ(r.insn.size, ir::Size::S64);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.src.mem.base, ir::Reg::Rax);
    EXPECT_EQ(r.insn.src.mem.index, ir::Reg::Flags); // 无 index
    EXPECT_EQ(r.insn.src.mem.disp, 0x3C);
}

TEST_F(LifterTranslate, MovsxdMemRspDispDifferent0x68) {
    // 48 63 44 24 68: movsxd rax, [rsp+0x68] — 不同 disp 回归测试
    // SIB 路径必正确（与 MovsxdMemRspDisp8 一起覆盖 RSP+disp8 形式全量）
    const wvmp::u8 b[] = {0x48, 0x63, 0x44, 0x24, 0x68};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Movsxd);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.src.mem.base, ir::Reg::Rsp);
    EXPECT_EQ(r.insn.src.mem.disp, 0x68);
    EXPECT_FALSE(r.insn.updates_flags);
}

// MIT-315: movzx (0F B6 /r, 可选 REX.W) 8→32/64 位零扩展，x64/x86 都支持。
// 字节编码来自项目主反汇编（派活单 §A, wvmp_cl_shift_sample.exe capstone 输出）：
//   - REG-REG 8→32:         0F B6 C8 = movzx ecx, al
//   - REG-REG 8→32 同寄:     0F B6 C0 = movzx eax, al
//   - REG-MEM RSP+disp8:    0F B6 4C 24 22 = movzx ecx, [rsp+0x22]
//   - REG-MEM base+disp8:   0F B6 44 24 40 = movzx eax, [rsp+0x40]
//   - REG-MEM 复杂寻址:     0F B6 84 01 88 3E 00 00 = movzx eax, [rcx+rax+0x3e88]
//   - REG-REG 8→64 (REX.W): 48 0F B6 C8 = movzx rcx, al
// lifter 对 REG-REG / REG-MEM 都直接 emit（不折 Load + ZeroExt）。
// size 取目的位宽：8→32 → S32, 8→64 (REX.W) → S64；updates_flags=false。
TEST_F(LifterTranslate, MovzxRegToReg8To32) {
    // 0F B6 C8: movzx ecx, al — REG-REG 形式 8→32
    const wvmp::u8 b[] = {0x0F, 0xB6, 0xC8};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Movzx);
    EXPECT_EQ(r.insn.size, ir::Size::S32);       // 8→32
    EXPECT_FALSE(r.insn.updates_flags);          // movzx 不改 flags
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rcx);     // ECX 折叠到 Rcx
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rax);     // AL 折叠到 Rax
    EXPECT_EQ(r.insn.addr, 0u);
}

TEST_F(LifterTranslate, MovzxRegToRegSameReg) {
    // 0F B6 C0: movzx eax, al — REG-REG 同寄存器
    const wvmp::u8 b[] = {0x0F, 0xB6, 0xC0};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Movzx);
    EXPECT_EQ(r.insn.size, ir::Size::S32);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rax);
    EXPECT_FALSE(r.insn.updates_flags);
}

TEST_F(LifterTranslate, MovzxMemRspDisp8) {
    // 0F B6 4C 24 22: movzx ecx, [rsp+0x22] — REG-MEM 含 SIB (5 字节)
    // 0F (multi-byte prefix) | B6 (opcode) | 4C (ModR/M: mod=01, reg=1=Rcx,
    //   r/m=100=SIB) | 24 (SIB: scale=00, index=100=none, base=100=Rsp)
    //   | 22 (disp8)
    const wvmp::u8 b[] = {0x0F, 0xB6, 0x4C, 0x24, 0x22};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Movzx);
    EXPECT_EQ(r.insn.size, ir::Size::S32);
    EXPECT_FALSE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rcx);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.src.mem.base, ir::Reg::Rsp);
    EXPECT_EQ(r.insn.src.mem.index, ir::Reg::Flags); // SIB index=100=none
    EXPECT_EQ(r.insn.src.mem.disp, 0x22);
}

TEST_F(LifterTranslate, MovzxMemBaseDisp8) {
    // 0F B6 44 24 40: movzx eax, [rsp+0x40] — base+disp8
    // 0F B6 44 (ModR/M: mod=01, reg=0=Rax, r/m=100=SIB) | 24 (SIB)
    //   | 40 (disp8=0x40)
    const wvmp::u8 b[] = {0x0F, 0xB6, 0x44, 0x24, 0x40};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Movzx);
    EXPECT_EQ(r.insn.size, ir::Size::S32);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.src.mem.base, ir::Reg::Rsp);
    EXPECT_EQ(r.insn.src.mem.index, ir::Reg::Flags);
    EXPECT_EQ(r.insn.src.mem.disp, 0x40);
}

TEST_F(LifterTranslate, MovzxMemComplexSIB) {
    // 0F B6 84 01 88 3E 00 00: movzx eax, [rcx+rax+0x3e88] — 复杂寻址 (7 字节)
    // 0F B6 84 (ModR/M: mod=10, reg=0=Rax, r/m=100=SIB) | 01 (SIB: scale=00,
    //   index=000=Rax, base=001=Rcx) | 88 3E 00 00 (disp32=0x3e88)
    const wvmp::u8 b[] = {0x0F, 0xB6, 0x84, 0x01, 0x88, 0x3E, 0x00, 0x00};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Movzx);
    EXPECT_EQ(r.insn.size, ir::Size::S32);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.src.mem.base, ir::Reg::Rcx);
    EXPECT_EQ(r.insn.src.mem.index, ir::Reg::Rax);
    EXPECT_EQ(r.insn.src.mem.scale, 1); // scale=00 in SIB → 1 (MemOperand 规整)
    EXPECT_EQ(r.insn.src.mem.disp, 0x3e88);
}

TEST_F(LifterTranslate, MovzxRexW64) {
    // 48 0F B6 C8: movzx rcx, al — REX.W 触发 8→64 (size=S64)
    // 48 (REX.W) | 0F B6 | C8 (ModR/M: mod=11, reg=1=Rcx, r/m=0=Rax)
    const wvmp::u8 b[] = {0x48, 0x0F, 0xB6, 0xC8};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Movzx);
    EXPECT_EQ(r.insn.size, ir::Size::S64);       // REX.W → 8→64
    EXPECT_FALSE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rcx);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rax);
}

TEST_F(LifterTranslate, SkippedInstructions) {
    // 0F A2: cpuid —— 超出白名单
    const wvmp::u8 cpuid[] = {0x0F, 0xA2};
    EXPECT_EQ(translate_bytes(x64, cpuid, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);

    // F0 01 00: lock add [rax], eax —— 带前缀的 ALU v1 跳过
    //（注：lock 加在寄存器目标上的编码非法，capstone 直接拒绝解码）
    const wvmp::u8 lock[] = {0xF0, 0x01, 0x00};
    EXPECT_EQ(translate_bytes(x64, lock, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
}

// MIT-249 follow-up (issue-09): TranslateResult.skipped_ranges 在 status != Ok
// 时被填 (rva, size), Ok 时留空。这是下游 C1 gate 识别 "IR 缺字节" 的核心数据。
// MIT-301 后: lifter 不再走 Todo 分支（cl 变体已接住, 余下不可识别一律
// Unsupported）——两条 cpuid + 一条 mov 都验证 skipped_ranges 的累积/留空。
TEST_F(LifterTranslate, SkippedRangesAccumulated) {
    // cpuid (0F A2, 2 字节, @ RVA 0x1000): Unsupported → skipped_ranges 1 项
    const wvmp::u8 cpuid[] = {0x0F, 0xA2};
    auto r1 = translate_bytes(x64, cpuid, ir::Arch::X64, 0x1000);
    ASSERT_EQ(r1.status, lifter::TranslateStatus::Unsupported);
    ASSERT_EQ(r1.skipped_ranges.size(), 1u);
    EXPECT_EQ(r1.skipped_ranges[0].first, 0x1000u);
    EXPECT_EQ(r1.skipped_ranges[0].second, 2u);

    // rol ch（0F A5 等不在白名单的指令占位用 cpuid 替代）：同上，验证 rva 2000
    const wvmp::u8 cpuid2[] = {0x0F, 0xA2};
    auto r2 = translate_bytes(x64, cpuid2, ir::Arch::X64, 0x2000);
    ASSERT_EQ(r2.status, lifter::TranslateStatus::Unsupported);
    ASSERT_EQ(r2.skipped_ranges.size(), 1u);
    EXPECT_EQ(r2.skipped_ranges[0].first, 0x2000u);
    EXPECT_EQ(r2.skipped_ranges[0].second, 2u);

    // Ok 情况: skipped_ranges 留空, 不污染下游
    const wvmp::u8 mov[] = {0xB8, 0x01, 0x00, 0x00, 0x00}; // mov eax, 1
    auto r3 = translate_bytes(x64, mov, ir::Arch::X64, 0x3000);
    ASSERT_EQ(r3.status, lifter::TranslateStatus::Ok);
    EXPECT_TRUE(r3.skipped_ranges.empty());
}

TEST_F(LifterTranslate, RolRorLifted) {
    // MIT-247: rol/ror 已解除 TODO, 由 translate_shift 走 Op::Rol/Op::Ror。
    // 覆盖 imm 计数 / 隐式计数 1 / size 变体。

    // C1 C0 04: rol eax, 4 —— imm 计数
    const wvmp::u8 rol_imm[] = {0xC1, 0xC0, 0x04};
    auto r = translate_bytes(x64, rol_imm, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Rol);
    EXPECT_TRUE(r.insn.updates_flags);
    EXPECT_EQ(r.insn.size, ir::Size::S32);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r.insn.src.imm, 4);

    // D1 C0: rol eax（隐式计数 1）
    const wvmp::u8 rol_1[] = {0xD1, 0xC0};
    auto r1 = translate_bytes(x64, rol_1, ir::Arch::X64);
    ASSERT_EQ(r1.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r1.insn.op, ir::Op::Rol);
    ASSERT_EQ(r1.insn.src.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r1.insn.src.imm, 1);

    // C1 C8 04: ror eax, 4 —— imm 计数
    const wvmp::u8 ror_imm[] = {0xC1, 0xC8, 0x04};
    auto rr = translate_bytes(x64, ror_imm, ir::Arch::X64);
    ASSERT_EQ(rr.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(rr.insn.op, ir::Op::Ror);
    EXPECT_TRUE(rr.insn.updates_flags);
    EXPECT_EQ(rr.insn.size, ir::Size::S32);
    EXPECT_EQ(rr.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(rr.insn.src.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(rr.insn.src.imm, 4);

    // D1 C8: ror eax（隐式计数 1）
    const wvmp::u8 ror_1[] = {0xD1, 0xC8};
    auto rr1 = translate_bytes(x64, ror_1, ir::Arch::X64);
    ASSERT_EQ(rr1.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(rr1.insn.op, ir::Op::Ror);
    ASSERT_EQ(rr1.insn.src.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(rr1.insn.src.imm, 1);

    // 48 C1 C1 20: rol rcx, 32 —— 64 位 size
    const wvmp::u8 rol_64[] = {0x48, 0xC1, 0xC1, 0x20};
    auto r64 = translate_bytes(x64, rol_64, ir::Arch::X64);
    ASSERT_EQ(r64.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r64.insn.op, ir::Op::Rol);
    EXPECT_EQ(r64.insn.size, ir::Size::S64);
    EXPECT_EQ(r64.insn.dst.reg, ir::Reg::Rcx);
    ASSERT_EQ(r64.insn.src.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r64.insn.src.imm, 32);

    // MIT-301: cl 变体 (D3 /5) 由 lifter 接住, src=Operand::reg_(Rcx)。
    // D3 C0: rol eax, cl —— Op::Rol + src.kind=Reg + src.reg=Rcx
    const wvmp::u8 rol_cl[] = {0xD3, 0xC0};
    auto rolr = translate_bytes(x64, rol_cl, ir::Arch::X64);
    ASSERT_EQ(rolr.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(rolr.insn.op, ir::Op::Rol);
    EXPECT_EQ(rolr.insn.size, ir::Size::S32);
    EXPECT_EQ(rolr.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(rolr.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(rolr.insn.src.reg, ir::Reg::Rcx);
    EXPECT_TRUE(rolr.insn.updates_flags);

    // D3 C8: ror eax, cl —— 同上
    const wvmp::u8 ror_cl[] = {0xD3, 0xC8};
    auto rorr = translate_bytes(x64, ror_cl, ir::Arch::X64);
    ASSERT_EQ(rorr.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(rorr.insn.op, ir::Op::Ror);
    ASSERT_EQ(rorr.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(rorr.insn.src.reg, ir::Reg::Rcx);
    EXPECT_TRUE(rorr.insn.updates_flags);
}

// MIT-301: D3 /5 (cl 变体) 全量覆盖 - shl/shr/sar/rol/ror + 64 位 size。
//   - cl 在 x86 编码是 RCX 低 8 位；lifter 把 src 转 Operand::reg_(Rcx) 不改
//     ir/ 冻结契约头（区分依赖 Operand::Kind::Reg, 与 imm 计数 Imm 严格区分）。
//   - D3 E0/E8/F8/C0/C8: shl/shr/sar/rol/ror eax, cl —— 全部 Ok。
TEST_F(LifterTranslate, ClVariantShiftLifted) {
    // D3 E0: shl eax, cl
    const wvmp::u8 shl_cl[] = {0xD3, 0xE0};
    auto r = translate_bytes(x64, shl_cl, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Shl);
    EXPECT_EQ(r.insn.size, ir::Size::S32);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rcx);
    EXPECT_TRUE(r.insn.updates_flags);

    // D3 E8: shr eax, cl
    const wvmp::u8 shr_cl[] = {0xD3, 0xE8};
    auto r2 = translate_bytes(x64, shr_cl, ir::Arch::X64);
    ASSERT_EQ(r2.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r2.insn.op, ir::Op::Shr);
    EXPECT_EQ(r2.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(r2.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r2.insn.src.reg, ir::Reg::Rcx);

    // D3 F8: sar eax, cl
    const wvmp::u8 sar_cl[] = {0xD3, 0xF8};
    auto r3 = translate_bytes(x64, sar_cl, ir::Arch::X64);
    ASSERT_EQ(r3.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r3.insn.op, ir::Op::Sar);
    ASSERT_EQ(r3.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r3.insn.src.reg, ir::Reg::Rcx);

    // D3 C0: rol eax, cl
    const wvmp::u8 rol_cl[] = {0xD3, 0xC0};
    auto r4 = translate_bytes(x64, rol_cl, ir::Arch::X64);
    ASSERT_EQ(r4.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r4.insn.op, ir::Op::Rol);
    ASSERT_EQ(r4.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r4.insn.src.reg, ir::Reg::Rcx);

    // D3 C8: ror eax, cl
    const wvmp::u8 ror_cl[] = {0xD3, 0xC8};
    auto r5 = translate_bytes(x64, ror_cl, ir::Arch::X64);
    ASSERT_EQ(r5.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r5.insn.op, ir::Op::Ror);
    ASSERT_EQ(r5.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r5.insn.src.reg, ir::Reg::Rcx);

    // 48 D3 E0: shl rax, cl —— 64 位 size (REX.W)
    const wvmp::u8 shl_cl_64[] = {0x48, 0xD3, 0xE0};
    auto r6 = translate_bytes(x64, shl_cl_64, ir::Arch::X64);
    ASSERT_EQ(r6.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r6.insn.op, ir::Op::Shl);
    EXPECT_EQ(r6.insn.size, ir::Size::S64);
    EXPECT_EQ(r6.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(r6.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r6.insn.src.reg, ir::Reg::Rcx);
}

TEST_F(LifterTranslate, X86Mode32) {
    // B8 01 00 00 00: mov eax, 1（CS_MODE_32）
    const wvmp::u8 mb[] = {0xB8, 0x01, 0x00, 0x00, 0x00};
    auto m = translate_bytes(x86, mb, ir::Arch::X86);
    ASSERT_EQ(m.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(m.insn.op, ir::Op::Mov);
    EXPECT_EQ(m.insn.size, ir::Size::S32);
    EXPECT_EQ(m.insn.dst.reg, ir::Reg::Rax);

    // 89 04 24: mov [esp], eax —— SIB index=100 在 32 位下表示"无 index"
    //（index 字段为 100 是 ESP 占位/无 index，REX.X 置位才是 r12）
    const wvmp::u8 sb[] = {0x89, 0x04, 0x24};
    auto s = translate_bytes(x86, sb, ir::Arch::X86);
    ASSERT_EQ(s.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(s.insn.op, ir::Op::Store);
    EXPECT_EQ(s.insn.size, ir::Size::S32);
    ASSERT_EQ(s.insn.dst.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(s.insn.dst.mem.base, ir::Reg::Rsp);
    EXPECT_EQ(s.insn.dst.mem.index, ir::Reg::Flags); // 哨兵=无 index
    EXPECT_EQ(s.insn.dst.mem.scale, 0);

    // 74 05: je +5 —— 32 位下控制流指令取 S32
    const wvmp::u8 jb[] = {0x74, 0x05};
    auto j = translate_bytes(x86, jb, ir::Arch::X86);
    ASSERT_EQ(j.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(j.insn.op, ir::Op::Jcc);
    EXPECT_EQ(j.insn.size, ir::Size::S32);
    EXPECT_EQ(j.insn.dst.imm, 7);
}

// ---------------- 基本块划分 ----------------

// 综合用例：
//   0:  48 89 C1     mov rcx,rax
//   3:  74 06        je 11
//   5:  48 83 C1 02  add rcx,2
//   9:  EB 03        jmp 14
//   11: 90 90 90     nop ×3
//   14: 31 C0        xor eax,eax
//   16: C3           ret
constexpr wvmp::u8 kBlockBytes[] = {
    0x48, 0x89, 0xC1,             // 0
    0x74, 0x06,                   // 3
    0x48, 0x83, 0xC1, 0x02,       // 5
    0xEB, 0x03,                   // 9
    0x90, 0x90, 0x90,             // 11,12,13
    0x31, 0xC0,                   // 14
    0xC3,                         // 16
};

TEST(LifterBlocks, JeJmpSplitsIntoFourBlocks) {
    lifter::CapstoneSession session(ir::Arch::X64);
    ir::FunctionRegion fr;
    fr.name = "blocky";
    fr.arch = ir::Arch::X64;
    fr.begin_rva = 0;
    fr.end_rva = sizeof(kBlockBytes);

    wvmp::Diagnostics diag;
    lifter::LiftMetadata meta;
    const wvmp::u64 decoded = lifter::disassemble_and_lift(
        session, kBlockBytes, sizeof(kBlockBytes), 0, fr.end_rva, fr.name, "lifter", diag, fr, meta);
    EXPECT_EQ(decoded, 9u);
    EXPECT_TRUE(diag.items().empty());

    ASSERT_EQ(fr.blocks.size(), 4u);
    // 块地址按升序：0, 5, 11, 14
    EXPECT_EQ(fr.blocks[0].addr, 0u);
    EXPECT_EQ(fr.blocks[1].addr, 5u);
    EXPECT_EQ(fr.blocks[2].addr, 11u);
    EXPECT_EQ(fr.blocks[3].addr, 14u);

    // 块 0: mov + je → 出口 {跳转目标 11, fallthrough 5}
    ASSERT_EQ(fr.blocks[0].insns.size(), 2u);
    EXPECT_EQ(fr.blocks[0].insns[0].op, ir::Op::Mov);
    EXPECT_EQ(fr.blocks[0].insns[1].op, ir::Op::Jcc);
    EXPECT_EQ(fr.blocks[0].succs, (std::vector<wvmp::u64>{11, 5}));
    EXPECT_TRUE(fr.blocks[0].preds.empty());

    // 块 1: add + jmp → 出口 {14}
    ASSERT_EQ(fr.blocks[1].insns.size(), 2u);
    EXPECT_EQ(fr.blocks[1].insns[0].op, ir::Op::Add);
    EXPECT_EQ(fr.blocks[1].insns[1].op, ir::Op::Jmp);
    EXPECT_EQ(fr.blocks[1].succs, (std::vector<wvmp::u64>{14}));
    EXPECT_EQ(fr.blocks[1].preds, (std::vector<wvmp::u64>{0}));

    // 块 2: nop×3 → 顺序落入 14
    ASSERT_EQ(fr.blocks[2].insns.size(), 3u);
    EXPECT_EQ(fr.blocks[2].insns[0].op, ir::Op::Nop);
    EXPECT_EQ(fr.blocks[2].succs, (std::vector<wvmp::u64>{14}));
    EXPECT_EQ(fr.blocks[2].preds, (std::vector<wvmp::u64>{0}));

    // 块 3: xor + ret → 无出口；前驱 {5, 11}
    ASSERT_EQ(fr.blocks[3].insns.size(), 2u);
    EXPECT_EQ(fr.blocks[3].insns[0].op, ir::Op::Xor);
    EXPECT_EQ(fr.blocks[3].insns[1].op, ir::Op::Ret);
    EXPECT_TRUE(fr.blocks[3].succs.empty());
    EXPECT_EQ(fr.blocks[3].preds, (std::vector<wvmp::u64>{5, 11}));
}

TEST(LifterBlocks, UnsupportedInsnRecordedButNotFatal) {
    // 51 0F A2 59 C3: push rcx; cpuid; pop rcx; ret
    constexpr wvmp::u8 b[] = {0x51, 0x0F, 0xA2, 0x59, 0xC3};
    lifter::CapstoneSession session(ir::Arch::X64);
    ir::FunctionRegion fr;
    fr.name = "cpuidy";
    fr.arch = ir::Arch::X64;
    fr.begin_rva = 0x1000;
    fr.end_rva = 0x1000 + sizeof(b);

    wvmp::Diagnostics diag;
    lifter::LiftMetadata meta;
    const wvmp::u64 decoded =
        lifter::disassemble_and_lift(session, b, sizeof(b), fr.begin_rva, fr.end_rva, fr.name,
                                     "lifter", diag, fr, meta);
    EXPECT_EQ(decoded, 4u); // cpuid 也被解码（计入），但不进入 insns
    ASSERT_EQ(fr.blocks.size(), 1u);
    ASSERT_EQ(fr.blocks[0].insns.size(), 3u); // push/pop/ret
    EXPECT_EQ(fr.blocks[0].insns[0].op, ir::Op::Push);
    EXPECT_EQ(fr.blocks[0].insns[1].op, ir::Op::Pop);
    EXPECT_EQ(fr.blocks[0].insns[2].op, ir::Op::Ret);
    EXPECT_EQ(fr.blocks[0].insns[0].addr, 0x1000u); // addr 为 RVA

    // 记 Note（函数名 + 地址 + 未支持指令），不产生 Error
    ASSERT_EQ(diag.items().size(), 1u);
    EXPECT_EQ(diag.items()[0].severity, wvmp::Severity::Note);
    EXPECT_EQ(diag.items()[0].pass, "lifter");
    EXPECT_NE(diag.items()[0].message.find("cpuidy"), std::string::npos);
    EXPECT_NE(diag.items()[0].message.find("cpuid"), std::string::npos);
    EXPECT_NE(diag.items()[0].message.find("4097"), std::string::npos); // 0x1001 的十进制
    EXPECT_FALSE(diag.has_errors());

    // MIT-249 follow-up (issue-09): cpuid (0F A2, 2 字节) 被跳过, 应在
    // meta.skipped_ranges 累积 (RVA, size) = (0x1001, 2). 这是下游
    // C1 gate 识别 "IR 缺字节" 的关键数据。
    ASSERT_EQ(meta.skipped_ranges.size(), 1u);
    EXPECT_EQ(meta.skipped_ranges[0].first, 0x1001u);  // cpuid 的 RVA
    EXPECT_EQ(meta.skipped_ranges[0].second, 2u);     // 0F A2 = 2 字节
}

TEST(LifterBlocks, CallTargetAndReturnPointAreLeaders) {
    // 0: E8 04 00 00 00  call 9
    // 5: 31 C0            xor eax,eax
    // 7: C3               ret
    // 8: 90               nop（填充，使 call 目标落在 9）
    // 9: C3               ret
    constexpr wvmp::u8 b[] = {
        0xE8, 0x04, 0x00, 0x00, 0x00, // 0: call 9
        0x31, 0xC0,                   // 5
        0xC3,                         // 7
        0x90,                         // 8
        0xC3,                         // 9
    };
    lifter::CapstoneSession session(ir::Arch::X64);
    ir::FunctionRegion fr;
    fr.name = "callish";
    fr.arch = ir::Arch::X64;
    fr.begin_rva = 0;
    fr.end_rva = sizeof(b);

    wvmp::Diagnostics diag;
    lifter::LiftMetadata meta;
    lifter::disassemble_and_lift(session, b, sizeof(b), 0, fr.end_rva, fr.name, "lifter", diag, fr, meta);
    ASSERT_TRUE(diag.items().empty());

    // leader：0（起点）、9（call 目标）、5（返回点）。9 之后单独成块。
    ASSERT_EQ(fr.blocks.size(), 3u);
    EXPECT_EQ(fr.blocks[0].addr, 0u);  // call：块末是 call → succ = fallthrough
    EXPECT_EQ(fr.blocks[0].succs, (std::vector<wvmp::u64>{5}));
    EXPECT_EQ(fr.blocks[0].insns.size(), 1u);
    EXPECT_EQ(fr.blocks[1].addr, 5u);  // xor + ret
    EXPECT_TRUE(fr.blocks[1].succs.empty());
    EXPECT_EQ(fr.blocks[1].preds, (std::vector<wvmp::u64>{0}));
    EXPECT_EQ(fr.blocks[2].addr, 9u);  // call 目标块
    EXPECT_TRUE(fr.blocks[2].preds.empty()); // call 不产生 CFG 边（目标块仅被识别为 leader）
}

// ---------------- PE 映射 + 端到端 run() ----------------

// 构造最小 PE32+ 镜像：单节 .text（RVA 0x1000，文件偏移 0x400）。
std::vector<wvmp::u8> make_min_pe(std::span<const wvmp::u8> code) {
    std::vector<wvmp::u8> img;
    wvmp::ByteWriter w(img);
    // DOS 头（64 字节，e_lfanew=0x40）
    w.write_u8('M');
    w.write_u8('Z');
    for (int i = 2; i < 60; ++i) w.write_u8(0);
    w.write_u32(0x40);
    // NT 头
    w.write_u8('P');
    w.write_u8('E');
    w.write_u8(0);
    w.write_u8(0);
    w.write_u16(0x8664); // Machine = AMD64
    w.write_u16(1);      // NumberOfSections
    w.write_u32(0);      // TimeDateStamp
    w.write_u32(0);      // PointerToSymbolTable
    w.write_u32(0);      // NumberOfSymbols
    w.write_u16(240);    // SizeOfOptionalHeader（PE32+）
    w.write_u16(0x0022); // Characteristics: EXECUTABLE_IMAGE | LARGEADDRESSAWARE
    // 可选头 PE32+（240 字节；ImageBase @24）
    w.write_u16(0x020B);
    for (int i = 2; i < 24; ++i) w.write_u8(0);
    w.write_u64(0x140000000);
    for (int i = 32; i < 240; ++i) w.write_u8(0);
    // 节表（40 字节）
    const wvmp::u8 name[8] = {'.', 't', 'e', 'x', 't', 0, 0, 0};
    w.write_bytes(name);
    w.write_u32(static_cast<wvmp::u32>(code.size())); // VirtualSize
    w.write_u32(0x1000);                              // VirtualAddress
    w.write_u32(static_cast<wvmp::u32>(code.size())); // SizeOfRawData
    w.write_u32(0x400);                               // PointerToRawData
    for (int i = 0; i < 16; ++i) w.write_u8(0);
    while (img.size() < 0x400) img.push_back(0);
    w.write_bytes(code);
    return img;
}

TEST(LifterPeMap, SectionMapping) {
    const auto img = make_min_pe(std::span<const wvmp::u8>(kBlockBytes));
    const lifter::PeSectionMap pe = lifter::PeSectionMap::parse(img);
    ASSERT_TRUE(pe.valid);
    ASSERT_EQ(pe.sections.size(), 1u);
    EXPECT_EQ(pe.image_base, 0x140000000u);
    EXPECT_EQ(pe.rva_to_offset(0x1000).value_or(0), 0x400u);
    EXPECT_EQ(pe.rva_to_offset(0x1004).value_or(0), 0x404u);
    EXPECT_FALSE(pe.rva_to_offset(0x1000 + sizeof(kBlockBytes)).has_value()); // 越界
    EXPECT_FALSE(pe.rva_to_offset(0x2000).has_value());

    const auto range = pe.map_rva_range(0x1000, 0x1000 + sizeof(kBlockBytes));
    ASSERT_TRUE(range.has_value());
    EXPECT_EQ(range->first, 0x400u);
    EXPECT_EQ(range->second, sizeof(kBlockBytes));

    // 非 PE 镜像
    const std::vector<wvmp::u8> junk{1, 2, 3};
    EXPECT_FALSE(lifter::PeSectionMap::parse(junk).valid);
}

TEST(LifterPass, RunLiftsFunctionsFromImage) {
    wvmp::ProtectionContext ctx;
    ctx.image = make_min_pe(std::span<const wvmp::u8>(kBlockBytes));

    ir::FunctionRegion good;
    good.name = "fn_good";
    good.arch = ir::Arch::X64;
    good.begin_rva = 0x1000;
    good.end_rva = 0x1000 + sizeof(kBlockBytes);
    ctx.functions.push_back(good);

    ir::FunctionRegion bad;
    bad.name = "fn_bad";
    bad.arch = ir::Arch::X64;
    bad.begin_rva = 0x3000; // 不在任何节内
    bad.end_rva = 0x3010;
    ctx.functions.push_back(bad);

    wvmp::passes::LifterPass pass;
    pass.run(ctx);

    // kLiftedIr = 成功 lift 的函数个数（fn_bad 无法映射 RVA，不计入）
    // 槽类型契约是 size_t（注：MSVC 上 size_t 即 unsigned long long）
    const size_t* lifted_sz = ctx.find_slot<size_t>(wvmp::kLiftedIr);
    ASSERT_NE(lifted_sz, nullptr);
    EXPECT_EQ(*lifted_sz, 1u);

    // fn_good 的块结构 = 综合用例 + 0x1000 基址
    const ir::FunctionRegion& out = ctx.functions[0];
    ASSERT_EQ(out.blocks.size(), 4u);
    EXPECT_EQ(out.blocks[0].addr, 0x1000u);
    EXPECT_EQ(out.blocks[1].addr, 0x1005u);
    EXPECT_EQ(out.blocks[2].addr, 0x100Bu);
    EXPECT_EQ(out.blocks[3].addr, 0x100Eu);
    EXPECT_EQ(out.blocks[0].succs, (std::vector<wvmp::u64>{0x100B, 0x1005}));
    EXPECT_EQ(out.blocks[1].succs, (std::vector<wvmp::u64>{0x100E}));
    EXPECT_EQ(out.blocks[2].succs, (std::vector<wvmp::u64>{0x100E}));
    EXPECT_TRUE(out.blocks[3].succs.empty());
    EXPECT_EQ(out.blocks[3].preds, (std::vector<wvmp::u64>{0x1005, 0x100B}));

    // fn_bad：无块 + 一条 Note
    EXPECT_TRUE(ctx.functions[1].blocks.empty());
    ASSERT_EQ(ctx.diag.items().size(), 1u);
    EXPECT_EQ(ctx.diag.items()[0].severity, wvmp::Severity::Note);
    EXPECT_NE(ctx.diag.items()[0].message.find("fn_bad"), std::string::npos);
    EXPECT_FALSE(ctx.diag.has_errors()); // 未识别/无法映射不视为失败
}

TEST(LifterPass, InvalidImageReportsError) {
    wvmp::ProtectionContext ctx;
    ctx.image = {1, 2, 3};
    ir::FunctionRegion fr;
    fr.name = "fn";
    fr.arch = ir::Arch::X64;
    fr.begin_rva = 0x1000;
    fr.end_rva = 0x1010;
    ctx.functions.push_back(fr);

    wvmp::passes::LifterPass pass;
    pass.run(ctx);
    EXPECT_TRUE(ctx.diag.has_errors());
    EXPECT_EQ(ctx.find_slot<size_t>(wvmp::kLiftedIr) != nullptr, true);
    EXPECT_EQ(*ctx.find_slot<size_t>(wvmp::kLiftedIr), 0u);
}

TEST(LifterPass, EmptyFunctionsLiftsNothing) {
    wvmp::ProtectionContext ctx;
    wvmp::passes::LifterPass pass;
    pass.run(ctx);
    ASSERT_NE(ctx.find_slot<size_t>(wvmp::kLiftedIr), nullptr);
    EXPECT_EQ(*ctx.find_slot<size_t>(wvmp::kLiftedIr), 0u);
    EXPECT_TRUE(ctx.diag.items().empty());
}

} // namespace
