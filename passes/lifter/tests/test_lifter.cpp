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

TEST_F(LifterTranslate, JmpMemLifted) {
    // MIT-413 (G2-b): FF 24 C8: jmp qword ptr [rax+rcx*8] — mem 源间接跳转
    // （clang/GCC `jmp [tbl+idx*8]` 平台表）lift 为 Jmp(dst=Mem)；翻译器
    // 跳转表匹配器按 MEM 源形态展开，非表形态在翻译器侧照旧 gate。
    const wvmp::u8 b[] = {0xFF, 0x24, 0xC8};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Jmp);
    EXPECT_EQ(r.insn.size, ir::Size::S64);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.dst.mem.base, ir::Reg::Rax);
    EXPECT_EQ(r.insn.dst.mem.index, ir::Reg::Rcx);
    EXPECT_EQ(r.insn.dst.mem.scale, 8);
    EXPECT_EQ(r.insn.dst.mem.disp, 0);
}

TEST_F(LifterTranslate, QwordIndexedLoadScale8) {
    // MIT-413 (G2-a): 48 8B 04 C8: mov rax, qword ptr [rax+rcx*8] — 8B 表项
    // 读入（G2-a 双语义表形态的表读指令）。
    const wvmp::u8 b[] = {0x48, 0x8B, 0x04, 0xC8};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Load);
    EXPECT_EQ(r.insn.size, ir::Size::S64);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.src.mem.base, ir::Reg::Rax);
    EXPECT_EQ(r.insn.src.mem.index, ir::Reg::Rcx);
    EXPECT_EQ(r.insn.src.mem.scale, 8);
    EXPECT_EQ(r.insn.src.mem.disp, 0);
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

// MIT-345: movzx 8→16 (66 0F B6 + ModR/M) — 16 位目的, 8 位源。
// 字节: 66 (operand-size prefix, 16-bit dst) | 0F B6 (opcode) | C1 (ModR/M:
// mod=11, reg=000=Rax=dst, r/m=001=Rcx=src). MSVC /Od codegen for
// `(unsigned short)(unsigned char)x` 通常 emit 这条。
TEST_F(LifterTranslate, MovzxRegToReg8To16) {
    const wvmp::u8 b[] = {0x66, 0x0F, 0xB6, 0xC1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Movzx);
    EXPECT_EQ(r.insn.size, ir::Size::S16);       // 16 位目的寄存器
    EXPECT_EQ(r.insn.src_size, ir::Size::S8);    // 0F B6 → S8 源
    EXPECT_FALSE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);     // ModR/M reg = dst
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rcx);     // ModR/M r/m = src
}

// MIT-345: movzx 16→64 (REX.W + 0F B7 + ModR/M) — 64 位目的, 16 位源。
// 字节: 48 (REX.W, 64-bit dst) | 0F B7 (opcode, 16-bit src) | C3
// (ModR/M: mod=11, reg=000=Rax=dst, r/m=011=Rbx=src). MSVC /Od codegen for
// `(unsigned long long)(unsigned short)x` 通常 emit 这条。
TEST_F(LifterTranslate, MovzxRegToReg16To64) {
    const wvmp::u8 b[] = {0x48, 0x0F, 0xB7, 0xC3};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Movzx);
    EXPECT_EQ(r.insn.size, ir::Size::S64);       // REX.W → 64 位目的
    EXPECT_EQ(r.insn.src_size, ir::Size::S16);   // 0F B7 → S16 源
    EXPECT_FALSE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);     // ModR/M reg = dst
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rbx);     // ModR/M r/m = src
}

// MIT-345: movzx 16→32 (0F B7 + ModR/M, 无 REX.W) — 32 位目的, 16 位源。
// 字节: 0F B7 | C1 (ModR/M: mod=11, reg=000=Rax=dst, r/m=001=Rcx=src).
TEST_F(LifterTranslate, MovzxRegToReg16To32) {
    const wvmp::u8 b[] = {0x0F, 0xB7, 0xC1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Movzx);
    EXPECT_EQ(r.insn.size, ir::Size::S32);       // 32 位目的
    EXPECT_EQ(r.insn.src_size, ir::Size::S16);   // 0F B7 → S16 源
    EXPECT_FALSE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);     // ModR/M reg = dst
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rcx);     // ModR/M r/m = src
}

// MIT-345: movzx MEM 形式 16→64 (REX.W + 0F B7 + ModR/M, mem src)。
// 字节: 48 (REX.W) | 0F B7 | 4C (ModR/M: mod=01, reg=1=Rcx, r/m=100=SIB)
//       | 24 (SIB: scale=00, index=100=none, base=100=Rsp) | 22 (disp8=0x22)
// = movzx rcx, [rsp+0x22] (16→64 zero-extend)
TEST_F(LifterTranslate, MovzxMemRspDisp8_16To64) {
    const wvmp::u8 b[] = {0x48, 0x0F, 0xB7, 0x4C, 0x24, 0x22};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Movzx);
    EXPECT_EQ(r.insn.size, ir::Size::S64);       // REX.W → 64 位目的
    EXPECT_EQ(r.insn.src_size, ir::Size::S16);   // 0F B7 → S16 源
    EXPECT_FALSE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rcx);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.src.mem.base, ir::Reg::Rsp);
    EXPECT_EQ(r.insn.src.mem.index, ir::Reg::Flags);
    EXPECT_EQ(r.insn.src.mem.disp, 0x22);
}

// MIT-347: movsx 8→32 (0F BE + ModR/M) — 32 位目的, 8 位源。REG-REG 形式。
// 字节: 0F BE | C8 (ModR/M: mod=11, reg=001=Rcx=dst, r/m=000=Rax=src).
// MSVC /Od codegen for `int r = (signed char)x` 通常 emit 这条 (e.g. 0F BE C0)。
TEST_F(LifterTranslate, MovsxRegToReg8To32) {
    const wvmp::u8 b[] = {0x0F, 0xBE, 0xC8};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Movsx);
    EXPECT_EQ(r.insn.size, ir::Size::S32);       // 8→32
    EXPECT_EQ(r.insn.src_size, ir::Size::S8);    // 0F BE → S8 源
    EXPECT_FALSE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rcx);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rax);
    EXPECT_EQ(r.insn.addr, 0u);
}

// MIT-347: movsx 8→64 (REX.W + 0F BE + ModR/M) — 64 位目的, 8 位源。
// 字节: 48 (REX.W) | 0F BE | C8 (ModR/M: mod=11, reg=001=Rcx, r/m=000=Rax)。
TEST_F(LifterTranslate, MovsxRegToReg8To64) {
    const wvmp::u8 b[] = {0x48, 0x0F, 0xBE, 0xC8};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Movsx);
    EXPECT_EQ(r.insn.size, ir::Size::S64);       // REX.W → 64 位目的
    EXPECT_EQ(r.insn.src_size, ir::Size::S8);    // 0F BE → S8 源
    EXPECT_FALSE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rcx);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rax);
}

// MIT-347: movsx 16→64 (REX.W + 0F BF + ModR/M) — 64 位目的, 16 位源。
// 字节: 48 (REX.W) | 0F BF | C3 (ModR/M: mod=11, reg=000=Rax, r/m=011=Rbx)。
TEST_F(LifterTranslate, MovsxRegToReg16To64) {
    const wvmp::u8 b[] = {0x48, 0x0F, 0xBF, 0xC3};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Movsx);
    EXPECT_EQ(r.insn.size, ir::Size::S64);       // REX.W → 64 位目的
    EXPECT_EQ(r.insn.src_size, ir::Size::S16);   // 0F BF → S16 源
    EXPECT_FALSE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rbx);
}

// MIT-347: movsx 16→32 (0F BF + ModR/M, 无 REX.W) — 32 位目的, 16 位源。
// 字节: 0F BF | C1 (ModR/M: mod=11, reg=000=Rax, r/m=001=Rcx)。
TEST_F(LifterTranslate, MovsxRegToReg16To32) {
    const wvmp::u8 b[] = {0x0F, 0xBF, 0xC1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Movsx);
    EXPECT_EQ(r.insn.size, ir::Size::S32);       // 32 位目的
    EXPECT_EQ(r.insn.src_size, ir::Size::S16);   // 0F BF → S16 源
    EXPECT_FALSE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rcx);
}

// MIT-349: popcnt (F3 0F B8+rm) SSE4.2 比特计数。
// 字节编码（来自项目主派活单 §A 反汇编验证, capstone 实测）：
//   - REG-REG 32-bit (no REX.W):    F3 0F B8 C0 = popcnt eax, eax
//   - REG-REG 32-bit 不同寄存器:    F3 0F B8 C8 = popcnt ecx, eax
//   - REG-REG 64-bit (REX.W):       48 F3 0F B8 C0 = popcnt rax, rax
//   - REG-REG 64-bit 不同寄存器:    48 F3 0F B8 C8 = popcnt rcx, rax
// lifter 只接 REG-REG 形式 (mod=11)；MEM (mod=00/01/10) 派活单限定不支持
// (lifter 拒为 unsupported → C1 gate 兜底)。
// size 由 REX.W 决定：无 REX.W → S32, 有 REX.W → S64。
// updates_flags=false (popcnt 不改 CF/OF/SF/ZF/PF; SSE4.2 popcnt 仅 ZF)。
TEST_F(LifterTranslate, PopcntRegToReg32Same) {
    // F3 0F B8 C0: popcnt eax, eax — REG-REG 32-bit 同寄存器
    const wvmp::u8 b[] = {0xF3, 0x0F, 0xB8, 0xC0};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Popcnt);
    EXPECT_EQ(r.insn.size, ir::Size::S32);        // 无 REX.W → S32
    EXPECT_FALSE(r.insn.updates_flags);            // popcnt 不改 flags
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rax);
    EXPECT_EQ(r.insn.addr, 0u);
}

TEST_F(LifterTranslate, PopcntRegToReg32Different) {
    // F3 0F B8 C8: popcnt ecx, eax — REG-REG 32-bit 不同寄存器
    // F3 (REP prefix) | 0F B8 (opcode) | C8 (ModR/M: mod=11, reg=001=Rcx, r/m=000=Rax)
    const wvmp::u8 b[] = {0xF3, 0x0F, 0xB8, 0xC8};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Popcnt);
    EXPECT_EQ(r.insn.size, ir::Size::S32);
    EXPECT_FALSE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rcx);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rax);
}

TEST_F(LifterTranslate, PopcntRegToReg64Same) {
    // 48 F3 0F B8 C0: popcnt rax, rax — REG-REG 64-bit (REX.W) 同寄存器
    // 48 (REX.W) | F3 (REP prefix) | 0F B8 | C0 (ModR/M: mod=11, reg=000=Rax, r/m=000=Rax)
    const wvmp::u8 b[] = {0x48, 0xF3, 0x0F, 0xB8, 0xC0};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Popcnt);
    EXPECT_EQ(r.insn.size, ir::Size::S64);        // REX.W → S64
    EXPECT_FALSE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rax);
}

TEST_F(LifterTranslate, PopcntRegToReg64Different) {
    // 48 F3 0F B8 C8: popcnt rcx, rax — REG-REG 64-bit 不同寄存器
    const wvmp::u8 b[] = {0x48, 0xF3, 0x0F, 0xB8, 0xC8};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Popcnt);
    EXPECT_EQ(r.insn.size, ir::Size::S64);
    EXPECT_FALSE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rcx);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rax);
}

// MIT-349: popcnt MEM 形式派活单限定不支持 (lifter 拒为 unsupported)。
// 派活单 §D 决策 9: 完全不支持 MEM, 不像 movzx/movsx 沿用 MovzxMem/MovsxMem
// 单独处理。
TEST_F(LifterTranslate, PopcntMemRejected) {
    // F3 0F B8 44 24 20: popcnt eax, [rsp+0x20] — REG-MEM 含 SIB
    // F3 (REP prefix) | 0F B8 | 44 (ModR/M: mod=01, reg=000=Rax, r/m=100=SIB)
    //   | 24 (SIB: scale=00, index=100=none, base=100=Rsp) | 20 (disp8)
    const wvmp::u8 b[] = {0xF3, 0x0F, 0xB8, 0x44, 0x24, 0x20};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    EXPECT_EQ(r.status, lifter::TranslateStatus::Unsupported);
}

// =============================================================================
// MIT-353: lzcnt (F3 0F BD+rm) BMI1 前导零计数 / tzcnt (F3 0F BC+rm) BMI1 末尾零计数
// =============================================================================
// 字节编码（来自项目主派活单 §A 反汇编验证, capstone 实测）：
//   - lzcnt REG-REG 32-bit (no REX.W):    F3 0F BD C0 = lzcnt eax, eax
//   - lzcnt REG-REG 32-bit 不同寄存器:    F3 0F BD C8 = lzcnt ecx, eax
//   - lzcnt REG-REG 64-bit (REX.W):       48 F3 0F BD C0 = lzcnt rax, rax
//   - lzcnt REG-REG 64-bit 不同寄存器:    48 F3 0F BD C8 = lzcnt rcx, rax
//   - tzcnt REG-REG 32-bit (no REX.W):    F3 0F BC C0 = tzcnt eax, eax
//   - tzcnt REG-REG 32-bit 不同寄存器:    F3 0F BC C8 = tzcnt ecx, eax
//   - tzcnt REG-REG 64-bit (REX.W):       48 F3 0F BC C0 = tzcnt rax, rax
//   - tzcnt REG-REG 64-bit 不同寄存器:    48 F3 0F BC C8 = tzcnt rcx, rax
// lifter 只接 REG-REG 形式 (mod=11)；MEM (mod=00/01/10) 派活单限定不支持
// (lifter 拒为 unsupported → C1 gate 兜底)。
// size 由 REX.W 决定：无 REX.W → S32, 有 REX.W → S64。
// updates_flags=false (lzcnt/tzcnt 不改 CF/OF/SF/ZF/PF; BMI1 bit-scan 仅 ZF)。
TEST_F(LifterTranslate, LzcntRegToReg32Same) {
    // F3 0F BD C0: lzcnt eax, eax — REG-REG 32-bit 同寄存器
    // F3 (REP prefix) | 0F BD (opcode) | C0 (ModR/M: mod=11, reg=000=Rax, r/m=000=Rax)
    const wvmp::u8 b[] = {0xF3, 0x0F, 0xBD, 0xC0};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Lzcount);
    EXPECT_EQ(r.insn.size, ir::Size::S32);        // 无 REX.W → S32
    EXPECT_FALSE(r.insn.updates_flags);            // lzcnt 不改 flags
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rax);
    EXPECT_EQ(r.insn.addr, 0u);
}

TEST_F(LifterTranslate, LzcntRegToReg32Different) {
    // F3 0F BD C8: lzcnt ecx, eax — REG-REG 32-bit 不同寄存器
    // F3 (REP prefix) | 0F BD (opcode) | C8 (ModR/M: mod=11, reg=001=Rcx, r/m=000=Rax)
    const wvmp::u8 b[] = {0xF3, 0x0F, 0xBD, 0xC8};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Lzcount);
    EXPECT_EQ(r.insn.size, ir::Size::S32);
    EXPECT_FALSE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rcx);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rax);
}

TEST_F(LifterTranslate, LzcntRegToReg64Same) {
    // 48 F3 0F BD C0: lzcnt rax, rax — REG-REG 64-bit (REX.W) 同寄存器
    // 48 (REX.W) | F3 (REP prefix) | 0F BD | C0 (ModR/M: mod=11, reg=000=Rax, r/m=000=Rax)
    const wvmp::u8 b[] = {0x48, 0xF3, 0x0F, 0xBD, 0xC0};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Lzcount);
    EXPECT_EQ(r.insn.size, ir::Size::S64);        // REX.W → S64
    EXPECT_FALSE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rax);
}

TEST_F(LifterTranslate, LzcntRegToReg64Different) {
    // 48 F3 0F BD C8: lzcnt rcx, rax — REG-REG 64-bit 不同寄存器
    const wvmp::u8 b[] = {0x48, 0xF3, 0x0F, 0xBD, 0xC8};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Lzcount);
    EXPECT_EQ(r.insn.size, ir::Size::S64);
    EXPECT_FALSE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rcx);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rax);
}

// MIT-353: lzcnt MEM 形式派活单限定不支持 (lifter 拒为 unsupported)。
// 派活单 §D 决策 9: 完全不支持 MEM, 沿用 popcnt 限定风格, 不像 movzx/movsx
// 沿用 MovzxMem/MovsxMem 单独处理。
TEST_F(LifterTranslate, LzcntMemRejected) {
    // F3 0F BD 44 24 20: lzcnt eax, [rsp+0x20] — REG-MEM 含 SIB
    // F3 (REP prefix) | 0F BD | 44 (ModR/M: mod=01, reg=000=Rax, r/m=100=SIB)
    //   | 24 (SIB: scale=00, index=100=none, base=100=Rsp) | 20 (disp8)
    const wvmp::u8 b[] = {0xF3, 0x0F, 0xBD, 0x44, 0x24, 0x20};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    EXPECT_EQ(r.status, lifter::TranslateStatus::Unsupported);
}

TEST_F(LifterTranslate, TzcntRegToReg32Same) {
    // F3 0F BC C0: tzcnt eax, eax — REG-REG 32-bit 同寄存器
    // F3 (REP prefix) | 0F BC (opcode) | C0 (ModR/M: mod=11, reg=000=Rax, r/m=000=Rax)
    const wvmp::u8 b[] = {0xF3, 0x0F, 0xBC, 0xC0};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Tzcount);
    EXPECT_EQ(r.insn.size, ir::Size::S32);        // 无 REX.W → S32
    EXPECT_FALSE(r.insn.updates_flags);            // tzcnt 不改 flags
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rax);
}

TEST_F(LifterTranslate, TzcntRegToReg32Different) {
    // F3 0F BC C8: tzcnt ecx, eax — REG-REG 32-bit 不同寄存器
    // F3 (REP prefix) | 0F BC (opcode) | C8 (ModR/M: mod=11, reg=001=Rcx, r/m=000=Rax)
    const wvmp::u8 b[] = {0xF3, 0x0F, 0xBC, 0xC8};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Tzcount);
    EXPECT_EQ(r.insn.size, ir::Size::S32);
    EXPECT_FALSE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rcx);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rax);
}

TEST_F(LifterTranslate, TzcntRegToReg64Same) {
    // 48 F3 0F BC C0: tzcnt rax, rax — REG-REG 64-bit (REX.W) 同寄存器
    // 48 (REX.W) | F3 (REP prefix) | 0F BC | C0 (ModR/M: mod=11, reg=000=Rax, r/m=000=Rax)
    const wvmp::u8 b[] = {0x48, 0xF3, 0x0F, 0xBC, 0xC0};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Tzcount);
    EXPECT_EQ(r.insn.size, ir::Size::S64);        // REX.W → S64
    EXPECT_FALSE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rax);
}

TEST_F(LifterTranslate, TzcntRegToReg64Different) {
    // 48 F3 0F BC C8: tzcnt rcx, rax — REG-REG 64-bit 不同寄存器
    const wvmp::u8 b[] = {0x48, 0xF3, 0x0F, 0xBC, 0xC8};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Tzcount);
    EXPECT_EQ(r.insn.size, ir::Size::S64);
    EXPECT_FALSE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rcx);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rax);
}

// MIT-353: tzcnt MEM 形式派活单限定不支持 (lifter 拒为 unsupported)。
TEST_F(LifterTranslate, TzcntMemRejected) {
    // F3 0F BC 44 24 20: tzcnt eax, [rsp+0x20] — REG-MEM 含 SIB
    // F3 (REP prefix) | 0F BC | 44 (ModR/M: mod=01, reg=000=Rax, r/m=100=SIB)
    //   | 24 (SIB: scale=00, index=100=none, base=100=Rsp) | 20 (disp8)
    const wvmp::u8 b[] = {0xF3, 0x0F, 0xBC, 0x44, 0x24, 0x20};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    EXPECT_EQ(r.status, lifter::TranslateStatus::Unsupported);
}

TEST_F(LifterTranslate, SkippedInstructions) {
    // 0F A2: cpuid —— 超出白名单
    const wvmp::u8 cpuid[] = {0x0F, 0xA2};
    EXPECT_EQ(translate_bytes(x64, cpuid, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);

    // F0 FF 00: lock inc [rax] —— lock 族白名单外 (MSVC _InterlockedIncrement
    // 真产物, 派活单族面外 → §F 残余登记, 照旧 gate)
    const wvmp::u8 lock_inc[] = {0xF0, 0xFF, 0x00};
    EXPECT_EQ(translate_bytes(x64, lock_inc, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);

    // F0 F6 10: lock not byte ptr [rax] —— 不可锁助记符 (D2 砍面)
    const wvmp::u8 lock_not[] = {0xF0, 0xF6, 0x10};
    EXPECT_EQ(translate_bytes(x64, lock_not, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);

    // 66 F0 01 00: 66 (16 位操作数) + lock 组合前缀 —— D4 组合前缀面收窄拒
    const wvmp::u8 lock66[] = {0x66, 0xF0, 0x01, 0x00};
    EXPECT_EQ(translate_bytes(x64, lock66, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);

    // F0 67 01 00: 67 (32 位地址宽) + lock 组合前缀 —— D4 拒
    const wvmp::u8 lock67[] = {0xF0, 0x67, 0x01, 0x00};
    EXPECT_EQ(translate_bytes(x64, lock67, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);

    // F0 F3 A4: lock rep movsb —— capstone 吸收 F0 报 prefix[0]=F3 (串指令
    // 三元组), 串闸字节级 F0 扫描专拒 (415 纪律, 本单继承; 本机实测该组合
    // 原生即 #UD, 不可执行样本, 仅单测覆盖)
    const wvmp::u8 lock_rep_movsb[] = {0xF0, 0xF3, 0xA4};
    EXPECT_EQ(translate_bytes(x64, lock_rep_movsb, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
}

// MIT-419 (G4): capstone 对非法 lock 组合 (lock mov / lock nop) 直接拒解码
// (无 detail 输出) — 上游 disassemble_and_lift 走 skipped_ranges → C1 gate。
// 单测钉死该通道: decode_first 返回 nullptr 即 gate 机制本身。
TEST_F(LifterTranslate, LockIllegalCombosUndecodable) {
    // F0 89 18: lock mov [rax], ebx —— 不可锁助记符 (capstone 拒解码)
    const wvmp::u8 lock_mov[] = {0xF0, 0x89, 0x18};
    EXPECT_EQ(decode_first(x64, lock_mov), nullptr);

    // F0 90: lock nop —— capstone 拒解码
    const wvmp::u8 lock_nop[] = {0xF0, 0x90};
    EXPECT_EQ(decode_first(x64, lock_nop), nullptr);
}

// MIT-419 (G4): lock 族白名单 — strip-and-execute 放行面全谱。
// src2 标记分域 (与 x86_translate.cpp translate_lock_op / translator.cpp
// is_lock_marker 对账): 5..8 = Op::Mov 载体族 (xadd/bts/btr/btc),
// 9..11 = 本体 op 族 (alu/cmpxchg/xchg 声明"曾带 lock")。
TEST_F(LifterTranslate, LockOpsLifted) {
    // ① F0 01 00: lock add [rax], eax —— ALU 族 × mem-dst 剥 F0 放行,
    //    Op::Add + dst=Mem + src=Reg + src2=imm(9) 标记
    const wvmp::u8 lock_add[] = {0xF0, 0x01, 0x00};
    auto r = translate_bytes(x64, lock_add, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Add);
    EXPECT_EQ(r.insn.size, ir::Size::S32);
    EXPECT_TRUE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Mem);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rax);
    ASSERT_EQ(r.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r.insn.src2.imm, 9);  // kLockStripAlu

    // ② F0 48 01 00: lock add [rax], rax —— REX.W (S64) + Reg 源
    const wvmp::u8 lock_add64[] = {0xF0, 0x48, 0x01, 0x00};
    auto r2 = translate_bytes(x64, lock_add64, ir::Arch::X64);
    ASSERT_EQ(r2.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r2.insn.op, ir::Op::Add);
    EXPECT_EQ(r2.insn.size, ir::Size::S64);

    // ③ F0 01 05 34 12 00 00: lock add [rip+0x1234], eax —— rip 目标
    const wvmp::u8 lock_add_rip[] = {0xF0, 0x01, 0x05, 0x34, 0x12, 0x00, 0x00};
    auto r3 = translate_bytes(x64, lock_add_rip, ir::Arch::X64);
    ASSERT_EQ(r3.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r3.insn.op, ir::Op::Add);
    ASSERT_EQ(r3.insn.dst.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r3.insn.dst.mem.base, ir::Reg::Rip);

    // ④ F0 11 18: lock adc [rax], ebx —— ADC 族同样放行 (src2=9)
    const wvmp::u8 lock_adc[] = {0xF0, 0x11, 0x18};
    auto r4 = translate_bytes(x64, lock_adc, ir::Arch::X64);
    ASSERT_EQ(r4.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r4.insn.op, ir::Op::Adc);
    ASSERT_EQ(r4.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r4.insn.src2.imm, 9);

    // ⑤ F0 0F B1 18: lock cmpxchg [rax], ebx —— dst=Mem + src2=imm(10)
    const wvmp::u8 lock_cmpxchg[] = {0xF0, 0x0F, 0xB1, 0x18};
    auto r5 = translate_bytes(x64, lock_cmpxchg, ir::Arch::X64);
    ASSERT_EQ(r5.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r5.insn.op, ir::Op::Cmpxchg);
    ASSERT_EQ(r5.insn.dst.kind, ir::Operand::Kind::Mem);
    ASSERT_EQ(r5.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r5.insn.src2.imm, 10);  // kLockStripCmpxchg

    // ⑥ F0 87 18: lock xchg [rax], ebx —— dst=Mem + src2=imm(11)
    const wvmp::u8 lock_xchg[] = {0xF0, 0x87, 0x18};
    auto r6 = translate_bytes(x64, lock_xchg, ir::Arch::X64);
    ASSERT_EQ(r6.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r6.insn.op, ir::Op::Xchg);
    ASSERT_EQ(r6.insn.dst.kind, ir::Operand::Kind::Mem);
    ASSERT_EQ(r6.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r6.insn.src2.imm, 11);  // kLockStripXchg

    // ⑦ 87 18: 裸 xchg [rax], ebx (InterlockedExchange 真产物, 无 F0 隐式锁)
    //    —— 本体 Op::Xchg + dst=Mem, src2 恒空 (无 lock-strip note 面)
    const wvmp::u8 xchg_mem[] = {0x87, 0x18};
    auto r7 = translate_bytes(x64, xchg_mem, ir::Arch::X64);
    ASSERT_EQ(r7.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r7.insn.op, ir::Op::Xchg);
    EXPECT_EQ(r7.insn.size, ir::Size::S32);
    ASSERT_EQ(r7.insn.dst.kind, ir::Operand::Kind::Mem);
    ASSERT_EQ(r7.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r7.insn.src2.kind, ir::Operand::Kind::None);

    // ⑧ 48 87 18: 裸 xchg [rax], rbx —— REX.W S64
    const wvmp::u8 xchg_mem64[] = {0x48, 0x87, 0x18};
    auto r8 = translate_bytes(x64, xchg_mem64, ir::Arch::X64);
    ASSERT_EQ(r8.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r8.insn.op, ir::Op::Xchg);
    EXPECT_EQ(r8.insn.size, ir::Size::S64);

    // ⑨ F0 0F C1 18: lock xadd [rax], ebx —— InterlockedAdd 真产物,
    //    Op::Mov 载体 + dst=Mem + src=Reg + src2=imm(5) + flags=true
    const wvmp::u8 lock_xadd[] = {0xF0, 0x0F, 0xC1, 0x18};
    auto r9 = translate_bytes(x64, lock_xadd, ir::Arch::X64);
    ASSERT_EQ(r9.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r9.insn.op, ir::Op::Mov);  // 载体 (src2 区分)
    EXPECT_EQ(r9.insn.size, ir::Size::S32);
    EXPECT_TRUE(r9.insn.updates_flags);  // xadd flags = add 语义
    ASSERT_EQ(r9.insn.dst.kind, ir::Operand::Kind::Mem);
    ASSERT_EQ(r9.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r9.insn.src.reg, ir::Reg::Rbx);
    ASSERT_EQ(r9.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r9.insn.src2.imm, 5);  // kLockXadd

    // ⑩ F0 48 0F C1 18: lock xadd [rax], rbx —— REX.W S64
    const wvmp::u8 lock_xadd64[] = {0xF0, 0x48, 0x0F, 0xC1, 0x18};
    auto r10 = translate_bytes(x64, lock_xadd64, ir::Arch::X64);
    ASSERT_EQ(r10.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r10.insn.size, ir::Size::S64);

    // ⑪ F0 0F BA 28 05: lock bts [rax], 5 —— imm8 形式 (InterlockedBitTest*
    //    真产物, D3) src2=imm(6)
    const wvmp::u8 lock_bts_imm[] = {0xF0, 0x0F, 0xBA, 0x28, 0x05};
    auto r11 = translate_bytes(x64, lock_bts_imm, ir::Arch::X64);
    ASSERT_EQ(r11.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r11.insn.op, ir::Op::Mov);  // 载体
    EXPECT_EQ(r11.insn.size, ir::Size::S32);
    EXPECT_TRUE(r11.insn.updates_flags);  // bts 写 CF
    ASSERT_EQ(r11.insn.dst.kind, ir::Operand::Kind::Mem);
    ASSERT_EQ(r11.insn.src.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r11.insn.src.imm, 5);
    ASSERT_EQ(r11.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r11.insn.src2.imm, 6);  // kLockBts

    // ⑫ F0 0F AB 18: lock bts [rax], ebx —— reg 位号形式
    const wvmp::u8 lock_bts_reg[] = {0xF0, 0x0F, 0xAB, 0x18};
    auto r12 = translate_bytes(x64, lock_bts_reg, ir::Arch::X64);
    ASSERT_EQ(r12.status, lifter::TranslateStatus::Ok);
    ASSERT_EQ(r12.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r12.insn.src.reg, ir::Reg::Rbx);
    ASSERT_EQ(r12.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r12.insn.src2.imm, 6);

    // ⑬ F0 0F B3 18: lock btr [rax], ebx / F0 0F BB 18: lock btc [rax], ebx
    const wvmp::u8 lock_btr[] = {0xF0, 0x0F, 0xB3, 0x18};
    auto r13 = translate_bytes(x64, lock_btr, ir::Arch::X64);
    ASSERT_EQ(r13.status, lifter::TranslateStatus::Ok);
    ASSERT_EQ(r13.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r13.insn.src2.imm, 7);  // kLockBtr
    const wvmp::u8 lock_btc[] = {0xF0, 0x0F, 0xBB, 0x18};
    auto r14 = translate_bytes(x64, lock_btc, ir::Arch::X64);
    ASSERT_EQ(r14.status, lifter::TranslateStatus::Ok);
    ASSERT_EQ(r14.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r14.insn.src2.imm, 8);  // kLockBtc

    // ⑭ F0 48 0F B1 18: lock cmpxchg [rax], rbx —— REX.W S64 (64 位全局
    //    InterlockedCompareExchange 真产物形态)
    const wvmp::u8 lock_cmpxchg64[] = {0xF0, 0x48, 0x0F, 0xB1, 0x18};
    auto r15 = translate_bytes(x64, lock_cmpxchg64, ir::Arch::X64);
    ASSERT_EQ(r15.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r15.insn.size, ir::Size::S64);
    EXPECT_EQ(r15.insn.op, ir::Op::Cmpxchg);
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
    EXPECT_NE(diag.items()[0].message.find("0x1001"), std::string::npos); // MIT-407 hex log fix (was "4097" = decimal bug)
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
    // MIT-409: ret 后的死代码（nop 填充）不再丢弃——可 lift 的死代码成块
    // （MSVC 跳转表 case body 只经表可达，翻译器跳转表特化需要这些指令
    // 存在；int3 等不可 lift 字节走 skipped_ranges 通道，不会成为 item）。
    // 死块语义不变：前块以无条件 jmp/ret 终结，VM 永不落入，仅表链可达。
    ASSERT_EQ(fr.blocks.size(), 4u);
    EXPECT_EQ(fr.blocks[0].addr, 0u);  // call：块末是 call → succ = fallthrough
    EXPECT_EQ(fr.blocks[0].succs, (std::vector<wvmp::u64>{5}));
    EXPECT_EQ(fr.blocks[0].insns.size(), 1u);
    EXPECT_EQ(fr.blocks[1].addr, 5u);  // xor + ret
    EXPECT_TRUE(fr.blocks[1].succs.empty());
    EXPECT_EQ(fr.blocks[1].preds, (std::vector<wvmp::u64>{0}));
    EXPECT_EQ(fr.blocks[2].addr, 8u);  // 死代码块（nop，仅表/未知目标可达）
    EXPECT_EQ(fr.blocks[2].insns.size(), 1u);
    EXPECT_EQ(fr.blocks[3].addr, 9u);  // call 目标块
    // call 不产生 CFG 边（目标块仅被识别为 leader）；pred 唯一来源 = 死
    // 代码块 @8 的 fallthrough 边（死块若被未知跳转目标进入, 顺序落入 9）。
    EXPECT_EQ(fr.blocks[3].preds, (std::vector<wvmp::u64>{8}));
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

// ---------------- MIT-411 (G1-b/G1-c): comiss/comisd 折叠 + pd 位运算族折叠 ----

TEST_F(LifterTranslate, ComissRegRegFoldsToUcomiss) {
    // 0F 2F C1: comiss xmm0, xmm1 (有序单精度比较, MIT-411 折叠为 Ucomiss)
    const wvmp::u8 b[] = {0x0F, 0x2F, 0xC1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Ucomiss);
    EXPECT_EQ(r.insn.size, ir::Size::S32);
    EXPECT_TRUE(r.insn.updates_flags);  // 真写 VM flags 槽 (pitfall #79)
    EXPECT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);  // 0..7 复用 = xmm0
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rcx);  // = xmm1 (ir::Reg 按 x86 编号 0..7 = Rax,Rcx,Rdx,Rbx,...)
}

TEST_F(LifterTranslate, ComisMemSrcFoldsToUcomiss) {
    // 0F 2F 05 00 00 00 00: comiss xmm0, dword ptr [rip] (mem 源, rip 全局)
    const wvmp::u8 b[] = {0x0F, 0x2F, 0x05, 0x00, 0x00, 0x00, 0x00};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Ucomiss);
    EXPECT_TRUE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.src.mem.base, ir::Reg::Rip);
}

TEST_F(LifterTranslate, ComisdRegRegFoldsToUcomisd) {
    // 66 0F 2F C1: comisd xmm0, xmm1 (有序双精度比较 → Ucomisd)
    const wvmp::u8 b[] = {0x66, 0x0F, 0x2F, 0xC1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Ucomisd);
    EXPECT_EQ(r.insn.size, ir::Size::S64);
    EXPECT_TRUE(r.insn.updates_flags);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rcx);
}

TEST_F(LifterTranslate, AndpdFoldsToAndps) {
    // 66 0F 54 C1: andpd xmm0, xmm1 → 复用 ps VmOp (MIT-411 D1 零新 VmOp)
    const wvmp::u8 b[] = {0x66, 0x0F, 0x54, 0xC1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Andps);
    EXPECT_EQ(r.insn.size, ir::Size::S64);
    EXPECT_FALSE(r.insn.updates_flags);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rcx);
}

TEST_F(LifterTranslate, OrpdFoldsToOrps) {
    // 66 0F 56 C1: orpd xmm0, xmm1 → Orps
    const wvmp::u8 b[] = {0x66, 0x0F, 0x56, 0xC1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Orps);
    EXPECT_EQ(r.insn.size, ir::Size::S64);
}

TEST_F(LifterTranslate, XorpdMemSrcFoldsToXorps) {
    // 66 0F 57 05 00 00 00 00: xorpd xmm0, xmmword ptr [rip] → Xorps mem 源
    const wvmp::u8 b[] = {0x66, 0x0F, 0x57, 0x05, 0x00, 0x00, 0x00, 0x00};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Xorps);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.src.mem.base, ir::Reg::Rip);
}

TEST_F(LifterTranslate, AndnpsStillUnsupported) {
    // 0F 55 C1: andnps xmm0, xmm1 — 0F 55 系不在 MIT-411 范围 (派活单 §C D4,
    // 留 412+) → unsupported → C1 gate 兜底 (负例断言照旧)
    const wvmp::u8 b[] = {0x0F, 0x55, 0xC1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    EXPECT_EQ(r.status, lifter::TranslateStatus::Unsupported);
}

// =============================================================================
// MIT-415 (G3): rep/repnz 串指令族 (movs/stos/scas/cmps/lods) 前缀闸放行
// =============================================================================
// 挂点 = 前缀闸 (x86_translate.cpp translate_insn :1494 起); 放行判定 =
// detail 级三元组白名单 (mnemonic + prefix[0] F3/F2 + 宽度), 禁全放。
// IR 编码: Op::Mov + src2=imm(family 0..4) + cond (E=rep/repe, Ne=repne) +
// size=元素宽 (S8/S32/S64)。capstone 报法全部经 probe 实测 (2026-08-29,
// vendored capstone x86.h: prefix[0]=rep/repne/lock, [1]=段覆盖, [2]=66,
// [3]=67)。

TEST_F(LifterTranslate, RepMovsbLifted) {
    // F3 A4: rep movsb — 前缀闸放行 (B.1 三元组白名单命中)
    const wvmp::u8 b[] = {0xF3, 0xA4};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Mov);          // 载体 (src2=family 标记区分)
    EXPECT_EQ(r.insn.size, ir::Size::S8);
    EXPECT_EQ(r.insn.cond, ir::Cond::E);        // F3 = rep
    ASSERT_EQ(r.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r.insn.src2.imm, 0);              // family 0 = movs
    EXPECT_FALSE(r.insn.updates_flags);         // movs 不写 flags (SDM)
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.dst.mem.base, ir::Reg::Rdi);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.src.mem.base, ir::Reg::Rsi);
}

TEST_F(LifterTranslate, RepMovsqRexWFixup) {
    // 48 F3 A5: rep movsq — capstone 实证把 REX.W 丢弃解为 'rep movsd' dword
    // (id=X86_INS_MOVSD, op_size=4); REX.W 字节扫描修正 → S64 (§A.3 先验
    // 实测, 与 popcnt REX 扫描同纪律)。
    const wvmp::u8 b[] = {0x48, 0xF3, 0xA5};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Mov);
    EXPECT_EQ(r.insn.size, ir::Size::S64);      // REX.W 修正
    EXPECT_EQ(r.insn.src2.imm, 0);
    // F3 先于 REX 的等价编码 (F3 48 A5) capstone 正确报 MOVSQ qword — 两序
    // 殊途同归
    const wvmp::u8 b2[] = {0xF3, 0x48, 0xA5};
    auto r2 = translate_bytes(x64, b2, ir::Arch::X64);
    ASSERT_EQ(r2.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r2.insn.size, ir::Size::S64);
}

TEST_F(LifterTranslate, StringMovsdVsSseMovsdDualForm) {
    // 双形态互斥 (D3 硬判据, 408 纪律): 同 id=X86_INS_MOVSD — F3 A5 双 MEM
    // = string movsd; F2 0F 10 C1 REG-REG = SSE movsd。两形态互不误纳。
    const wvmp::u8 str[] = {0xF3, 0xA5};        // rep movsd (string)
    auto s = translate_bytes(x64, str, ir::Arch::X64);
    ASSERT_EQ(s.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(s.insn.op, ir::Op::Mov);
    EXPECT_EQ(s.insn.src2.imm, 0);              // string 族
    EXPECT_EQ(s.insn.size, ir::Size::S32);

    const wvmp::u8 sse[] = {0xF2, 0x0F, 0x10, 0xC1};  // movsd xmm0, xmm1
    auto m = translate_bytes(x64, sse, ir::Arch::X64);
    ASSERT_EQ(m.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(m.insn.op, ir::Op::Movss);        // SSE 路径 (MIT-408 (Movss,S64))
    EXPECT_EQ(m.insn.size, ir::Size::S64);
    EXPECT_NE(m.insn.src2.kind, ir::Operand::Kind::Imm);
}

TEST_F(LifterTranslate, RepStosAndRepneScasLifted) {
    // F3 AA: rep stosb — family 1, dst=Mem{Rdi}, src=Reg{Rax}
    const wvmp::u8 sb[] = {0xF3, 0xAA};
    auto s = translate_bytes(x64, sb, ir::Arch::X64);
    ASSERT_EQ(s.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(s.insn.op, ir::Op::Mov);
    EXPECT_EQ(s.insn.src2.imm, 1);
    EXPECT_EQ(s.insn.size, ir::Size::S8);
    ASSERT_EQ(s.insn.dst.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(s.insn.dst.mem.base, ir::Reg::Rdi);
    ASSERT_EQ(s.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(s.insn.src.reg, ir::Reg::Rax);
    // F2 AE: repne scasb — family 2, cond=Ne, updates_flags=true
    const wvmp::u8 cb[] = {0xF2, 0xAE};
    auto c = translate_bytes(x64, cb, ir::Arch::X64);
    ASSERT_EQ(c.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(c.insn.op, ir::Op::Mov);
    EXPECT_EQ(c.insn.src2.imm, 2);
    EXPECT_EQ(c.insn.cond, ir::Cond::Ne);       // repne
    EXPECT_TRUE(c.insn.updates_flags);          // scas 写 flags
    ASSERT_EQ(c.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(c.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(c.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(c.insn.src.mem.base, ir::Reg::Rdi);
}

TEST_F(LifterTranslate, RepCmpsAndRepLodsLifted) {
    // F3 A6: repe cmpsb — family 3, updates_flags=true
    const wvmp::u8 mb[] = {0xF3, 0xA6};
    auto m = translate_bytes(x64, mb, ir::Arch::X64);
    ASSERT_EQ(m.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(m.insn.op, ir::Op::Mov);
    EXPECT_EQ(m.insn.src2.imm, 3);
    EXPECT_TRUE(m.insn.updates_flags);
    ASSERT_EQ(m.insn.dst.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(m.insn.dst.mem.base, ir::Reg::Rsi);
    ASSERT_EQ(m.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(m.insn.src.mem.base, ir::Reg::Rdi);
    // F3 AC: rep lodsb — family 4, dst=Reg{Rax}, src=Mem{Rsi}
    const wvmp::u8 lb[] = {0xF3, 0xAC};
    auto l = translate_bytes(x64, lb, ir::Arch::X64);
    ASSERT_EQ(l.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(l.insn.op, ir::Op::Mov);
    EXPECT_EQ(l.insn.src2.imm, 4);
    EXPECT_FALSE(l.insn.updates_flags);
    ASSERT_EQ(l.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(l.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(l.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(l.insn.src.mem.base, ir::Reg::Rsi);
}

TEST_F(LifterTranslate, RepStringOpNegativesStillGated) {
    // 负例全谱 (B.1 白名单纪律 — 放行必须 detail 级, 禁 prefix[0]!=0 全放):
    // rep 前缀非串指令 / lock rep / repne+movs (Intel undefined) / 16 位
    // (66 砍面, §B.7) / 67 地址宽 / 段覆盖 / 无前缀单发 — 全部照旧 gate。
    const wvmp::u8 pause[] = {0xF3, 0x90};          // rep nop = pause
    EXPECT_EQ(translate_bytes(x64, pause, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
    const wvmp::u8 lock_rep[] = {0xF0, 0xF3, 0xA4}; // lock rep movsb
    EXPECT_EQ(translate_bytes(x64, lock_rep, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
    const wvmp::u8 repne_movsb[] = {0xF2, 0xA4};    // repne movsb (undefined)
    EXPECT_EQ(translate_bytes(x64, repne_movsb, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
    const wvmp::u8 movsw[] = {0x66, 0xF3, 0xA5};    // 66 = 16 位 movsw → 砍面
    EXPECT_EQ(translate_bytes(x64, movsw, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
    const wvmp::u8 addr67[] = {0x67, 0xF3, 0xA4};   // 67 地址宽 (ECX 计数)
    EXPECT_EQ(translate_bytes(x64, addr67, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
    const wvmp::u8 segovr[] = {0x64, 0xF3, 0xA4};   // fs 段覆盖 + rep movsb
    EXPECT_EQ(translate_bytes(x64, segovr, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
    const wvmp::u8 plain[] = {0xA4};                // 无前缀 movsb (单发) → gate
    EXPECT_EQ(translate_bytes(x64, plain, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
    const wvmp::u8 plainq[] = {0x48, 0xA5};         // 无前缀 movsq → gate
    EXPECT_EQ(translate_bytes(x64, plainq, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
}

} // namespace
