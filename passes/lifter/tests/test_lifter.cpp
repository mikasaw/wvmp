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

// MIT-438 (X1b) B.3: ret imm16 lift 值进 IR.src 的回归钉（X0 §A.1 机制链首环，
// X0 §7 msvbvm60 82% of ret 的 stdcall 清栈主形）。双 arch 共享 translate_ret；
// 66 前缀形（66 C2 iw，16 位操作数宽）imm 亦须入 IR——X2 重构若回退此处断言
// 即红。translator 侧派发矩阵见 test_translator RetImm* 用例。
TEST_F(LifterTranslate, RetImm16LiftIntoSrc) {
    // x64: C2 08 00 = ret 8 → src=Imm(8), size=S64（pointer 宽）
    const wvmp::u8 b64[] = {0xC2, 0x08, 0x00};
    auto r = translate_bytes(x64, b64, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Ret);
    EXPECT_EQ(r.insn.size, ir::Size::S64);
    EXPECT_FALSE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r.insn.src.imm, 8);
    EXPECT_EQ(r.skipped_ranges.size(), 0u);

    // x64: 66 C2 34 12 = 66 前缀形 ret imm16（手写/第三方汇编形态，派活单 §B.3）
    const wvmp::u8 b66[] = {0x66, 0xC2, 0x34, 0x12};
    auto r66 = translate_bytes(x64, b66, ir::Arch::X64);
    ASSERT_EQ(r66.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r66.insn.op, ir::Op::Ret);
    ASSERT_EQ(r66.insn.src.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r66.insn.src.imm, 0x1234);
    EXPECT_EQ(r66.skipped_ranges.size(), 0u);

    // x86 (CS_MODE_32): C2 08 00 = ret 8 → src=Imm(8), size=S32
    const wvmp::u8 b86[] = {0xC2, 0x08, 0x00};
    auto r86 = translate_bytes(x86, b86, ir::Arch::X86);
    ASSERT_EQ(r86.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r86.insn.op, ir::Op::Ret);
    EXPECT_EQ(r86.insn.size, ir::Size::S32);
    ASSERT_EQ(r86.insn.src.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r86.insn.src.imm, 8);
}

// MIT-438 (X1b) B.4: FS 段寻址显式 gate —— "扫得到≠放得进"（X0 §7 seg_fs
// 语料 0.32%，SEH TEB 惯用法 `mov eax, fs:[0]`）。
//
// capstone 5.0.6 现状报法（实测钉死，字段断言即 probe）：段覆盖前缀字节落在
// prefix[1]（G3 串指令 probe 同款布局：prefix[0]=rep/lock、prefix[1]=段、
// prefix[2]=66、prefix[3]=67）；mem 操作数的段寄存器报在 mem.segment 字段
// （x86 32 位模与 x64 SIB 无基址形一致），mem.base 不承接段寄存器——故
// mem_operand 的 Flags 哨兵路径天然看不到 FS（map_reg(X86_REG_FS)=nullopt
// 已由 LifterRegMap 钉）。
//
// gate 链 = translate_insn 入口 `prefix[1]!=0 → unsupported`（x86_translate.cpp
// 入口闸）→ skipped_ranges 入 LiftMetadata → C1 整函数原生，零逃逸；callgate
// callee 自装 SEH 在原生栈上执行不受影响（文本见 GAPS x86 支持面节）。
TEST_F(LifterTranslate, SehFsSegmentOverrideGate) {
    // x86 32 位模: 64 8B 05 78 56 34 12 = mov eax, fs:[0x12345678]
    const wvmp::u8 b[] = {0x64, 0x8B, 0x05, 0x78, 0x56, 0x34, 0x12};
    const cs_insn* ci = decode_first(x86, b);
    ASSERT_NE(ci, nullptr);
    const auto& x = ci->detail->x86;
    EXPECT_EQ(ci->id, X86_INS_MOV);
    EXPECT_EQ(x.prefix[1], 0x64);   // 段覆盖 = prefix[1]（布局 probe 钉死）
    ASSERT_EQ(x.op_count, 2);
    EXPECT_EQ(x.operands[1].type, X86_OP_MEM);
    EXPECT_EQ(x.operands[1].mem.base, X86_REG_INVALID);      // 段不占 base 侧
    EXPECT_EQ(x.operands[1].mem.segment, X86_REG_FS);        // 段寄存器落 segment 字段
    auto r = lifter::translate_insn(*ci, ir::Arch::X86);
    EXPECT_EQ(r.status, lifter::TranslateStatus::Unsupported);
    ASSERT_EQ(r.skipped_ranges.size(), 1u);   // C1 gate 的 IR 缺字节证据
    EXPECT_EQ(r.skipped_ranges[0].first, 0u);
    EXPECT_EQ(r.skipped_ranges[0].second, ci->size);

    // x64: 64 8B 04 25 78 56 34 12 = mov eax, fs:[0x12345678]（64 位 SIB 无基址形）
    const wvmp::u8 b64[] = {0x64, 0x8B, 0x04, 0x25, 0x78, 0x56, 0x34, 0x12};
    auto r64 = translate_bytes(x64, b64, ir::Arch::X64);
    EXPECT_EQ(r64.status, lifter::TranslateStatus::Unsupported);
    ASSERT_EQ(r64.skipped_ranges.size(), 1u);

    // GS 同面（x64 TLS 惯用法 65 前缀）：65 48 8B 04 25 ... = mov rax, gs:[..]
    const wvmp::u8 bgs[] = {0x65, 0x48, 0x8B, 0x04, 0x25, 0x78, 0x56, 0x34, 0x12};
    auto rgs = translate_bytes(x64, bgs, ir::Arch::X64);
    EXPECT_EQ(rgs.status, lifter::TranslateStatus::Unsupported);
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

TEST_F(LifterTranslate, PushImmLiftsDstImm) {
    // MIT-454 (X6 B.1) #33 钉：push imm 本就被 lifter lift 为 Op::Push
    // dst=Imm（is_data_operand 含 Imm——X6 派单 A.1 "lifter 拒 imm 形" 定位
    // 被基线 gate note 推翻, 真卡点在 translator）。本用例把该既有行为钉死,
    // 防"开面"回流误改 lifter。x86 面 (68 imm32 + 6A imm8) 双编码:
    //   68 10 00 00 00: push 0x10   (x86, imm32)
    //   6A FB:          push -5     (x86, imm8 sext → capstone imm=-5)
    const wvmp::u8 b32[] = {0x68, 0x10, 0x00, 0x00, 0x00};
    auto a = translate_bytes(x86, b32, ir::Arch::X86);
    ASSERT_EQ(a.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(a.insn.op, ir::Op::Push);
    ASSERT_EQ(a.insn.dst.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(a.insn.dst.imm, 0x10);
    EXPECT_EQ(a.insn.size, ir::Size::S32);

    const wvmp::u8 b8[] = {0x6A, 0xFB};
    auto b = translate_bytes(x86, b8, ir::Arch::X86);
    ASSERT_EQ(b.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(b.insn.op, ir::Op::Push);
    ASSERT_EQ(b.insn.dst.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(b.insn.dst.imm, -5);
    EXPECT_EQ(b.insn.size, ir::Size::S32);
}

TEST_F(LifterTranslate, PushMemLiftsDstMem) {
    // MIT-456 (push-mem) 钉：push [mem] 本就被 lifter lift 为 Op::Push
    // dst=Mem（X7 批一"新数据行"记录的真卡点在 translator translate_push
    // Mem skip, 本单翻正后此钉防 lifter 侧误改回流）。x86 双编码 + x64 同
    // 字节面（FF 30 双 arch 同为 push [eax]/push [rax], 宽度按 arch 分叉）:
    //   FF 30:          push [eax]      (x86, FF /6 mod=00 rm=000)
    //   FF 77 08:       push [edi+8]    (x86, mod=01 disp8)
    const wvmp::u8 b32[] = {0xFF, 0x30};
    auto a = translate_bytes(x86, b32, ir::Arch::X86);
    ASSERT_EQ(a.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(a.insn.op, ir::Op::Push);
    ASSERT_EQ(a.insn.dst.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(a.insn.dst.mem.base, ir::Reg::Rax);
    EXPECT_EQ(a.insn.dst.mem.index, ir::Reg::Flags);
    EXPECT_EQ(a.insn.dst.mem.disp, 0);
    EXPECT_EQ(a.insn.size, ir::Size::S32);
    EXPECT_FALSE(a.insn.updates_flags);

    const wvmp::u8 bdisp[] = {0xFF, 0x77, 0x08};
    auto c = translate_bytes(x86, bdisp, ir::Arch::X86);
    ASSERT_EQ(c.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(c.insn.op, ir::Op::Push);
    ASSERT_EQ(c.insn.dst.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(c.insn.dst.mem.base, ir::Reg::Rdi);
    EXPECT_EQ(c.insn.dst.mem.disp, 8);

    const wvmp::u8 b64[] = {0xFF, 0x30};
    auto d = translate_bytes(x64, b64, ir::Arch::X64);
    ASSERT_EQ(d.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(d.insn.op, ir::Op::Push);
    ASSERT_EQ(d.insn.dst.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(d.insn.dst.mem.base, ir::Reg::Rax);
    EXPECT_EQ(d.insn.size, ir::Size::S64);
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

    // (MIT-423 G4b 前: lock inc [rax] 曾在此断言 Unsupported — 白名单已收
    // 入面, 正例迁移至 LockIncDecLifted。)

    // F0 F6 10: lock not byte ptr [rax] —— D2 裁决 gate (编码合法, 无 MSVC
    // 产物; F7 /2 dword 形同此 — LockIncDecNegative 覆盖)
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
// MIT-451 (X5b) B.4：REG-REG 位测试族 lift（x86 专属）— 载体 = Op::Mov +
// src2=G4 族标记（5..8 零新增），dst/src = Reg 双形。负形面：x64 arch /
// REG-IMM / S16 均维持 unsupported → C1 gate（G4 残余口径不动）。
TEST_F(LifterTranslate, BitRegRegFamilyX86) {
    // ① 0F C1 C3 (x86): xadd ebx, eax → 载体 Mov + src2=5(kLockXadd) + S32
    const wvmp::u8 xadd86[] = {0x0F, 0xC1, 0xC3};
    auto r = translate_bytes(x86, xadd86, ir::Arch::X86);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Mov);
    EXPECT_EQ(r.insn.size, ir::Size::S32);
    EXPECT_TRUE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rbx);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rax);
    ASSERT_EQ(r.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r.insn.src2.imm, 5);

    // ② 0F AB C3 (x86): bts ebx, eax → src2=6(kLockBts)
    const wvmp::u8 bts86[] = {0x0F, 0xAB, 0xC3};
    auto r2 = translate_bytes(x86, bts86, ir::Arch::X86);
    ASSERT_EQ(r2.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r2.insn.op, ir::Op::Mov);
    ASSERT_EQ(r2.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r2.insn.src2.imm, 6);
    EXPECT_EQ(r2.insn.dst.reg, ir::Reg::Rbx);
    EXPECT_EQ(r2.insn.src.reg, ir::Reg::Rax);

    // ③ 0F B3 C3 (x86): btr ebx, eax → src2=7
    const wvmp::u8 btr86[] = {0x0F, 0xB3, 0xC3};
    auto r3 = translate_bytes(x86, btr86, ir::Arch::X86);
    ASSERT_EQ(r3.status, lifter::TranslateStatus::Ok);
    ASSERT_EQ(r3.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r3.insn.src2.imm, 7);

    // ④ 0F BB C3 (x86): btc ebx, eax → src2=8
    const wvmp::u8 btc86[] = {0x0F, 0xBB, 0xC3};
    auto r4 = translate_bytes(x86, btc86, ir::Arch::X86);
    ASSERT_EQ(r4.status, lifter::TranslateStatus::Ok);
    ASSERT_EQ(r4.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r4.insn.src2.imm, 8);

    // ⑤ 0F C0 C3 (x86): xadd bl, al → S8 面放行
    const wvmp::u8 xadd8[] = {0x0F, 0xC0, 0xC3};
    auto r5 = translate_bytes(x86, xadd8, ir::Arch::X86);
    ASSERT_EQ(r5.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r5.insn.size, ir::Size::S8);

    // ⑥ 66 0F C1 C3 (x86): 66 xadd bx, ax → S16 维持 gate 口径
    const wvmp::u8 xadd16[] = {0x66, 0x0F, 0xC1, 0xC3};
    EXPECT_EQ(translate_bytes(x86, xadd16, ir::Arch::X86).status,
              lifter::TranslateStatus::Unsupported);

    // ⑦ 48 0F C1 C3 (x64): REX.W xadd rbx, rax → x64 REG-REG 照旧 gate
    const wvmp::u8 xadd64[] = {0x48, 0x0F, 0xC1, 0xC3};
    EXPECT_EQ(translate_bytes(x64, xadd64, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);

    // ⑧ 0F BA E0 05 (x86): bts eax, 5 → REG-IMM 不在本单面内照旧 gate
    const wvmp::u8 bts_imm[] = {0x0F, 0xBA, 0xE0, 0x05};
    EXPECT_EQ(translate_bytes(x86, bts_imm, ir::Arch::X86).status,
              lifter::TranslateStatus::Unsupported);

    // ⑨ 0F AB 03 (x86): bts [ebx], eax → REG-MEM 裸形照旧 gate（MEM 仅 lock 面）
    const wvmp::u8 bts_mem[] = {0x0F, 0xAB, 0x03};
    EXPECT_EQ(translate_bytes(x86, bts_mem, ir::Arch::X86).status,
              lifter::TranslateStatus::Unsupported);
}

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

// MIT-423 (G4b): lock inc/dec 白名单 — 本体通路折条 (D1: 零新 VmOp)。
// 标记域 12..13 (kLockInc/kLockDec) — 载体域对账见 translate_lock_op 枚举
// 注释 (src2=imm 任意值写入点全仓仅 translate_imul, Inc/Dec 唯一构造点
// translate_unary 不写 src2)。
TEST_F(LifterTranslate, LockIncDecLifted) {
    // ① F0 FF 00: lock inc [rax] — Op::Inc + dst=Mem + src2=imm(12) + flags
    const wvmp::u8 lock_inc[] = {0xF0, 0xFF, 0x00};
    auto r = translate_bytes(x64, lock_inc, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Inc);
    EXPECT_EQ(r.insn.size, ir::Size::S32);
    EXPECT_TRUE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.skipped_ranges.size(), 0u);
    ASSERT_EQ(r.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r.insn.src2.imm, 12);  // kLockInc

    // ② F0 48 FF 00: lock inc [rax] REX.W — S64 (_InterlockedIncrement64
    //    真产物形态先验 — 实测 MSVC 产 lock xadd, 本形态属手写/第三方面)
    const wvmp::u8 lock_inc64[] = {0xF0, 0x48, 0xFF, 0x00};
    auto r2 = translate_bytes(x64, lock_inc64, ir::Arch::X64);
    ASSERT_EQ(r2.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r2.insn.op, ir::Op::Inc);
    EXPECT_EQ(r2.insn.size, ir::Size::S64);
    ASSERT_EQ(r2.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r2.insn.src2.imm, 12);

    // ③ F0 FF 08: lock dec [rax] — Op::Dec + src2=imm(13)
    const wvmp::u8 lock_dec[] = {0xF0, 0xFF, 0x08};
    auto r3 = translate_bytes(x64, lock_dec, ir::Arch::X64);
    ASSERT_EQ(r3.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r3.insn.op, ir::Op::Dec);
    EXPECT_EQ(r3.insn.size, ir::Size::S32);
    EXPECT_TRUE(r3.insn.updates_flags);
    ASSERT_EQ(r3.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r3.insn.src2.imm, 13);  // kLockDec

    // ④ F0 48 FF 08: lock dec [rax] REX.W — S64
    const wvmp::u8 lock_dec64[] = {0xF0, 0x48, 0xFF, 0x08};
    auto r4 = translate_bytes(x64, lock_dec64, ir::Arch::X64);
    ASSERT_EQ(r4.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r4.insn.op, ir::Op::Dec);
    EXPECT_EQ(r4.insn.size, ir::Size::S64);
    EXPECT_EQ(r4.insn.src2.imm, 13);

    // ⑤ F0 FF 05 34 12 00 00: lock inc [rip+0x1234] — rip 目标 (64 位全局
    //    计数器惯用形态)
    const wvmp::u8 lock_inc_rip[] = {0xF0, 0xFF, 0x05, 0x34, 0x12, 0x00, 0x00};
    auto r5 = translate_bytes(x64, lock_inc_rip, ir::Arch::X64);
    ASSERT_EQ(r5.status, lifter::TranslateStatus::Ok);
    ASSERT_EQ(r5.insn.dst.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r5.insn.dst.mem.base, ir::Reg::Rip);
    EXPECT_EQ(r5.insn.src2.imm, 12);

    // ⑥ F0 FF 40 05: lock inc [rax+5] (disp8) — 常规非 rip 内存
    const wvmp::u8 lock_inc_disp[] = {0xF0, 0xFF, 0x40, 0x05};
    auto r6 = translate_bytes(x64, lock_inc_disp, ir::Arch::X64);
    ASSERT_EQ(r6.status, lifter::TranslateStatus::Ok);
    ASSERT_EQ(r6.insn.dst.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r6.insn.dst.mem.base, ir::Reg::Rax);
    EXPECT_EQ(r6.insn.dst.mem.disp, 5);
}

// MIT-423 (G4b): lock inc/dec 负例 + src2 载体域对账证据。
TEST_F(LifterTranslate, LockIncDecNegative) {
    // ① F0 FE 01: lock inc byte ptr [rcx] — S8 编码合法 (capstone 可解,
    //    probe 实测 id=230) 但白名单 pin S32/S64 (MSVC 无字节宽 Interlocked
    //    Increment 产物) → Unsupported + skipped_ranges (C1 gate)
    const wvmp::u8 lock_inc_s8[] = {0xF0, 0xFE, 0x01};
    auto r = translate_bytes(x64, lock_inc_s8, ir::Arch::X64, 0x1000);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Unsupported);
    ASSERT_EQ(r.skipped_ranges.size(), 1u);
    EXPECT_EQ(r.skipped_ranges[0].first, 0x1000u);
    EXPECT_EQ(r.skipped_ranges[0].second, 3u);

    // ② 66 F0 FF 01: lock inc word ptr [rcx] — 66 组合前缀 (prefix[0]=66,
    //    bytes[0]=66) → D4 拒
    const wvmp::u8 lock_inc_s16[] = {0x66, 0xF0, 0xFF, 0x01};
    auto r2 = translate_bytes(x64, lock_inc_s16, ir::Arch::X64);
    ASSERT_EQ(r2.status, lifter::TranslateStatus::Unsupported);

    // ③ F0 F7 11 / F0 F7 19: lock not/neg dword [rcx] — SDM 合法编码
    //    (capstone 实测 id=511/509 可解到 translate_lock_op default), D2
    //    裁决: 无 MSVC 产物 (无 InterlockedNot/Neg intrinsic) → gate
    const wvmp::u8 lock_not[] = {0xF0, 0xF7, 0x11};
    auto r3 = translate_bytes(x64, lock_not, ir::Arch::X64, 0x2000);
    ASSERT_EQ(r3.status, lifter::TranslateStatus::Unsupported);
    ASSERT_EQ(r3.skipped_ranges.size(), 1u);
    const wvmp::u8 lock_neg[] = {0xF0, 0xF7, 0x19};
    auto r4 = translate_bytes(x64, lock_neg, ir::Arch::X64, 0x3000);
    ASSERT_EQ(r4.status, lifter::TranslateStatus::Unsupported);

    // ④ F0 FF C1: lock inc ecx (reg-dst) — 非法编码, capstone 拒解码
    //    (probe 实测 DECODE FAIL) → 无 detail → skipped_ranges 通道
    const wvmp::u8 lock_inc_ecx[] = {0xF0, 0xFF, 0xC1};
    EXPECT_EQ(decode_first(x64, lock_inc_ecx), nullptr);

    // ⑤ FF C1: plain inc ecx (reg-dst, 无 F0) — 本体通路照常, **src2 恒空**
    //    (kind=None; 载体域对账证据: translate_unary 不写 src2, Operand
    //    默认 kind=None — is_lock_carrier_op 加 Inc/Dec 无碰撞面的依据)
    const wvmp::u8 inc_ecx[] = {0xFF, 0xC1};
    auto r5 = translate_bytes(x64, inc_ecx, ir::Arch::X64);
    ASSERT_EQ(r5.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r5.insn.op, ir::Op::Inc);
    EXPECT_EQ(r5.insn.src2.kind, ir::Operand::Kind::None);

    // ⑥ FF 00: plain inc [rax] (无 lock) — 同本体通路, src2 空 (不发
    //    lock-strip note 的对偶面)
    const wvmp::u8 inc_mem[] = {0xFF, 0x00};
    auto r6 = translate_bytes(x64, inc_mem, ir::Arch::X64);
    ASSERT_EQ(r6.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r6.insn.op, ir::Op::Inc);
    EXPECT_EQ(r6.insn.src2.kind, ir::Operand::Kind::None);
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

TEST(LifterBlocks, MovlpdStoreLiftsToScalarMovLoadStaysGate) {
    // MIT-494x (T47): movlpd store (66 0F E2 4D F8 = movlpd [ebp-8], xmm1)
    // → Op::Movsd（低 64 存储语义恒等，零新 VmOp）；load 形（66 0F E2 45 F8
    // = movlpd xmm1, [ebp-8]）上 64 保留语义不可映射 Movsd → 维持
    // unsupported（skipped_ranges 记账 → C1 gate 保守面）。
    // 前置标准序言（X86 lifter 面按真实函数形态驱动）
    // ⚠️ MOVLPD store = 66 0F 13 /r（0F E2 = PSRAD，首版用错操作码被
    // 解码探针当场证伪）；load = 66 0F 12 /r。
    constexpr wvmp::u8 b[] = {0x55,                   // push ebp
                              0x8B, 0xEC,             // mov ebp, esp
                              0x66, 0x0F, 0x13, 0x4D, 0xF8, // movlpd [ebp-8], xmm1
                              0x66, 0x0F, 0x12, 0x45, 0xF8, // movlpd xmm1, [ebp-8]
                              0x5D, 0xC3};            // pop ebp; ret
    lifter::CapstoneSession session(ir::Arch::X86);
    ir::FunctionRegion fr;
    fr.name = "movlpdz";
    fr.arch = ir::Arch::X86;
    fr.begin_rva = 0x1000;
    fr.end_rva = 0x1000 + sizeof(b);

    wvmp::Diagnostics diag;
    lifter::LiftMetadata meta;
    const wvmp::u64 decoded =
        lifter::disassemble_and_lift(session, b, sizeof(b), fr.begin_rva,
                                     fr.end_rva, fr.name, "lifter", diag, fr,
                                     meta);
    EXPECT_EQ(decoded, 6u);   // 5 lift + 1 skip（decoded 计数含跳过）
    ASSERT_GE(fr.blocks.size(), 1u);
    ASSERT_GE(fr.blocks[0].insns.size(), 1u);
    // insns: push, mov ebp,esp, Movsd(store), pop, ret（load 形跳过不入列）
    ASSERT_EQ(fr.blocks[0].insns.size(), 5u);
    const ir::Insn& st = fr.blocks[0].insns[2];
    // IR 口径：SSE 标量 mov 族统一 Movss + size 标签（S64 = movsd/movlpd
    // 形），与既有 X86_INS_MOVSD case 同编码。
    EXPECT_EQ(st.op, ir::Op::Movss);
    EXPECT_EQ(st.size, ir::Size::S64);
    EXPECT_EQ(st.dst.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(st.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(st.addr, 0x1003u);
    // load 形不支持 → 恰 1 段 skipped（@0x1008, 5B）
    ASSERT_EQ(meta.skipped_ranges.size(), 1u);
    EXPECT_EQ(meta.skipped_ranges[0].first, 0x1008u);
    EXPECT_EQ(meta.skipped_ranges[0].second, 5u);
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

// ==================== MIT-497 (T50): 出口 esp-resync 前瞻 ====================
// 出口延续代码扫窗：终止符 mov esp,ebp/leave + 窗内仅 call rel32/寄存器/
// 非 esp 访存 → true；delta 清栈/[esp±k]/jmp/间接 call/预算耗尽 → false。
// 字节编码为手工核对的 x86 指令（编码↔语义由 CapstoneSession 解码背书）。
namespace {
bool resync_of(std::span<const wvmp::u8> code, wvmp::u64 rva) {
    const auto img = make_min_pe(code);
    const lifter::PeSectionMap pe = lifter::PeSectionMap::parse(img);
    EXPECT_TRUE(pe.valid);
    lifter::CapstoneSession session(ir::Arch::X86);
    return lifter::exit_resync_verified(
        session, std::span<const wvmp::u8>(img), pe, rva);
}
} // namespace

TEST(LifterResync, Mul64hiShapePasses) {
    // mul64hi 延续形态：[ebp±X] 寻址 + call rel32（目标不跟）+ 尾声
    // mov esp,ebp 终止。
    const wvmp::u8 cont[] = {
        0x8B, 0x45, 0xD8,             // mov eax,[ebp-0x28]
        0x8B, 0x55, 0xDC,             // mov edx,[ebp-0x24]
        0xB1, 0x20,                   // mov cl,0x20
        0xE8, 0x00, 0x00, 0x00, 0x00, // call next (rel32)
        0x33, 0xC9,                   // xor ecx,ecx
        0x03, 0xC1,                   // add eax,ecx
        0x89, 0xEC,                   // mov esp,ebp   ← 终止符
        0xC3,                         // ret（窗后不扫）
    };
    EXPECT_TRUE(resync_of(std::span<const wvmp::u8>(cont), 0x1000));
}

TEST(LifterResync, LeaveTerminatorPasses) {
    const wvmp::u8 cont[] = {
        0x8B, 0x45, 0x08,             // mov eax,[ebp+8]
        0xE8, 0x00, 0x00, 0x00, 0x00, // call next
        0xC9,                         // leave ← 终止符
    };
    EXPECT_TRUE(resync_of(std::span<const wvmp::u8>(cont), 0x1000));
}

TEST(LifterResync, DeltaCleanupStaysGated) {
    // 增量式清栈（call 后 add esp）在错基 esp=ns 上语义即错 → 拒。
    const wvmp::u8 cont[] = {
        0xE8, 0x00, 0x00, 0x00, 0x00, // call next
        0x83, 0xC4, 0x40,             // add esp,0x40 ← esp 触碰非终止符
        0xC3,                         // ret
    };
    EXPECT_FALSE(resync_of(std::span<const wvmp::u8>(cont), 0x1000));
}

TEST(LifterResync, EspRelMemStaysGated) {
    // [esp+4] 数据读在错基上读到死参数区 → 拒。
    const wvmp::u8 cont[] = {
        0x8B, 0x44, 0x24, 0x04,       // mov eax,[esp+4]
        0x89, 0xEC,                   // mov esp,ebp
    };
    EXPECT_FALSE(resync_of(std::span<const wvmp::u8>(cont), 0x1000));
}

TEST(LifterResync, PushInWindowStaysGated) {
    // T50 验收 S-1：push/pop 族隐式 esp 不进 capstone 操作数（touches_sp
    // 探不到）→ 按 id 显式封禁（push 写 [ns-4] 与 native 世界 [ns-d-4]
    // 错位，静默错值面）。
    const wvmp::u8 cont[] = {
        0x50,                         // push eax
        0x89, 0xEC,                   // mov esp,ebp
    };
    EXPECT_FALSE(resync_of(std::span<const wvmp::u8>(cont), 0x1000));
}

TEST(LifterResync, FarCallStaysGated) {
    // T50 验收 N-1：far call（9A，id=LCALL≠CALL，不走 IMM 判据）显式拒。
    const wvmp::u8 cont[] = {
        0x9A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // lcall far
        0x89, 0xEC,                   // mov esp,ebp
    };
    EXPECT_FALSE(resync_of(std::span<const wvmp::u8>(cont), 0x1000));
}

// ==================== MIT-500 (T54): callee 清理约定扫描 ====================
namespace {
std::optional<wvmp::u32> ret_imm_of(std::span<const wvmp::u8> code, wvmp::u64 rva) {
    const auto img = make_min_pe(code);
    const lifter::PeSectionMap pe = lifter::PeSectionMap::parse(img);
    EXPECT_TRUE(pe.valid);
    lifter::CapstoneSession session(ir::Arch::X86);
    return lifter::callee_ret_imm(
        session, std::span<const wvmp::u8>(img), pe, rva);
}
} // namespace

TEST(LifterCleanup, PlainRetIsCdecl) {
    const wvmp::u8 body[] = {0xC3};  // ret
    const auto v = ret_imm_of(std::span<const wvmp::u8>(body), 0x1000);
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, 0u);
}

TEST(LifterCleanup, RetImm8IsStdcall) {
    const wvmp::u8 body[] = {0xC2, 0x10, 0x00};  // ret 10h (__allmul 形)
    const auto v = ret_imm_of(std::span<const wvmp::u8>(body), 0x1000);
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, 0x10u);
}

TEST(LifterCleanup, LoopBodyFallsToRet) {
    // fc_shr64/__aullshr 形：shr/rcr/dec/jnz 回边循环 + 循环出口裸 ret
    // （visited 去重兜回边，出口可达 → 终态唯一）。
    const wvmp::u8 body[] = {
        0xD1, 0xEA,                   // shr edx,1      @+0
        0xD1, 0xD8,                   // rcr eax,1      @+2
        0xFE, 0xC9,                   // dec cl         @+4
        0x75, 0xF8,                   // jnz -8（回边到块首 @0）
        0xC3,                         // ret
    };
    const auto v = ret_imm_of(std::span<const wvmp::u8>(body), 0x1000);
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, 0u);
}

TEST(LifterCleanup, ConflictingRetsRejected) {
    // jcc 分叉到裸 ret 与 ret 8 → 终态冲突 → nullopt（fail-closed）。
    // T54 验收 S-3 布局修正：jz rel8=1（目标 = 5+1 = 6 = C2 08 00 处；
    // 首版 74 04 目标 9 落节外经"越界拒绝"通过，冲突分支从未执行）。
    const wvmp::u8 body[] = {
        0x83, 0xC0, 0x01,             // add eax,1
        0x74, 0x01,                   // jz +1 → ret 8
        0xC3,                         // ret（cdecl 支路）
        0xC2, 0x08, 0x00,             // ret 8（stdcall 支路）
    };
    EXPECT_FALSE(ret_imm_of(std::span<const wvmp::u8>(body), 0x1000).has_value());
}

TEST(LifterCleanup, CallInsideBodyRejected) {
    // 体含 call → callee 体量与副作用不可界 → nullopt。
    const wvmp::u8 body[] = {
        0xE8, 0x00, 0x00, 0x00, 0x00, // call next
        0xC3,                         // ret
    };
    EXPECT_FALSE(ret_imm_of(std::span<const wvmp::u8>(body), 0x1000).has_value());
}

TEST(LifterCleanup, NoTerminalRejected) {
    // 无终态（自跳死循环）→ visited 去重耗尽队列 → nullopt。
    const wvmp::u8 body[] = {
        0xEB, 0xFE,                   // jmp self
    };
    EXPECT_FALSE(ret_imm_of(std::span<const wvmp::u8>(body), 0x1000).has_value());
}

// ==================== MIT-506/507 (T60): x87 L0 解码 ====================

TEST(LifterX87, CapstoneProbeFaddpFcomiFldcw) {
    lifter::CapstoneSession session(ir::Arch::X86);
    // T61 全矩阵探针: D8/DC 非弹 + DE 弹四象限 (fsub/fdiv 的 DE r 位反转)
    // + faddp/fmulp + fcomi/fcomip。实证 capstone 5.0.6 助记符命名与
    // (op0,op1) 报告序 —— rev 位判定的 ground truth。
    const wvmp::u8 code[] = {
        0xD8, 0xE1,                   // fsub st(1), st(0)
        0xD8, 0xE9,                   // fsubr st(1), st(0)
        0xD8, 0xF1,                   // fdiv st(1), st(0)
        0xD8, 0xF9,                   // fdivr st(1), st(0)
        0xDC, 0xE1,                   // fsub st(1), st(0)
        0xDE, 0xC1,                   // faddp st(1), st(0)
        0xDE, 0xC9,                   // fmulp st(1), st(0)
        0xDE, 0xE1,                   // fsubrp st(1), st(0)  (DE r 位反转)
        0xDE, 0xE9,                   // fsubp st(1), st(0)
        0xDE, 0xF1,                   // fdivrp st(1), st(0)
        0xDE, 0xF9,                   // fdivp st(1), st(0)
        0xDB, 0xF1,                   // fcomi st, st(1)
        0xDF, 0xF1,                   // fcomip st, st(1)
        0xD9, 0x28,                   // fldcw [eax]
        0xDF, 0xE0,                   // fnstsw ax
        0xD9, 0x38,                   // fnstsw word [eax]
        0xDD, 0x58, 0x10,             // fstp qword [eax+0x10]
        0xDF, 0x58, 0x10,             // fistp word [eax+0x10]
    };
    const wvmp::u8* p2 = code;
    size_t left = sizeof(code);
    wvmp::u64 addr = 0x1000;
    const cs_insn* ci;
    while ((ci = session.next(p2, left, addr)) != nullptr) {
        std::printf("[T60-CAP] %s op_count=%u", ci->mnemonic,
                    ci->detail ? ci->detail->x86.op_count : 99u);
        if (ci->detail)
            for (unsigned k = 0; k < ci->detail->x86.op_count; ++k) {
                const auto& op = ci->detail->x86.operands[k];
                std::printf(" op%u:type=%d", k, static_cast<int>(op.type));
                if (op.type == X86_OP_REG)
                    std::printf("(reg=%d,size=%u)", static_cast<int>(op.reg),
                                op.size);
                else if (op.type == X86_OP_MEM)
                    std::printf("(base=%d,size=%u)", static_cast<int>(op.mem.base),
                                op.size);
            }
        std::printf(" bytes=%02x%02x\n", ci->bytes[0], ci->bytes[1]);
    }
}

TEST(LifterX87, RegionDecodesX87Sequence) {
    // 真 x87 字节序列（fld m64; fadd m64; fstp m64; fchs; fnop）经
    // LifterPass 全管道 → IR 断言（物理 FPU 驻留架构的解码层验证）。
    const wvmp::u8 code[] = {
        0xDD, 0x00,                   // fld qword [eax]      (DD /0)
        0xD8, 0x40, 0x08,             // fadd dword [eax+8]   (D8 /0, modrm 40)
        0xDD, 0x58, 0x10,             // fstp qword [eax+0x10]
        0xD9, 0xE0,                   // fchs
        0xD9, 0xD0,                   // fnop
    };
    const auto img = make_min_pe(std::span<const wvmp::u8>(code));
    wvmp::ProtectionContext ctx;
    ctx.image = img;
    ir::FunctionRegion fr;
    fr.name = "x87fn";
    fr.arch = ir::Arch::X86;
    fr.begin_rva = 0x1000;
    fr.end_rva = 0x1000 + sizeof(code);
    ctx.functions.push_back(fr);
    wvmp::passes::LifterPass pass;
    pass.run(ctx);
    ASSERT_FALSE(ctx.functions[0].blocks.empty());
    std::vector<ir::Op> ops;
    for (const auto& b : ctx.functions[0].blocks)
        for (const auto& i : b.insns) {
            ops.push_back(i.op);
            const auto nm = to_string(i.op);
            std::printf("[T60-DBG] op=%u %.*s\n", static_cast<unsigned>(i.op),
                        static_cast<int>(nm.size()), nm.data());
        }
    ASSERT_GE(ops.size(), static_cast<size_t>(5));
    std::printf("[T60-ENUM] test-side Fld87Mem=%d ops0=%d\n",
                static_cast<int>(ir::Op::Fld87Mem), static_cast<int>(ops[0]));
    EXPECT_EQ(ops[0], ir::Op::Fld87Mem);
    EXPECT_EQ(ops[1], ir::Op::Fadd87);
    EXPECT_EQ(ops[2], ir::Op::Fstp87Mem);
    EXPECT_EQ(ops[3], ir::Op::Fchs87);
    EXPECT_EQ(ops[4], ir::Op::Nop);   // fnop 折 Nop (零新 op)
}

TEST(LifterResync, JmpInWindowStaysGated) {
    // 窗内控制流离开（jmp）→ resync 不可证 → 拒。
    const wvmp::u8 cont[] = {
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax,1
        0xE9, 0x00, 0x00, 0x00, 0x00, // jmp next
        0x89, 0xEC,                   // mov esp,ebp（不可达，不进窗）
    };
    EXPECT_FALSE(resync_of(std::span<const wvmp::u8>(cont), 0x1000));
}

TEST(LifterResync, IndirectCallStaysGated) {
    // 间接 call（FF /2）保守拒（目标未知，宁窄勿宽）。
    const wvmp::u8 cont[] = {
        0xFF, 0xD0,                   // call eax
        0x89, 0xEC,                   // mov esp,ebp
    };
    EXPECT_FALSE(resync_of(std::span<const wvmp::u8>(cont), 0x1000));
}

TEST(LifterResync, BudgetExhaustedStaysGated) {
    // 预算耗尽无终止符 → 拒（nops + ret，ret 在预算内触发 grp 拒——
    // 双重防线取先到者）。
    std::vector<wvmp::u8> cont(300, 0x90);
    cont.push_back(0xC3);
    EXPECT_FALSE(resync_of(std::span<const wvmp::u8>(cont), 0x1000));
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

TEST_F(LifterTranslate, AndnpsRegRegFoldsToAndnCarrier) {
    // 0F 55 C1: andnps xmm0, xmm1 — MIT-425 (G1b R3) 入面。dst = ~dst & src
    // 非纯位运算三元组 (VM 无 128-bit NOT 原语, 双折不可行) → 新 VmOp::
    // Andnps; IR 层 = (Op::Andps, src2=imm(kSseAndn=18)) 载体标记。
    // (MIT-411 时代本用例为负例断言 AndnpsStillUnsupported, 按 §B.4 翻转。)
    const wvmp::u8 b[] = {0x0F, 0x55, 0xC1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Andps);          // Andps 载体
    EXPECT_EQ(r.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r.insn.src2.imm, 18);               // kSseAndn 标记
    EXPECT_EQ(r.insn.size, ir::Size::S64);
    EXPECT_FALSE(r.insn.updates_flags);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);      // xmm0
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rcx);      // xmm1
}

TEST_F(LifterTranslate, AndnpdFoldsToAndnCarrier) {
    // 66 0F 55 C1: andnpd xmm0, xmm1 — 66 前缀吸收进 id (prefix[0]=0),
    // 与 andnps 逐位同语义, 折叠同一 Andnps 载体 (411 ps/pd 互认先验)。
    const wvmp::u8 b[] = {0x66, 0x0F, 0x55, 0xC1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Andps);
    EXPECT_EQ(r.insn.src2.imm, 18);               // kSseAndn
}

TEST_F(LifterTranslate, PandnMemSrcFoldsToAndnCarrier) {
    // 66 0F DF 05 xx: pandn xmm0, xmmword ptr [rip] — SSE2 整数 andn,
    // 与 andnps 逐位同语义 → 同一 (Andps, kSseAndn) 载体 (R2 档①)。
    const wvmp::u8 b[] = {0x66, 0x0F, 0xDF, 0x05, 0x00, 0x00, 0x00, 0x00};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Andps);
    EXPECT_EQ(r.insn.src2.imm, 18);               // kSseAndn
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.src.mem.base, ir::Reg::Rip);
}

TEST_F(LifterTranslate, PandPorPxorFoldToPsBitwise) {
    // 66 0F DB/EB/EF C1: pand/por/pxor xmm0, xmm1 — 128-bit 按位同语义,
    // 零新 VmOp 折叠 Andps/Orps/Xorps (411 pd 折叠 ps 的整数扩展, R2 档①)。
    const wvmp::u8 pand[]  = {0x66, 0x0F, 0xDB, 0xC1};
    const wvmp::u8 por[]   = {0x66, 0x0F, 0xEB, 0xC1};
    const wvmp::u8 pxor[]  = {0x66, 0x0F, 0xEF, 0xC1};
    auto a = translate_bytes(x64, pand, ir::Arch::X64);
    ASSERT_EQ(a.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(a.insn.op, ir::Op::Andps);
    auto o = translate_bytes(x64, por, ir::Arch::X64);
    ASSERT_EQ(o.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(o.insn.op, ir::Op::Orps);
    auto x = translate_bytes(x64, pxor, ir::Arch::X64);
    ASSERT_EQ(x.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(x.insn.op, ir::Op::Xorps);
    EXPECT_FALSE(a.insn.updates_flags);
    EXPECT_FALSE(o.insn.updates_flags);
    EXPECT_FALSE(x.insn.updates_flags);
}

TEST_F(LifterTranslate, PandMemSrcFoldsToAndps) {
    // 66 0F DB 05 xx: pand xmm0, xmmword ptr [rip] — mem 源 (408 通道)。
    const wvmp::u8 b[] = {0x66, 0x0F, 0xDB, 0x05, 0x00, 0x00, 0x00, 0x00};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Andps);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.src.mem.base, ir::Reg::Rip);
}

TEST_F(LifterTranslate, MulssRegRegMulCarrierMarker14) {
    // F3 0F 59 C1: mulss xmm0, xmm1 — (Op::Mul, src2=imm(14)=kSseMulSs)
    // 载体标记 (R1)。size=S32 (scalar single 形式标签)。
    const wvmp::u8 b[] = {0xF3, 0x0F, 0x59, 0xC1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Mul);
    EXPECT_EQ(r.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r.insn.src2.imm, 14);               // kSseMulSs
    EXPECT_EQ(r.insn.size, ir::Size::S32);
    EXPECT_FALSE(r.insn.updates_flags);           // SSE 不写 EFLAGS (GP mul 恒 true)
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);      // xmm0
    EXPECT_EQ(r.insn.src.reg, ir::Reg::Rcx);      // xmm1
}

TEST_F(LifterTranslate, MulsdRegRegMulCarrierMarker15) {
    // F2 0F 59 C1: mulsd xmm0, xmm1 — (Mul, src2=imm(15)=kSseMulSd), S64。
    const wvmp::u8 b[] = {0xF2, 0x0F, 0x59, 0xC1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Mul);
    EXPECT_EQ(r.insn.src2.imm, 15);               // kSseMulSd
    EXPECT_EQ(r.insn.size, ir::Size::S64);
}

TEST_F(LifterTranslate, MulpsMulpdRegRegMulCarrierMarker16_17) {
    // 0F 59 C1: mulps / 66 0F 59 C1: mulpd — (Mul, 16/17), packed S64 标签。
    const wvmp::u8 ps[] = {0x0F, 0x59, 0xC1};
    const wvmp::u8 pd[] = {0x66, 0x0F, 0x59, 0xC1};
    auto p = translate_bytes(x64, ps, ir::Arch::X64);
    ASSERT_EQ(p.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(p.insn.op, ir::Op::Mul);
    EXPECT_EQ(p.insn.src2.imm, 16);               // kSseMulPs
    EXPECT_EQ(p.insn.size, ir::Size::S64);
    auto d = translate_bytes(x64, pd, ir::Arch::X64);
    ASSERT_EQ(d.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(d.insn.op, ir::Op::Mul);
    EXPECT_EQ(d.insn.src2.imm, 17);               // kSseMulPd
    EXPECT_EQ(d.insn.size, ir::Size::S64);
}

TEST_F(LifterTranslate, MulsdRipMemSource) {
    // F2 0F 59 05 xx: mulsd xmm0, qword ptr [rip] — mem 源含 rip (408 通路
    // 一次到位, 派活单 §B.1)。MSVC /Od 对 `g_a *= g_b` 天然产此形态。
    const wvmp::u8 b[] = {0xF2, 0x0F, 0x59, 0x05, 0x00, 0x00, 0x00, 0x00};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Mul);
    EXPECT_EQ(r.insn.src2.imm, 15);               // kSseMulSd
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.src.mem.base, ir::Reg::Rip);
}

TEST_F(LifterTranslate, MulpsMemSource) {
    // 0F 59 05 xx: mulps xmm0, xmmword ptr [rip] — packed mem 源。
    const wvmp::u8 b[] = {0x0F, 0x59, 0x05, 0x00, 0x00, 0x00, 0x00};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Mul);
    EXPECT_EQ(r.insn.src2.imm, 16);               // kSseMulPs
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.src.mem.base, ir::Reg::Rip);
}

TEST_F(LifterTranslate, PaddqStillUnsupported) {
    // 66 0F D4 C1: paddq xmm0, xmm1 — SSE2 加法族不在 G1b 面 (跳表预算
    // 95 顶格, R2 档② 砍面留 G1c, 派活单 §B.3/D1) → unsupported → C1 gate
    // 兜底 (负例断言; 同款: psubq/pcmpeq 系)。
    const wvmp::u8 b[] = {0x66, 0x0F, 0xD4, 0xC1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    EXPECT_EQ(r.status, lifter::TranslateStatus::Unsupported);
}

// =============================================================================
// MIT-426 (G6a): VEX.128 V-pair 三地址折叠 — 38 id 白名单 + 位宽闸 + 三态
// =============================================================================
// 全部字节经 vendored capstone 5 probe 实测对账 (2026-08-30; vvvv 取反/
// pp 映射 0F=00,66=01,F3=10,F2=11 手算曾错 4 处被 probe 纠正 — #33 纪律)。
// 断言口径: dst/src 的 ir::Reg 值 = xmm 槽号 0..7 (借用 ir::Reg 0..7 约定)。

TEST_F(LifterTranslate, VexAddssDstSrc1Direct) {
    // C5 FA 58 C1: vaddss xmm0, xmm0, xmm1 — dst==src1 三态① 零成本直走
    // (2-op (dst, s2))。C5 短前缀形态 (D5 双编码之一)。
    const wvmp::u8 b[] = {0xC5, 0xFA, 0x58, 0xC1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Addss);
    EXPECT_EQ(r.insn.size, ir::Size::S32);
    EXPECT_EQ(static_cast<int>(r.insn.dst.reg), 0);   // xmm0
    EXPECT_EQ(static_cast<int>(r.insn.src.reg), 1);   // src2 = xmm1
    EXPECT_TRUE(r.extra.empty());                     // 直走无前置
    EXPECT_FALSE(r.insn.updates_flags);
}

TEST_F(LifterTranslate, VexAddsdC4FullEncoding) {
    // C4 E1 7B 58 C1: vaddsd xmm0, xmm0, xmm1 — C4 全前缀形态 (D5 双编码
    // 之二; 同 INS id, prefix=[0,0,0,0] 不经入口前缀闸)。(Addss,S64) 编码。
    const wvmp::u8 b[] = {0xC4, 0xE1, 0x7B, 0x58, 0xC1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Addss);
    EXPECT_EQ(r.insn.size, ir::Size::S64);            // (Addss,S64) = addsd
    EXPECT_EQ(static_cast<int>(r.insn.dst.reg), 0);
    EXPECT_EQ(static_cast<int>(r.insn.src.reg), 1);
    EXPECT_TRUE(r.extra.empty());
}

TEST_F(LifterTranslate, VexAddpsDstSrc2CommutativeSwap) {
    // C5 F8 58 D2: vaddps xmm2, xmm0, xmm2 — dst==src2 三态② 可交换
    // (swap: src1 上位) → 2-op (dst=xmm2, src=xmm0), 零成本。
    const wvmp::u8 b[] = {0xC5, 0xF8, 0x58, 0xD2};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Addps);
    EXPECT_EQ(static_cast<int>(r.insn.dst.reg), 2);
    EXPECT_EQ(static_cast<int>(r.insn.src.reg), 0);   // 交换后 = 原 src1
    EXPECT_TRUE(r.extra.empty());
}

TEST_F(LifterTranslate, VexMulpsDstSrc2CommutativeSwap) {
    // C5 F8 59 D2: vmulps xmm2, xmm0, xmm2 — mul 族 d==s2 交换 (可交换族
    // 第二形态, 三态② 各 ≥2 断言之一)。(Mul, src2=kSseMulPs)。
    const wvmp::u8 b[] = {0xC5, 0xF8, 0x59, 0xD2};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Mul);
    EXPECT_EQ(r.insn.src2.imm, 16);                   // kSseMulPs
    EXPECT_EQ(static_cast<int>(r.insn.dst.reg), 2);
    EXPECT_EQ(static_cast<int>(r.insn.src.reg), 0);
    EXPECT_TRUE(r.extra.empty());
}

TEST_F(LifterTranslate, VexMulssDstIndependentPreMov) {
    // C5 FA 59 CA: vmulss xmm1, xmm0, xmm2 — dst 独立 三态③ → 前置
    // Op::Movaps(xmm1←xmm0) 16B 纯拷贝 + 主 (Mul, src2=14, dst=1, src=2)。
    // VEX 标量 "dst 高位 ← src1 高位" == 16B 拷贝后 2-op "高位保持"。
    const wvmp::u8 b[] = {0xC5, 0xFA, 0x59, 0xCA};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Mul);
    EXPECT_EQ(r.insn.src2.imm, 14);                   // kSseMulSs
    EXPECT_EQ(r.insn.size, ir::Size::S32);
    EXPECT_EQ(static_cast<int>(r.insn.dst.reg), 1);
    EXPECT_EQ(static_cast<int>(r.insn.src.reg), 2);
    ASSERT_EQ(r.extra.size(), 1u);                    // 前置 Movaps
    EXPECT_EQ(r.extra[0].op, ir::Op::Movaps);
    EXPECT_EQ(r.extra[0].size, ir::Size::S64);        // 16B 全量
    EXPECT_EQ(static_cast<int>(r.extra[0].dst.reg), 1);
    EXPECT_EQ(static_cast<int>(r.extra[0].src.reg), 0);
    EXPECT_EQ(r.extra[0].addr, r.insn.addr);          // 共享机器地址
    EXPECT_FALSE(r.extra[0].updates_flags);
}

TEST_F(LifterTranslate, VexSubpsDstIndependentNoncommPreMov) {
    // C5 F8 5C D1: vsubps xmm2, xmm0, xmm1 — 非交换族 dst 独立 (三态③ 对
    // sub 也成立: pre-Mov(dst←s1) + 2-op = s1 - s2 逐位等价)。
    const wvmp::u8 b[] = {0xC5, 0xF8, 0x5C, 0xD1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Subps);
    EXPECT_EQ(static_cast<int>(r.insn.dst.reg), 2);
    EXPECT_EQ(static_cast<int>(r.insn.src.reg), 1);   // s2
    ASSERT_EQ(r.extra.size(), 1u);
    EXPECT_EQ(r.extra[0].op, ir::Op::Movaps);
    EXPECT_EQ(static_cast<int>(r.extra[0].dst.reg), 2);
    EXPECT_EQ(static_cast<int>(r.extra[0].src.reg), 0);  // s1
}

TEST_F(LifterTranslate, VexMulsdRipMemDstIndependentPreMov) {
    // C5 FB 59 0D xx: vmulsd xmm1, xmm0, qword ptr [rip] — mem 源 + dst
    // 独立组合 (408 通路 × pre-Mov 前置; next_ip_of 覆盖语义见 translator)。
    const wvmp::u8 b[] = {0xC5, 0xFB, 0x59, 0x0D, 0x78, 0x56, 0x34, 0x12};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Mul);
    EXPECT_EQ(r.insn.src2.imm, 15);                   // kSseMulSd
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.src.mem.base, ir::Reg::Rip);
    ASSERT_EQ(r.extra.size(), 1u);
    EXPECT_EQ(r.extra[0].op, ir::Op::Movaps);
    EXPECT_EQ(static_cast<int>(r.extra[0].dst.reg), 1);
    EXPECT_EQ(static_cast<int>(r.extra[0].src.reg), 0);
}

TEST_F(LifterTranslate, VexVmulsdDstSrc2ScalarGate) {
    // C5 FB 59 C9: vmulsd xmm1, xmm0, xmm1 — **标量 d==s2 一律 gate**
    // (D2 边界): VEX 标量 "dst 高位 ← s1 高位" 与 2-op "高位保持" 不相容
    // (swap 后高位 = dst 原值 ≠ s1 高位), pre-Mov 又先摧毁 s2(==dst) 的
    // 值; 正确序列需 xmm→GP 双槽暂存原 dst, 既有 VmOp 无此原语 (D1 禁新)
    // → gate 保守退化。packed 交换 (上方 Addps/Mulps swap) 不受影响。
    const wvmp::u8 b[] = {0xC5, 0xFB, 0x59, 0xC9};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    EXPECT_EQ(r.status, lifter::TranslateStatus::Unsupported);
    ASSERT_EQ(r.skipped_ranges.size(), 1u);
}

TEST_F(LifterTranslate, VexSubsdDstSrc2NoncommGate) {
    // C5 FB 5C D2: vsubsd xmm2, xmm0, xmm2 — 非交换 dst==src2 → D2 裁决
    // gate (频率: ucrtbase 2.19% / smartscreen 0.00% 合并 0.75%; 折叠需
    // xmm→GP 双槽暂存原 dst, 既有 VmOp 无此原语, 新 VmOp 违反 D1 →
    // 保守退化整函数原生, 见 GAPS G6a)。
    const wvmp::u8 b[] = {0xC5, 0xFB, 0x5C, 0xD2};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    EXPECT_EQ(r.status, lifter::TranslateStatus::Unsupported);
    ASSERT_EQ(r.skipped_ranges.size(), 1u);           // C1 gate 链 (字节级)
    EXPECT_EQ(r.skipped_ranges[0].first, 0u);
    EXPECT_EQ(r.skipped_ranges[0].second, 4u);
}

TEST_F(LifterTranslate, VexYmmWidthGateNegative) {
    // C5 FC 58 C1: vaddps ymm0, ymm0, ymm1 — **本单最大陷阱钉死** (B.4):
    // 与 vaddps xmm 同 INS id (X86_INS_VADDPS 覆盖 128/256 两宽), 位宽闸
    // 必须按操作数 32B 拒 — 放行 = 错误 lift 静默坏壳。
    const wvmp::u8 b[] = {0xC5, 0xFC, 0x58, 0xC1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    EXPECT_EQ(r.status, lifter::TranslateStatus::Unsupported);
    ASSERT_EQ(r.skipped_ranges.size(), 1u);
}

TEST_F(LifterTranslate, VexYmmMovapsGateNegative) {
    // C5 FC 28 C8: vmovaps ymm1, ymm0 — ymm 2-op 拷贝同拒 (D4 注意
    // "vmovaps 在 AVX 有 ymm 变体", 派活单 §E)。
    const wvmp::u8 b[] = {0xC5, 0xFC, 0x28, 0xC8};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    EXPECT_EQ(r.status, lifter::TranslateStatus::Unsupported);
}

TEST_F(LifterTranslate, VexXmm8UnmappedGate) {
    // C5 78 58 C1: vaddps xmm8, xmm0, xmm1 — xmm8..15 不在 SSE 跟踪区
    // (ctx.xmm[0..7]), 与 legacy SSE 同口径 gate (不可映射 → unsupported)。
    const wvmp::u8 b[] = {0xC5, 0x78, 0x58, 0xC1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    EXPECT_EQ(r.status, lifter::TranslateStatus::Unsupported);
}

TEST_F(LifterTranslate, VexMovapsTwoOpDirect) {
    // C5 F8 28 C8: vmovaps xmm1, xmm0 — 2-op 纯拷贝直折单条 (D4: 不进
    // binop 前置框架; capstone 报 op_count=2, 走既有 translate_sse_mov)。
    const wvmp::u8 b[] = {0xC5, 0xF8, 0x28, 0xC8};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Movaps);
    EXPECT_EQ(r.insn.size, ir::Size::S64);
    EXPECT_EQ(static_cast<int>(r.insn.dst.reg), 1);
    EXPECT_EQ(static_cast<int>(r.insn.src.reg), 0);
    EXPECT_TRUE(r.extra.empty());
}

TEST_F(LifterTranslate, VexMovupsRipMemLoad) {
    // C5 F8 10 05 xx: vmovups xmm0, xmmword ptr [rip] — 2-op mem load 直通
    // (408 store/load 通路; 与 legacy movups 同形)。
    const wvmp::u8 b[] = {0xC5, 0xF8, 0x10, 0x05, 0x78, 0x56, 0x34, 0x12};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Movups);
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.src.mem.base, ir::Reg::Rip);
    EXPECT_TRUE(r.extra.empty());
}

TEST_F(LifterTranslate, VexMovsdInsertDstSrc1Fold) {
    // C5 FB 10 C1: vmovsd xmm0, xmm0, xmm1 — 3-op 插入形态 (§F.4 "假 Mov")
    // dst==src1 可折: 2-op (dst, s2) "dst 高位保持" == s1 高位 (因 dst==s1)。
    // capstone 对 2 寄存器 vmovss/vmovsd 亦规范成 3-op (s1=dst) — 同路径。
    const wvmp::u8 b[] = {0xC5, 0xFB, 0x10, 0xC1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Movss);
    EXPECT_EQ(r.insn.size, ir::Size::S64);            // (Movss,S64) = movsd
    EXPECT_EQ(static_cast<int>(r.insn.dst.reg), 0);
    EXPECT_EQ(static_cast<int>(r.insn.src.reg), 1);
    EXPECT_TRUE(r.extra.empty());
}

TEST_F(LifterTranslate, VexMovsdInsertDstIndepGate) {
    // C5 FB 10 D1: vmovsd xmm2, xmm0, xmm1 — 插入语义 d≠s1 → gate
    // (dst 高位 ← s1 非 2-op 可表达; 禁当纯拷贝直折, §F.4)。
    const wvmp::u8 b[] = {0xC5, 0xFB, 0x10, 0xD1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    EXPECT_EQ(r.status, lifter::TranslateStatus::Unsupported);
}

TEST_F(LifterTranslate, VexAndnpsDstSrc1Direct) {
    // C5 F8 55 C1: vandnps xmm0, xmm0, xmm1 — andn (非交换) dst==src1 直走
    // (Op::Andps + kSseAndn 载体, 与 legacy 425 同编码)。
    const wvmp::u8 b[] = {0xC5, 0xF8, 0x55, 0xC1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Andps);
    EXPECT_EQ(r.insn.src2.imm, 18);                   // kSseAndn
    EXPECT_EQ(static_cast<int>(r.insn.dst.reg), 0);
    EXPECT_EQ(static_cast<int>(r.insn.src.reg), 1);
    EXPECT_TRUE(r.extra.empty());
}

TEST_F(LifterTranslate, VexAndnpsDstIndepPreMov) {
    // C5 F8 55 D1: vandnps xmm2, xmm0, xmm1 — andn dst 独立: pre-Mov(2←0)
    // + 2-op = ~xmm0 & xmm1 逐位等价 (VEX dst=~s1&s2)。
    const wvmp::u8 b[] = {0xC5, 0xF8, 0x55, 0xD1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Andps);
    EXPECT_EQ(r.insn.src2.imm, 18);
    EXPECT_EQ(static_cast<int>(r.insn.dst.reg), 2);
    EXPECT_EQ(static_cast<int>(r.insn.src.reg), 1);
    ASSERT_EQ(r.extra.size(), 1u);
    EXPECT_EQ(static_cast<int>(r.extra[0].dst.reg), 2);
    EXPECT_EQ(static_cast<int>(r.extra[0].src.reg), 0);
}

TEST_F(LifterTranslate, VexPxorZeroingIdiom) {
    // C5 F9 EF C0: vpxor xmm0, xmm0, xmm0 — 整数清零惯用法 (python314 语料
    // dst 独立占比主导形态的实源): d==s1==s2 → 2-op (dst, s2) 直走。
    const wvmp::u8 b[] = {0xC5, 0xF9, 0xEF, 0xC0};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Xorps);
    EXPECT_EQ(static_cast<int>(r.insn.dst.reg), 0);
    EXPECT_EQ(static_cast<int>(r.insn.src.reg), 0);
    EXPECT_TRUE(r.extra.empty());
}

TEST_F(LifterTranslate, VexUcomissTwoOpFlags) {
    // C5 F8 2E C1: vucomiss xmm0, xmm1 — 2-op 比较直通, flags 通路保真
    // (updates_flags=true, 区域内 setcc/jcc 读真比较结果)。
    const wvmp::u8 b[] = {0xC5, 0xF8, 0x2E, 0xC1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Ucomiss);
    EXPECT_EQ(r.insn.size, ir::Size::S32);
    EXPECT_TRUE(r.insn.updates_flags);
    EXPECT_EQ(static_cast<int>(r.insn.dst.reg), 0);
    EXPECT_EQ(static_cast<int>(r.insn.src.reg), 1);
    EXPECT_TRUE(r.extra.empty());
}

TEST_F(LifterTranslate, VexVzeroupperGate) {
    // C5 F8 77: vzeroupper — 白名单外 (档B ABI 面) → 现状 gate 保持。
    const wvmp::u8 b[] = {0xC5, 0xF8, 0x77};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    EXPECT_EQ(r.status, lifter::TranslateStatus::Unsupported);
}

TEST_F(LifterTranslate, VexVpadddGate) {
    // C5 F9 FE C1: vpaddd xmm0, xmm0, xmm1 — SSE2 整数加法族 (G1c 本体
    // paddq 砍面的 V-对镜像) → 现状 gate 保持 (随本体)。
    const wvmp::u8 b[] = {0xC5, 0xF9, 0xFE, 0xC1};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    EXPECT_EQ(r.status, lifter::TranslateStatus::Unsupported);
}

TEST_F(LifterTranslate, VexRorxNowFolded) {
    // MIT-434 (G8a): 426 时代的 gate 负例随 BMI 入面**翻转正例** (425 §B.4
    // 先例): C4 E3 7B F0 C1 03 = rorx eax, ecx, 3 — flagless 载体
    // (Op::Ror, src=Imm(3), src2=Imm(kFlagless=22), updates_flags=false;
    // 五位 flags 全不写 = SDM/probe)。字节经 vendored capstone probe 实测。
    const wvmp::u8 b[] = {0xC4, 0xE3, 0x7B, 0xF0, 0xC1, 0x03};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Ror);
    EXPECT_EQ(r.insn.size, ir::Size::S32);
    EXPECT_FALSE(r.insn.updates_flags);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(static_cast<int>(r.insn.dst.reg), 0);            // eax
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r.insn.src.imm, 3);                              // count 骑 src
    ASSERT_EQ(r.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r.insn.src2.imm, 22);                            // kFlagless
    // dst=eax ≠ value=ecx → 前置 [Mov eax, ecx]
    ASSERT_EQ(r.extra.size(), static_cast<size_t>(1));
    EXPECT_EQ(r.extra[0].op, ir::Op::Mov);
}

TEST_F(LifterTranslate, VexFmaGate) {
    // C4 E2 F1 99 C2: vfmadd132sd xmm0, xmm1, xmm2 — FMA 双舍入红线
    // (triage §6.5, 永不拆 mul+add) → 现状 gate 保持。(字节 probe 实测。)
    const wvmp::u8 b[] = {0xC4, 0xE2, 0xF1, 0x99, 0xC2};
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
    // (66 砍面, §B.7) / 67 地址宽 / 段覆盖 — 全部照旧 gate。
    // MIT-442 (X2a) ② 负例翻转登记 (425/428 §B.4 先例): 无前缀单发形
    // (A4 movsb / 48 A5 movsq / A5 movsd / AD lodsd / AE scasd) 由 gate
    // 翻正为 plain 单发微程序 (域 23..27), 断言迁移至 PlainStringLift*;
    // 66 形单发 (66 A5 movsw) 维持砍面 (S16 串形 G3 残余)。
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
    // MIT-442 (X2a) ②: 66 形单发 (66 A5 = movsw) 维持 gate (S16 串形砍面)。
    const wvmp::u8 plain16[] = {0x66, 0xA5};
    EXPECT_EQ(translate_bytes(x64, plain16, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
}


// ==================== MIT-427 (G1c): movd/movq GP↔xmm 桥 ====================
//
// 判据基线 = vendored capstone 5.0.6 probe (报告对照表): MOVD id=377 /
// MOVQ id=378 / VMOVD 1025 / VMOVQ 1021; 66 族 prefix[2]=0x66; F3 0F 7E
// 被吸收进 id 后 prefix 全零; NP 0F 6E/6F/7E/7F 带 mm 操作数 (D2 gate)。
// IR 载体 (Op::Movss, src2=imm 19..21): 19=GP→xmm / 20=xmm→GP / 21=xmm→xmm
// 清零拷贝 (F3 0F 7E 与 66 0F D6 reg-reg 实测逐位同语义, d6_probe)。

TEST_F(LifterTranslate, MovdBridgeLoadDirections) {
    // ① movd xmm0, eax (66 0F 6E C0): (Movss,S32, src2=19) dst=借用 0, src=Rax
    const wvmp::u8 d_in[] = {0x66, 0x0F, 0x6E, 0xC0};
    auto r1 = translate_bytes(x64, d_in, ir::Arch::X64);
    ASSERT_EQ(r1.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r1.insn.op, ir::Op::Movss);
    EXPECT_EQ(r1.insn.size, ir::Size::S32);
    ASSERT_EQ(r1.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r1.insn.src2.imm, 19);
    ASSERT_EQ(r1.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r1.insn.dst.reg, ir::Reg::Rax);   // 借用值 0 = xmm0 (SSE 惯例)
    ASSERT_EQ(r1.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r1.insn.src.reg, ir::Reg::Rax);   // GP 真寄存器
    // ② movq xmm0, rax (66 48 0F 6E C0): (Movss,S64, src2=19)
    const wvmp::u8 q_in[] = {0x66, 0x48, 0x0F, 0x6E, 0xC0};
    auto r2 = translate_bytes(x64, q_in, ir::Arch::X64);
    ASSERT_EQ(r2.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r2.insn.size, ir::Size::S64);
    EXPECT_EQ(r2.insn.src2.imm, 19);
    // ③ movd xmm0, [rcx] (66 0F 6E 01): mem 形式 → 既有 XmmLoad 载体
    //    ((Movss,S32, mem), 无标记 — translate_sse_mov 通路)
    const wvmp::u8 d_mem[] = {0x66, 0x0F, 0x6E, 0x01};
    auto r3 = translate_bytes(x64, d_mem, ir::Arch::X64);
    ASSERT_EQ(r3.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r3.insn.op, ir::Op::Movss);
    EXPECT_EQ(r3.insn.size, ir::Size::S32);
    EXPECT_EQ(r3.insn.src2.kind, ir::Operand::Kind::None);
    ASSERT_EQ(r3.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r3.insn.src.mem.base, ir::Reg::Rcx);
    // ④ movq xmm0, [rcx] (66 48 0F 6E 01): (Movss,S64, mem) → XmmLoad 8
    const wvmp::u8 q_mem[] = {0x66, 0x48, 0x0F, 0x6E, 0x01};
    auto r4 = translate_bytes(x64, q_mem, ir::Arch::X64);
    ASSERT_EQ(r4.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r4.insn.size, ir::Size::S64);
    ASSERT_EQ(r4.insn.src.kind, ir::Operand::Kind::Mem);
}

TEST_F(LifterTranslate, MovdBridgeStoreDirections) {
    // ⑤ movd eax, xmm0 (66 0F 7E C0): (Movss,S32, src2=20) dst=Rax, src=借用 0
    const wvmp::u8 d_out[] = {0x66, 0x0F, 0x7E, 0xC0};
    auto r1 = translate_bytes(x64, d_out, ir::Arch::X64);
    ASSERT_EQ(r1.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r1.insn.op, ir::Op::Movss);
    EXPECT_EQ(r1.insn.size, ir::Size::S32);
    ASSERT_EQ(r1.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r1.insn.src2.imm, 20);
    ASSERT_EQ(r1.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r1.insn.dst.reg, ir::Reg::Rax);   // GP 真寄存器
    ASSERT_EQ(r1.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r1.insn.src.reg, ir::Reg::Rax);   // 借用值 0 = xmm0
    // ⑥ movq rax, xmm0 (66 48 0F 7E C0): (Movss,S64, src2=20)
    const wvmp::u8 q_out[] = {0x66, 0x48, 0x0F, 0x7E, 0xC0};
    auto r2 = translate_bytes(x64, q_out, ir::Arch::X64);
    ASSERT_EQ(r2.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r2.insn.size, ir::Size::S64);
    EXPECT_EQ(r2.insn.src2.imm, 20);
    // ⑦ movd [rcx], xmm0 (66 0F 7E 01): mem 形式 → 既有 XmmStore 载体
    const wvmp::u8 d_mem[] = {0x66, 0x0F, 0x7E, 0x01};
    auto r3 = translate_bytes(x64, d_mem, ir::Arch::X64);
    ASSERT_EQ(r3.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r3.insn.size, ir::Size::S32);
    ASSERT_EQ(r3.insn.dst.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r3.insn.dst.mem.base, ir::Reg::Rcx);
    // ⑧ movq [rcx], xmm0 (66 48 0F 7E 01): (Movss,S64, mem) → XmmStore 8
    const wvmp::u8 q_mem[] = {0x66, 0x48, 0x0F, 0x7E, 0x01};
    auto r4 = translate_bytes(x64, q_mem, ir::Arch::X64);
    ASSERT_EQ(r4.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r4.insn.size, ir::Size::S64);
    ASSERT_EQ(r4.insn.dst.kind, ir::Operand::Kind::Mem);
}

TEST_F(LifterTranslate, MovqAllXmmBothEncodingsZeroHigh) {
    // all-xmm 双编码 — #33 实测逐位同语义 (d6_probe: 66 0F D6 C8 与
    // F3 0F 7E C1 高 64 均清零) → 双双折叠 kBridgeFromXmm (21)。
    // F3 0F 7E C1: movq xmm0, xmm1 (capstone 吸收 F3, prefix 全零)
    const wvmp::u8 f3[] = {0xF3, 0x0F, 0x7E, 0xC1};
    auto r1 = translate_bytes(x64, f3, ir::Arch::X64);
    ASSERT_EQ(r1.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r1.insn.op, ir::Op::Movss);
    EXPECT_EQ(r1.insn.size, ir::Size::S64);
    ASSERT_EQ(r1.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r1.insn.src2.imm, 21);
    EXPECT_EQ(r1.insn.dst.reg, ir::Reg::Rax);   // 借用 0 = xmm0 (dst)
    EXPECT_EQ(r1.insn.src.reg, ir::Reg::Rcx);   // 借用 1 = xmm1 (src)
    // 66 0F D6 C8: movq xmm0, xmm1 (reg 字段 = 源 xmm1, r/m = dst xmm0)
    const wvmp::u8 d6[] = {0x66, 0x0F, 0xD6, 0xC8};
    auto r2 = translate_bytes(x64, d6, ir::Arch::X64);
    ASSERT_EQ(r2.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r2.insn.src2.imm, 21);
    EXPECT_EQ(r2.insn.dst.reg, ir::Reg::Rax);
    EXPECT_EQ(r2.insn.src.reg, ir::Reg::Rcx);
}

TEST_F(LifterTranslate, VexVmovdVmovqBridgeMirror) {
    // B.3 VEX 镜像 (426 §F.4 ④ 挂账清偿): VMOVD 1025 / VMOVQ 1021, ymm
    // 位宽闸 + xmm8..15 闸继承 translate_vex128。
    // VEX vmovd xmm0, eax (C5 F9 6E C0): (Movss,S32, src2=19)
    const wvmp::u8 vd[] = {0xC5, 0xF9, 0x6E, 0xC0};
    auto r1 = translate_bytes(x64, vd, ir::Arch::X64);
    ASSERT_EQ(r1.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r1.insn.src2.imm, 19);
    EXPECT_EQ(r1.insn.size, ir::Size::S32);
    // VEX.W1 vmovq xmm0, rax (C4 E1 F9 6E C0): (Movss,S64, src2=19)
    const wvmp::u8 vq_in[] = {0xC4, 0xE1, 0xF9, 0x6E, 0xC0};
    auto r2 = translate_bytes(x64, vq_in, ir::Arch::X64);
    ASSERT_EQ(r2.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r2.insn.src2.imm, 19);
    EXPECT_EQ(r2.insn.size, ir::Size::S64);
    // VEX.W1 vmovq rax, xmm0 (C4 E1 F9 7E C0): (Movss,S64, src2=20)
    const wvmp::u8 vq_out[] = {0xC4, 0xE1, 0xF9, 0x7E, 0xC0};
    auto r3 = translate_bytes(x64, vq_out, ir::Arch::X64);
    ASSERT_EQ(r3.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r3.insn.src2.imm, 20);
    EXPECT_EQ(r3.insn.dst.reg, ir::Reg::Rax);
    // VEX vmovq xmm1, xmm0 (C5 F9 D6 C1): all-xmm → kBridgeFromXmm (21)
    const wvmp::u8 vq_rr[] = {0xC5, 0xF9, 0xD6, 0xC1};
    auto r4 = translate_bytes(x64, vq_rr, ir::Arch::X64);
    ASSERT_EQ(r4.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r4.insn.src2.imm, 21);
    // xmm8..15 负例: vmovq xmm8, rax (C4 41 F9 6E C0 — ~R=0 → reg=xmm8,
    // capstone 3-byte VEX 可解码, reg id 实测 130 = XMM8) → xmm_idx 不可
    // 映射 → gate (426 §F.3 同口径)。注: 2-byte VEX R=0 形态 (C5 39 6E C0)
    // vendored capstone 5.0.6 拒解码 — 上游 decoder 级 gate, 不入本单判据面。
    const wvmp::u8 vx8[] = {0xC4, 0x41, 0xF9, 0x6E, 0xC0};  // vmovq xmm8, rax
    EXPECT_EQ(translate_bytes(x64, vx8, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
}

TEST_F(LifterTranslate, MovdBridgeGatedFaces) {
    // D2 MMX 禁入: NP 0F 6F (mm 操作数 — capstone 报 id=MOVQ 同 id 混入,
    // mm 判据唯一可靠闸) / NP 0F 6E (MOVD mm 形) / NP 0F 7F (store 形)。
    const wvmp::u8 mmq[] = {0x0F, 0x6F, 0xC1};      // movq mm0, mm1
    EXPECT_EQ(translate_bytes(x64, mmq, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
    const wvmp::u8 mmd[] = {0x0F, 0x6E, 0xC1};      // movd mm0, ecx
    EXPECT_EQ(translate_bytes(x64, mmd, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
    const wvmp::u8 mmst[] = {0x0F, 0x7F, 0x01};     // movq [rcx], mm0
    EXPECT_EQ(translate_bytes(x64, mmst, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
    // B.2 砍面 (频率实测): paddq 66 0F D4 / psubq 66 0F FB → 照旧 gate
    // (#33: 派单 "paddq=66 0F FC" 实测为 PADDB — FC 也是 gate)。
    const wvmp::u8 paddq[] = {0x66, 0x0F, 0xD4, 0xC1};
    EXPECT_EQ(translate_bytes(x64, paddq, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
    const wvmp::u8 psubq[] = {0x66, 0x0F, 0xFB, 0xC1};
    EXPECT_EQ(translate_bytes(x64, psubq, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
    const wvmp::u8 paddb[] = {0x66, 0x0F, 0xFC, 0xC1};
    EXPECT_EQ(translate_bytes(x64, paddb, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
    // movdqa/movdqu (66/F3 0F 6F) 已由 MIT-428 (G1d) 折叠入面 — 原砍面
    // 负例断言移除 (翻转闭环), 方向矩阵与 VEX 镜像见 MIT-428 测试块。
    // D3 不本单: pmovmskb 66 0F D7 / pcmpeqd 66 0F 76 → gate。
    const wvmp::u8 pmskb[] = {0x66, 0x0F, 0xD7, 0xC0};
    EXPECT_EQ(translate_bytes(x64, pmskb, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
    const wvmp::u8 peqd[] = {0x66, 0x0F, 0x76, 0xC1};
    EXPECT_EQ(translate_bytes(x64, peqd, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
    // B.3: vpaddq 随 paddq 本体砍面 → gate (G6a ④ 保持)。
    const wvmp::u8 vpaddq[] = {0xC4, 0xE1, 0xF1, 0xD4, 0xC1};
    EXPECT_EQ(translate_bytes(x64, vpaddq, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
}

// ==================== MIT-428 (G1d): movdqa/movdqu 对齐传送 ====================
//
// 判据基线 = vendored capstone 5.0.6 probe 实测 (2026-08-31, 报告对照表):
// MOVDQA id=468 / MOVDQU id=469 (legacy 66/F3 0F 6F/7F) / VMOVDQA id=1028 /
// VMOVDQU id=1033 (VEX) / VMOVDQA32 1026 / VMOVDQA64 1027 (EVEX, 不入面)。
// §A.4 方向 probe 实测钉死: 6F (reg 字段=dst) 与 7F (rm 字段=dst, reg,reg
// 反写合法形) 双编码 capstone 均归一化 dst-first 报操作数 — 零调度层修正。

TEST_F(LifterTranslate, MovdqaMovdquEncodingDirectionMatrix) {
    // ---- 双编码 reg-reg: 6F 与 7F 反写形折叠结果一致 (probe 归一化钉) ----
    // 66 0F 6F C1: movdqa xmm0, xmm1 (reg 字段=dst) → (Movaps,S64) 全宽拷贝
    const wvmp::u8 dqa_6f[] = {0x66, 0x0F, 0x6F, 0xC1};
    auto r1 = translate_bytes(x64, dqa_6f, ir::Arch::X64);
    ASSERT_EQ(r1.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r1.insn.op, ir::Op::Movaps);
    EXPECT_EQ(r1.insn.size, ir::Size::S64);
    EXPECT_EQ(r1.insn.updates_flags, false);
    ASSERT_EQ(r1.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r1.insn.dst.reg, ir::Reg::Rax);   // 借用 0 = xmm0 (dst)
    ASSERT_EQ(r1.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r1.insn.src.reg, ir::Reg::Rcx);   // 借用 1 = xmm1 (src)
    // 66 0F 7F C8: movdqa xmm0, xmm1 (rm 字段=dst 反写形) — capstone 归一化
    // dst-first, 折叠与 6F 形逐字段一致 (§A.4 probe: op[0] access=W)
    const wvmp::u8 dqa_7f_rev[] = {0x66, 0x0F, 0x7F, 0xC8};
    auto r2 = translate_bytes(x64, dqa_7f_rev, ir::Arch::X64);
    ASSERT_EQ(r2.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r2.insn.op, ir::Op::Movaps);
    EXPECT_EQ(r2.insn.dst.reg, ir::Reg::Rax);
    EXPECT_EQ(r2.insn.src.reg, ir::Reg::Rcx);
    // F3 0F 6F C1 / F3 0F 7F C8: movdqu 双编码 → (Movups,S64)
    const wvmp::u8 dqu_6f[] = {0xF3, 0x0F, 0x6F, 0xC1};
    auto r3 = translate_bytes(x64, dqu_6f, ir::Arch::X64);
    ASSERT_EQ(r3.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r3.insn.op, ir::Op::Movups);
    EXPECT_EQ(r3.insn.dst.reg, ir::Reg::Rax);
    EXPECT_EQ(r3.insn.src.reg, ir::Reg::Rcx);
    const wvmp::u8 dqu_7f_rev[] = {0xF3, 0x0F, 0x7F, 0xC8};
    auto r4 = translate_bytes(x64, dqu_7f_rev, ir::Arch::X64);
    ASSERT_EQ(r4.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r4.insn.op, ir::Op::Movups);
    EXPECT_EQ(r4.insn.dst.reg, ir::Reg::Rax);
    EXPECT_EQ(r4.insn.src.reg, ir::Reg::Rcx);

    // ---- mem 双向: load (6F) → XmmLoad 载体 / store (7F) → XmmStore 载体 ----
    // 66 0F 6F 01: movdqa xmm0, [rcx] → (Movaps,S64, mem src)
    const wvmp::u8 dqa_ld[] = {0x66, 0x0F, 0x6F, 0x01};
    auto r5 = translate_bytes(x64, dqa_ld, ir::Arch::X64);
    ASSERT_EQ(r5.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r5.insn.op, ir::Op::Movaps);
    ASSERT_EQ(r5.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r5.insn.dst.reg, ir::Reg::Rax);
    ASSERT_EQ(r5.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r5.insn.src.mem.base, ir::Reg::Rcx);
    // 66 0F 7F 01: movdqa [rcx], xmm0 → (Movaps,S64, mem dst) = XmmStore
    const wvmp::u8 dqa_st[] = {0x66, 0x0F, 0x7F, 0x01};
    auto r6 = translate_bytes(x64, dqa_st, ir::Arch::X64);
    ASSERT_EQ(r6.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r6.insn.op, ir::Op::Movaps);
    ASSERT_EQ(r6.insn.dst.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r6.insn.dst.mem.base, ir::Reg::Rcx);
    ASSERT_EQ(r6.insn.src.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r6.insn.src.reg, ir::Reg::Rax);
    // F3 0F 6F 01 / F3 0F 7F 01: movdqu mem 双向 → (Movups,S64)
    const wvmp::u8 dqu_ld[] = {0xF3, 0x0F, 0x6F, 0x01};
    auto r7 = translate_bytes(x64, dqu_ld, ir::Arch::X64);
    ASSERT_EQ(r7.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r7.insn.op, ir::Op::Movups);
    ASSERT_EQ(r7.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r7.insn.src.mem.base, ir::Reg::Rcx);
    const wvmp::u8 dqu_st[] = {0xF3, 0x0F, 0x7F, 0x01};
    auto r8 = translate_bytes(x64, dqu_st, ir::Arch::X64);
    ASSERT_EQ(r8.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r8.insn.op, ir::Op::Movups);
    ASSERT_EQ(r8.insn.dst.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r8.insn.dst.mem.base, ir::Reg::Rcx);

    // ---- rip 形式 (408 通路): 66 0F 6F 05 disp32 → mem base=Rip ----
    const wvmp::u8 dqa_rip[] = {0x66, 0x0F, 0x6F, 0x05, 0x10, 0x00, 0x00, 0x00};
    auto r9 = translate_bytes(x64, dqa_rip, ir::Arch::X64);
    ASSERT_EQ(r9.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r9.insn.op, ir::Op::Movaps);
    ASSERT_EQ(r9.insn.src.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r9.insn.src.mem.base, ir::Reg::Rip);
    const wvmp::u8 dqu_rip[] = {0xF3, 0x0F, 0x7F, 0x05, 0x10, 0x00, 0x00, 0x00};
    auto r10 = translate_bytes(x64, dqu_rip, ir::Arch::X64);
    ASSERT_EQ(r10.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r10.insn.op, ir::Op::Movups);
    ASSERT_EQ(r10.insn.dst.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r10.insn.dst.mem.base, ir::Reg::Rip);
}

TEST_F(LifterTranslate, VexVmovdqaVmovdquMirror) {
    // B.2 VEX 镜像 (probe 实测 id: VMOVDQA 1028 / VMOVDQU 1033):
    // C5/C4 双编码 × dqa/dqu 双形式直折既有 Mov 通路 (426 D4 先例);
    // ymm 位宽闸 + xmm8..15 闸继承 translate_vex128。
    // C5 F9 6F C1: vmovdqa xmm0, xmm1 (C5 2B VEX) → (Movaps,S64)
    const wvmp::u8 vdqa_c5[] = {0xC5, 0xF9, 0x6F, 0xC1};
    auto r1 = translate_bytes(x64, vdqa_c5, ir::Arch::X64);
    ASSERT_EQ(r1.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r1.insn.op, ir::Op::Movaps);
    EXPECT_EQ(r1.insn.size, ir::Size::S64);
    EXPECT_EQ(r1.insn.dst.reg, ir::Reg::Rax);
    EXPECT_EQ(r1.insn.src.reg, ir::Reg::Rcx);
    // C4 E1 F9 6F C1: vmovdqa xmm0, xmm1 (C4 3B VEX, WIG)
    const wvmp::u8 vdqa_c4[] = {0xC4, 0xE1, 0xF9, 0x6F, 0xC1};
    auto r2 = translate_bytes(x64, vdqa_c4, ir::Arch::X64);
    ASSERT_EQ(r2.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r2.insn.op, ir::Op::Movaps);
    // C5 FA 6F C1: vmovdqu xmm0, xmm1 (C5, pp=F3) → (Movups,S64)
    const wvmp::u8 vdqu_c5[] = {0xC5, 0xFA, 0x6F, 0xC1};
    auto r3 = translate_bytes(x64, vdqu_c5, ir::Arch::X64);
    ASSERT_EQ(r3.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r3.insn.op, ir::Op::Movups);
    // C4 E1 7A 6F C1: vmovdqu xmm0, xmm1 (C4, pp=F3 — probe 修正: 3B VEX
    // byte3 pp=F3=10b → 0x7A, 误编 0x7F 带错误 mmmmm 不可解码)
    const wvmp::u8 vdqu_c4[] = {0xC4, 0xE1, 0x7A, 0x6F, 0xC1};
    auto r4 = translate_bytes(x64, vdqu_c4, ir::Arch::X64);
    ASSERT_EQ(r4.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r4.insn.op, ir::Op::Movups);
    // C5 F9 7F 01: vmovdqa [rcx], xmm0 (store 方向) → XmmStore 载体
    const wvmp::u8 vdqa_st[] = {0xC5, 0xF9, 0x7F, 0x01};
    auto r5 = translate_bytes(x64, vdqa_st, ir::Arch::X64);
    ASSERT_EQ(r5.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r5.insn.op, ir::Op::Movaps);
    ASSERT_EQ(r5.insn.dst.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r5.insn.dst.mem.base, ir::Reg::Rcx);
    // xmm8..15 闸: C4 41 F9 6F C0 (vmovdqa xmm8, xmm0 — probe 实测报
    // reg=130 xmm8) → xmm_idx 不可映射 → gate (426 §F.3 同口径)
    const wvmp::u8 vdqa_x8[] = {0xC4, 0x41, 0xF9, 0x6F, 0xC0};
    EXPECT_EQ(translate_bytes(x64, vdqa_x8, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
    // ymm 位宽闸: C5 FD 6F C1 (vmovdqa ymm0, ymm1 — op.size=32, 同 mnemonic
    // 覆盖 128/256 两宽, B.4 陷阱) → gate; vmovdqu ymm 同
    const wvmp::u8 vdqa_ymm[] = {0xC5, 0xFD, 0x6F, 0xC1};
    EXPECT_EQ(translate_bytes(x64, vdqa_ymm, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
    const wvmp::u8 vdqu_ymm[] = {0xC5, 0xFE, 0x6F, 0xC1};
    EXPECT_EQ(translate_bytes(x64, vdqu_ymm, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
    // EVEX 不入面 (独立 INS id 天然 gate, 426 §F.3 同款): 62 F1 7D 08 6F C1
    // (vmovdqa32 xmm0, xmm1 — probe 实测 id=1026) / vmovdqa64 id=1027
    const wvmp::u8 evex32[] = {0x62, 0xF1, 0x7D, 0x08, 0x6F, 0xC1};
    EXPECT_EQ(translate_bytes(x64, evex32, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
    const wvmp::u8 evex64[] = {0x62, 0xF1, 0xFD, 0x08, 0x6F, 0xC1};
    EXPECT_EQ(translate_bytes(x64, evex64, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
}

// =============================================================================
// MIT-434 (G8a): BMI1/2 折条款目 — andn/bzhi 零新 VmOp 折条 + rorx/shlx/
// sarx/shrx flagless 变体。全部字节 = probe_forms.obj ml64 v145 编码 +
// vendored capstone 5.0.7 反汇编双验 (2026-08-31)。
// =============================================================================

TEST_F(LifterTranslate, BmiAndnThreeAddressForms) {
    // andn 三操作数映射 (probe: op[1]=NOT 项 reg-only, op[2]=AND 项 r/m 可 mem):
    // C4 62 78 F2 C1 = andn r8d, eax, ecx — dst≠s1≠s2 → [Mov; Not] extra +
    // (And, r8, ecx) 主 insn。
    {
        const wvmp::u8 b[] = {0xC4, 0x62, 0x78, 0xF2, 0xC1};
        auto r = translate_bytes(x64, b, ir::Arch::X64);
        ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
        EXPECT_EQ(r.insn.op, ir::Op::And);
        EXPECT_EQ(r.insn.size, ir::Size::S32);
        EXPECT_TRUE(r.insn.updates_flags);
        ASSERT_EQ(static_cast<int>(r.insn.dst.reg), 8);
        ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
        EXPECT_EQ(static_cast<int>(r.insn.src.reg), 1);   // ecx (AND 项, Rcx=1)
        ASSERT_EQ(r.extra.size(), static_cast<size_t>(2));
        EXPECT_EQ(r.extra[0].op, ir::Op::Mov);            // [Mov r8, rax]
        EXPECT_EQ(r.extra[1].op, ir::Op::Not);            // [Not r8]
    }
    // d==s1: andn eax, eax, ecx — C4 E2 78 F2 C1 (ml64 t2.asm 编码实测) →
    // [Not eax] + And(eax, ecx)
    {
        const wvmp::u8 b[] = {0xC4, 0xE2, 0x78, 0xF2, 0xC1};
        auto r = translate_bytes(x64, b, ir::Arch::X64);
        ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
        EXPECT_EQ(r.insn.op, ir::Op::And);
        ASSERT_EQ(static_cast<int>(r.insn.dst.reg), 0);        // eax
        ASSERT_EQ(r.extra.size(), static_cast<size_t>(1));
        EXPECT_EQ(r.extra[0].op, ir::Op::Not);
    }
    // d==s2: andn eax, ecx, eax — C4 E2 70 F2 C0 (ml64 实测) → 载体
    // (Op::And, eax, src=ecx(NOT 项), src2=eax(AND 项)), extra 空。
    {
        const wvmp::u8 b[] = {0xC4, 0xE2, 0x70, 0xF2, 0xC0};
        auto r = translate_bytes(x64, b, ir::Arch::X64);
        ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
        EXPECT_EQ(r.insn.op, ir::Op::And);
        ASSERT_EQ(r.insn.src2.kind, ir::Operand::Kind::Reg);   // 载体判据
        EXPECT_EQ(static_cast<int>(r.insn.src2.reg), 0);       // eax (AND 项)
        EXPECT_EQ(static_cast<int>(r.insn.src.reg), 1);        // ecx (NOT 项)
        EXPECT_TRUE(r.extra.empty());
    }
    // S64 形: C4 62 F8 F2 C1 = andn r8, rax, rcx
    {
        const wvmp::u8 b[] = {0xC4, 0x62, 0xF8, 0xF2, 0xC1};
        auto r = translate_bytes(x64, b, ir::Arch::X64);
        ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
        EXPECT_EQ(r.insn.size, ir::Size::S64);
    }
    // s2=mem: C4 62 78 F2 44 24 30 = andn r8d, eax, [rsp+30h] — 主 And 直带
    // mem src (alu-binop src_mem 通道), extra = [Mov; Not]
    {
        const wvmp::u8 b[] = {0xC4, 0x62, 0x78, 0xF2, 0x44, 0x24, 0x30};
        auto r = translate_bytes(x64, b, ir::Arch::X64);
        ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
        ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
        ASSERT_EQ(r.extra.size(), static_cast<size_t>(2));
    }
}

TEST_F(LifterTranslate, BmiBzhiCarrierAllForms) {
    // bzhi: op[1]=value (r/m 可 mem), op[2]=index (reg-only) — 恒走载体
    // (Op::Sub, src2=Reg(index)); mask 需独占临时 + 边界 clamp/CF 补丁。
    // C4 62 70 F5 C0 = bzhi r8d, eax, ecx
    {
        const wvmp::u8 b[] = {0xC4, 0x62, 0x70, 0xF5, 0xC0};
        auto r = translate_bytes(x64, b, ir::Arch::X64);
        ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
        EXPECT_EQ(r.insn.op, ir::Op::Sub);                     // 载体
        EXPECT_EQ(r.insn.size, ir::Size::S32);
        EXPECT_TRUE(r.insn.updates_flags);
        ASSERT_EQ(static_cast<int>(r.insn.dst.reg), 8);
        ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);    // value=eax
        ASSERT_EQ(r.insn.src2.kind, ir::Operand::Kind::Reg);   // index=ecx
        EXPECT_EQ(static_cast<int>(r.insn.src2.reg), 1);
        EXPECT_TRUE(r.extra.empty());
    }
    // mem value: C4 62 70 F5 44 24 30 = bzhi r8d, [rsp+30h], ecx (probe 收)
    {
        const wvmp::u8 b[] = {0xC4, 0x62, 0x70, 0xF5, 0x44, 0x24, 0x30};
        auto r = translate_bytes(x64, b, ir::Arch::X64);
        ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
        ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Mem);
    }
    // S64: C4 62 F0 F5 C0 = bzhi r8, rax, rcx
    {
        const wvmp::u8 b[] = {0xC4, 0x62, 0xF0, 0xF5, 0xC0};
        auto r = translate_bytes(x64, b, ir::Arch::X64);
        ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
        EXPECT_EQ(r.insn.size, ir::Size::S64);
    }
}

TEST_F(LifterTranslate, BmiFlaglessShiftFamily) {
    // rorx/shlx/sarx/shrx — flagless 载体 (src2=Imm(22)), updates_flags=false
    // (五位全不写, probe raw 0x247 全程)。count 骑 src: Imm=rorx / Reg=shlx 族。
    {
        const wvmp::u8 rorx[] = {0xC4, 0x63, 0x7B, 0xF0, 0xC1, 0x07};
        auto r = translate_bytes(x64, rorx, ir::Arch::X64);
        ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
        EXPECT_EQ(r.insn.op, ir::Op::Ror);
        EXPECT_FALSE(r.insn.updates_flags);
        ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Imm);
        EXPECT_EQ(r.insn.src.imm, 7);
        ASSERT_EQ(r.insn.src2.kind, ir::Operand::Kind::Imm);
        EXPECT_EQ(r.insn.src2.imm, 22);                    // kFlagless
        ASSERT_EQ(r.extra.size(), static_cast<size_t>(1)); // d≠value → Mov
        EXPECT_EQ(r.extra[0].op, ir::Op::Mov);
    }
    {
        // C4 62 71 F7 C0 = shlx r8d, eax, ecx — cnt 骑 src=Reg (B.4)
        const wvmp::u8 shlx[] = {0xC4, 0x62, 0x71, 0xF7, 0xC0};
        auto r = translate_bytes(x64, shlx, ir::Arch::X64);
        ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
        EXPECT_EQ(r.insn.op, ir::Op::Shl);
        EXPECT_FALSE(r.insn.updates_flags);
        ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
        EXPECT_EQ(static_cast<int>(r.insn.src.reg), 1);    // ecx (cnt-in-reg)
        ASSERT_EQ(r.insn.src2.kind, ir::Operand::Kind::Imm);
        EXPECT_EQ(r.insn.src2.imm, 22);
        ASSERT_EQ(r.extra.size(), static_cast<size_t>(1));
    }
    {
        // C4 62 72 F7 C0 = sarx r8d, eax, ecx
        const wvmp::u8 sarx[] = {0xC4, 0x62, 0x72, 0xF7, 0xC0};
        auto r = translate_bytes(x64, sarx, ir::Arch::X64);
        ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
        EXPECT_EQ(r.insn.op, ir::Op::Sar);
        EXPECT_FALSE(r.insn.updates_flags);
        ASSERT_EQ(r.insn.src2.kind, ir::Operand::Kind::Imm);
        EXPECT_EQ(r.insn.src2.imm, 22);
    }
    {
        // C4 62 73 F7 C0 = shrx r8d, eax, ecx
        const wvmp::u8 shrx[] = {0xC4, 0x62, 0x73, 0xF7, 0xC0};
        auto r = translate_bytes(x64, shrx, ir::Arch::X64);
        ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
        EXPECT_EQ(r.insn.op, ir::Op::Shr);
        EXPECT_FALSE(r.insn.updates_flags);
    }
    {
        // mem value: C4 63 7B F0 44 24 30 07 = rorx r8d, [rsp+30h], 7 (probe 收)
        const wvmp::u8 rorxm[] = {0xC4, 0x63, 0x7B, 0xF0, 0x44, 0x24, 0x30, 0x07};
        auto r = translate_bytes(x64, rorxm, ir::Arch::X64);
        ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
        ASSERT_EQ(r.extra.size(), static_cast<size_t>(1));
        EXPECT_EQ(r.extra[0].op, ir::Op::Load);            // mem → Load 通路
    }
    {
        // S64: C4 63 FB F0 C1 07 = rorx r8, rax, 7
        const wvmp::u8 rorx64[] = {0xC4, 0x63, 0xFB, 0xF0, 0xC1, 0x07};
        auto r = translate_bytes(x64, rorx64, ir::Arch::X64);
        ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
        EXPECT_EQ(r.insn.size, ir::Size::S64);
    }
}

TEST_F(LifterTranslate, BmiNativeRorImmNotIntercepted) {
    // 陷阱② 回归钉: 原生 ror/shl 的 count 走 **src** (Imm/CL), src2 恒 None
    // → `ror eax,24` 不误拦 (is_bmi_flagless_marker 判据 = src2 存在性)。
    // C1 C8 18 = ror eax, 24
    {
        const wvmp::u8 b[] = {0xC1, 0xC8, 0x18};
        auto r = translate_bytes(x64, b, ir::Arch::X64);
        ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
        EXPECT_EQ(r.insn.op, ir::Op::Ror);
        EXPECT_TRUE(r.insn.updates_flags);                 // 原生 ror 写全量 (P1 partial)
        ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Imm);
        EXPECT_EQ(r.insn.src.imm, 24);
        EXPECT_EQ(r.insn.src2.kind, ir::Operand::Kind::None);  // 无载体
    }
    // D3 C8 = ror eax, cl — count=Reg(Rcx) 形同样不撞载体
    {
        const wvmp::u8 b[] = {0xD3, 0xC8};
        auto r = translate_bytes(x64, b, ir::Arch::X64);
        ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
        EXPECT_EQ(r.insn.op, ir::Op::Ror);
        ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Reg);
        EXPECT_EQ(r.insn.src2.kind, ir::Operand::Kind::None);
    }
    // 原生 and 与 22/任意值: 83 E0 16 = and eax, 22 — src2=None (ALU imm 在 src)
    {
        const wvmp::u8 b[] = {0x83, 0xE0, 0x16};
        auto r = translate_bytes(x64, b, ir::Arch::X64);
        ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
        EXPECT_EQ(r.insn.op, ir::Op::And);
        EXPECT_EQ(r.insn.src2.kind, ir::Operand::Kind::None);
    }
}

TEST_F(LifterTranslate, BmiAndnAndnpsNoCrossTalk) {
    // D4: andn (BMI, id 412) 与 andnps (SSE, id 414) 双正例并存零串扰 —
    // id 分裂 (432 亲验) 使 lifter case 层互染不可能。
    {
        const wvmp::u8 b[] = {0xC4, 0x62, 0x78, 0xF2, 0xC1};   // andn r8d, eax, ecx
        auto r = translate_bytes(x64, b, ir::Arch::X64);
        ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
        EXPECT_EQ(r.insn.op, ir::Op::And);                     // GP 域
        EXPECT_EQ(r.insn.size, ir::Size::S32);
    }
    {
        const wvmp::u8 b[] = {0x0F, 0x55, 0xC8};               // andnps xmm1, xmm0
        auto r = translate_bytes(x64, b, ir::Arch::X64);
        ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
        EXPECT_EQ(r.insn.op, ir::Op::Andps);                   // SSE 域
        EXPECT_EQ(r.insn.size, ir::Size::S64);
    }
}

TEST_F(LifterTranslate, BmiNegativeFamilyStillGated) {
    // 负例族 (D2 裁决: G8b/文档化 gate) 照旧 default → Unsupported:
    // mulx C4 62 33 F6 C0 / pdep C4 62 33 F5 C0 / pext C4 62 32 F5 C0 /
    // blsr C4 E2 38 F3 C8 / bextr C4 62 70 F7 C0 / blsi C4 E2 38 F3 D8 /
    // blsmsk C4 E2 38 F3 D0 — 字节 probe 实测 (probe_forms.obj)。
    const wvmp::u8 mulx[]   = {0xC4, 0x62, 0x33, 0xF6, 0xC0};
    const wvmp::u8 pdep[]   = {0xC4, 0x62, 0x33, 0xF5, 0xC0};
    const wvmp::u8 pext[]   = {0xC4, 0x62, 0x32, 0xF5, 0xC0};
    const wvmp::u8 blsr[]   = {0xC4, 0xE2, 0x38, 0xF3, 0xC8};
    const wvmp::u8 bextr[]  = {0xC4, 0x62, 0x70, 0xF7, 0xC0};
    const wvmp::u8 blsi[]   = {0xC4, 0xE2, 0x38, 0xF3, 0xD8};
    const wvmp::u8 blsmsk[] = {0xC4, 0xE2, 0x38, 0xF3, 0xD0};
    const std::span<const wvmp::u8> negs[] = {mulx, pdep, pext, blsr, bextr, blsi, blsmsk};
    for (const auto& b : negs) {
        auto r = translate_bytes(x64, b, ir::Arch::X64);
        EXPECT_EQ(r.status, lifter::TranslateStatus::Unsupported);
    }
}

// ==================== MIT-442 (X2a): 形级 fork 面双 arch 矩阵 ====================
//
// B.6 x86 纸面断言层 (X0 §F.3 证据分级: x86 侧 = 纸面级, x64 侧另有 E2E 全链
// 实证 wvmp_forkface_sample)。六形态: ① call [mem] ② plain 串形 ③ leave
// ④ cld/std (D5) ⑤ S16/p66 (含 66/67/段覆盖四位前缀互不误伤) ⑥ cwde/cbw。
// RetImm16LiftIntoSrc (438) 为本矩阵的格式先例。

TEST_F(LifterTranslate, LeaveLiftTwoInsnFold) {
    // ③ x64: C9 = leave → extra=[Mov{Rsp←Rbp, S64}] + main=Pop{Rbp, S64}
    const wvmp::u8 b[] = {0xC9};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Pop);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rbp);
    EXPECT_EQ(r.insn.size, ir::Size::S64);
    EXPECT_FALSE(r.insn.updates_flags);
    ASSERT_EQ(r.extra.size(), 1u);                    // 前置 Mov (426 extra 通道)
    EXPECT_EQ(r.extra[0].op, ir::Op::Mov);
    EXPECT_EQ(r.extra[0].size, ir::Size::S64);
    EXPECT_EQ(r.extra[0].dst.reg, ir::Reg::Rsp);
    EXPECT_EQ(r.extra[0].src.reg, ir::Reg::Rbp);
    EXPECT_EQ(r.extra[0].addr, r.insn.addr);          // 共享机器地址 (426 约定)

    // ③ x86 (CS_MODE_32, 纸面级): C9 → 同构 S32 对 (栈宽 B.2 分叉)
    auto r86 = translate_bytes(x86, b, ir::Arch::X86);
    ASSERT_EQ(r86.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r86.insn.op, ir::Op::Pop);
    EXPECT_EQ(r86.insn.size, ir::Size::S32);
    ASSERT_EQ(r86.extra.size(), 1u);
    EXPECT_EQ(r86.extra[0].op, ir::Op::Mov);
    EXPECT_EQ(r86.extra[0].size, ir::Size::S32);
}

TEST_F(LifterTranslate, CallMemLiftForkFace) {
    // ① x64: FF 55 F8 = call qword ptr [rbp-8] → Op::Call dst=Mem (409 Jmp 先例;
    //    translator 侧 D4 停手 gate, 见 test_translator CallMemGateNoteX3)
    const wvmp::u8 b[] = {0xFF, 0x55, 0xF8};
    auto r = translate_bytes(x64, b, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Call);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r.insn.dst.mem.base, ir::Reg::Rbp);
    EXPECT_EQ(r.insn.dst.mem.disp, -8);

    // ① x86 IAT 形: FF 15 78 56 34 12 = call [0x12345678] (abs disp32, 纸面级)
    const wvmp::u8 b86[] = {0xFF, 0x15, 0x78, 0x56, 0x34, 0x12};
    auto r86 = translate_bytes(x86, b86, ir::Arch::X86);
    ASSERT_EQ(r86.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r86.insn.op, ir::Op::Call);
    ASSERT_EQ(r86.insn.dst.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r86.insn.dst.mem.base, ir::Reg::Flags);  // 无 base → 哨兵
    EXPECT_EQ(r86.insn.dst.mem.disp, 0x12345678);

    // ① x86 reg-间接: FF 10 = call [eax] ([esp+..] 形同构)
    const wvmp::u8 b86b[] = {0xFF, 0x10};
    auto r86b = translate_bytes(x86, b86b, ir::Arch::X86);
    ASSERT_EQ(r86b.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r86b.insn.dst.kind, ir::Operand::Kind::Mem);
    EXPECT_EQ(r86b.insn.dst.mem.base, ir::Reg::Rax);

    // call reg (FF D0 = call rax) lift 钉: 白名单内, translator gate 归 X3
    const wvmp::u8 br[] = {0xFF, 0xD0};
    auto rr = translate_bytes(x64, br, ir::Arch::X64);
    ASSERT_EQ(rr.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(rr.insn.op, ir::Op::Call);
    ASSERT_EQ(rr.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(rr.insn.dst.reg, ir::Reg::Rax);
}

TEST_F(LifterTranslate, PlainStringLiftForkFace) {
    // ② x64 plain 单发形 → 域 23..27 (kStrPlainBase):
    // A5 = movsd (dword 单发) → (Mov, 23, S32)
    const wvmp::u8 md[] = {0xA5};
    auto r1 = translate_bytes(x64, md, ir::Arch::X64);
    ASSERT_EQ(r1.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r1.insn.op, ir::Op::Mov);
    ASSERT_EQ(r1.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r1.insn.src2.imm, 23);                  // plain movs
    EXPECT_EQ(r1.insn.size, ir::Size::S32);
    EXPECT_FALSE(r1.insn.updates_flags);              // movs 不写 flags
    // 48 A5 = movsq → S64 (REX 正常在前, 415 F3-in-front 缺陷不涉 plain)
    const wvmp::u8 mq[] = {0x48, 0xA5};
    auto r2 = translate_bytes(x64, mq, ir::Arch::X64);
    ASSERT_EQ(r2.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r2.insn.src2.imm, 23);
    EXPECT_EQ(r2.insn.size, ir::Size::S64);
    // AD = lodsd → (Mov, 27, S32); AC = lodsb → S8
    const wvmp::u8 ld[] = {0xAD};
    auto r3 = translate_bytes(x64, ld, ir::Arch::X64);
    ASSERT_EQ(r3.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r3.insn.src2.imm, 27);                  // plain lods
    EXPECT_EQ(r3.insn.size, ir::Size::S32);
    const wvmp::u8 lb[] = {0xAC};
    auto r4 = translate_bytes(x64, lb, ir::Arch::X64);
    ASSERT_EQ(r4.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r4.insn.src2.imm, 27);
    EXPECT_EQ(r4.insn.size, ir::Size::S8);
    // AE = scasd → (Mov, 25, S32) updates_flags=true (单发比较真写 flags)
    const wvmp::u8 sc[] = {0xAE};
    auto r5 = translate_bytes(x64, sc, ir::Arch::X64);
    ASSERT_EQ(r5.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r5.insn.src2.imm, 25);                  // plain scas
    EXPECT_TRUE(r5.insn.updates_flags);
    // AA = stosb → (Mov, 24, S8); A6 = cmpsb → (Mov, 26, S8) flags=true
    const wvmp::u8 st[] = {0xAA};
    auto r6 = translate_bytes(x64, st, ir::Arch::X64);
    ASSERT_EQ(r6.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r6.insn.src2.imm, 24);
    const wvmp::u8 cp[] = {0xA6};
    auto r7 = translate_bytes(x64, cp, ir::Arch::X64);
    ASSERT_EQ(r7.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r7.insn.src2.imm, 26);
    EXPECT_TRUE(r7.insn.updates_flags);

    // x86 (纸面级): A5/A4/AD 同构 S32/S8
    auto r86 = translate_bytes(x86, md, ir::Arch::X86);
    ASSERT_EQ(r86.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r86.insn.src2.imm, 23);
    EXPECT_EQ(r86.insn.size, ir::Size::S32);
    const wvmp::u8 mb86[] = {0xA4};
    auto r86b = translate_bytes(x86, mb86, ir::Arch::X86);
    ASSERT_EQ(r86b.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r86b.insn.src2.imm, 23);
    EXPECT_EQ(r86b.insn.size, ir::Size::S8);

    // 66 形单发 (66 A5 = movsw) 维持 gate (S16 串形 G3 残余, 位置判据双 arch)
    const wvmp::u8 sw[] = {0x66, 0xA5};
    EXPECT_EQ(translate_bytes(x86, sw, ir::Arch::X86).status,
              lifter::TranslateStatus::Unsupported);
}

TEST_F(LifterTranslate, CldNopStdGate) {
    // ④ D5: FC = cld → Op::Nop no-op 放行 (VM DF=0 假设一致, 415 口径)
    const wvmp::u8 c[] = {0xFC};
    auto r = translate_bytes(x64, c, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Nop);
    EXPECT_FALSE(r.insn.updates_flags);
    EXPECT_EQ(r.skipped_ranges.size(), 0u);
    auto r86 = translate_bytes(x86, c, ir::Arch::X86);
    ASSERT_EQ(r86.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r86.insn.op, ir::Op::Nop);

    // FD = std → 照旧 gate (DF←1 不可建模, 保守整函数原生; GAPS 清单登记)
    const wvmp::u8 s[] = {0xFD};
    auto rs = translate_bytes(x64, s, ir::Arch::X64);
    EXPECT_EQ(rs.status, lifter::TranslateStatus::Unsupported);
    ASSERT_EQ(rs.skipped_ranges.size(), 1u);
    auto rs86 = translate_bytes(x86, s, ir::Arch::X86);
    EXPECT_EQ(rs86.status, lifter::TranslateStatus::Unsupported);
}

TEST_F(LifterTranslate, CwdeCbwFoldForkFace) {
    // ⑥ x64: 98 = cwde (EAX←SX(AX)) → 两 IR: extra=[Movsx{Rax,Rax,S32,S16}]
    // + main=Mov{Rax,Rax,S32} (槽高位零扩展补偿, 见 translate_cwde 注)
    const wvmp::u8 w[] = {0x98};
    auto r = translate_bytes(x64, w, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    ASSERT_EQ(r.extra.size(), 1u);
    EXPECT_EQ(r.extra[0].op, ir::Op::Movsx);
    EXPECT_EQ(r.extra[0].size, ir::Size::S32);
    EXPECT_EQ(r.extra[0].src_size, ir::Size::S16);
    EXPECT_EQ(r.extra[0].dst.reg, ir::Reg::Rax);
    EXPECT_EQ(r.extra[0].src.reg, ir::Reg::Rax);
    EXPECT_EQ(r.insn.op, ir::Op::Mov);
    EXPECT_EQ(r.insn.size, ir::Size::S32);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);

    // ⑥ x86 (纸面级): 98 同构 (x86 主形)
    auto r86 = translate_bytes(x86, w, ir::Arch::X86);
    ASSERT_EQ(r86.status, lifter::TranslateStatus::Ok);
    ASSERT_EQ(r86.extra.size(), 1u);
    EXPECT_EQ(r86.extra[0].op, ir::Op::Movsx);
    EXPECT_EQ(r86.extra[0].src_size, ir::Size::S16);

    // ⑥ 66 98 = cbw (双 arch) → 载体 (Op::Movsx + src2=Imm(28)=kExtCbw)
    const wvmp::u8 cb[] = {0x66, 0x98};
    auto rc = translate_bytes(x64, cb, ir::Arch::X64);
    ASSERT_EQ(rc.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(rc.insn.op, ir::Op::Movsx);
    ASSERT_EQ(rc.insn.src2.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(rc.insn.src2.imm, 28);
    EXPECT_EQ(rc.insn.size, ir::Size::S16);
    EXPECT_EQ(rc.insn.src_size, ir::Size::S8);
    auto rc86 = translate_bytes(x86, cb, ir::Arch::X86);
    ASSERT_EQ(rc86.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(rc86.insn.src2.imm, 28);

    // cdqe (48 98) 既有通路不回踩 (404 归一 Movsxd)
    const wvmp::u8 cq[] = {0x48, 0x98};
    auto rq = translate_bytes(x64, cq, ir::Arch::X64);
    ASSERT_EQ(rq.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(rq.insn.op, ir::Op::Movsxd);

    // cwd (66 99) 维持 gate (dx = sx(ax), 无折条 — X0 §1.4 缺失行)
    const wvmp::u8 cw[] = {0x66, 0x99};
    EXPECT_EQ(translate_bytes(x64, cw, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
}

TEST_F(LifterTranslate, CdqX86LiftAndCqoBoundary) {
    // MIT-X7 批二: x86 cdq (99) 开面（Div face 必要条件——真实 idiv 代码
    // 恒有 cdq 前置）; cqo (48 99) x64 通路不回踩; cwd (66 99) 双 arch gate。
    // x86 cdq (99, 无 REX) → Op::Cdq S32。
    const wvmp::u8 c86[] = {0x99};
    auto r86 = translate_bytes(x86, c86, ir::Arch::X86);
    ASSERT_EQ(r86.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r86.insn.op, ir::Op::Cdq);
    EXPECT_EQ(r86.insn.size, ir::Size::S32);
    EXPECT_EQ(r86.insn.updates_flags, false);
    // x64 cdq (99) → Op::Cdq S32（404 既有通路）。
    auto r64 = translate_bytes(x64, c86, ir::Arch::X64);
    ASSERT_EQ(r64.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r64.insn.op, ir::Op::Cdq);
    EXPECT_EQ(r64.insn.size, ir::Size::S32);
    // x64 cqo (48 99, REX.W) → Op::Cdq S64（404 既有通路不回踩）。
    const wvmp::u8 cq[] = {0x48, 0x99};
    auto rq = translate_bytes(x64, cq, ir::Arch::X64);
    ASSERT_EQ(rq.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(rq.insn.op, ir::Op::Cdq);
    EXPECT_EQ(rq.insn.size, ir::Size::S64);
    // x86 cwd (66 99) 维持 gate（prefix[0]=0x66 → 66 前缀面 S16, 双 arch 同）。
    const wvmp::u8 cwd[] = {0x66, 0x99};
    EXPECT_EQ(translate_bytes(x86, cwd, ir::Arch::X86).status,
              lifter::TranslateStatus::Unsupported);
    // x86 idiv reg/mem 形 lift（Div face 主体）: F7 F9 = idiv ecx,
    // F7 39 = idiv dword ptr [ecx]。
    const wvmp::u8 iv[] = {0xF7, 0xF9};
    auto ri = translate_bytes(x86, iv, ir::Arch::X86);
    ASSERT_EQ(ri.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(ri.insn.op, ir::Op::Idiv);
    EXPECT_EQ(ri.insn.size, ir::Size::S32);
    EXPECT_EQ(ri.insn.updates_flags, true);
    const wvmp::u8 im[] = {0xF7, 0x39};
    auto rim = translate_bytes(x86, im, ir::Arch::X86);
    ASSERT_EQ(rim.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(rim.insn.op, ir::Op::Idiv);
    ASSERT_EQ(rim.insn.src.kind, ir::Operand::Kind::Mem);
    // x86 idiv S8/S16 防御: F6 F9 = idiv cl (S8, dividend=AX 不符拒)。
    const wvmp::u8 iv8[] = {0xF6, 0xF9};
    EXPECT_EQ(translate_bytes(x86, iv8, ir::Arch::X86).status,
              lifter::TranslateStatus::Unsupported);
}

TEST_F(LifterTranslate, AddressSize67Gate) {
    // B.4: 67 (prefix[3]) 显式 gate — 双 arch。x64: 67 8B 40 10 = mov eax,
    // [eax+10h] (地址截断 32 位, 平坦模型错址面); x86: 67 8B 00 = mov eax,
    // [bx+si] (16 位寻址, 编译器不产) — 两者均编译器不产形态, 保守拒。
    const wvmp::u8 b64[] = {0x67, 0x8B, 0x40, 0x10};
    const cs_insn* ci64 = decode_first(x64, b64);
    ASSERT_NE(ci64, nullptr);
    EXPECT_EQ(ci64->detail->x86.prefix[3], 0x67);     // 位置判据 probe 钉死
    auto r64 = lifter::translate_insn(*ci64, ir::Arch::X64);
    EXPECT_EQ(r64.status, lifter::TranslateStatus::Unsupported);
    ASSERT_EQ(r64.skipped_ranges.size(), 1u);

    const wvmp::u8 b86[] = {0x67, 0x8B, 0x00};
    const cs_insn* ci86 = decode_first(x86, b86);
    ASSERT_NE(ci86, nullptr);
    EXPECT_EQ(ci86->detail->x86.prefix[3], 0x67);
    auto r86 = lifter::translate_insn(*ci86, ir::Arch::X86);
    EXPECT_EQ(r86.status, lifter::TranslateStatus::Unsupported);

    // 66+67 组合 → 67 闸先拦 (prefix[3]); 67+段覆盖 → 本闸先拦 (互不误伤:
    // SEH 闸管 prefix[1], 本闸管 prefix[3], 位域正交)
    const wvmp::u8 b6667[] = {0x66, 0x67, 0x8B, 0xC1};
    auto r6667 = translate_bytes(x64, b6667, ir::Arch::X64);
    EXPECT_EQ(r6667.status, lifter::TranslateStatus::Unsupported);
    const wvmp::u8 bseg67[] = {0x64, 0x67, 0x8B, 0x05, 0x78, 0x56, 0x34, 0x12};
    auto rseg67 = translate_bytes(x64, bseg67, ir::Arch::X64);
    EXPECT_EQ(rseg67.status, lifter::TranslateStatus::Unsupported);
}

TEST_F(LifterTranslate, P66S16LiftAndPrefixPositionPin) {
    // ⑤ S16/p66: 66 落 prefix[2] (双 arch 同位 — B.4 位置判据实测重钉, X0 §7
    // 报法在案)。66 B8 05 00 = mov ax, 5 → (Mov, S16) 子寄存器折叠 + 宽度
    // 入 size (x86_translate.hpp 语义约定)。
    const wvmp::u8 b[] = {0x66, 0xB8, 0x05, 0x00};
    const cs_insn* ci = decode_first(x64, b);
    ASSERT_NE(ci, nullptr);
    const auto& x = ci->detail->x86;
    EXPECT_EQ(x.prefix[0], 0);
    EXPECT_EQ(x.prefix[1], 0);                        // 不触碰 SEH 闸 (438)
    EXPECT_EQ(x.prefix[2], 0x66);                     // 66 位置 = prefix[2]
    EXPECT_EQ(x.prefix[3], 0);                        // 不触碰 67 闸 (B.4)
    auto r = lifter::translate_insn(*ci, ir::Arch::X64);
    ASSERT_EQ(r.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r.insn.op, ir::Op::Mov);
    EXPECT_EQ(r.insn.size, ir::Size::S16);
    ASSERT_EQ(r.insn.dst.kind, ir::Operand::Kind::Reg);
    EXPECT_EQ(r.insn.dst.reg, ir::Reg::Rax);          // AX → Rax 折叠
    ASSERT_EQ(r.insn.src.kind, ir::Operand::Kind::Imm);
    EXPECT_EQ(r.insn.src.imm, 5);

    // x86 同位 (纸面级): 66 B8 05 00 → S16
    const cs_insn* ci86 = decode_first(x86, b);
    ASSERT_NE(ci86, nullptr);
    EXPECT_EQ(ci86->detail->x86.prefix[2], 0x66);
    auto r86 = lifter::translate_insn(*ci86, ir::Arch::X86);
    ASSERT_EQ(r86.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(r86.insn.size, ir::Size::S16);

    // S16 ALU: 66 03 C3 = add ax, bx → (Add, S16)
    const wvmp::u8 ba[] = {0x66, 0x03, 0xC3};
    auto ra = translate_bytes(x64, ba, ir::Arch::X64);
    ASSERT_EQ(ra.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(ra.insn.op, ir::Op::Add);
    EXPECT_EQ(ra.insn.size, ir::Size::S16);

    // S16 访存: 66 89 45 FA = mov [rbp-6], ax → (Store, S16)
    const wvmp::u8 bs[] = {0x66, 0x89, 0x45, 0xFA};
    auto rbs = translate_bytes(x64, bs, ir::Arch::X64);
    ASSERT_EQ(rbs.status, lifter::TranslateStatus::Ok);
    EXPECT_EQ(rbs.insn.op, ir::Op::Store);
    EXPECT_EQ(rbs.insn.size, ir::Size::S16);

    // 互不误伤 (B.4): 66+段覆盖 → SEH 闸赢 (prefix[1], 438 判据不变);
    // 66+rep 串 → S16 串形砍面 (G3 残余); 66+lock → lock 闸 (D4 仅 F0 独前缀)
    const wvmp::u8 bseg[] = {0x66, 0x64, 0x8B, 0x05, 0x78, 0x56, 0x34, 0x12};
    const cs_insn* ciseg = decode_first(x64, bseg);
    ASSERT_NE(ciseg, nullptr);
    EXPECT_EQ(ciseg->detail->x86.prefix[1], 0x64);    // 段覆盖仍 prefix[1]
    EXPECT_EQ(ciseg->detail->x86.prefix[2], 0x66);    // 66 仍 prefix[2]
    EXPECT_EQ(lifter::translate_insn(*ciseg, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);  // SEH 闸优先, 无 66 误放
    const wvmp::u8 brep[] = {0x66, 0xF3, 0xA5};
    EXPECT_EQ(translate_bytes(x64, brep, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
    const wvmp::u8 blk[] = {0x66, 0xF0, 0x0F, 0xB1, 0x06};
    EXPECT_EQ(translate_bytes(x64, blk, ir::Arch::X64).status,
              lifter::TranslateStatus::Unsupported);
}

} // namespace
