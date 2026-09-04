// MIT-459 (mutate-v1)：mutate pass 单测——确定性、异 seed 差异、插入面
// 不变量（v1 只发 Nop：kEnableJunkMov=false 收口裁定，junk-Mov 挂账 GAPS；
// 本文件的甄别/复算机制按通用面编写，junk-Mov 翻案时直接可用）。

#include "wvmp/passes/mutate/mutate_pass.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/protect_levels.hpp"
#include "wvmp/ir/insn.hpp"
#include "wvmp/ir/operand.hpp"
#include "wvmp/ir/region.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

namespace {

using wvmp::ir::BasicBlock;
using wvmp::ir::FunctionRegion;
using wvmp::ir::Insn;
using wvmp::ir::Operand;
using wvmp::ir::Reg;
using wvmp::ir::Size;
using wvmp::i64;

Insn mov_rr(Reg d, Reg s) {
    Insn i;
    i.op = wvmp::ir::Op::Mov;
    i.size = Size::S64;
    i.dst = Operand::reg_(d);
    i.src = Operand::reg_(s);
    return i;
}
Insn mov_ri(Reg d, i64 imm) {
    Insn i;
    i.op = wvmp::ir::Op::Mov;
    i.size = Size::S64;
    i.dst = Operand::reg_(d);
    i.src = Operand::imm_(imm);
    return i;
}
Insn add_rr(Reg d, Reg s) {
    Insn i;
    i.op = wvmp::ir::Op::Add;
    i.size = Size::S64;
    i.dst = Operand::reg_(d);
    i.src = Operand::reg_(s);
    i.updates_flags = true;
    return i;
}

FunctionRegion make_fn(const std::string& name, const std::vector<Insn>& insns,
                       wvmp::u64 base) {
    FunctionRegion fn;
    fn.name = name;
    fn.arch = wvmp::ir::Arch::X64;
    fn.begin_rva = base;
    fn.end_rva = base + 0x100;
    BasicBlock b;
    b.addr = base;
    wvmp::u64 addr = base;
    for (const Insn& i : insns) {
        Insn copy = i;
        copy.addr = addr;
        addr += 4;
        b.insns.push_back(std::move(copy));
    }
    fn.blocks.push_back(std::move(b));
    return fn;
}

// 确定性测试程序：寄存器活性链（每条读前一条的写），N 个边界。
std::vector<Insn> chain_program(int n) {
    std::vector<Insn> out;
    out.push_back(mov_ri(Reg::Rax, 1));
    for (int i = 0; i < n; ++i) {
        const Reg d = static_cast<Reg>(1 + (i % 6));  // rcx..rdi 轮转
        const Reg s = i == 0 ? Reg::Rax : static_cast<Reg>(1 + ((i - 1) % 6));
        if (i % 2 == 0)
            out.push_back(add_rr(d, s));
        else
            out.push_back(mov_rr(d, s));
    }
    return out;
}

// 序列化 IR 供比对（op/size/dst/src 粗粒度指纹）。
std::string fingerprint(const FunctionRegion& fn) {
    std::string out;
    for (const auto& b : fn.blocks)
        for (const auto& i : b.insns) {
            out += static_cast<char>(i.op);
            out += static_cast<char>(i.size);
            out += static_cast<char>(i.dst.kind);
            out += static_cast<char>(i.src.kind);
            out += static_cast<char>(i.dst.reg);
            if (i.src.kind == wvmp::ir::Operand::Kind::Imm)
                out += std::to_string(i.src.imm) + ";";
        }
    return out;
}

} // namespace

TEST(MutatePass, DeterministicSameSeed) {
    const auto prog = chain_program(20);
    wvmp::ProtectionContext a, b;
    a.seed = b.seed = 12345;
    a.functions.push_back(make_fn("f", prog, 0x1000));
    b.functions.push_back(make_fn("f", prog, 0x1000));
    wvmp::passes::MutatePass pa, pb;
    pa.run(a);
    pb.run(b);
    EXPECT_EQ(fingerprint(a.functions[0]), fingerprint(b.functions[0]));
}

TEST(MutatePass, DifferentSeedDifferentMutation) {
    // 概率性断言：41 边界 × P(nop)=0.10，两 seed 同时零插入的概率
    // ≈ 0.9^80 ≈ 0.03%（确定性固定——若换密度常数后偶发相等，换种子对）。
    const auto prog = chain_program(40);
    wvmp::ProtectionContext a, b;
    a.seed = 1;
    b.seed = 99999;
    a.functions.push_back(make_fn("f", prog, 0x1000));
    b.functions.push_back(make_fn("f", prog, 0x1000));
    wvmp::passes::MutatePass pa, pb;
    pa.run(a);
    pb.run(b);
    EXPECT_NE(fingerprint(a.functions[0]), fingerprint(b.functions[0]));
}

TEST(MutatePass, InsertionSurfaceInvariant) {
    // 插入面不变量（对通用插入物成立；v1 实际只产 Nop）：
    //   - 原始序列双指针匹配 = 原序完整保留（零语义删改）；
    //   - 插入物 updates_flags=false、dst ≠ rsp；
    //   - 插入 Mov 的 dst 在其边界处（仅按真实指令计算）活性为 0。
    const auto prog = chain_program(40);
    wvmp::ProtectionContext ctx;
    ctx.seed = 777;
    std::vector<Insn> orig = prog;
    {
        wvmp::u64 a = 0x1000;
        for (auto& i : orig) {
            i.addr = a;
            a += 4;
        }
    }
    ctx.functions.push_back(make_fn("f", prog, 0x1000));
    wvmp::passes::MutatePass pass;
    pass.run(ctx);
    const auto& block = ctx.functions[0].blocks[0];
    ASSERT_GT(block.insns.size(), orig.size());  // 确实插入了垃圾

    // 前向双指针：匹配原始指令（op/addr/操作数全比），不匹配者 = 插入物。
    std::vector<char> is_junk(block.insns.size(), 0);
    {
        size_t j = 0;
        for (size_t i = 0; i < block.insns.size(); ++i) {
            const Insn& m = block.insns[i];
            const bool matches =
                j < orig.size() && m.op == orig[j].op && m.addr == orig[j].addr &&
                m.dst.kind == orig[j].dst.kind && m.dst.reg == orig[j].dst.reg &&
                m.src.kind == orig[j].src.kind &&
                (m.src.kind != wvmp::ir::Operand::Kind::Imm || m.src.imm == orig[j].src.imm);
            if (matches)
                ++j;
            else
                is_junk[i] = 1;
        }
        EXPECT_EQ(j, orig.size());  // 原始序列原序完整保留
    }

    // 反向扫描（插入物透明）：junk Mov 的 dst 在其边界处必须不活。
    std::vector<char> live(static_cast<size_t>(Reg::Count), 1);
    for (size_t idx = block.insns.size(); idx-- > 0;) {
        const Insn& i = block.insns[idx];
        if (is_junk[idx]) {
            EXPECT_FALSE(i.updates_flags);
            ASSERT_TRUE(i.op == wvmp::ir::Op::Nop || i.op == wvmp::ir::Op::Mov);
            if (i.op == wvmp::ir::Op::Mov) {
                ASSERT_EQ(i.src.kind, wvmp::ir::Operand::Kind::Imm);
                EXPECT_NE(i.dst.reg, Reg::Rsp);
                EXPECT_EQ(live[static_cast<size_t>(i.dst.reg)], 0)
                    << "junk Mov 写入边界处活性寄存器 (slot "
                    << static_cast<int>(i.dst.reg) << ")";
            } else {
                EXPECT_EQ(i.dst.kind, wvmp::ir::Operand::Kind::None);  // Nop 无操作数
            }
            continue;  // 插入物透明：不更新 live
        }
        if (i.src.kind == wvmp::ir::Operand::Kind::Reg)
            live[static_cast<size_t>(i.src.reg)] = 1;
        if (i.dst.kind == wvmp::ir::Operand::Kind::Reg) {
            if (i.updates_flags)  // RMW（Add 等）：目的也是读
                live[static_cast<size_t>(i.dst.reg)] = 1;
            if (i.op == wvmp::ir::Op::Mov)  // 纯定义杀
                live[static_cast<size_t>(i.dst.reg)] = 0;
        }
    }
}

TEST(MutatePass, LevelNoneSkipped) {
    // 档位 none 的函数不变异；默认档函数正常变异（30 边界 × 0.10 ≈ 确定性
    // 至少 1 插入；若密度调整后偶发为零，增大程序规模）。
    const auto prog_a = chain_program(80);
    const auto prog_b = chain_program(80);
    wvmp::ProtectionContext ctx;
    ctx.seed = 314;
    ctx.functions.push_back(make_fn("off", prog_a, 0x1000));
    ctx.functions.push_back(make_fn("on", prog_b, 0x2000));
    wvmp::ProtectRules rules;
    wvmp::FunctionProtectRule rule;
    rule.has_rva = true;
    rule.rva = 0x1000;
    rule.level = wvmp::ProtectLevel::None;
    rules.functions.push_back(rule);
    ctx.slot<wvmp::ProtectRules>(wvmp::kProtectRules) = rules;

    const std::string before_off = fingerprint(ctx.functions[0]);
    const std::string before_on = fingerprint(ctx.functions[1]);
    wvmp::passes::MutatePass pass;
    pass.run(ctx);
    EXPECT_EQ(fingerprint(ctx.functions[0]), before_off);  // none → 原样
    EXPECT_NE(fingerprint(ctx.functions[1]), before_on);   // 默认档 → 变异
}

TEST(MutatePass, EmptyBlocksNoop) {
    wvmp::ProtectionContext ctx;
    FunctionRegion fn = make_fn("empty", {}, 0x1000);
    ctx.functions.push_back(std::move(fn));
    wvmp::passes::MutatePass pass;
    pass.run(ctx);
    // 空块不插任何指令、零 Error。
    ASSERT_FALSE(ctx.functions[0].blocks.empty());
    EXPECT_TRUE(ctx.functions[0].blocks[0].insns.empty());
    EXPECT_FALSE(ctx.diag.has_errors());
}
