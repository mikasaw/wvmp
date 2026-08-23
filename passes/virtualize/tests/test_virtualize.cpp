// M2-1：后端工厂注册 + virtualize pass 接线测试。

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/phase.hpp"
#include "wvmp/ir/insn.hpp"
#include "wvmp/ir/operand.hpp"
#include "wvmp/ir/region.hpp"
#include "wvmp/passes/virtualize/virtualize_pass.hpp"
#include "wvmp/regvm/backend/regvm_backend.hpp"
#include "wvmp/vm/backend.hpp"

#include <gtest/gtest.h>

#include <cstring>

namespace {
namespace ir = wvmp::ir;

ir::Insn mk_bin(ir::Op op, ir::Reg dst, ir::Reg src) {
    ir::Insn i;
    i.op = op;
    i.size = ir::Size::S64;
    i.dst = ir::Operand::reg_(dst);
    i.src = ir::Operand::reg_(src);
    i.updates_flags = true;
    return i;
}
ir::Insn mk_mov_imm(ir::Reg dst, wvmp::u64 v) {
    ir::Insn i;
    i.op = ir::Op::Mov;
    i.size = ir::Size::S64;
    i.dst = ir::Operand::reg_(dst);
    i.src = ir::Operand::imm_(static_cast<wvmp::i64>(v));
    return i;
}

// 两个基本块：块 0 以 jne 结尾（回跳本块模拟循环），块 1 收尾。
ir::FunctionRegion make_sample_function(const std::string& name) {
    ir::FunctionRegion fn;
    fn.name = name;
    fn.arch = ir::Arch::X64;
    fn.begin_rva = 0x1000;
    fn.end_rva = 0x1100;

    ir::BasicBlock b0;
    b0.addr = 0x1000;
    b0.insns.push_back(mk_mov_imm(ir::Reg::Rax, 0));        // sum = 0
    b0.insns.push_back(mk_mov_imm(ir::Reg::Rcx, 10));       // i = 10
    ir::Insn add;
    add.op = ir::Op::Add; add.size = ir::Size::S64;
    add.dst = ir::Operand::reg_(ir::Reg::Rax);
    add.src = ir::Operand::reg_(ir::Reg::Rcx);
    add.updates_flags = true;
    b0.insns.push_back(add);                                 // sum += i
    ir::Insn dec = mk_bin(ir::Op::Dec, ir::Reg::Rcx, ir::Reg::Rcx);
    b0.insns.push_back(dec);                                 // i--
    ir::Insn jne;
    jne.op = ir::Op::Jcc; jne.size = ir::Size::S64; jne.cond = ir::Cond::Ne;
    jne.dst = ir::Operand::imm_(0);                          // 目标块序号由 lifter 语义给地址，
    jne.updates_flags = false;                               // 翻译器按块地址解析
    b0.insns.push_back(jne);
    b0.succs = {0x1000, 0x1080};

    ir::BasicBlock b1;
    b1.addr = 0x1080;
    b1.insns.push_back(mk_bin(ir::Op::Ret, ir::Reg::Rax, ir::Reg::Rax));
    b1.succs = {};

    fn.blocks = {std::move(b0), std::move(b1)};
    return fn;
}

TEST(BackendFactory, RegVmRegisteredAndUnknownIsNull) {
    // 测试链接了 wvmp_pass_virtualize（内含 make_regvm 锚点），注册必已发生。
    EXPECT_NE(wvmp::vm::create_backend("regvm"), nullptr);
    EXPECT_EQ(wvmp::vm::create_backend("no_such_backend"), nullptr);

    auto backend = wvmp::vm::create_backend("regvm");
    EXPECT_EQ(backend->name(), "regvm");
}

TEST(VirtualizePass, ContractSurface) {
    wvmp::passes::VirtualizePass p;
    EXPECT_EQ(p.name(), "virtualize");
    EXPECT_EQ(p.phase(), wvmp::Phase::Transform);
    bool req = false, prov = false;
    for (auto k : p.requires_keys()) req = req || k == wvmp::kLiftedIr;
    for (auto k : p.provides_keys()) prov = prov || k == wvmp::kVmProgram;
    EXPECT_TRUE(req);
    EXPECT_TRUE(prov);
}

TEST(VirtualizePass, CompilesLiftedFunctionsIntoSlot) {
    wvmp::ProtectionContext ctx;
    ctx.functions.push_back(make_sample_function("sample"));
    ctx.functions.push_back(make_sample_function("another"));

    wvmp::passes::VirtualizePass pass;
    pass.run(ctx);

    const auto* programs = ctx.find_slot<std::vector<wvmp::vm::VmProgram>>(wvmp::kVmProgram);
    ASSERT_NE(programs, nullptr);
    ASSERT_EQ(programs->size(), static_cast<size_t>(2));

    // 每个程序都是合法 blob：magic "WVMP" + 非空指令流。
    for (const auto& p : *programs) {
        ASSERT_GE(p.bytecode.size(), static_cast<size_t>(32));
        EXPECT_EQ(std::memcmp(p.bytecode.data(), "WVMP", 4), 0);
        // 头 32 字节后是 8 字节对齐的指令流。
        EXPECT_EQ((p.bytecode.size() - 32) % 8, static_cast<size_t>(0));
        EXPECT_GT(p.bytecode.size(), static_cast<size_t>(32));  // 至少一条指令
    }
    EXPECT_FALSE(ctx.diag.has_errors());
}

TEST(VirtualizePass, SkipsUnliftedAndWarnsWhenNothingVirtualized) {
    wvmp::ProtectionContext ctx;
    ir::FunctionRegion empty;
    empty.name = "empty";
    empty.blocks = {};
    ctx.functions.push_back(std::move(empty));

    wvmp::passes::VirtualizePass pass;
    pass.run(ctx);

    const auto* programs = ctx.find_slot<std::vector<wvmp::vm::VmProgram>>(wvmp::kVmProgram);
    ASSERT_NE(programs, nullptr);
    EXPECT_TRUE(programs->empty());
    // 一条 Note（跳过）+ 一条 Warning（无函数虚拟化），无 Error。
    EXPECT_FALSE(ctx.diag.has_errors());
    bool has_warn = false;
    for (const auto& d : ctx.diag.items())
        if (d.severity == wvmp::Severity::Warning) has_warn = true;
    EXPECT_TRUE(has_warn);
}

} // namespace
