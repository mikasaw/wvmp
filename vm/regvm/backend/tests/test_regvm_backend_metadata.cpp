// MIT-380：regvm 后端 LiftMetadata 按 begin_rva 匹配的单元测试。
//
// 覆盖三个场景：
//   1. MetadataMatchByBeginRva      —— 多函数 + 平行 metadata, 各函数只被
//                                      自己的 skipped_ranges 拦截（gate 不
//                                      跨函数粘滞）；
//   2. MetadataNotFoundFallsBackTo  —— 平行关系破坏（槽在但无元素）时保守
//      ToConservative                  兜底, 保持原生执行;
//   3. FrontBugRegression           —— 回归 v1 的 meta_list->front() 退化:
//                                      只有末位函数缺 IR 字节、乱序调用时,
//                                      每个函数仍精确命中自己的 metadata。

#include "wvmp/passes/lifter/lift_metadata.hpp"
#include "wvmp/regvm/backend/regvm_backend.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

namespace {

namespace ir = wvmp::ir;
using wvmp::passes::lifter::kLiftedMetadata;
using wvmp::passes::lifter::LiftMetadata;
using wvmp::regvm::make_regvm;

// 构造 blocks 为空的函数区：translate_function 对空函数产出非空字节码
// （至少一条 Halt）且 notes 为空——恰作"未被 gate 放行"的判定信号。
ir::FunctionRegion MakeFn(const std::string& name, wvmp::u64 begin_rva) {
    ir::FunctionRegion fn;
    fn.name = name;
    fn.arch = ir::Arch::X64;
    fn.begin_rva = begin_rva;
    fn.end_rva = begin_rva + 0x10;
    return fn;
}

void SetMetadata(wvmp::ProtectionContext& ctx, std::vector<LiftMetadata> metas) {
    ctx.slot<std::vector<LiftMetadata>>(kLiftedMetadata) = std::move(metas);
}

// 经 kLastTranslateNotes 槽取最近一次 compile 的 notes（契约见
// regvm_backend.hpp：每次 compile 无条件覆写）。
std::vector<std::string> LastNotes(const wvmp::ProtectionContext& ctx) {
    const auto* notes =
        ctx.find_slot<std::vector<std::string>>(wvmp::regvm::kLastTranslateNotes);
    return notes == nullptr ? std::vector<std::string>{} : *notes;
}

} // namespace

// Test 1（沿用 GateNotStickyAcrossFunctions 的"gate 不跨函数粘滞"思路）：
// 3 函数 + 3 平行 metadata，仅 metadata[1].skipped_ranges 非空 → 编译第 2 个
// 函数时 notes 非空且不产字节码；前后两个正常翻译。
TEST(RegVmBackendMetadata, MetadataMatchByBeginRva) {
    wvmp::ProtectionContext ctx;
    ctx.functions = {MakeFn("f0", 0x1000), MakeFn("f1", 0x1100),
                     MakeFn("f2", 0x1200)};
    LiftMetadata m0, m1, m2;
    m1.skipped_ranges = {{0x1108, 4}};
    SetMetadata(ctx, {m0, m1, m2});

    auto backend = make_regvm();
    ASSERT_NE(backend, nullptr);

    const bool expect_gate[] = {false, true, false};
    for (size_t i = 0; i < ctx.functions.size(); ++i) {
        const wvmp::vm::VmProgram prog = backend->compile(ctx.functions[i], ctx);
        const std::vector<std::string> notes = LastNotes(ctx);
        EXPECT_EQ(!notes.empty(), expect_gate[i]) << "函数下标 " << i;
        EXPECT_EQ(prog.bytecode.empty(), expect_gate[i]) << "函数下标 " << i;
    }

    // 被拦截函数的 note 触发 C1 gate 关键字，且字节码保持为空（未翻译）。
    const wvmp::vm::VmProgram prog1 = backend->compile(ctx.functions[1], ctx);
    const std::vector<std::string> notes1 = LastNotes(ctx);
    ASSERT_EQ(notes1.size(), 1u);
    EXPECT_NE(notes1[0].find("C1 gate"), std::string::npos);
    EXPECT_TRUE(prog1.bytecode.empty());
}

// Test 2：槽存在但 metadata 列表为空（平行关系破坏）→ helper 返回 nullptr
// → 保守兜底：notes 带"无对应 LiftMetadata / 保守兜底"，不调用翻译器。
TEST(RegVmBackendMetadata, MetadataNotFoundFallsBackToConservative) {
    wvmp::ProtectionContext ctx;
    ctx.functions = {MakeFn("solo", 0x2000)};
    SetMetadata(ctx, {});

    auto backend = make_regvm();
    ASSERT_NE(backend, nullptr);
    const wvmp::vm::VmProgram prog = backend->compile(ctx.functions[0], ctx);

    const std::vector<std::string> notes = LastNotes(ctx);
    ASSERT_EQ(notes.size(), 1u);
    EXPECT_NE(notes[0].find("无对应 LiftMetadata"), std::string::npos);
    EXPECT_NE(notes[0].find("保守兜底"), std::string::npos);
    EXPECT_TRUE(prog.bytecode.empty()); // 未翻译, 保持原生执行
}

// Test 3：回归 front() 退化。5 函数只有末位有 skipped_ranges（对应真实场景
// sha256 marker 位于列表尾部）；乱序调用的每一个函数都必须按自身 begin_rva
// 命中自己的 metadata。退化版会让所有函数都读 metadata[0]（空）→ 全部错误
// 放行，末位函数被 stub_link 覆写出行为错误的 PE。
TEST(RegVmBackendMetadata, FrontBugRegression) {
    wvmp::ProtectionContext ctx;
    for (int i = 0; i < 5; ++i)
        ctx.functions.push_back(MakeFn("fn" + std::to_string(i),
                                       0x3000 + 0x100 * static_cast<wvmp::u64>(i)));
    std::vector<LiftMetadata> metas(ctx.functions.size());
    metas.back().skipped_ranges = {{0x3408, 8}}; // 仅末位函数 IR 缺字节
    SetMetadata(ctx, std::move(metas));

    auto backend = make_regvm();
    ASSERT_NE(backend, nullptr);

    const size_t order[] = {2, 4, 0, 3, 1}; // 乱序: 结果与调用顺序无关
    for (const size_t idx : order) {
        const bool gated = idx == 4;
        const wvmp::vm::VmProgram prog = backend->compile(ctx.functions[idx], ctx);
        const std::vector<std::string> notes = LastNotes(ctx);
        EXPECT_EQ(!notes.empty(), gated) << "函数下标 " << idx;
        EXPECT_EQ(prog.bytecode.empty(), gated) << "函数下标 " << idx;
    }

    // 末位函数的拦截 note 同样走 C1 gate 路径。
    const wvmp::vm::VmProgram prog4 = backend->compile(ctx.functions[4], ctx);
    const std::vector<std::string> notes4 = LastNotes(ctx);
    ASSERT_EQ(notes4.size(), 1u);
    EXPECT_NE(notes4[0].find("C1 gate"), std::string::npos);
    EXPECT_TRUE(prog4.bytecode.empty());
}
