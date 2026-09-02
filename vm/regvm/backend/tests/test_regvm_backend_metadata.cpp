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

// ==================== MIT-453 (X5c) B.3: 上界 lambda 病态形防护 ====================
//
// F1 回退链 (regvm_backend.cpp pdata_empty 分支) 的定义域与保守性钉:
//   ub = min{fr.begin_rva > begin_rva} (不依赖排序), 无后继 → 所在节节尾
//   (VirtualAddress + VirtualSize), 节尾兼作收紧上界 (cap)。pe==nullptr /
//   无 .text / 回跳检出 / 目标越节尾一律 nullopt → C1 gate (保守正确)。
// 观测面: ExitNative 站点 note 经过滤槽转 diag (notes 空 = 放行),
//   gate note "跳转目标块未找到" 留在 kLastTranslateNotes (notes 非空)。

#include "wvmp/passes/pe_loader/pe_image.hpp"
#include "wvmp/framework/keys.hpp"

namespace {

using wvmp::kPeImage;
using wvmp::passes::PeImage;
using wvmp::passes::SectionInfo;

// 带 end_rva 的函数区 (Jmp Imm 越区单条, 无栈操作 → 栈深 walk d=0)。
ir::FunctionRegion MakeFnX(const std::string& name, wvmp::u64 begin_rva,
                           wvmp::u64 end_rva) {
    ir::Insn jmp;
    jmp.op = ir::Op::Jmp;
    jmp.size = ir::Size::S32;
    jmp.dst = ir::Operand::imm_(static_cast<wvmp::i64>(end_rva + 0x40));
    ir::BasicBlock b;
    b.addr = begin_rva;
    b.insns = {jmp};
    ir::FunctionRegion fn;
    fn.name = name;
    fn.arch = ir::Arch::X86;
    fn.begin_rva = begin_rva;
    fn.end_rva = end_rva;
    fn.blocks = {b};
    return fn;
}

PeImage MakeX86Pe() {
    PeImage pe;
    pe.pdata_empty = true;  // x86 PE32: DataDirectory[3] = 0/0
    SectionInfo text;
    text.name = ".text";
    text.characteristics = 0x60000020;
    text.virtual_addr = 0x1000;
    text.virtual_size = 0x3000;  // 节尾 = 0x4000
    text.raw_size = 0x3000;
    text.raw_ptr = 0x400;
    pe.sections = {text};
    return pe;
}

// F1 回退链放行判据: notes 空 (exit-native note 已过滤进 diag) 且产码非空。
::testing::AssertionResult F1ExitEmitted(wvmp::ProtectionContext& ctx,
                                         ir::FunctionRegion fn) {
    auto backend = make_regvm();
    const wvmp::vm::VmProgram prog = backend->compile(fn, ctx);
    const std::vector<std::string> notes = LastNotes(ctx);
    if (!notes.empty())
        return ::testing::AssertionFailure()
               << "期望 ExitNative 放行 (notes 空), 实得 gate note: "
               << (notes.empty() ? std::string("<none>") : notes.front());
    if (prog.bytecode.empty())
        return ::testing::AssertionFailure() << "期望产码非空, 实得空";
    return ::testing::AssertionSuccess();
}

// 保守 gate 判据: notes 含 "跳转目标块未找到"。
::testing::AssertionResult F1Gated(wvmp::ProtectionContext& ctx,
                                   ir::FunctionRegion fn) {
    auto backend = make_regvm();
    backend->compile(fn, ctx);
    const std::vector<std::string> notes = LastNotes(ctx);
    for (const auto& n : notes)
        if (n.find("跳转目标块未找到") != std::string::npos)
            return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure()
           << "期望 C1 gate note, 实得 notes 数=" << notes.size();
}

} // namespace

// 病态形 ①: 下一区域 begin 兜底 (常规面)——target 落本函数尾 gap
// [end_rva, next_begin) → ExitNative 放行 (wvmpTest 17 处同形)。
TEST(RegVmBackendUpperBound, PdataEmptyNextRegionBeginExits) {
    wvmp::ProtectionContext ctx;
    ctx.slot<PeImage>(kPeImage) = MakeX86Pe();
    ctx.functions = {MakeFnX("f0", 0x1000, 0x1010),
                     MakeFnX("f1", 0x2000, 0x2010)};
    EXPECT_TRUE(F1ExitEmitted(ctx, ctx.functions[0]));  // 0x1050 < 0x2000
}

// 病态形 ② (X5c D1 核心): 区域表仅自身 (无后继) → .text 节尾兜底,
// target < 节尾 → ExitNative 放行 (wvmpTest 末区 0xC972 形)。
TEST(RegVmBackendUpperBound, PdataEmptyLastRegionTextTailFallback) {
    wvmp::ProtectionContext ctx;
    ctx.slot<PeImage>(kPeImage) = MakeX86Pe();
    ctx.functions = {MakeFnX("solo", 0x1000, 0x1010)};
    EXPECT_TRUE(F1ExitEmitted(ctx, ctx.functions[0]));  // 0x1050 < 节尾 0x4000
}

// 病态形 ③: 目标越 .text 节尾 → 裁决表 "目标出节尾 = gate"。
TEST(RegVmBackendUpperBound, PdataEmptyTargetBeyondTextTailGates) {
    wvmp::ProtectionContext ctx;
    ctx.slot<PeImage>(kPeImage) = MakeX86Pe();
    ctx.functions = {MakeFnX("solo", 0x1000, 0x1010)};
    ir::FunctionRegion fn = ctx.functions[0];
    fn.blocks.front().insns.front().dst = ir::Operand::imm_(0x5000);  // > 0x4000
    EXPECT_TRUE(F1Gated(ctx, fn));
}

// 病态形 ④: 下一区域 begin 落在节尾之后 (多执行节病态布局) → cap 收紧,
// 不得放行 [节尾, next_begin) 零填充/他节内存。
TEST(RegVmBackendUpperBound, TailCapOverridesFarNextBegin) {
    wvmp::ProtectionContext ctx;
    ctx.slot<PeImage>(kPeImage) = MakeX86Pe();
    ctx.functions = {MakeFnX("f0", 0x1000, 0x1010),
                     MakeFnX("far", 0x8000, 0x8010)};  // begin > 节尾 0x4000
    ir::FunctionRegion fn = ctx.functions[0];
    fn.blocks.front().insns.front().dst = ir::Operand::imm_(0x6000);  // ∈ [tail, next_begin)
    EXPECT_TRUE(F1Gated(ctx, fn));  // cap → ub=0x4000 → D 失败
}

// 病态形 ⑤: 嵌套区域——min{begin > fn.begin} = 内层 begin < fn.end_rva,
// C/D 联合不可满足 → 外层函数任何越区目标保守 gate (零 ExitNative 进嵌套区)。
TEST(RegVmBackendUpperBound, NestedRegionOuterGates) {
    wvmp::ProtectionContext ctx;
    ctx.slot<PeImage>(kPeImage) = MakeX86Pe();
    ctx.functions = {MakeFnX("outer", 0x1000, 0x1100),
                     MakeFnX("inner", 0x1050, 0x1080)};  // 嵌套于 outer
    ir::FunctionRegion fn = ctx.functions[0];
    fn.blocks.front().insns.front().dst = ir::Operand::imm_(0x1200);
    EXPECT_TRUE(F1Gated(ctx, fn));  // ub=0x1050 < end_rva=0x1100 → D 恒败
}

// 病态形 ⑥: 区域表为空 (fn 不在表内) → 无后继 → 节尾兜底仍生效
// (min 定义式对空表自然退化, 不依赖 fn 自身入表)。
TEST(RegVmBackendUpperBound, RegionTableEmptyFallsToTextTail) {
    wvmp::ProtectionContext ctx;
    ctx.slot<PeImage>(kPeImage) = MakeX86Pe();
    ctx.functions = {};  // 空
    EXPECT_TRUE(F1ExitEmitted(ctx, MakeFnX("orphan", 0x1000, 0x1010)));
}

// 病态形 ⑦: pe == nullptr (无 kPeImage 槽) → 维持 nullopt, 保守 gate。
TEST(RegVmBackendUpperBound, PeNullStaysConservative) {
    wvmp::ProtectionContext ctx;  // 不设 kPeImage
    EXPECT_TRUE(F1Gated(ctx, MakeFnX("solo", 0x1000, 0x1010)));
}

// 病态形 ⑧: 回跳检出 (exit_native_blocked) 与 pdata_empty 组合——BFS 是
// arch 共享码 (452 §3.4), x86 回退链前同样拦截。
TEST(RegVmBackendUpperBound, PdataEmptyBlockedStillGates) {
    wvmp::ProtectionContext ctx;
    ctx.slot<PeImage>(kPeImage) = MakeX86Pe();
    ctx.functions = {MakeFnX("solo", 0x1000, 0x1010)};
    LiftMetadata m;
    m.exit_native_blocked = true;  // lifter BFS 检出越区目标回跳本区
    SetMetadata(ctx, {m});
    EXPECT_TRUE(F1Gated(ctx, ctx.functions[0]));
}

// 病态形 ⑨: 节表无 .text (区域不在任何节内容面) → 无可靠上界 → 保守 gate。
TEST(RegVmBackendUpperBound, NoTextSectionGates) {
    wvmp::ProtectionContext ctx;
    PeImage pe = MakeX86Pe();
    pe.sections.clear();
    ctx.slot<PeImage>(kPeImage) = pe;
    EXPECT_TRUE(F1Gated(ctx, MakeFnX("solo", 0x1000, 0x1010)));
}

// 对照组: pdata 非空路径原样在前 (D2)——region end_rva 收窄于 .pdata
// EndAddress 时, gap 内目标经 find_function_end_rva 放行, 字节不变。
TEST(RegVmBackendUpperBound, PdataNonEmptyKeepsPdataPath) {
    wvmp::ProtectionContext ctx;
    PeImage pe = MakeX86Pe();
    pe.pdata = {{0x1000, 0x1010, 0}};
    pe.pdata_empty = false;
    ctx.slot<PeImage>(kPeImage) = pe;
    ctx.functions = {MakeFnX("f0", 0x1000, 0x1008)};
    ir::FunctionRegion fn = ctx.functions[0];
    fn.blocks.front().insns.front().dst = ir::Operand::imm_(0x100C);  // ∈ [0x1008, 0x1010)
    EXPECT_TRUE(F1ExitEmitted(ctx, fn));
}
