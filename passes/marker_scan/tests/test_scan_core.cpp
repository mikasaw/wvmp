// scan_core 纯函数单元测试：手工构造的字节串直接验证扫描/配对语义，
// 不依赖任何真实 PE。

#include "wvmp/passes/marker_scan/scan_core.hpp"

#include <gtest/gtest.h>

#include <vector>

namespace {
namespace ms = wvmp::passes::marker_scan;
using wvmp::u8;

std::vector<u8> bytes(std::initializer_list<int> xs) {
    std::vector<u8> out;
    out.reserve(xs.size());
    for (int x : xs) out.push_back(static_cast<u8>(x));
    return out;
}

TEST(FindAll, MultipleHits) {
    const auto hay = bytes({0x90, 0xE8, 0x00, 0xE8, 0x01});
    const auto needle = bytes({0xE8});
    EXPECT_EQ(ms::find_all(hay, needle), (std::vector<size_t>{1, 3}));
}

TEST(FindAll, OverlappingHits) {
    const auto hay = bytes({0xAA, 0xAA, 0xAA});
    const auto needle = bytes({0xAA, 0xAA});
    EXPECT_EQ(ms::find_all(hay, needle), (std::vector<size_t>{0, 1}));
}

TEST(FindAll, AbsentNeedle) {
    const auto hay = bytes({1, 2, 3});
    EXPECT_TRUE(ms::find_all(hay, bytes({9})).empty());
    // needle 比 hay 长 / 与 hay 等长且相等 / 空 needle 均不崩溃
    EXPECT_TRUE(ms::find_all(hay, bytes({1, 2, 3, 4})).empty());
    EXPECT_EQ(ms::find_all(hay, bytes({1, 2, 3})), (std::vector<size_t>{0}));
    EXPECT_TRUE(ms::find_all(hay, {}).empty());
    EXPECT_TRUE(ms::find_all({}, bytes({1})).empty());
}

TEST(ScanCalls, BackwardTargetWithBaseOffset) {
    // 0x90 | E8 FE FF FF FF (rel32 = -2) | 0x90，片段在镜像中的起点 = 100
    const auto code = bytes({0x90, 0xE8, 0xFE, 0xFF, 0xFF, 0xFF, 0x90});
    const auto calls = ms::scan_calls(code, 100);
    ASSERT_EQ(calls.size(), static_cast<size_t>(1));
    EXPECT_EQ(calls[0].insn_off, static_cast<size_t>(101));
    EXPECT_EQ(calls[0].next_off, static_cast<size_t>(106));
    EXPECT_EQ(calls[0].target_off, static_cast<size_t>(104)); // 106 - 2
}

TEST(ScanCalls, ForwardTargetAndTruncatedTailIgnored) {
    // 首字节即 E8 rel32=+5；结尾悬空的 E8 不足 5 字节，必须被忽略
    const auto code = bytes({0xE8, 0x05, 0x00, 0x00, 0x00, 0xE8});
    const auto calls = ms::scan_calls(code, 0);
    ASSERT_EQ(calls.size(), static_cast<size_t>(1));
    EXPECT_EQ(calls[0].insn_off, static_cast<size_t>(0));
    EXPECT_EQ(calls[0].next_off, static_cast<size_t>(5));
    EXPECT_EQ(calls[0].target_off, static_cast<size_t>(10));

    EXPECT_TRUE(ms::scan_calls(bytes({0xE8, 0, 0, 0}), 0).empty());
}

TEST(ScanCalls, OnlyE8OpcodeIsEnumerated) {
    // E9 (jmp rel32) 不是 call，不产出；E8 出现在 imm 字段内也会被枚举
    // （v1 按字节枚举的既知语义，由窗口过滤兜底）
    const auto code = bytes({0xE9, 0x10, 0x00, 0x00, 0x00, 0x90, 0x90});
    EXPECT_TRUE(ms::scan_calls(code, 0).empty());
}

TEST(AttributeCalls, AdjacentStubsAreExclusivelyAttributed) {
    // begin/end 两桩相邻（同一 sdk.cpp 链接后的典型布局）：
    //   begin 入口 98，begin magic 100；end 入口 118，end magic 120
    // 双向 ±64 窗口会互相串扰；"紧随其后"规则必须排他归属。
    const std::vector<ms::Anchor> anchors{{100, true}, {120, false}};
    const std::vector<ms::CallRef> calls{
        ms::CallRef{200, 205, 98},  // call marker_begin
        ms::CallRef{300, 305, 118}, // call marker_end
    };
    const auto m = ms::attribute_marker_calls(calls, anchors, ms::kStubWindow);
    EXPECT_EQ(m.begin_nexts, (std::vector<size_t>{205}));
    EXPECT_EQ(m.end_addrs, (std::vector<size_t>{300}));
}

TEST(AttributeCalls, WindowAndBoundaryRules) {
    const std::vector<ms::Anchor> anchors{{100, false}, {500, true}};
    const std::vector<ms::CallRef> calls{
        ms::CallRef{0, 5, 20},    // 距最近的后续 magic 80B > 64：忽略
        ms::CallRef{10, 15, 99},  // magic 前 1B：归属
        ms::CallRef{20, 25, 100}, // 恰好落在 magic 上：归属（距离 0）
        ms::CallRef{30, 35, 436}, // 距 begin magic 64B：边界内归属
        ms::CallRef{40, 45, 435}, // 距 begin magic 65B > 64：忽略
        ms::CallRef{50, 55, 600}, // 在所有 magic 之后：忽略
    };
    const auto m = ms::attribute_marker_calls(calls, anchors, 64);
    EXPECT_EQ(m.end_addrs, (std::vector<size_t>{10, 20}));
    EXPECT_EQ(m.begin_nexts, (std::vector<size_t>{35}));
    EXPECT_TRUE(ms::attribute_marker_calls(calls, {}, 64).begin_nexts.empty());
    EXPECT_TRUE(ms::attribute_marker_calls({}, anchors, 64).end_addrs.empty());
}

TEST(PairRegions, SequentialPairing) {
    const auto r = ms::pair_regions({10, 100}, {50, 140});
    ASSERT_EQ(r.regions.size(), static_cast<size_t>(2));
    EXPECT_EQ(r.regions[0].begin_off, static_cast<size_t>(10));
    EXPECT_EQ(r.regions[0].end_off, static_cast<size_t>(50));
    EXPECT_EQ(r.regions[1].begin_off, static_cast<size_t>(100));
    EXPECT_EQ(r.regions[1].end_off, static_cast<size_t>(140));
    EXPECT_TRUE(r.unmatched_begins.empty());
    EXPECT_TRUE(r.unmatched_ends.empty());
}

TEST(PairRegions, NestedPairing) {
    const auto r = ms::pair_regions({10, 20}, {30, 40});
    ASSERT_EQ(r.regions.size(), static_cast<size_t>(2));
    // 按闭合序产出：内层 (20,30) 先闭合，外层 (10,40) 后闭合
    EXPECT_EQ(r.regions[0].begin_off, static_cast<size_t>(20));
    EXPECT_EQ(r.regions[0].end_off, static_cast<size_t>(30));
    EXPECT_EQ(r.regions[1].begin_off, static_cast<size_t>(10));
    EXPECT_EQ(r.regions[1].end_off, static_cast<size_t>(40));
}

TEST(PairRegions, UnmatchedBeginAndEnd) {
    const auto r = ms::pair_regions({10}, {3}); // end 出现在任何 begin 之前
    EXPECT_TRUE(r.regions.empty());
    EXPECT_EQ(r.unmatched_ends, (std::vector<size_t>{3}));
    EXPECT_EQ(r.unmatched_begins, (std::vector<size_t>{10}));

    const auto only_begin = ms::pair_regions({7}, {});
    EXPECT_TRUE(only_begin.regions.empty());
    EXPECT_EQ(only_begin.unmatched_begins, (std::vector<size_t>{7}));

    const auto empty = ms::pair_regions({}, {});
    EXPECT_TRUE(empty.regions.empty());
    EXPECT_TRUE(empty.unmatched_begins.empty());
    EXPECT_TRUE(empty.unmatched_ends.empty());
}

// —— x86 双段 magic（X1a / MIT-437）——
// fixture 采用 cl v19.51.36256 x86 实测形态（探针 dumpbin /disasm）：
//   /Od    : B8 <hi4> ; C7 45 F8 <lo4> ; 89 45 FC   （hi→lo，间隔 3B）
//   /O1 /O2: C7 45 F8 <lo4> ; C7 45 FC <hi4>        （lo→hi，紧邻）
TEST(FindAllX86, OdFormHighBeforeLow) {
    // /Od 实测形：B8 @3，hi 字节 @4..7；C7 45 F8 @8，lo 字节 @11..14
    const auto code = bytes({0x55, 0x8B, 0xEC,
                             0xB8, 0x42, 0x45, 0x47, 0x31,       // hi "BEG1" @4
                             0xC7, 0x45, 0xF8, 0x57, 0x56, 0x4D, 0x50, // lo "WVMP" @11
                             0x89, 0x45, 0xFC, 0x8B, 0xE5, 0x5D, 0xC3});
    const auto hits = ms::find_all_x86(code, ms::kBeginPatternX86);
    ASSERT_EQ(hits.size(), static_cast<size_t>(1));
    EXPECT_EQ(hits[0], static_cast<size_t>(4)); // 物化起点 = 先出的 hi 半
}

TEST(FindAllX86, O1O2FormLowBeforeHigh) {
    // /O1 /O2 实测形：C7 45 F8 @3，lo 字节 @6..9；C7 45 FC @10，hi 字节 @13..16
    const auto code = bytes({0x55, 0x8B, 0xEC,
                             0xC7, 0x45, 0xF8, 0x57, 0x56, 0x4D, 0x50, // lo @6
                             0xC7, 0x45, 0xFC, 0x42, 0x45, 0x47, 0x31, // hi @13
                             0xC9, 0xC3});
    const auto hits = ms::find_all_x86(code, ms::kBeginPatternX86);
    ASSERT_EQ(hits.size(), static_cast<size_t>(1));
    EXPECT_EQ(hits[0], static_cast<size_t>(6)); // 物化起点 = 先出的 lo 半
}

TEST(FindAllX86, BeginAndEndBothLocatedWithSharedLowHalf) {
    // begin/end 共享 lo 半（"WVMP"）；相邻两桩（x86 SDK 链接后典型布局）
    // 必须各自精确归类，不得因共享半串扰。/O1 形紧邻物化。
    const auto code = bytes({
        // begin 桩：prologue @0..2，lo @6..9，hi(BEG1) @13..16
        0x55, 0x8B, 0xEC,
        0xC7, 0x45, 0xF8, 0x57, 0x56, 0x4D, 0x50,
        0xC7, 0x45, 0xFC, 0x42, 0x45, 0x47, 0x31,
        0xC9, 0xC3, 0xCC, 0xCC,
        // end 桩：prologue @21..23，lo @27..30，hi(END1) @34..37
        0x55, 0x8B, 0xEC,
        0xC7, 0x45, 0xF8, 0x57, 0x56, 0x4D, 0x50,
        0xC7, 0x45, 0xFC, 0x45, 0x4E, 0x44, 0x31,
        0xC9, 0xC3,
    });
    EXPECT_EQ(ms::find_all_x86(code, ms::kBeginPatternX86), (std::vector<size_t>{6}));
    EXPECT_EQ(ms::find_all_x86(code, ms::kEndPatternX86), (std::vector<size_t>{27}));
}

TEST(FindAllX86, ReversedHalvesBeyondWindowRejected) {
    // "反序负"：hi 半在前、lo 半在后是 /Od 合法方向，但 lo 落点超出
    // [hi+4, hi+4+gap] 窗 → 两方向均不成锚（堵"忽略落点的共现匹配"漏洞）。
    const std::vector<u8> hi = {0x42, 0x45, 0x47, 0x31};
    const std::vector<u8> lo = {0x57, 0x56, 0x4D, 0x50};
    std::vector<u8> code{0x90, 0x90, 0x90};
    code.insert(code.end(), hi.begin(), hi.end());          // hi @3..6
    code.insert(code.end(), 4 + ms::kX86MaxHalfGap + 1, 0x90); // 垫 13B
    code.insert(code.end(), lo.begin(), lo.end());          // lo @20..23
    EXPECT_TRUE(ms::find_all_x86(code, ms::kBeginPatternX86).empty());
}

TEST(FindAllX86, GapBeyondWindowRejected) {
    // "间隔超窗负"：lo→hi 方向，后半起点 = lo+4+gap 恰超窗 1 字节 → 不成锚；
    // 窗沿（= lo+4+gap）→ 成锚（判据语义钉死：后半起点 ∈ [首半+4, 首半+4+gap]）。
    const std::vector<u8> lo = {0x57, 0x56, 0x4D, 0x50};
    const std::vector<u8> hi = {0x42, 0x45, 0x47, 0x31};
    std::vector<u8> code;
    code.insert(code.end(), lo.begin(), lo.end());             // lo @0..3
    code.insert(code.end(), ms::kX86MaxHalfGap + 1, 0x90);     // 垫 9B → hi @13
    code.insert(code.end(), hi.begin(), hi.end());
    EXPECT_TRUE(ms::find_all_x86(code, ms::kBeginPatternX86).empty());

    code.assign(lo.begin(), lo.end());                         // lo @0..3
    code.insert(code.end(), ms::kX86MaxHalfGap, 0x90);         // 垫 8B → hi @12 窗沿
    code.insert(code.end(), hi.begin(), hi.end());
    EXPECT_EQ(ms::find_all_x86(code, ms::kBeginPatternX86), (std::vector<size_t>{0}));
}

TEST(FindAllX86, StrayHalfAloneIsNotAnAnchor) {
    // "幻影锚点负"（424 §3.2 / 432 §6.2 纪律）：孤立半（数据里的 "WVMP"
    // 字符串等）不得凭空产生锚点；begin 的 lo 半与 end 的 hi 半远距共现
    // （共享 lo 半但跨桩错配）亦然。
    const auto one_lo = bytes({0x90, 0x57, 0x56, 0x4D, 0x50, 0x90});
    const auto one_hi = bytes({0x90, 0x42, 0x45, 0x47, 0x31, 0x90});
    EXPECT_TRUE(ms::find_all_x86(one_lo, ms::kBeginPatternX86).empty());
    EXPECT_TRUE(ms::find_all_x86(one_hi, ms::kBeginPatternX86).empty());

    std::vector<u8> cross{0x57, 0x56, 0x4D, 0x50};             // lo @0..3
    cross.insert(cross.end(), 4 + ms::kX86MaxHalfGap + 1, 0x90); // 垫 13B
    cross.push_back(0x45); cross.push_back(0x4E);              // "END1" @17..20
    cross.push_back(0x44); cross.push_back(0x31);
    EXPECT_TRUE(ms::find_all_x86(cross, ms::kBeginPatternX86).empty());
    EXPECT_TRUE(ms::find_all_x86(cross, ms::kEndPatternX86).empty());
}

TEST(FindAllX86, ContinuousEightByteIsDegenerateDualAndX64NeedleStillWorks) {
    // "x64 单段回归" + 退化组合：8 字节连续 magic 对 x64 路径（find_all）
    // 恒命中；对 x86 双段识别 = 间隔 0 的 lo→hi 退化形，同样命中——
    // 两条路径对连续形态的判定一致，互不破坏。
    const auto code = bytes({0x48, 0xB8, 0x57, 0x56, 0x4D, 0x50,
                             0x42, 0x45, 0x47, 0x31, 0x90});
    EXPECT_EQ(ms::find_all(code, ms::kBeginPattern),
              (std::vector<size_t>{2}));
    EXPECT_EQ(ms::find_all_x86(code, ms::kBeginPatternX86),
              (std::vector<size_t>{2}));
    // 反向：x64 8 字节 needle 对真双段（不连续）形态不命中——这正是
    // x86 需要独立扫描路径的原因（GAPS C5 实证缺口，X1a 收口）。
    const auto split = bytes({0xB8, 0x42, 0x45, 0x47, 0x31,
                              0xC7, 0x45, 0xF8, 0x57, 0x56, 0x4D, 0x50});
    EXPECT_TRUE(ms::find_all(split, ms::kBeginPattern).empty());
    EXPECT_EQ(ms::find_all_x86(split, ms::kBeginPatternX86),
              (std::vector<size_t>{1}));
}

} // namespace

// ==================== MIT-460 (P7-names)：名字物化定位 ====================

namespace {
std::vector<u8> with(const std::vector<u8>& prefix, size_t total) {
    std::vector<u8> v = prefix;
    v.resize(total, 0xCC);
    return v;
}
} // namespace

TEST(ScanCoreNameOperand, X64LeaRipRelLocated) {
    // 48 8D 0D <disp32> 紧邻 E8：lea 在 [call_next-12, call_next-5)、
    // E8 占 [call_next-5, call_next)。disp 有符号读出。
    std::vector<u8> img = with({0x48, 0x8D, 0x0D, 0x34, 0x12, 0x00, 0x00,
                                0xE8, 0x00, 0x00, 0x00, 0x00},
                               32);
    const auto r = ms::locate_name_operand(img, 12, false);
    ASSERT_TRUE(r.has_value());
    EXPECT_TRUE(r->is_rip_rel);
    EXPECT_EQ(r->value, 0x1234);
}

TEST(ScanCoreNameOperand, X86PushAbsLocated) {
    // 68 <abs32> 紧邻 E8：push 在 [call_next-10, call_next-5)。
    std::vector<u8> img = with({0x68, 0x78, 0x56, 0x00, 0x01,
                                0xE8, 0x00, 0x00, 0x00, 0x00},
                               32);
    const auto r = ms::locate_name_operand(img, 10, true);
    ASSERT_TRUE(r.has_value());
    EXPECT_FALSE(r->is_rip_rel);
    EXPECT_EQ(r->value, 0x01005678);
}

TEST(ScanCoreNameOperand, X64NegativeDispSignExtended) {
    // MIT-460 验收反馈：负 disp（.rdata 在 lea 之前）必须符号扩展
    // （0xFFFFF000 → -4096，而非 +4294952960）。
    std::vector<u8> img = with({0x48, 0x8D, 0x0D, 0x00, 0xF0, 0xFF, 0xFF,
                                0xE8, 0x00, 0x00, 0x00, 0x00},
                               32);
    const auto r = ms::locate_name_operand(img, 12, false);
    ASSERT_TRUE(r.has_value());
    EXPECT_TRUE(r->is_rip_rel);
    EXPECT_EQ(r->value, -4096);
}

TEST(ScanCoreNameOperand, NoPatternFallsBack) {
    // 无物化（旧产物）→ nullopt（调用方回退地址名）。
    std::vector<u8> img = with({0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                                0xE8, 0x00, 0x00, 0x00, 0x00},
                               32);
    EXPECT_FALSE(ms::locate_name_operand(img, 12, false).has_value());
    EXPECT_FALSE(ms::locate_name_operand(img, 12, true).has_value());
    // 太短防越界。
    std::vector<u8> tiny = {0x48, 0x8D};
    EXPECT_FALSE(ms::locate_name_operand(tiny, 2, false).has_value());
}
