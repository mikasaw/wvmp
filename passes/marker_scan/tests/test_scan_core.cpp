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

} // namespace
