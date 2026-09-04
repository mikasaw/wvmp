// MIT-463 (anti_debug-v1)：anti_debug pass 单测——plan 写入、技术位、
// 注册面。

#include "wvmp/passes/anti_debug/anti_debug_pass.hpp"

#include "wvmp/passes/anti_debug/anti_debug_plan.hpp"
#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"

#include <gtest/gtest.h>

#include <string>

namespace {

namespace adb = wvmp::passes::anti_debug;

TEST(AntiDebugPass, WritesPlanWithV1Techniques) {
    wvmp::ProtectionContext ctx;
    wvmp::passes::AntiDebugPass pass;
    pass.run(ctx);
    const auto* plan = ctx.find_slot<adb::AntiDebugPlan>(wvmp::kAntiDebugPlan);
    ASSERT_NE(plan, nullptr);
    EXPECT_EQ(plan->techniques, adb::tech::kV1All);
    EXPECT_EQ(plan->techniques & adb::tech::kBeingDebugged, adb::tech::kBeingDebugged);
    EXPECT_EQ(plan->techniques & adb::tech::kNtGlobalFlag, adb::tech::kNtGlobalFlag);
    EXPECT_EQ(plan->response, adb::response::kFailFast);
    EXPECT_FALSE(ctx.diag.has_errors());
    bool has_note = false;
    for (const auto& d : ctx.diag.items())
        if (d.message.find("BeingDebugged") != std::string::npos) has_note = true;
    EXPECT_TRUE(has_note);
}

TEST(AntiDebugPlan, TechniqueBitsDistinct) {
    // append-only 位分配纪律：两位互不重叠，且 v1 全集 = 二者按位或。
    EXPECT_NE(adb::tech::kBeingDebugged, adb::tech::kNtGlobalFlag);
    EXPECT_EQ(adb::tech::kV1All,
              adb::tech::kBeingDebugged | adb::tech::kNtGlobalFlag);
}

TEST(AntiDebugPass, ContractSurface) {
    wvmp::passes::AntiDebugPass pass;
    EXPECT_EQ(pass.name(), "anti_debug");
    EXPECT_EQ(pass.phase(), wvmp::Phase::Transform);
}

} // namespace
