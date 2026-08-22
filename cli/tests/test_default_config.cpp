// 默认配置守卫：cli/configs/default.toml 必须能解析，且其 pass 名单必须
// 能装配出阶段序正确的完整管道（"默认配置可运行"）。
//
// 需要把 wvmp_passes_all 整包（WHOLE_ARCHIVE）链接进来：pass 的自注册
// 对象不被 main 显式引用，MSVC 默认会丢弃它们。

#include "wvmp/cli/config.hpp"

#include "wvmp/framework/pass.hpp"
#include "wvmp/framework/phase.hpp"
#include "wvmp/framework/pipeline.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <string>
#include <vector>

#ifndef WVMP_DEFAULT_CONFIG_PATH
#error "test must be built with WVMP_DEFAULT_CONFIG_PATH compile definition"
#endif

namespace {

TEST(DefaultConfig, ParsesWithExpectedFields) {
    const auto result = wvmp::cli::parse_config(WVMP_DEFAULT_CONFIG_PATH);
    ASSERT_TRUE(result.ok) << result.error;
    EXPECT_EQ(result.value.input, "target.exe");
    EXPECT_EQ(result.value.output, "target_protected.exe");
    EXPECT_EQ(result.value.seed, uint64_t{12345});

    const std::vector<std::string> expected_names = {
        "pe_loader", "marker_scan", "lifter", "virtualize", "pe_writer",
    };
    ASSERT_EQ(result.value.passes.size(), expected_names.size());
    for (size_t i = 0; i < expected_names.size(); ++i)
        EXPECT_EQ(result.value.passes[i].name, expected_names[i]) << "index " << i;
}

TEST(DefaultConfig, AssemblesPipelineInPhaseOrder) {
    const auto result = wvmp::cli::parse_config(WVMP_DEFAULT_CONFIG_PATH);
    ASSERT_TRUE(result.ok) << result.error;

    std::vector<std::string> names;
    for (const auto& p : result.value.passes) names.push_back(p.name);

    // 未知 pass 名 / requires 缺提供者 -> from_names / validate 抛错。
    wvmp::Pipeline pipeline;
    try {
        pipeline = wvmp::Pipeline::from_names(names);
    } catch (const std::exception& e) {
        FAIL() << "Pipeline::from_names threw: " << e.what();
    }

    const auto& stages = pipeline.stages();
    ASSERT_EQ(stages.size(), size_t{5});

    // from_names 按 Phase 稳定排序：marker_scan 与 lifter 同为 Analyze，
    // 保持配置给定顺序（marker_scan 在前）。
    struct Expected {
        const char* name;
        wvmp::Phase phase;
    };
    const Expected expected[] = {
        {"pe_loader", wvmp::Phase::Load},   {"marker_scan", wvmp::Phase::Analyze},
        {"lifter", wvmp::Phase::Analyze},   {"virtualize", wvmp::Phase::Transform},
        {"pe_writer", wvmp::Phase::Write},
    };
    for (size_t i = 0; i < 5; ++i) {
        EXPECT_EQ(stages[i]->name(), expected[i].name) << "index " << i;
        EXPECT_EQ(stages[i]->phase(), expected[i].phase) << "index " << i;
    }
}

} // namespace
