// cli/args.cpp 的参数解析测试（main 的参数处理拆出来的可测函数）。

#include "wvmp/cli/args.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

namespace {

wvmp::cli::ArgsResult parse(std::vector<std::string> args) {
    args.insert(args.begin(), "wvmp"); // argv[0] = 程序名
    std::vector<const char*> argv;
    argv.reserve(args.size());
    for (const auto& a : args) argv.push_back(a.c_str());
    return wvmp::cli::parse_args(static_cast<int>(argv.size()), argv.data());
}

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

TEST(ArgsParse, NoSubcommandFails) {
    const auto r = parse({});
    EXPECT_FALSE(r.ok);
    EXPECT_TRUE(contains(r.error, "子命令")) << r.error;
    EXPECT_TRUE(contains(r.error, "protect")) << r.error; // usage 附带
}

TEST(ArgsParse, UnknownSubcommandFails) {
    const auto r = parse({"nope"});
    EXPECT_FALSE(r.ok);
    EXPECT_TRUE(contains(r.error, "未知子命令")) << r.error;
}

TEST(ArgsParse, Version) {
    const auto r = parse({"version"});
    EXPECT_TRUE(r.ok) << r.error;
    EXPECT_TRUE(r.is_version);
}

TEST(ArgsParse, VersionRejectsExtraArgs) {
    const auto r = parse({"version", "--now"});
    EXPECT_FALSE(r.ok);
}

TEST(ArgsParse, ProtectRequiresConfig) {
    const auto r = parse({"protect"});
    EXPECT_FALSE(r.ok);
    EXPECT_TRUE(contains(r.error, "--config")) << r.error;
}

TEST(ArgsParse, ProtectConfigWithoutValueFails) {
    const auto r = parse({"protect", "--config"});
    EXPECT_FALSE(r.ok);
    EXPECT_TRUE(contains(r.error, "--config")) << r.error;
}

TEST(ArgsParse, ProtectBasic) {
    const auto r = parse({"protect", "--config", "wvmp.toml"});
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_FALSE(r.is_version);
    EXPECT_EQ(r.config_path, "wvmp.toml");
    EXPECT_EQ(r.output_override, "");
    EXPECT_FALSE(r.dry_run);
}

TEST(ArgsParse, ProtectOutputOverride) {
    const auto r = parse({"protect", "--config", "wvmp.toml", "-o", "overridden.exe"});
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.output_override, "overridden.exe");
}

TEST(ArgsParse, ProtectDryRun) {
    const auto r = parse({"protect", "--config", "wvmp.toml", "--dry-run"});
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_TRUE(r.dry_run);
    EXPECT_EQ(r.output_override, "");
}

TEST(ArgsParse, ProtectAllFlagsTogether) {
    const auto r = parse({"protect", "--dry-run", "-o", "o.exe", "--config", "c.toml"});
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.config_path, "c.toml");
    EXPECT_EQ(r.output_override, "o.exe");
    EXPECT_TRUE(r.dry_run);
}

TEST(ArgsParse, ProtectUnknownFlagFails) {
    const auto r = parse({"protect", "--config", "c.toml", "--frobnicate"});
    EXPECT_FALSE(r.ok);
    EXPECT_TRUE(contains(r.error, "--frobnicate")) << r.error;
}

TEST(ArgsParse, ProtectStrayPositionalFails) {
    const auto r = parse({"protect", "--config", "c.toml", "extra.exe"});
    EXPECT_FALSE(r.ok);
    EXPECT_TRUE(contains(r.error, "extra.exe")) << r.error;
}

} // namespace
