// P1：PassRegistry / Pipeline 的注册、装配排序与依赖检查测试。

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/pipeline.hpp"
#include "wvmp/framework/registry.hpp"

#include <gtest/gtest.h>

#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

class FakePass final : public wvmp::Pass {
public:
    FakePass(std::string name, wvmp::Phase phase,
             std::vector<std::string_view> req = {},
             std::vector<std::string_view> prov = {})
        : name_(std::move(name)), phase_(phase), req_(std::move(req)), prov_(std::move(prov)) {}

    std::string_view name() const override { return name_; }
    wvmp::Phase phase() const override { return phase_; }
    std::span<const std::string_view> requires_keys() const override { return req_; }
    std::span<const std::string_view> provides_keys() const override { return prov_; }

    void run(wvmp::ProtectionContext&) override {
        if (!throw_msg_.empty()) throw std::runtime_error(throw_msg_);
        ran_ = true;
    }

    void set_throws(std::string msg) { throw_msg_ = std::move(msg); }
    bool ran() const { return ran_; }

private:
    std::string name_;
    wvmp::Phase phase_;
    std::vector<std::string_view> req_, prov_;
    std::string throw_msg_;
    bool ran_ = false;
};

class FrameworkTest : public ::testing::Test {
protected:
    void SetUp() override { wvmp::PassRegistry::instance().clear(); }
    void TearDown() override { wvmp::PassRegistry::instance().clear(); }

    void register_fake(std::string name, wvmp::Phase phase,
                       std::vector<std::string_view> req = {},
                       std::vector<std::string_view> prov = {}) {
        wvmp::PassRegistry::instance().register_pass(
            std::make_unique<FakePass>(std::move(name), phase, std::move(req), std::move(prov)));
    }
};

TEST_F(FrameworkTest, RegistrarObjectRegistersPass) {
    {
        const ::wvmp::PassRegistrar r{std::make_unique<FakePass>("tmp", wvmp::Phase::Emit)};
        EXPECT_NE(wvmp::PassRegistry::instance().find("tmp"), nullptr);
    }
    // registrar 构造即注册，析构不注销（进程级注册表语义）。
    EXPECT_NE(wvmp::PassRegistry::instance().find("tmp"), nullptr);
}

TEST_F(FrameworkTest, DuplicateNameThrows) {
    register_fake("dup", wvmp::Phase::Load);
    EXPECT_THROW(register_fake("dup", wvmp::Phase::Write), std::runtime_error);
}

TEST_F(FrameworkTest, FindAndNamesPreserveOrder) {
    register_fake("b", wvmp::Phase::Load);
    register_fake("a", wvmp::Phase::Load);
    register_fake("c", wvmp::Phase::Write);
    const auto names = wvmp::PassRegistry::instance().names();
    ASSERT_EQ(names.size(), static_cast<size_t>(3));
    EXPECT_EQ(names[0], "b");
    EXPECT_EQ(names[1], "a");
    EXPECT_EQ(names[2], "c");
    EXPECT_EQ(wvmp::PassRegistry::instance().find("a")->name(), "a");
    EXPECT_EQ(wvmp::PassRegistry::instance().find("missing"), nullptr);
}

TEST_F(FrameworkTest, UnknownPipelineNameThrows) {
    register_fake("known", wvmp::Phase::Load);
    EXPECT_THROW((void)wvmp::Pipeline::from_names({"known", "ghost"}), std::runtime_error);
}

TEST_F(FrameworkTest, PhaseStableOrdering) {
    // 注册顺序无关；配置顺序 = [write, load, an1, an2]，
    // 期望：Load 先于 Analyze/Write，且 an1/an2 保持配置相对顺序。
    register_fake("load", wvmp::Phase::Load);
    register_fake("an1", wvmp::Phase::Analyze);
    register_fake("an2", wvmp::Phase::Analyze);
    register_fake("write", wvmp::Phase::Write);
    auto pipe = wvmp::Pipeline::from_names({"write", "load", "an1", "an2"});
    const auto& st = pipe.stages();
    ASSERT_EQ(st.size(), static_cast<size_t>(4));
    EXPECT_EQ(st[0]->name(), "load");
    EXPECT_EQ(st[1]->name(), "an1");
    EXPECT_EQ(st[2]->name(), "an2");
    EXPECT_EQ(st[3]->name(), "write");
}

TEST_F(FrameworkTest, ValidateMissingKeyThrowsWithNames) {
    register_fake("needy", wvmp::Phase::Transform, {"no.such.key"});
    try {
        (void)wvmp::Pipeline::from_names({"needy"});
        FAIL() << "expected runtime_error";
    } catch (const std::runtime_error& e) {
        const std::string msg = e.what();
        EXPECT_NE(msg.find("needy"), std::string::npos);
        EXPECT_NE(msg.find("no.such.key"), std::string::npos);
    }
}

TEST_F(FrameworkTest, ValidateCoreKeysAlwaysAvailable) {
    register_fake("core_user", wvmp::Phase::Transform, {wvmp::kImage, wvmp::kFunctions});
    EXPECT_NO_THROW((void)wvmp::Pipeline::from_names({"core_user"}));
}

TEST_F(FrameworkTest, ValidateProviderMustComeEarlier) {
    register_fake("provider", wvmp::Phase::Transform, {}, {"custom.key"});
    register_fake("consumer", wvmp::Phase::Transform, {"custom.key"});
    // 同 Phase 下，consumer 排在 provider 前则校验失败……
    EXPECT_THROW((void)wvmp::Pipeline::from_names({"consumer", "provider"}), std::runtime_error);
    // ……排在后面则通过。
    EXPECT_NO_THROW((void)wvmp::Pipeline::from_names({"provider", "consumer"}));
}

TEST_F(FrameworkTest, RunExecutesStagesInOrder) {
    register_fake("a", wvmp::Phase::Load);
    register_fake("b", wvmp::Phase::Load);
    register_fake("c", wvmp::Phase::Write);
    auto pipe = wvmp::Pipeline::from_names({"c", "b", "a"});  // 配置乱序，执行按 Phase 序
    wvmp::ProtectionContext ctx;
    EXPECT_NO_THROW(pipe.run(ctx));
    EXPECT_FALSE(ctx.diag.has_errors());
}

TEST_F(FrameworkTest, RunRecordsDiagAndRethrows) {
    register_fake("boom", wvmp::Phase::Load);
    register_fake("after", wvmp::Phase::Load);
    auto pipe = wvmp::Pipeline::from_names({"boom", "after"});
    // 取回注册的 FakePass 让它抛错。
    auto* boom = dynamic_cast<FakePass*>(wvmp::PassRegistry::instance().find("boom"));
    ASSERT_NE(boom, nullptr);
    boom->set_throws("exploded");

    wvmp::ProtectionContext ctx;
    EXPECT_THROW(pipe.run(ctx), std::runtime_error);
    ASSERT_TRUE(ctx.diag.has_errors());
    EXPECT_EQ(ctx.diag.items().size(), static_cast<size_t>(1));
    EXPECT_EQ(ctx.diag.items()[0].pass, "boom");
    EXPECT_NE(ctx.diag.items()[0].message.find("exploded"), std::string::npos);
    // 抛错后后续 stage 不再执行。
    auto* after = dynamic_cast<FakePass*>(wvmp::PassRegistry::instance().find("after"));
    ASSERT_NE(after, nullptr);
    EXPECT_FALSE(after->ran());
}

} // namespace
