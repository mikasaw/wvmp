// MIT-458 (crypt-v1)：crypt pass 单测——plan 构造、头/尾保持、往返、
// 空 vfs 跳过、确定性（同 seed 同密钥）。

#include "wvmp/passes/crypt/crypt_pass.hpp"

#include "wvmp/common/bytes.hpp"

#include "wvmp/passes/crypt/crypt_plan.hpp"
#include "wvmp/passes/virtualize/virtualize_pass.hpp"
#include "wvmp/regvm/codecs/xor_chain.hpp"
#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/protect_levels.hpp"
#include "wvmp/regvm/isa/blob.hpp"

#include <gtest/gtest.h>

#include <cstring>
#include <vector>

namespace {

namespace isa = wvmp::regvm::isa;
using wvmp::u32;
using wvmp::u8;

constexpr u32 kG = wvmp::regvm::codecs::kXorChainMult;

void decrypt_reference(u32 key0, std::vector<u8>& blob) {
    u32 state = key0;
    const size_t end = blob.size() & ~size_t{3};
    for (size_t off = 32; off + 4 <= end; off += 4) {
        const u32 c = static_cast<u32>(blob[off]) |
                      (static_cast<u32>(blob[off + 1]) << 8) |
                      (static_cast<u32>(blob[off + 2]) << 16) |
                      (static_cast<u32>(blob[off + 3]) << 24);
        const u32 k = state;
        state = state * kG + c;
        const u32 p = c ^ k;
        blob[off] = static_cast<u8>(p);
        blob[off + 1] = static_cast<u8>(p >> 8);
        blob[off + 2] = static_cast<u8>(p >> 16);
        blob[off + 3] = static_cast<u8>(p >> 24);
    }
}

// 造一个 kVmProgram 槽：两个 VM 程序（真 make_blob/write_blob 序列化：
// 32B 头 + 8xN 流）。
void fill_vfs(wvmp::ProtectionContext& ctx) {
    auto& vfs = ctx.slot<std::vector<wvmp::passes::VirtualizedFunction>>(wvmp::kVmProgram);
    for (int i = 0; i < 2; ++i) {
        const wvmp::ir::Arch arch = i == 0 ? wvmp::ir::Arch::X64 : wvmp::ir::Arch::X86;
        std::vector<u8> stream(static_cast<size_t>(8) * (3 + i),
                               static_cast<u8>(0x11 * (i + 1)));
        const isa::VmBlob blob = isa::make_blob(arch, 0, std::move(stream));
        wvmp::passes::VirtualizedFunction vf;
        vf.name = "fn" + std::to_string(i);
        vf.begin_rva = 0x1000 + static_cast<wvmp::u64>(i) * 0x100;
        std::vector<u8> serialized;
        wvmp::ByteWriter w(serialized);
        isa::write_blob(w, blob);
        vf.program.bytecode = std::move(serialized);
        vfs.push_back(std::move(vf));
    }
}

TEST(CryptPass, BuildsPlanAndPreservesHeader) {
    wvmp::ProtectionContext ctx;
    fill_vfs(ctx);
    const auto* vfs =
        ctx.find_slot<std::vector<wvmp::passes::VirtualizedFunction>>(wvmp::kVmProgram);
    const std::vector<u8> plain[2] = {(*vfs)[0].program.bytecode,
                                      (*vfs)[1].program.bytecode};

    wvmp::passes::CryptPass pass;
    ctx.seed = 12345;
    pass.run(ctx);

    const auto* plan = ctx.find_slot<wvmp::passes::crypt::CryptPlan>(wvmp::kCryptPlan);
    ASSERT_NE(plan, nullptr);
    EXPECT_EQ(plan->algo, "xor_chain");
    ASSERT_EQ(plan->functions.size(), size_t{2});
    for (size_t i = 0; i < plan->functions.size(); ++i) {
        const auto& e = plan->functions[i];
        EXPECT_EQ(e.vfs_index, i);
        EXPECT_NE(e.key0, 0u);  // mt19937_64 首抽非零（统计性；本 seed 实测恒真）
        const std::vector<u8>& own_plain = plain[i];  // 各条目对各自明文配对
        // 头 32B 明文保持。
        EXPECT_EQ(std::memcmp(e.encrypted_blob.data(), own_plain.data(), 32), 0);
        // 尾旗标 = 8B：flag=1 + reserved=0。
        ASSERT_GE(e.encrypted_blob.size(), own_plain.size() + 8);
        const size_t flag_off = 32 + e.stream_bytes;
        const u32 flag = static_cast<u32>(e.encrypted_blob[flag_off]) |
                         (static_cast<u32>(e.encrypted_blob[flag_off + 1]) << 8) |
                         (static_cast<u32>(e.encrypted_blob[flag_off + 2]) << 16) |
                         (static_cast<u32>(e.encrypted_blob[flag_off + 3]) << 24);
        EXPECT_EQ(flag, wvmp::passes::crypt::kFlagEncrypted);
        // 往返：参考解密还原明文流。
        std::vector<u8> roundtrip = e.encrypted_blob;
        roundtrip.resize(32 + e.stream_bytes);  // 去掉尾旗标再解
        decrypt_reference(e.key0, roundtrip);
        ASSERT_EQ(roundtrip.size(), own_plain.size());
        EXPECT_EQ(std::memcmp(roundtrip.data() + 32, own_plain.data() + 32,
                              own_plain.size() - 32), 0);
        EXPECT_EQ(e.stream_bytes, static_cast<wvmp::u64>(own_plain.size() - 32));
    }
    EXPECT_FALSE(ctx.diag.has_errors());
}

TEST(CryptPass, DeterministicPerSeed) {
    // 同 seed 两次 run：plan 密钥与密文逐字节一致（可复现纪律）；
    // 换 seed 密钥必变（每目标嵌入的差异化来源）。
    std::vector<u8> first_blob;
    u32 first_key = 0;
    for (int run = 0; run < 2; ++run) {
        wvmp::ProtectionContext ctx;
        ctx.seed = 42;
        fill_vfs(ctx);
        wvmp::passes::CryptPass pass;
        pass.run(ctx);
        const auto* plan =
            ctx.find_slot<wvmp::passes::crypt::CryptPlan>(wvmp::kCryptPlan);
        ASSERT_NE(plan, nullptr);
        if (run == 0) {
            first_blob = plan->functions[0].encrypted_blob;
            first_key = plan->functions[0].key0;
        } else {
            EXPECT_EQ(plan->functions[0].key0, first_key);
            EXPECT_EQ(plan->functions[0].encrypted_blob, first_blob);
        }
    }
    wvmp::ProtectionContext ctx;
    ctx.seed = 43;
    fill_vfs(ctx);
    wvmp::passes::CryptPass pass;
    pass.run(ctx);
    const auto* plan = ctx.find_slot<wvmp::passes::crypt::CryptPlan>(wvmp::kCryptPlan);
    ASSERT_NE(plan, nullptr);
    EXPECT_NE(plan->functions[0].key0, first_key);
}

TEST(CryptPass, EmptyProgramSlotSkips) {
    wvmp::ProtectionContext ctx;
    wvmp::passes::CryptPass pass;
    pass.run(ctx);
    EXPECT_FALSE(ctx.has_slot(wvmp::kCryptPlan));
    bool has_warn = false;
    for (const auto& d : ctx.diag.items())
        if (d.severity == wvmp::Severity::Warning) has_warn = true;
    EXPECT_TRUE(has_warn);
    EXPECT_FALSE(ctx.diag.has_errors());
}

} // namespace

TEST(CryptPass, NameRuleCryptFalseExemptsFunction) {
    // MIT-461: name 选择器 crypt=false → 该函数不进 plan（豁免），
    // 其他函数照常加密。
    wvmp::ProtectionContext ctx;
    ctx.seed = 99;
    fill_vfs(ctx);
    wvmp::ProtectRules rules;
    wvmp::FunctionProtectRule rule;
    rule.has_name = true;
    rule.name = "fn0";
    rule.has_crypt = true;
    rule.crypt = false;
    rules.functions.push_back(rule);
    ctx.slot<wvmp::ProtectRules>(wvmp::kProtectRules) = rules;

    wvmp::passes::CryptPass pass;
    pass.run(ctx);
    const auto* plan = ctx.find_slot<wvmp::passes::crypt::CryptPlan>(wvmp::kCryptPlan);
    ASSERT_NE(plan, nullptr);
    ASSERT_EQ(plan->functions.size(), size_t{1});
    EXPECT_EQ(plan->functions[0].name, "fn1");
}

TEST(CryptPass, ExemptionDoesNotShiftKeyStream) {
    // MIT-461 验收 REJECT 项修复钉：密钥流按 vfs 序无条件消费（豁免函数
    // 也消费一次）——加一条豁免规则后，其余已加密函数的 key0 与无豁免
    // 基线逐字节一致（"只加豁免不改密钥"性质）。
    // 基线：无规则。
    wvmp::ProtectionContext base;
    base.seed = 99;
    fill_vfs(base);
    wvmp::passes::CryptPass p0;
    p0.run(base);
    const auto* base_plan =
        base.find_slot<wvmp::passes::crypt::CryptPlan>(wvmp::kCryptPlan);
    ASSERT_NE(base_plan, nullptr);
    ASSERT_EQ(base_plan->functions.size(), size_t{2});
    const u32 key_fn0 = base_plan->functions[0].key0;
    const u32 key_fn1 = base_plan->functions[1].key0;

    // 加豁免 fn0 → fn1 的 key0 必须不变（密钥流序未被豁免扰动）。
    wvmp::ProtectionContext ctx;
    ctx.seed = 99;
    fill_vfs(ctx);
    wvmp::ProtectRules rules;
    wvmp::FunctionProtectRule rule;
    rule.has_name = true;
    rule.name = "fn0";
    rule.has_crypt = true;
    rule.crypt = false;
    rules.functions.push_back(rule);
    ctx.slot<wvmp::ProtectRules>(wvmp::kProtectRules) = rules;
    wvmp::passes::CryptPass pass;
    pass.run(ctx);
    const auto* plan = ctx.find_slot<wvmp::passes::crypt::CryptPlan>(wvmp::kCryptPlan);
    ASSERT_NE(plan, nullptr);
    ASSERT_EQ(plan->functions.size(), size_t{1});
    EXPECT_EQ(plan->functions[0].name, "fn1");
    EXPECT_EQ(plan->functions[0].key0, key_fn1) << "豁免不应改变后续函数密钥";
    EXPECT_NE(plan->functions[0].key0, key_fn0);
}
