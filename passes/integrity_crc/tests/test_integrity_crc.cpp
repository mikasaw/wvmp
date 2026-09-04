// MIT-464 (integrity_crc-v1)：CRC32 已知向量 + integrity pass plan 写入 +
// 篡改检测（密文单字节翻转被 CRC 捕获）。

#include "wvmp/passes/integrity_crc/integrity_crc_pass.hpp"

#include "wvmp/passes/crypt/crypt_plan.hpp"
#include "wvmp/passes/crypt/crypt_pass.hpp"
#include "wvmp/common/crc32.hpp"
#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/regvm/codecs/xor_chain.hpp"
#include "wvmp/regvm/isa/blob.hpp"

#include <gtest/gtest.h>

#include <cstring>
#include <vector>

namespace {

using wvmp::u32;
using wvmp::u8;

TEST(Crc32, KnownVector123456789) {
    // 标准校验值：CRC32("123456789") = 0xCBF43926（IEEE 反射式金标）。
    const std::vector<u8> data = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
    EXPECT_EQ(wvmp::crc32_of(data), 0xCBF43926u);
}

TEST(Crc32, EmptyAndIncrementalConsistency) {
    EXPECT_EQ(wvmp::crc32_of({}), 0u);  // 空 = init~0 再取反 = 0
    const std::vector<u8> data = {1, 2, 3, 4, 5, 6, 7, 8};
    const u32 whole = wvmp::crc32_of(data);
    // 分两段 update ≡ 一次全量（crc32_update 语义）。
    const u32 half = wvmp::crc32_update(
        wvmp::crc32_update(0, std::span<const u8>(data.data(), 4)),
        std::span<const u8>(data.data() + 4, 4));
    EXPECT_EQ(whole, half);
}

// 造一个含真 blob（make_blob + xor_chain 加密 + 8B 尾区）的 plan 条目。
wvmp::passes::crypt::CryptedFunction make_crypted(const std::string& name,
                                                  size_t vfs_index) {
    std::vector<u8> stream(static_cast<size_t>(8) * 5, 0x42);
    const auto blob =
        wvmp::regvm::isa::make_blob(wvmp::ir::Arch::X64, 0, std::move(stream));
    wvmp::passes::crypt::CryptedFunction e;
    e.vfs_index = vfs_index;
    e.name = name;
    e.key0 = 0xCAFEBABEu;
    std::vector<u8> serialized;
    wvmp::ByteWriter w(serialized);
    wvmp::regvm::isa::write_blob(w, blob);
    e.encrypted_blob = std::move(serialized);
    e.stream_bytes = e.encrypted_blob.size() - 32;
    wvmp::regvm::codecs::XorChainCodec::encrypt_with_key(e.key0, e.encrypted_blob);
    // 尾区（crypt pass 布局）。
    e.encrypted_blob.push_back(1);
    e.encrypted_blob.push_back(0);
    e.encrypted_blob.push_back(0);
    e.encrypted_blob.push_back(0);
    for (int b = 0; b < 4; ++b) e.encrypted_blob.push_back(0);  // crc 槽（待写）
    return e;
}

TEST(IntegrityCrcPass, WritesCrcIntoTrailerAndEntry) {
    wvmp::ProtectionContext ctx;
    auto& plan = ctx.slot<wvmp::passes::crypt::CryptPlan>(wvmp::kCryptPlan);
    plan.algo = "xor_chain";
    plan.functions.push_back(make_crypted("fn0", 0));

    const auto& e = plan.functions[0];
    const std::vector<u8> cipher(e.encrypted_blob.data() + 32, e.encrypted_blob.data() + 32 + e.stream_bytes);
    const u32 expect = wvmp::crc32_of(cipher);

    wvmp::passes::IntegrityCrcPass pass;
    pass.run(ctx);

    ASSERT_TRUE(e.has_crc);
    EXPECT_EQ(e.crc32, expect);
    // 尾区 crc 槽（流起点 + stream_bytes + 4）已补丁。
    u32 trailer_crc = 0;
    for (int b = 0; b < 4; ++b)
        trailer_crc |= static_cast<u32>(e.encrypted_blob[32 + e.stream_bytes + 4 + b]) << (8 * b);
    EXPECT_EQ(trailer_crc, expect);
    // flag 仍在（1）。
    EXPECT_EQ(e.encrypted_blob[32 + e.stream_bytes], 1);
    EXPECT_FALSE(ctx.diag.has_errors());
}

// 辅助：独立 ctx 构造（避免跨用例共享状态）。
static wvmp::ProtectionContext make_ctx_with_plan() {
    wvmp::ProtectionContext ctx;
    auto& plan = ctx.slot<wvmp::passes::crypt::CryptPlan>(wvmp::kCryptPlan);
    plan.algo = "xor_chain";
    plan.functions.push_back(make_crypted("fn0", 0));
    return ctx;
}

TEST(IntegrityCrcPass, SingleByteFlipBreaksCrc) {
    auto ctx = make_ctx_with_plan();
    wvmp::passes::IntegrityCrcPass pass;
    pass.run(ctx);
    const auto* plan = ctx.find_slot<wvmp::passes::crypt::CryptPlan>(wvmp::kCryptPlan);
    ASSERT_NE(plan, nullptr);
    const u32 orig_crc = plan->functions[0].crc32;
    // 翻转密文中段 1 字节（非 const 视图）。
    auto& blob = const_cast<wvmp::passes::crypt::CryptPlan*>(plan)->functions[0].encrypted_blob;
    blob[32 + 20] ^= 0x01;
    // 重算 CRC ≠ 原值（篡改可检测）。
    const u32 recomputed =
        wvmp::crc32_of(std::span<const u8>(blob.data() + 32,
                                           static_cast<size_t>(plan->functions[0].stream_bytes)));
    EXPECT_NE(recomputed, orig_crc);
}

} // namespace
