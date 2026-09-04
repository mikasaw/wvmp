// MIT-458 (crypt-v1)：xor_chain codec 单测——往返、已知向量、头/尾保持、
// 契约面一致性。

#include "wvmp/regvm/codecs/xor_chain.hpp"

#include "wvmp/common/rng.hpp"

#include <gtest/gtest.h>

#include <cstring>
#include <string>

namespace {

namespace codecs = wvmp::regvm::codecs;
using wvmp::u32;
using wvmp::u8;

constexpr u32 kG = codecs::kXorChainMult;

// 解密参考实现（与 stub asm 模板同递推：state 吃密文）。
void decrypt_reference(u32 key0, std::vector<u8>& blob) {
    u32 state = key0;
    const size_t end = blob.size() & ~size_t{3};
    for (size_t off = codecs::kBlobHeaderBytes; off + 4 <= end; off += 4) {
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

// 32B 假头 + 4 个 dword 明文 + 2B 尾（尾不足 4B，防御面钉）。
std::vector<u8> make_sample_blob() {
    std::vector<u8> blob(32, 0xAA);  // 头：非零图案（加密不得触碰）
    const u32 words[] = {0x00000000u, 0xDEADBEEFu, 0x12345678u, 0xFFFFFFFFu};
    for (u32 w : words) {
        blob.push_back(static_cast<u8>(w));
        blob.push_back(static_cast<u8>(w >> 8));
        blob.push_back(static_cast<u8>(w >> 16));
        blob.push_back(static_cast<u8>(w >> 24));
    }
    blob.push_back(0x5A);
    blob.push_back(0xA5);
    return blob;
}

TEST(XorChainCodec, RoundTripPreservesStream) {
    const u32 key0 = 0x12345678u;
    auto plain = make_sample_blob();
    auto cipher = plain;
    codecs::XorChainCodec::encrypt_with_key(key0, cipher);
    EXPECT_NE(cipher, plain);  // 加密确实改变了流
    decrypt_reference(key0, cipher);
    EXPECT_EQ(cipher, plain);  // 解密还原逐字节
}

TEST(XorChainCodec, KnownVectorFirstWordAndChain) {
    // p0 = 0 → c0 = key0（首字链初态直通）；p1 = 0xFFFFFFFF →
    // state1 = key0*G + c0；c1 = p1 ^ state1。测试内按同一递推重算，
    // 钉住"链吃密文"的更新序（若 asm 模板或 C++ 侧改动递推序即红）。
    const u32 key0 = 0x0000002Au;
    std::vector<u8> blob(32, 0);
    const u32 p0 = 0u, p1 = 0xFFFFFFFFu;
    for (int b = 0; b < 4; ++b) blob.push_back(static_cast<u8>(p0 >> (8 * b)));
    for (int b = 0; b < 4; ++b) blob.push_back(static_cast<u8>(p1 >> (8 * b)));
    codecs::XorChainCodec::encrypt_with_key(key0, blob);
    auto word = [&](size_t off) {
        return static_cast<u32>(blob[off]) | (static_cast<u32>(blob[off + 1]) << 8) |
               (static_cast<u32>(blob[off + 2]) << 16) |
               (static_cast<u32>(blob[off + 3]) << 24);
    };
    EXPECT_EQ(word(32), key0);  // c0 = p0 ^ key0，p0=0
    const u32 state1 = key0 * kG + key0;
    EXPECT_EQ(word(36), p1 ^ state1);
}

TEST(XorChainCodec, HeaderAndTailUntouched) {
    const u32 key0 = 0xFFFF0000u;
    auto plain = make_sample_blob();
    auto cipher = plain;
    codecs::XorChainCodec::encrypt_with_key(key0, cipher);
    // 32B 头明文（stub_link x86 白名单 gate 与 read_blob 消费头）。
    EXPECT_EQ(std::memcmp(cipher.data(), plain.data(), 32), 0);
    // 尾部 <4B 明文（防御面：blob 流恒 8 对齐，正常不可达）。
    EXPECT_EQ(cipher[cipher.size() - 2], plain[plain.size() - 2]);
    EXPECT_EQ(cipher[cipher.size() - 1], plain[plain.size() - 1]);
}

TEST(XorChainCodec, ContractFaceUsesOneRngDraw) {
    // encrypt_stream（BytecodeCodec 契约面）恰消费一个 next() 作 key0，
    // 与 encrypt_with_key 直连面产出逐字节一致（crypt pass 直连 + 记录
    // 同一 key0 的实现锚）。
    wvmp::Rng rng(0xC0FFEE);
    const u32 key0 = static_cast<u32>(rng.next());
    auto a = make_sample_blob();
    auto b = make_sample_blob();
    codecs::XorChainCodec::encrypt_with_key(key0, a);
    codecs::XorChainCodec codec;
    wvmp::Rng rng2(0xC0FFEE);  // encrypt_stream 内部消费首个 next() 作 key0
    codec.encrypt_stream(rng2, b);
    EXPECT_EQ(a, b);
}

TEST(CodecFactory, XorChainRegisteredUnknownNull) {
    auto c = codecs::create_codec("xor_chain");
    ASSERT_NE(c, nullptr);
    EXPECT_EQ(c->name(), "xor_chain");
    EXPECT_EQ(codecs::create_codec("no_such_codec"), nullptr);
}

} // namespace
