#include "wvmp/regvm/codecs/xor_chain.hpp"

namespace wvmp::regvm::codecs {

void XorChainCodec::encrypt_with_key(u32 key0, std::vector<u8>& blob) {
    u32 state = key0;
    // 加密序：k = state_old；c = 字 ^ k；state = state * G + c（链吃密文）。
    // 覆盖 [kBlobHeaderBytes, blob.size() & ~3u)——尾部不足 4B 保持明文。
    const size_t end = blob.size() & ~size_t{3};
    for (size_t off = kBlobHeaderBytes; off + 4 <= end; off += 4) {
        const u32 word = static_cast<u32>(blob[off]) |
                         (static_cast<u32>(blob[off + 1]) << 8) |
                         (static_cast<u32>(blob[off + 2]) << 16) |
                         (static_cast<u32>(blob[off + 3]) << 24);
        const u32 cipher = word ^ state;
        state = state * kXorChainMult + cipher;
        blob[off] = static_cast<u8>(cipher);
        blob[off + 1] = static_cast<u8>(cipher >> 8);
        blob[off + 2] = static_cast<u8>(cipher >> 16);
        blob[off + 3] = static_cast<u8>(cipher >> 24);
    }
}

u32 XorChainCodec::encrypt_fetch_with_key(u32 key0, std::vector<u8>& blob) {
    // 位置键流（与解释器 dispatch 织入侧同式）：K_i = key0 + i*STEP，字 i
    // 的低/高 u32 同 xor K_i。仅依赖字序 → 跳转/循环/imm aux 字任意取指序
    // 全兼容；初态写头 seed（offset 16，解释器侧键基）。
    constexpr u32 kStep = 0x9E3779B1u;
    u32 word_index = 0;
    for (size_t off = kBlobHeaderBytes; off + 8 <= (blob.size() & ~size_t{7});
         off += 8, ++word_index) {
        const u32 key = key0 + word_index * kStep;
        for (size_t k = 0; k < 2; ++k) {
            const size_t o = off + k * 4;
            const u32 word = static_cast<u32>(blob[o]) |
                             (static_cast<u32>(blob[o + 1]) << 8) |
                             (static_cast<u32>(blob[o + 2]) << 16) |
                             (static_cast<u32>(blob[o + 3]) << 24);
            const u32 cipher = word ^ key;
            blob[o] = static_cast<u8>(cipher);
            blob[o + 1] = static_cast<u8>(cipher >> 8);
            blob[o + 2] = static_cast<u8>(cipher >> 16);
            blob[o + 3] = static_cast<u8>(cipher >> 24);
        }
    }
    blob[16] = static_cast<u8>(key0);
    blob[17] = static_cast<u8>(key0 >> 8);
    blob[18] = static_cast<u8>(key0 >> 16);
    blob[19] = static_cast<u8>(key0 >> 24);
    return key0;
}

void XorChainCodec::decrypt_fetch_with_key(u32 key0, std::vector<u8>& blob) {
    // 与加密同式（xor 对合）：K_i = key0 + i*STEP。
    constexpr u32 kStep = 0x9E3779B1u;
    u32 word_index = 0;
    for (size_t off = kBlobHeaderBytes; off + 8 <= (blob.size() & ~size_t{7});
         off += 8, ++word_index) {
        const u32 key = key0 + word_index * kStep;
        for (size_t k = 0; k < 2; ++k) {
            const size_t o = off + k * 4;
            const u32 cipher = static_cast<u32>(blob[o]) |
                               (static_cast<u32>(blob[o + 1]) << 8) |
                               (static_cast<u32>(blob[o + 2]) << 16) |
                               (static_cast<u32>(blob[o + 3]) << 24);
            const u32 word = cipher ^ key;
            blob[o] = static_cast<u8>(word);
            blob[o + 1] = static_cast<u8>(word >> 8);
            blob[o + 2] = static_cast<u8>(word >> 16);
            blob[o + 3] = static_cast<u8>(word >> 24);
        }
    }
}

std::unique_ptr<vm::BytecodeCodec> create_codec(std::string_view name) {
    if (name == "xor_chain") return std::make_unique<XorChainCodec>();
    return nullptr;
}

} // namespace wvmp::regvm::codecs
