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

std::unique_ptr<vm::BytecodeCodec> create_codec(std::string_view name) {
    if (name == "xor_chain") return std::make_unique<XorChainCodec>();
    return nullptr;
}

} // namespace wvmp::regvm::codecs
