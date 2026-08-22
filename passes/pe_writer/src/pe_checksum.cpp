#include "pe_checksum.hpp"

namespace wvmp::passes {

u32 pe_checksum(std::span<const u8> img, size_t chk_off) {
    u32 sum = 0;
    const auto add_word = [&sum](u32 w) {
        sum += w;
        if (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16); // 折进位，回到 16 位内
    };

    const size_t n = img.size();
    size_t i = 0;
    while (i + 1 < n) {
        if (i == chk_off) {
            i += 4; // 跳过 CheckSum dword（4 字节 = 2 个 u16）
            continue;
        }
        add_word(u32(img[i]) | (u32(img[i + 1]) << 8));
        i += 2;
    }
    if (i < n) add_word(img[i]); // 奇数长度：末字节高字节补 0

    return sum + u32(n); // 尾加文件总长（u32，不再折位）
}

} // namespace wvmp::passes
