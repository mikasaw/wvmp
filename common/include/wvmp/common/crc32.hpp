#pragma once
#include "wvmp/common/types.hpp"

#include <array>
#include <cstddef>
#include <span>

namespace wvmp {

// MIT-464 (integrity_crc-v1)：IEEE CRC32（反射式，poly 0xEDB88320，
// init/final 全 1）——密文完整性校验的单一来源。
// 常数/算法消费方：integrity_crc pass（C++ 计算侧）与 stub_gen（asm 校验
// 块，bitwise 无表实现）——两侧必须同步改，并复跑 crc32 已知向量单测
//（"123456789" → 0xCBF43926，标准校验值）。
inline constexpr u32 kCrc32Poly = 0xEDB88320u;

[[nodiscard]] inline u32 crc32_update(u32 crc, std::span<const u8> data) {
    crc = ~crc;
    for (u8 b : data) {
        crc ^= b;
        for (int k = 0; k < 8; ++k)
            crc = (crc >> 1) ^ (kCrc32Poly & (0u - (crc & 1u)));
    }
    return ~crc;
}

[[nodiscard]] inline u32 crc32_of(std::span<const u8> data) {
    return crc32_update(0, data);
}

} // namespace wvmp
