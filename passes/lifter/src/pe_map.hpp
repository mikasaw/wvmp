// 最小 PE RVA ↔ 文件偏移 映射（lifter 私有，不属于契约）。
//
// 只解析 DOS 头 / NT 头 / 节表，供 lifter 把 FunctionRegion 的 RVA 区间
// 映射到 ctx.image 的文件偏移做线性反汇编。
// TODO(M1-integration): use PeImage from pe_loader —— 此处与 P2 泳道
// （pe_loader）存在约 50 行的临时重复，M1 集成时统一删除本文件。
#pragma once

#include "wvmp/common/types.hpp"

#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace wvmp::passes::lifter {

struct PeSectionMap {
    struct Section {
        u32 virtual_size = 0;
        u32 rva = 0;
        u32 raw_size = 0;
        u32 raw_offset = 0;
    };

    std::vector<Section> sections;
    u64 image_base = 0; // 可选头 ImageBase（仅诊断用）
    bool valid = false;

    // 解析 image 的 DOS/NT 头 + 节表；结构不合法时 valid=false。
    static PeSectionMap parse(std::span<const u8> image);

    // 把 [begin_rva, end_rva) 完整映射进单个节的原始数据区。
    // 成功返回 {文件偏移, 字节长度}，失败返回 nullopt（跨节 / 落在
    // 未初始化数据区 / 越界）。
    std::optional<std::pair<u64, u64>> map_rva_range(u64 begin_rva, u64 end_rva) const;

    // 单点映射（诊断/调试用）。
    std::optional<u64> rva_to_offset(u64 rva) const;
};

} // namespace wvmp::passes::lifter
