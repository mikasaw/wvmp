#include "pe_map.hpp"

namespace wvmp::passes::lifter {

namespace {

u16 rd_u16(const u8* p) { return static_cast<u16>(p[0]) | (static_cast<u16>(p[1]) << 8); }
u32 rd_u32(const u8* p) {
    return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) | (static_cast<u32>(p[2]) << 16) |
           (static_cast<u32>(p[3]) << 24);
}
u64 rd_u64(const u8* p) {
    return static_cast<u64>(rd_u32(p)) | (static_cast<u64>(rd_u32(p + 4)) << 32);
}

bool read_at(std::span<const u8> img, u64 off, u64 len) {
    return off <= img.size() && len <= img.size() - off;
}

} // namespace

PeSectionMap PeSectionMap::parse(std::span<const u8> image) {
    PeSectionMap map;

    // DOS 头：'MZ' + e_lfanew @0x3C
    if (!read_at(image, 0, 0x40) || image[0] != 'M' || image[1] != 'Z') return map;
    const u32 pe_off = rd_u32(image.data() + 0x3C);

    // NT 头：'PE\0\0' + COFF 头（20 字节）
    if (!read_at(image, pe_off, 24) || rd_u32(image.data() + pe_off) != 0x00004550u) return map;
    const u8* coff = image.data() + pe_off + 4;
    const u16 num_sections = rd_u16(coff + 2);
    const u16 size_optional = rd_u16(coff + 16);

    // 可选头：Magic 判 PE32 / PE32+，取 ImageBase
    const u64 opt_off = pe_off + 4 + 20;
    if (!read_at(image, opt_off, size_optional) || size_optional < 0x40) return map;
    const u16 magic = rd_u16(image.data() + opt_off);
    if (magic == 0x20B) {          // PE32+
        map.image_base = rd_u64(image.data() + opt_off + 24);
    } else if (magic == 0x10B) {   // PE32
        map.image_base = rd_u32(image.data() + opt_off + 28);
    } else {
        return map;
    }

    // 节表：每项 40 字节
    const u64 table_off = opt_off + size_optional;
    if (!read_at(image, table_off, static_cast<u64>(num_sections) * 40)) return map;
    map.sections.reserve(num_sections);
    for (u16 i = 0; i < num_sections; ++i) {
        const u8* sh = image.data() + table_off + static_cast<u64>(i) * 40;
        Section s;
        s.virtual_size = rd_u32(sh + 8);  // VirtualSize
        s.rva = rd_u32(sh + 12);          // VirtualAddress
        s.raw_size = rd_u32(sh + 16);     // SizeOfRawData
        s.raw_offset = rd_u32(sh + 20);   // PointerToRawData
        map.sections.push_back(s);
    }

    map.valid = true;
    return map;
}

std::optional<std::pair<u64, u64>> PeSectionMap::map_rva_range(u64 begin_rva, u64 end_rva) const {
    if (!valid || begin_rva >= end_rva) return std::nullopt;
    const u64 len = end_rva - begin_rva;
    for (const Section& s : sections) {
        if (s.raw_size == 0) continue; // 未映射节（纯 .bss 等）
        if (begin_rva < s.rva || begin_rva >= s.rva + s.raw_size) continue;
        const u64 in_section = begin_rva - s.rva;
        if (in_section + len > s.raw_size) return std::nullopt; // 跨节 / 越界
        return std::make_pair(s.raw_offset + in_section, len);
    }
    return std::nullopt;
}

std::optional<u64> PeSectionMap::rva_to_offset(u64 rva) const {
    auto r = map_rva_range(rva, rva + 1);
    if (!r) return std::nullopt;
    return r->first;
}

} // namespace wvmp::passes::lifter
