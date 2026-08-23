#include "section_builder.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <string>

namespace wvmp::passes {
namespace {

u16 rd16(const u8* p) {
    return static_cast<u16>(static_cast<u16>(p[0]) | (static_cast<u16>(p[1]) << 8));
}
u32 rd32(const u8* p) {
    return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) |
           (static_cast<u32>(p[2]) << 16) | (static_cast<u32>(p[3]) << 24);
}
void wr16(u8* p, u16 v) {
    p[0] = static_cast<u8>(v);
    p[1] = static_cast<u8>(v >> 8);
}
void wr32(u8* p, u32 v) {
    p[0] = static_cast<u8>(v);
    p[1] = static_cast<u8>(v >> 8);
    p[2] = static_cast<u8>(v >> 16);
    p[3] = static_cast<u8>(v >> 24);
}

u64 align_up(u64 v, u64 a) {
    return a == 0 ? v : ((v + a - 1) / a) * a;
}

[[noreturn]] void fail(const std::string& what) {
    throw std::runtime_error("add_sections: " + what);
}

} // namespace

std::vector<SectionPlacement> add_sections(std::vector<u8>& image,
                                           const std::vector<NewSection>& requests,
                                           u32 section_alignment, u32 file_alignment) {
    if (requests.empty()) return {};
    if (image.size() < 0x40) fail("image too small");
    if (image[0] != 'M' || image[1] != 'Z') fail("no MZ");
    const size_t nt = rd32(&image[0x3C]);
    if (nt + 24 + 64 > image.size()) fail("e_lfanew out of range");
    if (rd32(&image[nt]) != 0x0000'4550) fail("no PE signature");
    if (section_alignment == 0 || file_alignment == 0) fail("zero alignment");

    const u16 num_sections = rd16(&image[nt + 6]);
    const u16 opt_size = rd16(&image[nt + 20]);
    const size_t table = nt + 24 + opt_size;
    if (table + static_cast<size_t>(num_sections) * 40 > image.size())
        fail("section table out of range");

    // 头部可用上限：首个非零 PointerToRawData（原始数据前全是头的地盘）。
    size_t header_limit = image.size();
    u32 size_of_headers = rd32(&image[nt + 24 + 60]); // OptionalHeader.SizeOfHeaders
    if (size_of_headers != 0) header_limit = std::min<size_t>(header_limit, size_of_headers);
    for (u16 i = 0; i < num_sections; ++i) {
        const size_t sh = table + static_cast<size_t>(i) * 40;
        const u32 raw_ptr = rd32(&image[sh + 20]);
        if (raw_ptr != 0) header_limit = std::min<size_t>(header_limit, raw_ptr);
    }
    const size_t new_table_end = table + (static_cast<size_t>(num_sections) + requests.size()) * 40;
    if (new_table_end > header_limit)
        fail("no room in headers for " + std::to_string(requests.size()) + " more entries (" +
             std::to_string(new_table_end) + " > " + std::to_string(header_limit) + ")");

    // 既有节的虚拟/文件末端。
    u64 max_va_end = 0;
    u64 max_raw_end = 0;
    struct Existing {
        u32 va, len;
    };
    std::vector<Existing> existing;
    existing.reserve(num_sections);
    for (u16 i = 0; i < num_sections; ++i) {
        const size_t sh = table + static_cast<size_t>(i) * 40;
        const u32 vsize = rd32(&image[sh + 8]);
        const u32 va = rd32(&image[sh + 12]);
        const u32 rsize = rd32(&image[sh + 16]);
        const u32 rptr = rd32(&image[sh + 20]);
        existing.push_back({va, std::max(vsize, rsize)});
        if (va != 0) max_va_end = std::max<u64>(max_va_end, align_up(u64(va) + std::max(vsize, rsize), section_alignment));
        if (rptr != 0) max_raw_end = std::max<u64>(max_raw_end, u64(rptr) + rsize);
    }
    if (max_raw_end == 0) max_raw_end = align_up(header_limit, file_alignment);
    max_raw_end = std::max<u64>(max_raw_end, align_up(image.size(), file_alignment));

    // —— 全部校验先行 ——
    for (const auto& req : requests) {
        if (req.name.size() > 8) fail("section name '" + req.name + "' longer than 8 bytes");
        if (req.data.empty()) fail("section '" + req.name + "' has no data");
        if (req.requested_rva != 0) {
            const u64 begin = req.requested_rva;
            const u64 end = align_up(begin + req.data.size(), section_alignment);
            for (const auto& e : existing) {
                if (e.va == 0) continue;
                const u64 eb = e.va, ee = align_up(u64(e.va) + e.len, section_alignment);
                if (begin < ee && eb < end)
                    fail("requested RVA 0x" + std::to_string(req.requested_rva) + " overlaps existing section");
            }
            max_va_end = std::max(max_va_end, end);
        }
    }

    // —— 校验通过，落位计算 ——
    std::vector<SectionPlacement> placed;
    placed.reserve(requests.size());
    u64 next_rva = align_up(max_va_end, section_alignment);
    u64 next_raw = align_up(max_raw_end, file_alignment);
    for (const auto& req : requests) {
        SectionPlacement p;
        if (req.requested_rva != 0) {
            p.rva = req.requested_rva;
        } else {
            p.rva = static_cast<u32>(next_rva);
            next_rva = align_up(next_rva + req.data.size(), section_alignment);
        }
        p.file_offset = static_cast<u32>(next_raw);
        p.raw_size = static_cast<u32>(align_up(req.data.size(), file_alignment));
        next_raw += p.raw_size;
        placed.push_back(p);
    }

    // —— 修改字节 ——
    // 1) 数据区：文件尾补齐对齐垫片后写入各节数据 + 垫片。
    if (image.size() < max_raw_end)
        image.resize(static_cast<size_t>(max_raw_end), 0);
    for (size_t i = 0; i < requests.size(); ++i) {
        image.resize(placed[i].file_offset, 0);
        image.insert(image.end(), requests[i].data.begin(), requests[i].data.end());
        image.resize(static_cast<size_t>(placed[i].file_offset) + placed[i].raw_size, 0);
    }
    // 2) 节表：追加表项。
    for (size_t i = 0; i < requests.size(); ++i) {
        u8* sh = &image[table + (static_cast<size_t>(num_sections) + i) * 40];
        std::memset(sh, 0, 40);
        std::memcpy(sh, requests[i].name.data(),
                    std::min<size_t>(requests[i].name.size(), 8));
        wr32(sh + 8, static_cast<u32>(requests[i].data.size()));  // VirtualSize
        wr32(sh + 12, placed[i].rva);                              // VirtualAddress
        wr32(sh + 16, placed[i].raw_size);                         // SizeOfRawData
        wr32(sh + 20, placed[i].file_offset);                      // PointerToRawData
        wr32(sh + 36, requests[i].characteristics);                // Characteristics
    }
    // 3) 头部计数与镜像大小（auto/请求节统一按落位结果取最大端）。
    wr16(&image[nt + 6], static_cast<u16>(num_sections + requests.size()));
    u64 final_end = max_va_end;
    for (size_t i = 0; i < placed.size(); ++i)
        final_end = std::max<u64>(final_end,
                                  align_up(u64(placed[i].rva) + requests[i].data.size(),
                                           section_alignment));
    wr32(&image[nt + 24 + 56], static_cast<u32>(align_up(final_end, section_alignment)));
    return placed;
}

} // namespace wvmp::passes
