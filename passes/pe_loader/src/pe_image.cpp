#include "wvmp/passes/pe_loader/pe_image.hpp"

#include "wvmp/common/bytes.hpp"

#include <cstdio>
#include <limits>

namespace wvmp::passes {
namespace {

constexpr u16 kDosMagic = 0x5A4D;            // 'MZ'
constexpr u32 kPeSignature = 0x00004550;     // 'PE\0\0'
constexpr u16 kMachineX86 = 0x014C;
constexpr u16 kMachineX64 = 0x8664;
constexpr u16 kMagicPe32 = 0x10B;
constexpr u16 kMagicPe32Plus = 0x20B;

// 解析所需的最小 OptionalHeader 长度：覆盖到 FileAlignment @36+4。
constexpr u16 kMinOptionalHeaderSize = 64;

std::string hex16(u16 v) {
    char buf[8];
    std::snprintf(buf, sizeof(buf), "0x%04X", v);
    return std::string(buf);
}

PeImage parse_impl(std::span<const u8> image) {
    if (image.size() < 0x40) throw PeParseError("文件太小，容纳不下 DOS 头");

    // —— DOS 头：'MZ' + e_lfanew @0x3C ——
    ByteReader r{image.data(), image.size()};
    if (r.read_u16() != kDosMagic) throw PeParseError("DOS 头魔数不是 'MZ'");
    r.skip(0x3A);
    const u32 pe_off = r.read_u32();
    if (pe_off < 0x40 || u64(pe_off) + 24 > image.size())
        throw PeParseError("e_lfanew 越界（" + std::to_string(pe_off) + "）");

    // —— NT 头：签名 + FILE_HEADER（20 字节）——
    r.off = pe_off;
    if (r.read_u32() != kPeSignature) throw PeParseError("PE 签名不是 'PE\\0\\0'");

    PeImage img;
    img.nt_headers_offset = pe_off;
    img.machine = r.read_u16();
    if (img.machine != kMachineX86 && img.machine != kMachineX64)
        throw PeParseError("不支持的 Machine " + hex16(img.machine) +
                           "（仅支持 x86 0x014C / x64 0x8664）");
    img.num_sections = r.read_u16();
    r.skip(12);                        // TimeDateStamp / 符号表指针 / 符号数
    const u16 opt_size = r.read_u16(); // SizeOfOptionalHeader（nt+20）
    r.skip(2);                         // FILE Characteristics → 可选头起点 nt+24

    // —— OptionalHeader：Magic 判 PE32/PE32+；EntryPoint @16、
    //    SectionAlignment @32、FileAlignment @36（两种格式偏移一致）——
    if (opt_size < kMinOptionalHeaderSize)
        throw PeParseError("SizeOfOptionalHeader 过小（" + std::to_string(opt_size) + "）");
    if (u64(r.off) + opt_size > image.size())
        throw PeParseError("OptionalHeader 越界（镜像被截断）");
    const u16 magic = r.read_u16();
    if (magic == kMagicPe32Plus) img.is_pe32_plus = true;
    else if (magic != kMagicPe32) throw PeParseError("OptionalHeader 魔数不是 PE32/PE32+");
    r.skip(14);                     // 到 AddressOfEntryPoint @16
    img.entry_point_rva = r.read_u32();
    r.skip(12);                     // BaseOfCode / ImageBase（两种格式对齐到 @32）
    img.section_alignment = r.read_u32();
    img.file_alignment = r.read_u32();

    // —— 节表：每项 40 字节，位于 NT 头 + 24 + SizeOfOptionalHeader ——
    r.off = u64(pe_off) + 24 + opt_size;
    img.sections.reserve(img.num_sections);
    for (u16 i = 0; i < img.num_sections; ++i) {
        char raw_name[8];
        for (char& c : raw_name) c = static_cast<char>(r.read_u8());
        size_t len = 0;
        while (len < 8 && raw_name[len] != '\0') ++len;
        SectionInfo s;
        s.name.assign(raw_name, len);
        s.virtual_size = r.read_u32();
        s.virtual_addr = r.read_u32();
        s.raw_size = r.read_u32();
        s.raw_ptr = r.read_u32();
        r.skip(12);                 // 重定位/行号指针与计数
        s.characteristics = r.read_u32();
        img.sections.push_back(std::move(s));
    }
    return img;
}

} // namespace

u64 PeImage::headers_raw_size() const {
    u64 hs = std::numeric_limits<u64>::max();
    for (const SectionInfo& s : sections)
        if (s.raw_ptr != 0) hs = hs < s.raw_ptr ? hs : s.raw_ptr;
    return hs == std::numeric_limits<u64>::max() ? 0 : hs;
}

std::optional<u64> PeImage::rva_to_offset(u64 rva) const {
    // 文件头区间：头在文件开头线性铺开，RVA == 文件偏移。
    if (rva < headers_raw_size()) return rva;
    for (const SectionInfo& s : sections) {
        if (s.raw_size == 0) continue; // 纯未初始化节（.bss 等）：无文件映射
        if (rva < s.virtual_addr || rva >= s.virtual_addr + u64(s.raw_size)) continue;
        return u64(s.raw_ptr) + (rva - s.virtual_addr);
    }
    return std::nullopt;
}

std::optional<u64> PeImage::offset_to_rva(u64 offset) const {
    if (offset < headers_raw_size()) return offset;
    for (const SectionInfo& s : sections) {
        if (s.raw_size == 0) continue;
        if (offset < s.raw_ptr || offset >= u64(s.raw_ptr) + s.raw_size) continue;
        return u64(s.virtual_addr) + (offset - s.raw_ptr);
    }
    return std::nullopt;
}

const SectionInfo* PeImage::find_section(std::string_view name) const {
    for (const SectionInfo& s : sections)
        if (s.name == name) return &s;
    return nullptr;
}

PeImage parse_pe_image(std::span<const u8> image) {
    try {
        return parse_impl(image);
    } catch (const std::out_of_range&) {
        // ByteReader 越界兜底（理论上前置边界检查已覆盖，双保险）。
        throw PeParseError("PE 结构被截断");
    }
}

} // namespace wvmp::passes
