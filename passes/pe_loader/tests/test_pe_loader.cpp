// pe_loader 泳道测试：
//  1) 手工拼装最小合法 PE（DOS+NT+节表）→ 解析字段断言；
//  2) rva_to_offset / offset_to_rva 边界（节内 / 节间隙 / 头部 / bss）；
//  3) pass 级：文件读入 + 槽存储 + 各类畸形输入的失败路径。

#include "wvmp/passes/pe_loader/pe_image.hpp"
#include "wvmp/passes/pe_loader/pe_loader_pass.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <span>
#include <vector>

namespace {
namespace fs = std::filesystem;

using wvmp::u16;
using wvmp::u32;
using wvmp::u64;
using wvmp::u8;
using wvmp::ProtectionContext;

constexpr u16 kMachineX86 = 0x014C;
constexpr u16 kMachineX64 = 0x8664;

void put16(std::vector<u8>& v, size_t o, u16 x) {
    v[o] = u8(x);
    v[o + 1] = u8(x >> 8);
}
void put32(std::vector<u8>& v, size_t o, u32 x) {
    for (int i = 0; i < 4; ++i) v[o + i] = u8(x >> (8 * i));
}

// 手工拼最小合法 PE：DOS 头(0x00) + NT 头(0x40) + 节表 + ".text" 原始数据。
// 布局：[0x000,0x200) 头部 | [0x200,0x400) .text（VA 0x1000，VS=SR=0x200）。
// image_base 默认 0x400000；PE32+ 8B 字段写入, PE32 4B 字段写入。
std::vector<u8> build_minimal_pe(bool pe32_plus, u16 machine, u64 image_base = 0x400000ull) {
    const u16 opt_size = pe32_plus ? 240 : 224; // PE32+ 240 / PE32 224
    const size_t nt = 0x40;
    const size_t opt = nt + 24;
    const size_t sec = opt + opt_size;
    std::vector<u8> img(0x400, 0);

    // DOS 头
    put16(img, 0x00, 0x5A4D); // 'MZ'
    put32(img, 0x3C, u32(nt)); // e_lfanew
    // NT 头：签名 + FILE_HEADER
    put32(img, nt + 0, 0x00004550); // 'PE\0\0'
    put16(img, nt + 4, machine);    // Machine
    put16(img, nt + 6, 1);          // NumberOfSections
    put16(img, nt + 20, opt_size);  // SizeOfOptionalHeader
    // OptionalHeader（EntryPoint @16 / ImageBase @24 (PE32+) / @24 (PE32) /
    // SectionAlignment @32 / FileAlignment @36, 两种格式对齐到 @32）
    put16(img, opt + 0, pe32_plus ? 0x20B : 0x10B);
    put32(img, opt + 16, 0x1234);  // AddressOfEntryPoint
    put32(img, opt + 20, 0x1000);  // BaseOfCode
    if (pe32_plus) {
        for (int i = 0; i < 8; ++i) img[opt + 24 + i] = u8(image_base >> (8 * i));
    } else {
        put32(img, opt + 24, u32(image_base));
    }
    put32(img, opt + 32, 0x1000);  // SectionAlignment
    put32(img, opt + 36, 0x200);   // FileAlignment
    // 节表：".text"
    std::memcpy(&img[sec], ".text", 5);
    put32(img, sec + 8, 0x200);        // VirtualSize
    put32(img, sec + 12, 0x1000);      // VirtualAddress
    put32(img, sec + 16, 0x200);       // SizeOfRawData
    put32(img, sec + 20, 0x200);       // PointerToRawData
    put32(img, sec + 36, 0x60000020);  // CNT_CODE|MEM_EXECUTE|MEM_READ
    return img;
}

// 最小 x64 PE 追加一个纯 .bss 节（raw_size=0，VA 0x2000，VS 0x100）。
std::vector<u8> build_pe_with_bss() {
    std::vector<u8> img = build_minimal_pe(true, kMachineX64);
    const size_t nt = 0x40;
    const size_t s2 = nt + 24 + 240 + 40; // 第二节表项
    put16(img, nt + 6, 2);                // NumberOfSections = 2
    std::memcpy(&img[s2], ".bss", 4);
    put32(img, s2 + 8, 0x100);       // VirtualSize
    put32(img, s2 + 12, 0x2000);     // VirtualAddress
    put32(img, s2 + 16, 0);          // SizeOfRawData = 0（未初始化）
    put32(img, s2 + 20, 0);          // PointerToRawData = 0
    put32(img, s2 + 36, 0xC0000080); // MEM_READ|MEM_WRITE|CNT_UNINITIALIZED
    return img;
}

fs::path write_temp(const std::string& name, std::span<const u8> bytes) {
    fs::path dir = fs::temp_directory_path() / "wvmp_pe_loader_tests";
    fs::create_directories(dir);
    fs::path p = dir / name;
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
    return p;
}

} // namespace

// —— 解析字段断言 ————————————————————————————————————————————————

TEST(PeImageParse, MinimalX64) {
    const auto bytes = build_minimal_pe(true, kMachineX64, 0x0000000140000000ull);
    const wvmp::passes::PeImage img = wvmp::passes::parse_pe_image(bytes);

    EXPECT_TRUE(img.is_pe32_plus);
    EXPECT_EQ(img.machine, kMachineX64);
    EXPECT_EQ(img.entry_point_rva, 0x1234u);
    EXPECT_EQ(img.image_base, 0x0000000140000000ull);  // PE32+ 8B ImageBase
    EXPECT_EQ(img.section_alignment, 0x1000u);
    EXPECT_EQ(img.file_alignment, 0x200u);
    EXPECT_EQ(img.num_sections, u16(1));
    EXPECT_EQ(img.nt_headers_offset, 0x40u);

    ASSERT_EQ(img.sections.size(), 1u);
    const auto& s = img.sections[0];
    EXPECT_EQ(s.name, ".text");
    EXPECT_EQ(s.characteristics, 0x60000020u);
    EXPECT_EQ(s.virtual_size, 0x200u);
    EXPECT_EQ(s.virtual_addr, 0x1000u);
    EXPECT_EQ(s.raw_size, 0x200u);
    EXPECT_EQ(s.raw_ptr, 0x200u);
}

TEST(PeImageParse, MinimalX86) {
    const auto bytes = build_minimal_pe(false, kMachineX86, 0x400000u);
    const wvmp::passes::PeImage img = wvmp::passes::parse_pe_image(bytes);

    EXPECT_FALSE(img.is_pe32_plus);
    EXPECT_EQ(img.machine, kMachineX86);
    EXPECT_EQ(img.image_base, 0x400000u);  // PE32 4B ImageBase
    EXPECT_EQ(img.num_sections, u16(1));
    EXPECT_EQ(img.sections[0].name, ".text");
}

// —— rva_to_offset 边界 ————————————————————————————————————————————

TEST(PeImageMap, RvaToOffsetBoundaries) {
    const wvmp::passes::PeImage img =
        wvmp::passes::parse_pe_image(build_minimal_pe(true, kMachineX64));

    // 头部区间恒等映射（< 首节 PointerToRawData = 0x200）
    EXPECT_EQ(img.rva_to_offset(0), std::optional<u64>(0));
    EXPECT_EQ(img.rva_to_offset(0x1FF), std::optional<u64>(0x1FF));
    // 节内映射
    EXPECT_EQ(img.rva_to_offset(0x1000), std::optional<u64>(0x200));
    EXPECT_EQ(img.rva_to_offset(0x1001), std::optional<u64>(0x201));
    EXPECT_EQ(img.rva_to_offset(0x11FF), std::optional<u64>(0x3FF)); // raw 最后一个字节
    // 节间隙（头部与首节之间）
    EXPECT_EQ(img.rva_to_offset(0x200), std::nullopt);
    EXPECT_EQ(img.rva_to_offset(0xFFF), std::nullopt);
    // 越过已初始化区间
    EXPECT_EQ(img.rva_to_offset(0x1200), std::nullopt);
    EXPECT_EQ(img.rva_to_offset(0x1'0000'0000ull), std::nullopt);
}

TEST(PeImageMap, RvaToOffsetSkipsUninitializedSections) {
    const wvmp::passes::PeImage img =
        wvmp::passes::parse_pe_image(build_pe_with_bss());

    ASSERT_EQ(img.sections.size(), 2u);
    // 纯 .bss（raw_size=0）不映射——与 lifter pe_map 的语义一致
    EXPECT_EQ(img.rva_to_offset(0x2000), std::nullopt);
    EXPECT_EQ(img.rva_to_offset(0x2001), std::nullopt);
    // .text 与 .bss 之间的节间隙
    EXPECT_EQ(img.rva_to_offset(0x1800), std::nullopt);
    // .text 仍正常
    EXPECT_EQ(img.rva_to_offset(0x1000), std::optional<u64>(0x200));
    // 头部区间不受 bss（raw_ptr=0）影响
    EXPECT_EQ(img.rva_to_offset(0x100), std::optional<u64>(0x100));
}

// —— offset_to_rva 对称 ————————————————————————————————————————————

TEST(PeImageMap, OffsetToRvaSymmetric) {
    const wvmp::passes::PeImage img =
        wvmp::passes::parse_pe_image(build_minimal_pe(true, kMachineX64));

    EXPECT_EQ(img.offset_to_rva(0), std::optional<u64>(0));
    EXPECT_EQ(img.offset_to_rva(0x1FF), std::optional<u64>(0x1FF));
    EXPECT_EQ(img.offset_to_rva(0x200), std::optional<u64>(0x1000));
    EXPECT_EQ(img.offset_to_rva(0x2AB), std::optional<u64>(0x10AB));
    EXPECT_EQ(img.offset_to_rva(0x3FF), std::optional<u64>(0x11FF));
    EXPECT_EQ(img.offset_to_rva(0x400), std::nullopt); // 文件尾之后

    // 往返一致性：可映射偏移上 offset→rva→offset 应还原
    for (u64 off : {u64(0), u64(0x42), u64(0x1FF), u64(0x200), u64(0x357), u64(0x3FF)}) {
        const auto rva = img.offset_to_rva(off);
        ASSERT_TRUE(rva.has_value()) << "offset 0x" << std::hex << off;
        const auto back = img.rva_to_offset(*rva);
        ASSERT_TRUE(back.has_value());
        EXPECT_EQ(*back, off);
    }
}

// —— find_section ——————————————————————————————————————————————————

TEST(PeImageSections, FindSection) {
    const wvmp::passes::PeImage img =
        wvmp::passes::parse_pe_image(build_pe_with_bss());

    const wvmp::passes::SectionInfo* text = img.find_section(".text");
    ASSERT_NE(text, nullptr);
    EXPECT_EQ(text->virtual_addr, 0x1000u);
    EXPECT_EQ(text->characteristics, 0x60000020u);
    EXPECT_NE(img.find_section(".bss"), nullptr);
    EXPECT_EQ(img.find_section(".rdata"), nullptr);
    EXPECT_EQ(img.find_section(""), nullptr);
}

// —— pass 级 ———————————————————————————————————————————————————————

TEST(PeLoaderPass, LoadsFileIntoImageAndSlot) {
    const auto bytes = build_minimal_pe(true, kMachineX64);
    ProtectionContext ctx;
    ctx.input_path = write_temp("minimal_x64.exe", bytes);

    wvmp::passes::PeLoaderPass pass;
    const auto provides = pass.provides_keys();
    ASSERT_EQ(provides.size(), 2u);
    EXPECT_EQ(provides[0], wvmp::kImage);
    EXPECT_EQ(provides[1], wvmp::kPeImage);

    pass.run(ctx);

    ASSERT_EQ(ctx.image.size(), bytes.size());
    EXPECT_EQ(0, std::memcmp(ctx.image.data(), bytes.data(), bytes.size()));
    EXPECT_FALSE(ctx.diag.has_errors());

    const wvmp::passes::PeImage* meta = ctx.find_slot<wvmp::passes::PeImage>(
        wvmp::passes::kImageMeta);
    ASSERT_NE(meta, nullptr);
    EXPECT_TRUE(meta->is_pe32_plus);
    EXPECT_EQ(meta->machine, kMachineX64);
    EXPECT_EQ(meta->num_sections, u16(1));
}

TEST(PeLoaderPass, MissingInputFileFails) {
    ProtectionContext ctx;
    ctx.input_path = fs::temp_directory_path() / "wvmp_pe_loader_tests" / "no_such_file.exe";
    wvmp::passes::PeLoaderPass pass;
    EXPECT_THROW(pass.run(ctx), std::runtime_error);
    EXPECT_TRUE(ctx.diag.has_errors());
    EXPECT_FALSE(ctx.has_slot(wvmp::passes::kImageMeta));
}

TEST(PeLoaderPass, RejectsMalformedInputs) {
    struct Case {
        const char* name;
        std::vector<u8> bytes;
    };
    std::vector<u8> bad_dos = build_minimal_pe(true, kMachineX64);
    bad_dos[0] = 'X';
    std::vector<u8> bad_sig = build_minimal_pe(true, kMachineX64);
    bad_sig[0x40] = 'X';
    std::vector<u8> bad_machine = build_minimal_pe(true, 0xAA64); // ARM64
    std::vector<u8> bad_magic = build_minimal_pe(true, kMachineX64);
    put16(bad_magic, 0x40 + 24, 0x999); // 可选头魔数非法
    std::vector<u8> truncated = build_minimal_pe(true, kMachineX64);
    put16(truncated, 0x40 + 6, 32); // 声称 32 节，节表远超 0x400 的镜像边界
    std::vector<u8> tiny(0x20, 0); // 比 DOS 头还小

    const Case cases[] = {
        {"bad_dos", bad_dos},       {"bad_signature", bad_sig},
        {"bad_machine", bad_machine}, {"bad_optional_magic", bad_magic},
        {"truncated_section_table", truncated}, {"too_small", tiny},
    };
    for (const Case& c : cases) {
        ProtectionContext ctx;
        ctx.input_path = write_temp(std::string("bad_") + c.name + ".exe", c.bytes);
        wvmp::passes::PeLoaderPass pass;
        EXPECT_THROW(pass.run(ctx), std::runtime_error) << c.name;
        EXPECT_TRUE(ctx.diag.has_errors()) << c.name;
        EXPECT_FALSE(ctx.has_slot(wvmp::passes::kImageMeta)) << c.name;
    }
}

TEST(PeLoaderPass, EmptyFileFails) {
    ProtectionContext ctx;
    ctx.input_path = write_temp("empty.exe", {});
    wvmp::passes::PeLoaderPass pass;
    EXPECT_THROW(pass.run(ctx), std::runtime_error);
    EXPECT_TRUE(ctx.diag.has_errors());
}
