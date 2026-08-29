// M2-2：add_sections 追加新节的落位/校验/头部更新测试。

#include "section_builder.hpp"

#include "wvmp/passes/pe_loader/pe_image.hpp"
#include "wvmp/passes/pe_writer/pe_writer_pass.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace {

using wvmp::u16;
using wvmp::u32;
using wvmp::u8;
using wvmp::passes::NewSection;
using wvmp::passes::SectionPlacement;
using wvmp::passes::add_sections;
using wvmp::passes::parse_pe_image;
using wvmp::ProtectionContext;

constexpr u16 kMachineX64 = 0x8664;
constexpr u32 kSecAlign = 0x1000;
constexpr u32 kFileAlign = 0x200;

void wr32(std::vector<u8>& v, size_t o, u32 x) {
    v[o] = u8(x);
    v[o + 1] = u8(x >> 8);
    v[o + 2] = u8(x >> 16);
    v[o + 3] = u8(x >> 24);
}
u32 rd32(const std::vector<u8>& v, size_t o) {
    return u32(v[o]) | (u32(v[o + 1]) << 8) | (u32(v[o + 2]) << 16) | (u32(v[o + 3]) << 24);
}

// 最小 PE：DOS + NT(x64) + 单个 .text 节（raw @0x200 len 0x200，文件共 0x500）。
std::vector<u8> build_minimal_pe() {
    std::vector<u8> img(0x500, 0);
    img[0] = 'M';
    img[1] = 'Z';
    wr32(img, 0x3C, 0x40); // e_lfanew
    const size_t nt = 0x40;
    img[nt + 0] = 'P';
    img[nt + 1] = 'E';
    wr32(img, nt + 4, kMachineX64); // Machine
    img[nt + 6] = 1;                // NumberOfSections
    img[nt + 20] = 240;             // SizeOfOptionalHeader
    const size_t opt = nt + 24;
    img[opt] = 0x0B;
    img[opt + 1] = 0x02;                  // PE32+ Magic
    wr32(img, opt + 32, kSecAlign);       // SectionAlignment
    wr32(img, opt + 36, kFileAlign);      // FileAlignment
    wr32(img, opt + 56, 0x2000);          // SizeOfImage
    wr32(img, opt + 60, 0x200);           // SizeOfHeaders
    const size_t sh = nt + 24 + 240;
    std::memcpy(&img[sh], ".text", 5);
    wr32(img, sh + 8, 0x100);   // VirtualSize
    wr32(img, sh + 12, 0x1000); // VirtualAddress
    wr32(img, sh + 16, 0x200);  // SizeOfRawData
    wr32(img, sh + 20, 0x200);  // PointerToRawData
    wr32(img, sh + 36, 0x6000'0020);
    std::fill(img.begin() + 0x200, img.begin() + 0x500, 0xCC);
    return img;
}

NewSection make_section(const char* name, size_t size, u32 requested_rva = 0) {
    NewSection s;
    s.name = name;
    s.data.assign(size, 0xAB);
    s.characteristics = 0xE000'0020; // code|execute|read|write
    s.requested_rva = requested_rva;
    return s;
}

TEST(AddSections, AppendsSectionAndUpdatesHeaders) {
    std::vector<u8> img = build_minimal_pe();
    const auto placed = add_sections(img, {make_section(".wvmp", 0x123)}, kSecAlign, kFileAlign);

    ASSERT_EQ(placed.size(), static_cast<size_t>(1));
    EXPECT_EQ(placed[0].rva, 0x2000u);        // .text 端 0x1100 → 对齐 0x2000
    EXPECT_EQ(placed[0].file_offset, 0x600u); // 文件尾 0x500 → 对齐 0x600
    EXPECT_EQ(placed[0].raw_size, 0x200u);    // 0x123 → 对齐 0x200

    const auto model = parse_pe_image(img);
    ASSERT_EQ(model.num_sections, 2);
    EXPECT_EQ(model.sections[1].name, ".wvmp");
    EXPECT_EQ(model.sections[1].virtual_addr, placed[0].rva);
    EXPECT_EQ(model.sections[1].raw_ptr, placed[0].file_offset);
    const auto off = model.rva_to_offset(placed[0].rva);
    ASSERT_TRUE(off.has_value());
    EXPECT_EQ(img[*off], 0xAB);
    EXPECT_EQ(rd32(img, model.nt_headers_offset + 24 + 56), 0x3000u); // SizeOfImage
    EXPECT_EQ(img[0x200], 0xCC); // 原始数据未破坏
}

TEST(AddSections, MultipleSectionsSequential) {
    std::vector<u8> img = build_minimal_pe();
    const auto placed =
        add_sections(img, {make_section(".a", 0x10), make_section(".b", 0x200)}, kSecAlign, kFileAlign);
    ASSERT_EQ(placed.size(), static_cast<size_t>(2));
    EXPECT_EQ(placed[0].rva, 0x2000u);
    EXPECT_EQ(placed[1].rva, 0x3000u);
    EXPECT_EQ(placed[1].file_offset, 0x800u);
    EXPECT_EQ(parse_pe_image(img).num_sections, 3);
}

// MIT-414 (G7p2 B.4)：追加节与前一节对齐端连续（无 VA 空洞）时按请求落位。
// 既有 .text 端 0x1100 → 对齐端 0x2000，请求 0x2000 即连续。
TEST(AddSections, RequestedRvaContiguousHonored) {
    std::vector<u8> img = build_minimal_pe();
    const auto placed = add_sections(img, {make_section(".wvmp", 0x10, 0x2000)}, kSecAlign, kFileAlign);
    ASSERT_EQ(placed.size(), static_cast<size_t>(1));
    EXPECT_EQ(placed[0].rva, 0x2000u);
    EXPECT_EQ(parse_pe_image(img).sections[1].virtual_addr, 0x2000u);
}

// MIT-414 (G7p2 B.4)：VA 空洞（请求 RVA 落在前一节对齐端之后）必须显式失败。
// Windows 加载器拒绝带空洞的节布局（triage §3.3 实测：既有节端 0x5000 时
// .wvmp 落 0x5000 可加载、0x6000 起全拒 WinError 193）。旧行为是"空洞也
// 照落"（本测试原名 RequestedRvaHonoredWhenFree）——正是产坏壳的帮凶。
TEST(AddSections, RequestedRvaGapThrowsAndLeavesImageIntact) {
    std::vector<u8> img = build_minimal_pe();
    const std::vector<u8> before = img;
    EXPECT_THROW((void)add_sections(img, {make_section(".far", 0x10, 0x9000)}, kSecAlign, kFileAlign),
                 std::runtime_error);
    EXPECT_EQ(img, before); // 校验先行：失败零修改
}

// MIT-414 (G7p2 B.4)：多请求之间同样不得留空洞——auto 请求顺序延伸对齐端，
// 后续 requested_rva 必须接其对齐端。请求 0x4000 在 auto(.a@0x2000→端 0x3000)
// 之后留下 0x3000..0x4000 空洞 → 拒绝。
TEST(AddSections, RequestedRvaGapAfterAutoRequestThrows) {
    std::vector<u8> img = build_minimal_pe();
    EXPECT_THROW((void)add_sections(img, {make_section(".a", 0x10), make_section(".b", 0x10, 0x4000)},
                                    kSecAlign, kFileAlign),
                 std::runtime_error);
}

TEST(AddSections, RequestedRvaConflictThrowsAndLeavesImageIntact) {
    std::vector<u8> img = build_minimal_pe();
    const std::vector<u8> before = img;
    EXPECT_THROW((void)add_sections(img, {make_section(".bad", 0x10, 0x1000)}, kSecAlign, kFileAlign),
                 std::runtime_error);
    EXPECT_EQ(img, before); // 校验先行：失败零修改
}

TEST(AddSections, NoHeaderRoomThrows) {
    std::vector<u8> img = build_minimal_pe();
    wr32(img, 0x40 + 24 + 60, 0xF0); // SizeOfHeaders 压到节表尾之前
    EXPECT_THROW((void)add_sections(img, {make_section(".wvmp", 0x10)}, kSecAlign, kFileAlign),
                 std::runtime_error);
}

TEST(AddSections, WriterPassConsumesSlot) {
    ProtectionContext ctx;
    ctx.image = build_minimal_pe();
    ctx.output_path = "m2-section-test-out.exe";
    ctx.slot<std::vector<NewSection>>(wvmp::kNewSections).push_back(make_section(".wvmp", 0x80));

    wvmp::passes::PeWriterPass pass;
    pass.run(ctx);

    const auto model = parse_pe_image(ctx.image);
    ASSERT_EQ(model.num_sections, 2);
    EXPECT_EQ(model.sections[1].name, ".wvmp");
    std::remove("m2-section-test-out.exe");
    std::remove("m2-section-test-out.exe.wvmp-tmp");
}

} // namespace
