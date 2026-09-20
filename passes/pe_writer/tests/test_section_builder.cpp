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
#include <filesystem>
#include <stdexcept>
#include <vector>

namespace {

using wvmp::u16;
using wvmp::u32;
using wvmp::u64;
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

// ── MIT-528 (CR-08)：auto/fixed 混排下"校验通过的布局 == 实际写入布局" ──────
//
// 旧缺陷：校验阶段把指定 RVA 请求推进过的 max_va_end 又当作 auto 请求的落位
// 初值 ⇒ 同一份请求校验一套布局、写盘另一套（审核实测期望 [0x2000,0x3000]、
// 实写 [0x4000,0x3000]）。本组断言三方向同表比对，任一不符即失败：
//   ① 手算连续布局 expect   ② add_sections 返回值 placed   ③ 镜像节表读回。
// 夹具既有 .text：VA 0x1000 + max(0x100,0x200) → 对齐末端 0x2000。
constexpr u32 kExistingEnd = 0x2000;

u64 au(u64 v, u64 a) { return ((v + a - 1) / a) * a; }

void expect_validated_layout_written(const std::vector<NewSection>& reqs,
                                     const std::vector<u32>& expect_rva,
                                     const char* what) {
    std::vector<u8> img = build_minimal_pe();
    const auto placed = add_sections(img, reqs, kSecAlign, kFileAlign);
    const size_t n = expect_rva.size();
    ASSERT_EQ(placed.size(), n) << what;

    u64 run_end = kExistingEnd;
    u64 prev_rva = 0;
    for (size_t i = 0; i < n; ++i) {
        // ① 落位 == 手算连续布局
        EXPECT_EQ(placed[i].rva, expect_rva[i])
            << what << " #" << i << " 校验布局 != 期望（auto 游标被 fixed 请求推走？）";
        // ② 末端连续性：本节起点必须严丝合缝接在前一节对齐末端（无空洞/无逆序）
        EXPECT_EQ(placed[i].rva, static_cast<u32>(run_end))
            << what << " #" << i << " 与前一节对齐端不连续（VA 空洞 → 加载器拒载）";
        // ③ 节 RVA 表序单调递增
        if (i > 0) EXPECT_GT(placed[i].rva, prev_rva) << what << " #" << i << " 节 RVA 逆序";
        prev_rva = placed[i].rva;
        run_end = au(u64(placed[i].rva) + reqs[i].data.size(), kSecAlign);
    }

    // ④ 实际写入 == 返回的校验布局（读节表，不是读返回值）
    const auto model = parse_pe_image(img);
    ASSERT_EQ(model.num_sections, static_cast<u16>(1 + n)) << what;
    for (size_t i = 0; i < n; ++i) {
        EXPECT_EQ(model.sections[1 + i].virtual_addr, placed[i].rva)
            << what << " #" << i << " 节表实写 RVA != 返回值";
        EXPECT_EQ(model.sections[1 + i].virtual_addr, expect_rva[i]) << what << " #" << i;
        EXPECT_EQ(model.sections[1 + i].raw_ptr, placed[i].file_offset) << what << " #" << i;
        const auto off = model.rva_to_offset(expect_rva[i]);
        ASSERT_TRUE(off.has_value()) << what << " #" << i << " RVA 无对应文件偏移";
        EXPECT_EQ(img[*off], 0xAB) << what << " #" << i << " 数据未落在声称的 RVA";
    }

    // ⑤ SizeOfImage == 连续链末端（不得随游标漂移）
    EXPECT_EQ(rd32(img, 0x40 + 24 + 56), static_cast<u32>(run_end)) << what;
}

// 复现审核那对读数：auto 在前、fixed 在后 ⇒ 期望 [0x2000,0x3000]。
TEST(AddSections, MixedAutoThenFixedKeepsValidatedLayout) {
    expect_validated_layout_written({make_section(".a", 0x100), make_section(".b", 0x100, 0x3000)},
                                    {0x2000, 0x3000}, "auto→fixed");
}

// fixed 在前、auto 在后：auto 接 fixed 的对齐末端。
TEST(AddSections, MixedFixedThenAutoKeepsValidatedLayout) {
    expect_validated_layout_written({make_section(".a", 0x100, 0x2000), make_section(".b", 0x100)},
                                    {0x2000, 0x3000}, "fixed→auto");
}

// 三请求混排（auto/fixed/auto）：中间那枚 fixed 不得把后面的 auto 推位。
TEST(AddSections, MixedAutoFixedAutoKeepsValidatedLayout) {
    expect_validated_layout_written(
        {make_section(".a", 0x100), make_section(".b", 0x100, 0x3000), make_section(".c", 0x100)},
        {0x2000, 0x3000, 0x4000}, "auto→fixed→auto");
}

// 四请求交替混排（fixed/auto/fixed/auto）。
TEST(AddSections, MixedFixedAutoFixedAutoKeepsValidatedLayout) {
    expect_validated_layout_written(
        {make_section(".a", 0x100, 0x2000), make_section(".b", 0x100),
         make_section(".c", 0x100, 0x4000), make_section(".d", 0x100)},
        {0x2000, 0x3000, 0x4000, 0x5000}, "fixed→auto→fixed→auto");
}

// 六请求长链混排：fixed 的推进量最容易被误当成 auto 游标初值。
TEST(AddSections, MixedSixRequestAlternatingKeepsValidatedLayout) {
    expect_validated_layout_written(
        {make_section(".a", 0x100), make_section(".b", 0x100, 0x3000), make_section(".c", 0x100),
         make_section(".d", 0x100, 0x5000), make_section(".e", 0x100),
         make_section(".f", 0x100, 0x7000)},
        {0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000}, "6 请求交替混排");
}

// 跨页尺寸（0x1500）混排：auto 游标推进按对齐后末端，fixed 仍须接其后。
TEST(AddSections, MixedCrossPageAutoThenFixedKeepsValidatedLayout) {
    expect_validated_layout_written({make_section(".a", 0x1500), make_section(".b", 0x10, 0x4000)},
                                    {0x2000, 0x4000}, "跨页 auto→fixed");
}

// 一枚 fixed 之后跟两枚 auto：两处 auto 都不得借用被推过的末端起算。
TEST(AddSections, MixedFixedThenTwoAutoKeepsValidatedLayout) {
    expect_validated_layout_written(
        {make_section(".a", 0x10, 0x2000), make_section(".b", 0x10), make_section(".c", 0x10)},
        {0x2000, 0x3000, 0x4000}, "fixed→auto→auto");
}

// 混排不成立时必须显式失败，而不是产出逆序布局：指定 RVA 落在 auto 已占用
// 区间之后（留洞）或之前（逆序）都属此类。
TEST(AddSections, MixedInvertedFixedRequestThrowsAndLeavesImageIntact) {
    std::vector<u8> img = build_minimal_pe();
    const std::vector<u8> before = img;
    EXPECT_THROW((void)add_sections(img, {make_section(".a", 0x10), make_section(".b", 0x10, 0x2000)},
                                    kSecAlign, kFileAlign),
                 std::runtime_error);
    EXPECT_EQ(img, before); // 校验先行：失败零修改
}

TEST(AddSections, MixedFixedAfterAutoGapThrows) {
    std::vector<u8> img = build_minimal_pe();
    // .a@0x2000→端 0x3000、.b auto→0x3000 端 0x4000，.c 指定 0x5000 ⇒ 留洞。
    EXPECT_THROW((void)add_sections(
                     img,
                     {make_section(".a", 0x100, 0x2000), make_section(".b", 0x100),
                      make_section(".c", 0x100, 0x5000)},
                     kSecAlign, kFileAlign),
                 std::runtime_error);
}

// 真实产物形态（stub_link 两枚 fixed 请求）逐字节不变——本单只改混排/失败路径。
TEST(AddSections, AllFixedRequestsUnchangedUnderMixingFix) {
    expect_validated_layout_written(
        {make_section(".wvmp", 0x2100, 0x2000), make_section(".wvmpc", 0x40, 0x5000)},
        {0x2000, 0x5000}, "stub_link 双 fixed");
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
    // pass 结束后工作目录里只该留下产物本身（tmp 已被替换消化，CR-09）
    int same_prefix = 0;
    for (const auto& e : std::filesystem::directory_iterator(".")) {
        if (e.path().filename().string().rfind("m2-section-test-out.exe", 0) != 0) continue;
        ++same_prefix;
        EXPECT_EQ(e.path().filename().string(), "m2-section-test-out.exe");
    }
    EXPECT_EQ(same_prefix, 1);
    std::remove("m2-section-test-out.exe");
}

} // namespace
