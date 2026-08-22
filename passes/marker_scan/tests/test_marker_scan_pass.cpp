// MarkerScanPass 集成测试：
//  1) 真实样例 exe（wvmp_marker_sample，静态链接 wvmp::sdk）——端到端扫描；
//  2) 手工构造的合成镜像——无 PE 头，覆盖降级路径与告警路径；
//  3) magic 常量与 SDK 头的同步性断言。

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/phase.hpp"
#include "wvmp/ir/region.hpp"
#include "wvmp/passes/marker_scan/marker_scan_pass.hpp"
#include "wvmp/passes/marker_scan/scan_core.hpp"
#include "wvmp/passes/pe_loader/pe_image.hpp"
#include "wvmp/sdk/markers.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <vector>

namespace {
namespace ms = wvmp::passes::marker_scan;
using wvmp::u8;
using wvmp::u16;
using wvmp::u32;
using wvmp::u64;

std::vector<u8> read_file(const char* path) {
    std::ifstream f(path, std::ios::binary);
    return std::vector<u8>(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

u16 rd16(const u8* p) {
    return static_cast<u16>(static_cast<u16>(p[0]) | (static_cast<u16>(p[1]) << 8));
}
u32 rd32(const u8* p) {
    return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) |
           (static_cast<u32>(p[2]) << 16) | (static_cast<u32>(p[3]) << 24);
}

// 测试侧独立的最小节表解析（宽松：只找名为 .text 的节的 RVA 范围）。
bool text_rva_range(const std::vector<u8>& img, size_t& lo, size_t& hi) {
    if (img.size() < 0x40) return false;
    const size_t lfanew = rd32(&img[0x3C]);
    if (lfanew + 24 > img.size()) return false;
    if (rd32(&img[lfanew]) != 0x0000'4550) return false;
    const u16 num_sections = rd16(&img[lfanew + 6]);
    const u16 opt_size = rd16(&img[lfanew + 20]);
    const size_t sec_base = lfanew + 24 + opt_size;
    if (sec_base + static_cast<size_t>(num_sections) * 40 > img.size()) return false;
    for (u16 i = 0; i < num_sections; ++i) {
        const size_t sh = sec_base + static_cast<size_t>(i) * 40;
        if (std::strncmp(reinterpret_cast<const char*>(&img[sh]), ".text", 5) != 0) continue;
        lo = rd32(&img[sh + 12]); // VirtualAddress
        hi = lo + std::max<u32>(rd32(&img[sh + 8]), 1); // VirtualSize
        return lo < hi;
    }
    return false;
}

// 在 img 的 off 处安放桩函数体：48 B8 <8 字节 magic>（mov rax, imm64）。
void plant_stub(std::vector<u8>& img, size_t off, std::span<const u8> magic) {
    img[off] = 0x48;
    img[off + 1] = 0xB8;
    std::copy(magic.begin(), magic.end(), img.begin() + static_cast<std::ptrdiff_t>(off) + 2);
}

// 在 img 的 off 处安放 E8 rel32，目标为 target。
void plant_call(std::vector<u8>& img, size_t off, size_t target) {
    const auto rel = static_cast<wvmp::i32>(
        static_cast<wvmp::i64>(target) - static_cast<wvmp::i64>(off) - 5);
    img[off] = 0xE8;
    img[off + 1] = static_cast<u8>(rel & 0xFF);
    img[off + 2] = static_cast<u8>((rel >> 8) & 0xFF);
    img[off + 3] = static_cast<u8>((rel >> 16) & 0xFF);
    img[off + 4] = static_cast<u8>((rel >> 24) & 0xFF);
}

} // namespace

// scan_core 的模式与 SDK 头中的 magic 常量必须逐字节一致（跨模块同步护栏）。
TEST(MagicSync, ScanPatternsMatchSdkConstants) {
    u64 b = 0, e = 0;
    for (size_t i = 0; i < 8; ++i) {
        b |= static_cast<u64>(ms::kBeginPattern[i]) << (8 * i);
        e |= static_cast<u64>(ms::kEndPattern[i]) << (8 * i);
    }
    EXPECT_EQ(b, wvmp::sdk::kBeginMagic);
    EXPECT_EQ(e, wvmp::sdk::kEndMagic);
    // 可打印、不含 E8/E9（避免 magic 自身干扰 call 扫描）
    for (u8 c : ms::kBeginPattern) {
        EXPECT_NE(c, 0xE8);
        EXPECT_NE(c, 0xE9);
    }
}

TEST(MarkerScanPass, ContractSurface) {
    wvmp::passes::MarkerScanPass p;
    EXPECT_EQ(p.name(), "marker_scan");
    EXPECT_EQ(p.phase(), wvmp::Phase::Analyze);
    bool req_image = false, prov_functions = false;
    for (auto k : p.requires_keys()) req_image = req_image || k == wvmp::kImage;
    for (auto k : p.provides_keys()) prov_functions = prov_functions || k == wvmp::kFunctions;
    EXPECT_TRUE(req_image);
    EXPECT_TRUE(prov_functions);
}

TEST(MarkerScanPass, ScansSampleExecutable) {
    const auto image = read_file(WVMP_MARKER_SAMPLE_EXE);
    ASSERT_FALSE(image.empty());

    // 前置验证：每个 magic 恰好出现 1 次——同时证明 MSVC x64 把 imm64
    // 编码为连续 8 字节（48 B8 ...），SDK 桩的扫描锚点成立。
    ASSERT_EQ(ms::find_all(image, ms::kBeginPattern).size(), static_cast<size_t>(1));
    ASSERT_EQ(ms::find_all(image, ms::kEndPattern).size(), static_cast<size_t>(1));

    wvmp::ProtectionContext ctx;
    ctx.image = image;
    // M1：与真实管道一致——先由 pe_loader 产出 PeImage 模型，marker_scan 做
    // 文件偏移 → RVA 换算。
    ctx.slot<wvmp::passes::PeImage>(wvmp::kPeImage) = wvmp::passes::parse_pe_image(image);
    wvmp::passes::MarkerScanPass().run(ctx);

    ASSERT_EQ(ctx.functions.size(), static_cast<size_t>(2));
    EXPECT_FALSE(ctx.diag.has_errors());
    EXPECT_TRUE(ctx.diag.items().empty()); // 恰好配对：无告警

    for (const auto& f : ctx.functions) {
        EXPECT_EQ(f.arch, wvmp::ir::Arch::X64);
        EXPECT_NE(f.name.find("marker@"), std::string::npos);
        EXPECT_GT(f.end_rva, f.begin_rva);       // 长度 > 0
        EXPECT_TRUE(f.blocks.empty());           // Analyze 阶段不产出块
    }
    // 地址有序且不重叠
    EXPECT_LT(ctx.functions[0].begin_rva, ctx.functions[1].begin_rva);
    EXPECT_LE(ctx.functions[0].end_rva, ctx.functions[1].begin_rva);

    // 宽松：区域（RVA）落在 .text 的 RVA 范围内
    size_t lo = 0, hi = 0;
    ASSERT_TRUE(text_rva_range(image, lo, hi));
    for (const auto& f : ctx.functions) {
        EXPECT_GE(f.begin_rva, lo);
        EXPECT_LE(f.end_rva, hi);
    }
}

TEST(MarkerScanPass, EmptyImageWarns) {
    wvmp::ProtectionContext ctx;
    wvmp::passes::MarkerScanPass().run(ctx);
    EXPECT_TRUE(ctx.functions.empty());
    EXPECT_FALSE(ctx.diag.has_errors());
    EXPECT_FALSE(ctx.diag.items().empty());
}

TEST(MarkerScanPass, MissingMagicWarns) {
    std::vector<u8> image(512, 0x90); // 无 magic、无 PE 头
    wvmp::ProtectionContext ctx;
    ctx.image = image;
    wvmp::passes::MarkerScanPass().run(ctx);
    EXPECT_TRUE(ctx.functions.empty());
    EXPECT_FALSE(ctx.diag.has_errors());
    EXPECT_GE(ctx.diag.items().size(), static_cast<size_t>(2)); // begin+end 缺失
}

TEST(MarkerScanPass, SyntheticPairProducesRegion) {
    std::vector<u8> image(512, 0x90); // 无 PE 头：同时覆盖全镜像降级扫描路径
    plant_stub(image, 0x40, ms::kBeginPattern);
    plant_stub(image, 0xC0, ms::kEndPattern);
    plant_call(image, 0x80, 0x40); // call marker_begin
    plant_call(image, 0xA0, 0xC0); // call marker_end

    wvmp::ProtectionContext ctx;
    ctx.image = image;
    wvmp::passes::MarkerScanPass().run(ctx);

    ASSERT_EQ(ctx.functions.size(), static_cast<size_t>(1));
    const auto& f = ctx.functions[0];
    // 区域 = begin 调用的下一条指令(0x85) .. end 调用指令(0xA0)
    EXPECT_EQ(f.begin_rva, static_cast<wvmp::u64>(0x85));
    EXPECT_EQ(f.end_rva, static_cast<wvmp::u64>(0xA0));
    EXPECT_FALSE(ctx.diag.has_errors());
    // 无 PE 头：PeImage 槽缺失 → 恰好一条回退 Note（保持文件偏移）。
    ASSERT_EQ(ctx.diag.items().size(), static_cast<size_t>(1));
    EXPECT_EQ(ctx.diag.items()[0].severity, wvmp::Severity::Note);
}

TEST(MarkerScanPass, SyntheticUnpairedBeginWarns) {
    std::vector<u8> image(512, 0x90);
    plant_stub(image, 0x40, ms::kBeginPattern);
    plant_call(image, 0x80, 0x40); // 只有 begin，没有 end

    wvmp::ProtectionContext ctx;
    ctx.image = image;
    wvmp::passes::MarkerScanPass().run(ctx);

    EXPECT_TRUE(ctx.functions.empty());
    EXPECT_FALSE(ctx.diag.has_errors());
    EXPECT_FALSE(ctx.diag.items().empty());
}
