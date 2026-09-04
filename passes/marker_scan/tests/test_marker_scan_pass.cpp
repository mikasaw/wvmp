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
#include <array>
#include <cstring>
#include <fstream>
#include <string>
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

// —— X1a (MIT-437) x86 合成镜像辅助 ——

void put16(std::vector<u8>& v, size_t o, u16 x) {
    for (int i = 0; i < 2; ++i) v[o + i] = u8(x >> (8 * i));
}
void put32x(std::vector<u8>& v, size_t o, u32 x) {
    for (int i = 0; i < 4; ++i) v[o + i] = u8(x >> (8 * i));
}

// 手工拼最小合法 PE32（machine=0x014C，布局同 test_pe_loader 的
// build_minimal_pe(false, kMachineX86)）：头部 [0x000,0x200) + ".text"
// 原始数据 [0x200,0x400)（VA 0x1000，VS=SR=0x200），image_base 0x400000。
std::vector<u8> build_minimal_pe32_x86() {
    const size_t nt = 0x40, opt = nt + 24, sec = opt + 224;
    std::vector<u8> img(0x400, 0);
    put16(img, 0x00, 0x5A4D);            // 'MZ'
    put32x(img, 0x3C, u32(nt));          // e_lfanew
    put32x(img, nt + 0, 0x00004550);     // 'PE\0\0'
    put16(img, nt + 4, 0x014C);          // Machine = I386
    put16(img, nt + 6, 1);               // NumberOfSections
    put16(img, nt + 20, 224);            // SizeOfOptionalHeader (PE32)
    put16(img, opt + 0, 0x10B);          // PE32 可选头魔数
    put32x(img, opt + 16, 0x1234);       // AddressOfEntryPoint
    put32x(img, opt + 20, 0x1000);       // BaseOfCode
    put32x(img, opt + 24, 0x2000);       // BaseOfData（PE32 独占）
    put32x(img, opt + 28, 0x400000);     // ImageBase（PE32 4B）
    put32x(img, opt + 32, 0x1000);       // SectionAlignment
    put32x(img, opt + 36, 0x200);        // FileAlignment
    std::memcpy(&img[sec], ".text", 5);
    put32x(img, sec + 8, 0x200);         // VirtualSize
    put32x(img, sec + 12, 0x1000);       // VirtualAddress
    put32x(img, sec + 16, 0x200);        // SizeOfRawData
    put32x(img, sec + 20, 0x200);        // PointerToRawData
    put32x(img, sec + 36, 0x60000020);   // CNT_CODE|MEM_EXECUTE|MEM_READ
    return img;
}

// 在 img 的 off 处安放 x86 /Od 形双段桩体：
//   push ebp / mov ebp,esp / B8 <hi4> / C7 45 F8 <lo4> / 89 45 FC
// 物化起点（锚点）= hi 半（off+4）。
void plant_stub_x86(std::vector<u8>& img, size_t off, const ms::X86DualMagic& m) {
    const u8 seq[] = {0x55, 0x8B, 0xEC, 0xB8, m.hi[0], m.hi[1], m.hi[2], m.hi[3],
                      0xC7, 0x45, 0xF8, m.lo[0], m.lo[1], m.lo[2], m.lo[3],
                      0x89, 0x45, 0xFC};
    std::copy(seq, seq + sizeof(seq), img.begin() + static_cast<std::ptrdiff_t>(off));
}

// 从节表取 ".text" 的 VirtualAddress 与 PointerToRawData（真产物 RVA →
// 文件偏移换算用；与 text_rva_range 同一解析法）。
bool text_section_location(const std::vector<u8>& img, u32& va, u32& raw_ptr) {
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
        va = rd32(&img[sh + 12]);
        raw_ptr = rd32(&img[sh + 20]);
        return true;
    }
    return false;
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

// X1a (MIT-437 B.4 同步纪律)：x86 双段两半必须与 SDK 常量逐字节一致，且
// 直接派生自 8 字节模式（单一来源，禁止另写字面量）。
TEST(MagicSync, X86DualHalvesMatchSdkConstants) {
    constexpr u64 b = wvmp::sdk::kBeginMagic;
    constexpr u64 e = wvmp::sdk::kEndMagic;
    // & 0xFF 先收敛再收窄：规避 /W4 /WX 的 C4310（常量截断告警）
    constexpr std::array<u8, 4> b_lo{u8(b & 0xFF), u8((b >> 8) & 0xFF),
                                     u8((b >> 16) & 0xFF), u8((b >> 24) & 0xFF)};
    constexpr std::array<u8, 4> b_hi{u8((b >> 32) & 0xFF), u8((b >> 40) & 0xFF),
                                     u8((b >> 48) & 0xFF), u8((b >> 56) & 0xFF)};
    constexpr std::array<u8, 4> e_lo{u8(e & 0xFF), u8((e >> 8) & 0xFF),
                                     u8((e >> 16) & 0xFF), u8((e >> 24) & 0xFF)};
    constexpr std::array<u8, 4> e_hi{u8((e >> 32) & 0xFF), u8((e >> 40) & 0xFF),
                                     u8((e >> 48) & 0xFF), u8((e >> 56) & 0xFF)};
    EXPECT_EQ(ms::kBeginPatternX86.lo, b_lo);
    EXPECT_EQ(ms::kBeginPatternX86.hi, b_hi);
    EXPECT_EQ(ms::kEndPatternX86.lo, e_lo);
    EXPECT_EQ(ms::kEndPatternX86.hi, e_hi);
    for (int i = 0; i < 4; ++i) {
        EXPECT_EQ(ms::kBeginPatternX86.lo[i], ms::kBeginPattern[i]);
        EXPECT_EQ(ms::kBeginPatternX86.hi[i], ms::kBeginPattern[4 + i]);
        EXPECT_EQ(ms::kEndPatternX86.lo[i], ms::kEndPattern[i]);
        EXPECT_EQ(ms::kEndPatternX86.hi[i], ms::kEndPattern[4 + i]);
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
    // MIT-460 (P7-names)：SDK 传名 → 两个区域都解析到真名，零 Note。
    EXPECT_TRUE(ctx.diag.items().empty()); // 恰好配对：无告警

    for (const auto& f : ctx.functions) {
        EXPECT_EQ(f.arch, wvmp::ir::Arch::X64);
        // MIT-460 (P7-names)：SDK WVMP_BEGIN(fn) 传名 → 区域名 = 真名。
        EXPECT_TRUE(f.name == "compute_alpha" || f.name == "compute_beta")
            << "实际名: " << f.name;
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
    // 无 PE 头：PeImage 槽缺失 → 恰好一条 M1 回退 Note（保持文件偏移）；
    // 名字解析 gated on pe（MIT-460），pe 缺席时不产 P7-names Note。
    ASSERT_EQ(ctx.diag.items().size(), static_cast<size_t>(1));
    for (const auto& item : ctx.diag.items())
        EXPECT_EQ(item.severity, wvmp::Severity::Note);
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

// —— X1a (MIT-437)：x86 双段锚点 + arch 分叉 ——

// 合成 PE32 (machine=0x014C)：pass 级 arch 分叉（is_x86 → 双段识别）+
// E8 回溯链 + 文件偏移 → RVA 换算全链。桩体用 /Od 实测形（hi→lo）。
TEST(MarkerScanPassX86, SyntheticX86ImageProducesRegionWithArchX86) {
    auto image = build_minimal_pe32_x86();
    // .text raw [0x200,0x400) ↔ RVA 0x1000 起（RVA = file_off − 0x200 + 0x1000）
    plant_stub_x86(image, 0x210, ms::kBeginPatternX86);
    plant_stub_x86(image, 0x260, ms::kEndPatternX86);
    plant_call(image, 0x240, 0x210); // call marker_begin → next 0x245
    plant_call(image, 0x280, 0x260); // call marker_end   → insn 0x280

    wvmp::ProtectionContext ctx;
    ctx.image = image;
    ctx.slot<wvmp::passes::PeImage>(wvmp::kPeImage) =
        wvmp::passes::parse_pe_image(image);
    wvmp::passes::MarkerScanPass().run(ctx);

    ASSERT_EQ(ctx.functions.size(), static_cast<size_t>(1));
    const auto& f = ctx.functions[0];
    EXPECT_EQ(f.arch, wvmp::ir::Arch::X86);
    EXPECT_EQ(f.begin_rva, static_cast<wvmp::u64>(0x1045)); // 0x245 → RVA
    EXPECT_EQ(f.end_rva, static_cast<wvmp::u64>(0x1080));   // 0x280 → RVA
    EXPECT_FALSE(ctx.diag.has_errors());
    // 合成镜像无名字物化 → 恰好一条 P7-names 回退 Note（MIT-460）。
    ASSERT_EQ(ctx.diag.items().size(), static_cast<size_t>(1));
    EXPECT_EQ(ctx.diag.items()[0].severity, wvmp::Severity::Note);
    EXPECT_NE(ctx.diag.items()[0].message.find("回退地址名"), std::string::npos);
}

#ifdef WVMP_X86_MARKER_SAMPLE_EXE
// ml.exe 真产物 x86 fixture（build_x86_marker_sample.bat 构建进本构建树）：
// 双段锚点两形态（/Od 形 + /O1 形桩各一对）真字节识别 + 区域定位精确性
//（nop 哨兵逐字节断言，独立于扫描逻辑钉死边界）+ fr.arch 落位。
TEST(MarkerScanPassX86, ScansRealMlExeDualSegmentAnchors) {
    const auto image = read_file(WVMP_X86_MARKER_SAMPLE_EXE);
    ASSERT_FALSE(image.empty());

    const wvmp::passes::PeImage pe = wvmp::passes::parse_pe_image(image);
    ASSERT_EQ(pe.machine, 0x014C); // 真产物 PE32（ml.exe + /MACHINE:X86）

    // 前置负证：x64 连续 8B needle 在 x86 真产物上零命中（GAPS C5 实证
    // 断层的真产物复现；X1a 双段路径消费的就是这些不连续形态）。
    EXPECT_TRUE(ms::find_all(image, ms::kBeginPattern).empty());
    EXPECT_TRUE(ms::find_all(image, ms::kEndPattern).empty());

    // 前置正证：双段锚点各恰 2 处（/Od 形桩对 + /O1 形桩对）。
    EXPECT_EQ(ms::find_all_x86(image, ms::kBeginPatternX86).size(),
              static_cast<size_t>(2));
    EXPECT_EQ(ms::find_all_x86(image, ms::kEndPatternX86).size(),
              static_cast<size_t>(2));

    wvmp::ProtectionContext ctx;
    ctx.image = image;
    ctx.slot<wvmp::passes::PeImage>(wvmp::kPeImage) = pe;
    wvmp::passes::MarkerScanPass().run(ctx);

    ASSERT_EQ(ctx.functions.size(), static_cast<size_t>(2)); // 两个标记区域
    EXPECT_FALSE(ctx.diag.has_errors());
    // 双 begin/双 end 桩 → 各一条"出现 2 处（期望 1）"告警（预期内）
    std::string diag_dump;
    for (const auto& item : ctx.diag.items())
        diag_dump += "[" + std::to_string(static_cast<int>(item.severity)) + "] " +
                     item.message + "\n";
    // MIT-460: ml 手编产物无名字物化 → 每区域一条 P7-names 回退 Note（2 条）。
    ASSERT_EQ(ctx.diag.items().size(), static_cast<size_t>(4)) << diag_dump;
    size_t warnings = 0, fallback_notes = 0;
    for (const auto& item : ctx.diag.items()) {
        if (item.severity == wvmp::Severity::Warning) ++warnings;
        if (item.message.find("回退地址名") != std::string::npos) ++fallback_notes;
    }
    EXPECT_EQ(warnings, static_cast<size_t>(2));
    EXPECT_EQ(fallback_notes, static_cast<size_t>(2));

    u32 text_va = 0, text_raw = 0;
    ASSERT_TRUE(text_section_location(image, text_va, text_raw));
    std::vector<wvmp::u64> sizes;
    for (const auto& f : ctx.functions) {
        EXPECT_EQ(f.arch, wvmp::ir::Arch::X86);
        EXPECT_NE(f.name.find("marker@"), std::string::npos);
        EXPECT_GT(f.end_rva, f.begin_rva);
        sizes.push_back(f.end_rva - f.begin_rva);
    }
    std::sort(sizes.begin(), sizes.end());
    // 哨兵精确性：区域尺寸恰为 8×nop / 12×nop（rgn_one / rgn_two）
    EXPECT_EQ(sizes, (std::vector<wvmp::u64>{8, 12}));
    // 区域字节逐字节 = 0x90 哨兵（RVA → 文件偏移独立换算，非扫描逻辑重放）
    for (const auto& f : ctx.functions) {
        const size_t off = static_cast<size_t>(f.begin_rva - text_va + text_raw);
        for (wvmp::u64 i = 0; i < f.end_rva - f.begin_rva; ++i)
            ASSERT_EQ(image[off + i], 0x90) << f.name << " byte " << i;
    }
    // 地址有序、互不重叠、落在 .text RVA 域内
    EXPECT_LT(ctx.functions[0].begin_rva, ctx.functions[1].begin_rva);
    EXPECT_LE(ctx.functions[0].end_rva, ctx.functions[1].begin_rva);
    size_t lo = 0, hi = 0;
    ASSERT_TRUE(text_rva_range(image, lo, hi));
    for (const auto& f : ctx.functions) {
        EXPECT_GE(f.begin_rva, lo);
        EXPECT_LE(f.end_rva, hi);
    }
}
#endif
