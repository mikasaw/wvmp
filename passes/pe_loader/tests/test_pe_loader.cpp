// pe_loader 泳道测试：
//  1) 手工拼装最小合法 PE（DOS+NT+节表）→ 解析字段断言；
//  2) rva_to_offset / offset_to_rva 边界（节内 / 节间隙 / 头部 / bss）；
//  3) pass 级：文件读入 + 槽存储 + 各类畸形输入的失败路径。

#include "wvmp/passes/pe_loader/pe_image.hpp"
#include "wvmp/passes/pe_loader/pe_loader_pass.hpp"
#include "wvmp/passes/pe_loader/target_arch.hpp"

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
// image_base 默认 0x400000；PE32+ 8B 字段写入, PE32 按真实布局写入——
// BaseOfData @opt+24、ImageBase @opt+28（MIT-414：漏读 BaseOfData 是
// pe_loader PE32 分支三字段错位的根因，fixture 必须按真实布局构造）。
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
    // OptionalHeader（EntryPoint @16 / BaseOfData @24 (PE32) / ImageBase
    // @28 (PE32) 或 @24 (PE32+) / SectionAlignment @32 / FileAlignment @36,
    // 两种格式对齐到 @32）
    put16(img, opt + 0, pe32_plus ? 0x20B : 0x10B);
    put32(img, opt + 16, 0x1234);  // AddressOfEntryPoint
    put32(img, opt + 20, 0x1000);  // BaseOfCode
    if (pe32_plus) {
        for (int i = 0; i < 8; ++i) img[opt + 24 + i] = u8(image_base >> (8 * i));
    } else {
        put32(img, opt + 24, 0x2000);       // BaseOfData（PE32 独占字段）
        put32(img, opt + 28, u32(image_base));
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

// —— MIT-525 (CR-06/CR-07) 夹具：带 IMAGE_DIRECTORY_ENTRY_EXCEPTION 的 PE ——
//
// 表体放在 .text 内：RVA 0x1100 ↔ 文件偏移 0x300（.text VA 0x1000 ↔ 0x200），
// 单条 RUNTIME_FUNCTION{ begin=0x1100, end=0x1180, unwind_info=0x1190 }。
// 两种格式共用同一份表体与同一条目录项，只差 OptionalHeader 布局 ⇒ 双格式
// 对照才有意义（判据 1）。
constexpr u32 kPdataRva = 0x1100;
constexpr u32 kPdataFileOff = 0x300;
constexpr u32 kPfBegin = 0x1100;
constexpr u32 kPfEnd = 0x1180;
constexpr u32 kPfUnwind = 0x1190;

// DataDirectory 起点 / NumberOfRvaAndSizes 在 OptionalHeader 内的偏移，与仓内
// 既有真源同值（pe_writer_pass.cpp:70、tls_hook_pass.cpp:53、
// import_protect_pass.cpp:30 的 opt_data_dir_off / opt_num_rva_sizes_off）。
size_t opt_dir_off(bool plus) { return plus ? 112u : 96u; }
size_t opt_num_dirs_off(bool plus) { return plus ? 108u : 92u; }

void put_pdata_dir(std::vector<u8>& img, bool plus, u32 num_dirs, u32 dir3_rva,
                   u32 dir3_size, u32 dir4_rva = 0, u32 dir4_size = 0) {
    const size_t opt = 0x40 + 24;
    put32(img, opt + opt_num_dirs_off(plus), num_dirs);
    put32(img, opt + opt_dir_off(plus) + 3 * 8, dir3_rva);
    put32(img, opt + opt_dir_off(plus) + 3 * 8 + 4, dir3_size);
    put32(img, opt + opt_dir_off(plus) + 4 * 8, dir4_rva);
    put32(img, opt + opt_dir_off(plus) + 4 * 8 + 4, dir4_size);
}

// 落表体（3 个 u32）到 .text 内 0x1100。
void put_runtime_function(std::vector<u8>& img) {
    put32(img, kPdataFileOff + 0, kPfBegin);
    put32(img, kPdataFileOff + 4, kPfEnd);
    put32(img, kPdataFileOff + 8, kPfUnwind);
}

// 默认正例夹具：表 + DataDirectory[3]={kPdataRva,12} + NumberOfRvaAndSizes=16。
std::vector<u8> build_pe_with_pdata(bool plus, u32 num_dirs = 16) {
    std::vector<u8> img =
        build_minimal_pe(plus, plus ? kMachineX64 : kMachineX86);
    put_runtime_function(img);
    put_pdata_dir(img, plus, num_dirs, kPdataRva, 12);
    return img;
}

// 短 SizeOfOptionalHeader 夹具（PE32）：opt_size 缩到 0x78 ⇒ 声明区间
// [0,0x78) 不再完整覆盖 DataDirectory[0..3] 所需的 [0x60,0x80)。节表随之
// 平移到 0xD0，第一项取名 ".pd"（SizeOfRawData=0，不参与 RVA 映射），其
// name[4..7] 与 VirtualSize 两字段恰好是旧实现（skip 0x3C 多跳 4B）误读
// 的那 8 字节 —— 修复前会从节表字节里读出 1 条"合法"表项（0x1100/12），
// 修复后必须在"目录区间落位"这一层就判为无异常目录。
std::vector<u8> build_pe_short_opt_with_pdata_shape() {
    const size_t nt = 0x40;
    const size_t opt = nt + 24;
    const u16 opt_size = 0x78;
    const size_t sec = opt + opt_size; // 0xD0
    std::vector<u8> img(0x400, 0);

    put16(img, 0x00, 0x5A4D);
    put32(img, 0x3C, u32(nt));
    put32(img, nt + 0, 0x00004550);
    put16(img, nt + 4, kMachineX86);
    put16(img, nt + 6, 2);          // .pd + .text
    put16(img, nt + 20, opt_size);
    put16(img, opt + 0, 0x10B);     // PE32
    put32(img, opt + 16, 0x1234);   // AddressOfEntryPoint
    put32(img, opt + 20, 0x1000);   // BaseOfCode
    put32(img, opt + 24, 0x2000);   // BaseOfData
    put32(img, opt + 28, 0x400000); // ImageBase
    put32(img, opt + 32, 0x1000);   // SectionAlignment
    put32(img, opt + 36, 0x200);    // FileAlignment
    // NumberOfRvaAndSizes 照写满 16：本例要单独钉"区间落位"这一层，
    // 不让目录计数层先替它背锅。
    put32(img, opt + opt_num_dirs_off(false), 16);

    // 节表项 1 = ".pd"：name[4..7]=00 11 00 00（旧实现读作目录 RVA=0x1100）、
    // VirtualSize=12（旧实现读作目录 Size=12）。
    std::memcpy(&img[sec], ".pd", 4);
    put32(img, sec + 4, 0x1100);    // name[4..7]（旧实现读作目录 RVA=0x1100）
    put32(img, sec + 8, 12);        // VirtualSize（旧实现读作目录 Size）
    put32(img, sec + 12, 0x3000);   // VirtualAddress
    put32(img, sec + 36, 0xE0000040); // CNT_INITIALIZED_DATA|MEM_READ|MEM_WRITE
    // 节表项 2 = ".text"（与 build_minimal_pe 同布局）。
    const size_t s2 = sec + 40;
    std::memcpy(&img[s2], ".text", 5);
    put32(img, s2 + 8, 0x200);   // VirtualSize
    put32(img, s2 + 12, 0x1000); // VirtualAddress
    put32(img, s2 + 16, 0x200);  // SizeOfRawData
    put32(img, s2 + 20, 0x200);  // PointerToRawData
    put32(img, s2 + 36, 0x60000020);
    put_runtime_function(img);
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

// MIT-414 (G7p2 B.1) 回归：PE32 分支必须跳过 BaseOfData 再读 ImageBase。
// 修复前 pe_image.cpp 漏读 BaseOfData → image_base=0x2000(BaseOfData)、
// section_alignment=0x400000(ImageBase)、file_alignment=0x1000(SectionAlignment)
// 三字段错位 4B；triage §3.3 实测后果链：stub_link 把 .wvmp 对齐到 0x400000
// → 加载器节 VA 连续性拒绝（WinError 193）。hello32/craft32 直读对照见
// MIT-414 报告（真实字段 BaseOfData=0x2000/ImageBase=0x400000/
// SectionAlignment=0x1000/FileAlignment=0x200，与此 fixture 同构）。
TEST(PeImageParse, Pe32OptionalHeaderFieldLayout) {
    const auto bytes = build_minimal_pe(false, kMachineX86, 0x400000u);
    const wvmp::passes::PeImage img = wvmp::passes::parse_pe_image(bytes);

    EXPECT_FALSE(img.is_pe32_plus);
    EXPECT_EQ(img.machine, kMachineX86);
    EXPECT_EQ(img.entry_point_rva, 0x1234u);
    EXPECT_EQ(img.image_base, 0x400000u);      // opt+28 的 ImageBase（非 opt+24 的 BaseOfData）
    EXPECT_EQ(img.section_alignment, 0x1000u); // 修复前误读为 0x400000
    EXPECT_EQ(img.file_alignment, 0x200u);     // 修复前误读为 0x1000
    EXPECT_EQ(img.num_sections, u16(1));
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

// MIT-446 (X4) D1 解禁：x86 输入通行（auto 槽缺省 = machine 推导）。解析
// 模型落槽，下游 x86 全管道承接（此前 MIT-414 的硬拒文案随解禁翻正，
// mismatch 象限维持硬拒——见 TargetArchDeclGate）。
TEST(PeLoaderPass, AutoDeclX86InputPassesAfterD1Unlock) {
    ProtectionContext ctx;
    ctx.input_path = write_temp("x86_target.exe", build_minimal_pe(false, kMachineX86));
    wvmp::passes::PeLoaderPass pass;

    EXPECT_NO_THROW(pass.run(ctx));
    EXPECT_FALSE(ctx.diag.has_errors());
    const wvmp::passes::PeImage* meta = ctx.find_slot<wvmp::passes::PeImage>(
        wvmp::passes::kImageMeta);
    ASSERT_NE(meta, nullptr);
    EXPECT_FALSE(meta->is_pe32_plus);
    EXPECT_EQ(meta->machine, kMachineX86);
}

// MIT-438 (X1b) B.5: CLI arch 声明校验挂点——X64 声明与目标不符 → rc=2 显
// 拒（x86 machine 上消息区分于旧 C5 文本）；X64 声明 + x64 machine → 正常
// 路径；X86 声明 + x86 machine → MIT-446 (X4) D1 解禁放行；X86 声明 + x64
// machine → 声明不符维持拒。
TEST(PeLoaderPass, TargetArchDeclGate) {
    // X64 声明 + x64 machine → 正常通过（槽写入后常规路径零回踩）。
    {
        ProtectionContext ctx;
        ctx.input_path = write_temp("decl_x64_ok.exe", build_minimal_pe(true, kMachineX64));
        ctx.slot<wvmp::u8>(wvmp::passes::kTargetArchDecl) = wvmp::passes::kTargetArchX64;
        wvmp::passes::PeLoaderPass pass;
        EXPECT_NO_THROW(pass.run(ctx));
        EXPECT_FALSE(ctx.diag.has_errors());
        EXPECT_TRUE(ctx.has_slot(wvmp::passes::kImageMeta));
    }
    // X64 声明 + x86 machine → 声明不符显式拒（消息 ≠ C5 文本）。
    {
        ProtectionContext ctx;
        ctx.input_path = write_temp("decl_x64_mismatch.exe",
                                    build_minimal_pe(false, kMachineX86));
        ctx.slot<wvmp::u8>(wvmp::passes::kTargetArchDecl) = wvmp::passes::kTargetArchX64;
        wvmp::passes::PeLoaderPass pass;
        EXPECT_THROW(pass.run(ctx), std::runtime_error);
        EXPECT_TRUE(ctx.diag.has_errors());
        EXPECT_FALSE(ctx.has_slot(wvmp::passes::kImageMeta));
        bool saw_mismatch = false;
        for (const auto& d : ctx.diag.items())
            if (d.severity == wvmp::Severity::Error &&
                d.message.find("config arch=x64 与目标") != std::string::npos)
                saw_mismatch = true;
        EXPECT_TRUE(saw_mismatch);
    }
    // X86 声明 + x86 machine（匹配）：MIT-446 (X4) D1 解禁 → 放行。
    {
        ProtectionContext ctx;
        ctx.input_path = write_temp("decl_x86_matched.exe",
                                    build_minimal_pe(false, kMachineX86));
        ctx.slot<wvmp::u8>(wvmp::passes::kTargetArchDecl) = wvmp::passes::kTargetArchX86;
        wvmp::passes::PeLoaderPass pass;
        EXPECT_NO_THROW(pass.run(ctx));
        EXPECT_FALSE(ctx.diag.has_errors());
        const wvmp::passes::PeImage* meta = ctx.find_slot<wvmp::passes::PeImage>(
            wvmp::passes::kImageMeta);
        ASSERT_NE(meta, nullptr);
        EXPECT_EQ(meta->machine, kMachineX86);
    }
    // X86 声明 + x64 machine → 声明不符显式拒。
    {
        ProtectionContext ctx;
        ctx.input_path = write_temp("decl_x86_mismatch.exe",
                                    build_minimal_pe(true, kMachineX64));
        ctx.slot<wvmp::u8>(wvmp::passes::kTargetArchDecl) = wvmp::passes::kTargetArchX86;
        wvmp::passes::PeLoaderPass pass;
        EXPECT_THROW(pass.run(ctx), std::runtime_error);
        EXPECT_TRUE(ctx.diag.has_errors());
        EXPECT_FALSE(ctx.has_slot(wvmp::passes::kImageMeta));
    }
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

// —— MIT-525 (CR-06/CR-07)：异常目录绝对定位 + 目录计数/区间校验 ——————————
//
// 判据要求"修复前必红"，故每条断言都在注释里写清修前实际读数与成因：
//   CR-06 —— 读完 FileAlignment 后 reader 已在 opt+0x28（两种格式同点），
//     PE32 的 DataDirectory 起点是 opt+0x60 ⇒ 跳距 0x38，旧码写 0x3C 多跳
//     4B，实际读的是 DataDirectory[3].Size（当 RVA）+ DataDirectory[4].RVA
//     （当 Size）。PE32+ 侧 0x48 本就对，所以只有 PE32 读空。
//   CR-07 —— 全文件从不读 NumberOfRvaAndSizes，也不校验目录项是否完整落在
//     SizeOfOptionalHeader 内，还按未校验的 Size 预分配 pdata。

// 判据 1 正例（双格式对照）：同一条 (0x1100,0x1180,0x1190) 表分别打进
// PE32 与 PE32+ ⇒ 修后两者都读 1 条且三元组逐字段相等。
// 修前读数：PE32+ 1 条 / PE32 **0 条**（pdata_empty=true，CR-06 多跳 4B）。
TEST(PeImagePdata, DualFormatReadsSameExceptionTable) {
    const wvmp::passes::PeImage plus =
        wvmp::passes::parse_pe_image(build_pe_with_pdata(true));
    const wvmp::passes::PeImage pe32 =
        wvmp::passes::parse_pe_image(build_pe_with_pdata(false));

    // 先各自钉住期望三元组（不做"两边都 ≥1 条"的同义反复，判据 4）
    ASSERT_EQ(plus.pdata.size(), 1u) << "PE32+ 侧修前也红 ⇒ 说明夹具坏了";
    EXPECT_FALSE(plus.pdata_empty);
    EXPECT_EQ(plus.pdata[0].begin_rva, kPfBegin);
    EXPECT_EQ(plus.pdata[0].end_rva, kPfEnd);
    EXPECT_EQ(plus.pdata[0].unwind_info_rva, kPfUnwind);

    ASSERT_EQ(pe32.pdata.size(), 1u) << "CR-06：修前 PE32 读 0 条（目录 RVA 拿成了 Size）";
    EXPECT_FALSE(pe32.pdata_empty) << "CR-06：修前 PE32 pdata_empty 恒 true";
    EXPECT_EQ(pe32.pdata[0].begin_rva, kPfBegin);
    EXPECT_EQ(pe32.pdata[0].end_rva, kPfEnd);
    EXPECT_EQ(pe32.pdata[0].unwind_info_rva, kPfUnwind);

    // 双格式必须读到同一条目，而不是"都非空"就算数
    EXPECT_EQ(plus.pdata[0].begin_rva, pe32.pdata[0].begin_rva);
    EXPECT_EQ(plus.pdata[0].end_rva, pe32.pdata[0].end_rva);
    EXPECT_EQ(plus.pdata[0].unwind_info_rva, pe32.pdata[0].unwind_info_rva);

    // 上界查询是下游唯一消费面（ExitNative），一并钉住
    EXPECT_EQ(plus.find_function_end_rva(kPfBegin), std::optional<u64>(kPfEnd));
    EXPECT_EQ(pe32.find_function_end_rva(kPfBegin), std::optional<u64>(kPfEnd));
}

// 判据 1 负例①②：NumberOfRvaAndSizes = 0 / 3 ⇒ 无异常目录。
// 修前读数：两者都读出 1 条（旧码从不读该字段），故两条都必红。
// 取 PE32+ 构造：PE32+ 侧旧偏移本就正确，红了只能是因为缺目录计数校验。
TEST(PeImagePdata, SmallNumberOfRvaAndSizesFallsBack) {
    for (u32 n : {0u, 3u}) {
        const wvmp::passes::PeImage img =
            wvmp::passes::parse_pe_image(build_pe_with_pdata(true, n));
        EXPECT_TRUE(img.pdata_empty) << "NumberOfRvaAndSizes=" << n;
        EXPECT_TRUE(img.pdata.empty()) << "NumberOfRvaAndSizes=" << n;
        EXPECT_EQ(img.find_function_end_rva(kPfBegin), std::nullopt)
            << "NumberOfRvaAndSizes=" << n;
    }
}

// 判据 1 负例③（=4 边界档，双格式）：恰好容得下 DataDirectory[3] 的最小
// 计数必须被接受。修前读数：PE32+ 1 条 ✓ / PE32 **0 条** ✗（CR-06）⇒ 必红。
TEST(PeImagePdata, NumberOfRvaAndSizesFourIsAccepted) {
    const wvmp::passes::PeImage plus =
        wvmp::passes::parse_pe_image(build_pe_with_pdata(true, 4));
    const wvmp::passes::PeImage pe32 =
        wvmp::passes::parse_pe_image(build_pe_with_pdata(false, 4));

    ASSERT_EQ(plus.pdata.size(), 1u);
    EXPECT_EQ(plus.pdata[0].begin_rva, kPfBegin);
    ASSERT_EQ(pe32.pdata.size(), 1u) << "CR-06：修前 PE32 在 =4 档同样读 0 条";
    EXPECT_EQ(pe32.pdata[0].begin_rva, kPfBegin);
    EXPECT_EQ(pe32.pdata[0].end_rva, kPfEnd);
}

// 判据 1 负例④：短 SizeOfOptionalHeader（声明区间盖不住目录项）。
// 夹具见 build_pe_short_opt_with_pdata_shape 注释。修前读数：1 条（从节表
// 的 ".pd" 名字字段 + VirtualSize 里拼出 RVA=0x1100/Size=12）⇒ 必红。
TEST(PeImagePdata, ShortSizeOfOptionalHeaderFallsBack) {
    const wvmp::passes::PeImage img = wvmp::passes::parse_pe_image(
        build_pe_short_opt_with_pdata_shape());

    EXPECT_TRUE(img.pdata_empty)
        << "CR-07：修前不看 SizeOfOptionalHeader，把节表字节当目录读了 1 条";
    EXPECT_TRUE(img.pdata.empty());
    // 夹具本身仍可解析（两节、.text 映射正常）——排除"整个解析炸了"的假绿
    ASSERT_EQ(img.sections.size(), 2u);
    EXPECT_NE(img.find_section(".text"), nullptr);
    EXPECT_EQ(img.rva_to_offset(kPdataRva), std::optional<u64>(kPdataFileOff));
}

// 判据 1 负例⑤：目录 Size 越界（0xFFFFFFFF）⇒ 不得据未校验的 Size 预分配。
// 修前读数：pdata_empty=true（扫描到第 2 条落空即回退），但 reserve 已按
// 0xFFFFFFFF/12 = 357,913,941 条（≈4.3GB）预分配 ⇒ capacity 断言必红。
TEST(PeImagePdata, HugeDirectorySizeDoesNotPreallocate) {
    std::vector<u8> bytes = build_pe_with_pdata(true);
    put_pdata_dir(bytes, true, 16, kPdataRva, 0xFFFFFFFFu);

    const wvmp::passes::PeImage img = wvmp::passes::parse_pe_image(bytes);
    EXPECT_TRUE(img.pdata_empty);
    EXPECT_TRUE(img.pdata.empty());
    // 表体第 2 条落空即停 ⇒ 容量只会是 push_back 的几何级数，不是 Size 的
    // 一次性预分配。留足余量（64）以免绑定实现细节。
    EXPECT_LE(img.pdata.capacity(), 64u)
        << "CR-07：按目录 Size 预分配 = " << img.pdata.capacity() << " 条";
}

// 判据 1 负例⑥：把旧 bug 的读数形态还原回来（Size 与下一目录 RVA 互换），
// 跑在修后代码上必须读不出目录。只修对 RVA 那一半、Size 那半没动的实现，
// 会在这里读出 begin/end/unwind 拼接垃圾值的"1 条"。
TEST(PeImagePdata, OldBugShapeIsNotMistakenForATable) {
    std::vector<u8> bytes = build_minimal_pe(false, kMachineX86);
    put_runtime_function(bytes);
    // 真目录（修后该读的 8 字节）：RVA 是永不映射的垃圾、Size 借给下一目录
    put_pdata_dir(bytes, false, 16, 0xDEAD'0000u, kPdataRva, /*dir4_rva=*/12,
                  /*dir4_size=*/0);

    const wvmp::passes::PeImage img = wvmp::passes::parse_pe_image(bytes);
    // 修前：读 RVA=0x1100（dir3.Size）/ Size=12（dir4.RVA）⇒ 1 条真表项，
    // 看着"对"却是错位拼出来的 ⇒ 两条断言都必红。
    EXPECT_TRUE(img.pdata_empty) << "错位形态在修后仍被当成目录读出";
    EXPECT_TRUE(img.pdata.empty());
}

// 判据 1 负例⑦：PE32 侧同样要吃到目录计数校验（旧码在 PE32 上错位读，
// 单靠格式对照看不出计数层缺失）。修前读数：RVA 取 dir3.Size=0x1100、
// Size 取 dir4.RVA=12 ⇒ 1 条 ⇒ 必红。
TEST(PeImagePdata, Pe32SmallNumberOfRvaAndSizesFallsBack) {
    std::vector<u8> bytes = build_minimal_pe(false, kMachineX86);
    put_runtime_function(bytes);
    put_pdata_dir(bytes, false, /*num_dirs=*/3, kPdataRva, 0x1100u,
                  /*dir4_rva=*/12, /*dir4_size=*/0);

    const wvmp::passes::PeImage img = wvmp::passes::parse_pe_image(bytes);
    EXPECT_TRUE(img.pdata_empty) << "CR-07：修前 PE32 不校验目录计数即读表";
    EXPECT_TRUE(img.pdata.empty());
}

// 回归保护：既有 PE32/PE32+ 夹具从不写 NumberOfRvaAndSizes（=0）也不写目录
// ⇒ 修后仍须"无异常目录"，且不得因三层校验而抛错（回退链语义，判据 7）。
TEST(PeImagePdata, NoDirectoryAtAllStillParsesAndFallsBack) {
    for (bool plus : {false, true}) {
        const wvmp::passes::PeImage img =
            wvmp::passes::parse_pe_image(build_minimal_pe(plus, plus ? kMachineX64 : kMachineX86));
        EXPECT_TRUE(img.pdata_empty) << "plus=" << plus;
        EXPECT_TRUE(img.pdata.empty()) << "plus=" << plus;
        EXPECT_EQ(img.num_sections, 1u) << "plus=" << plus;
    }
}

