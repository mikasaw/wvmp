// MIT-465 (TLS 回调基建 v1)：tls_hook 单测 —— 双架构占位回调桩/回调数组/
// IMAGE_TLS_DIRECTORY 装配 + 原 TLS 目录合并 + 无 .wvmp 空转 + pe_writer
// 的 DataDirectory[9] 表项落位。

#include "wvmp/passes/tls_hook/tls_hook_pass.hpp"
#include "wvmp/passes/tls_hook/tls_plan.hpp"

#include "wvmp/passes/anti_debug/anti_debug_plan.hpp"

#include "wvmp/passes/pe_loader/pe_image.hpp"
#include "wvmp/passes/pe_writer/pe_writer_pass.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"

#include <gtest/gtest.h>

#include <cstring>
#include <fstream>
#include <string>
#include <iterator>
#include <vector>

namespace {

using namespace wvmp;
using namespace wvmp::passes;
using wvmp::passes::tls_hook::TlsPlan;

constexpr size_t kNt = 0x80;   // 合成镜像的 NT 头偏移（e_lfanew）
constexpr size_t kOpt = kNt + 24;  // OptionalHeader 偏移

// 合成最小 PE 镜像：DOS 头 + NT（签名+FILE+OPT+16 目录项）+ 单节表项
// （.text：VA 0x1000，raw 0x400 字节 @ 文件偏移 0x400）。
std::vector<u8> make_image(bool plus, u16 machine, u64 base, u32 num_dirs = 16) {
    const size_t opt_size = plus ? 240 : 224;
    const size_t table = kOpt + opt_size;
    std::vector<u8> img(table + 40 + 0x400, 0);
    img[0] = 'M';
    img[1] = 'Z';
    for (int i = 0; i < 4; ++i) img[0x3C + i] = u8((kNt >> (8 * i)) & 0xFF);
    img[kNt] = 'P';
    img[kNt + 1] = 'E';
    auto wr16 = [&](size_t off, u16 v) {
        img[off] = u8(v & 0xFF);
        img[off + 1] = u8((v >> 8) & 0xFF);
    };
    auto wr32 = [&](size_t off, u32 v) {
        for (int i = 0; i < 4; ++i) img[off + i] = u8((v >> (8 * i)) & 0xFF);
    };
    wr16(kNt + 4, machine);           // Machine
    wr16(kNt + 6, 1);                 // NumberOfSections
    wr16(kNt + 20, u16(opt_size));    // SizeOfOptionalHeader
    wr16(kNt + 22, 0x0022);           // Characteristics
    wr16(kOpt, plus ? 0x020B : 0x010B);
    wr32(kOpt + 16, 0x1000);          // SectionAlignment
    wr32(kOpt + 20, 0x200);           // FileAlignment
    wr32(kOpt + (plus ? 24 : 28), u32(base));  // ImageBase（PE32+ 24 / PE32 28）
    wr32(kOpt + 56, 0x2000);          // SizeOfImage
    wr32(kOpt + 60, 0x200);           // SizeOfHeaders
    wr32(kOpt + (plus ? 108 : 92), num_dirs);  // NumberOfRvaAndSizes
    const size_t sh = table;
    std::memcpy(&img[sh], ".text", 5);
    wr32(sh + 8, 0x400);              // VirtualSize
    wr32(sh + 12, 0x1000);            // VirtualAddress
    wr32(sh + 16, 0x400);             // SizeOfRawData
    wr32(sh + 20, 0x400);             // PointerToRawData
    wr32(sh + 36, 0x60000020);        // Characteristics
    return img;
}

PeImage make_meta(bool plus, u16 machine, u64 base) {
    PeImage m;
    m.is_pe32_plus = plus;
    m.machine = machine;
    m.image_base = base;
    m.section_alignment = 0x1000;
    m.file_alignment = 0x200;
    m.num_sections = 1;
    m.nt_headers_offset = u32(kNt);
    SectionInfo s;
    s.name = ".text";
    s.virtual_size = 0x400;
    s.virtual_addr = 0x1000;
    s.raw_size = 0x400;
    s.raw_ptr = 0x400;
    s.characteristics = 0x60000020;
    m.sections.push_back(s);
    return m;
}

u64 rd(const std::vector<u8>& v, size_t off, size_t w) {
    u64 x = 0;
    for (size_t i = 0; i < w; ++i) x |= u64(v[off + i]) << (8 * i);
    return x;
}

// 造一个已存在原 TLS 的镜像（目录 @ RVA 0x1000、数组 @ RVA 0x1010，
// 数组 2 项 + NULL），返回原字段快照供断言。
struct OrigTlsFixture {
    std::vector<u8> image;
    u64 start, end, index, cb0, cb1;
};

OrigTlsFixture make_image_with_orig_tls(bool plus, u16 machine, u64 base) {
    OrigTlsFixture f;
    f.image = make_image(plus, machine, base);
    const size_t w = plus ? 8 : 4;
    const size_t dir_off = 0x400 + 0x00;   // RVA 0x1000 → 文件 0x400
    const size_t arr_off = 0x400 + 0x40;   // RVA 0x1040 → 文件 0x440
                                            // （离目录 6 字段至少 0x28，勿重叠）
    f.start = base + 0x3000;
    f.end = base + 0x3100;
    f.index = base + 0x3200;
    f.cb0 = base + 0x1800;
    f.cb1 = base + 0x1900;
    auto wr = [&](size_t off, u64 v, size_t width) {
        for (size_t i = 0; i < width; ++i) f.image[off + i] = u8((v >> (8 * i)) & 0xFF);
    };
    wr(dir_off, f.start, w);
    wr(dir_off + w, f.end, w);
    wr(dir_off + 2 * w, f.index, w);
    wr(dir_off + 3 * w, base + 0x1040, w);  // AddressOfCallBacks
    wr(dir_off + 4 * w, 0, 4);              // SizeOfZeroFill
    wr(dir_off + 4 * w + 4, 0, 4);          // Characteristics
    // 目录表项 [9] 指向原目录（可选头内）。
    const size_t dd = kOpt + (plus ? 112u : 96u) + 9 * 8;
    wr(dd, 0x1000, 4);
    wr(dd + 4, plus ? 40 : 24, 4);
    wr(arr_off, f.cb0, w);
    wr(arr_off + w, f.cb1, w);
    wr(arr_off + 2 * w, 0, w);  // NULL 终止符
    return f;
}

TEST(TlsHookFresh, X64LayoutAndBytes) {
    const u64 base = 0x140000000;
    ProtectionContext ctx;
    ctx.image = make_image(true, 0x8664, base);
    ctx.slot<PeImage>(kPeImage) = make_meta(true, 0x8664, base);
    NewSection sec;
    sec.name = ".wvmp";
    sec.data.assign(11, 0xAB);  // 非 16 对齐的尾，验证追加对齐
    sec.characteristics = 0xE0000040u;
    sec.requested_rva = 0x2000u;
    ctx.slot<std::vector<NewSection>>(kNewSections).push_back(sec);

    TlsHookPass pass;
    pass.run(ctx);

    const auto* plan = ctx.find_slot<TlsPlan>(kTlsPlan);
    ASSERT_NE(plan, nullptr);
    // 11 → 16 对齐后放桩（3B），24 对齐放 index 槽（8B），32 放数组（16B），
    // 48 放目录（40B）。
    EXPECT_EQ(plan->callback_rva, 0x2010u);
    EXPECT_EQ(plan->callback_va, base + 0x2010u);
    EXPECT_EQ(plan->array_rva, 0x2020u);
    EXPECT_EQ(plan->tls_dir_rva, 0x2030u);
    EXPECT_EQ(plan->tls_dir_size, 40u);
    EXPECT_EQ(plan->merged_originals, 0u);

    const auto* wvmp = ctx.find_slot<std::vector<NewSection>>(kNewSections);
    ASSERT_NE(wvmp, nullptr);
    ASSERT_FALSE(wvmp->empty());
    const auto& d = (*wvmp)[0].data;
    ASSERT_EQ(d.size(), 88u);
    // 前 11 字节原样保留 + 垫片零。
    EXPECT_EQ(d[0], 0xABu);
    EXPECT_EQ(d[10], 0xABu);
    EXPECT_EQ(d[11], 0u);
    // 回调桩 x64：xor eax,eax; ret —— keystone 选 XOR r/m,r 形式 = 31 C0 C3。
    EXPECT_EQ(d[16], 0x31u);
    EXPECT_EQ(d[17], 0xC0u);
    EXPECT_EQ(d[18], 0xC3u);
    // index 槽零。
    EXPECT_EQ(rd(d, 24, 8), 0u);
    // 回调数组：[cb_va][NULL]，8B 项。
    EXPECT_EQ(rd(d, 32, 8), base + 0x2010u);
    EXPECT_EQ(rd(d, 40, 8), 0u);
    // TLS 目录：start=end=index=idx 槽 VA，callbacks=数组 VA，零填充/特征 0。
    EXPECT_EQ(rd(d, 48, 8), base + 0x2018u);
    EXPECT_EQ(rd(d, 56, 8), base + 0x2018u);
    EXPECT_EQ(rd(d, 64, 8), base + 0x2018u);
    EXPECT_EQ(rd(d, 72, 8), base + 0x2020u);
    EXPECT_EQ(rd(d, 80, 4), 0u);
    EXPECT_EQ(rd(d, 84, 4), 0u);
}

TEST(TlsHookFresh, X86LayoutAndBytes) {
    const u64 base = 0x400000;
    ProtectionContext ctx;
    ctx.image = make_image(false, 0x014C, base);
    ctx.slot<PeImage>(kPeImage) = make_meta(false, 0x014C, base);
    NewSection sec;
    sec.name = ".wvmp";
    sec.data.assign(5, 0x11);
    sec.characteristics = 0xE0000040u;
    sec.requested_rva = 0x2000u;
    ctx.slot<std::vector<NewSection>>(kNewSections).push_back(sec);

    TlsHookPass pass;
    pass.run(ctx);

    const auto* plan = ctx.find_slot<TlsPlan>(kTlsPlan);
    ASSERT_NE(plan, nullptr);
    // 5 → 16 对齐放桩（5B），24 放 index 槽，32 放数组（8B），40 放目录（24B）。
    EXPECT_EQ(plan->callback_rva, 0x2010u);
    EXPECT_EQ(plan->callback_va, base + 0x2010u);
    EXPECT_EQ(plan->array_rva, 0x2020u);
    EXPECT_EQ(plan->tls_dir_rva, 0x2028u);
    EXPECT_EQ(plan->tls_dir_size, 24u);

    const auto& d = ctx.find_slot<std::vector<NewSection>>(kNewSections)->at(0).data;
    ASSERT_EQ(d.size(), 64u);
    // 回调桩 x86（stdcall）：xor eax,eax; ret 0Ch —— 31 C0 C2 0C 00。
    EXPECT_EQ(d[16], 0x31u);
    EXPECT_EQ(d[17], 0xC0u);
    EXPECT_EQ(d[18], 0xC2u);
    EXPECT_EQ(d[19], 0x0Cu);
    EXPECT_EQ(d[20], 0x00u);
    // 数组 4B 项：[cb_va][NULL]。
    EXPECT_EQ(rd(d, 32, 4), u32(base + 0x2010u));
    EXPECT_EQ(rd(d, 36, 4), 0u);
    // 目录 4B 字段。
    EXPECT_EQ(rd(d, 40, 4), u32(base + 0x2018u));  // start
    EXPECT_EQ(rd(d, 44, 4), u32(base + 0x2018u));  // end
    EXPECT_EQ(rd(d, 48, 4), u32(base + 0x2018u));  // index
    EXPECT_EQ(rd(d, 52, 4), u32(base + 0x2020u));  // callbacks
    EXPECT_EQ(rd(d, 56, 4), 0u);
    EXPECT_EQ(rd(d, 60, 4), 0u);
}

TEST(TlsHookMerge, PreservesOriginalFieldsAndAppendsCallbacks) {
    const u64 base = 0x140000000;
    OrigTlsFixture f = make_image_with_orig_tls(true, 0x8664, base);
    ProtectionContext ctx;
    ctx.image = std::move(f.image);
    ctx.slot<PeImage>(kPeImage) = make_meta(true, 0x8664, base);
    NewSection sec;
    sec.name = ".wvmp";
    sec.data.assign(16, 0);
    sec.requested_rva = 0x2000u;
    ctx.slot<std::vector<NewSection>>(kNewSections).push_back(sec);

    TlsHookPass pass;
    pass.run(ctx);

    const auto* plan = ctx.find_slot<TlsPlan>(kTlsPlan);
    ASSERT_NE(plan, nullptr);
    EXPECT_EQ(plan->merged_originals, 2u);
    const auto& d = ctx.find_slot<std::vector<NewSection>>(kNewSections)->at(0).data;
    // 数组：[我们的回调][原 cb0][原 cb1][NULL]。
    EXPECT_EQ(rd(d, 32, 8), base + 0x2010u);
    EXPECT_EQ(rd(d, 40, 8), f.cb0);
    EXPECT_EQ(rd(d, 48, 8), f.cb1);
    EXPECT_EQ(rd(d, 56, 8), 0u);
    // 目录 6 字段：start/end/index 原样保留，callbacks 换新数组 VA。
    EXPECT_EQ(rd(d, 64, 8), f.start);
    EXPECT_EQ(rd(d, 72, 8), f.end);
    EXPECT_EQ(rd(d, 80, 8), f.index);
    EXPECT_EQ(rd(d, 88, 8), base + 0x2020u);
}

// MIT-467：init 期 PEB 检查块挂 TLS 回调（anti_debug 计划驱动）。
TEST(TlsHookAdbInit, X64CarriesPebCheckBlock) {
    const u64 base = 0x140000000;
    ProtectionContext ctx;
    ctx.image = make_image(true, 0x8664, base);
    ctx.slot<PeImage>(kPeImage) = make_meta(true, 0x8664, base);
    NewSection sec;
    sec.name = ".wvmp";
    sec.data.assign(16, 0);
    sec.requested_rva = 0x2000u;
    ctx.slot<std::vector<NewSection>>(kNewSections).push_back(sec);
    wvmp::passes::anti_debug::AntiDebugPlan adb;
    adb.techniques = wvmp::passes::anti_debug::tech::kV1All;
    adb.init_techniques = wvmp::passes::anti_debug::tech::kV1All;
    ctx.slot<wvmp::passes::anti_debug::AntiDebugPlan>(kAntiDebugPlan) = adb;

    TlsHookPass pass;
    pass.run(ctx);

    const auto* plan = ctx.find_slot<tls_hook::TlsPlan>(kTlsPlan);
    ASSERT_NE(plan, nullptr);
    const auto& d = ctx.find_slot<std::vector<NewSection>>(kNewSections)->at(0).data;
    const size_t cb = size_t(plan->callback_rva - 0x2000);
    // x64 TEB 走访：mov rax, gs:[0x30]。keystone 可能出两种编码：
    //   65 48 8B 04 25 30 00 00 00（disp32 形）或
    //   65 48 A1 30 00 00 00 00 00 00（moffs64 形）——均语义等价。
    bool found = false;
    for (size_t i = cb; i + 10 <= d.size(); ++i) {
        const bool disp32 = d[i] == 0x65 && d[i+1] == 0x48 && d[i+2] == 0x8B &&
                            d[i+3] == 0x04 && d[i+4] == 0x25 && d[i+5] == 0x30;
        const bool moffs = d[i] == 0x65 && d[i+1] == 0x48 && d[i+2] == 0xA1 &&
                           d[i+3] == 0x30;
        if (disp32 || moffs) { found = true; break; }
    }
    if (!found) {
        char hexs[3];
        std::string dump;
        for (size_t i = cb; i + 1 <= d.size() && i < cb + 80; ++i) {
            std::snprintf(hexs, sizeof(hexs), "%02X", d[i]);
            dump += hexs;
        }
        ADD_FAILURE() << "stub bytes: " << dump;
    }
    EXPECT_TRUE(found);
}

TEST(TlsHookAdbInit, X86CarriesPebCheckBlock) {
    const u64 base = 0x400000;
    ProtectionContext ctx;
    ctx.image = make_image(false, 0x014C, base);
    ctx.slot<PeImage>(kPeImage) = make_meta(false, 0x014C, base);
    NewSection sec;
    sec.name = ".wvmp";
    sec.data.assign(16, 0);
    sec.requested_rva = 0x2000u;
    ctx.slot<std::vector<NewSection>>(kNewSections).push_back(sec);
    wvmp::passes::anti_debug::AntiDebugPlan adb;
    adb.init_techniques = wvmp::passes::anti_debug::tech::kBeingDebugged;  // 位面裁剪
    ctx.slot<wvmp::passes::anti_debug::AntiDebugPlan>(kAntiDebugPlan) = adb;

    TlsHookPass pass;
    pass.run(ctx);

    const auto* plan = ctx.find_slot<tls_hook::TlsPlan>(kTlsPlan);
    ASSERT_NE(plan, nullptr);
    const auto& d = ctx.find_slot<std::vector<NewSection>>(kNewSections)->at(0).data;
    const size_t cb = size_t(plan->callback_rva - 0x2000);
    // x86 TEB 走访：mov eax, fs:[0x18] = 64 A1 18 00 00 00。
    bool found = false;
    for (size_t i = cb; i + 6 <= d.size(); ++i) {
        if (d[i] == 0x64 && d[i+1] == 0xA1 && d[i+2] == 0x18 &&
            d[i+3] == 0x00 && d[i+4] == 0x00 && d[i+5] == 0x00) { found = true; break; }
    }
    EXPECT_TRUE(found);
    // 位面裁剪：NtGlobalFlag 检查（test eax, 0x70 = A9 70 00 00 00）不在场。
    bool ntg = false;
    for (size_t i = cb; i + 5 <= d.size(); ++i) {
        if (d[i] == 0xA9 && d[i+1] == 0x70) { ntg = true; break; }
    }
    EXPECT_FALSE(ntg);
}

TEST(TlsHookAdbInit, DisabledLeavesPlaceholderBytes) {
    const u64 base = 0x140000000;
    ProtectionContext ctx;
    ctx.image = make_image(true, 0x8664, base);
    ctx.slot<PeImage>(kPeImage) = make_meta(true, 0x8664, base);
    NewSection sec;
    sec.name = ".wvmp";
    sec.data.assign(16, 0);
    sec.requested_rva = 0x2000u;
    ctx.slot<std::vector<NewSection>>(kNewSections).push_back(sec);
    wvmp::passes::anti_debug::AntiDebugPlan adb;
    adb.init_techniques = 0;  // 关闭 init 面
    ctx.slot<wvmp::passes::anti_debug::AntiDebugPlan>(kAntiDebugPlan) = adb;

    TlsHookPass pass;
    pass.run(ctx);

    const auto& d = ctx.find_slot<std::vector<NewSection>>(kNewSections)->at(0).data;
    // v1 占位体：31 C0 C3（无 TEB 走访字节）。
    ASSERT_GE(d.size(), 19u);
    EXPECT_EQ(d[16], 0x31u);
    EXPECT_EQ(d[17], 0xC0u);
    EXPECT_EQ(d[18], 0xC3u);
}

TEST(TlsHookNoop, NoWvmpSectionLeavesNoPlan) {
    ProtectionContext ctx;
    ctx.image = make_image(true, 0x8664, 0x140000000);
    ctx.slot<PeImage>(kPeImage) = make_meta(true, 0x8664, 0x140000000);

    TlsHookPass pass;
    pass.run(ctx);

    EXPECT_EQ(ctx.find_slot<TlsPlan>(kTlsPlan), nullptr);
}

// —— pe_writer 侧：TlsPlan → DataDirectory[9] 表项 ——

std::vector<u8> read_file(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

TEST(TlsDirPatch, X64WritesDirectoryEntry) {
    const u64 base = 0x140000000;
    auto out = std::filesystem::temp_directory_path() / "wvmp_tls_patch_x64.bin";
    ProtectionContext ctx;
    ctx.image = make_image(true, 0x8664, base);
    ctx.output_path = out;
    ctx.slot<PeImage>(kPeImage) = make_meta(true, 0x8664, base);
    TlsPlan plan;
    plan.tls_dir_rva = 0x6000;
    plan.tls_dir_size = 40;
    ctx.slot<TlsPlan>(kTlsPlan) = plan;

    PeWriterPass pass;
    pass.run(ctx);

    const std::vector<u8> written = read_file(out);
    std::error_code ec;
    std::filesystem::remove(out, ec);
    ASSERT_EQ(written.size(), ctx.image.size());
    // dd[9] @ opt+112+72（PE32+）。
    const size_t dd9 = kOpt + 112 + 72;
    EXPECT_EQ(rd(written, dd9, 4), 0x6000u);
    EXPECT_EQ(rd(written, dd9 + 4, 4), 40u);
    // 其他目录项不动（dd[0] 在 opt+112）。
    EXPECT_EQ(rd(written, kOpt + 112, 8), 0u);
    // checksum 已重算（非零）。
    EXPECT_NE(rd(written, kOpt + 64, 4), 0u);
}

TEST(TlsDirPatch, X86WritesDirectoryEntry) {
    const u64 base = 0x400000;
    auto out = std::filesystem::temp_directory_path() / "wvmp_tls_patch_x86.bin";
    ProtectionContext ctx;
    ctx.image = make_image(false, 0x014C, base);
    ctx.output_path = out;
    ctx.slot<PeImage>(kPeImage) = make_meta(false, 0x014C, base);
    TlsPlan plan;
    plan.tls_dir_rva = 0x5000;
    plan.tls_dir_size = 24;
    ctx.slot<TlsPlan>(kTlsPlan) = plan;

    PeWriterPass pass;
    pass.run(ctx);

    const std::vector<u8> written = read_file(out);
    std::error_code ec;
    std::filesystem::remove(out, ec);
    // dd[9] @ opt+96+72（PE32）。
    const size_t dd9 = kOpt + 96 + 72;
    EXPECT_EQ(rd(written, dd9, 4), 0x5000u);
    EXPECT_EQ(rd(written, dd9 + 4, 4), 24u);
}

TEST(TlsDirPatch, SmallNumberOfRvaAndSizesFails) {
    auto out = std::filesystem::temp_directory_path() / "wvmp_tls_patch_fail.bin";
    ProtectionContext ctx;
    ctx.image = make_image(true, 0x8664, 0x140000000, /*num_dirs=*/9);
    ctx.output_path = out;
    ctx.slot<PeImage>(kPeImage) = make_meta(true, 0x8664, 0x140000000);
    TlsPlan plan;
    plan.tls_dir_rva = 0x6000;
    plan.tls_dir_size = 40;
    ctx.slot<TlsPlan>(kTlsPlan) = plan;

    PeWriterPass pass;
    EXPECT_THROW(pass.run(ctx), std::runtime_error);
    std::error_code ec;
    std::filesystem::remove(out, ec);
}

} // namespace
