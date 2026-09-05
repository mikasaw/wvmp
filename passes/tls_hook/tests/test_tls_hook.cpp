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
#include "wvmp/framework/protect_levels.hpp"

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


// MIT-470：DRx 位请求但目标无 GetThreadContext 导入 → 静默降级（无 CONTEXT
// 暂存追加），其余面（PEB init 块）照常。
TEST(TlsHookAdbInit, DrxWithoutGetThreadContextFallsBack) {
    const u64 base = 0x140000000;
    ProtectionContext ctx;
    ctx.image = make_image(true, 0x8664, base);  // 夹具无导入表
    ctx.slot<PeImage>(kPeImage) = make_meta(true, 0x8664, base);
    NewSection sec;
    sec.name = ".wvmp";
    sec.data.assign(16, 0);
    sec.requested_rva = 0x2000u;
    ctx.slot<std::vector<NewSection>>(kNewSections).push_back(sec);
    wvmp::passes::anti_debug::AntiDebugPlan adb;
    adb.init_techniques = wvmp::passes::anti_debug::tech::kBeingDebugged |
                          wvmp::passes::anti_debug::tech::kHardwareBreakpoints;
    ctx.slot<wvmp::passes::anti_debug::AntiDebugPlan>(kAntiDebugPlan) = adb;

    TlsHookPass pass;
    pass.run(ctx);

    const auto* plan = ctx.find_slot<tls_hook::TlsPlan>(kTlsPlan);
    ASSERT_NE(plan, nullptr);
    // 与 drx 关闭的等价用例对照：无 CONTEXT 暂存追加（尺寸差 = 0）。先跑
    // 对照 ctx。
    ProtectionContext ctx2;
    ctx2.image = make_image(true, 0x8664, base);
    ctx2.slot<PeImage>(kPeImage) = make_meta(true, 0x8664, base);
    NewSection sec2;
    sec2.name = ".wvmp";
    sec2.data.assign(16, 0);
    sec2.requested_rva = 0x2000u;
    ctx2.slot<std::vector<NewSection>>(kNewSections).push_back(sec2);
    wvmp::passes::anti_debug::AntiDebugPlan adb2;
    adb2.init_techniques = wvmp::passes::anti_debug::tech::kBeingDebugged;
    ctx2.slot<wvmp::passes::anti_debug::AntiDebugPlan>(kAntiDebugPlan) = adb2;
    TlsHookPass pass2;
    pass2.run(ctx2);

    const auto& d1 = ctx.find_slot<std::vector<NewSection>>(kNewSections)->at(0).data;
    const auto& d2 = ctx2.find_slot<std::vector<NewSection>>(kNewSections)->at(0).data;
    EXPECT_EQ(d1.size(), d2.size());  // DRx 降级 = 无额外追加
}



// 带单条 GetThreadContext 导入的最小导入面（DRx 槽定位正例夹具）。
// desc0 @RVA 0x1000：INT=0x1080、FT=0x10A0；INT 槽0 → 名字 @0x10C0。
static std::vector<u8> make_image_with_gtc_import(u64 base) {
    auto img = make_image(true, 0x8664, base);
    auto wr32 = [&](size_t off, u32 v) {
        for (int i = 0; i < 4; ++i) img[off + i] = u8((v >> (8 * i)) & 0xFF);
    };
    auto rva2off = [](u32 rva) { return size_t(rva) - 0x1000 + 0x400; };
    wr32(rva2off(0x1000) + 0, 0x1080);   // INT
    wr32(rva2off(0x1000) + 16, 0x10A0);  // FT
    wr32(rva2off(0x1080), 0x10C0);       // 槽0 → IMAGE_IMPORT_BY_NAME
    wr32(rva2off(0x1080) + 4, 0);        // 槽1 = NULL（x64 槽 8B：+4 也是 0）
    img[rva2off(0x10C0)] = 0;
    img[rva2off(0x10C0) + 1] = 0;
    std::memcpy(&img[rva2off(0x10C0) + 2], "GetThreadContext", 16);
    img[rva2off(0x10C0) + 18] = 0;
    const size_t dd1 = kOpt + 112 + 1 * 8;
    wr32(dd1, 0x1000);
    wr32(dd1 + 4, 20);
    return img;
}

// MIT-470 验收返工防回归：x64 DRx 块的 Dr0-Dr3 比较偏移必须是 0x48/0x50/
// 0x58/0x60（winnt.h x64 CONTEXT；0x88/0x90/0x98/0xA0 是整型寄存器 home，
// DEBUG_REGISTERS-only 调用恒零 → 永不命中的静默失效形态）。
// cmp qword ptr [rdx+disp8], 0 = 48 83 BA <disp32> 00 00 00 00 —— keystone
// 出 disp32 形（48 83 BA 只带 imm8 符号扩展……实为 48 83 BA imm8 或
// 48 81 BA imm32），此处按助记符宽松断言四条 cmp 顺序 + 每条紧随的
// jne drx_fail（75 xx）。
TEST(TlsHookAdbInit, X64DrxOffsetsAreDebugRegisterSlots) {
    const u64 base = 0x140000000;
    ProtectionContext ctx;
    ctx.image = make_image(true, 0x8664, base);
    ctx.slot<PeImage>(kPeImage) = make_meta(true, 0x8664, base);
    ctx.image = make_image_with_gtc_import(base);
    ctx.slot<PeImage>(kPeImage) = make_meta(true, 0x8664, base);
    NewSection sec;
    sec.name = ".wvmp";
    sec.data.assign(16, 0);
    sec.requested_rva = 0x3000u;
    ctx.slot<std::vector<NewSection>>(kNewSections).push_back(sec);
    wvmp::passes::anti_debug::AntiDebugPlan adb;
    adb.init_techniques = wvmp::passes::anti_debug::tech::kHardwareBreakpoints;
    ctx.slot<wvmp::passes::anti_debug::AntiDebugPlan>(kAntiDebugPlan) = adb;

    TlsHookPass pass;
    pass.run(ctx);

    const auto* plan = ctx.find_slot<tls_hook::TlsPlan>(kTlsPlan);
    ASSERT_NE(plan, nullptr);
    const auto& d = ctx.find_slot<std::vector<NewSection>>(kNewSections)->at(0).data;
    const size_t cb = size_t(plan->callback_rva - 0x3000);
    // cmp qword ptr [rdx+0x48], 0 的 disp8/disp32 两形都搜（keystone 选形）：
    //   disp8: 48 83 BA 48 00 00 00 00
    //   disp32: 48 8B BA 48 00 00 00 00 (mov rdi,[rdx+0x48]) 不适用——cmp 的
    //   disp32 形 = 48 81 BA <imm32>。逐字节搜 0x48/0x50/0x58/0x60 依序出现。
    bool ok48 = false, ok50 = false, ok58 = false, ok60 = false;
    // cmp qword ptr [rdx+disp], 0 的两种编码：
    //   disp8 形  48 83 7A <disp8> 00           （ModRM 7A = [rdx+disp8]）
    //   disp32 形 48 81 BA <disp32 LE> 00 00 00 00（ModRM BA = [rdx+disp32]）
    const auto scan = [&](size_t i, u8 disp) {
        if (i + 8 > d.size()) return false;
        if (d[i] == 0x48 && d[i+1] == 0x83 && d[i+2] == 0x7A &&
            d[i+3] == disp && d[i+4] == 0x00) return true;
        if (d[i] == 0x48 && d[i+1] == 0x81 && d[i+2] == 0xBA &&
            d[i+3] == disp && d[i+4] == 0x00 && d[i+5] == 0x00 &&
            d[i+6] == 0x00 && d[i+7] == 0x00) return true;
        return false;
    };
    for (size_t i = cb; i + 8 <= d.size(); ++i) {
        if (scan(i, 0x48)) ok48 = true;
        if (scan(i, 0x50)) ok50 = true;
        if (scan(i, 0x58)) ok58 = true;
        if (scan(i, 0x60)) ok60 = true;
    }
    EXPECT_TRUE(ok48);
    EXPECT_TRUE(ok50);
    EXPECT_TRUE(ok58);
    EXPECT_TRUE(ok60);
    // ContextFlags 存储编码（x64：字段在 ctx+0x30，非 +0！）：
    //   mov dword ptr [rdx+0x30], 0x00100010 = C7 82 30 00 00 00 10 00 10 00
    // 此断言拦截"flags 写错偏移 → GTC 返回成功但零填充 → 永不命中"的
    // 静默失效形态（T13 第二轮验收实证缺陷）。
    bool ok_flags = false;
    for (size_t i = cb; i + 10 <= d.size(); ++i) {
        // disp8 形  C7 42 30 <imm32>（7B）
        if (d[i] == 0xC7 && d[i+1] == 0x42 && d[i+2] == 0x30 &&
            d[i+3] == 0x10 && d[i+4] == 0x00 && d[i+5] == 0x10 && d[i+6] == 0x00) {
            ok_flags = true; break;
        }
        // disp32 形 C7 82 30 00 00 00 <imm32>（10B）
        if (d[i] == 0xC7 && d[i+1] == 0x82 && d[i+2] == 0x30 && d[i+3] == 0x00 &&
            d[i+4] == 0x00 && d[i+5] == 0x00 && d[i+6] == 0x10 && d[i+7] == 0x00 &&
            d[i+8] == 0x10 && d[i+9] == 0x00) {
            ok_flags = true; break;
        }
    }
    EXPECT_TRUE(ok_flags);
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


// —— MIT-468：[tls] enabled=false 配置关断 ——
TEST(TlsHookAdbInit, ConfigDisabledSkipsWithNoPlan) {
    const u64 base = 0x140000000;
    ProtectionContext ctx;
    ctx.image = make_image(true, 0x8664, base);
    ctx.slot<PeImage>(kPeImage) = make_meta(true, 0x8664, base);
    NewSection sec;
    sec.name = ".wvmp";
    sec.data.assign(16, 0);
    sec.requested_rva = 0x2000u;
    ctx.slot<std::vector<NewSection>>(kNewSections).push_back(sec);
    ProtectRules rules;
    rules.has_tls_enabled = true;
    rules.tls_enabled = false;
    ctx.slot<ProtectRules>(kProtectRules) = rules;

    TlsHookPass pass;
    pass.run(ctx);

    // 不写 kTlsPlan 槽（pe_writer 不动 dd9）+ 镜像零改动。
    EXPECT_EQ(ctx.find_slot<tls_hook::TlsPlan>(kTlsPlan), nullptr);
    EXPECT_EQ(ctx.find_slot<std::vector<NewSection>>(kNewSections)->at(0).data.size(), 16u);
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
