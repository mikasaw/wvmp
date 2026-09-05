// MIT-466 (import_protect v1)：合成带导入表 PE 的迁移单测 —— 描述符解析 /
// 连续 IAT 区迁移 / FirstThunk 重指 / 绑定导入与无导入回退 / tls_hook
// 联动（回调体携带 rep movs 回填循环）。

#include "wvmp/passes/import_protect/import_protect_pass.hpp"
#include "wvmp/passes/import_protect/import_plan.hpp"

#include "wvmp/passes/pe_loader/pe_image.hpp"
#include "wvmp/passes/tls_hook/tls_hook_pass.hpp"
#include "wvmp/passes/tls_hook/tls_plan.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"

#include <gtest/gtest.h>

#include <cstring>
#include <vector>

namespace {

using namespace wvmp;
using namespace wvmp::passes;
using import_protect::ImportPlan;

constexpr size_t kNt = 0x80;
constexpr size_t kOpt = kNt + 24;

// 合成 PE：结构同 tls_hook 测试，但 .text 加大（vs=rs=0x1000 @ 文件
// 0x400）容纳导入描述符 / INT / IAT。
std::vector<u8> make_image(bool plus, u16 machine, u64 base) {
    const size_t opt_size = plus ? 240 : 224;
    const size_t table = kOpt + opt_size;
    std::vector<u8> img(table + 40 + 0x1000, 0);
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
    wr16(kNt + 4, machine);
    wr16(kNt + 6, 1);
    wr16(kNt + 20, u16(opt_size));
    wr16(kNt + 22, 0x0022);
    wr16(kOpt, plus ? 0x020B : 0x010B);
    wr32(kOpt + 16, 0x1000);
    wr32(kOpt + 20, 0x200);
    wr32(kOpt + (plus ? 24 : 28), u32(base));
    wr32(kOpt + 56, 0x5000);
    wr32(kOpt + 60, 0x200);
    wr32(kOpt + (plus ? 108 : 92), 16);
    const size_t sh = table;
    std::memcpy(&img[sh], ".text", 5);
    wr32(sh + 8, 0x1000);
    wr32(sh + 12, 0x1000);
    wr32(sh + 16, 0x1000);
    wr32(sh + 20, 0x400);
    wr32(sh + 36, 0x60000020);
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
    s.virtual_size = 0x1000;
    s.virtual_addr = 0x1000;
    s.raw_size = 0x1000;
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

// 在 .text 内布置导入面（RVA 基 = 0x1000，文件偏移 = RVA - 0x1000 + 0x400）：
//   描述符链 @0x1000：desc0（INT@0x1100，FT@0x1200，2 槽）、
//                     desc1（INT@0x1300，FT@0x1218，1 槽，与 desc0 连续）、
//                     全零终止 @0x1040。
//   INT0 @0x1100：2 槽 + NULL；IAT0 @0x1200：2 槽 + NULL（终止槽与
//   IAT1 首槽相接）；INT1 @0x1300：1 槽 + NULL；IAT1 @0x1218：1 槽 + NULL。
// 返回 dd[1] 已指描述符链的镜像。
struct ImportFixture {
    std::vector<u8> image;
    u64 iat_base = 0x140000000 + 0x1200;  // FT0
    u32 desc_rva = 0x1000;
};

ImportFixture make_import_fixture(u64 base) {
    ImportFixture f;
    f.image = make_image(true, 0x8664, base);
    const u64 ib = base;
    auto wr32 = [&](size_t off, u32 v) {
        for (int i = 0; i < 4; ++i) f.image[off + i] = u8((v >> (8 * i)) & 0xFF);
    };
    auto rv2off = [](u32 rva) { return size_t(rva) - 0x1000 + 0x400; };

    // 描述符：desc0 / desc1 / 终止。
    wr32(rv2off(0x1000) + 0, 0x1100);   // desc0 INT
    wr32(rv2off(0x1000) + 16, 0x1200);  // desc0 FT
    wr32(rv2off(0x1000) + 20 + 0, 0x1300);      // desc1 INT
    wr32(rv2off(0x1000) + 20 + 16, 0x1218);     // desc1 FT（连续）
    // desc2 = 全零（20 字节已是 0）。
    // INT0 @0x1100：2 槽 + NULL（x64 槽宽 8B）。槽0 = VirtualProtect 名字
    // 导入（thunk → IMAGE_IMPORT_BY_NAME @0x1500：WORD hint + 名字），
    // 供 v1 硬依赖（回填需经其 IAT 槽调 VirtualProtect）。
    wr32(rv2off(0x1100), 0x1500);
    wr32(rv2off(0x1100) + 4, 0);
    wr32(rv2off(0x1100) + 8, 0x2222);
    wr32(rv2off(0x1100) + 12, 0);
    // IMAGE_IMPORT_BY_NAME @0x1500：hint(2B) + "VirtualProtect\0"。
    f.image[rv2off(0x1500)] = 0;
    f.image[rv2off(0x1500) + 1] = 0;
    std::memcpy(&f.image[rv2off(0x1500) + 2], "VirtualProtect", 14);
    f.image[rv2off(0x1500) + 16] = 0;
    // INT1 @0x1300：1 槽 + NULL（非名字匹配的杂散 thunk 值）。
    wr32(rv2off(0x1300), 0x3333);
    wr32(rv2off(0x1300) + 4, 0);
    // IAT0/IAT1 文件态预置 0（真实镜像为绑定值或 0——loader 运行期覆写）。
    (void)ib;

    // dd[1] → 描述符链。
    const size_t dd1 = kOpt + 112 + 1 * 8;
    wr32(dd1, 0x1000);
    wr32(dd1 + 4, 60);  // 3 × 20B
    return f;
}

NewSection make_wvmp(u32 rva) {
    NewSection sec;
    sec.name = ".wvmp";
    sec.data.assign(64, 0);
    sec.requested_rva = rva;
    return sec;
}

TEST(ImportProtectMigrate, X64ContiguousMigration) {
    const u64 base = 0x140000000;
    ProtectionContext ctx;
    ctx.image = make_image(true, 0x8664, base);
    ctx.slot<PeImage>(kPeImage) = make_meta(true, 0x8664, base);
    ctx.slot<std::vector<NewSection>>(kNewSections).push_back(make_wvmp(0x3000));
    ImportFixture fx = make_import_fixture(base);
    ctx.image = fx.image;

    ImportProtectPass pass;
    pass.run(ctx);

    const auto* plan = ctx.find_slot<ImportPlan>(kImportPlan);
    ASSERT_NE(plan, nullptr);
    EXPECT_TRUE(plan->active);
    EXPECT_EQ(plan->iat_base_rva, 0x1200u);
    // 跨度：FT0 [0x1200,0x1218) + FT1 [0x1218,0x1228) = 0x28 字节 = 5 槽位宽。
    EXPECT_EQ(plan->iat_bytes, 0x28u);
    EXPECT_EQ(plan->slot_count, 3u);      // 2 + 1
    EXPECT_EQ(plan->descriptor_count, 2u);
    EXPECT_EQ(plan->mirror_rva, 0x3040u);  // 64B 载荷 8 对齐后追加
    // v1 回填硬依赖面：VP 槽定位 + 页面覆盖 + oldprot 暂存。
    EXPECT_EQ(plan->vp_slot_rva, 0x1200u);            // desc0 FT + idx0
    EXPECT_EQ(plan->page_rva, 0x1000u);               // IAT 区首页
    EXPECT_EQ(plan->page_bytes, 0x1000u);             // 0x1200..0x1228 ⊂ [0x1000,0x2000)
    EXPECT_EQ(plan->oldprot_rva, 0x3068u);            // 镜像尾 8 对齐

    // dd[1] FirstThunk 重指：desc0 FT → 0x3040，desc1 FT → 0x3040+0x18。
    const auto rv2off = [](u32 rva) { return size_t(rva) - 0x1000 + 0x400; };
    EXPECT_EQ(rd(ctx.image, rv2off(0x1000) + 16, 4), 0x3040u);
    EXPECT_EQ(rd(ctx.image, rv2off(0x1000) + 20 + 16, 4), 0x3058u);
    // INT 原位保留。
    EXPECT_EQ(rd(ctx.image, rv2off(0x1000) + 0, 4), 0x1100u);
    EXPECT_EQ(rd(ctx.image, rv2off(0x1000) + 20 + 0, 4), 0x1300u);

    // .wvmp 尾部追加镜像乱数（非全零，且与原 IAT 区无关）+ 8B oldprot 暂存。
    const auto& d = ctx.find_slot<std::vector<NewSection>>(kNewSections)->at(0).data;
    ASSERT_EQ(d.size(), 64u + 0x28u + 8u);
    u32 nonzero = 0;
    for (size_t i = 64; i < d.size(); ++i) nonzero += (d[i] != 0);
    EXPECT_GT(nonzero, 0u);
}

TEST(ImportProtectMigrate, TlsHookCarriesBackfillLoop) {
    const u64 base = 0x140000000;
    ProtectionContext ctx;
    ctx.image = make_image(true, 0x8664, base);
    ctx.slot<PeImage>(kPeImage) = make_meta(true, 0x8664, base);
    ctx.slot<std::vector<NewSection>>(kNewSections).push_back(make_wvmp(0x3000));
    ctx.image = make_import_fixture(base).image;

    ImportProtectPass imp;
    imp.run(ctx);
    ASSERT_NE(ctx.find_slot<ImportPlan>(kImportPlan), nullptr);
    const u64 mirror_rva = ctx.find_slot<ImportPlan>(kImportPlan)->mirror_rva;

    // 先放一个原 TLS 目录（合并路径 + 回填体同桩验证）。
    ImportFixture dummy = make_import_fixture(base);
    (void)dummy;
    TlsHookPass tls;
    tls.run(ctx);

    const auto* plan = ctx.find_slot<tls_hook::TlsPlan>(kTlsPlan);
    ASSERT_NE(plan, nullptr);
    const auto& d = ctx.find_slot<std::vector<NewSection>>(kNewSections)->at(0).data;
    const size_t cb_off = size_t(plan->callback_rva - 0x3000);
    // 回调体含 rep movsq（F3 48 A5）——回填循环在场。
    bool found = false;
    for (size_t i = cb_off; i + 3 <= d.size(); ++i)
        if (d[i] == 0xF3 && d[i + 1] == 0x48 && d[i + 2] == 0xA5) { found = true; break; }
    EXPECT_TRUE(found);
    (void)mirror_rva;
}

TEST(ImportProtectFallback, BoundImportAbortsMigration) {
    const u64 base = 0x140000000;
    ProtectionContext ctx;
    ctx.image = make_image(true, 0x8664, base);
    ctx.slot<PeImage>(kPeImage) = make_meta(true, 0x8664, base);
    ctx.slot<std::vector<NewSection>>(kNewSections).push_back(make_wvmp(0x3000));
    ctx.image = make_import_fixture(base).image;
    // desc0 改为绑定形态：INT = 0（FirstThunk 承载名字面）。
    const auto rv2off = [](u32 rva) { return size_t(rva) - 0x1000 + 0x400; };
    for (int i = 0; i < 4; ++i) ctx.image[rv2off(0x1000) + i] = 0;

    ImportProtectPass pass;
    pass.run(ctx);

    EXPECT_EQ(ctx.find_slot<ImportPlan>(kImportPlan), nullptr);
    // FirstThunk 字段未被改动。
    EXPECT_EQ(rd(ctx.image, rv2off(0x1000) + 16, 4), 0x1200u);
}

TEST(ImportProtectFallback, VpNotImportedAbortsMigration) {
    const u64 base = 0x140000000;
    ProtectionContext ctx;
    ctx.image = make_image(true, 0x8664, base);
    ctx.slot<PeImage>(kPeImage) = make_meta(true, 0x8664, base);
    ctx.slot<std::vector<NewSection>>(kNewSections).push_back(make_wvmp(0x3000));
    ctx.image = make_import_fixture(base).image;
    // 名字面改为 VirtualAlloc（VP 缺席 → v1 硬依赖不满足 → 整单回退）。
    const auto rv2off = [](u32 rva) { return size_t(rva) - 0x1000 + 0x400; };
    std::memcpy(&ctx.image[rv2off(0x1500) + 2], "VirtualAlloc", 12);
    ctx.image[rv2off(0x1500) + 14] = 0;

    ImportProtectPass pass;
    pass.run(ctx);

    EXPECT_EQ(ctx.find_slot<ImportPlan>(kImportPlan), nullptr);
    // dd1 FirstThunk 未被改动（半改状态防线）。
    EXPECT_EQ(rd(ctx.image, rv2off(0x1000) + 16, 4), 0x1200u);
    EXPECT_EQ(rd(ctx.image, rv2off(0x1000) + 20 + 16, 4), 0x1218u);
}

TEST(ImportProtectFallback, NoImportDirectoryIsNoop) {
    const u64 base = 0x140000000;
    ProtectionContext ctx;
    ctx.image = make_image(true, 0x8664, base);  // dd[1] 保持 0
    ctx.slot<PeImage>(kPeImage) = make_meta(true, 0x8664, base);
    ctx.slot<std::vector<NewSection>>(kNewSections).push_back(make_wvmp(0x3000));

    ImportProtectPass pass;
    pass.run(ctx);
    EXPECT_EQ(ctx.find_slot<ImportPlan>(kImportPlan), nullptr);
    EXPECT_EQ(ctx.find_slot<std::vector<NewSection>>(kNewSections)->at(0).data.size(), 64u);
}

} // namespace
