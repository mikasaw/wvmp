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
#include "wvmp/framework/protect_levels.hpp"

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

// MIT-477 (T9.1)：x64 rip 引用重写——.text 内 call [rip+IAT] / mov r64,
// [rip+IAT] 的 disp 重指镜像等价槽；槽对齐判据外的伪命中不动。
TEST(ImportProtectMigrate, X64CodeRefRewrite) {
    const u64 base = 0x140000000;
    ProtectionContext ctx;
    ctx.image = make_image(true, 0x8664, base);
    ctx.slot<PeImage>(kPeImage) = make_meta(true, 0x8664, base);
    ctx.slot<std::vector<NewSection>>(kNewSections).push_back(make_wvmp(0x3000));
    ImportFixture fx = make_import_fixture(base);
    ctx.image = fx.image;

    // .text 内植引用（.text = RVA 0x1000..0x2000）：
    //   @0x1600: FF 15 disp32  → call [0x1200]（IAT 槽 0，8 对齐）
    //   @0x1610: 48 8B 05 disp32 → mov rax,[0x1208]（IAT 槽 1）
    //   @0x1620: FF 15 disp32  → call [0x1204]（槽中间，非对齐 → 不改写）
    //   @0x1630: FF 15 disp32  → call [0x1300]（跨出 span → 不改写）
    const auto rv2off = [](u32 rva) { return size_t(rva) - 0x1000 + 0x400; };
    auto put_ff15 = [&](u32 at, u32 target) {
        ctx.image[rv2off(at)] = 0xFF;
        ctx.image[rv2off(at) + 1] = 0x15;
        const u32 d = u32(i64(target) - i64(at + 6));
        for (int b = 0; b < 4; ++b)
            ctx.image[rv2off(at) + 2 + b] = u8((d >> (8 * b)) & 0xFF);
    };
    put_ff15(0x1600, 0x1200);
    put_ff15(0x1610, 0x1300);  // 占位，稍后被 mov 覆写前 3 字节——独立排布
    {
        // mov rax,[rip+disp] @0x1610 → 0x1208
        ctx.image[rv2off(0x1610)] = 0x48;
        ctx.image[rv2off(0x1610) + 1] = 0x8B;
        ctx.image[rv2off(0x1610) + 2] = 0x05;
        const u32 d = u32(i64(0x1208) - i64(0x1610 + 7));
        for (int b = 0; b < 4; ++b)
            ctx.image[rv2off(0x1610) + 3 + b] = u8((d >> (8 * b)) & 0xFF);
    }
    put_ff15(0x1620, 0x1204);  // 非对齐
    put_ff15(0x1630, 0x1300);  // INT1 区（span 外：span = [0x1200,0x1228)）
    const std::vector<u8> raw_backup(ctx.image);

    ImportProtectPass pass;
    pass.run(ctx);

    const auto* plan = ctx.find_slot<ImportPlan>(kImportPlan);
    ASSERT_NE(plan, nullptr);
    ASSERT_EQ(plan->mirror_rva, 0x3040u);

    // 槽 0 引用 → 镜像槽 0：new_disp = 0x3040 - 0x1606。
    {
        const i64 want = i64(0x3040) - i64(0x1606);
        u32 raw32 = 0;
        std::memcpy(&raw32, &ctx.image[rv2off(0x1600) + 2], 4);
        EXPECT_EQ(static_cast<i64>(static_cast<i32>(raw32)), want);
    }
    // mov rax 形 → 镜像槽 1：new_disp = 0x3048 - 0x1617。
    {
        const i64 want = i64(0x3048) - i64(0x1617);
        u32 raw32 = 0;
        std::memcpy(&raw32, &ctx.image[rv2off(0x1610) + 3], 4);
        EXPECT_EQ(static_cast<i64>(static_cast<i32>(raw32)), want);
    }
    // 非对齐 / span 外引用原样保留。
    EXPECT_EQ(std::memcmp(&ctx.image[rv2off(0x1620)], &raw_backup[rv2off(0x1620)], 6), 0);
    EXPECT_EQ(std::memcmp(&ctx.image[rv2off(0x1630)], &raw_backup[rv2off(0x1630)], 6), 0);
}

TEST(ImportProtectMigrate, TlsHookCarriesBackfillLoop) {
    const u64 base = 0x140000000;
    ProtectionContext ctx;
    ctx.image = make_image(true, 0x8664, base);
    ctx.slot<PeImage>(kPeImage) = make_meta(true, 0x8664, base);
    // MIT-472 W^X 拆节：镜像 → 数据节 .wvmp；回调桩 → 代码节 .wvmpc。
    ctx.slot<std::vector<NewSection>>(kNewSections).push_back(make_wvmp(0x3000));
    NewSection csec;
    csec.name = ".wvmpc";
    csec.data.assign(16, 0);
    csec.characteristics = 0x60000020u;
    csec.requested_rva = 0x4000u;
    ctx.slot<std::vector<NewSection>>(kNewSections).push_back(csec);
    ctx.image = make_import_fixture(base).image;

    ImportProtectPass imp;
    imp.run(ctx);
    ASSERT_NE(ctx.find_slot<ImportPlan>(kImportPlan), nullptr);
    const u64 mirror_rva = ctx.find_slot<ImportPlan>(kImportPlan)->mirror_rva;

    TlsHookPass tls;
    tls.run(ctx);

    const auto* plan = ctx.find_slot<tls_hook::TlsPlan>(kTlsPlan);
    ASSERT_NE(plan, nullptr);
    std::vector<u8> const* code = nullptr;
    for (const auto& sc : *ctx.find_slot<std::vector<NewSection>>(kNewSections))
        if (sc.name == ".wvmpc") code = &sc.data;
    ASSERT_NE(code, nullptr);
    const auto& d = *code;
    const size_t cb_off = size_t(plan->callback_rva - 0x4000);
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

// ---------------------------------------------------------------------------
// MIT-486 (T9.2)：x86 abs32 代码引用重写 + 数据段指针重写（.reloc 扫描）。
// 通用三节夹具：.text @0x1000（EXECUTE，容纳导入面/代码引用站点）、
// .data @0x2000（RW，数据指针站点）、.rdata @0x3000（RO，承载 .reloc
// 目录 blob）；节 raw 步进与 .text 一致（raw_ptr = 0x400 + (rva-0x1000)）
// → rv2off 全节通用。.wvmp 挂 @0x4000（避开 .rdata）。
struct MultiSectionImage {
    std::vector<u8> image;
    PeImage meta;
};

MultiSectionImage make_multisection_image(bool plus, u64 base) {
    const u16 machine = plus ? 0x8664 : 0x14C;
    const size_t opt_size = plus ? 240 : 224;
    const size_t table = kOpt + opt_size;
    const size_t sh = table;  // 3 节头
    const size_t end = sh + 3 * 40;
    // 节布局（raw 步进与 .text 一致：raw_ptr = 0x400 + (rva-0x1000)）：
    // .text vs/rs 0x1000 @ raw 0x400；.data 0x400 @ 0x1400；
    // .rdata 0x400 @ 0x2400（.reloc blob @0x3400 → raw 0x2800）。文件总长
    // 0x2900（含 blob 24B）。
    std::vector<u8> img(end + 0x2900, 0);
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
    wr16(kNt + 6, 3);
    wr16(kNt + 20, u16(opt_size));
    wr16(kNt + 22, 0x0022);
    wr32(kOpt, plus ? 0x020B : 0x010B);
    wr32(kOpt + 16, 0x1000);
    wr32(kOpt + 20, 0x200);
    wr32(kOpt + (plus ? 24 : 28), u32(base));
    wr32(kOpt + 56, 0x5000);
    wr32(kOpt + 60, 0x200);
    wr32(kOpt + (plus ? 108 : 92), 16);
    // dd[1] → 描述符链 @0x1000；dd[5] → .reloc blob @0x3380（.rdata 界内
    // ——节终点 0x3400 为排他界，rva_to_offset 对端点返回空）。
    const size_t dd = kOpt + (plus ? 112 : 96);
    wr32(dd + 1 * 8, 0x1000);
    wr32(dd + 1 * 8 + 4, 60);
    wr32(dd + 5 * 8, 0x3380);
    wr32(dd + 5 * 8 + 4, 8 + 2 * 8);

    struct Sec {
        const char* name;
        u32 va;
        u32 size;
        u32 raw;
        u32 ch;
    };
    const Sec secs[3] = {
        {".text", 0x1000, 0x1000, 0x400, 0x60000020},
        {".data", 0x2000, 0x400, 0x1400, 0xC0000040},
        {".rdata", 0x3000, 0x400, 0x2400, 0x40000040},
    };
    for (int i = 0; i < 3; ++i) {
        const size_t o = sh + size_t(i) * 40;
        std::memcpy(&img[o], secs[i].name, std::strlen(secs[i].name));
        wr32(o + 8, secs[i].size);
        wr32(o + 12, secs[i].va);
        wr32(o + 16, secs[i].size);
        wr32(o + 20, secs[i].raw);
        wr32(o + 36, secs[i].ch);
    }

    PeImage m;
    m.is_pe32_plus = plus;
    m.machine = machine;
    m.image_base = base;
    m.section_alignment = 0x1000;
    m.file_alignment = 0x200;
    m.num_sections = 3;
    m.nt_headers_offset = u32(kNt);
    for (const auto& s : secs) {
        SectionInfo si;
        si.name = s.name;
        si.virtual_size = s.size;
        si.virtual_addr = s.va;
        si.raw_size = s.size;
        si.raw_ptr = s.raw;
        si.characteristics = s.ch;
        m.sections.push_back(si);
    }
    return {std::move(img), std::move(m)};
}

// 在三节镜像内布置导入面（x64 槽宽 8B / x86 4B，rv2off = rva - 0xC00）：
// desc0（INT@0x1100、FT@0x1200、2 槽）、desc1（INT@0x1300、FT@0x1200+3w
// 连续、1 槽）、全零终止；VirtualProtect 名字面 @0x1500（v1 硬依赖）。
struct ImportFixture2 {
    std::vector<u8> image;
    u64 iat_base = 0x1200;
    u64 iat_span = 0;
};

ImportFixture2 make_import_fixture2(std::vector<u8> img, bool plus) {
    const size_t w = plus ? 8 : 4;
    auto wr32 = [&](size_t off, u32 v) {
        for (int i = 0; i < 4; ++i) img[off + i] = u8((v >> (8 * i)) & 0xFF);
    };
    const auto rv2off = [](u32 rva) { return size_t(rva) - 0xC00; };
    const u32 ft1 = 0x1200 + u32(3 * w);
    // desc0 / desc1 / 终止。
    wr32(rv2off(0x1000) + 0, 0x1100);
    wr32(rv2off(0x1000) + 16, 0x1200);
    wr32(rv2off(0x1000) + 20 + 0, 0x1300);
    wr32(rv2off(0x1000) + 20 + 16, ft1);
    // INT0 @0x1100：slot0 → VirtualProtect 名字 @0x1500、slot1 → 杂散、NULL。
    wr32(rv2off(0x1100), 0x1500);
    wr32(rv2off(u32(0x1100 + w)), 0x2222);
    // IMAGE_IMPORT_BY_NAME @0x1500。
    std::memcpy(&img[rv2off(0x1500) + 2], "VirtualProtect", 14);
    // INT1 @0x1300：1 槽 + NULL。
    wr32(rv2off(0x1300), 0x3333);
    return {std::move(img), 0x1200, 4 * w};
}

// .reloc blob 布置：单块 PageRva=0x2000（.data），entries 由调用方给定
//（type<<12|off）。blob 位于 @0x3400（.rdata 内），大小 8 + 2*n（须与
// 夹具 dd[5] 尺寸一致：8 entry 槽位已按上限预留）。
static void put_reloc_block(std::vector<u8>& img, const std::vector<u16>& entries) {
    const size_t off = 0x3380 - 0xC00;
    auto wr32 = [&](size_t o, u32 v) {
        for (int i = 0; i < 4; ++i) img[o + i] = u8((v >> (8 * i)) & 0xFF);
    };
    wr32(off, 0x2000);
    wr32(off + 4, u32(8 + 2 * entries.size()));
    for (size_t i = 0; i < entries.size(); ++i) {
        img[off + 8 + i * 2] = u8(entries[i] & 0xFF);
        img[off + 8 + i * 2 + 1] = u8(entries[i] >> 8);
    }
}

TEST(ImportProtectMigrate, X86Abs32CodeRefRewrite) {
    const u64 base = 0x400000;
    auto ms = make_multisection_image(false, base);
    ProtectionContext ctx;
    ctx.image = ms.image;
    ctx.slot<PeImage>(kPeImage) = ms.meta;
    ctx.slot<std::vector<NewSection>>(kNewSections).push_back(make_wvmp(0x4000));
    ImportFixture2 fx = make_import_fixture2(std::move(ctx.image), false);
    ctx.image = std::move(fx.image);
    const auto rv2off = [](u32 rva) { return size_t(rva) - 0xC00; };
    const u64 ib = base;
    auto put_abs = [&](u32 at, u8 op0, u8 op1, u32 target) {
        ctx.image[rv2off(at)] = op0;
        if (op1 != 0) ctx.image[rv2off(at) + 1] = op1;
        const u32 a = u32(ib + target);
        const size_t doff = op1 != 0 ? 2 : 1;
        for (int b = 0; b < 4; ++b)
            ctx.image[rv2off(at) + doff + b] = u8((a >> (8 * b)) & 0xFF);
    };
    //   @0x1600: FF 15 abs → call [0x1200]（槽 0 → 改写）
    //   @0x1610: 8B 05 abs → mov eax,[0x1204]（槽 1 → 改写）
    //   @0x1620: A1 abs    → mov eax,[0x1200]（槽 0 → 改写）
    //   @0x1630: FF 15 abs → call [0x1202]（非对齐 → 保留）
    //   @0x1640: FF 15 abs → call [0x1300]（span 外 → 保留）
    put_abs(0x1600, 0xFF, 0x15, 0x1200);
    put_abs(0x1610, 0x8B, 0x05, 0x1204);
    put_abs(0x1620, 0xA1, 0x00, 0x1200);
    put_abs(0x1630, 0xFF, 0x15, 0x1202);
    put_abs(0x1640, 0xFF, 0x15, 0x1300);
    const std::vector<u8> raw_backup(ctx.image);

    ImportProtectPass pass;
    pass.run(ctx);

    const auto* plan = ctx.find_slot<ImportPlan>(kImportPlan);
    ASSERT_NE(plan, nullptr);
    const u64 mirror = plan->mirror_rva;
    const auto rd_abs = [&](u32 at, size_t disp_off) {
        u32 raw32 = 0;
        std::memcpy(&raw32, &ctx.image[rv2off(at) + disp_off], 4);
        return raw32;
    };
    EXPECT_EQ(rd_abs(0x1600, 2), u32(ib + mirror + 0));
    EXPECT_EQ(rd_abs(0x1610, 2), u32(ib + mirror + 4));
    EXPECT_EQ(rd_abs(0x1620, 1), u32(ib + mirror + 0));
    EXPECT_EQ(std::memcmp(&ctx.image[rv2off(0x1630)], &raw_backup[rv2off(0x1630)], 6), 0);
    EXPECT_EQ(std::memcmp(&ctx.image[rv2off(0x1640)], &raw_backup[rv2off(0x1640)], 6), 0);
}

TEST(ImportProtectMigrate, DataRefRewriteRelocScan) {
    // 双架构参数化：PE32+ DIR64 / PE32 HIGHLOW。
    for (const bool plus : {true, false}) {
        const u64 base = plus ? 0x140000000 : 0x400000;
        const size_t w = plus ? 8 : 4;
        const u16 rtype = plus ? 10 : 3;
        auto ms = make_multisection_image(plus, base);
        ProtectionContext ctx;
        ctx.image = ms.image;
        ctx.slot<PeImage>(kPeImage) = ms.meta;
        ctx.slot<std::vector<NewSection>>(kNewSections).push_back(make_wvmp(0x4000));
        ImportFixture2 fx = make_import_fixture2(std::move(ctx.image), plus);
        ctx.image = std::move(fx.image);
        const auto rv2off = [](u32 rva) { return size_t(rva) - 0xC00; };
        const u64 ib = base;
        // .data 站点：@0x2000 → IAT 槽 0（改写）；@0x2000+w → span 外
        // 0x1300（保留）。
        auto put_ptr = [&](u32 at, u64 rva) {
            const u64 v = ib + rva;
            for (size_t b = 0; b < w; ++b)
                ctx.image[rv2off(at) + b] = u8((v >> (8 * b)) & 0xFF);
        };
        put_ptr(0x2000, 0x1200);
        put_ptr(u32(0x2000 + w), 0x1300);
        // EXECUTE 节站点（.text @0x1700 持 IAT 槽 VA 但无指令语义）：
        // 数据路径必须按节属性分流跳过。
        put_ptr(0x1700, 0x1200);
        put_reloc_block(ctx.image,
                        {u16(rtype << 12 | 0x000), u16(0 << 12 | 0x004),
                         u16(rtype << 12 | u16(0x000 + w)), u16(rtype << 12 | 0x700)});
        const std::vector<u8> raw_backup(ctx.image);

        ImportProtectPass pass;
        pass.run(ctx);

        const auto* plan = ctx.find_slot<ImportPlan>(kImportPlan);
        ASSERT_NE(plan, nullptr);
        const u64 mirror = plan->mirror_rva;
        const auto rd_val = [&](u32 at) {
            u64 v = 0;
            std::memcpy(&v, &ctx.image[rv2off(at)], w);
            return v;
        };
        EXPECT_EQ(rd_val(0x2000), ib + mirror + 0);
        EXPECT_EQ(rd_val(u32(0x2000 + w)), ib + 0x1300);
        EXPECT_EQ(rd_val(0x1700), ib + 0x1200);
        (void)raw_backup;
    }
}

// ---------------------------------------------------------------------------
// MIT-488 (T9.3b)：[import] skip_backfill=true——跳回填模式。原 IAT 全槽
// 写入 FailFast 红线桩 VA；tls_hook 回调体不再携带回填循环。
TEST(ImportProtectMigrate, SkipBackfillSlotsFilledWithFailFastStub) {
    const u64 base = 0x140000000;
    ProtectionContext ctx;
    ctx.image = make_image(true, 0x8664, base);
    ctx.slot<PeImage>(kPeImage) = make_meta(true, 0x8664, base);
    ctx.slot<std::vector<NewSection>>(kNewSections).push_back(make_wvmp(0x3000));
    NewSection csec;
    csec.name = ".wvmpc";
    csec.data.assign(16, 0);
    csec.characteristics = 0x60000020u;
    csec.requested_rva = 0x4000u;
    ctx.slot<std::vector<NewSection>>(kNewSections).push_back(csec);
    ctx.image = make_import_fixture(base).image;
    auto& rules = ctx.slot<ProtectRules>(kProtectRules);
    rules.has_import_skip_backfill = true;
    rules.import_skip_backfill = true;

    ImportProtectPass pass;
    pass.run(ctx);

    const auto* plan = ctx.find_slot<ImportPlan>(kImportPlan);
    ASSERT_NE(plan, nullptr);
    EXPECT_TRUE(plan->skip_backfill);
    ASSERT_NE(plan->failfast_stub_rva, 0u);

    // 桩字节（31 C0 C7 00 00 00 00 00）落 .wvmpc @ failfast_stub_rva。
    const std::vector<NewSection>* sections =
        ctx.find_slot<std::vector<NewSection>>(kNewSections);
    const std::vector<u8>* code = nullptr;
    for (const auto& sc : *sections)
        if (sc.name == ".wvmpc") code = &sc.data;
    ASSERT_NE(code, nullptr);
    const size_t stub_off = size_t(plan->failfast_stub_rva - 0x4000);
    ASSERT_LE(stub_off + 8, code->size());
    static const u8 kStub[8] = {0x31, 0xC0, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00};
    EXPECT_EQ(std::memcmp(code->data() + stub_off, kStub, 8), 0);

    // 原 IAT 全槽（3 槽 + NULL 终止，8B 宽）= 桩全 VA。
    const u64 stub_va = base + plan->failfast_stub_rva;
    const auto rv2off = [](u32 rva) { return size_t(rva) - 0x1000 + 0x400; };
    for (u32 slot = 0x1200; slot < 0x1228; slot += 8) {
        const u64 v = rd(ctx.image, rv2off(slot), 8);
        EXPECT_EQ(v, stub_va);
    }
}

TEST(ImportProtectMigrate, SkipBackfillTlsCallbackOmitsBackfillLoop) {
    const u64 base = 0x140000000;
    ProtectionContext ctx;
    ctx.image = make_image(true, 0x8664, base);
    ctx.slot<PeImage>(kPeImage) = make_meta(true, 0x8664, base);
    ctx.slot<std::vector<NewSection>>(kNewSections).push_back(make_wvmp(0x3000));
    NewSection csec;
    csec.name = ".wvmpc";
    csec.data.assign(16, 0);
    csec.characteristics = 0x60000020u;
    csec.requested_rva = 0x4000u;
    ctx.slot<std::vector<NewSection>>(kNewSections).push_back(csec);
    ctx.image = make_import_fixture(base).image;
    auto& rules = ctx.slot<ProtectRules>(kProtectRules);
    rules.has_import_skip_backfill = true;
    rules.import_skip_backfill = true;

    ImportProtectPass imp;
    imp.run(ctx);
    ASSERT_NE(ctx.find_slot<ImportPlan>(kImportPlan), nullptr);

    TlsHookPass tls;
    tls.run(ctx);

    const auto* plan = ctx.find_slot<tls_hook::TlsPlan>(kTlsPlan);
    ASSERT_NE(plan, nullptr);
    std::vector<u8> const* code = nullptr;
    for (const auto& sc : *ctx.find_slot<std::vector<NewSection>>(kNewSections))
        if (sc.name == ".wvmpc") code = &sc.data;
    ASSERT_NE(code, nullptr);
    const auto& d = *code;
    const size_t cb_off = size_t(plan->callback_rva - 0x4000);
    // 回调体不含 rep movsq（F3 48 A5）——回填循环已随 skip_backfill 消失。
    bool found = false;
    for (size_t i = cb_off; i + 3 <= d.size(); ++i)
        if (d[i] == 0xF3 && d[i + 1] == 0x48 && d[i + 2] == 0xA5) { found = true; break; }
    EXPECT_FALSE(found);
}

} // namespace
