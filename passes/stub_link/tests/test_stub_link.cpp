// M2-3 stub_link 测试：
//  1) kVmProgram 缺失 → Warning 返回（M1 空管道兼容）；
//  2) 端到端（进程内模拟 PE 场景）：手搭最小 PE + 虚拟化函数 →
//     .text 入口被覆写为 E9（目标=stub RVA）+ 区域余量 INT3；
//     kNewSections 有 .wvmp 请求（requested_rva 对齐、含 blob magic 与
//     解释器代码）；
//  3) stub 机器码结构性检查（push 序言 / sub rsp 0x130）。

#include "stub_gen.hpp"

#include "wvmp/common/bytes.hpp"
#include "wvmp/common/rng.hpp"
#include "wvmp/framework/context.hpp"
#include "wvmp/framework/diagnostics.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/protect_levels.hpp"
#include "wvmp/passes/pe_loader/pe_image.hpp"
#include "wvmp/passes/stub_link/stub_link_pass.hpp"
#include "wvmp/passes/virtualize/virtualize_pass.hpp"
#include "wvmp/regvm/isa/blob.hpp"
#include "wvmp/regvm/isa/encoding.hpp"
#include "wvmp/vm/backend.hpp"

#include <gtest/gtest.h>

#include <cstdio>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

namespace {

namespace isa = wvmp::regvm::isa;
using wvmp::i64;
using wvmp::u8;
using wvmp::u32;
using wvmp::u64;
using wvmp::passes::NewSection;
using wvmp::passes::PeImage;
using wvmp::passes::VirtualizedFunction;
using wvmp::ProtectionContext;

constexpr u32 kSecAlign = 0x1000;
constexpr u32 kFileAlign = 0x200;

void wr32(std::vector<u8>& v, size_t o, u32 x) {
    v[o] = u8(x);
    v[o + 1] = u8(x >> 8);
    v[o + 2] = u8(x >> 16);
    v[o + 3] = u8(x >> 24);
}

// 最小 PE：单 .text 节（VA 0x1000，raw @0x200 长 0x400，内容 0x90）。
// 区域 RVA 0x1100..0x1140 落在节内（文件偏移 0x300..0x340）。
std::vector<u8> build_pe_with_region() {
    std::vector<u8> img(0x600, 0);
    img[0] = 'M';
    img[1] = 'Z';
    wr32(img, 0x3C, 0x40);
    const size_t nt = 0x40;
    img[nt + 0] = 'P';
    img[nt + 1] = 'E';
    wr32(img, nt + 4, 0x8664);
    img[nt + 6] = 1;
    img[nt + 20] = 240;
    const size_t opt = nt + 24;
    img[opt] = 0x0B;
    img[opt + 1] = 0x02;
    wr32(img, opt + 32, kSecAlign);
    wr32(img, opt + 36, kFileAlign);
    wr32(img, opt + 56, 0x2000);
    wr32(img, opt + 60, 0x200);
    const size_t sh = nt + 24 + 240;
    std::memcpy(&img[sh], ".text", 5);
    wr32(img, sh + 8, 0x400);
    wr32(img, sh + 12, 0x1000);
    wr32(img, sh + 16, 0x400);
    wr32(img, sh + 20, 0x200);
    wr32(img, sh + 36, 0x6000'0020);
    std::fill(img.begin() + 0x200, img.begin() + 0x600, 0x90);
    return img;
}

wvmp::vm::VmProgram make_program() {
    // mov r0,77; halt —— 足以构造合法 blob。
    std::vector<u8> stream;
    isa::append_insn(stream, isa::make_insn(isa::VmOp::Mov, isa::OpKind::Reg, 0,
                                            isa::OpKind::Imm, 0, 77, 3));
    isa::append_insn(stream, isa::make_insn(isa::VmOp::Halt, isa::OpKind::None, 0,
                                            isa::OpKind::None, 0));
    const auto blob = isa::make_blob(wvmp::ir::Arch::X64, 0, std::move(stream));
    std::vector<u8> serialized;
    wvmp::ByteWriter w(serialized);
    isa::write_blob(w, blob);

    wvmp::vm::VmProgram p;
    p.bytecode = std::move(serialized);
    p.entry_offset = 0;
    return p;
}

ProtectionContext make_ctx_with_one_function() {
    ProtectionContext ctx;
    ctx.image = build_pe_with_region();
    ctx.slot<PeImage>(wvmp::kPeImage) = wvmp::passes::parse_pe_image(ctx.image);

    VirtualizedFunction vf;
    vf.name = "sample";
    vf.begin_rva = 0x1100;
    vf.end_rva = 0x1140;
    vf.program = make_program();
    ctx.slot<std::vector<VirtualizedFunction>>(wvmp::kVmProgram).push_back(std::move(vf));
    return ctx;
}

TEST(StubLinkPass, NoProgramWarns) {
    ProtectionContext ctx;
    wvmp::passes::StubLinkPass pass;
    pass.run(ctx);
    EXPECT_FALSE(ctx.diag.has_errors());
    EXPECT_FALSE(ctx.diag.items().empty());
    EXPECT_EQ(ctx.find_slot<std::vector<NewSection>>(wvmp::kNewSections), nullptr);
}

TEST(StubLinkPass, OverwritesEntryAndRequestsSection) {
    ProtectionContext ctx = make_ctx_with_one_function();
    wvmp::passes::StubLinkPass pass;
    pass.run(ctx);

    ASSERT_FALSE(ctx.diag.has_errors());

    // .text 覆写：RVA 0x1100 → 文件偏移 0x300。
    const u8* code = ctx.image.data() + 0x300;
    ASSERT_EQ(code[0], 0xE9);
    const i64 rel = static_cast<i64>(u32(code[1]) | (u32(code[2]) << 8) |
                                     (u32(code[3]) << 16) | (u32(code[4]) << 24));
    const u64 stub_rva = 0x1100 + 5 + rel;

    // 新节请求（MIT-472 W^X 拆节：.wvmp 数据节 + .wvmpc 代码节）。
    const auto* reqs = ctx.find_slot<std::vector<NewSection>>(wvmp::kNewSections);
    ASSERT_NE(reqs, nullptr);
    ASSERT_EQ(reqs->size(), static_cast<size_t>(2));
    const NewSection& data_req = (*reqs)[0];
    const NewSection& code_req = (*reqs)[1];
    EXPECT_EQ(data_req.name, ".wvmp");
    EXPECT_EQ(code_req.name, ".wvmpc");
    EXPECT_EQ(data_req.characteristics, 0xC000'0040u);  // RW
    EXPECT_EQ(code_req.characteristics, 0x6000'0020u);  // RX
    EXPECT_GT(data_req.requested_rva, 0u);
    EXPECT_EQ(data_req.requested_rva % kSecAlign, 0u);
    EXPECT_GT(code_req.requested_rva, data_req.requested_rva);
    EXPECT_EQ(code_req.requested_rva % kSecAlign, 0u);
    ASSERT_GT(code_req.data.size(), static_cast<size_t>(64));
    // 入口 stub（.text E9 目标）落在代码节内。
    EXPECT_GE(stub_rva, code_req.requested_rva);
    EXPECT_LT(stub_rva, code_req.requested_rva + code_req.data.size());

    // 数据节含 blob magic。
    bool has_blob = false;
    for (size_t i = 0; i + 4 <= data_req.data.size(); ++i)
        if (std::memcmp(&data_req.data[i], "WVMP", 4) == 0) has_blob = true;
    EXPECT_TRUE(has_blob);

    // 区域余量 INT3 填充（0x40 字节区域，E9 后全 CC）。
    for (size_t i = 5; i < 0x40; ++i) EXPECT_EQ(code[i], 0xCC) << "byte " << i;
}

// MIT-494c (T26c)：覆写区登记——跳板写入成功即登记 {begin_rva, len}，
// 供 pe_writer 扩展 reloc 目录剪枝孤儿条目（MIT-494a forkface 0x13DE）。
TEST(StubLinkPass, RecordsPatchedRangeOnEntryOverwrite) {
    ProtectionContext ctx = make_ctx_with_one_function();
    wvmp::passes::StubLinkPass pass;
    pass.run(ctx);
    ASSERT_FALSE(ctx.diag.has_errors());
    const auto* ranges = ctx.find_slot<std::vector<std::pair<u32, u32>>>(
        wvmp::kPatchedRanges);
    ASSERT_NE(ranges, nullptr);
    ASSERT_EQ(ranges->size(), static_cast<size_t>(1));
    EXPECT_EQ((*ranges)[0].first, 0x1100u);
    EXPECT_EQ((*ranges)[0].second, 0x40u);
}

// MIT-476 (T20)：x86 全 gate —— 零 blob 时数据节恒非空（emit 预留区，
// 票②）、代码节 RVA > 数据节 RVA（票①），gate note 携带未支持 opcode
// 名（票③）。
TEST(StubLinkPass, X86AllGatedEmitsNonEmptyDataSection) {
    auto ctx = make_ctx_with_one_function();
    {   // PeImage 槽改 x86 形（machine=0x014C / PE32）。全 gate 路径不写
        // .text / 不依赖镜像字节，槽字段足够驱动 x86 分支。
        PeImage meta = ctx.slot<PeImage>(wvmp::kPeImage);
        meta.machine = 0x014C;
        meta.is_pe32_plus = false;
        ctx.slot<PeImage>(wvmp::kPeImage) = meta;
    }
    {   // 程序换成含 x86 未支持 op（Movsxd）的流。
        std::vector<u8> stream;
        isa::append_insn(stream, isa::make_insn(isa::VmOp::Movsxd, isa::OpKind::Reg,
                                                0, isa::OpKind::Reg, 1, 0, 3));
        isa::append_insn(stream, isa::make_insn(isa::VmOp::Halt, isa::OpKind::None, 0,
                                                isa::OpKind::None, 0));
        const auto blob = isa::make_blob(wvmp::ir::Arch::X86, 0, std::move(stream));
        std::vector<u8> serialized;
        wvmp::ByteWriter w(serialized);
        isa::write_blob(w, blob);
        auto& vfs = ctx.slot<std::vector<VirtualizedFunction>>(wvmp::kVmProgram);
        vfs.front().program.bytecode = std::move(serialized);
    }

    wvmp::passes::StubLinkPass pass;
    pass.run(ctx);

    ASSERT_FALSE(ctx.diag.has_errors());

    const auto* reqs = ctx.find_slot<std::vector<NewSection>>(wvmp::kNewSections);
    ASSERT_NE(reqs, nullptr);
    ASSERT_EQ(reqs->size(), static_cast<size_t>(2));
    const NewSection& data_req = (*reqs)[0];
    const NewSection& code_req = (*reqs)[1];
    // 票②：全 gate（零 blob）数据节恒非空（emit 预留区）。
    EXPECT_GE(data_req.data.size(), wvmp::passes::kEmitReserveBytes);
    // 票①：代码节落在数据节（含预留）对齐端之后。
    EXPECT_GT(code_req.requested_rva, data_req.requested_rva);
    EXPECT_EQ(code_req.requested_rva % kSecAlign, 0u);
    // 票③：gate note 携带未支持 opcode 名。
    bool note_found = false;
    for (const auto& d : ctx.diag.items())
        if (d.message.find("movsxd") != std::string::npos &&
            d.message.find("白名单 gate") != std::string::npos)
            note_found = true;
    EXPECT_TRUE(note_found);
}

TEST(StubLinkPass, UnmappableRegionKeepsNative) {
    ProtectionContext ctx = make_ctx_with_one_function();
    auto& vfs = ctx.slot<std::vector<VirtualizedFunction>>(wvmp::kVmProgram);
    vfs.front().begin_rva = 0xFF000;  // 超出节范围
    wvmp::passes::StubLinkPass pass;
    pass.run(ctx);
    EXPECT_TRUE(ctx.diag.has_errors());
    EXPECT_EQ(ctx.image[0x300], 0x90);  // .text 未动
}

namespace {

// 扩展夹具：.text vs/rs 扩到 0x2000（区域 0x1100 仍在节内），文件随
// raw 末端扩到 0x2200——给"真实 reloc 块内容"测试提供可容纳大目录的
// 原生节空间（基础夹具 0x400 raw 装不下触发精确路径的目录规模）。
std::vector<u8> build_pe_with_region_bigtext() {
    std::vector<u8> img = build_pe_with_region();
    const size_t sh = 0x40 + 24 + 240;
    wr32(img, sh + 8, 0x2000);   // VirtualSize
    wr32(img, sh + 16, 0x2000);  // SizeOfRawData
    img.resize(0x2200, 0x90);
    return img;
}

// 在 [off, off+len) 写 n 个合法 reloc 块（每块 ents 个条目 + 4 字节倍数
// 对齐语义由断言方按 Σ(8+pad4·2) 推导期望）。
void write_reloc_blocks(std::vector<u8>& img, size_t off, int n, u32 ents) {
    size_t pos = off;
    for (int i = 0; i < n; ++i) {
        const u32 bsz = 8 + ents * 2;
        wr32(img, pos, 0x1000u + u32(i) * 0x1000);  // page
        wr32(img, pos + 4, bsz);
        for (u32 e = 0; e < ents; ++e)
            wr32(img, pos + 8 + e * 2, (3u << 12) | (e & 0xFFF));  // HIGHLOW
        pos += bsz;
    }
}

// 在夹具 PE 上声明 dd[5]（base reloc 目录）尺寸与 DllCharacteristics 位。
// stub_link 的加成判据只读这两个字段（dd[5].Size + DYNAMIC_BASE），不解析
// reloc 块内容（那是 pe_writer 的职责）。
void declare_reloc_dir(std::vector<u8>& img, u32 rva, u32 size, bool dynamic_base) {
    const size_t nt = 0x40;
    const size_t opt = nt + 24;
    wr32(img, opt + 112 + 5 * 8, rva);          // DataDirectory[5].VirtualAddress
    wr32(img, opt + 112 + 5 * 8 + 4, size);     // DataDirectory[5].Size
    const size_t dllchar_off = opt + 0x46;
    unsigned short cur =
        static_cast<unsigned short>(img[dllchar_off]) |
        static_cast<unsigned short>(static_cast<unsigned short>(img[dllchar_off + 1]) << 8);
    cur = dynamic_base ? static_cast<unsigned short>(cur | 0x0040)
                       : static_cast<unsigned short>(cur & static_cast<unsigned short>(~0x0040));
    img[dllchar_off] = u8(cur);
    img[dllchar_off + 1] = u8(cur >> 8);
}

} // namespace

TEST(StubLinkPass, LargeNativeRelocGrowsEmitReserve) {
    // MIT-494j：原生 reloc 目录超 8KB 基础预算（判据 = size*1.25+64+4096
    // > 8192，size=0x2000 → 加成 6208）→ .wvmp 数据节随之扩容，防
    // emit_reserve_take fail-closed 打包硬失败（wvmpTest x86 28.5KB
    // reloc 实录）。
    auto ctx = make_ctx_with_one_function();
    declare_reloc_dir(ctx.image, 0x1000, 0x2000, true);
    ctx.slot<PeImage>(wvmp::kPeImage) = wvmp::passes::parse_pe_image(ctx.image);

    wvmp::passes::StubLinkPass pass;
    pass.run(ctx);
    ASSERT_FALSE(ctx.diag.has_errors());

    const auto* reqs = ctx.find_slot<std::vector<NewSection>>(wvmp::kNewSections);
    ASSERT_NE(reqs, nullptr);
    ASSERT_EQ(reqs->size(), static_cast<size_t>(2));
    const NewSection& data_req = (*reqs)[0];
    // blob 48B（对齐 8）+ 8192 基础 + 6208 加成。
    // T36 口径：size=0x2000 超出小夹具文件（0x600）= dd[5] 目录不可映射
    // （pe_writer 同样放弃原块拷贝）→ 启发式兜底 size×1.25+64 = 0x2000×
    // 1.25+64 = 10304 → extra = align8(10304+4096−8192) = 6208。
    EXPECT_EQ(data_req.data.size(), static_cast<size_t>(48) + 8192 + 6208);
    bool note_found = false;
    for (const auto& d : ctx.diag.items())
        if (d.message.find("ASLR reloc 扩展预算加成") != std::string::npos)
            note_found = true;
    EXPECT_TRUE(note_found);
}

TEST(StubLinkPass, SmallOrAbsentNativeRelocKeepsBaseReserve) {
    // 零扰动面：小 reloc 目录 / 无 DYNAMIC_BASE → 加成严格为零，.wvmp
    // 尺寸 = blobs + 8KB 基础预算（multiseed 池与 x64 wvmpTest 产物字节
    // 不变的锚）。
    auto ctx = make_ctx_with_one_function();
    declare_reloc_dir(ctx.image, 0x1000, 0x100, true);   // 小目录：不触发
    ctx.slot<PeImage>(wvmp::kPeImage) = wvmp::passes::parse_pe_image(ctx.image);
    wvmp::passes::StubLinkPass pass;
    pass.run(ctx);
    ASSERT_FALSE(ctx.diag.has_errors());
    const auto* reqs = ctx.find_slot<std::vector<NewSection>>(wvmp::kNewSections);
    ASSERT_NE(reqs, nullptr);
    EXPECT_EQ((*reqs)[0].data.size(),
              static_cast<size_t>(48) + wvmp::passes::kEmitReserveBytes);

    auto ctx2 = make_ctx_with_one_function();
    declare_reloc_dir(ctx2.image, 0x1000, 0x2000, false);  // 大目录但无 ASLR 位
    ctx2.slot<PeImage>(wvmp::kPeImage) = wvmp::passes::parse_pe_image(ctx2.image);
    wvmp::passes::StubLinkPass pass2;
    pass2.run(ctx2);
    ASSERT_FALSE(ctx2.diag.has_errors());
    const auto* reqs2 = ctx2.find_slot<std::vector<NewSection>>(wvmp::kNewSections);
    ASSERT_NE(reqs2, nullptr);
    EXPECT_EQ((*reqs2)[0].data.size(),
              static_cast<size_t>(48) + wvmp::passes::kEmitReserveBytes);
}

TEST(StubLinkPass, ExactRebuildUpperBoundFromRealBlocks) {
    // T36：加成判据精确化——dd[5] 指向真实 reloc 块内容时，重建上界 =
    // 逐块 Σ(8 + pad4(entries)·2)（全保留展开，剪枝只减不增）+ 未解析
    // 尾段原样计入。构造：64 块 × 3 条目（bsz=14，重建 16B/块 > 原 14B
    // ——pad4 膨胀面），size=0x1000：
    //   exact = 64×16 + 尾段(0x1000 − 896) = 1024 + 3200 = 4224
    //   extra = align8(4224 + 4096 − 8192) = 128
    // （×1.25 启发式会给 1088——本测试锁死精确值，启发式即挂。）
    auto ctx = make_ctx_with_one_function();
    ctx.image = build_pe_with_region_bigtext();
    write_reloc_blocks(ctx.image, 0x200, 64, 3);
    declare_reloc_dir(ctx.image, 0x1000, 0x1000, true);
    ctx.slot<PeImage>(wvmp::kPeImage) = wvmp::passes::parse_pe_image(ctx.image);

    wvmp::passes::StubLinkPass pass;
    pass.run(ctx);
    ASSERT_FALSE(ctx.diag.has_errors());
    const auto* reqs = ctx.find_slot<std::vector<NewSection>>(wvmp::kNewSections);
    ASSERT_NE(reqs, nullptr);
    EXPECT_EQ((*reqs)[0].data.size(),
              static_cast<size_t>(48) + wvmp::passes::kEmitReserveBytes + 128);
}

TEST(StubLinkPass, BrokenRelocBlockTailCountedInFull) {
    // 块头断裂（bsz 越界）= pe_writer 同口径提前终止遍历、其后不发射 →
    // 上界 = 已展开 0 + 尾段 size 全额 = 0x1000 → 4096+4096 = 8192 不超
    // 基础预算 → 加成 0（启发式会给 1088——保守方向正确但过宽）。
    auto ctx = make_ctx_with_one_function();
    ctx.image = build_pe_with_region_bigtext();
    wr32(ctx.image, 0x200, 0x1000u);          // page 合法
    wr32(ctx.image, 0x204, 0xFFFFFFF0u);      // bsz 越界 → 断裂
    declare_reloc_dir(ctx.image, 0x1000, 0x1000, true);
    ctx.slot<PeImage>(wvmp::kPeImage) = wvmp::passes::parse_pe_image(ctx.image);

    wvmp::passes::StubLinkPass pass;
    pass.run(ctx);
    ASSERT_FALSE(ctx.diag.has_errors());
    const auto* reqs = ctx.find_slot<std::vector<NewSection>>(wvmp::kNewSections);
    ASSERT_NE(reqs, nullptr);
    EXPECT_EQ((*reqs)[0].data.size(),
              static_cast<size_t>(48) + wvmp::passes::kEmitReserveBytes);
}

TEST(StubLinkPass, AslrConfigOffKeepsBaseReserve) {
    // MIT-494j 验收 SH3：配置侧零加成路径——[pe] aslr=false（ProtectRules
    // 显式覆写）时即使原生 reloc 目录超预算也不加成（pe_writer 同步走清
    // DYNAMIC_BASE 回退，无扩展无预算需求）。
    auto ctx = make_ctx_with_one_function();
    declare_reloc_dir(ctx.image, 0x1000, 0x2000, true);
    ctx.slot<PeImage>(wvmp::kPeImage) = wvmp::passes::parse_pe_image(ctx.image);
    wvmp::ProtectRules rules;
    rules.has_pe_aslr = true;
    rules.pe_aslr = false;
    ctx.slot<wvmp::ProtectRules>(wvmp::kProtectRules) = rules;

    wvmp::passes::StubLinkPass pass;
    pass.run(ctx);
    ASSERT_FALSE(ctx.diag.has_errors());
    const auto* reqs = ctx.find_slot<std::vector<NewSection>>(wvmp::kNewSections);
    ASSERT_NE(reqs, nullptr);
    EXPECT_EQ((*reqs)[0].data.size(),
              static_cast<size_t>(48) + wvmp::passes::kEmitReserveBytes);
    // 加成槽不得被写入。
    EXPECT_EQ(ctx.find_slot<u64>(wvmp::kEmitReserveExtra), nullptr);
}

TEST(StubGen, StubBytesStartWithPushesAndSubRsp) {
    // image_base（M2-8 起 stub 协定新增；PE optional header 的 ImageBase 字段
    // 写入 VmContext.scratch_mem，供 Load/Store 访存汇编 `add addr, [CTX+0x110]`）。
    // M2-9: VmContext 加 native_sp (+0x120) + host_rsp (+0x128) + base_save
    // (+0x130) 共 24 字节，结构从 0x120 长到 0x138；kCtxSize 同步从 0x130 调到
    // 0x140（0x138 + 8 字节 16-对齐垫）。
    // MIT-371: VmContext 加 xmm[8] (128B) @ 0x140；结构总长 0x1D8；kCtxSize 同步
    // 从 0x140 调到 0x1C8（0x1D8 + 8 字节 16-对齐垫 = 0x1E0，rounded down to 8-byte
    // alignment = 0x1C8 + 8 = 0x1D0 ... 但 8 字节对齐向下取整 = 0x1C8）。
    const auto stub =
        wvmp::passes::generate_entry_stub(0x9000, 0x9100, 0x9040, 0x1100, 0x140000000ull);
    ASSERT_GT(stub.size(), static_cast<size_t>(32));
    // 首字节必为 push（0x50-0x57 或 REX 0x41 前缀）。
    EXPECT_TRUE((stub[0] >= 0x50 && stub[0] <= 0x57) ||
                (stub[0] == 0x41 && stub[1] >= 0x50 && stub[1] <= 0x57));
    // 序言后应有 sub rsp, 0x3C8（48 81 EC C8 03 00 00）—— MIT-371 xmm 跟踪区
    // 0x1C8 之后，MIT-511 档B wave1 加 ymm[16] (512B) → VmContext 0x3C0，
    // kCtxSize = 0x3C8。
    bool found_sub = false;
    for (size_t i = 0; i + 7 <= stub.size(); ++i) {
        if (stub[i] == 0x48 && stub[i + 1] == 0x81 && stub[i + 2] == 0xEC &&
            stub[i + 3] == 0xC8 && stub[i + 4] == 0x03) {
            found_sub = true;
            break;
        }
    }
    EXPECT_TRUE(found_sub);
}

TEST(StubGen, YmmSyncVariantBytes) {
    // MIT-512 (档B wave2①): ymm_sync 变体 = 既有 stub + 入口 8×vmovups
    // store (C5 FD 11 84 24 disp32) + 出口 8×vmovups load (C5 FD 10 84 24
    // disp32)。默认 false = 字节恒等（既有产物零回踩）。
    const auto plain = wvmp::passes::generate_entry_stub(
        0x9000, 0x9100, 0x9040, 0x1100, 0x140000000ull);
    const auto ymm = wvmp::passes::generate_entry_stub(
        0x9000, 0x9100, 0x9040, 0x1100, 0x140000000ull,
        wvmp::passes::StubArch::X64, nullptr, nullptr, nullptr, true);
    ASSERT_GT(ymm.size(), plain.size());
    auto count = [](const std::vector<u8>& b, const u8* pat, size_t n) {
        int c = 0;
        for (size_t i = 0; i + n <= b.size(); ++i)
            if (std::memcmp(b.data() + i, pat, n) == 0) ++c;
        return c;
    };
    static const u8 st_pat[] = {0xC5, 0xFC, 0x11};  // vmovups [mem], ymm (kstool 钉板: 无 66 前缀)
    static const u8 ld_pat[] = {0xC5, 0xFC, 0x10};  // vmovups ymm, [mem]
    EXPECT_EQ(count(ymm, st_pat, sizeof(st_pat)), 8);
    EXPECT_EQ(count(ymm, ld_pat, sizeof(ld_pat)), 8);
    EXPECT_EQ(count(plain, st_pat, sizeof(st_pat)), 0);
    EXPECT_EQ(count(plain, ld_pat, sizeof(ld_pat)), 0);
    // x86 + ymm_sync → fail-closed throw
    EXPECT_ANY_THROW((static_cast<void>(wvmp::passes::generate_entry_stub(
        0x9000, 0x9100, 0x9040, 0x1100, 0x140000000ull,
        wvmp::passes::StubArch::X86, nullptr, nullptr, nullptr, true))));
}

} // namespace
