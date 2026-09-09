// pe_writer 泳道测试：
//  1) pe_checksum 已知向量（含进位折叠链与奇数长度）；
//  2) pass 级：checksum patch 进镜像与文件、临时文件+rename、幂等、失败路径；
//  3) 系统 PE（notepad x64/x86）loader→writer 逐字节往返。

#include "pe_checksum.hpp"

#include "wvmp/passes/pe_loader/pe_image.hpp"
#include "wvmp/passes/pe_loader/pe_loader_pass.hpp"
#include "wvmp/passes/pe_writer/pe_writer_pass.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/protect_levels.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <set>
#include <span>
#include <string>
#include <system_error>
#include <utility>
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
constexpr size_t kNt = 0x40;
constexpr size_t kChkOff = kNt + 24 + 64; // OptionalHeader.CheckSum

void put16(std::vector<u8>& v, size_t o, u16 x) {
    v[o] = u8(x);
    v[o + 1] = u8(x >> 8);
}
void put32(std::vector<u8>& v, size_t o, u32 x) {
    for (int i = 0; i < 4; ++i) v[o + i] = u8(x >> (8 * i));
}
u32 rd32(const std::vector<u8>& v, size_t o) {
    return u32(v[o]) | (u32(v[o + 1]) << 8) | (u32(v[o + 2]) << 16) | (u32(v[o + 3]) << 24);
}

// 手工拼最小合法 PE（与 pe_loader 测试同构）：头部 [0,0x200) +
// ".text" [0x200,0x400)（VA 0x1000）。
std::vector<u8> build_minimal_pe(bool pe32_plus, u16 machine) {
    const u16 opt_size = pe32_plus ? 240 : 224;
    const size_t sec = kNt + 24 + opt_size;
    std::vector<u8> img(0x400, 0);
    put16(img, 0x00, 0x5A4D);
    put32(img, 0x3C, u32(kNt));
    put32(img, kNt + 0, 0x00004550);
    put16(img, kNt + 4, machine);
    put16(img, kNt + 6, 1);
    put16(img, kNt + 20, opt_size);
    put16(img, kNt + 24, pe32_plus ? 0x20B : 0x10B);
    put32(img, kNt + 24 + 16, 0x1234);
    put32(img, kNt + 24 + 32, 0x1000);
    put32(img, kNt + 24 + 36, 0x200);
    std::memcpy(&img[sec], ".text", 5);
    put32(img, sec + 8, 0x200);
    put32(img, sec + 12, 0x1000);
    put32(img, sec + 16, 0x200);
    put32(img, sec + 20, 0x200);
    put32(img, sec + 36, 0x60000020);
    return img;
}

fs::path temp_dir() {
    fs::path dir = fs::temp_directory_path() / "wvmp_pe_writer_tests";
    fs::create_directories(dir);
    return dir;
}

std::vector<u8> read_file(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    in.seekg(0, std::ios::end);
    const std::streamoff n = in.tellg();
    in.seekg(0, std::ios::beg);
    std::vector<u8> v(static_cast<size_t>(n < 0 ? 0 : n));
    if (!v.empty())
        in.read(reinterpret_cast<char*>(v.data()), static_cast<std::streamsize>(v.size()));
    return v;
}

// 分块（64KB）比较两个文件，不一致时报首个差异偏移。
::testing::AssertionResult compare_files(const fs::path& a, const fs::path& b) {
    std::ifstream fa(a, std::ios::binary), fb(b, std::ios::binary);
    if (!fa || !fb) return ::testing::AssertionFailure() << "无法打开比较对象";
    constexpr size_t kChunk = 0x10000;
    std::vector<u8> ba(kChunk), bb(kChunk);
    u64 off = 0;
    for (;;) {
        fa.read(reinterpret_cast<char*>(ba.data()), std::streamsize(kChunk));
        const std::streamsize na = fa.gcount();
        fb.read(reinterpret_cast<char*>(bb.data()), std::streamsize(kChunk));
        const std::streamsize nb = fb.gcount();
        if (na != nb)
            return ::testing::AssertionFailure() << "文件长度不同（块首偏移 " << off << "）";
        if (na == 0) break;
        if (std::memcmp(ba.data(), bb.data(), size_t(na)) != 0) {
            for (std::streamsize i = 0; i < na; ++i) {
                if (ba[size_t(i)] != bb[size_t(i)])
                    return ::testing::AssertionFailure()
                           << "首个差异字节 @0x" << std::hex << (off + u64(i)) << std::dec
                           << ": 0x" << std::hex << unsigned(ba[size_t(i)]) << " vs 0x"
                           << unsigned(bb[size_t(i)]);
            }
        }
        off += u64(na);
        if (na < std::streamsize(kChunk)) break;
    }
    return ::testing::AssertionSuccess();
}

// loader→writer 完整往返一个已存在的 PE，断言逐字节一致 + checksum 吻合。
void roundtrip_system_pe(const fs::path& src, u16 machine, bool pe32_plus, const char* tag) {
    const fs::path dir = temp_dir();
    const fs::path copy = dir / (std::string("rt_") + tag + ".exe");
    const fs::path out = dir / (std::string("rt_") + tag + ".out.exe");
    std::error_code ec;
    fs::remove(copy, ec);
    fs::remove(out, ec);
    fs::copy_file(src, copy, fs::copy_options::overwrite_existing);

    ProtectionContext ctx;
    ctx.input_path = copy;
    ctx.output_path = out;
    ctx.image = read_file(copy);
    // MIT-414 (G7p2 B.2): x86 输入在 PeLoaderPass 层显式硬 gate（不产保护壳）。
    // 本测试意图是验证 pe_writer 对 PE32 镜像"不追加节时逐字节往返保持"，
    // 与 gate 语义不冲突——x86 分支绕过 pass 层、直接以 parse 级接口（解析
    // 本身双架构无害）产出模型；pass 层 gate 行为由 test_pe_loader 的
    // RejectsX86InputWithHardError 覆盖。
    if (machine == kMachineX86) {
        ctx.slot<wvmp::passes::PeImage>(wvmp::passes::kImageMeta) =
            wvmp::passes::parse_pe_image(ctx.image);
    } else {
        wvmp::passes::PeLoaderPass loader;
        loader.run(ctx);
    }
    const wvmp::passes::PeImage* meta =
        ctx.find_slot<wvmp::passes::PeImage>(wvmp::passes::kImageMeta);
    ASSERT_NE(meta, nullptr);
    EXPECT_EQ(meta->machine, machine);
    EXPECT_EQ(meta->is_pe32_plus, pe32_plus);

    wvmp::passes::PeWriterPass writer;
    writer.run(ctx);

    ASSERT_TRUE(fs::exists(out)) << out;
    // 临时文件应已被 rename 消化
    fs::path leftover = out;
    leftover += ".wvmp-tmp";
    EXPECT_FALSE(fs::exists(leftover));

    EXPECT_TRUE(compare_files(copy, out)) << "往返输出应与原文件逐字节一致";

    // 单独点名 checksum：重算值应与系统签名值吻合（逐字节一致的子集，
    // 失败时便于区分是 checksum 算法错还是镜像被改动）。
    const std::vector<u8> orig = read_file(copy), mine = read_file(out);
    ASSERT_EQ(orig.size(), mine.size());
    const size_t chk = size_t(meta->nt_headers_offset) + 24 + 64;
    ASSERT_LE(chk + 4, orig.size());
    EXPECT_EQ(rd32(orig, chk), rd32(mine, chk));
}

} // namespace

// —— checksum 算法已知向量 ————————————————————————————————————————

TEST(PeChecksum, KnownVectors) {
    // 全零 8 字节，跳过 @0：字和 0 → 0 + 8
    const std::vector<u8> zeros(8, 0);
    EXPECT_EQ(wvmp::passes::pe_checksum(zeros, 0), 8u);

    // [AA BB CC DD | EE FF 11 22] 跳过 @4：小端字 0xBBAA + 0xDDCC = 0x19976
    // → 折位 0x9977 → +8 = 0x997F
    const std::vector<u8> v = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22};
    EXPECT_EQ(wvmp::passes::pe_checksum(v, 4), 0x997Fu);

    // 奇数长度 5 字节跳过 @0：仅剩末字节 0x05（高字节补 0）→ 5 + 5
    const std::vector<u8> odd = {1, 2, 3, 4, 5};
    EXPECT_EQ(wvmp::passes::pe_checksum(odd, 0), 10u);

    // 进位折叠链：0xFFFF + 0xFFFF（跳过 @4 的 4 个 0 字节）。
    // 每步折位保持 ≤0xFFFF ⇒ 结果 0xFFFF + 8（若折位实现错误会得到
    // 0x10000 + 8，此向量专防该偏差）。
    const std::vector<u8> carry = {0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0};
    EXPECT_EQ(wvmp::passes::pe_checksum(carry, 4), 0xFFFFu + 8u);
}

// —— pass 级写出 ——————————————————————————————————————————————————

TEST(PeWriterPass, PatchesChecksumIntoImageAndFile) {
    std::vector<u8> bytes = build_minimal_pe(true, kMachineX64);
    put32(bytes, kChkOff, 0xDEADBEEF); // 故意塞错值
    const fs::path out = temp_dir() / "minimal_out.exe";

    ProtectionContext ctx; // 无 kImageMeta 槽：writer 需现场重解析（覆盖该分支）
    ctx.image = bytes;
    ctx.output_path = out;
    wvmp::passes::PeWriterPass writer;

    const auto reqs = writer.requires_keys();
    ASSERT_EQ(reqs.size(), 1u);
    EXPECT_EQ(reqs[0], wvmp::kImage);

    writer.run(ctx);

    const u32 cs_img = rd32(ctx.image, kChkOff);
    EXPECT_NE(cs_img, 0xDEADBEEFu); // 镜像内已重算
    EXPECT_NE(cs_img, 0u);

    const std::vector<u8> file = read_file(out); // 输出文件携带同一 checksum
    ASSERT_EQ(file.size(), ctx.image.size());
    EXPECT_EQ(0, std::memcmp(file.data(), ctx.image.data(), file.size()));
    EXPECT_EQ(rd32(file, kChkOff), cs_img);

    // 幂等：以输出为输入再写一遍，逐字节不变（checksum 已正确时重算稳定）
    ProtectionContext ctx2;
    ctx2.image = file;
    ctx2.output_path = temp_dir() / "minimal_out2.exe";
    writer.run(ctx2);
    EXPECT_TRUE(compare_files(out, ctx2.output_path));
}

TEST(PeWriterPass, EmptyImageFails) {
    ProtectionContext ctx;
    ctx.output_path = temp_dir() / "empty_out.exe";
    wvmp::passes::PeWriterPass writer;
    EXPECT_THROW(writer.run(ctx), std::runtime_error);
    EXPECT_TRUE(ctx.diag.has_errors());
}

TEST(PeWriterPass, GarbageImageFails) {
    ProtectionContext ctx;
    ctx.image.assign(0x100, 'A'); // 连 MZ 都没有
    ctx.output_path = temp_dir() / "garbage_out.exe";
    wvmp::passes::PeWriterPass writer;
    EXPECT_THROW(writer.run(ctx), std::runtime_error);
    EXPECT_TRUE(ctx.diag.has_errors());
}

TEST(PeWriterPass, UnwritableOutputPathFails) {
    ProtectionContext ctx;
    ctx.image = build_minimal_pe(true, kMachineX64);
    ctx.output_path = temp_dir() / "no_such_dir" / "out.exe";
    wvmp::passes::PeWriterPass writer;
    EXPECT_THROW(writer.run(ctx), std::runtime_error);
    EXPECT_TRUE(ctx.diag.has_errors());
}

// —— MIT-494 (T26)：ASLR reloc 扩展 ————————————————————————————

// 夹具：最小 PE + native DYNAMIC_BASE/ reloc 块（覆盖 .text 内 1 个
// native 站点 @0x1400）+ .wvmp/.wvmpc 载荷 + 发射点登记表。aslr_on=
// false 时不置 native DYNAMIC_BASE（native 未 opt-in 分支）。
static void make_aslr_fixture(ProtectionContext& ctx, bool aslr_on,
                              const std::vector<u32>& sites) {
    std::vector<u8> bytes = build_minimal_pe(true, kMachineX64);
    const size_t opt = kNt + 24;  // OptionalHeader
    if (aslr_on) {
        const u16 ch = static_cast<u16>(rd32(bytes, opt + 0x46) & 0xFFFF);
        put16(bytes, opt + 0x46, static_cast<u16>(ch | 0x0040));
    }
    // 原 reloc：单块 PageRva=0x1000，1 个 DIR64 站点 @0x400；块体放
    // .text raw 内（0x380），dd[5] = (.text VA + 0x180, 16)。
    const size_t blk_off = 0x380;
    put32(bytes, blk_off, 0x1000);       // PageRva
    put32(bytes, blk_off + 4, 16);       // SizeOfBlock（头 + 1 条目 + 垫）
    put16(bytes, blk_off + 8, static_cast<u16>(10 << 12 | 0x400));
    put16(bytes, blk_off + 10, 0);       // ABSOLUTE 垫
    put32(bytes, opt + 112 + 5 * 8, 0x1180);
    put32(bytes, opt + 112 + 5 * 8 + 4, 16);

    ctx.image = bytes;
    ctx.output_path = temp_dir() / "aslr_case.exe";
    wvmp::passes::NewSection wvmp;
    wvmp.name = ".wvmp";
    wvmp.data.assign(0x100 + wvmp::passes::kEmitReserveBytes, 0);
    wvmp.requested_rva = 0x2000u;
    wvmp.characteristics = 0xC0000040u;
    wvmp::passes::NewSection wvmpc;
    wvmpc.name = ".wvmpc";
    wvmpc.data.assign(0x40, 0);
    // 连续性：.wvmp 虚拟末端 = align(0x2000 + 0x2100, 0x1000) = 0x5000。
    wvmpc.requested_rva = 0x5000u;
    wvmpc.characteristics = 0x60000020u;
    auto& secs =
        ctx.slot<std::vector<wvmp::passes::NewSection>>(wvmp::kNewSections);
    secs.push_back(wvmp);
    secs.push_back(wvmpc);
    ctx.slot<std::vector<u32>>(wvmp::kRelocSites) = sites;
}

TEST(PeWriterPass, EmitRelocExtensionRepointsDirectory) {
    ProtectionContext ctx;
    make_aslr_fixture(ctx, /*aslr_on=*/true, {0x5008, 0x5010});
    wvmp::passes::PeWriterPass writer;
    writer.run(ctx);

    // DYNAMIC_BASE 保留。
    const u16 ch = static_cast<u16>(rd32(ctx.image, kNt + 24 + 0x46) & 0xFFFF);
    EXPECT_NE(ch & 0x0040, 0u);

    // dd[5] 重指 .wvmp（保持原值 0x1180 即失败形态）。
    const u32 rva = rd32(ctx.image, kNt + 24 + 112 + 5 * 8);
    const u32 sz = rd32(ctx.image, kNt + 24 + 112 + 5 * 8 + 4);
    // 落点 = .wvmp blobs 末端（0x2000 + 0x2100 = 0x4100）。
    EXPECT_GE(rva, 0x2000u);
    EXPECT_LE(rva, 0x4100u);
    EXPECT_NE(rva, 0x1180u);

    // 经节表定位 .wvmp raw，遍历 reloc 块：闭合、含登记站点 0x5008、
    // 原生站点 0x1400 恰好一次（双重 delta 防线）。
    const u16 nsec = static_cast<u16>(rd32(ctx.image, kNt + 6) & 0xFFFF);
    const u16 optsz = static_cast<u16>(rd32(ctx.image, kNt + 20) & 0xFFFF);
    const size_t opt2 = kNt + 24;
    u64 ro = 0;
    for (u16 i = 0; i < nsec && ro == 0; ++i) {
        const size_t sh = opt2 + optsz + size_t(i) * 40;
        if (std::memcmp(&ctx.image[sh], ".wvmp\0", 6) == 0) {
            const u32 va = rd32(ctx.image, sh + 12);
            const u32 rp = rd32(ctx.image, sh + 20);
            ro = u64(rp) + (rva - va);
        }
    }
    ASSERT_NE(ro, 0u);
    u32 pos = 0;
    int blocks = 0;
    bool has_5008 = false;
    int native_1400_count = 0;
    while (pos + 8 <= sz) {
        const u32 page = rd32(ctx.image, size_t(ro) + pos);
        const u32 bsz = rd32(ctx.image, size_t(ro) + pos + 4);
        ASSERT_GE(bsz, 8u);
        ASSERT_LE(pos + bsz, sz);
        for (u32 k = 0; k < (bsz - 8) / 2; ++k) {
            const u16 ent = static_cast<u16>(
                rd32(ctx.image, size_t(ro) + pos + 8 + k * 2) & 0xFFFF);
            if (ent >> 12 == 10) {
                const u32 site = page + (ent & 0xFFF);
                if (site == 0x5008) has_5008 = true;
                // 原生站点恰好一次（原块拷贝保留；不得重复登记）。
                if (site == 0x1400) ++native_1400_count;
            }
        }
        pos += bsz;
        ++blocks;
    }
    EXPECT_GE(blocks, 2);          // 原块 + 新块
    EXPECT_TRUE(has_5008);
    EXPECT_EQ(native_1400_count, 1);
}

TEST(PeWriterPass, EmitRelocAslrDisabledClearsFlag) {
    ProtectionContext ctx;
    make_aslr_fixture(ctx, /*aslr_on=*/true, {0x5008});
    auto& rules = ctx.slot<wvmp::ProtectRules>(wvmp::kProtectRules);
    rules.has_pe_aslr = true;
    rules.pe_aslr = false;  // [pe] aslr=false
    wvmp::passes::PeWriterPass writer;
    writer.run(ctx);
    const u16 ch = static_cast<u16>(rd32(ctx.image, kNt + 24 + 0x46) & 0xFFFF);
    EXPECT_EQ(ch & 0x0040, 0u);  // 维持清除
    EXPECT_EQ(rd32(ctx.image, kNt + 24 + 112 + 5 * 8), 0x1180u);  // dd[5] 未动
}

TEST(PeWriterPass, EmitRelocNativeNotAslrClearsFlag) {
    // native 未声明 DYNAMIC_BASE → 保守清除（扩展跳过）。
    ProtectionContext ctx;
    make_aslr_fixture(ctx, /*aslr_on=*/false, {0x5008});
    wvmp::passes::PeWriterPass writer;
    writer.run(ctx);
    const u16 ch = static_cast<u16>(rd32(ctx.image, kNt + 24 + 0x46) & 0xFFFF);
    EXPECT_EQ(ch & 0x0040, 0u);
}

// —— MIT-494c (T26c)：覆写区孤儿 reloc 条目剪枝 ————————————————————

// 扩展目录通用遍历：按 loader 的 pos += bsz 语义走完整 blob（块间不允许
// 间隙——零洞假头会提前终止遍历），收集 (site, type) 集。不闭合即失败。
static void collect_ext_sites(const ProtectionContext& ctx, u32 dd_rva,
                              u32 dd_sz, std::set<std::pair<u32, u16>>& out) {
    const u16 nsec = static_cast<u16>(rd32(ctx.image, kNt + 6) & 0xFFFF);
    const u16 optsz = static_cast<u16>(rd32(ctx.image, kNt + 20) & 0xFFFF);
    const size_t opt2 = kNt + 24;
    u64 ro = 0;
    for (u16 i = 0; i < nsec && ro == 0; ++i) {
        const size_t sh = opt2 + optsz + size_t(i) * 40;
        if (std::memcmp(&ctx.image[sh], ".wvmp\0", 6) == 0) {
            const u32 va = rd32(ctx.image, sh + 12);
            const u32 rp = rd32(ctx.image, sh + 20);
            ro = u64(rp) + (dd_rva - va);
        }
    }
    ASSERT_NE(ro, 0u);
    u32 pos = 0;
    while (pos + 8 <= dd_sz) {
        const u32 page = rd32(ctx.image, size_t(ro) + pos);
        const u32 bsz = rd32(ctx.image, size_t(ro) + pos + 4);
        ASSERT_GE(bsz, 8u);
        ASSERT_EQ(bsz % 4, 0u);
        ASSERT_LE(pos + bsz, dd_sz);
        for (u32 k = 0; k < (bsz - 8) / 2; ++k) {
            const u16 ent = static_cast<u16>(
                rd32(ctx.image, size_t(ro) + pos + 8 + k * 2) & 0xFFFF);
            if ((ent >> 12) != 0)
                out.insert({page + u32(ent & 0xFFF),
                            static_cast<u16>(ent >> 12)});
        }
        pos += bsz;
    }
    ASSERT_EQ(pos, dd_sz);  // 遍历恰好闭合（无尾部零洞）
}

TEST(PeWriterPass, EmitRelocPrunesOrphansInPatchedRanges) {    ProtectionContext ctx;
    make_aslr_fixture(ctx, /*aslr_on=*/true, {0x5008});
    // 原 reloc 块重组：DIR64@0x1400（落覆写区 [0x1400,0x140C)，孤儿）+
    // HIGHLOW@0x1480（落覆写区 [0x1480,0x1484)，孤儿）+ DIR64@0x1500
    // （覆写区外，幸存）+ ABSOLUTE 垫。
    const size_t blk = 0x380;
    put32(ctx.image, blk, 0x1000);
    put32(ctx.image, blk + 4, 8 + 4 * 2);
    put16(ctx.image, blk + 8, static_cast<u16>(10 << 12 | 0x400));
    put16(ctx.image, blk + 10, static_cast<u16>(3 << 12 | 0x480));
    put16(ctx.image, blk + 12, static_cast<u16>(10 << 12 | 0x500));
    put16(ctx.image, blk + 14, 0);
    put32(ctx.image, kNt + 24 + 112 + 5 * 8, 0x1180);
    put32(ctx.image, kNt + 24 + 112 + 5 * 8 + 4, 16);
    auto& ranges =
        ctx.slot<std::vector<std::pair<u32, u32>>>(wvmp::kPatchedRanges);
    ranges = {{0x1400, 12}, {0x1480, 4}};

    wvmp::passes::PeWriterPass writer;
    writer.run(ctx);

    std::set<std::pair<u32, u16>> sites;
    const u32 rva = rd32(ctx.image, kNt + 24 + 112 + 5 * 8);
    const u32 sz = rd32(ctx.image, kNt + 24 + 112 + 5 * 8 + 4);
    ASSERT_NE(rva, 0x1180u);  // 扩展发生
    collect_ext_sites(ctx, rva, sz, sites);
    EXPECT_EQ(sites.count({0x1400, 10}), 0u);  // 孤儿剪净
    EXPECT_EQ(sites.count({0x1480, 3}), 0u);
    EXPECT_EQ(sites.count({0x1500, 10}), 1u);  // 幸存者保留
    EXPECT_EQ(sites.count({0x5008, 10}), 1u);  // 发射点登记站点在场
    const u16 ch = static_cast<u16>(rd32(ctx.image, kNt + 24 + 0x46) & 0xFFFF);
    EXPECT_NE(ch & 0x0040, 0u);  // 扩展成功 → DYNAMIC_BASE 保留
}

TEST(PeWriterPass, EmitRelocHighAdjFollowsPairedHighLow) {
    // MIT-494c：HIGHADJ(1) 隶属其前导 HIGHLOW(3)——前导被剪则随剪，前导
    // 幸存则随存（loader 格式安全敏感面，双向钉死）。
    ProtectionContext ctx;
    make_aslr_fixture(ctx, /*aslr_on=*/true, {0x5008});
    const size_t blk = 0x380;
    put32(ctx.image, blk, 0x1000);
    put32(ctx.image, blk + 4, 8 + 4 * 2);
    // 对 1：HIGHLOW@0x1400 落覆写区 [0x1400,0x140C) → 剪；HIGHADJ@0x1402 随剪。
    // 对 2：HIGHLOW@0x1600 幸存；HIGHADJ@0x1602 随存。
    put16(ctx.image, blk + 8, static_cast<u16>(3 << 12 | 0x400));
    put16(ctx.image, blk + 10, static_cast<u16>(1 << 12 | 0x402));
    put16(ctx.image, blk + 12, static_cast<u16>(3 << 12 | 0x600));
    put16(ctx.image, blk + 14, static_cast<u16>(1 << 12 | 0x602));
    put32(ctx.image, kNt + 24 + 112 + 5 * 8, 0x1180);
    put32(ctx.image, kNt + 24 + 112 + 5 * 8 + 4, 16);
    auto& ranges =
        ctx.slot<std::vector<std::pair<u32, u32>>>(wvmp::kPatchedRanges);
    ranges = {{0x1400, 12}};

    wvmp::passes::PeWriterPass writer;
    writer.run(ctx);

    std::set<std::pair<u32, u16>> sites;
    collect_ext_sites(ctx,
                      rd32(ctx.image, kNt + 24 + 112 + 5 * 8),
                      rd32(ctx.image, kNt + 24 + 112 + 5 * 8 + 4), sites);
    EXPECT_EQ(sites.count({0x1400, 3}), 0u);
    EXPECT_EQ(sites.count({0x1402, 1}), 0u);  // 配对 HIGHADJ 随剪
    EXPECT_EQ(sites.count({0x1600, 3}), 1u);
    EXPECT_EQ(sites.count({0x1602, 1}), 1u);  // 幸存 HIGHLOW 的 HIGHADJ 保留
}

TEST(PeWriterPass, EmitRelocAllOrphansFallsBackToClearDynamicBase) {
    ProtectionContext ctx;
    make_aslr_fixture(ctx, /*aslr_on=*/true, {});  // 无 packer 站点
    // 原 reloc 唯一条目落覆写区内 = 全孤儿。
    const size_t blk = 0x380;
    put32(ctx.image, blk, 0x1000);
    put32(ctx.image, blk + 4, 16);
    put16(ctx.image, blk + 8, static_cast<u16>(10 << 12 | 0x400));
    put16(ctx.image, blk + 10, 0);
    auto& ranges =
        ctx.slot<std::vector<std::pair<u32, u32>>>(wvmp::kPatchedRanges);
    ranges = {{0x1400, 12}};
    wvmp::passes::PeWriterPass writer;
    writer.run(ctx);
    // 回退：DYNAMIC_BASE 清除（delta=0 成为声明行为）且 dd[5] 未动。
    const u16 ch = static_cast<u16>(rd32(ctx.image, kNt + 24 + 0x46) & 0xFFFF);
    EXPECT_EQ(ch & 0x0040, 0u);
    EXPECT_EQ(rd32(ctx.image, kNt + 24 + 112 + 5 * 8), 0x1180u);
}

TEST(PeWriterPass, EmitRelocNoRangesKeepsOriginalEntries) {
    // 回归防线：无 kPatchedRanges（旧管道 / 直接 pe_writer 单测）时原条
    // 目零剪枝——剪枝面必须由显式覆写区登记驱动，禁止隐式猜测。
    ProtectionContext ctx;
    make_aslr_fixture(ctx, /*aslr_on=*/true, {0x5008});
    wvmp::passes::PeWriterPass writer;
    writer.run(ctx);
    std::set<std::pair<u32, u16>> sites;
    collect_ext_sites(ctx,
                      rd32(ctx.image, kNt + 24 + 112 + 5 * 8),
                      rd32(ctx.image, kNt + 24 + 112 + 5 * 8 + 4), sites);
    EXPECT_EQ(sites.count({0x1400, 10}), 1u);  // 原生站点仍在（现行为）
    EXPECT_EQ(sites.count({0x5008, 10}), 1u);
}

// —— MIT-491 (T23)：Emit 预留区高水位观测 ————————————————————————

// 高水位夹具：合法最小 PE + .wvmp 数据节（blobs + 8KB 预留）+ 游标。
// used_high = 游标越过 75% 预算线 → 期望高水位 Note；used_low → 无。
static void run_high_water_case(u64 cursor, bool& hit) {
    std::vector<u8> bytes = build_minimal_pe(true, kMachineX64);
    const fs::path out = temp_dir() / "hw_case.exe";
    ProtectionContext ctx;
    ctx.image = bytes;
    ctx.output_path = out;
    wvmp::passes::NewSection wvmp;
    wvmp.name = ".wvmp";
    wvmp.data.assign(0x200 + wvmp::passes::kEmitReserveBytes, 0);
    wvmp.requested_rva = 0x2000u;  // 紧接最小 PE .text 节尾（连续性校验）
    ctx.slot<std::vector<wvmp::passes::NewSection>>(wvmp::kNewSections)
        .push_back(wvmp);
    ctx.slot<u64>(wvmp::kEmitReserveBase) = cursor;
    wvmp::passes::PeWriterPass writer;
    writer.run(ctx);
    hit = false;
    for (const auto& item : ctx.diag.items())
        if (item.message.find("Emit 预留区高水位") != std::string::npos)
            hit = true;
}

TEST(PeWriterPass, EmitReserveHighWaterEmitsNote) {
    // blobs 0x200 + 预留 0x2000：used = 0x2000 - 0x1800 = 0x800... 取
    // 7000/8192 ≈ 85% > 75% → 必出 Note。
    bool hit = false;
    run_high_water_case(0x200 + 7000, hit);  // used = cursor - reserve_start(0x200) = 7000 ≈ 85%
    EXPECT_TRUE(hit);
}

TEST(PeWriterPass, EmitReserveLowWaterStaysSilent) {
    // used = 1000/8192 ≈ 12% < 75% → 无高水位 Note。
    bool hit = true;
    run_high_water_case(0x200 + 1000, hit);  // used = 1000 ≈ 12% < 75%
    EXPECT_FALSE(hit);
}

TEST(PeWriterPass, EmitReserveNoCursorSlotStaysSilent) {
    // 旧夹具（无游标槽）→ 观测面静默跳过，行为零改动。
    std::vector<u8> bytes = build_minimal_pe(true, kMachineX64);
    const fs::path out = temp_dir() / "hw_nocursor.exe";
    ProtectionContext ctx;
    ctx.image = bytes;
    ctx.output_path = out;
    wvmp::passes::NewSection wvmp;
    wvmp.name = ".wvmp";
    wvmp.data.assign(0x200 + wvmp::passes::kEmitReserveBytes, 0);
    wvmp.requested_rva = 0x2000u;  // 紧接最小 PE .text 节尾（连续性校验）
    ctx.slot<std::vector<wvmp::passes::NewSection>>(wvmp::kNewSections)
        .push_back(wvmp);
    wvmp::passes::PeWriterPass writer;
    writer.run(ctx);
    bool hit = false;
    for (const auto& item : ctx.diag.items())
        if (item.message.find("Emit 预留区高水位") != std::string::npos)
            hit = true;
    EXPECT_FALSE(hit);
}

// —— 系统 PE 往返（Windows 签名的 checksum 即正确性判据）———————————

TEST(PeWriterRoundtrip, NotepadX64) {
    const fs::path src = R"(C:\Windows\System32\notepad.exe)";
    if (!fs::exists(src)) GTEST_SKIP() << "系统 PE 不存在，跳过: " << src.string();
    roundtrip_system_pe(src, kMachineX64, true, "x64");
}

TEST(PeWriterRoundtrip, NotepadX86) {
    const fs::path src = R"(C:\Windows\SysWOW64\notepad.exe)";
    if (!fs::exists(src)) GTEST_SKIP() << "系统 PE 不存在，跳过: " << src.string();
    roundtrip_system_pe(src, kMachineX86, false, "x86");
}
