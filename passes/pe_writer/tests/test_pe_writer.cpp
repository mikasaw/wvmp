// pe_writer 泳道测试：
//  1) pe_checksum 已知向量（含进位折叠链与奇数长度）；
//  2) pass 级：checksum patch 进镜像与文件、临时文件+rename、幂等、失败路径；
//  3) 系统 PE（notepad x64/x86）loader→writer 逐字节往返。

#include "pe_checksum.hpp"
#include "output_publish.hpp"

#include "wvmp/passes/pe_loader/pe_image.hpp"
#include "wvmp/passes/pe_loader/pe_loader_pass.hpp"
#include "wvmp/passes/pe_writer/pe_writer_pass.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/protect_levels.hpp"

#include <gtest/gtest.h>

#include <algorithm>
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
    // 临时文件必须已被替换消化（CR-09 后 tmp 名带唯一后缀，不再点名固定后缀）
    for (const auto& e : fs::directory_iterator(out.parent_path()))
        if (e.path().filename().string().rfind(out.filename().string(), 0) == 0)
            EXPECT_EQ(e.path(), out) << "写出后残留临时文件: " << e.path();

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

TEST(PeWriterPass, EmitRelocX86ExtendsHighLow) {
    // MIT-494d/T27b：x86（PE32）真 ASLR——词流 RVA 化（T27a）后撤声明回
    // 退，HIGHLOW 扩展与 x64 同管道。PE32 dd 在 opt+96；native 站点
    // HIGHLOW @0x1400 + packer 站点 @0x2008 → dd[5] 重指 + 类型 3 条目。
    std::vector<u8> bytes = build_minimal_pe(false, kMachineX86);
    const size_t opt = kNt + 24;
    put16(bytes, opt + 0x46, 0x0040);  // native DYNAMIC_BASE
    const size_t blk = 0x380;
    put32(bytes, blk, 0x1000);
    put32(bytes, blk + 4, 8 + 2 * 2);
    put16(bytes, blk + 8, static_cast<u16>(3 << 12 | 0x400));
    put16(bytes, blk + 10, 0);
    put32(bytes, opt + 96 + 5 * 8, 0x1180);
    put32(bytes, opt + 96 + 5 * 8 + 4, 12);

    ProtectionContext ctx;
    ctx.image = bytes;
    ctx.output_path = temp_dir() / "aslr_x86.exe";
    wvmp::passes::NewSection wvmp;
    wvmp.name = ".wvmp";
    wvmp.data.assign(0x100 + wvmp::passes::kEmitReserveBytes, 0);
    wvmp.requested_rva = 0x2000u;
    wvmp.characteristics = 0xC0000040u;
    wvmp::passes::NewSection wvmpc;
    wvmpc.name = ".wvmpc";
    wvmpc.data.assign(0x40, 0);
    wvmpc.requested_rva = 0x5000u;
    wvmpc.characteristics = 0x60000020u;
    auto& secs =
        ctx.slot<std::vector<wvmp::passes::NewSection>>(wvmp::kNewSections);
    secs.push_back(wvmp);
    secs.push_back(wvmpc);
    ctx.slot<std::vector<u32>>(wvmp::kRelocSites) = {0x2008};

    wvmp::passes::PeWriterPass writer;
    writer.run(ctx);

    const u16 ch = static_cast<u16>(rd32(ctx.image, opt + 0x46) & 0xFFFF);
    EXPECT_NE(ch & 0x0040, 0u);  // DYNAMIC_BASE 保留（x86 真 ASLR）
    const u32 rva = rd32(ctx.image, opt + 96 + 5 * 8);
    ASSERT_NE(rva, 0x1180u);     // 扩展发生（回退已撤）
    std::set<std::pair<u32, u16>> sites;
    collect_ext_sites(ctx, rva, rd32(ctx.image, opt + 96 + 5 * 8 + 4), sites);
    EXPECT_EQ(sites.count({0x1400, 3}), 1u);   // native HIGHLOW 幸存
    EXPECT_EQ(sites.count({0x2008, 3}), 1u);   // packer 站点 HIGHLOW
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

// —— MIT-528 (CR-09)：输出替换可靠性（禁止先 remove 目标）——————————————
//
// 旧流程：写固定名 .wvmp-tmp → fs::remove(目标) → rename。两处不可靠：删得
// 掉目标却 rename 失败 ⇒ 旧产物已丢、新产物（tmp）也被清掉；固定名 ⇒ 同一
// 目标的并发写入共用一份 tmp。本组用"只读目标"做失败注入——MSVC 的
// fs::remove 会清掉只读位真的删掉旧产物（修前可观测：run 反而"成功"、旧
// 字节消失），而原子替换（MoveFileExW + REPLACE_EXISTING）在只读目标上必须
// 失败，并把旧目标与新 tmp 双双保留且在诊断里点名。

namespace {

// 临时名唯一后缀的起始标记（.wvmp-tmp 固定名必须已消失）。
constexpr const char* kTmpMark = ".wvmp-tmp-";

void set_read_only(const fs::path& p, bool ro) {
    std::error_code ec;
    fs::permissions(p,
                    ro ? fs::perms::owner_read
                       : (fs::perms::owner_read | fs::perms::owner_write |
                          fs::perms::group_read | fs::perms::group_write |
                          fs::perms::others_read | fs::perms::others_write),
                    fs::perm_options::replace, ec);
    ASSERT_FALSE(ec) << "设置只读属性失败: " << ec.message();
}

// 夹具自证：只读确实生效（以写方式打开必须失败）。
void expect_write_blocked(const fs::path& p) {
    std::ofstream probe(p, std::ios::binary | std::ios::app);
    EXPECT_FALSE(probe.is_open()) << "只读夹具未生效: " << p.string();
}

// 目录内除 keep 之外、文件名以 keep 打头的残留（= 本单语义下的 tmp）。
std::vector<fs::path> tmp_leftovers(const fs::path& dir, const fs::path& keep) {
    std::vector<fs::path> v;
    const std::string prefix = keep.filename().string();
    for (const auto& e : fs::directory_iterator(dir)) {
        const fs::path p = e.path();
        if (p == keep) continue;
        if (p.filename().string().rfind(prefix, 0) == 0) v.push_back(p);
    }
    std::sort(v.begin(), v.end());
    return v;
}

int count_entries(const fs::path& dir) {
    return static_cast<int>(std::distance(fs::directory_iterator(dir), fs::directory_iterator{}));
}

std::string joined_diag(const ProtectionContext& ctx) {
    std::string all;
    for (const auto& item : ctx.diag.items()) all += item.message, all += '\n';
    return all;
}

fs::path cr09_dir(const char* tag) {
    const fs::path dir = temp_dir() / (std::string("cr09_") + tag);
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir);
    return dir;
}

// 造一枚"既有产物"：先正常写出一次（返回写出后的镜像字节）。
std::vector<u8> seed_previous_product(const fs::path& out) {
    ProtectionContext seed;
    seed.image = build_minimal_pe(true, kMachineX64);
    seed.output_path = out;
    wvmp::passes::PeWriterPass writer;
    writer.run(seed);
    return seed.image;
}

} // namespace

TEST(PeWriterPublish, ReadOnlyTargetKeepsOldProductAndPreservesTmp) {
    const fs::path dir = cr09_dir("ro");
    const fs::path out = dir / "victim.exe";
    const std::vector<u8> old_bytes = seed_previous_product(out);
    ASSERT_FALSE(old_bytes.empty());
    set_read_only(out, true);
    expect_write_blocked(out);

    ProtectionContext ctx;
    ctx.image = build_minimal_pe(true, kMachineX64);
    ctx.image.back() = 0x5A; // 与旧产物可区分的"新产物"
    ctx.output_path = out;
    wvmp::passes::PeWriterPass writer;

    // ① 返回码非 0（抛错 + diag 记 Error）
    EXPECT_THROW(writer.run(ctx), std::runtime_error);
    EXPECT_TRUE(ctx.diag.has_errors());

    // ② 旧产物字节完好（替换失败一律不得动过它）
    EXPECT_EQ(read_file(out), old_bytes) << "旧产物被删/被改（先 remove 目标的后果）";

    // ③ 新 tmp 仍在、与目标同目录、内容是完整新镜像；诊断点名两侧路径
    const auto left = tmp_leftovers(dir, out);
    ASSERT_EQ(left.size(), static_cast<size_t>(1)) << "失败分支应恰好保留一枚 tmp";
    EXPECT_EQ(read_file(left[0]), ctx.image) << "tmp 未含完整新产物（半写？）";
    const std::string texts = joined_diag(ctx);
    EXPECT_NE(texts.find(left[0].string()), std::string::npos) << "诊断未点名保留的 tmp 路径";
    EXPECT_NE(texts.find(out.string()), std::string::npos) << "诊断未点名保留的旧目标路径";

    // ④ 无半写文件：目录内除目标 + 一枚 tmp 外别无他物
    EXPECT_EQ(count_entries(dir), 2);

    set_read_only(out, false);
    std::error_code ec;
    fs::remove_all(dir, ec);
}

TEST(PeWriterPublish, ConsecutiveWritesUseDistinctTmpNames) {
    const fs::path dir = cr09_dir("uniq");
    const fs::path out = dir / "victim.exe";
    const std::vector<u8> old_bytes = seed_previous_product(out);
    set_read_only(out, true);
    expect_write_blocked(out);

    const std::string stem = out.filename().string();
    // 单测直判：临时名生成器连续两次调用必须给出不同字符串（同目录、唯一后缀）
    const fs::path n0 = wvmp::passes::make_temp_output_path(out);
    const fs::path n1 = wvmp::passes::make_temp_output_path(out);
    EXPECT_NE(n0, n1) << "两次生成共用同一 tmp 名";
    for (const fs::path& n : {n0, n1}) {
        EXPECT_EQ(n.parent_path(), out.parent_path()) << "tmp 必须与目标同目录";
        EXPECT_NE(n.filename().string().rfind(stem, 0), std::string::npos)
            << "tmp 名应仍可归到该目标: " << n.filename();
        EXPECT_NE(n.filename().string().find(kTmpMark), std::string::npos)
            << "tmp 名缺少带分隔符的唯一后缀: " << n.filename();
    }

    for (int i = 0; i < 2; ++i) {
        ProtectionContext ctx;
        ctx.image = build_minimal_pe(true, kMachineX64);
        ctx.image.back() = static_cast<u8>(0x5A + i);
        ctx.output_path = out;
        wvmp::passes::PeWriterPass writer;
        EXPECT_THROW(writer.run(ctx), std::runtime_error);
    }

    // 旧产物仍在，两枚 tmp 各留一份（落盘实测）
    EXPECT_EQ(read_file(out), old_bytes);
    const auto left = tmp_leftovers(dir, out);
    ASSERT_EQ(left.size(), static_cast<size_t>(2)) << "每次失败各留一枚 tmp";
    EXPECT_NE(left[0], left[1]) << "两次写入落盘的 tmp 同名";
    for (const auto& p : left) {
        EXPECT_NE(p.filename().string().find(kTmpMark), std::string::npos) << p;
        EXPECT_EQ(p.parent_path(), dir);
    }

    set_read_only(out, false);
    std::error_code ec;
    fs::remove_all(dir, ec);
}

TEST(PeWriterPublish, NormalOverwriteReplacesTargetAndLeavesNoTmp) {
    const fs::path dir = cr09_dir("ok");
    const fs::path out = dir / "plain.exe";
    const std::vector<u8> old_bytes = seed_previous_product(out);

    ProtectionContext ctx;
    ctx.image = build_minimal_pe(true, kMachineX64);
    ctx.image.back() = 0x77;
    ctx.output_path = out;
    wvmp::passes::PeWriterPass writer;
    ASSERT_NO_THROW(writer.run(ctx));

    EXPECT_EQ(read_file(out), ctx.image) << "正常路径应完成替换";
    EXPECT_NE(read_file(out), old_bytes) << "新产物没写进去";
    EXPECT_TRUE(tmp_leftovers(dir, out).empty()) << "成功路径不得残留 tmp";
    EXPECT_FALSE(ctx.diag.has_errors());

    std::error_code ec;
    fs::remove_all(dir, ec);
}

// ---------------------------------------------------------------------------
// MIT-530：写后读回校验（verify_written_image）。核长挡半写，读回挡"等长错
// 字节"。run() 级的正例由上面 NormalOverwrite* 覆盖（读回是它的必经步骤）；
// 此处直接钉校验器自身的正反例——等长单字节翻转必须被抓到并点名偏移。
// ---------------------------------------------------------------------------
TEST(PeWriterPublish, ReadbackAcceptsExactImage) {
    const fs::path dir = cr09_dir("rb_ok");
    const fs::path f = dir / "exact.bin";
    std::vector<u8> img(300 * 1024 + 7); // 跨多个 64KiB 读回块
    for (size_t i = 0; i < img.size(); ++i) img[i] = static_cast<u8>(i * 31u + 7u);
    {
        std::ofstream o(f, std::ios::binary | std::ios::trunc);
        o.write(reinterpret_cast<const char*>(img.data()),
                static_cast<std::streamsize>(img.size()));
    }
    std::string err = "untouched";
    EXPECT_TRUE(wvmp::passes::verify_written_image(f, img.data(), img.size(), err));
    EXPECT_EQ(err, "untouched") << "成功路径不得改写 err";

    std::error_code ec;
    fs::remove_all(dir, ec);
}

TEST(PeWriterPublish, ReadbackCatchesEqualLengthCorruption) {
    const fs::path dir = cr09_dir("rb_flip");
    const fs::path f = dir / "flip.bin";
    std::vector<u8> img(200 * 1024);
    for (size_t i = 0; i < img.size(); ++i) img[i] = static_cast<u8>(i);
    std::vector<u8> disk = img;
    const size_t kFlip = 150 * 1024 + 3; // 落在第 3 个读回块内
    disk[kFlip] ^= 0xFF;

    {
        std::ofstream o(f, std::ios::binary | std::ios::trunc);
        o.write(reinterpret_cast<const char*>(disk.data()),
                static_cast<std::streamsize>(disk.size()));
    }
    std::string err;
    EXPECT_FALSE(wvmp::passes::verify_written_image(f, img.data(), img.size(), err));
    EXPECT_NE(err.find("首处差异"), std::string::npos) << err;
    // 点名偏移：0x%zx 形式（十进制 153603 = 0x25803）
    EXPECT_NE(err.find("25803"), std::string::npos) << err;
    EXPECT_NE(err.find("!= image"), std::string::npos) << err;

    std::error_code ec;
    fs::remove_all(dir, ec);
}

TEST(PeWriterPublish, ReadbackCatchesTruncatedAndOverlong) {
    const fs::path dir = cr09_dir("rb_len");
    const std::vector<u8> img(4096, 0xAB);

    // 短读：磁盘文件比镜像少（核长应先红，读回兜底同样不得放过）
    const fs::path short_f = dir / "short.bin";
    {
        std::ofstream o(short_f, std::ios::binary | std::ios::trunc);
        o.write(reinterpret_cast<const char*>(img.data()),
                static_cast<std::streamsize>(img.size() - 1));
    }
    std::string err;
    EXPECT_FALSE(wvmp::passes::verify_written_image(short_f, img.data(), img.size(), err));
    EXPECT_NE(err.find("短读"), std::string::npos) << err;

    // 超长：磁盘文件比镜像多一个字节
    const fs::path long_f = dir / "long.bin";
    {
        std::ofstream o(long_f, std::ios::binary | std::ios::trunc);
        o.write(reinterpret_cast<const char*>(img.data()),
                static_cast<std::streamsize>(img.size()));
        const u8 extra = 0x01;
        o.write(reinterpret_cast<const char*>(&extra), 1);
    }
    err.clear();
    EXPECT_FALSE(wvmp::passes::verify_written_image(long_f, img.data(), img.size(), err));
    EXPECT_NE(err.find("多出字节"), std::string::npos) << err;

    std::error_code ec;
    fs::remove_all(dir, ec);
}
