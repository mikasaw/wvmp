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

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <system_error>
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
