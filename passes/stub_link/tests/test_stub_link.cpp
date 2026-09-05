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
#include "wvmp/passes/pe_loader/pe_image.hpp"
#include "wvmp/passes/stub_link/stub_link_pass.hpp"
#include "wvmp/passes/virtualize/virtualize_pass.hpp"
#include "wvmp/regvm/isa/blob.hpp"
#include "wvmp/regvm/isa/encoding.hpp"
#include "wvmp/vm/backend.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
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

TEST(StubLinkPass, UnmappableRegionKeepsNative) {
    ProtectionContext ctx = make_ctx_with_one_function();
    auto& vfs = ctx.slot<std::vector<VirtualizedFunction>>(wvmp::kVmProgram);
    vfs.front().begin_rva = 0xFF000;  // 超出节范围
    wvmp::passes::StubLinkPass pass;
    pass.run(ctx);
    EXPECT_TRUE(ctx.diag.has_errors());
    EXPECT_EQ(ctx.image[0x300], 0x90);  // .text 未动
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
    // 序言后应有 sub rsp, 0x1C8（48 81 EC C8 01 00 00）—— MIT-371 xmm 跟踪区扩 8 个
    // XmmSlot (各 16B) 后 VmContext 从 0x138 扩到 0x1C0，kCtxSize = 0x1C8。
    bool found_sub = false;
    for (size_t i = 0; i + 7 <= stub.size(); ++i) {
        if (stub[i] == 0x48 && stub[i + 1] == 0x81 && stub[i + 2] == 0xEC &&
            stub[i + 3] == 0xC8 && stub[i + 4] == 0x01) {
            found_sub = true;
            break;
        }
    }
    EXPECT_TRUE(found_sub);
}

} // namespace
