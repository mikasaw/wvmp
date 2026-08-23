// stub_link 泳道测试：
//  1) kVmProgram 缺失 → Warning 且不产出 kVmRuntime（M1 空管道不失败）；
//  2) 伪 program（手搭 blob）→ 产出非空 [blob | runtime] 载荷：blob magic
//     "WVMP" 在首、entry 偏移 16 对齐、含 Note 诊断；
//  3) 端到端：载荷内 runtime 部分拷入 RWX 执行伪 program，验证 ret_value。

#include "wvmp/common/bytes.hpp"
#include "wvmp/common/rng.hpp"
#include "wvmp/framework/context.hpp"
#include "wvmp/framework/diagnostics.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/registry.hpp"
#include "wvmp/ir/arch.hpp"
#include "wvmp/passes/stub_link/stub_link_pass.hpp"
#include "wvmp/regvm/isa/blob.hpp"
#include "wvmp/regvm/isa/encoding.hpp"
#include "wvmp/regvm/runtime/runtime.hpp"
#include "wvmp/vm/backend.hpp"

#include <gtest/gtest.h>

#include <windows.h>

#include <array>
#include <cstring>
#include <vector>

namespace {

namespace isa = wvmp::regvm::isa;
namespace ir = wvmp::ir;
using wvmp::u8;
using wvmp::u32;
using wvmp::u64;

std::vector<u8> make_tiny_blob(u32 imm) {
    // mov r0, imm ; halt
    std::vector<u8> stream;
    isa::append_insn(stream, isa::make_insn(isa::VmOp::Mov, isa::OpKind::Reg, 0,
                                            isa::OpKind::Imm, 0, imm));
    isa::append_insn(stream, isa::make_insn(isa::VmOp::Halt, isa::OpKind::None, 0,
                                            isa::OpKind::None, 0));
    const auto blob = isa::make_blob(ir::Arch::X64, 0, stream);
    std::vector<u8> out;
    wvmp::ByteWriter w(out);
    isa::write_blob(w, blob);
    return out;
}

u32 rd32(const u8* p) {
    return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) |
           (static_cast<u32>(p[2]) << 16) | (static_cast<u32>(p[3]) << 24);
}

} // namespace

TEST(StubLink, MissingProgramWarnsAndSkips) {
    wvmp::ProtectionContext ctx;
    ctx.rng.reseed(1);
    wvmp::passes::StubLinkPass pass;
    pass.run(ctx);

    EXPECT_FALSE(ctx.diag.has_errors());
    ASSERT_EQ(ctx.diag.items().size(), 1u);
    EXPECT_EQ(ctx.diag.items()[0].severity, wvmp::Severity::Warning);
    EXPECT_NE(ctx.diag.items()[0].message.find("no vm program"), std::string::npos);
    EXPECT_FALSE(ctx.has_slot(wvmp::kVmRuntime));
}

TEST(StubLink, EmitsExecutableRuntimePayload) {
    const std::vector<u8> blob = make_tiny_blob(42);

    wvmp::ProtectionContext ctx;
    ctx.rng.reseed(7);
    ctx.slot<wvmp::vm::VmProgram>(wvmp::kVmProgram) = wvmp::vm::VmProgram{blob, 0};
    wvmp::passes::StubLinkPass pass;
    pass.run(ctx);

    EXPECT_FALSE(ctx.diag.has_errors());
    const auto* payload = ctx.find_slot<wvmp::vm::RuntimeImage>(wvmp::kVmRuntime);
    ASSERT_NE(payload, nullptr);
    ASSERT_GT(payload->code.size(), blob.size());
    // 载荷首部 = blob（magic "WVMP"）。
    EXPECT_EQ(payload->code[0], 'W');
    EXPECT_EQ(payload->code[1], 'V');
    EXPECT_EQ(payload->code[2], 'M');
    EXPECT_EQ(payload->code[3], 'P');
    // entry 偏移 = 16 对齐的 blob 大小；其后是解释器机器码（非零）。
    EXPECT_EQ(payload->vm_entry_offset % 16, 0u);
    EXPECT_EQ(payload->vm_entry_offset, ((blob.size() + 15) & ~size_t(15)));
    bool runtime_nonzero = false;
    for (size_t i = payload->vm_entry_offset; i < payload->code.size(); ++i)
        if (payload->code[i] != 0) runtime_nonzero = true;
    EXPECT_TRUE(runtime_nonzero);
    // 产出记录（Note）。
    bool has_note = false;
    for (const auto& d : ctx.diag.items())
        if (d.severity == wvmp::Severity::Note) has_note = true;
    EXPECT_TRUE(has_note);

    // —— 端到端：runtime 拷入 RWX，执行 blob 内程序 ——
    const size_t runtime_size = payload->code.size() - payload->vm_entry_offset;
    void* mem = VirtualAlloc(nullptr, runtime_size, MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);
    ASSERT_NE(mem, nullptr);
    std::memcpy(mem, payload->code.data() + payload->vm_entry_offset, runtime_size);

    alignas(16) std::array<u8, 0x1000> scratch{};
    wvmp::regvm::runtime::VmContext vmctx;
    vmctx.bytecode = const_cast<u8*>(payload->code.data()) + 32;   // 跳过 blob 头
    vmctx.pc = rd32(payload->code.data() + 8) / 8;                 // 头 entry_offset（字节→条数）
    vmctx.scratch_mem = reinterpret_cast<u64>(scratch.data());
    reinterpret_cast<void (*)(wvmp::regvm::runtime::VmContext*)>(mem)(&vmctx);

    EXPECT_EQ(vmctx.regs[0], 42u);
    EXPECT_EQ(vmctx.ret_value, 42u);
    EXPECT_EQ(vmctx.pc, 2u);
    VirtualFree(mem, 0, MEM_RELEASE);
}

TEST(StubLink, RegisteredInRegistry) {
    EXPECT_NE(wvmp::PassRegistry::instance().find("stub_link"), nullptr);
}
