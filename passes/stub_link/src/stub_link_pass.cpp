#include "wvmp/passes/stub_link/stub_link_pass.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/diagnostics.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/registry.hpp"
#include "wvmp/regvm/runtime/runtime.hpp"
#include "wvmp/vm/backend.hpp"

#include <string>

namespace wvmp::passes {

std::span<const std::string_view> StubLinkPass::requires_keys() const {
    static constexpr std::string_view kRequires[] = {kVmProgram};
    return kRequires;
}

std::span<const std::string_view> StubLinkPass::provides_keys() const {
    static constexpr std::string_view kProvides[] = {kVmRuntime};
    return kProvides;
}

// v1（Phase::Emit，不写 PE）：
//   1) kVmProgram 缺失 → Warning 后直接返回（M1 空管道不失败）；
//   2) 有 program → generate_runtime（随机化消耗 ctx.rng）+ 装配载荷。
//
// 载荷布局（slot kVmRuntime = vm::RuntimeImage）：
//
//   [VmBlob（32B 头 + 8xN 流）| 0 垫片至 16 对齐 | 解释器机器码]
//   ^payload.code[0]                              ^vm_entry_offset
//
//   - entry 偏移 = 对齐后 blob 大小 + rt.vm_entry_offset(=0)。M2 注入时：
//     入口 RVA = 新节基址(RVA) + vm_entry_offset；被保护函数原入口改写为
//     跳转入口的 stub（E9 rel32 / FF 25 jmp [rip+disp]），gate 失败回退原指令；
//   - stub 运行时职责（M2）：在节内构造 VmContext——
//       bytecode  = blob 基址 + 32（跳过 blob 头，指向指令流）
//       pc        = blob 头 entry_offset / 8（入口指令序号）
//       regs[v4]  = 真实 Rsp（或 carve 出的影子栈顶）
//       scratch_mem = Load/Store/Push/Pop 的内存基址（v1 为测试 scratch，
//     M2 换被保护进程的真实可写页基址）；
//   - 解密 codec（M3）织入点见 runtime/asmgen.cpp 头注（dispatch fetch 后）。
void StubLinkPass::run(ProtectionContext& ctx) {
    const auto* prog = ctx.find_slot<vm::VmProgram>(kVmProgram);
    if (prog == nullptr || prog->bytecode.empty()) {
        ctx.diag.report(Severity::Warning, name(), "no vm program, skip");
        return;
    }

    // 解释器机器码（寄存器分配随机化走 ctx.rng）。
    const regvm::runtime::RuntimeGenResult rt = regvm::runtime::generate_runtime(ctx.rng);

    // [blob | runtime] 装配。
    vm::RuntimeImage payload;
    const size_t blob_aligned = (prog->bytecode.size() + 15) & ~size_t(15);
    payload.code = prog->bytecode;
    payload.code.resize(blob_aligned, 0);
    payload.code.insert(payload.code.end(), rt.image.code.begin(), rt.image.code.end());
    payload.vm_entry_offset = blob_aligned + rt.image.vm_entry_offset;

    ctx.slot<vm::RuntimeImage>(kVmRuntime) = std::move(payload);
    ctx.diag.report(Severity::Note, name(),
                    "vm runtime payload: " + std::to_string(blob_aligned) +
                        "+runtime=" + std::to_string(rt.image.code.size()) +
                        " bytes, entry at +" + std::to_string(payload.vm_entry_offset));
}

WVMP_REGISTER_PASS(StubLinkPass)

} // namespace wvmp::passes
