#include "wvmp/passes/lifter/lifter_pass.hpp"

#include "capstone_session.hpp"
#include "lifter_core.hpp"
#include "pe_map.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/registry.hpp"
#include "wvmp/passes/lifter/lift_metadata.hpp"

#include <span>
#include <string>

namespace wvmp::passes {

std::span<const std::string_view> LifterPass::requires_keys() const {
    static constexpr std::string_view kRequires[] = {kImage, kFunctions};
    return kRequires;
}

std::span<const std::string_view> LifterPass::provides_keys() const {
    // MIT-249 follow-up (issue-09): 顺带给下游提供 kLiftedMetadata, 供
    // translator / virtualize 识别 lifter 跳过的字节范围并触发 C1 gate。
    static constexpr std::string_view kProvides[] = {kLiftedIr, lifter::kLiftedMetadata};
    return kProvides;
}

void LifterPass::run(ProtectionContext& ctx) {
    // kLiftedIr 槽类型契约：size_t = 成功 lift 的函数个数
    //（lifted IR 本体直接写入核心字段 ctx.functions[i].blocks）。
    size_t lifted = 0;

    // kLiftedMetadata 槽类型契约：std::vector<LiftMetadata>, 与 ctx.functions
    // 下标平行。每个 LiftMetadata 含该函数被 lifter 跳过的指令字节范围。
    auto& metadata = ctx.slot<std::vector<lifter::LiftMetadata>>(lifter::kLiftedMetadata);
    metadata.clear();
    metadata.reserve(ctx.functions.size());

    if (ctx.functions.empty()) {
        ctx.slot<size_t>(kLiftedIr) = lifted;
        return;
    }

    // TODO(M1-integration): use PeImage from pe_loader —— 此处使用 lifter
    // 私有的最小 PE 解析，M1 集成时替换为 pe_loader 的公共结构。
    const lifter::PeSectionMap pe = lifter::PeSectionMap::parse(ctx.image);
    if (!pe.valid) {
        ctx.diag.report(Severity::Error, name(), "image 不是合法 PE，lifter 未运行");
        ctx.slot<size_t>(kLiftedIr) = lifted;
        return;
    }

    lifter::CapstoneSession session_x64(ir::Arch::X64);
    lifter::CapstoneSession session_x86(ir::Arch::X86);

    for (ir::FunctionRegion& fr : ctx.functions) {
        // 每个函数的 LiftMetadata 槽位（与 functions[i] 下标对齐）。
        lifter::LiftMetadata meta;
        if (fr.begin_rva >= fr.end_rva) {
            ctx.diag.report(Severity::Note, name(),
                            "函数 '" + fr.name + "': RVA 区间为空/非法，跳过");
            metadata.push_back(std::move(meta));
            continue;
        }
        const auto range = pe.map_rva_range(fr.begin_rva, fr.end_rva);
        if (!range) {
            ctx.diag.report(Severity::Note, name(),
                            "函数 '" + fr.name + "': RVA 区间 [0x" +
                                std::to_string(fr.begin_rva) + ", 0x" +
                                std::to_string(fr.end_rva) +
                                ") 无法映射到文件偏移（跨节或越界），跳过");
            metadata.push_back(std::move(meta));
            continue;
        }
        const auto [offset, len] = *range;
        lifter::CapstoneSession& session = (fr.arch == ir::Arch::X86) ? session_x86 : session_x64;
        // MIT-407: 越区跳转目标回跳检出回调（ExitNative 上界判定的一环）——
        // 捕获当前函数区域端点 + image 原始字节 + 本会话，从越区目标起走
        // ≤3 层静态可达集，落回本区即判危险。结果经 LiftMetadata 传下游。
        const lifter::ExitNativeGuardFn exit_guard =
            [&session, image = std::span<const u8>(ctx.image), &pe, &fr](u64 target) {
                return lifter::back_jump_reaches_region(session, image, pe, target,
                                                        fr.begin_rva, fr.end_rva);
            };
        lifter::disassemble_and_lift(session, ctx.image.data() + offset, len, fr.begin_rva,
                                     fr.end_rva, fr.name, name(), ctx.diag, fr, meta,
                                     exit_guard);
        metadata.push_back(std::move(meta));
        ++lifted;
    }

    ctx.slot<size_t>(kLiftedIr) = lifted;
}

WVMP_REGISTER_PASS(LifterPass)

} // namespace wvmp::passes
