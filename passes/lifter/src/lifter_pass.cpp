#include "wvmp/passes/lifter/lifter_pass.hpp"

#include "capstone_session.hpp"
#include "lifter_core.hpp"
#include "pe_map.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/registry.hpp"

#include <string>

namespace wvmp::passes {

std::span<const std::string_view> LifterPass::requires_keys() const {
    static constexpr std::string_view kRequires[] = {kImage, kFunctions};
    return kRequires;
}

std::span<const std::string_view> LifterPass::provides_keys() const {
    static constexpr std::string_view kProvides[] = {kLiftedIr};
    return kProvides;
}

void LifterPass::run(ProtectionContext& ctx) {
    // kLiftedIr 槽类型契约：size_t = 成功 lift 的函数个数
    //（lifted IR 本体直接写入核心字段 ctx.functions[i].blocks）。
    size_t lifted = 0;

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
        if (fr.begin_rva >= fr.end_rva) {
            ctx.diag.report(Severity::Note, name(),
                            "函数 '" + fr.name + "': RVA 区间为空/非法，跳过");
            continue;
        }
        const auto range = pe.map_rva_range(fr.begin_rva, fr.end_rva);
        if (!range) {
            ctx.diag.report(Severity::Note, name(),
                            "函数 '" + fr.name + "': RVA 区间 [0x" +
                                std::to_string(fr.begin_rva) + ", 0x" +
                                std::to_string(fr.end_rva) +
                                ") 无法映射到文件偏移（跨节或越界），跳过");
            continue;
        }
        const auto [offset, len] = *range;
        lifter::CapstoneSession& session = (fr.arch == ir::Arch::X86) ? session_x86 : session_x64;
        lifter::disassemble_and_lift(session, ctx.image.data() + offset, len, fr.begin_rva,
                                     fr.end_rva, fr.name, name(), ctx.diag, fr);
        ++lifted;
    }

    ctx.slot<size_t>(kLiftedIr) = lifted;
}

WVMP_REGISTER_PASS(LifterPass)

} // namespace wvmp::passes
