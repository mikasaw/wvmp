#include "wvmp/passes/lifter/lifter_pass.hpp"

#include "capstone_session.hpp"
#include "lifter_core.hpp"
#include "pe_map.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/registry.hpp"
#include "wvmp/passes/lifter/lift_metadata.hpp"

#include <cstdio>
#include <set>
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
        // MIT-497 (T50, X5b 挂账落地)：出口 esp-resync 前瞻。对区域全部
        // 区外出口目标（越区 Jmp/Jcc Imm + 末端 fallthrough end_rva）做
        // 延续扫窗（exit_resync_verified），绝对恢复可达 → 记入
        // fr.resync_ok_exits，供 translator 栈深 walk 规则 5 对 d≠0 出口
        // 放行。ExitNative 出口 esp=ns 冻结协议零触碰（放行安全性来自
        // 延续代码自身的绝对恢复，论证见 lifter_core.hpp）。
        // x64 跳过：walk budget=0 下任何 push/sub rsp 即 gate，d≠0 出口
        // 不可达，前瞻为死代码面。
        if (fr.arch == ir::Arch::X86) {
            std::set<u64> exits;
            for (const ir::BasicBlock& b : fr.blocks)
                for (const ir::Insn& in : b.insns)
                    if ((in.op == ir::Op::Jmp || in.op == ir::Op::Jcc) &&
                        in.dst.kind == ir::Operand::Kind::Imm) {
                        const u64 t = static_cast<u64>(in.dst.imm);
                        if (t < fr.begin_rva || t >= fr.end_rva) exits.insert(t);
                    }
            exits.insert(fr.end_rva);
            for (const u64 t : exits) {
                if (lifter::exit_resync_verified(session, std::span<const u8>(ctx.image),
                                                 pe, t)) {
                    fr.resync_ok_exits.push_back(t);
                }
            }
            if (!fr.resync_ok_exits.empty()) {
                std::string rvas;
                char buf[24];
                for (const u64 t : fr.resync_ok_exits) {
                    std::snprintf(buf, sizeof(buf), " 0x%llX",
                                  static_cast<unsigned long long>(t));
                    rvas += buf;
                }
                ctx.diag.report(Severity::Note, name(),
                                "函数 '" + fr.name + "': 出口 esp-resync 前瞻通过 (" +
                                    std::to_string(fr.resync_ok_exits.size()) + " 出口:" +
                                    rvas + ")——d≠0 出口在栈深 walk 中放行");
            }
            // MIT-500 (T54)：callgate 清理约定扫描。对越区直接 call 的目标
            // （Imm 形）做终态 ret imm 判定（callee_ret_imm），stdcall 形
            // （imm>0）记入 fr.callgate_cleanup —— translator 两处消费：
            // 栈深 walk 记 d -= imm（native esp 语义精确化）+ CallGate 词后
            // 合成 `Add Rsp, imm`（guest rsp 槽真实推进，守卫用量与模型恒
            // 对齐）。imm==0（cdecl）/扫描失败不入表 = 维持保守模型。
            {
                std::set<u64> targets;
                for (const ir::BasicBlock& b : fr.blocks)
                    for (const ir::Insn& in : b.insns)
                        if (in.op == ir::Op::Call &&
                            in.dst.kind == ir::Operand::Kind::Imm) {
                            const u64 t = static_cast<u64>(in.dst.imm);
                            if (t < fr.begin_rva || t >= fr.end_rva) targets.insert(t);
                        }
                for (const u64 t : targets) {
                    const auto imm = lifter::callee_ret_imm(
                        session, std::span<const u8>(ctx.image), pe, t);
                    if (imm.has_value() && *imm > 0)
                        fr.callgate_cleanup.emplace_back(t, *imm);
                }
                if (!fr.callgate_cleanup.empty()) {
                    std::string rvas;
                    char buf[32];
                    for (const auto& [t, n] : fr.callgate_cleanup) {
                        std::snprintf(buf, sizeof(buf), " 0x%llX+%u",
                                      static_cast<unsigned long long>(t),
                                      static_cast<unsigned>(n));
                        rvas += buf;
                    }
                    ctx.diag.report(Severity::Note, name(),
                                    "函数 '" + fr.name + "': callgate 清理约定扫描 " +
                                        std::to_string(fr.callgate_cleanup.size()) +
                                        " 项(stdcall):" + rvas);
                }
            }
        }
        metadata.push_back(std::move(meta));
        ++lifted;
    }

    ctx.slot<size_t>(kLiftedIr) = lifted;
}

WVMP_REGISTER_PASS(LifterPass)

} // namespace wvmp::passes
