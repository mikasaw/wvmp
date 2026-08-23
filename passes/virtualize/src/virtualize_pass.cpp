#include "wvmp/passes/virtualize/virtualize_pass.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/registry.hpp"
#include "wvmp/regvm/backend/regvm_backend.hpp"
#include "wvmp/vm/backend.hpp"

#include <stdexcept>
#include <string>
#include <vector>

namespace wvmp::passes {
namespace {

// 引用 regvm 的具名工厂符号，确保其翻译单元（含静态注册）进入链接——
// 否则 MSVC 会丢弃归档中无引用的自注册对象，create_backend 查不到后端。
const auto kRegVmAnchor = &regvm::make_regvm;

} // namespace

std::span<const std::string_view> VirtualizePass::requires_keys() const {
    static constexpr std::string_view kRequires[] = {kLiftedIr};
    return kRequires;
}

std::span<const std::string_view> VirtualizePass::provides_keys() const {
    static constexpr std::string_view kProvides[] = {kVmProgram};
    return kProvides;
}

void VirtualizePass::run(ProtectionContext& ctx) {
    std::unique_ptr<vm::VMBackend> backend = vm::create_backend("regvm");
    if (backend == nullptr) {
        ctx.diag.report(Severity::Error, name(), "regvm 后端未注册（链接配置错误？）");
        throw std::runtime_error(std::string(name()) + ": regvm backend not registered");
    }

    auto& programs = ctx.slot<std::vector<vm::VmProgram>>(kVmProgram);
    programs.clear();

    for (const auto& fn : ctx.functions) {
        if (fn.blocks.empty()) {
            ctx.diag.report(Severity::Note, name(),
                            "函数 " + fn.name + " 无已 lift 的基本块，跳过虚拟化");
            continue;
        }
        try {
            vm::VmProgram program = backend->compile(fn, ctx);
            programs.push_back(std::move(program));
        } catch (const std::exception& e) {
            // 单函数失败不拖垮整条管道：记 Error 并跳过该函数（其区域保持原生）。
            ctx.diag.report(Severity::Error, name(),
                            "函数 " + fn.name + " 虚拟化失败（保持原生）: " + e.what());
        }
    }

    if (programs.empty())
        ctx.diag.report(Severity::Warning, name(), "没有任何函数被虚拟化");
}

WVMP_REGISTER_PASS(VirtualizePass)

} // namespace wvmp::passes
