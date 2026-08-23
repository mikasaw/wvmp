#include "wvmp/regvm/backend/regvm_backend.hpp"

#include "wvmp/regvm/runtime/runtime.hpp"
#include "wvmp/regvm/translator/translator.hpp"
#include "wvmp/vm/backend_registry.hpp"

#include <memory>
#include <string>
#include <vector>

namespace wvmp::regvm {
namespace {

class RegVmBackend final : public vm::VMBackend {
public:
    std::string_view name() const override { return "regvm"; }

    void set_codec(vm::BytecodeCodec* codec) override {
        // v1：codec 织入点已预留（dispatch fetch 后），尚未接线；记录并在
        // M3 的 xor_chain codec 任务中启用。先行持有以防调用方意外丢失。
        codec_ = codec;
    }

    vm::VmProgram compile(const ir::FunctionRegion& fn, ProtectionContext& ctx) override {
        // 翻译是纯函数；诊断级 notes 经扩展槽传回调用方（virtualize pass）
        // 转 diag 并做 C1 保守拦截（key 见 regvm_backend.hpp）。契约签名
        // 冻结，无法改返回值——槽是框架预留的跨 pass 通道。
        translator::TranslateResult result = translator::translate_function(fn);
        ctx.slot<std::vector<std::string>>(kLastTranslateNotes) = std::move(result.notes);
        return std::move(result.program);
    }

    vm::RuntimeImage generate_runtime(const vm::VmProgram& /*prog*/,
                                      ProtectionContext& ctx) override {
        // 解释器机器码与具体程序无关（按 ctx.rng 随机化寄存器分配）。
        return runtime::generate_runtime(ctx.rng).image;
    }

private:
    vm::BytecodeCodec* codec_ = nullptr;
};

[[maybe_unused]] const bool kRegistered = [] {
    vm::register_backend_factory("regvm", &make_regvm);
    return true;
}();

} // namespace

std::unique_ptr<vm::VMBackend> make_regvm() {
    return std::make_unique<RegVmBackend>();
}

} // namespace wvmp::regvm
