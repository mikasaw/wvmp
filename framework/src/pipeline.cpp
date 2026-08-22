#include "wvmp/framework/pipeline.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/registry.hpp"

#include <algorithm>
#include <stdexcept>

namespace wvmp {
namespace {

constexpr int phase_rank(Phase p) {
    switch (p) {
        case Phase::Load: return 0;
        case Phase::Analyze: return 1;
        case Phase::Transform: return 2;
        case Phase::Emit: return 3;
        case Phase::Write: return 4;
    }
    return 5;
}

// 核心字段对应的 key：无需任何 pass 提供即视为可用。
constexpr bool is_core_key(std::string_view key) {
    return key == kImage || key == kFunctions;
}

} // namespace

Pipeline Pipeline::from_names(const std::vector<std::string>& pass_names) {
    Pipeline pipe;
    for (const auto& n : pass_names) {
        Pass* p = PassRegistry::instance().find(n);
        if (p == nullptr)
            throw std::runtime_error("pipeline: unknown pass '" + n + "'");
        pipe.stages_.push_back(p);
    }
    // 稳定排序：Phase 序 Load<Analyze<Transform<Emit<Write；同 Phase 内保持配置给定顺序。
    std::stable_sort(pipe.stages_.begin(), pipe.stages_.end(),
                     [](const Pass* a, const Pass* b) {
                         return phase_rank(a->phase()) < phase_rank(b->phase());
                     });
    pipe.validate();
    return pipe;
}

void Pipeline::validate() const {
    std::vector<std::string_view> available = {kImage, kFunctions};
    for (const Pass* p : stages_) {
        for (std::string_view key : p->requires_keys()) {
            if (is_core_key(key)) continue;
            bool ok = false;
            for (std::string_view have : available)
                if (have == key) { ok = true; break; }
            if (!ok)
                throw std::runtime_error(
                    std::string("pipeline: pass '") + std::string(p->name()) +
                    "' requires key '" + std::string(key) +
                    "' which neither a core field nor an earlier pass provides "
                    "(missing provider pass in the pipeline?)");
        }
        for (std::string_view key : p->provides_keys())
            available.push_back(key);
    }
}

void Pipeline::run(ProtectionContext& ctx) const {
    for (Pass* p : stages_) {
        try {
            p->run(ctx);
        } catch (const std::exception& e) {
            // 失败也要在诊断里留下是哪个 pass 抛的，再让异常继续向上传播。
            ctx.diag.report(Severity::Error, p->name(), e.what());
            throw;
        }
    }
}

const std::vector<Pass*>& Pipeline::stages() const {
    return stages_;
}

} // namespace wvmp
