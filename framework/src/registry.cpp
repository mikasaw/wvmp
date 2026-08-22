#include "wvmp/framework/registry.hpp"

#include <stdexcept>

namespace wvmp {

PassRegistry& PassRegistry::instance() {
    static PassRegistry inst;
    return inst;
}

void PassRegistry::register_pass(std::unique_ptr<Pass> p) {
    if (p == nullptr)
        throw std::runtime_error("register_pass: null pass");
    const std::string_view n = p->name();
    if (find(n) != nullptr)
        throw std::runtime_error("register_pass: duplicate pass name '" + std::string(n) + "'");
    passes_.push_back(std::move(p));
}

Pass* PassRegistry::find(std::string_view name) const {
    for (const auto& p : passes_)
        if (p->name() == name) return p.get();
    return nullptr;
}

std::vector<std::string_view> PassRegistry::names() const {
    std::vector<std::string_view> out;
    out.reserve(passes_.size());
    for (const auto& p : passes_) out.push_back(p->name());
    return out;
}

void PassRegistry::clear() {
    passes_.clear();
}

PassRegistrar::PassRegistrar(std::unique_ptr<Pass> p) {
    PassRegistry::instance().register_pass(std::move(p));
}

} // namespace wvmp
