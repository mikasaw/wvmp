#pragma once
#include "wvmp/framework/phase.hpp"
#include <span>
#include <string_view>
namespace wvmp {
class ProtectionContext;
class Pass {
public:
    virtual ~Pass() = default;
    virtual std::string_view name() const = 0;
    virtual Phase phase() const = 0;
    virtual std::span<const std::string_view> requires_keys() const { return {}; }
    virtual std::span<const std::string_view> provides_keys() const { return {}; }
    virtual void run(ProtectionContext& ctx) = 0;
};
}
