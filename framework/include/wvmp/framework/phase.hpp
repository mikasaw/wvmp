#pragma once
#include <string_view>
namespace wvmp {
enum class Phase { Load, Analyze, Transform, Emit, Write };
constexpr std::string_view to_string(Phase p) noexcept {
    switch (p) { case Phase::Load: return "Load"; case Phase::Analyze: return "Analyze";
        case Phase::Transform: return "Transform"; case Phase::Emit: return "Emit"; case Phase::Write: return "Write"; }
    return "?";
}
}
