#pragma once
#include "wvmp/framework/pass.hpp"
#include <span>

#include "wvmp/framework/keys.hpp"

namespace wvmp::passes {

// Encrypts the VM bytecode stream (and other protected payloads) using a
// BytecodeCodec selected for the active backend.
// P0: interface placeholder; crypt lane implements it.
class CryptPass final : public Pass {
public:
    std::string_view name() const override { return "crypt"; }
    Phase phase() const override { return Phase::Transform; }
    std::span<const std::string_view> provides_keys() const override {
        // MIT-464: kCryptPlan 显式 provide —— integrity_crc 的 requires_keys
        // 依赖此声明做管道装配检查。
        static constexpr std::string_view kProvides[] = {wvmp::kCryptPlan};
        return kProvides;
    }
    void run(ProtectionContext& ctx) override;
};

} // namespace wvmp::passes
