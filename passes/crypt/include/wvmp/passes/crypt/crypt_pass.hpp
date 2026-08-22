#pragma once
#include "wvmp/framework/pass.hpp"

namespace wvmp::passes {

// Encrypts the VM bytecode stream (and other protected payloads) using a
// BytecodeCodec selected for the active backend.
// P0: interface placeholder; crypt lane implements it.
class CryptPass final : public Pass {
public:
    std::string_view name() const override { return "crypt"; }
    Phase phase() const override { return Phase::Transform; }
    void run(ProtectionContext& ctx) override;
};

} // namespace wvmp::passes
