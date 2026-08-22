#pragma once
#include "wvmp/framework/pass.hpp"

namespace wvmp::passes {

// Computes/records integrity CRC digests over protected regions so the
// runtime can detect tampering. P0: interface placeholder.
class IntegrityCrcPass final : public Pass {
public:
    std::string_view name() const override { return "integrity_crc"; }
    Phase phase() const override { return Phase::Transform; }
    void run(ProtectionContext& ctx) override;
};

} // namespace wvmp::passes
