#pragma once
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/pass.hpp"

#include <span>

namespace wvmp::passes {

// MIT-464 (integrity_crc-v1)：密文流 CRC32 完整性校验（crypt 之后；解密前
// FailFast 校验，封死 xor 可延展盲翻面——MIT-458 预留位的兑现面）。
// requires kCryptPlan = 管道装配期强制 crypt 先行（缺席即装配错误，防
// "有完整性 pass 无加密对象"的静默空转——MIT-464 验收披露①修正）。
class IntegrityCrcPass final : public Pass {
public:
    std::string_view name() const override { return "integrity_crc"; }
    Phase phase() const override { return Phase::Transform; }
    std::span<const std::string_view> requires_keys() const override {
        static constexpr std::string_view kRequires[] = {wvmp::kCryptPlan};
        return kRequires;
    }
    void run(ProtectionContext& ctx) override;
};

} // namespace wvmp::passes
