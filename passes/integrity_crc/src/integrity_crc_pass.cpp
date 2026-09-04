#include "wvmp/passes/integrity_crc/integrity_crc_pass.hpp"

#include "wvmp/passes/crypt/crypt_plan.hpp"
#include "wvmp/common/crc32.hpp"
#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/registry.hpp"

#include <stdexcept>

namespace wvmp::passes {

// MIT-464 (integrity_crc-v1)：密文完整性校验。
//
// Transform 阶段、crypt 之后：对 kCryptPlan 中每个密文流（blob 的
// [32, 32+stream_bytes) 段）计算 IEEE CRC32，写入该条目尾旗标区的
// reserved 槽（布局 [flag][crc32]，MIT-458 预留位兑现，零布局变更），
// 并记录进 entry.crc32；stub_link → stub 的解密块在解密**之前**校验
// CRC（mismatch = 密文被篡改 → FailFast）。封死 xor 链可延展加密的
// 盲翻密文位面（MIT-464 D2 拍板的核心价值）。
//
// 边界披露（D1）：仅覆盖密文流面（32B 头/旗标不在 CRC 内——旗标本身是
// one-shot 状态；头明文供扫描/解析）；无 crypt 管道时无校验对象（Note
// 跳过）；解密后明文的运行时完整性（.wvmp 其余部分）属 init 钩子面
//（MIT-465 TLS 基建后续单）。

void IntegrityCrcPass::run(ProtectionContext& ctx) {
    auto* plan = ctx.find_slot<crypt::CryptPlan>(kCryptPlan);
    if (plan == nullptr || plan->functions.empty()) {
        ctx.diag.report(Severity::Note, name(),
                        "无加密计划（crypt 未在管道或无已虚拟化函数），integrity_crc 无校验对象，跳过");
        return;
    }

    for (auto& entry : plan->functions) {
        // CRC 覆盖密文流段（与 stub 校验面严格一致）。
        const size_t stream_off = 32;
        const size_t stream_end = 32 + static_cast<size_t>(entry.stream_bytes);
        if (stream_end > entry.encrypted_blob.size()) {
            ctx.diag.report(Severity::Error, name(),
                            "函数 " + entry.name + " 密文流越界（plan 损坏？）");
            throw std::runtime_error(std::string(name()) + ": corrupted plan entry");
        }
        entry.crc32 = crc32_of(std::span<const u8>(entry.encrypted_blob.data() + stream_off,
                                                   entry.stream_bytes));
        entry.has_crc = true;
        // 尾旗标 reserved 槽复用为 CRC32（布局 [flag][crc32]，零变更）。
        for (int b = 0; b < 4; ++b)
            entry.encrypted_blob[stream_end + 4 + b] =
                static_cast<u8>(entry.crc32 >> (8 * b));
    }

    ctx.diag.report(Severity::Note, name(),
                    "已为 " + std::to_string(plan->functions.size()) +
                        " 个密文流计算 CRC32 完整性校验（stub 解密前校验，mismatch FailFast）");
}

WVMP_REGISTER_PASS(IntegrityCrcPass)

} // namespace wvmp::passes
