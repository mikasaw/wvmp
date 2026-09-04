#include "wvmp/passes/crypt/crypt_pass.hpp"

#include "wvmp/passes/crypt/crypt_plan.hpp"
#include "wvmp/passes/virtualize/virtualize_pass.hpp"
#include "wvmp/regvm/codecs/xor_chain.hpp"
#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/registry.hpp"

#include <stdexcept>

namespace wvmp::passes {

// MIT-458 (crypt-v1)：blob 级字节码加密。
//
// 流水线位置：Transform 阶段、virtualize 之后（默认管道顺序
// virtualize → crypt → stub_link）。本 pass 对 kVmProgram 里每个 VM 程序：
//   1. 从独立 Rng（ctx.seed ^ kCryptSeedSalt，确定性——不消费 ctx.rng，
//      下游随机序列与无 crypt 管道逐字节一致，回归基线零扰动）派生 key0；
//   2. XorChainCodec::encrypt_with_key 原地加密（32B 头明文保留——
//      stub_link x86 白名单 gate 与 read_blob 消费头）；
//   3. 追加 8B 尾旗标（flag=1=已加密）；
//   4. 全量记录进 kCryptPlan 槽。
// stub_link（Emit）消费 plan：发射密文 blob + 在 stub 入口织入 one-shot
// 解密块（密钥立即数嵌入 = 密钥每目标嵌入，MIT-458 D2 拍板）。
//
// 边界披露（D1，详见 crypt_plan.hpp 与 GAPS 保护强度缺口节）：
//   - 首入口并发双重解密未防护（v1 威胁模型 = 单线程初始化）；
//   - 首次执行后明文驻留镜像内存（对抗静态提取，不对抗运行时内存转储）；
//   - 档位面：函数是否加密由"管道是否含 crypt pass"决定（全有/全无）；
//     每函数级 crypt 档位随 ProtectLevel 追加（append-only）后续单扩。

namespace {

// crypt 专属 Rng 盐（任意固定 64 位常量；与 ctx.seed 异或派生独立密钥流，
// 不扰动 ctx.rng 的既有消费序——stub 布局/解释器随机化对无 crypt 管道
// 逐字节不变，回归基线零回踩）。
constexpr u64 kCryptSeedSalt = 0x57564D5043525950ull;  // "WVMPCRYP" LE

} // namespace

void CryptPass::run(ProtectionContext& ctx) {
    const auto* vfs = ctx.find_slot<std::vector<VirtualizedFunction>>(kVmProgram);
    if (vfs == nullptr || vfs->empty()) {
        ctx.diag.report(Severity::Warning, name(), "无已虚拟化函数，crypt 无加密对象，跳过");
        return;
    }

    auto codec = regvm::codecs::create_codec(std::string(crypt::kAlgoXorChain));
    if (codec == nullptr) {
        ctx.diag.report(Severity::Error, name(), "xor_chain codec 工厂未注册（链接配置错误？）");
        throw std::runtime_error(std::string(name()) + ": xor_chain codec not registered");
    }

    // 独立确定性密钥流（盐见上注）。逐函数消费一个 next()（vfs 序）。
    Rng key_rng(ctx.seed ^ kCryptSeedSalt);

    crypt::CryptPlan plan;
    plan.algo = std::string(crypt::kAlgoXorChain);
    plan.functions.reserve(vfs->size());

    for (size_t i = 0; i < vfs->size(); ++i) {
        const auto& vf = (*vfs)[i];
        crypt::CryptedFunction entry;
        entry.vfs_index = i;
        entry.name = vf.name;
        entry.key0 = static_cast<u32>(key_rng.next());

        entry.encrypted_blob = vf.program.bytecode;
        regvm::codecs::XorChainCodec::encrypt_with_key(entry.key0, entry.encrypted_blob);
        // 尾旗标：flag=1（已加密）；旗标 RVA = 流起点 + stream_bytes（stub
        // 侧按此计算，见 stub_gen.cpp 解密块）。
        const u64 stream_bytes = entry.encrypted_blob.size() - 32;
        entry.stream_bytes = stream_bytes;
        for (int b = 0; b < 4; ++b)
            entry.encrypted_blob.push_back(
                static_cast<u8>(crypt::kFlagEncrypted >> (8 * b)));
        for (int b = 0; b < 4; ++b)
            entry.encrypted_blob.push_back(0);
        plan.functions.push_back(std::move(entry));
    }

    ctx.slot<crypt::CryptPlan>(kCryptPlan) = std::move(plan);
    ctx.diag.report(Severity::Note, name(),
                    "已加密 " + std::to_string(vfs->size()) + "/" +
                        std::to_string(vfs->size()) + " 个 VM 程序（xor_chain，"
                        "seed 派生密钥，stub 入口 one-shot 解密）");
}

WVMP_REGISTER_PASS(CryptPass)

} // namespace wvmp::passes
