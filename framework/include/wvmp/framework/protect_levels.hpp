#pragma once
#include "wvmp/common/types.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace wvmp {

// 保护档位（MIT-457 配置系统 v1）。
// ⚠️ append-only enum（pitfall #34 纪律）：v1 只有 Virtualize/None 两档；
// mutate / crypt / ultra 随 M3 对应 pass 落地时**追加**（禁重排、禁复用
// 既有值——该枚举经 TOML 字符串 ↔ 枚举映射进配置，重排即静默改语义）。
enum class ProtectLevel : u8 {
    Virtualize = 0,  // 真虚拟化（缺省 = 现状行为）
    None       = 1,  // 保持原生执行（区域不进 VM）
};

inline constexpr std::string_view to_string(ProtectLevel level) {
    switch (level) {
    case ProtectLevel::Virtualize: return "virtualize";
    case ProtectLevel::None: return "none";
    }
    return "?";
}

// 单条函数规则：选择器（rva / index / name 恰一，解析期保证，MIT-461 起
// 增 name——依赖 MIT-460 P7-names 真名解析）+ 档位 + 可选 crypt 覆写。
struct FunctionProtectRule {
    bool has_rva = false;
    u64  rva   = 0;  // begin 标记 RVA（= FunctionRegion.begin_rva；TOML 支持 0x 十六进制字面量）
    bool has_index = false;
    u64  index = 0;  // 扫描序 0-based（= ProtectionContext.functions 下标，
                     // 即 VirtualizedFunction.src_index；**不是** kVmProgram 下标；
                     // 跨重编译不稳，调试用）
    bool has_name = false;
    std::string name;  // 标记函数真名（MIT-460 解析；跨重编译稳定的选择器）
    ProtectLevel level = ProtectLevel::Virtualize;
    // MIT-461：每函数 crypt 覆写（三态）。nullopt = 跟随管道全局行为
    //（crypt pass 在 = 全加密）；false = 该函数豁免加密；true = 强制加密
    //（仅当 crypt pass 在管道时有意义）。
    bool has_crypt = false;
    bool crypt = true;
};

// 保护规则集（CLI 解析 TOML 后整体写入 ctx 扩展槽，key = kProtectRules）。
// 消费方（virtualize / mutate 取档位面 level_for；crypt 取覆写面 crypt_for，
// anti_debug 等后续 pass 同理）查询；槽缺席（find_slot == nullptr，直连 API
// 未装配配置）= 全部按缺省档位 Virtualize 走，行为与 MIT-457 之前逐字节一致。
struct ProtectRules {
    ProtectLevel default_level = ProtectLevel::Virtualize;
    std::vector<FunctionProtectRule> functions;

    // —— MIT-468 (T11)：保护参数配置面（三态 has_*：缺省 = 现状行为）——
    // anti_debug_techniques 为裸位域（bit0 = PEB.BeingDebugged，bit1 =
    // PEB.NtGlobalFlag；位语义单一来源 = passes/anti_debug 的 tech::*，
    // framework 不反向依赖 pass 头，消费方原样透传）。缺省值仅在场时
    // 生效（has_* 哨兵），直连 API 未装配配置的镜像行为不变。
    bool has_mutate_density = false;
    u32  mutate_density = 10;            // nop 填充密度百分比（0-100）
    bool has_mutate_junk_density = false;
    u32  mutate_junk_density = 15;       // MIT-489: junk-Mov 密度百分比（0-100）
    bool has_anti_debug_techniques = false;
    u32  anti_debug_techniques = 0x3;    // 位域（见上注）
    bool has_anti_debug_init = false;
    bool anti_debug_init = true;         // init 期 TLS 检查面开关
    bool has_tls_enabled = false;
    bool tls_enabled = true;             // TLS 回调基建面开关
    bool has_crypt_fetch = false;
    bool crypt_fetch = false;            // MIT-473: 取指级加密（替代 blob 级）
    bool has_import_skip_backfill = false;
    bool import_skip_backfill = false;   // MIT-488: 跳过 TLS 回填 + FailFast 红线桩
    bool has_pe_aslr = false;
    bool pe_aslr = true;                 // MIT-494: ASLR 兼容（保留 DYNAMIC_BASE
                                         // + .reloc 扩展；native 未 opt-in 时保守清除）
    bool has_require_avx = false;
    bool require_avx = true;
    // MIT-534 (G8b 通路 A): BMI2 词面开关（false 时含 Mulx/Pdep/Pext 的
    // 函数整函数 gate；append-only 追加，既有聚合初始化逐位兼容）。
    bool has_require_bmi2 = false;
    bool require_bmi2 = true;             // MIT-518: AVX 词面开关（false 时
                                         // ymm/vzero 词函数级 gate——部署非
                                         // AVX 机器安全开关；G8b require_bmi2
                                         // 同位预留）

    // —— 查询面（契约 C-A2，MIT-491 / CR-02+CR-03）：三个选择器能力对等，
    // 仲裁序唯一 ——
    //
    // level_for 与 crypt_for 共用 matching_rule_indices 的同一套遍历：按
    // functions 声明序**单遍**扫描，任一选择器（name / index / rva）命中即
    // 覆写，**后声明者胜**；default_level（level 面）/ 无覆写（crypt 面）是
    // 兜底。这废除了 MIT-457~MIT-461 的"index 先评、rva 后评"两遍序——两遍
    // 序正是"查询能力不对等"的病根（name 进不了 level 面 ⇒ 按 name 配 level
    // 解析成功却查不到）。
    //
    // src_index 一律是 ProtectionContext.functions 的原始扫描序号（0-based，
    // 见 :34）。CryptPass 侧经 VirtualizedFunction.src_index 携带（规则 4），
    // 不再用压缩后的 kVmProgram 下标解释 index。
    //
    // 解析期已拒"同选择器重复"（cli/src/config.cpp 的矛盾配置拒绝）；跨选择器
    // 撞同一函数（如 name 与 index 各一条）在解析期不可静态判定，故按本序后评
    // 胜，并由消费方在运行时以 Note 披露生效规则（resolve_level 的 hits 即披露
    // 依据）——不允许静默仲裁后毫无痕迹。
    struct LevelDecision {
        ProtectLevel level = ProtectLevel::Virtualize;
        // 命中该函数的规则在 functions 中的声明序号，按声明序升序；末位即
        // 生效者。空 = 无命中（level = default_level）。
        std::vector<size_t> hits;
    };

    LevelDecision resolve_level(u64 begin_rva, u64 src_index,
                                std::string_view name) const {
        LevelDecision d;
        d.hits = matching_rule_indices(begin_rva, src_index, name,
                                       [](const FunctionProtectRule&) { return true; });
        d.level = d.hits.empty()
                      ? default_level
                      : functions[d.hits.back()].level;
        return d;
    }

    ProtectLevel level_for(u64 begin_rva, u64 src_index,
                           std::string_view name) const {
        return resolve_level(begin_rva, src_index, name).level;
    }

    // MIT-461：每函数 crypt 覆写解析。返回 nullopt = 无显式覆写（跟随全局
    // 行为）；仅统计显式携带 crypt 覆写的规则，其余同 level 面（后评胜）。
    std::optional<bool> crypt_for(u64 begin_rva, u64 src_index,
                                  std::string_view name) const {
        return resolve_crypt(begin_rva, src_index, name).crypt;
    }

    // crypt 面的披露增强版（同 resolve_level：命中列表供消费方留痕，判定一致）。
    struct CryptDecision {
        std::optional<bool> crypt;
        std::vector<size_t> hits;  // 带 crypt 覆写且命中该函数的规则声明序号
    };

    CryptDecision resolve_crypt(u64 begin_rva, u64 src_index,
                                std::string_view name) const {
        CryptDecision d;
        d.hits = matching_rule_indices(
            begin_rva, src_index, name,
            [](const FunctionProtectRule& r) { return r.has_crypt; });
        if (!d.hits.empty()) d.crypt = functions[d.hits.back()].crypt;
        return d;
    }

private:
    // 唯一的规则遍历：返回命中该函数且参与本次查询（accept 为真）的规则
    // 声明序号，按声明序升序。选择器之间无优先级——只有声明序先后。
    template <typename Accept>
    std::vector<size_t> matching_rule_indices(u64 begin_rva, u64 src_index,
                                              std::string_view name,
                                              Accept accept) const {
        std::vector<size_t> hits;
        for (size_t i = 0; i < functions.size(); ++i) {
            const FunctionProtectRule& r = functions[i];
            if (!accept(r)) continue;
            if ((r.has_name && r.name == name) ||
                (r.has_index && r.index == src_index) ||
                (r.has_rva && r.rva == begin_rva))
                hits.push_back(i);
        }
        return hits;
    }
};

} // namespace wvmp
