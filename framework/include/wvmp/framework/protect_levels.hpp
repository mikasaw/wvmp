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
    u64  index = 0;  // 扫描序 0-based（= ProtectionContext.functions 下标；跨重编译不稳，调试用）
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
// 消费方（virtualize；后续 mutate/crypt/anti_debug 各取自己关心的档位面）
// 经 level_for 查询；槽缺席（find_slot == nullptr，直连 API 未装配配置）
// = 全部按缺省档位 Virtualize 走，行为与 MIT-457 之前逐字节一致。
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

    // 解析某函数的档位：显式规则覆盖缺省；index 规则先评、rva 规则后评
    // （rva 是跨重编译唯一较稳的选择器，后评 = 与 index 规则同时命中时
    // rva 胜；解析期已拒同选择器重复，双通道撞同一函数且档位不同的矛盾
    // 配置属用户错误，消费方不静默仲裁——解析期拒绝成本低且报错可读，
    // 这里保留"后评胜"的确定序只为防御直连 API 绕过解析器构造的规则集）。
    ProtectLevel level_for(u64 begin_rva, u64 index) const {
        ProtectLevel level = default_level;
        for (const auto& r : functions) {
            if (r.has_index && r.index == index) level = r.level;
        }
        for (const auto& r : functions) {
            if (r.has_rva && r.rva == begin_rva) level = r.level;
        }
        return level;
    }

    // MIT-461：每函数 crypt 覆写解析。按规则声明序后评胜（任一选择器
    // 命中即覆写；仅统计显式携带 crypt 覆写的规则）。
    // 返回 nullopt = 无显式覆写（跟随全局行为）。
    std::optional<bool> crypt_for(u64 begin_rva, u64 index,
                                  std::string_view name) const {
        std::optional<bool> result;
        for (const auto& r : functions) {
            if (r.has_crypt &&
                ((r.has_index && r.index == index) ||
                 (r.has_rva && r.rva == begin_rva) ||
                 (r.has_name && r.name == name)))
                result = r.crypt;
        }
        return result;
    }
};

} // namespace wvmp
