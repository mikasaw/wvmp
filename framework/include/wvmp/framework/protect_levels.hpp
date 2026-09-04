#pragma once
#include "wvmp/common/types.hpp"

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

// 单条函数规则：选择器（rva / index 恰一，解析期保证）+ 档位。
struct FunctionProtectRule {
    bool has_rva = false;
    u64  rva   = 0;  // begin 标记 RVA（= FunctionRegion.begin_rva；TOML 支持 0x 十六进制字面量）
    bool has_index = false;
    u64  index = 0;  // 扫描序 0-based（= ProtectionContext.functions 下标；跨重编译不稳，调试用）
    ProtectLevel level = ProtectLevel::Virtualize;
};

// 保护规则集（CLI 解析 TOML 后整体写入 ctx 扩展槽，key = kProtectRules）。
// 消费方（virtualize；后续 mutate/crypt/anti_debug 各取自己关心的档位面）
// 经 level_for 查询；槽缺席（find_slot == nullptr，直连 API 未装配配置）
// = 全部按缺省档位 Virtualize 走，行为与 MIT-457 之前逐字节一致。
struct ProtectRules {
    ProtectLevel default_level = ProtectLevel::Virtualize;
    std::vector<FunctionProtectRule> functions;

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
};

} // namespace wvmp
