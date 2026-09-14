#include "wvmp/cli/config.hpp"

#include <toml++/toml.hpp>

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <system_error>

#ifdef _WIN32
#include <windows.h>
#endif

namespace wvmp::cli {
namespace {

// toml++ 开着异常（TOML_EXCEPTIONS=1）时语法错以 toml::parse_error 抛出；
// 其 source() 携带位置，这里透传出行号。
std::string describe_parse_error(const toml::parse_error& err) {
    std::string msg = "config 语法错误: " + std::string(err.description());
    const auto& begin = err.source().begin;
    if (begin.line > 0)
        msg += " (line " + std::to_string(begin.line) +
               ", column " + std::to_string(begin.column) + ")";
    return msg;
}

// 把 MSYS/Git-Bash 风格 POSIX 路径转换为 Windows 路径。返回空 path 表示
// "看起来不像 MSYS 风格，调用方应保留原路径"。
//
// 背景：std::filesystem 在 Windows 上不识别 MSYS mount (e.g. /c/Users/...)
// 也不识别 POSIX /tmp（实际指向 $TEMP）。当脚本（如 scripts/e2e.sh）
// 把 MSYS 风格路径通过命令行传给 wvmp_cli.exe 时，需要在这里 fallback。
//   /tmp/xxx/foo.toml          -> $TEMP\xxx\foo.toml
//   /tmp/foo.toml              -> $TEMP\foo.toml
//   /c/Users/foo/bar.toml      -> C:/Users/foo/bar.toml
//   C:/Windows/path            -> {} (已 Windows)
//   D:\foo                     -> {} (已 Windows)
//   foo.toml (相对)            -> {} (由 std::filesystem 处理)
std::filesystem::path msys_to_windows_path(const std::filesystem::path& p) {
#ifdef _WIN32
    std::string s = p.string();
    if (s.empty()) return {};
    // 已是 Windows 路径: "C:/..." 或 "C:\" 或 "\\server\share"
    if (s.size() >= 2 && s[1] == ':') return {};
    if (s.size() >= 2 && s[0] == '\\' && s[1] == '\\') return {};
    if (s[0] != '/') return {};  // 相对路径, std::filesystem 会处理

    // /tmp 风格 -> $TEMP
    if (s.size() >= 4 && s.compare(0, 4, "/tmp") == 0) {
        char buf[MAX_PATH];
        DWORD n = GetEnvironmentVariableA("TEMP", buf, sizeof(buf));
        if (n == 0 || n >= sizeof(buf)) return {};
        std::string rest = s.substr(4);
        // 去前缀的 '/'
        if (!rest.empty() && rest[0] == '/') rest.erase(0, 1);
        // 把 POSIX '/' 全部转 Windows '\'
        for (auto& c : rest) if (c == '/') c = '\\';
        if (rest.empty()) return std::filesystem::path(buf);
        return std::filesystem::path(std::string(buf) + "\\" + rest);
    }
    // /c/, /d/ 等单字母 mount 前缀
    if (s.size() >= 3 && s[2] == '/') {
        char drive = static_cast<char>(std::toupper(static_cast<unsigned char>(s[1])));
        if (drive < 'A' || drive > 'Z') return {};
        std::string rest = s.substr(2);  // 形如 "/Users/foo"
        return std::filesystem::path(std::string(1, drive) + ":" + rest);
    }
    return {};
#else
    (void)p;
    return {};
#endif
}

} // namespace

ConfigResult parse_config(const std::filesystem::path& file) {
    ConfigResult result;

    // MSYS/Git-Bash 路径 fallback: 原路径不存在时, 尝试转换为 Windows 路径.
    // 适用场景: scripts/e2e.sh 用 mktemp -d 生成 /tmp/xxx, wvmp_cli.exe 拿到
    // 这条 POSIX 路径在 std::filesystem::exists 失败. fallback 不修改原 file
    // 引用 (caller 拿到的 result.value.input/output 仍是 TOML 里的字符串),
    // 只影响"是否能打开文件"这一关.
    std::filesystem::path actual = file;
    {
        std::error_code ec;
        if (!std::filesystem::exists(actual, ec)) {
            ec.clear();
            std::filesystem::path converted = msys_to_windows_path(file);
            if (!converted.empty() && std::filesystem::exists(converted, ec)) {
                actual = converted;
                ec.clear();
            } else {
                result.error = "config 文件不存在: " + file.string();
                return result;
            }
        }
    }

    toml::table tbl;
    try {
        tbl = toml::parse_file(actual.string());
    } catch (const toml::parse_error& err) {
        result.error = describe_parse_error(err);
        return result;
    }

    const auto fail = [&result](std::string error) -> ConfigResult {
        result.ok = false;
        result.error = std::move(error);
        return result;
    };

    // MIT-457（验收反馈加固）：严格 schema——未知键显式拒绝。背景：TOML
    // 的表作用域规则会把写在 [[表头]] 之后的顶层键静默吸进该表（如
    // default_level 追加到文件尾 → 落进最后一个 [[passes]] 元素），v0 的
    // "未知键忽略" 口径会让这类配置静默失效零告警——保护工具的配置打错
    // 必须响，不能静默吞。
    constexpr std::string_view kTopLevelKeys[] = {"input", "output", "seed", "arch",
                                                  "default_level", "functions", "passes",
                                                  "avx",
                                                  "mutate", "anti_debug", "tls", "crypt",
                                                  "import", "pe"};
    for (const auto& [key, value] : tbl) {
        bool known = false;
        for (auto k : kTopLevelKeys)
            if (key.str() == k) known = true;
        if (!known)
            return fail("config 未知顶层字段 '" + std::string(key.str()) +
                        "'（允许: input/output/seed/arch/default_level/functions/"
                        "passes/mutate/anti_debug/tls/crypt/import——⚠️ 顶层键必须写在任何 "
                        "[[表头]] 之前，否则会被 TOML 作用域规则吸进表内）");
    }

    // input / output：必填非空字符串。
    if (auto input = tbl["input"].value<std::string>()) {
        if (input->empty()) return fail("config 缺少字段: 'input' 不能为空字符串");
        result.value.input = *input;
    } else {
        return fail("config 缺少必填字段: 'input'（字符串，被保护文件路径）");
    }

    if (auto output = tbl["output"].value<std::string>()) {
        if (output->empty()) return fail("config 缺少字段: 'output' 不能为空字符串");
        result.value.output = *output;
    } else {
        return fail("config 缺少必填字段: 'output'（字符串，保护后输出路径）");
    }

    // seed：可省略（默认 0）；必须是 >= 0 的整数。
    if (const toml::node* seed_node = tbl.get("seed")) {
        auto seed = seed_node->value<std::int64_t>();
        if (!seed)
            return fail("config 字段 'seed' 必须是整数");
        if (*seed < 0)
            return fail("config 字段 'seed' 必须是非负整数");
        result.value.seed = static_cast<u64>(*seed);
    } else {
        result.value.seed = 0;
    }

    // arch：可省略（默认 auto）；字符串枚举，非法值显式失败（MIT-438 B.5）。
    if (const toml::node* arch_node = tbl.get("arch")) {
        auto arch = arch_node->value<std::string>();
        if (!arch)
            return fail("config 字段 'arch' 必须是字符串（auto/x64/x86）");
        if (*arch == "auto")
            result.value.arch = ArchOpt::Auto;
        else if (*arch == "x64")
            result.value.arch = ArchOpt::X64;
        else if (*arch == "x86")
            result.value.arch = ArchOpt::X86;
        else
            return fail("config 字段 'arch' 非法值 '" + *arch + "'（允许: auto/x64/x86）");
    } else {
        result.value.arch = ArchOpt::Auto;
    }

    // passes：可省略或为空（空管道合法）；若存在必须是 [[passes]] 数组，
    // 每个表必填非空 'name'（名字是否真实存在由 Pipeline::from_names 校验）。
    if (const toml::node* passes_node = tbl.get("passes")) {
        const toml::array* arr = passes_node->as_array();
        if (!arr)
            return fail("config 字段 'passes' 必须是表数组（[[passes]]）");
        size_t index = 0;
        for (const toml::node& elem : *arr) {
            const toml::table* entry = elem.as_table();
            if (!entry)
                return fail("config 'passes[" + std::to_string(index) +
                            "]' 必须是 [[passes]] 表");
            auto name = (*entry)["name"].value<std::string>();
            if (!name || name->empty())
                return fail("config 'passes[" + std::to_string(index) +
                            "]' 缺少必填字段 'name'（非空字符串）");
            // 严格 schema：[[passes]] 条目只认 name（见上注——静默吸键防线）。
            for (const auto& [key, value] : *entry) {
                if (key.str() != "name")
                    return fail("config 'passes[" + std::to_string(index) +
                                "]' 未知字段 '" + std::string(key.str()) +
                                "'（[[passes]] 条目只允许 'name'；若这是顶层键，"
                                "必须写在任何 [[表头]] 之前）");
            }
            result.value.passes.push_back(PassConfig{*name});
            ++index;
        }
    }

    // MIT-457 配置系统 v1：default_level + [[functions]] 每函数档位规则。
    // 两者皆可省略（= 全部 Virtualize，与 v1 之前行为逐字节一致）。
    if (const toml::node* level_node = tbl.get("default_level")) {
        auto level = level_node->value<std::string>();
        if (!level)
            return fail("config 字段 'default_level' 必须是字符串（none/virtualize）");
        if (*level == "virtualize")
            result.value.rules.default_level = ProtectLevel::Virtualize;
        else if (*level == "none")
            result.value.rules.default_level = ProtectLevel::None;
        else
            return fail("config 字段 'default_level' 非法值 '" + *level +
                        "'（允许: none/virtualize）");
    }

    if (const toml::node* fns_node = tbl.get("functions")) {
        const toml::array* arr = fns_node->as_array();
        if (!arr)
            return fail("config 字段 'functions' 必须是表数组（[[functions]]）");
        size_t entry_no = 0;
        for (const toml::node& elem : *arr) {
            const toml::table* entry = elem.as_table();
            if (!entry)
                return fail("config 'functions[" + std::to_string(entry_no) +
                            "]' 必须是 [[functions]] 表");
            const auto where = "config 'functions[" + std::to_string(entry_no) + "]'";

            // 选择器 rva / index：恰一（TOML 整数字面量，rva 支持 0x 前缀）。
            const bool has_rva = entry->get("rva") != nullptr;
            const bool has_index = entry->get("index") != nullptr;
            const bool has_name = entry->get("name") != nullptr;
            const int selectors = static_cast<int>(has_rva) + static_cast<int>(has_index) +
                                  static_cast<int>(has_name);
            if (selectors > 1)
                return fail(where + " 'rva'/'index'/'name' 只能选其一（消除选择器歧义）");
            if (selectors == 0)
                return fail(where + " 缺少选择器字段（'rva'/'index'/'name' 恰一）");

            FunctionProtectRule rule;
            if (has_name) {
                auto name = (*entry)["name"].value<std::string>();
                if (!name || name->empty())
                    return fail(where + " 字段 'name' 必须是非空字符串（标记函数真名）");
                rule.has_name = true;
                rule.name = *name;
            } else if (has_rva) {
                auto rva = (*entry)["rva"].value<std::int64_t>();
                if (!rva || *rva < 0)
                    return fail(where + " 字段 'rva' 必须是非负整数（begin 标记 "
                                     "RVA，支持 0x 十六进制字面量）");
                rule.has_rva = true;
                rule.rva = static_cast<u64>(*rva);
            } else {
                auto index = (*entry)["index"].value<std::int64_t>();
                if (!index || *index < 0)
                    return fail(where + " 字段 'index' 必须是非负整数（扫描序 0-based）");
                rule.has_index = true;
                rule.index = static_cast<u64>(*index);
            }

            // crypt 覆写：可省略；MIT-461。
            if (const toml::node* cr = entry->get("crypt")) {
                auto c = cr->value<bool>();
                if (!c)
                    return fail(where + " 字段 'crypt' 必须是布尔值（true/false）");
                rule.has_crypt = true;
                rule.crypt = *c;
            }

            // level：可省略 = "virtualize"（与 default 独立显式化）。
            if (const toml::node* lv = entry->get("level")) {
                auto level = lv->value<std::string>();
                if (!level)
                    return fail(where + " 字段 'level' 必须是字符串（none/virtualize）");
                if (*level == "virtualize")
                    rule.level = ProtectLevel::Virtualize;
                else if (*level == "none")
                    rule.level = ProtectLevel::None;
                else
                    return fail(where + " 字段 'level' 非法值 '" + *level +
                                "'（允许: none/virtualize）");
            }
            // 严格 schema：[[functions]] 条目只认 rva/index/level（静默吸键防线）。
            for (const auto& [key, value] : *entry) {
                if (key.str() != "rva" && key.str() != "index" && key.str() != "name" &&
                    key.str() != "level" && key.str() != "crypt")
                    return fail(where + " 未知字段 '" + std::string(key.str()) +
                                "'（[[functions]] 条目只允许 rva/index/name/level/crypt）");
            }

            // 同选择器重复 = 配置矛盾（后写覆盖类语义在此最易埋雷），显式拒。
            for (const auto& existing : result.value.rules.functions) {
                if ((rule.has_rva && existing.has_rva && existing.rva == rule.rva) ||
                    (rule.has_index && existing.has_index && existing.index == rule.index) ||
                    (rule.has_name && existing.has_name && existing.name == rule.name))
                    return fail(where + " 选择器与前文规则重复（同一函数只允许一条规则）");
            }
            result.value.rules.functions.push_back(rule);
            ++entry_no;
        }
    }

    // —— MIT-468 (T11)：保护参数三表（均可省略 = 现状缺省；子键严格
    // schema，未知子键显式拒绝——同顶层键的静默吞防线）。——

    // [mutate] density = 0..100（nop 填充密度百分比；0 = 关闭填充）；
    // junk_density = 0..100（MIT-489：junk-Mov 密度百分比，缺省 15，在场
    // 时覆写；0 = 关闭 junk 面）。
    if (const toml::node* mutate_node = tbl.get("mutate")) {
        const toml::table* mt = mutate_node->as_table();
        if (!mt) return fail("config 字段 'mutate' 必须是表（[mutate]）");
        for (const auto& [key, value] : *mt)
            if (key.str() != "density" && key.str() != "junk_density")
                return fail("config [mutate] 未知子键 '" + std::string(key.str()) +
                            "'（允许: density, junk_density）");
        const toml::node* dn = mt->get("density");
        if (dn == nullptr) return fail("config [mutate] 缺少子键 'density'");
        auto density = dn->value<std::int64_t>();
        if (!density)
            return fail("config [mutate] 'density' 必须是整数（0-100）");
        if (*density < 0 || *density > 100)
            return fail("config [mutate] 'density' 超界（0-100）："
                        + std::to_string(*density));
        result.value.rules.has_mutate_density = true;
        result.value.rules.mutate_density = static_cast<u32>(*density);
        if (const toml::node* jd = mt->get("junk_density")) {
            auto junk = jd->value<std::int64_t>();
            if (!junk)
                return fail("config [mutate] 'junk_density' 必须是整数（0-100）");
            if (*junk < 0 || *junk > 100)
                return fail("config [mutate] 'junk_density' 超界（0-100）："
                            + std::to_string(*junk));
            result.value.rules.has_mutate_junk_density = true;
            result.value.rules.mutate_junk_density = static_cast<u32>(*junk);
        }
    }

    // [anti_debug] being_debugged / nt_global_flag / init（默认全开）。
    if (const toml::node* adb_node = tbl.get("anti_debug")) {
        const toml::table* at = adb_node->as_table();
        if (!at) return fail("config 字段 'anti_debug' 必须是表（[anti_debug]）");
        u32 techniques = 0;
        for (const auto& [key, value] : *at)
            if (key.str() != "being_debugged" && key.str() != "nt_global_flag" &&
                key.str() != "init" && key.str() != "drx" && key.str() != "rdtsc")
                return fail("config [anti_debug] 未知子键 '" + std::string(key.str()) +
                            "'（允许: being_debugged/nt_global_flag/init/drx/rdtsc）");
        result.value.rules.has_anti_debug_techniques = true;
        result.value.rules.has_anti_debug_init = true;
        // 类型严格校验：布尔子键允许 bool 与 0/1 整数（toml++ permissive
        // 语义，直觉一致），字符串/浮点等一律可读报错（验收 issue：静默
        // 回落缺省 = 配置写错零告警，不可接受）。
        for (const char* k : {"being_debugged", "nt_global_flag", "init", "drx",
                              "rdtsc"}) {
            const toml::node* n = at->get(k);
            if (n != nullptr && !n->is_boolean() && !n->is_integer())
                return fail("config [anti_debug] '" + std::string(k) +
                            "' 必须是布尔值（true/false 或 0/1）");
        }
        auto get_bool = [&](const char* k, bool dflt) {
            if (auto v = at->get(k)) {
                if (auto b = v->value<bool>()) return *b;
            }
            return dflt;
        };
        if (get_bool("being_debugged", true)) techniques |= 0x1;
        if (get_bool("nt_global_flag", true)) techniques |= 0x2;
        if (get_bool("drx", false)) techniques |= 0x4;      // MIT-470: DRx 面（opt-in）
        if (get_bool("rdtsc", false)) techniques |= 0x8;    // MIT-471: rdtsc 面（opt-in）
        result.value.rules.anti_debug_techniques = techniques;
        result.value.rules.anti_debug_init = get_bool("init", true);
    }

    // [crypt] fetch（MIT-473：取指级加密开关，默认 false = blob 级）。
    if (const toml::node* crypt_node = tbl.get("crypt")) {
        const toml::table* ct = crypt_node->as_table();
        if (!ct) return fail("config 字段 'crypt' 必须是表（[crypt]）");
        for (const auto& [key, value] : *ct)
            if (key.str() != "fetch")
                return fail("config [crypt] 未知子键 '" + std::string(key.str()) +
                            "'（允许: fetch）");
        const toml::node* fn = ct->get("fetch");
        if (fn == nullptr) return fail("config [crypt] 缺少子键 'fetch'");
        auto fetch = fn->value<bool>();
        if (!fetch) return fail("config [crypt] 'fetch' 必须是布尔值");
        result.value.rules.has_crypt_fetch = true;
        result.value.rules.crypt_fetch = *fetch;
    }

    // [tls] enabled（默认 true；false = tls_hook 空转）。
    if (const toml::node* tls_node = tbl.get("tls")) {
        const toml::table* tt = tls_node->as_table();
        if (!tt) return fail("config 字段 'tls' 必须是表（[tls]）");
        for (const auto& [key, value] : *tt)
            if (key.str() != "enabled")
                return fail("config [tls] 未知子键 '" + std::string(key.str()) +
                            "'（允许: enabled）");
        const toml::node* en = tt->get("enabled");
        if (en == nullptr) return fail("config [tls] 缺少子键 'enabled'");
        auto enabled = en->value<bool>();
        if (!enabled)
            return fail("config [tls] 'enabled' 必须是布尔值");
        result.value.rules.has_tls_enabled = true;
        result.value.rules.tls_enabled = *enabled;
    }

    // [import] skip_backfill（默认 false；true = MIT-488 跳过 TLS 回填 +
    // 原 IAT 全槽 FailFast 红线桩——依据 MIT-487 完备性证据链，opt-in）。
    if (const toml::node* imp_node = tbl.get("import")) {
        const toml::table* it = imp_node->as_table();
        if (!it) return fail("config 字段 'import' 必须是表（[import]）");
        for (const auto& [key, value] : *it)
            if (key.str() != "skip_backfill")
                return fail("config [import] 未知子键 '" + std::string(key.str()) +
                            "'（允许: skip_backfill）");
        const toml::node* sb = it->get("skip_backfill");
        if (sb == nullptr) return fail("config [import] 缺少子键 'skip_backfill'");
        auto skip = sb->value<bool>();
        if (!skip)
            return fail("config [import] 'skip_backfill' 必须是布尔值");
        result.value.rules.has_import_skip_backfill = true;
        result.value.rules.import_skip_backfill = *skip;
    }

    // [avx] require（MIT-518；默认 true；false = ymm/vzero 词函数级 gate
    // ——部署非 AVX 机器的安全开关。require_bmi2 同位预留）。
    if (const toml::node* avx_node = tbl.get("avx")) {
        const toml::table* at = avx_node->as_table();
        if (!at) return fail("config 字段 'avx' 必须是表（[avx]）");
        for (const auto& [key, value] : *at)
            if (key.str() != "require")
                return fail("config [avx] 未知子键 '" + std::string(key.str()) +
                            "'（允许: require）");
        const toml::node* rq = at->get("require");
        if (rq == nullptr) return fail("config [avx] 缺少子键 'require'");
        auto req = rq->value<bool>();
        if (!req)
            return fail("config [avx] 'require' 必须是布尔值");
        result.value.rules.has_require_avx = true;
        result.value.rules.require_avx = *req;
    }

    // [pe] aslr（默认 true；true = 保留 native DYNAMIC_BASE + .reloc 扩展
    // ——MIT-494 ASLR 兼容；false = 清 DYNAMIC_BASE 维持 M2-8 行为）。
    if (const toml::node* pe_node = tbl.get("pe")) {
        const toml::table* pt = pe_node->as_table();
        if (!pt) return fail("config 字段 'pe' 必须是表（[pe]）");
        for (const auto& [key, value] : *pt)
            if (key.str() != "aslr")
                return fail("config [pe] 未知子键 '" + std::string(key.str()) +
                            "'（允许: aslr）");
        const toml::node* ab = pt->get("aslr");
        if (ab == nullptr) return fail("config [pe] 缺少子键 'aslr'");
        auto aslr = ab->value<bool>();
        if (!aslr)
            return fail("config [pe] 'aslr' 必须是布尔值");
        result.value.rules.has_pe_aslr = true;
        result.value.rules.pe_aslr = *aslr;
    }

    result.ok = true;
    return result;
}

} // namespace wvmp::cli
