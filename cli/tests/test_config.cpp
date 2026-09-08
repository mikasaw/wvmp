// cli/config.cpp 的 TOML 解析测试。

#include "wvmp/cli/config.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>

#ifdef _WIN32
#include <windows.h>
#endif

namespace {

// 把一段 TOML 落到临时文件，析构时删除。
class TempToml {
public:
    explicit TempToml(std::string_view content) {
        static std::atomic<unsigned> counter{0};
        path_ = std::filesystem::temp_directory_path() /
                ("wvmp_cli_config_" + std::to_string(counter++) + ".toml");
        std::ofstream out(path_, std::ios::binary | std::ios::trunc);
        out << content;
    }
    ~TempToml() {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }
    TempToml(const TempToml&) = delete;
    TempToml& operator=(const TempToml&) = delete;

    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

TEST(ConfigParse, FullConfigFields) {
    const TempToml toml(
        "input  = \"target.exe\"\n"
        "output = \"out/target_protected.exe\"\n"
        "seed   = 12345\n"
        "\n"
        "[[passes]]\n"
        "name = \"pe_loader\"\n"
        "[[passes]]\n"
        "name = \"marker_scan\"\n"
        "[[passes]]\n"
        "name = \"pe_writer\"\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_TRUE(result.ok) << result.error;
    EXPECT_EQ(result.value.input, "target.exe");
    EXPECT_EQ(result.value.output, "out/target_protected.exe");
    EXPECT_EQ(result.value.seed, uint64_t{12345});
    ASSERT_EQ(result.value.passes.size(), size_t{3});
    EXPECT_EQ(result.value.passes[0].name, "pe_loader");
    EXPECT_EQ(result.value.passes[1].name, "marker_scan");
    EXPECT_EQ(result.value.passes[2].name, "pe_writer");
}

TEST(ConfigParse, SeedOptionalDefaultsToZero) {
    const TempToml toml("input = \"a.exe\"\noutput = \"b.exe\"\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_TRUE(result.ok) << result.error;
    EXPECT_EQ(result.value.seed, uint64_t{0});
}

TEST(ConfigParse, MissingInputReportsInput) {
    const TempToml toml("output = \"b.exe\"\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    EXPECT_FALSE(result.ok);
    EXPECT_TRUE(contains(result.error, "input")) << result.error;
}

TEST(ConfigParse, MissingOutputReportsOutput) {
    const TempToml toml("input = \"a.exe\"\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    EXPECT_FALSE(result.ok);
    EXPECT_TRUE(contains(result.error, "output")) << result.error;
}

TEST(ConfigParse, SyntaxErrorCarriesLineNumber) {
    // 第 3 行是坏的（"= = "），错误必须透传 toml++ 的行号。
    const TempToml toml(
        "input = \"a.exe\"\n"
        "output = \"b.exe\"\n"
        "seed = = 42\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    EXPECT_FALSE(result.ok);
    EXPECT_TRUE(contains(result.error, "line")) << result.error;
    EXPECT_TRUE(contains(result.error, "line 3")) << result.error;
}

TEST(ConfigParse, EmptyPassesIsLegal) {
    const TempToml toml("input = \"a.exe\"\noutput = \"b.exe\"\n\npasses = []\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_TRUE(result.ok) << result.error;
    EXPECT_TRUE(result.value.passes.empty());
}

TEST(ConfigParse, MissingPassesKeyIsLegal) {
    const TempToml toml("input = \"a.exe\"\noutput = \"b.exe\"\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_TRUE(result.ok) << result.error;
    EXPECT_TRUE(result.value.passes.empty());
}

TEST(ConfigParse, MissingConfigFile) {
    const auto result = wvmp::cli::parse_config(
        std::filesystem::temp_directory_path() / "wvmp_no_such_config.toml");
    EXPECT_FALSE(result.ok);
    EXPECT_TRUE(contains(result.error, "不存在")) << result.error;
}

#ifdef _WIN32
// ---- MSYS/Git-Bash 路径 fallback (fix(cli)) --------------------------------
//
// 背景: scripts/e2e.sh 用 mktemp -d 生成 /tmp/xxx, wvmp_cli.exe 拿到 POSIX
// 风格路径后 std::filesystem::exists 找不到. fallback 在 parse_config 里尝试
// 转换为 Windows 路径, 这两组测试固定该行为.
//
// 测试方法: 在 std::filesystem::temp_directory_path() 下手动创建一个 toml,
// 拿到它的绝对 Windows 路径, 然后用 MSYS 风格 (POSIX) 形式当 key, 验证
// parse_config 仍能识别.

// 把一个 Windows 路径转换为对应的 MSYS POSIX 表达. 仅适用本测试环境.
static std::filesystem::path to_msys_posix(const std::filesystem::path& win) {
    std::string s = win.string();
    if (s.size() < 3 || s[1] != ':') return {};
    char drive = static_cast<char>(std::tolower(static_cast<unsigned char>(s[0])));
    std::string rest = s.substr(2);
    if (!rest.empty() && (rest[0] == '\\' || rest[0] == '/')) rest[0] = '/';
    for (auto& c : rest) if (c == '\\') c = '/';
    return std::filesystem::path(std::string("/") + drive + rest);
}

TEST(ConfigParse, MsysTmpPathFallback) {
    std::error_code ec;
    auto win_dir = std::filesystem::temp_directory_path() /
                   "wvmp_cli_config_msys_tmp_test";
    std::filesystem::create_directories(win_dir, ec);
    auto win_file = win_dir / "e2e.toml";
    {
        std::ofstream out(win_file, std::ios::binary | std::ios::trunc);
        out << "input  = \"in.exe\"\noutput = \"out.exe\"\n";
    }
    char buf[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("TEMP", buf, sizeof(buf));
    ASSERT_GT(n, 0u);
    std::string rest = "\\wvmp_cli_config_msys_tmp_test\\e2e.toml";
    for (auto& c : rest) if (c == '\\') c = '/';
    std::filesystem::path msys_path = std::string("/tmp") + rest;

    const auto result = wvmp::cli::parse_config(msys_path);
    ASSERT_TRUE(result.ok) << result.error << " | msys=" << msys_path.string();
    EXPECT_EQ(result.value.input, "in.exe");

    std::filesystem::remove_all(win_dir, ec);
}

TEST(ConfigParse, MsysMountPathFallback) {
    std::error_code ec;
    auto win_dir = std::filesystem::temp_directory_path() /
                   "wvmp_cli_config_msys_mount_test";
    std::filesystem::create_directories(win_dir, ec);
    auto win_file = win_dir / "cfg.toml";
    {
        std::ofstream out(win_file, std::ios::binary | std::ios::trunc);
        out << "input = \"a.exe\"\noutput = \"b.exe\"\n";
    }
    auto msys_path = to_msys_posix(win_file);
    ASSERT_FALSE(msys_path.empty());

    const auto result = wvmp::cli::parse_config(msys_path);
    ASSERT_TRUE(result.ok) << result.error << " | msys=" << msys_path.string();
    EXPECT_EQ(result.value.input, "a.exe");

    std::filesystem::remove_all(win_dir, ec);
}

TEST(ConfigParse, WindowsPathUntouched) {
    std::error_code ec;
    auto win_dir = std::filesystem::temp_directory_path() /
                   "wvmp_cli_config_native_test";
    std::filesystem::create_directories(win_dir, ec);
    auto win_file = win_dir / "n.toml";
    {
        std::ofstream out(win_file, std::ios::binary | std::ios::trunc);
        out << "input = \"n.exe\"\noutput = \"m.exe\"\n";
    }
    const auto result = wvmp::cli::parse_config(win_file);
    ASSERT_TRUE(result.ok) << result.error;
    EXPECT_EQ(result.value.input, "n.exe");

    std::filesystem::remove_all(win_dir, ec);
}


// —— MIT-468 (T11)：保护参数三表（mutate / anti_debug / tls）——

TEST(ConfigParse, ProtectOptionTablesParse) {
    const TempToml toml(
        "input  = \"target.exe\"\n"
        "output = \"out.exe\"\n"
        "\n"
        "[mutate]\n"
        "density = 25\n"
        "[anti_debug]\n"
        "being_debugged = true\n"
        "nt_global_flag = false\n"
        "init = false\n"
        "[tls]\n"
        "enabled = false\n"
    );
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_TRUE(result.ok) << result.error;
    const auto& rules = result.value.rules;
    EXPECT_TRUE(rules.has_mutate_density);
    EXPECT_EQ(rules.mutate_density, 25u);
    EXPECT_TRUE(rules.has_anti_debug_techniques);
    EXPECT_EQ(rules.anti_debug_techniques, 0x1u);  // 仅 BeingDebugged
    EXPECT_TRUE(rules.has_anti_debug_init);
    EXPECT_FALSE(rules.anti_debug_init);
    EXPECT_TRUE(rules.has_tls_enabled);
    EXPECT_FALSE(rules.tls_enabled);
}

TEST(ConfigParse, ProtectOptionTablesOmittedAreSentinelFree) {
    const TempToml toml(
        "input  = \"target.exe\"\n"
        "output = \"out.exe\"\n"
    );
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_TRUE(result.ok) << result.error;
    const auto& rules = result.value.rules;
    EXPECT_FALSE(rules.has_mutate_density);
    EXPECT_FALSE(rules.has_anti_debug_techniques);
    EXPECT_FALSE(rules.has_anti_debug_init);
    EXPECT_FALSE(rules.has_tls_enabled);
}

TEST(ConfigParse, MutateDensityOutOfBoundsRejected) {
    const TempToml toml(
        "input  = \"t.exe\"\n"
        "output = \"o.exe\"\n"
        "[mutate]\n"
        "density = 101\n"
    );
    const auto result = wvmp::cli::parse_config(toml.path());
    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.error.find("0-100"), std::string::npos);
}

TEST(ConfigParse, UnknownSubkeysRejected) {
    const TempToml toml(
        "input  = \"t.exe\"\n"
        "output = \"o.exe\"\n"
        "[tls]\n"
        "enabled = true\n"
        "mode = \"aggressive\"\n"
    );
    const auto result = wvmp::cli::parse_config(toml.path());
    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.error.find("mode"), std::string::npos);
}

TEST(ConfigParse, AntiDebugStringBoolRejected) {
    const TempToml toml(
        "input  = \"t.exe\"\n"
        "output = \"o.exe\"\n"
        "[anti_debug]\n"
        "init = \"false\"\n"
    );
    const auto result = wvmp::cli::parse_config(toml.path());
    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.error.find("必须是布尔值"), std::string::npos);
}

// MIT-476 (T20 / T17 验收建议 4)：[crypt] fetch 严格 schema 负例三连。
TEST(ConfigParse, CryptFetchStringBoolRejected) {
    const TempToml toml(
        "input  = \"t.exe\"\n"
        "output = \"o.exe\"\n"
        "[crypt]\n"
        "fetch = \"yes\"\n"
    );
    const auto result = wvmp::cli::parse_config(toml.path());
    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.error.find("必须是布尔值"), std::string::npos);
}

TEST(ConfigParse, CryptFetchFloatBoolRejected) {
    const TempToml toml(
        "input  = \"t.exe\"\n"
        "output = \"o.exe\"\n"
        "[crypt]\n"
        "fetch = 1.5\n"
    );
    const auto result = wvmp::cli::parse_config(toml.path());
    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.error.find("必须是布尔值"), std::string::npos);
}

TEST(ConfigParse, CryptUnknownSubkeyRejected) {
    const TempToml toml(
        "input  = \"t.exe\"\n"
        "output = \"o.exe\"\n"
        "[crypt]\n"
        "mode = \"xor\"\n"
    );
    const auto result = wvmp::cli::parse_config(toml.path());
    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.error.find("mode"), std::string::npos);
}

TEST(ConfigParse, MsysFallbackNotFound) {
    const auto result = wvmp::cli::parse_config(
        std::filesystem::path("/tmp/wvmp_does_not_exist_12345.toml"));
    EXPECT_FALSE(result.ok);
    EXPECT_TRUE(contains(result.error, "不存在")) << result.error;
}
#endif  // _WIN32

TEST(ConfigParse, BadSeedType) {
    const TempToml toml("input = \"a.exe\"\noutput = \"b.exe\"\nseed = \"not a number\"\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    EXPECT_FALSE(result.ok);
    EXPECT_TRUE(contains(result.error, "seed")) << result.error;
}

TEST(ConfigParse, NegativeSeedRejected) {
    const TempToml toml("input = \"a.exe\"\noutput = \"b.exe\"\nseed = -1\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    EXPECT_FALSE(result.ok);
    EXPECT_TRUE(contains(result.error, "seed")) << result.error;
}

TEST(ConfigParse, PassEntryMissingName) {
    const TempToml toml(
        "input = \"a.exe\"\n"
        "output = \"b.exe\"\n"
        "[[passes]]\n"
        "tuning = 1\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    EXPECT_FALSE(result.ok);
    EXPECT_TRUE(contains(result.error, "name")) << result.error;
    EXPECT_TRUE(contains(result.error, "0")) << result.error; // 报出索引
}

TEST(ConfigParse, PassesWrongShape) {
    const TempToml toml("input = \"a.exe\"\noutput = \"b.exe\"\npasses = \"pe_loader\"\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    EXPECT_FALSE(result.ok);
    EXPECT_TRUE(contains(result.error, "passes")) << result.error;
}

// MIT-438 (X1b) B.5: arch 字段解析——可省略（= Auto 现状行为）/ 三合法值 /
// 非法值与错型显式失败。值域与 pe_loader target_arch.hpp 的 kTargetArch*
// 常量对账（映射面的漂移由 main.cpp 穷举 switch + 本侧对账注释钉）。
TEST(ConfigParse, ArchOptionalDefaultsToAuto) {
    const TempToml toml("input = \"a.exe\"\noutput = \"b.exe\"\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_TRUE(result.ok) << result.error;
    EXPECT_EQ(result.value.arch, wvmp::cli::ArchOpt::Auto);
}

TEST(ConfigParse, ArchThreeLegalValues) {
    struct Case {
        const char* text;
        wvmp::cli::ArchOpt expect;
    };
    const Case cases[] = {
        {"auto", wvmp::cli::ArchOpt::Auto},
        {"x64", wvmp::cli::ArchOpt::X64},
        {"x86", wvmp::cli::ArchOpt::X86},
    };
    for (const Case& c : cases) {
        const std::string toml_text = std::string("input = \"a.exe\"\noutput = \"b.exe\"\narch = \"") +
                                      c.text + "\"\n";
        const TempToml toml(toml_text);
        const auto result = wvmp::cli::parse_config(toml.path());
        ASSERT_TRUE(result.ok) << c.text << ": " << result.error;
        EXPECT_EQ(result.value.arch, c.expect) << c.text;
    }
}

TEST(ConfigParse, ArchIllegalValueRejected) {
    const TempToml toml("input = \"a.exe\"\noutput = \"b.exe\"\narch = \"arm64\"\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    EXPECT_FALSE(result.ok);
    EXPECT_TRUE(contains(result.error, "arch")) << result.error;
}

TEST(ConfigParse, ArchWrongTypeRejected) {
    const TempToml toml("input = \"a.exe\"\noutput = \"b.exe\"\narch = 64\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    EXPECT_FALSE(result.ok);
    EXPECT_TRUE(contains(result.error, "arch")) << result.error;
}

} // namespace

// ==================== MIT-457 配置系统 v1：保护档位规则 ====================

TEST(ConfigParse, ProtectRulesFullForm) {
    const TempToml toml(
        "input  = \"target.exe\"\n"
        "output = \"out.exe\"\n"
        "default_level = \"none\"\n"
        "\n"
        "[[functions]]\n"
        "rva = 0xAEBB\n"
        "level = \"virtualize\"\n"
        "[[functions]]\n"
        "index = 3\n"
        "[[passes]]\n"
        "name = \"pe_loader\"\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_TRUE(result.ok) << result.error;
    EXPECT_EQ(result.value.rules.default_level, wvmp::ProtectLevel::None);
    ASSERT_EQ(result.value.rules.functions.size(), size_t{2});
    EXPECT_TRUE(result.value.rules.functions[0].has_rva);
    EXPECT_FALSE(result.value.rules.functions[0].has_index);
    EXPECT_EQ(result.value.rules.functions[0].rva, uint64_t{0xAEBB});
    EXPECT_EQ(result.value.rules.functions[0].level, wvmp::ProtectLevel::Virtualize);
    EXPECT_TRUE(result.value.rules.functions[1].has_index);
    EXPECT_EQ(result.value.rules.functions[1].index, uint64_t{3});
    // level 可省略 = virtualize。
    EXPECT_EQ(result.value.rules.functions[1].level, wvmp::ProtectLevel::Virtualize);
}

TEST(ConfigParse, ProtectRulesAbsentDefaultsEmpty) {
    const TempToml toml(
        "input  = \"target.exe\"\n"
        "output = \"out.exe\"\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_TRUE(result.ok) << result.error;
    EXPECT_EQ(result.value.rules.default_level, wvmp::ProtectLevel::Virtualize);
    EXPECT_TRUE(result.value.rules.functions.empty());
}

TEST(ConfigParse, ProtectRulesUnknownDefaultLevelFails) {
    const TempToml toml(
        "input  = \"target.exe\"\n"
        "output = \"out.exe\"\n"
        "default_level = \"ultra\"\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_FALSE(result.ok);
    EXPECT_TRUE(contains(result.error, "default_level"));
}

TEST(ConfigParse, ProtectRulesUnknownLevelFails) {
    const TempToml toml(
        "input  = \"target.exe\"\n"
        "output = \"out.exe\"\n"
        "[[functions]]\n"
        "rva = 1\n"
        "level = \"mutate\"\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_FALSE(result.ok);
    EXPECT_TRUE(contains(result.error, "level"));
}

TEST(ConfigParse, ProtectRulesBothSelectorsFails) {
    const TempToml toml(
        "input  = \"target.exe\"\n"
        "output = \"out.exe\"\n"
        "[[functions]]\n"
        "rva = 1\n"
        "index = 2\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_FALSE(result.ok);
    EXPECT_TRUE(contains(result.error, "只能选其一"));
}

TEST(ConfigParse, ProtectRulesNoSelectorFails) {
    const TempToml toml(
        "input  = \"target.exe\"\n"
        "output = \"out.exe\"\n"
        "[[functions]]\n"
        "level = \"none\"\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_FALSE(result.ok);
    EXPECT_TRUE(contains(result.error, "选择器"));
}

TEST(ConfigParse, ProtectRulesNegativeSelectorFails) {
    const TempToml toml(
        "input  = \"target.exe\"\n"
        "output = \"out.exe\"\n"
        "[[functions]]\n"
        "index = -1\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_FALSE(result.ok);
    EXPECT_TRUE(contains(result.error, "index"));
}

TEST(ConfigParse, ProtectRulesDuplicateSelectorFails) {
    const TempToml toml(
        "input  = \"target.exe\"\n"
        "output = \"out.exe\"\n"
        "[[functions]]\n"
        "rva = 0x1000\n"
        "level = \"none\"\n"
        "[[functions]]\n"
        "rva = 0x1000\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_FALSE(result.ok);
    EXPECT_TRUE(contains(result.error, "重复"));
}

TEST(ConfigParse, UnknownTopLevelKeyFails) {
    // MIT-457 验收反馈加固：顶层未知键显式拒（TOML 表作用域吸键静默失效防线）。
    const TempToml toml(
        "input  = \"target.exe\"\n"
        "output = \"out.exe\"\n"
        "seedx = 1\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_FALSE(result.ok);
    EXPECT_TRUE(contains(result.error, "未知顶层字段 'seedx'"));
}

TEST(ConfigParse, MisplacedTopLevelKeyAfterTableHeaderFails) {
    // 验收实录陷阱：default_level 追加在 [[passes]] 之后会被 TOML 吸进表内
    // ——顶层查不到该键 = 缺字段口径报错（不再静默忽略）。
    const TempToml toml(
        "input  = \"target.exe\"\n"
        "output = \"out.exe\"\n"
        "[[passes]]\n"
        "name = \"pe_loader\"\n"
        "default_level = \"none\"\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_FALSE(result.ok);
    EXPECT_TRUE(contains(result.error, "passes[0]"));
}

TEST(ConfigParse, UnknownFunctionsEntryKeyFails) {
    const TempToml toml(
        "input  = \"target.exe\"\n"
        "output = \"out.exe\"\n"
        "[[functions]]\n"
        "rva = 1\n"
        "note = \"x\"\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_FALSE(result.ok);
    EXPECT_TRUE(contains(result.error, "未知字段 'note'"));
}

// ==================== MIT-461 配置 v2：name 选择器 + crypt 覆写 ====================

TEST(ConfigParse, NameSelectorAndCryptOverride) {
    const TempToml toml(
        "input  = \"target.exe\"\n"
        "output = \"out.exe\"\n"
        "[[functions]]\n"
        "name = \"compute_alpha\"\n"
        "crypt = false\n"
        "[[functions]]\n"
        "name = \"secret_box\"\n"
        "level = \"none\"\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_TRUE(result.ok) << result.error;
    ASSERT_EQ(result.value.rules.functions.size(), size_t{2});
    EXPECT_TRUE(result.value.rules.functions[0].has_name);
    EXPECT_EQ(result.value.rules.functions[0].name, "compute_alpha");
    EXPECT_TRUE(result.value.rules.functions[0].has_crypt);
    EXPECT_FALSE(result.value.rules.functions[0].crypt);
    EXPECT_TRUE(result.value.rules.functions[1].has_name);
    EXPECT_EQ(result.value.rules.functions[1].level, wvmp::ProtectLevel::None);
    EXPECT_FALSE(result.value.rules.functions[1].has_crypt);
}

TEST(ConfigParse, NameSelectorEmptyValueFails) {
    const TempToml toml(
        "input  = \"target.exe\"\n"
        "output = \"out.exe\"\n"
        "[[functions]]\n"
        "name = \"\"\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_FALSE(result.ok);
    EXPECT_TRUE(contains(result.error, "name"));
}

TEST(ConfigParse, CryptNonBoolFails) {
    const TempToml toml(
        "input  = \"target.exe\"\n"
        "output = \"out.exe\"\n"
        "[[functions]]\n"
        "rva = 1\n"
        "crypt = \"yes\"\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_FALSE(result.ok);
    EXPECT_TRUE(contains(result.error, "crypt"));
}

TEST(ConfigParse, MutateJunkDensityParses) {
    const TempToml toml(
        "input  = \"target.exe\"\n"
        "output = \"out.exe\"\n"
        "[mutate]\n"
        "density = 20\n"
        "junk_density = 40\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_TRUE(result.ok) << result.error;
    EXPECT_TRUE(result.value.rules.has_mutate_junk_density);
    EXPECT_EQ(result.value.rules.mutate_junk_density, 40u);
}

TEST(ConfigParse, MutateJunkDensityZeroOk) {
    const TempToml toml(
        "input  = \"target.exe\"\n"
        "output = \"out.exe\"\n"
        "[mutate]\n"
        "density = 10\n"
        "junk_density = 0\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_TRUE(result.ok) << result.error;
    EXPECT_EQ(result.value.rules.mutate_junk_density, 0u);
}

TEST(ConfigParse, MutateJunkDensityOutOfRangeFails) {
    const TempToml toml(
        "input  = \"target.exe\"\n"
        "output = \"out.exe\"\n"
        "[mutate]\n"
        "density = 10\n"
        "junk_density = 101\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_FALSE(result.ok);
    EXPECT_TRUE(contains(result.error, "junk_density"));
}

TEST(ConfigParse, MutateJunkDensityNonIntFails) {
    const TempToml toml(
        "input  = \"target.exe\"\n"
        "output = \"out.exe\"\n"
        "[mutate]\n"
        "density = 10\n"
        "junk_density = \"lots\"\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_FALSE(result.ok);
    EXPECT_TRUE(contains(result.error, "junk_density"));
}

TEST(ConfigParse, ImportSkipBackfillParses) {
    const TempToml toml(
        "input  = \"target.exe\"\n"
        "output = \"out.exe\"\n"
        "[import]\n"
        "skip_backfill = true\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_TRUE(result.ok) << result.error;
    EXPECT_TRUE(result.value.rules.has_import_skip_backfill);
    EXPECT_TRUE(result.value.rules.import_skip_backfill);
}

TEST(ConfigParse, ImportUnknownSubkeyFails) {
    const TempToml toml(
        "input  = \"target.exe\"\n"
        "output = \"out.exe\"\n"
        "[import]\n"
        "skip = true\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_FALSE(result.ok);
    EXPECT_TRUE(contains(result.error, "skip_backfill"));
}

TEST(ConfigParse, ImportNonBoolFails) {
    const TempToml toml(
        "input  = \"target.exe\"\n"
        "output = \"out.exe\"\n"
        "[import]\n"
        "skip_backfill = \"yes\"\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_FALSE(result.ok);
    EXPECT_TRUE(contains(result.error, "skip_backfill"));
}

TEST(ConfigParse, MixedSelectorPairStillRejected) {
    const TempToml toml(
        "input  = \"target.exe\"\n"
        "output = \"out.exe\"\n"
        "[[functions]]\n"
        "name = \"x\"\n"
        "rva = 2\n");
    const auto result = wvmp::cli::parse_config(toml.path());
    ASSERT_FALSE(result.ok);
    EXPECT_TRUE(contains(result.error, "只能选其一"));
}
