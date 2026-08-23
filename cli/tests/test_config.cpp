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
        "name_unused = \"被忽略的额外键\"\n"
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

} // namespace
