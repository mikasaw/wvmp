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
            result.value.passes.push_back(PassConfig{*name});
            ++index;
        }
    }

    result.ok = true;
    return result;
}

} // namespace wvmp::cli
