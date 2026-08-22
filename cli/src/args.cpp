#include "wvmp/cli/args.hpp"

#include <string_view>

namespace wvmp::cli {
namespace {

constexpr std::string_view kUsage =
    "usage:\n"
    "  wvmp protect --config <file> [-o <output>] [--dry-run]\n"
    "  wvmp version";

ArgsResult fail(std::string error) {
    ArgsResult result;
    result.ok = false;
    result.error = std::move(error);
    result.error += "\n";
    result.error += kUsage;
    return result;
}

ArgsResult parse_protect(int argc, const char* const argv[], int first_flag) {
    ArgsResult result;
    for (int i = first_flag; i < argc; ++i) {
        const std::string_view arg = argv[i];
        if (arg == "--config") {
            if (i + 1 >= argc)
                return fail("--config 需要一个参数（TOML 配置文件路径）");
            result.config_path = argv[++i];
        } else if (arg == "-o") {
            if (i + 1 >= argc)
                return fail("-o 需要一个参数（输出路径，覆盖配置里的 output）");
            result.output_override = argv[++i];
        } else if (arg == "--dry-run") {
            result.dry_run = true;
        } else if (arg.starts_with('-')) {
            return fail("未知选项 '" + std::string(arg) + "'");
        } else {
            return fail("多余的位置参数 '" + std::string(arg) + "'（protect 不接受）");
        }
    }
    if (result.config_path.empty())
        return fail("protect 需要 --config <file>");
    result.ok = true;
    return result;
}

} // namespace

ArgsResult parse_args(int argc, const char* const argv[]) {
    if (argc < 2)
        return fail("缺少子命令");
    const std::string_view sub = argv[1];
    if (sub == "version") {
        if (argc > 2)
            return fail("version 不接受额外参数: '" + std::string(argv[2]) + "'");
        ArgsResult result;
        result.ok = true;
        result.is_version = true;
        return result;
    }
    if (sub == "protect")
        return parse_protect(argc, argv, 2);
    return fail("未知子命令 '" + std::string(sub) + "'");
}

} // namespace wvmp::cli
