// wvmp CLI 参数解析（P8 泳道）。
//
// 从 main() 拆出来以便单测：parse_args(argv) 只做词法层面的解析，
// 不碰文件系统。argv[0] 为程序名，跳过。
//
// 用法：
//   wvmp protect --config <file> [-o <output>] [--dry-run]
//   wvmp version
#pragma once

#include <string>

namespace wvmp::cli {

struct ArgsResult {
    bool ok = false;
    bool is_version = false;     // 子命令 version
    std::string config_path;     // protect: --config 的值
    std::string output_override; // protect: -o 的值（空 = 不覆盖）
    bool dry_run = false;        // protect: --dry-run
    std::string error;           // 失败描述（含 usage，可直接打印）
};

ArgsResult parse_args(int argc, const char* const argv[]);

} // namespace wvmp::cli
