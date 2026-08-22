// wvmp 命令行入口（P8 泳道）。
//
// 子命令：
//   wvmp protect --config <file> [-o <output>] [--dry-run]
//   wvmp version
//
// 退出码约定：
//   0  成功（dry-run 打印管道后退出也走这里）
//   1  参数 / 配置 / 管道装配错误（含 from_names 抛错：未知 pass、依赖缺失）
//   2  管道运行期失败（run 抛错；diag 尾部会打印到 stderr）

#include "wvmp/cli/args.hpp"
#include "wvmp/cli/config.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/diagnostics.hpp"
#include "wvmp/framework/pass.hpp"
#include "wvmp/framework/phase.hpp"
#include "wvmp/framework/pipeline.hpp"

#include <cstdio>
#include <exception>
#include <string>
#include <vector>

namespace {

// 与根 CMakeLists 的 project(wvmp VERSION 0.1.0) 保持一致。
constexpr char kVersion[] = "wvmp 0.1.0";

const char* severity_tag(wvmp::Severity s) {
    switch (s) {
    case wvmp::Severity::Note: return "note";
    case wvmp::Severity::Warning: return "warning";
    case wvmp::Severity::Error: return "error";
    }
    return "?";
}

void print_diag_item(const wvmp::Diagnostic& d) {
    std::fprintf(stderr, "[wvmp] [%s] %s: %s\n", severity_tag(d.severity),
                 d.pass.c_str(), d.message.c_str());
}

// run 失败时打印诊断尾部（最后 5 条，含 pass 名，便于定位是谁抛的）。
void print_diag_tail(const wvmp::Diagnostics& diag) {
    const auto& items = diag.items();
    if (items.empty()) return;
    const size_t first = items.size() > 5 ? items.size() - 5 : 0;
    std::fprintf(stderr, "[wvmp] ---- 诊断尾部 ----\n");
    for (size_t i = first; i < items.size(); ++i) print_diag_item(items[i]);
}

// 成功时打印 pass 留下的 Note / Warning（Error 不该出现在这里）。
void print_diag_notes(const wvmp::Diagnostics& diag) {
    for (const auto& d : diag.items())
        if (d.severity != wvmp::Severity::Error) print_diag_item(d);
}

// 按 stages() 的实际顺序（已按 Phase 排好序）渲染：
//   Load: pe_loader → Analyze: marker_scan, lifter → Transform: virtualize → Write: pe_writer
std::string describe_pipeline(const wvmp::Pipeline& pipe) {
    const auto& stages = pipe.stages();
    std::string out = "将执行的管道：";
    for (size_t i = 0; i < stages.size(); ++i) {
        const bool new_phase = i == 0 || stages[i]->phase() != stages[i - 1]->phase();
        if (new_phase) {
            if (i != 0) out += " → ";
            out += std::string(wvmp::to_string(stages[i]->phase())) + ": ";
        } else {
            out += ", ";
        }
        out += std::string(stages[i]->name());
    }
    if (stages.empty()) out += "(空管道)";
    return out;
}

int cmd_version() {
    std::puts(kVersion);
    return 0;
}

int cmd_protect(const wvmp::cli::ArgsResult& args) {
    // 1) 配置。
    const wvmp::cli::ConfigResult cfg = wvmp::cli::parse_config(args.config_path);
    if (!cfg.ok) {
        std::fprintf(stderr, "[wvmp] %s\n", cfg.error.c_str());
        return 1;
    }
    const wvmp::cli::WvmpConfig& config = cfg.value;

    std::string output = config.output;
    if (!args.output_override.empty()) output = args.output_override;

    // 2) 装配管道（未知名 / 依赖缺失在 from_names 里抛）。
    std::vector<std::string> names;
    names.reserve(config.passes.size());
    for (const auto& p : config.passes) names.push_back(p.name);

    wvmp::Pipeline pipeline;
    try {
        pipeline = wvmp::Pipeline::from_names(names);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[wvmp] %s\n", e.what());
        return 1;
    }

    // 3) 打印任务摘要（dry-run 与真实执行共用）。
    std::printf("[wvmp] input : %s\n", config.input.c_str());
    std::printf("[wvmp] output: %s%s\n", output.c_str(),
                output != config.output ? "（-o 覆盖）" : "");
    std::printf("[wvmp] seed  : %llu\n", static_cast<unsigned long long>(config.seed));
    std::printf("[wvmp] %s\n", describe_pipeline(pipeline).c_str());

    if (args.dry_run) {
        std::puts("[wvmp] dry-run：仅装配，未执行。");
        return 0;
    }

    // 4) 真实执行。
    wvmp::ProtectionContext ctx;
    ctx.input_path = config.input;
    ctx.output_path = output;
    ctx.seed = config.seed;
    ctx.rng.reseed(config.seed);

    try {
        pipeline.run(ctx);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[wvmp] 管道执行失败: %s\n", e.what());
        print_diag_tail(ctx.diag);
        return 2;
    }

    // M1 决策（P8 遗留项）：run 正常返回但 diag 含 Error 级条目时视为失败——
    // "没抛但报过错"的 pass 不应被静默放过。
    if (ctx.diag.has_errors()) {
        std::fprintf(stderr, "[wvmp] 管道完成但诊断含 %zu 条 Error：\n",
                     ctx.diag.items().size());
        print_diag_tail(ctx.diag);
        return 2;
    }

    print_diag_notes(ctx.diag);
    std::printf("[wvmp] 完成: %s -> %s\n", config.input.c_str(), output.c_str());
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    const wvmp::cli::ArgsResult args = wvmp::cli::parse_args(argc, argv);
    if (!args.ok) {
        std::fprintf(stderr, "[wvmp] %s\n", args.error.c_str());
        return 1;
    }
    if (args.is_version) return cmd_version();
    return cmd_protect(args);
}
