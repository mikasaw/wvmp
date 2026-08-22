#include "wvmp/cli/config.hpp"

#include <toml++/toml.hpp>

#include <cstdint>
#include <system_error>

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

} // namespace

ConfigResult parse_config(const std::filesystem::path& file) {
    ConfigResult result;

    std::error_code ec;
    if (!std::filesystem::exists(file, ec)) {
        result.error = "config 文件不存在: " + file.string();
        return result;
    }

    toml::table tbl;
    try {
        tbl = toml::parse_file(file.string());
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
