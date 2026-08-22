#include "wvmp/passes/pe_loader/pe_loader_pass.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/registry.hpp"
#include "wvmp/passes/pe_loader/pe_image.hpp"

#include <fstream>
#include <stdexcept>
#include <string>
#include <utility>

namespace wvmp::passes {

std::span<const std::string_view> PeLoaderPass::provides_keys() const {
    static constexpr std::string_view kProvides[] = {kImage};
    return kProvides;
}

void PeLoaderPass::run(ProtectionContext& ctx) {
    // 统一的失败路径：diag 记 Error，再抛 std::runtime_error 中断流水线。
    const auto fail = [this](ProtectionContext& c, std::string msg) {
        c.diag.report(Severity::Error, name(), msg);
        throw std::runtime_error(std::string(name()) + ": " + std::move(msg));
    };

    // 1) 二进制读入输入文件。
    std::ifstream in(ctx.input_path, std::ios::binary);
    if (!in) fail(ctx, "无法打开输入文件: " + ctx.input_path.string());
    in.seekg(0, std::ios::end);
    const std::streamoff end = in.tellg();
    if (end < 0) fail(ctx, "无法确定输入文件大小: " + ctx.input_path.string());
    in.seekg(0, std::ios::beg);
    ctx.image.resize(static_cast<size_t>(end));
    if (!ctx.image.empty()) {
        in.read(reinterpret_cast<char*>(ctx.image.data()),
                static_cast<std::streamsize>(ctx.image.size()));
        if (in.gcount() != static_cast<std::streamsize>(ctx.image.size()))
            fail(ctx, "输入文件读取不完整（短读）: " + ctx.input_path.string());
    }
    if (ctx.image.empty()) fail(ctx, "输入文件为空: " + ctx.input_path.string());

    // 2) 解析 PE 结构（MZ / e_lfanew / PE 签名 / Machine / 可选头 / 节表）。
    try {
        PeImage img = parse_pe_image(ctx.image);
        // 3) 解析模型入扩展槽，供下游 pass（marker_scan/lifter/pe_writer）使用。
        ctx.slot<PeImage>(kImageMeta) = std::move(img);
    } catch (const PeParseError& e) {
        fail(ctx, e.what());
    }
}

WVMP_REGISTER_PASS(PeLoaderPass)

} // namespace wvmp::passes
