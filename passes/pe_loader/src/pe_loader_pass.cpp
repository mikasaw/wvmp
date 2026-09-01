#include "wvmp/passes/pe_loader/pe_loader_pass.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/registry.hpp"
#include "wvmp/passes/pe_loader/pe_image.hpp"
#include "wvmp/passes/pe_loader/target_arch.hpp"

#include <fstream>
#include <stdexcept>
#include <string>
#include <utility>

namespace wvmp::passes {
namespace {

// IMAGE_FILE_MACHINE_I386（x86 32 位目标）。MIT-446 (X4) D1 起 x86 通行
// （auto / 显式 arch=x86 双形），mismatch（arch=x64）维持硬拒。
constexpr u16 kMachineX86 = 0x014C;

} // namespace

std::span<const std::string_view> PeLoaderPass::provides_keys() const {
    static constexpr std::string_view kProvides[] = {kImage, kPeImage};
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
        // 2.5) MIT-414 (G7p2 B.2) 引入 x86 machine gate；MIT-446 (X4) D1
        // 拍板解禁：x86 (machine=0x014C) 通行——auto（槽缺省）与显式
        // arch=x86 双形放行，x86 全管道（marker_scan 双段 magic / lifter
        // pointer_size / translator / runtime_x86 / stub_link cdecl）自本单
        // 起承接 PE32 输入。声明不符（arch=x64 + machine=0x014C）维持硬拒；
        // lifter/translator 未支持形在 x86 真管道下全部走既有 C1 gate
        // （x87=R-SSE-only 定稿面：含 x87 指令的标记函数整函数 gate 原生）。
        // 解析本身双架构无害（gate 在解析后，§F #2）。
        if (img.machine == kMachineX86) {
            // 2.55) MIT-438 (X1b) B.5: CLI arch 声明校验挂点。槽缺省（直接
            // 管道调用/单测）= Auto → machine 推导通行。
            if (const u8* decl = ctx.find_slot<u8>(kTargetArchDecl); decl != nullptr) {
                if (*decl == kTargetArchX64) {
                    ctx.diag.report(Severity::Error, name(),
                                    "config arch=x64 与目标 machine=0x014C (x86) 不符; "
                                    "不产出保护壳");
                    throw std::runtime_error(std::string(name()) +
                                             ": config arch=x64 与目标不符");
                }
            }
        }
        // 2.6) MIT-438 (X1b) B.5: x64 machine 上的声明校验（MIT-446 (X4)
        // 起明确限定 machine != x86——x86 machine 已在 2.5 分叉，x86 声明
        // 匹配象限放行，不再落入本块）。x86 声明 + x64 machine → rc=2 显式
        // 拒；槽缺省 / Auto / X64 → 常规 x64 路径（现状行为不变）。
        if (img.machine != kMachineX86) {
            if (const u8* decl = ctx.find_slot<u8>(kTargetArchDecl);
                decl != nullptr && *decl == kTargetArchX86) {
                ctx.diag.report(Severity::Error, name(),
                                "config arch=x86 与目标 machine=0x8664 (x64) 不符; "
                                "不产出保护壳");
                throw std::runtime_error(std::string(name()) +
                                         ": config arch=x86 与目标不符");
            }
        }
        // 3) 解析模型入扩展槽，供下游 pass（marker_scan/lifter/pe_writer）使用。
        ctx.slot<PeImage>(kImageMeta) = std::move(img);
    } catch (const PeParseError& e) {
        fail(ctx, e.what());
    }
}

WVMP_REGISTER_PASS(PeLoaderPass)

} // namespace wvmp::passes
