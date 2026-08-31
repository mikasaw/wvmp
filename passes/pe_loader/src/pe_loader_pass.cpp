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

// IMAGE_FILE_MACHINE_I386（x86 32 位目标）。解析层白名单仍接受（解析本身
// 无害，诊断信息可读），门在 pass 层落下。
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
        // 2.5) MIT-414 (G7p2 B.2): x86 (machine=0x014C) 显式 gate —— 硬失败
        // 语义（派活单 D1：非零退出 + ERROR diag，不做"尽力而为静默透传"）。
        // 解析本身双架构无害（gate 在解析后，§F #2）；但继续跑下游只会两态：
        // SDK magic 不连续 → 静默无操作（用户以为受保护）；手造连续锚点 →
        // x64 管道（asmgen/stub_gen 硬编码 KS_MODE_64 + Win64 ABI）在 32 位
        // PE 上覆写 .text 产出 WinError 193 坏壳（triage §3.2/§3.3 实测）。
        // x86 全量对齐 = P1 backlog（G7x-1..8），本单只收安全拒绝面。
        if (img.machine == kMachineX86) {
            // 2.55) MIT-438 (X1b) B.5: CLI arch 声明校验挂点（x86 面先行分叉，
            // 消息与 Auto 的 C5 语义区分）。槽缺省（直接管道调用/单测）= Auto。
            if (const u8* decl = ctx.find_slot<u8>(kTargetArchDecl); decl != nullptr) {
                if (*decl == kTargetArchX86) {
                    // 声明与目标匹配，但 x86 通行未解禁 (D1: X4 收口单拍板)。
                    ctx.diag.report(Severity::Error, name(),
                                    "config arch=x86 与目标 machine=0x014C 匹配, "
                                    "但 x86 通行未解禁 (D1); 不产出保护壳");
                    throw std::runtime_error(std::string(name()) +
                                             ": config arch=x86 通行未解禁");
                }
                if (*decl == kTargetArchX64) {
                    ctx.diag.report(Severity::Error, name(),
                                    "config arch=x64 与目标 machine=0x014C (x86) 不符; "
                                    "不产出保护壳");
                    throw std::runtime_error(std::string(name()) +
                                             ": config arch=x64 与目标不符");
                }
            }
            ctx.diag.report(Severity::Error, name(),
                            "32 位目标 (x86) 未支持 (GAPS C5); 不产出保护壳");
            throw std::runtime_error(std::string(name()) + ": 32 位目标 (x86) 未支持");
        }
        // 2.6) MIT-438 (X1b) B.5: x64 machine 上的声明校验。x86 声明（匹配亦
        // 未解禁 / 声明与目标不符）→ rc=2 显式拒；槽缺省 / Auto / X64 → 常规
        // x64 路径（现状行为不变）。
        if (const u8* decl = ctx.find_slot<u8>(kTargetArchDecl);
            decl != nullptr && *decl == kTargetArchX86) {
            ctx.diag.report(Severity::Error, name(),
                            "config arch=x86 与目标 machine=0x8664 (x64) 不符; "
                            "不产出保护壳");
            throw std::runtime_error(std::string(name()) +
                                     ": config arch=x86 与目标不符");
        }
        // 3) 解析模型入扩展槽，供下游 pass（marker_scan/lifter/pe_writer）使用。
        ctx.slot<PeImage>(kImageMeta) = std::move(img);
    } catch (const PeParseError& e) {
        fail(ctx, e.what());
    }
}

WVMP_REGISTER_PASS(PeLoaderPass)

} // namespace wvmp::passes
