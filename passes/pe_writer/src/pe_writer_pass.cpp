#include "wvmp/passes/pe_writer/pe_writer_pass.hpp"

#include "pe_checksum.hpp"

#include "wvmp/common/bytes.hpp"
#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/registry.hpp"
#include "wvmp/passes/pe_loader/pe_image.hpp"

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <system_error>

namespace wvmp::passes {
namespace {

// OptionalHeader.CheckSum 固定位于可选头 +64（PE32 与 PE32+ 相同），
// 即 NT 头偏移 + 4(签名) + 20(FILE_HEADER) + 64。
constexpr size_t kChecksumOffsetInOpt = 64;
constexpr size_t kNtPrefix = 4 + 20;

} // namespace

std::span<const std::string_view> PeWriterPass::requires_keys() const {
    static constexpr std::string_view kRequires[] = {kImage};
    return kRequires;
}

void PeWriterPass::run(ProtectionContext& ctx) {
    // 统一的失败路径：diag 记 Error，再抛 std::runtime_error 中断流水线。
    const auto fail = [this](ProtectionContext& c, std::string msg) {
        c.diag.report(Severity::Error, name(), msg);
        throw std::runtime_error(std::string(name()) + ": " + std::move(msg));
    };

    if (ctx.image.empty()) fail(ctx, "镜像为空，没有可写出的内容");
    if (ctx.output_path.empty()) fail(ctx, "输出路径为空");

    // 1) 定位 NT 头：优先用 pe_loader 存入的模型；缺失（镜像来自其他
    //    来源 / 中途被整体替换）时对当前镜像现场重解析。
    u32 nt_off = 0;
    if (const PeImage* meta = ctx.find_slot<PeImage>(kImageMeta)) {
        nt_off = meta->nt_headers_offset;
    } else {
        try {
            nt_off = parse_pe_image(ctx.image).nt_headers_offset;
        } catch (const PeParseError& e) {
            fail(ctx, std::string("输出前重解析 PE 失败: ") + e.what());
        }
    }
    const size_t chk_off = size_t(nt_off) + kNtPrefix + kChecksumOffsetInOpt;
    if (chk_off + 4 > ctx.image.size())
        fail(ctx, "CheckSum 字段越界（nt_headers_offset=" + std::to_string(nt_off) + "）");
    if (chk_off % 2 != 0)
        fail(ctx, "CheckSum 字段未按 u16 对齐（nt_headers_offset=" + std::to_string(nt_off) + "）");

    // 2) 重算 PE checksum：清零 → 标准算法（u16 累加 + 文件总长）→ patch
    //    回 ctx.image（输出文件由镜像写出，随之携带新 checksum）。
    ByteWriter w(ctx.image);
    w.patch_u32(chk_off, 0);
    w.patch_u32(chk_off, pe_checksum(ctx.image, chk_off));

    // 3) TODO(M2): add .wvmp section（附加节表项 + 重排镜像，属 Transform 阶段职责）

    // 4) 临时文件 + rename 原子替换，防止半写文件暴露给用户。
    std::filesystem::path tmp = ctx.output_path;
    tmp += ".wvmp-tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) fail(ctx, "无法创建输出文件: " + tmp.string());
        out.write(reinterpret_cast<const char*>(ctx.image.data()),
                  static_cast<std::streamsize>(ctx.image.size()));
        out.flush();
        if (!out) fail(ctx, "输出文件写入不完整: " + tmp.string());
    }
    std::error_code ec;
    std::filesystem::remove(ctx.output_path, ec); // 部分平台 rename 不覆盖既有目标
    ec.clear();
    std::filesystem::rename(tmp, ctx.output_path, ec);
    if (ec) {
        std::error_code cleanup;
        std::filesystem::remove(tmp, cleanup);
        fail(ctx, "输出文件重命名失败 (" + ec.message() + "): " + tmp.string());
    }
}

WVMP_REGISTER_PASS(PeWriterPass)

} // namespace wvmp::passes
