#include "wvmp/passes/pe_writer/pe_writer_pass.hpp"

#include "pe_checksum.hpp"
#include "section_builder.hpp"

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
#include <vector>

namespace wvmp::passes {
namespace {

// OptionalHeader.CheckSum 固定位于可选头 +64（PE32 与 PE32+ 相同），
// 即 NT 头偏移 + 4(签名) + 20(FILE_HEADER) + 64。
constexpr size_t kChecksumOffsetInOpt = 64;
constexpr size_t kNtPrefix = 4 + 20;

// DllCharacteristics 位于 OptionalHeader +0x46 (PE32+/PE32 相同, 在 Subsystem
// +0x02 处). 绝对偏移 = nt_off (PE 签名 4 + FILE_HEADER 20) + 0x46 = nt_off + 0x5e.
// IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x40 (ASLR 标志). M2-8 起 rip-relative
// 翻译期把 [rip+disp] 转 RVA, 运行时经 LoadRva/StoreRva + VmContext.scratch_mem
// (=image_base) 还原 VA. Windows ASLR 把 image 重新定位到随机基址, 但 stub
// 只知道 PE.ImageBase（写入 scratch_mem）— 二者不等 → 访存错位 → 段错误。
// 简化方案（M2-8 局限）：保护后清除 DYNAMIC_BASE 标志，强制 Windows 加载到
// ImageBase 声明位置. 完整 ASLR 兼容需要 stub 在运行时通过 PE 重定位 / GetModuleHandle
// 取真实基址——M2-9+ 排期。
constexpr size_t kDllCharsOffsetFromNt = 0x5e;  // 4 (签名) + 20 (FILE_HEADER) + 0x46 (opt)
constexpr u16 kImageDllCharacteristicsDynamicBase = 0x0040;

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

    // 1) 落位新节（kNewSections 槽；stub_link 等 Emit 阶段产出）——必须在
    //    checksum 之前，校验失败则整体失败（镜像不被部分修改）。
    if (auto* new_sections = ctx.find_slot<std::vector<NewSection>>(kNewSections);
        new_sections != nullptr && !new_sections->empty()) {
        u32 sec_align = 0x1000, file_align = 0x200; // PE 规范默认值兜底
        if (const PeImage* meta = ctx.find_slot<PeImage>(kImageMeta)) {
            sec_align = meta->section_alignment != 0 ? meta->section_alignment : sec_align;
            file_align = meta->file_alignment != 0 ? meta->file_alignment : file_align;
        }
        try {
            const auto placed = add_sections(ctx.image, *new_sections, sec_align, file_align);
            ctx.diag.report(Severity::Note, name(),
                            "已追加 " + std::to_string(placed.size()) + " 个新节");
        } catch (const std::exception& e) {
            fail(ctx, std::string("追加新节失败: ") + e.what());
        }
        // 节表变化后 NT 头偏移不变（只动表项与文件尾），但保险起见重取模型
        // 中的对齐/偏移用于后续 checksum。
    }

    // 2) 定位 NT 头：优先用 pe_loader 存入的模型；缺失（镜像来自其他
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

    // 2.5) M2-8: 清除 DllCharacteristics.DYNAMIC_BASE (ASLR) — 仅在确实虚拟化
    //   时（有 stub 产出）才需要. 没虚拟化的镜像保持原状（PE-writer 单元测试
    //   往返断言要求 byte-identical）。
    //   见 kDllCharsOffsetFromNt 注释——stub_link 写入 scratch_mem 用
    //   PE.ImageBase, ASLR 重定位后不等于实际基址, 全局读写越界段错.
    const auto* new_sections_check = ctx.find_slot<std::vector<NewSection>>(kNewSections);
    const bool has_stub = new_sections_check != nullptr && !new_sections_check->empty();
    if (has_stub &&
        nt_off + kDllCharsOffsetFromNt + 2 <= ctx.image.size()) {
        const u16 old_dll =
            static_cast<u16>(static_cast<u16>(ctx.image[nt_off + kDllCharsOffsetFromNt]) |
                            (static_cast<u16>(ctx.image[nt_off + kDllCharsOffsetFromNt + 1]) << 8));
        const u16 new_dll = static_cast<u16>(old_dll & ~kImageDllCharacteristicsDynamicBase);
        if (new_dll != old_dll) {
            ctx.image[nt_off + kDllCharsOffsetFromNt] = static_cast<u8>(new_dll & 0xFF);
            ctx.image[nt_off + kDllCharsOffsetFromNt + 1] = static_cast<u8>((new_dll >> 8) & 0xFF);
            ctx.diag.report(Severity::Note, name(),
                            "M2-8: 已清除 DllCharacteristics.DYNAMIC_BASE (ASLR)，强制镜像加载到 ImageBase 声明位置（stub scratch_mem 兼容性）");
            // checksum 含 DllCharacters, 重新计算.
            ByteWriter w2(ctx.image);
            w2.patch_u32(chk_off, 0);
            w2.patch_u32(chk_off, pe_checksum(ctx.image, chk_off));
        }
    }

    // 3) 临时文件 + rename 原子替换，防止半写文件暴露给用户。
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
