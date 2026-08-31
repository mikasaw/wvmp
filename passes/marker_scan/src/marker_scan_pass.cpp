#include "wvmp/passes/marker_scan/marker_scan_pass.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/registry.hpp"
#include "wvmp/ir/region.hpp"
#include "wvmp/passes/marker_scan/scan_core.hpp"
#include "wvmp/passes/pe_loader/pe_image.hpp"

#include <algorithm>
#include <cstdio>
#include <span>
#include <string>
#include <vector>

namespace wvmp::passes {
namespace {
namespace ms = marker_scan;

// —— 泳道内部最小 PE 节表解析（只读，仅用于把 E8 扫描限定在可执行节）——
// TODO(M1-integration): 与 pe_loader 的完整解析/节表元数据合并；并在此处
// 补上区域文件偏移 → RVA 的换算（当前 FunctionRegion 的 begin_rva/end_rva
// 存的是文件偏移）。
struct RawRange {
    size_t lo = 0, hi = 0;
};

// IMAGE_FILE_MACHINE_I386（x86）。x86 全量支持在 P1 backlog，此处仅用于把
// fr.arch 从 PeImage.machine 推导出来（MIT-414 G7p2 B.3，为未来 P1 铺路；
// x64 路径恒 X64，零行为变化）。
constexpr u16 kMachineX86 = 0x014C;

u16 rd16(const u8* p) {
    return static_cast<u16>(static_cast<u16>(p[0]) | (static_cast<u16>(p[1]) << 8));
}
u32 rd32(const u8* p) {
    return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) |
           (static_cast<u32>(p[2]) << 16) | (static_cast<u32>(p[3]) << 24);
}

// 返回所有可执行节的文件偏移范围；解析失败返回空（调用方退化为全镜像扫描）。
std::vector<RawRange> executable_ranges(std::span<const u8> img) {
    constexpr u32 kScnCntCode = 0x0000'0020;
    constexpr u32 kScnMemExecute = 0x2000'0000;
    std::vector<RawRange> ranges;
    if (img.size() < 0x40) return ranges;
    const size_t lfanew = rd32(&img[0x3C]);
    if (lfanew + 24 > img.size()) return ranges;
    if (rd32(&img[lfanew]) != 0x0000'4550) return ranges; // "PE\0\0"
    const u16 num_sections = rd16(&img[lfanew + 6]);      // FILE_HEADER.NumberOfSections
    const u16 opt_size = rd16(&img[lfanew + 20]);         // FILE_HEADER.SizeOfOptionalHeader
    const size_t sec_base = lfanew + 24 + opt_size;
    if (sec_base + static_cast<size_t>(num_sections) * 40 > img.size()) return ranges;
    for (u16 i = 0; i < num_sections; ++i) {
        const size_t sh = sec_base + static_cast<size_t>(i) * 40;
        const u32 raw_size = rd32(&img[sh + 16]); // SizeOfRawData
        const u32 raw_ptr = rd32(&img[sh + 20]);  // PointerToRawData
        const u32 chars = rd32(&img[sh + 36]);    // Characteristics
        if ((chars & (kScnCntCode | kScnMemExecute)) == 0) continue;
        if (raw_ptr == 0 || raw_size == 0) continue;
        const size_t lo = raw_ptr;
        const size_t hi = std::min<size_t>(lo + raw_size, img.size());
        if (lo < hi) ranges.push_back(RawRange{lo, hi});
    }
    return ranges;
}

std::string hex_off(size_t v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%zx", v);
    return buf;
}

} // namespace

std::span<const std::string_view> MarkerScanPass::requires_keys() const {
    static constexpr std::string_view kRequires[] = {kImage, kPeImage};
    return kRequires;
}

std::span<const std::string_view> MarkerScanPass::provides_keys() const {
    static constexpr std::string_view kProvides[] = {kFunctions};
    return kProvides;
}

void MarkerScanPass::run(ProtectionContext& ctx) {
    const std::span<const u8> image(ctx.image);
    if (image.empty()) {
        ctx.diag.report(Severity::Warning, "marker_scan", "镜像为空，跳过标记扫描");
        return;
    }

    // 0) PeImage 提前取出：x86 (machine=0x014C) 走双段 magic 识别（X1a）。
    const PeImage* pe = ctx.find_slot<PeImage>(kPeImage);
    const bool is_x86 = pe != nullptr && pe->machine == kMachineX86;

    // 1) 定位两个桩函数体的 magic（各应恰好 1 处；缺失/多处只告警并继续）。
    //    x64：imm64 连续 8 字节 needle。x86（X1a）：SDK 桩把 magic 拆成两条
    //    imm32（/O1 /O2 lo→hi 紧邻、/Od hi→lo 间隔 3B，实测形态见
    //    scan_core.hpp），用双段识别；PeImage 缺失（泳道单测直接构造
    //    context）沿用 x64 路径，行为不变。
    const auto begin_hits = is_x86 ? ms::find_all_x86(image, ms::kBeginPatternX86)
                                   : ms::find_all(image, ms::kBeginPattern);
    const auto end_hits = is_x86 ? ms::find_all_x86(image, ms::kEndPatternX86)
                                 : ms::find_all(image, ms::kEndPattern);
    if (begin_hits.empty())
        ctx.diag.report(Severity::Warning, "marker_scan",
                        "begin 桩 magic 未找到（SDK 未链接进目标？）");
    if (end_hits.empty())
        ctx.diag.report(Severity::Warning, "marker_scan",
                        "end 桩 magic 未找到（SDK 未链接进目标？）");
    if (begin_hits.size() > 1)
        ctx.diag.report(Severity::Warning, "marker_scan",
                        "begin 桩 magic 出现 " + std::to_string(begin_hits.size()) +
                            " 处（期望 1），全部按候选锚点继续");
    if (end_hits.size() > 1)
        ctx.diag.report(Severity::Warning, "marker_scan",
                        "end 桩 magic 出现 " + std::to_string(end_hits.size()) +
                            " 处（期望 1），全部按候选锚点继续");

    // 2) 在可执行节中枚举 E8 rel32（节表解析失败退化为整个镜像）。
    //    TODO(P7-opts): O2 下尾调用会被编成 E9 jmp（不产生 E8），v1 不覆盖。
    auto ranges = executable_ranges(image);
    if (ranges.empty()) ranges.push_back(RawRange{0, image.size()});
    std::vector<ms::CallRef> calls;
    for (const auto& r : ranges) {
        auto sub = ms::scan_calls(image.subspan(r.lo, r.hi - r.lo), r.lo);
        calls.insert(calls.end(), sub.begin(), sub.end());
    }
    std::sort(calls.begin(), calls.end(),
              [](const ms::CallRef& a, const ms::CallRef& b) { return a.insn_off < b.insn_off; });

    // 3) 调用点排他归属：桩入口必位于其 magic 之前，故每个 E8 目标归属
    //    "紧随其后（≤ kStubWindow）的第一个 magic"的桩。begin/end 两桩在
    //    同一 sdk.cpp 中通常相邻，朴素的双向 ±64 窗口会互相串扰，此规则
    //    天然排他。误报率：随机 E8 恰好命中 magic 前 64B 的概率
    //    ~64/2^32/条，可忽略。
    std::vector<ms::Anchor> anchors;
    anchors.reserve(begin_hits.size() + end_hits.size());
    for (size_t off : begin_hits) anchors.push_back(ms::Anchor{off, true});
    for (size_t off : end_hits) anchors.push_back(ms::Anchor{off, false});
    std::sort(anchors.begin(), anchors.end(),
              [](const ms::Anchor& a, const ms::Anchor& b) { return a.magic_off < b.magic_off; });
    auto marker_calls = ms::attribute_marker_calls(calls, anchors, ms::kStubWindow);
    auto begin_nexts = std::move(marker_calls.begin_nexts);
    auto end_addrs = std::move(marker_calls.end_addrs);
    std::sort(begin_nexts.begin(), begin_nexts.end());
    begin_nexts.erase(std::unique(begin_nexts.begin(), begin_nexts.end()), begin_nexts.end());
    std::sort(end_addrs.begin(), end_addrs.end());
    end_addrs.erase(std::unique(end_addrs.begin(), end_addrs.end()), end_addrs.end());

    // 4) 配对 begin/end 调用点 → 保护区域；未配对告警。
    auto paired = ms::pair_regions(std::move(begin_nexts), std::move(end_addrs));
    for (size_t b : paired.unmatched_begins)
        ctx.diag.report(Severity::Warning, "marker_scan",
                        "begin@0x" + hex_off(b) + " 没有配对的 end（区域被丢弃）");
    for (size_t e : paired.unmatched_ends)
        ctx.diag.report(Severity::Warning, "marker_scan",
                        "end@0x" + hex_off(e) + " 没有配对的 begin（区域被丢弃）");

    // 5) 每对区域生成一个 FunctionRegion（M1：文件偏移 → RVA 统一换算）。
    //    PeImage 缺失时（如泳道单测直接构造 context）退化为保持文件偏移并
    //    记 Note，不失败。
    if (pe == nullptr)
        ctx.diag.report(Severity::Note, "marker_scan",
                        "PeImage 模型缺失（pe_loader 未运行？），区域保持文件偏移");
    auto to_rva = [&](size_t off, const char* what, const std::string& name) -> u64 {
        if (pe == nullptr) return off;
        const auto rva = pe->offset_to_rva(off);
        if (!rva.has_value()) {
            ctx.diag.report(Severity::Warning, "marker_scan",
                            name + " 的 " + what + " 偏移 0x" + hex_off(off) +
                                " 无法换算为 RVA（越界？），保持原值");
            return off;
        }
        return *rva;
    };
    auto& regions = paired.regions;
    std::sort(regions.begin(), regions.end(),
              [](const ms::Region& a, const ms::Region& b) { return a.begin_off < b.begin_off; });
    ctx.functions.reserve(regions.size());
    for (const auto& r : regions) {
        ir::FunctionRegion fr;
        // TODO(P7-names): 从 begin 调用点的 lea/rcx 引用解析字符串名；v1 用地址。
        fr.name = "(marker@0x" + hex_off(r.begin_off) + ")";
        // X1a：x86 双段锚点已由步骤 1 的 is_x86 分支消费；区域 E8 回溯链
        // 双架构同形（x86 call rel32 与 x64 编码一致，实测）。arch 推导自
        // PeImage.machine（MIT-414 引入）；PeImage 缺失（泳道单测）沿用 X64。
        fr.arch = (pe != nullptr && pe->machine == kMachineX86) ? ir::Arch::X86
                                                                : ir::Arch::X64;
        fr.begin_rva = to_rva(r.begin_off, "begin", fr.name);
        fr.end_rva = to_rva(r.end_off, "end", fr.name);
        ctx.functions.push_back(std::move(fr));
    }
}

WVMP_REGISTER_PASS(MarkerScanPass)

} // namespace wvmp::passes
