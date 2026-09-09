#include "wvmp/passes/pe_writer/pe_writer_pass.hpp"

#include "pe_checksum.hpp"
#include "section_builder.hpp"

#include "wvmp/common/bytes.hpp"
#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/protect_levels.hpp"
#include "wvmp/framework/registry.hpp"
#include "wvmp/passes/pe_loader/pe_image.hpp"
#include "wvmp/passes/tls_hook/tls_plan.hpp"

#include <cstdio>
#include <map>
#include <optional>
#include <set>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace wvmp::passes {
namespace {

// OptionalHeader.CheckSum 固定位于可选头 +64（PE32 与 PE32+ 相同），
// 即 NT 头偏移 + 4(签名) + 20(FILE_HEADER) + 64。
constexpr size_t kChecksumOffsetInOpt = 64;
constexpr size_t kNtPrefix = 4 + 20;

// DllCharacteristics 位于 OptionalHeader +0x46 (PE32+/PE32 相同, 在 Subsystem
// +0x02 处). 绝对偏移 = nt_off (PE 签名 4 + FILE_HEADER 20) + 0x46 = nt_off + 0x5e.
//
// MVP P0 #3 替代方案 A (MIT-370 派活单): 派活单派发**前**已知完整 ASLR 兼容
// (MIT-340 派活单 §A 假设错 #11) 与 FORCE_INTEGRITY 启用 (未签名 → Windows
// "无法验证此文件的数字签名" → Permission denied rc=126) 两条路都不可行, 因
// 而保沿用 M2-8 简化方案并扩增 FORCE_INTEGRITY 清除:
//   1) IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x40 (ASLR). M2-8 起 rip-relative
//      翻译期把 [rip+disp] 转 RVA, 运行时经 LoadRva/StoreRva + VmContext.scratch_mem
//      (=image_base) 还原 VA. Windows ASLR 把 image 重新定位到随机基址, 但 stub
//      只知道 PE.ImageBase（写入 scratch_mem）— 二者不等 → 访存错位 → 段错误。
//      简化方案（M2-8 局限）：保护后清除 DYNAMIC_BASE 标志, 强制 Windows 加载到
//      ImageBase 声明位置. 完整 ASLR 兼容（MIT-340 派活单目标）需通过 .reloc 节
//      IMAGE_REL_BASED_DIR64 在 stub 的 image_base 立即上发布重定位——经实测
//      在 snake 真虚拟化样本上仍触发 segfault（pitfall #33 §A 假设错 #11），推测
//      Windows 加载器对保护后 .reloc 扩展存在未排查的行为差异. 完整 ASLR 兼容
//      留待后续派活单; 本 pass 沿用 M2-8 行为清 DYNAMIC_BASE.
//   2) IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x80. 启用后 Windows loader
//      强制校验数字签名, 未签名 PE → "无法验证此文件的数字签名" → 加载失败
//      (Permission denied rc=126). MVP P0 #1 + #2 修复保持 (MIT-330 + MIT-367
//      v2 verifier 独立确认) 要求保沿用 snake 真虚拟化 byte-exact 闭环, 与
//      FORCE_INTEGRITY 启用互斥 (pitfall #54 候选, MIT-367 v2 verifier 实证).
//      MVP P0 #4 (PE 签名 EV 证书采购 + 集成) MVP派发**前**到位**前**, 沿用派
//      活单 §D 决策 1: 保护后清除 FORCE_INTEGRITY, 避免杀软扫描兼容路径被
//      "Permission denied" 拦截. EV 证书到位后由后续派活单恢复 FORCE_INTEGRITY.
constexpr size_t kDllCharsOffsetFromNt = 0x5e;  // 4 (签名) + 20 (FILE_HEADER) + 0x46 (opt)
constexpr u16 kImageDllCharacteristicsDynamicBase = 0x0040;
constexpr u16 kImageDllCharacteristicsForceIntegrity = 0x0080;
// 保护后一律清除的两个位 (MVP P0 #3 替代方案 A): DYNAMIC_BASE + FORCE_INTEGRITY.
constexpr u16 kDllCharsClearMask = static_cast<u16>(
    kImageDllCharacteristicsDynamicBase | kImageDllCharacteristicsForceIntegrity);

// MIT-465: DataDirectory[9] (IMAGE_DIRECTORY_ENTRY_TLS) 表项写入。目录区在
// 可选头内的偏移 PE32+ = 112 / PE32 = 96，NumberOfRvaAndSizes 在其前 4 字节
// （108 / 92）；与 tls_hook 侧的读路径同布局独立声明（模块边界约定）。
size_t opt_num_rva_sizes_off(bool plus) { return plus ? 108u : 92u; }
size_t opt_data_dir_off(bool plus) { return plus ? 112u : 96u; }
constexpr size_t kTlsDirIndex = 9;

// MIT-494：小端读（reloc 扩展解析用；与 import_protect 同名 helper 独立
// 声明——模块边界约定）。
u64 rd_le(const u8* p, size_t n) {
    u64 v = 0;
    for (size_t i = 0; i < n; ++i) v |= u64(p[i]) << (8 * i);
    return v;
}

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

    // MIT-491 (T23，MIT-476 观察项落地)：Emit 预留区高水位观测——使用
    // 超过 75% 预算打 Note（协议超限本身是 emit_reserve_take 硬失败，
    // 此处为提前预警面）。游标是 .wvmp 数据节专属预算（MIT-488 R1 教
    // 训），预留区 = [size - kEmitReserveBytes, size)；无游标槽（旧夹
    // 具）或 .wvmp 缺席 → 静默跳过。
    if (auto* sections = ctx.find_slot<std::vector<NewSection>>(kNewSections);
        sections != nullptr)
        if (auto* r = ctx.find_slot<u64>(kEmitReserveBase); r != nullptr &&
            *r != 0)
            for (const auto& s : *sections) {
                if (s.name != ".wvmp" ||
                    s.data.size() <= kEmitReserveBytes)
                    continue;
                const u64 reserve_start = s.data.size() - kEmitReserveBytes;
                if (*r <= reserve_start) continue;
                const u64 used = *r - reserve_start;
                // 除法形态恒无乘法回绕（MIT-491 验收建议 1：游标被外部
                // 腐化 ≥2^62 时 used*4 理论回绕；当前威胁模型不可达，
                // 形态防御仍取）。
                if (used > kEmitReserveBytes / 4 * 3) {
                    char hw[128];
                    std::snprintf(hw, sizeof(hw),
                                  "Emit 预留区高水位：%llu / %u 字节（%.0f%%）"
                                  "——逼近预算上限，请评估 kEmitReserveBytes 扩容",
                                  static_cast<unsigned long long>(used),
                                  static_cast<unsigned>(kEmitReserveBytes),
                                  100.0 * static_cast<double>(used) /
                                      static_cast<double>(kEmitReserveBytes));
                    ctx.diag.report(Severity::Note, name(), hw);
                }
                break;
            }

    // MIT-494 (T26，MIT-493 定案实现)：ASLR 兼容——native 声明了
    // DYNAMIC_BASE 且带 .reloc 时，保留 DYNAMIC_BASE 并把 reloc 目录扩
    // 展为「原块拷贝 + packer 面 DIR64/HIGHLOW 新块」，整体拷入 .wvmp
    // 预留区（单连续区间，dd[5] 重指；预算 = 8KB 预留，远超典型 3KB
    // reloc + 数百站点）。packer 站点 = 字节粒度扫描 [ImageBase,
    // ImageBase+span) 内的全宽值（发射点登记的替代形态：keystone 装配
    // 的 imm 偏移难以静态映射，扫描假阳率 ≈ span/2^64 ≈ 0，MIT-493
    // PoC 实证）。原 reloc 已覆盖站点去重（双重 delta = 错位）。
    // native 未声明 DYNAMIC_BASE / 无 .reloc / 配置 [pe] aslr=false →
    // 跳过扩展（DllCharacteristics 面维持清除语义）。
    bool aslr_extended = false;
    const bool aslr_enabled =
        [](ProtectionContext& c) {
            const auto* rules = c.find_slot<ProtectRules>(kProtectRules);
            return rules == nullptr || !rules->has_pe_aslr || rules->pe_aslr;
        }(ctx);
    NewSection* wvmp_sec = nullptr;
    if (auto* sections = ctx.find_slot<std::vector<NewSection>>(kNewSections))
        for (auto& s : *sections)
            if (s.name == ".wvmp") { wvmp_sec = &s; break; }
    if (aslr_enabled && wvmp_sec != nullptr && !ctx.image.empty()) {
        const size_t e_off = static_cast<size_t>(
            ctx.image[0x3C]) | (static_cast<size_t>(ctx.image[0x3D]) << 8) |
            (static_cast<size_t>(ctx.image[0x3E]) << 16) |
            (static_cast<size_t>(ctx.image[0x3F]) << 24);
        if (e_off + 24 + 2 <= ctx.image.size() &&
            ctx.image[e_off] == 'P' && ctx.image[e_off + 1] == 'E') {
            const size_t opt_off = e_off + 24;
            // Magic 高字节：0x020B(PE32+) → 0x02 / 0x010B(PE32) → 0x01。
            const bool plus = ctx.image[opt_off + 1] == 0x02;
            // MIT-494d/T27b：x86（PE32）真 ASLR 启用——词流 RVA 化
            // （T27a：emit_address 绝对形 + mov imm32 映像窗口折条 +
            // SizeOfImage 布线）落地后撤 MIT-494c 的 x86 声明回退，
            // HIGHLOW 扩展与 x64 同管道（want_type = plus ? 10 : 3）。
            const u16 want_type = plus ? 10 : 3;  // DIR64 / HIGHLOW
            const size_t dd5 = opt_off + opt_data_dir_off(plus) + 5 * 8;
            const u32 old_rva =
                u32(rd_le(ctx.image.data() + dd5, 4));
            const u32 old_size =
                u32(rd_le(ctx.image.data() + dd5 + 4, 4));
            const u16 dllchars =
                u16(rd_le(ctx.image.data() + opt_off + 0x46, 2));
            const bool native_aslr =
                (dllchars & kImageDllCharacteristicsDynamicBase) != 0;
            if (native_aslr && old_size > 0 && old_rva != 0) {
                // —— 原 reloc 块拷贝 + 已覆盖站点集 ——
                const auto old_off = [&]() -> std::optional<size_t> {
                    u16 num = u16(rd_le(ctx.image.data() + e_off + 6, 2));
                    size_t sh = opt_off +
                                u16(rd_le(ctx.image.data() + e_off + 20, 2));
                    for (u16 i = 0; i < num; ++i) {
                        const size_t o = sh + size_t(i) * 40;
                        const u32 va =
                            u32(rd_le(ctx.image.data() + o + 12, 4));
                        const u32 rs =
                            u32(rd_le(ctx.image.data() + o + 16, 4));
                        const u32 rp =
                            u32(rd_le(ctx.image.data() + o + 20, 4));
                        const u32 vs =
                            u32(rd_le(ctx.image.data() + o + 8, 4));
                        const u32 ext = rs > vs ? rs : vs;
                        if (va <= old_rva && old_rva + old_size <= va + ext)
                            return size_t(rp) + (old_rva - va);
                    }
                    return std::nullopt;
                }();
                if (old_off.has_value() &&
                    u64(*old_off) + old_size <= ctx.image.size()) {
                    std::set<u32> covered;
                    {
                        size_t pos = 0;
                        const u8* rp = ctx.image.data() + *old_off;
                        while (pos + 8 <= old_size) {
                            const u32 page = u32(rd_le(rp + pos, 4));
                            const u32 bsz = u32(rd_le(rp + pos + 4, 4));
                            if (bsz < 8 || pos + bsz > old_size) break;
                            for (u32 i = 0; i < (bsz - 8) / 2; ++i) {
                                const u16 ent =
                                    u16(rd_le(rp + pos + 8 + i * 2, 2));
                                if (u16(ent >> 12) == want_type)
                                    covered.insert(
                                        page + u32(ent & 0x0FFF));
                            }
                            pos += bsz;
                        }
                    }
                    // —— packer 站点（发射点登记表；MIT-493 首选形态）——
                    // 生产方只登记自产 buffer 中的真实 VA（全镜像扫描存在
                    // 结构化数据假阳：误登记 = loader 对非 VA 值加 delta =
                    // 静默数据损坏，MIT-494 开发实录）。
                    std::set<u32> new_sites;
                    if (auto* sites =
                            ctx.find_slot<std::vector<u32>>(kRelocSites))
                        // 双重 delta 防线：原 reloc 已覆盖的站点不重复登
                        // 记（同站点双重 delta = 错位，MIT-493 口径）。
                        for (const u32 rva : *sites)
                            if (covered.count(rva) == 0)
                                new_sites.insert(rva);
                    // —— 原 reloc 块拷贝（剪枝覆写区孤儿条目，MIT-494c）——
                    // 覆写区（kPatchedRanges，stub_link 跳板 E9 rel32 +
                    // 填充）内的原字节已非指针；指向其中的 native reloc
                    // 条目自跳板写入起成为孤儿，拷贝时必须剪枝（不剪 =
                    // loader 把 delta 写进跳板字节 → rel32 毒变野跳，
                    // MIT-494a forkface 0x13DE cdb 实证）。幸存条目按原
                    // 序重组；4 字节对齐以 type-0（ABSOLUTE，loader 忽
                    // 略）哑条目补齐；剪空的块整体删除。
                    size_t pruned_entries = 0;
                    std::vector<u8> blob;
                    {
                        const auto* ranges =
                            ctx.find_slot<std::vector<std::pair<u32, u32>>>(
                                kPatchedRanges);
                        const auto deadened = [&](u32 site, size_t width) {
                            if (ranges == nullptr) return false;
                            for (const auto& [rva, len] : *ranges)
                                if (site < rva + len && rva < site + width)
                                    return true;
                            return false;
                        };
                        size_t pos = 0;
                        const u8* rp = ctx.image.data() + *old_off;
                        while (pos + 8 <= old_size) {
                            const u32 page = u32(rd_le(rp + pos, 4));
                            const u32 bsz = u32(rd_le(rp + pos + 4, 4));
                            if (bsz < 8 || pos + bsz > old_size) break;
                            std::vector<u16> keep;
                            bool prev_hl_dropped = false;
                            for (u32 i = 0; i < (bsz - 8) / 2; ++i) {
                                const u16 ent =
                                    u16(rd_le(rp + pos + 8 + i * 2, 2));
                                const u16 type = u16(ent >> 12);
                                const u32 site = page + u32(ent & 0x0FFF);
                                bool drop = false;
                                if (type == 1) {
                                    drop = prev_hl_dropped;  // HIGHADJ 隶属前导 HIGHLOW
                                } else if (type != 0) {
                                    drop = deadened(site, type == 10 ? 8 : 4);
                                }
                                prev_hl_dropped = type == 3 && drop;
                                if (drop) ++pruned_entries;
                                else keep.push_back(ent);
                            }
                            if (!keep.empty()) {
                                // 只剩 type-0 垫的块 = 功能性空块，整体
                                // 删除（发射会骗 loader 重定位一个无活
                                // 站点的目录 = 桩 VA 全部失配）。
                                bool has_live = false;
                                for (const u16 e2 : keep)
                                    if ((e2 >> 12) != 0) has_live = true;
                                if (has_live) {
                                    // 垫到 4 条目倍数 = 块 8 字节对齐：
                                    // loader 以 pos += bsz 顺序遍历，块间
                                    // 不允许任何间隙（4 字节垫 + 尾部补零
                                    // 会让下一个块头落在零洞上，遍历提前
                                    // 终止）。type-0 哑条目 loader 忽略。
                                    while (keep.size() % 4 != 0)
                                        keep.push_back(0);
                                    const u32 nbsz = static_cast<u32>(
                                        8 + keep.size() * 2);
                                    for (int b = 0; b < 4; ++b)
                                        blob.push_back(static_cast<u8>(
                                            (page >> (8 * b)) & 0xFF));
                                    for (int b = 0; b < 4; ++b)
                                        blob.push_back(static_cast<u8>(
                                            (nbsz >> (8 * b)) & 0xFF));
                                    for (const u16 e2 : keep)
                                        for (int b = 0; b < 2; ++b)
                                            blob.push_back(static_cast<u8>(
                                                ((e2 >> (8 * b)) & 0xFF)));
                                }
                            }
                            pos += bsz;
                        }
                    }
                    if (new_sites.empty() && pruned_entries == 0) {
                        // 无 packer 新站点且零孤儿：原 reloc 已完整覆盖
                        // （native 面自足），保留 DYNAMIC_BASE 即可，无需
                        // 扩展。
                        aslr_extended = true;
                    } else if (!blob.empty() || !new_sites.empty()) {
                        // —— 页分组 → 追加块 ——
                        std::map<u32, std::set<u32>> pages;
                        for (const u32 rva : new_sites)
                            pages[rva & ~u32(0xFFF)].insert(rva & 0xFFF);
                        if (blob.size() % 8 != 0)
                            blob.resize(
                                (blob.size() + 7) / 8 * 8, 0);
                        for (const auto& [page, offs] : pages) {
                            std::vector<u8> ents;
                            for (const u32 off : offs)
                                for (int b = 0; b < 2; ++b)
                                    ents.push_back(static_cast<u8>(
                                        ((want_type << 12 | off) >> (8 * b)) &
                                        0xFF));
                            while (ents.size() % 8 != 0) ents.push_back(0);
                            u32 bsz = static_cast<u32>(8 + ents.size());
                            for (int b = 0; b < 4; ++b)
                                blob.push_back(static_cast<u8>(
                                    (page >> (8 * b)) & 0xFF));
                            for (int b = 0; b < 4; ++b)
                                blob.push_back(static_cast<u8>(
                                    (bsz >> (8 * b)) & 0xFF));
                            blob.insert(blob.end(), ents.begin(), ents.end());
                        }
                        // —— 拷入 .wvmp 预留区并重指 dd[5] ——
                        u64 cur = wvmp_sec->data.size();
                        bool grow_ok = true;
                        if (auto* r = ctx.find_slot<u64>(kEmitReserveBase)) {
                            cur = *r;
                            grow_ok = false;
                        }
                        const u64 copy_off = emit_reserve_take(
                            wvmp_sec->data, cur, 8, blob.size(), grow_ok);
                        std::memcpy(wvmp_sec->data.data() + copy_off,
                                    blob.data(), blob.size());
                        if (auto* r = ctx.find_slot<u64>(kEmitReserveBase))
                            *r = cur;
                        const u64 new_rva =
                            wvmp_sec->requested_rva + copy_off;
                        ByteWriter wt(ctx.image);
                        wt.patch_u32(dd5, static_cast<u32>(new_rva));
                        wt.patch_u32(dd5 + 4,
                                     static_cast<u32>(blob.size()));
                        aslr_extended = true;
                        char rb[192];
                        std::snprintf(rb, sizeof(rb),
                                      "ASLR 兼容：reloc 目录已扩展（+ %zu "
                                      "站点 / 剪枝覆写区孤儿 %zu / %zu 字节"
                                      "）→ .wvmp @ RVA 0x%llX",
                                      new_sites.size(), pruned_entries,
                                      blob.size(),
                                      static_cast<unsigned long long>(new_rva));
                        ctx.diag.report(Severity::Note, name(), rb);
                    } else {
                        // 原目录条目全部为覆写区孤儿且无 packer 站点：扩
                        // 展无从谈起，aslr_extended 保持 false → 底部回退
                        // 清 DYNAMIC_BASE 路径（delta=0 是声明行为）。
                        ctx.diag.report(Severity::Note, name(),
                                        "ASLR 兼容：原 reloc 条目全部为覆写"
                                        "区孤儿，放弃扩展（回退清 DYNAMIC_BASE）");
                    }
                }
            }
        }
    }

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

    // 1.9) MIT-465: TLS 目录表项 —— tls_hook（Emit 阶段）已把
    //   IMAGE_TLS_DIRECTORY / 回调数组放进 .wvmp，经 kTlsPlan 槽交来目录
    //   RVA；这里落 DataDirectory[9] 表项（在 checksum 之前，保证校验和
    //   覆盖新表项）。槽缺席 = 管道不含 tls_hook，镜像一个字节不动。
    if (auto* tls = ctx.find_slot<tls_hook::TlsPlan>(kTlsPlan)) {
        const u16 opt_magic = static_cast<u16>(
            static_cast<u16>(ctx.image[size_t(nt_off) + 24]) |
            (static_cast<u16>(ctx.image[size_t(nt_off) + 25]) << 8));
        const bool plus = opt_magic == 0x020B;  // PE32+（0x010B = PE32）
        const size_t num_off = size_t(nt_off) + 24 + opt_num_rva_sizes_off(plus);
        const size_t dd_off =
            size_t(nt_off) + 24 + opt_data_dir_off(plus) + kTlsDirIndex * 8;
        if (num_off + 4 > ctx.image.size() || dd_off + 8 > ctx.image.size())
            fail(ctx, "可选头数据目录区越界，无法写入 TLS 目录表项");
        const u32 num_dirs = static_cast<u32>(ctx.image[num_off]) |
                             (static_cast<u32>(ctx.image[num_off + 1]) << 8) |
                             (static_cast<u32>(ctx.image[num_off + 2]) << 16) |
                             (static_cast<u32>(ctx.image[num_off + 3]) << 24);
        if (num_dirs < kTlsDirIndex + 1)
            fail(ctx, "NumberOfRvaAndSizes=" + std::to_string(num_dirs) +
                          " < 10，放不下 TLS 表项（ NumberOfRvaAndSizes 不可扩，"
                          "可选项头定长区内无空位）");
        {
            ByteWriter wt(ctx.image);
            wt.patch_u32(dd_off, static_cast<u32>(tls->tls_dir_rva));
            wt.patch_u32(dd_off + 4, tls->tls_dir_size);
        }
        char tls_buf[96];
        std::snprintf(tls_buf, sizeof(tls_buf),
                      "已写 TLS 目录表项: RVA 0x%llX, size %u（DataDirectory[9]）",
                      static_cast<unsigned long long>(tls->tls_dir_rva),
                      tls->tls_dir_size);
        ctx.diag.report(Severity::Note, name(), tls_buf);
    }

    // 2) 重算 PE checksum：清零 → 标准算法（u16 累加 + 文件总长）→ patch
    //    回 ctx.image（输出文件由镜像写出，随之携带新 checksum）。
    ByteWriter w(ctx.image);
    w.patch_u32(chk_off, 0);
    w.patch_u32(chk_off, pe_checksum(ctx.image, chk_off));

    // 2.5) MVP P0 #3 替代方案 A (MIT-370): 仅在确实虚拟化时（有 stub 产出）
    //   才需要清除 DllCharacteristics 的 DYNAMIC_BASE + FORCE_INTEGRITY 两个位。
    //   没虚拟化的镜像保持原状（PE-writer 单元测试往返断言要求 byte-identical）。
    //   MVP P0 #3 替代方案 A 完整动机: 详见 kDllCharsClearMask 上方注释块。
    const auto* new_sections_check = ctx.find_slot<std::vector<NewSection>>(kNewSections);
    const bool has_stub = new_sections_check != nullptr && !new_sections_check->empty();
    // MIT-494：DYNAMIC_BASE 仅在"ASLR 路径未成立"时清除——
    //   配置关断（[pe] aslr=false）或扩展未成功（native 未 opt-in / 无
    //   reloc / 无站点可扩展且原目录缺失）。扩展成功（aslr_extended，
    //   含"无新站点、原目录自足"分支）→ 保留 DYNAMIC_BASE。
    const bool keep_dynamic_base = aslr_enabled && aslr_extended;
    const u16 dll_clear_mask =
        keep_dynamic_base
            ? static_cast<u16>(kImageDllCharacteristicsForceIntegrity)
            : kDllCharsClearMask;
    if (has_stub &&
        nt_off + kDllCharsOffsetFromNt + 2 <= ctx.image.size()) {
        const u16 old_dll =
            static_cast<u16>(static_cast<u16>(ctx.image[nt_off + kDllCharsOffsetFromNt]) |
                            (static_cast<u16>(ctx.image[nt_off + kDllCharsOffsetFromNt + 1]) << 8));
        const u16 new_dll = static_cast<u16>(old_dll & ~dll_clear_mask);
        if (new_dll != old_dll) {
            ctx.image[nt_off + kDllCharsOffsetFromNt] = static_cast<u8>(new_dll & 0xFF);
            ctx.image[nt_off + kDllCharsOffsetFromNt + 1] = static_cast<u8>((new_dll >> 8) & 0xFF);
            // 列出被实际清除的位便于 verifier + fresh verify 一眼核对
            // (pitfall #50 多维验证, MIT-370 派活单 §D 决策 1).
            std::string note =
                "MVP P0 #3 替代方案 A: 已清除 DllCharacteristics 位 ";
            const u16 cleared_bits = static_cast<u16>(old_dll & ~new_dll);
            bool first = true;
            if (cleared_bits & kImageDllCharacteristicsDynamicBase) {
                note += "DYNAMIC_BASE(0x0040, ASLR)";
                first = false;
            }
            if (cleared_bits & kImageDllCharacteristicsForceIntegrity) {
                if (!first) note += " + ";
                note += "FORCE_INTEGRITY(0x0080, 数字签名校验)";
            }
            note += "; 强制镜像加载到 ImageBase 声明位置, 避免未签名 Permission denied rc=126";
            ctx.diag.report(Severity::Note, name(), note);
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