#include "wvmp/passes/import_protect/import_protect_pass.hpp"

#include "wvmp/passes/import_protect/import_plan.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/registry.hpp"
#include "wvmp/passes/pe_loader/pe_image.hpp"

#include <capstone/capstone.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace wvmp::passes {
namespace {

constexpr u16 kMachineX86 = 0x014C;  // 与 stub_link 同值独立声明（模块边界约定）
constexpr size_t kImportDirIndex = 1;      // DataDirectory[1] = IMAGE_DIRECTORY_ENTRY_IMPORT
constexpr size_t kMaxDescriptors = 1024;   // 描述符链上限（损坏防御）
constexpr size_t kMaxSlotsPerDesc = 4096;  // 单描述符槽上限（损坏防御）

size_t opt_data_dir_off(bool plus) { return plus ? 112u : 96u; }

u64 rd_le(const u8* p, size_t n) {
    u64 v = 0;
    for (size_t i = 0; i < n; ++i) v |= u64(p[i]) << (8 * i);
    return v;
}

// IMAGE_IMPORT_DESCRIPTOR：OriginalFirstThunk(0) TimeDateStamp(4)
// ForwarderChain(8) Name(12) FirstThunk(16)，全 u32，20 字节。
struct ImportDescriptor {
    u32 original_first_thunk = 0;  // INT RVA（名字面，原位保留）
    u32 first_thunk = 0;           // IAT RVA（地址面，迁移对象）
    u32 desc_entry_rva = 0;        // 描述符自身 RVA（FirstThunk 字段回写点）
};

// 解析 dd[1] 描述符链（未按全零终止 / 越界 → nullopt，整单放弃）。
std::optional<std::vector<ImportDescriptor>> read_descriptors(ProtectionContext& ctx,
                                                              const PeImage& pe,
                                                              u32 desc_rva) {
    const auto off = pe.rva_to_offset(desc_rva);
    if (!off.has_value()) return std::nullopt;
    std::vector<ImportDescriptor> out;
    for (size_t i = 0; i < kMaxDescriptors; ++i) {
        const size_t e = *off + i * 20;
        if (e + 20 > ctx.image.size()) return std::nullopt;
        ImportDescriptor d;
        d.original_first_thunk = u32(rd_le(&ctx.image[e], 4));
        d.first_thunk = u32(rd_le(&ctx.image[e] + 16, 4));
        d.desc_entry_rva = desc_rva + static_cast<u32>(i * 20);
        if (d.original_first_thunk == 0 && d.first_thunk == 0) return out;  // 全零终止
        out.push_back(d);
    }
    return std::nullopt;  // 未终止
}

// 单描述符 IAT 槽数：以 INT 数为基准（INT 与 IAT 平行、同长、各自 NULL 终止）。
// 命中回调：idx = 槽序号，thunk = INT 槽值（名字导入 = IMAGE_IMPORT_BY_NAME RVA）。
template <typename Fn>
std::optional<size_t> for_each_slot(ProtectionContext& ctx, const PeImage& pe, u32 int_rva,
                                    Fn&& on_slot) {
    const auto off = pe.rva_to_offset(int_rva);
    if (!off.has_value()) return std::nullopt;
    const size_t w = pe.is_pe32_plus ? 8 : 4;
    for (size_t i = 0; i < kMaxSlotsPerDesc; ++i) {
        const size_t e = *off + i * w;
        if (e + w > ctx.image.size()) return std::nullopt;
        const u64 thunk = rd_le(&ctx.image[e], w);
        if (thunk == 0) return i;  // NULL 终止（不含终止槽）
        on_slot(i, thunk);
    }
    return std::nullopt;
}

// 在某描述符的 INT 中找名字导入 `VirtualProtect`（ordinal 导入跳过）。
// 返回其在 IAT 中的槽 RVA（FirstThunk + idx*w）；未找到 → nullopt。
std::optional<u64> find_virtual_protect_slot(ProtectionContext& ctx, const PeImage& pe,
                                             const ImportDescriptor& d) {
    const auto off = pe.rva_to_offset(d.original_first_thunk);
    if (!off.has_value()) return std::nullopt;
    const size_t w = pe.is_pe32_plus ? 8 : 4;
    for (size_t i = 0; i < kMaxSlotsPerDesc; ++i) {
        const size_t e = *off + i * w;
        if (e + w > ctx.image.size()) return std::nullopt;
        const u64 thunk = rd_le(&ctx.image[e], w);
        if (thunk == 0) return std::nullopt;
        if (thunk & (1ULL << 63)) continue;  // x64 ordinal 导入（高位 1）；x86 恒假
        const u32 by_name_rva = u32(thunk & 0xFFFFFFFFu);
        const auto n_off = pe.rva_to_offset(by_name_rva);
        if (!n_off.has_value() || *n_off + 2 > ctx.image.size()) continue;
        const char* name = reinterpret_cast<const char*>(ctx.image.data() + *n_off + 2);
        const size_t left = ctx.image.size() - *n_off - 2;
        if (left >= 15 && std::memcmp(name, "VirtualProtect", 14) == 0 && name[14] == '\0')
            return u64(d.first_thunk) + i * w;
    }
    return std::nullopt;
}

} // namespace

std::span<const std::string_view> ImportProtectPass::requires_keys() const {
    static constexpr std::string_view kRequires[] = {kNewSections, kPeImage, kImage};
    return kRequires;
}

std::span<const std::string_view> ImportProtectPass::provides_keys() const {
    static constexpr std::string_view kProvides[] = {kImportPlan};
    return kProvides;
}

// ---------------------------------------------------------------------------
// MIT-477 (T9.1)：x64 代码引用重写——EXECUTE 节内所有 rip 相对引用原 IAT
// 槽的指令，disp 重指 .wvmp 镜像等价槽（mirror_rva + (target - iat_base)）。
// 扫描 = 线性 capstone 反汇编（解码失败步进 1 字节，抗数据混排）；disp
// 位置 = encoding.modrm_offset + 2（mod=00/rm=101 无 SIB），并以"指令地址
// + 长度 + disp == 目标"回读校验兜底（不符即跳过，保守）。x86 目标不重写
// （绝对寻址 + .reloc 联动复杂，v1 砍面；TLS 回填兜底仍覆盖未重写引用）。
// 返回重写条数。
static size_t rewrite_iat_code_refs(ProtectionContext& ctx, const PeImage& pe,
                                    u64 iat_base, u64 iat_span, u64 mirror_rva) {
    csh h = 0;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) != CS_ERR_OK)
        throw std::runtime_error("import_protect: cs_open failed");
    cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
    // cs_disasm_iter 要求 insn.detail 指向有效存储（capstone 5 契约）——
    // cs_malloc 统一分配并初始化；栈上裸 cs_insn 的 detail 为垃圾 → 桩内
    // memset AV（实测）。
    cs_insn* insn = cs_malloc(h);
    if (insn == nullptr) {
        cs_close(&h);
        throw std::runtime_error("import_protect: cs_malloc failed");
    }
    size_t rewritten = 0;
    for (const auto& sec : pe.sections) {
        if ((sec.characteristics & 0x2000'0000u) == 0) continue;  // EXECUTE
        const auto sec_off = pe.rva_to_offset(sec.virtual_addr);
        if (!sec_off.has_value()) continue;
        // 长度钳制到镜像实际末端（头表 raw_size 与文件布局偶尔不符——
        // 钳制而非整节跳过，扫描照常覆盖可见部分）。
        size_t len = sec.raw_size;
        if (static_cast<u64>(*sec_off) >= ctx.image.size()) continue;
        len = static_cast<size_t>(
            std::min<u64>(len, ctx.image.size() - *sec_off));
        if (len == 0) continue;
        const u8* cur = ctx.image.data() + *sec_off;
        size_t pos = 0;
        u64 va = sec.virtual_addr;  // cs 地址游标（RVA 空间）
        while (pos < len) {
            size_t remain = len - pos;
            const u8* p = cur + pos;
            u64 at = va;
            if (!cs_disasm_iter(h, &p, &remain, &at, insn)) {
                ++pos;
                ++va;
                continue;
            }
            // 定位 rip 相对内存操作数
            bool hit = false;
            i64 disp = 0;
            {
                const cs_x86& x = insn->detail->x86;
                for (size_t k = 0; k < x.op_count && !hit; ++k) {
                    const cs_x86_op& op = x.operands[k];
                    if (op.type != X86_OP_MEM) continue;
                    if (op.mem.base != X86_REG_RIP) continue;
                    hit = true;
                    disp = op.mem.disp;
                }
            }
            if (hit) {
                const u64 target = insn->address + insn->size +
                                   static_cast<u64>(static_cast<i64>(disp));
                // 槽对齐判据：合法 IAT 引用命中 8B 对齐槽起点；线性扫描
                // 漂移产生的伪 rip 命中几乎必然非对齐 → 跳过（防误改写）。
                if (target >= iat_base && target + 4 <= iat_base + iat_span &&
                    (target - iat_base) % 8 == 0) {
                    // disp 字段定位：mod=00/rm=101 时 disp32 紧跟 1 字节
                    // modrm → modrm_offset + 1；capstone 缺席时按 FF 15/25
                    // 形（size-4）兜底。回读校验不符即跳过（保守）。
                    const cs_x86& x = insn->detail->x86;
                    size_t disp_off = 0;
                    bool ok = false;
                    if (x.encoding.modrm_offset != 0 ||
                        (x.encoding.modrm_offset == 0 && insn->size >= 6 &&
                         insn->bytes[0] == 0xFF &&
                         (insn->bytes[1] == 0x15 || insn->bytes[1] == 0x25))) {
                        disp_off = x.encoding.modrm_offset != 0
                                       ? x.encoding.modrm_offset + 1
                                       : insn->size - 4;
                        ok = disp_off + 4 <= insn->size;
                    } else {
                        ok = false;
                    }
                    if (ok) {
                        // disp32 是有符号值——必须读 u32 后符号扩展（直接
                        // memcpy 进 i64 是零扩展，负 disp 全部误判，实测）。
                        u32 raw32 = 0;
                        std::memcpy(&raw32, insn->bytes + disp_off, 4);
                        const i64 cur_disp = static_cast<i64>(static_cast<i32>(raw32));
                        if (insn->address + insn->size + cur_disp == target) {
                            const u64 new_target = mirror_rva + (target - iat_base);
                            const i64 new_disp =
                                cur_disp + static_cast<i64>(new_target) -
                                static_cast<i64>(target);
                            const i64 lo = -0x8000'0000LL, hi = 0x7FFF'FFFFLL;
                            if (new_disp >= lo && new_disp <= hi) {
                                u8* raw = ctx.image.data() + *sec_off + pos;
                                for (int b = 0; b < 4; ++b)
                                    raw[disp_off + b] =
                                        static_cast<u8>((static_cast<u64>(new_disp) >>
                                                         (8 * b)) & 0xFF);
                                ++rewritten;
                            }
                        }
                    }
                }
            }
            pos += insn->size;
            va += insn->size;
        }
        // —— 锚点补漏扫描（MIT-477）：线性反汇编在数据混排区失步会漏过
        // 真实引用（单测实录）。锚点 = FF 15/25（call/jmp [rip]）与
        // (REX)? 8B modrm(00/101)（mov r32/r64, [rip]）——逐候选偏移独立
        // 解码，不受失步影响；与线性共享同一套对齐/回读/span 守卫（对已
        // 重写位点幂等：其 disp 已指镜像、target 不再落原 span）。
        for (size_t i = 0; i + 3 <= len; ++i) {
            const u8* b = cur + i;
            size_t clen = 0;
            if (b[0] == 0xFF && (b[1] == 0x15 || b[1] == 0x25)) {
                clen = 6;              // FF /2 /4：call/jmp [rip+disp32]
            } else if ((b[0] == 0x8B || (b[0] >= 0x40 && b[0] <= 0x4F)) &&
                       b[1] == 0x8B && (b[2] & 0xC7) == 0x05) {
                clen = (b[0] >= 0x40 && b[0] <= 0x4F) ? 7 : 6;  // (REX) 8B /r mov r32/r64
            } else {
                continue;
            }
            if (i + clen > len) continue;
            size_t remain = clen;
            const u8* p = b;
            u64 at = sec.virtual_addr + i;
            if (!cs_disasm_iter(h, &p, &remain, &at, insn)) continue;
            if (insn->size != clen) continue;
            const cs_x86& x = insn->detail->x86;
            bool hit = false;
            i64 disp = 0;
            for (size_t k = 0; k < x.op_count && !hit; ++k) {
                const cs_x86_op& op = x.operands[k];
                if (op.type == X86_OP_MEM && op.mem.base == X86_REG_RIP) {
                    hit = true;
                    disp = op.mem.disp;
                }
            }
            if (!hit) continue;
            const u64 target = insn->address + insn->size +
                               static_cast<u64>(static_cast<i64>(disp));
            if (!(target >= iat_base && target + 4 <= iat_base + iat_span &&
                  (target - iat_base) % 8 == 0))
                continue;
            size_t disp_off = x.encoding.modrm_offset != 0 ? x.encoding.modrm_offset + 1
                                                           : (clen == 6 ? 2 : 3);
            if (disp_off + 4 > insn->size) continue;
            u32 raw32 = 0;
            std::memcpy(&raw32, insn->bytes + disp_off, 4);
            const i64 cur_disp = static_cast<i64>(static_cast<i32>(raw32));
            if (insn->address + insn->size + cur_disp != target) continue;
            const u64 new_target = mirror_rva + (target - iat_base);
            const i64 new_disp = cur_disp + static_cast<i64>(new_target) -
                                 static_cast<i64>(target);
            if (new_disp < -0x8000'0000LL || new_disp > 0x7FFF'FFFFLL) continue;
            u8* raw = ctx.image.data() + *sec_off + i;
            for (int b2 = 0; b2 < 4; ++b2)
                raw[disp_off + b2] =
                    static_cast<u8>((static_cast<u64>(new_disp) >> (8 * b2)) & 0xFF);
            ++rewritten;
        }
    }
    cs_free(insn, 1);
    cs_close(&h);
    return rewritten;
}

void ImportProtectPass::run(ProtectionContext& ctx) {
    // .wvmp 节（stub_link 产出）缺席 = 无可挂靠镜像 → 空转（镜像零改动）。
    NewSection* wvmp = nullptr;
    if (auto* sections = ctx.find_slot<std::vector<NewSection>>(kNewSections))
        for (auto& s : *sections)
            if (s.name == ".wvmp") { wvmp = &s; break; }
    if (wvmp == nullptr) {
        ctx.diag.report(Severity::Note, name(),
                        "无 .wvmp 节（stub_link 未产出），跳过 IAT 迁移");
        return;
    }
    const PeImage* pe = ctx.find_slot<PeImage>(kPeImage);
    if (pe == nullptr) {
        ctx.diag.report(Severity::Error, name(), "PeImage 模型缺失，无法迁移 IAT");
        throw std::runtime_error(std::string(name()) + ": pe image model missing");
    }
    const bool plus = pe->is_pe32_plus;
    const size_t w = plus ? 8 : 4;

    // dd[1] 在场性（缺失 = 无导入面，空转放行——不是错误）。
    const size_t dd1 = size_t(pe->nt_headers_offset) + 24 + opt_data_dir_off(plus) +
                       kImportDirIndex * 8;
    if (dd1 + 8 > ctx.image.size()) {
        ctx.diag.report(Severity::Note, name(), "无导入目录，跳过 IAT 迁移");
        return;
    }
    const u32 desc_rva = u32(rd_le(ctx.image.data() + dd1, 4));
    if (desc_rva == 0) {
        ctx.diag.report(Severity::Note, name(), "无导入目录，跳过 IAT 迁移");
        return;
    }

    const auto descs = read_descriptors(ctx, *pe, desc_rva);
    if (!descs.has_value() || descs->empty()) {
        ctx.diag.report(Severity::Note, name(), "导入描述符链不可解析，放弃 IAT 迁移（保守回退）");
        return;
    }
    // 绑定导入 / 残缺描述符 → 整单放弃（保守回退）。
    for (const auto& d : *descs) {
        if (d.first_thunk == 0 || d.original_first_thunk == 0) {
            ctx.diag.report(Severity::Note, name(),
                            "检测到绑定导入或残缺描述符，放弃 IAT 迁移（保守回退）");
            return;
        }
    }

    // 逐描述符数槽 + 计算连续区间（标准链接器布局：全部 FirstThunk 落在
    // 同一连续 IAT 区，相邻描述符共享 NULL 终止槽）。
    u64 base = ~u64(0);
    u64 end = 0;
    u32 total_slots = 0;
    std::vector<std::pair<u64, u64>> spans;  // [ft, ft+(n+1)*w) 逐描述符
    for (const auto& d : *descs) {
        const auto n = for_each_slot(ctx, *pe, d.original_first_thunk,
                                     [](size_t, u64) {});
        if (!n.has_value() || *n == 0) {
            ctx.diag.report(Severity::Note, name(), "IAT 槽数不可解析，放弃 IAT 迁移（保守回退）");
            return;
        }
        base = std::min<u64>(base, d.first_thunk);
        end = std::max<u64>(end, u64(d.first_thunk) + u64(*n + 1) * w);  // 含 NULL 终止槽
        total_slots += static_cast<u32>(*n);
        spans.emplace_back(d.first_thunk, u64(d.first_thunk) + u64(*n + 1) * w);
    }
    // 连续性校验（回填为整段 memcpy 的前提）：按 FirstThunk 排序后相邻
    // 切片首尾相接，区间内无夹缝（夹缝里的无关数据会被镜像内容覆盖）。
    std::sort(spans.begin(), spans.end());
    for (size_t i = 1; i < spans.size(); ++i) {
        if (spans[i].first != spans[i - 1].second) {
            ctx.diag.report(Severity::Note, name(),
                            "IAT 区间非连续（描述符间有夹缝），放弃 IAT 迁移（保守回退）");
            return;
        }
    }
    const u64 span = end - base;
    if (span == 0 || span > u64(kMaxDescriptors + 1) * kMaxSlotsPerDesc * w) {
        ctx.diag.report(Severity::Note, name(), "IAT 区间异常，放弃 IAT 迁移（保守回退）");
        return;
    }
    // VirtualProtect 槽定位（v1 硬依赖）：回填写入的原始 IAT 页在 TLS 回调
    // 期已被 loader 重新只读保护，必须经 VirtualProtect 解除/恢复。
    u64 vp_slot_rva = 0;
    for (const auto& d : *descs)
        if (auto s = find_virtual_protect_slot(ctx, *pe, d)) { vp_slot_rva = *s; break; }
    if (vp_slot_rva == 0) {
        ctx.diag.report(Severity::Note, name(),
                        "目标未导入 kernel32!VirtualProtect，放弃 IAT 迁移（v1 硬依赖，保守回退）");
        return;
    }
    // 页面覆盖：原 IAT 区所在首页起、页对齐跨度。
    const u64 page_rva = base & ~u64(0xFFF);
    const u64 page_bytes = ((base + span + 0xFFF) & ~u64(0xFFF)) - page_rva;

    // MIT-476：镜像写入 .wvmp 预留区（emit_reserve_take 协议，见
    // pe_image.hpp）——节尺寸恒定，代码节连续性不再依赖对齐垫片。
    // 镜像之后 8 字节 oldprot 暂存（初始 0）。预留槽缺席（旧夹具）=
    // 旧"尾部追加"语义（grow_ok）。
    u64 cur = wvmp->data.size();
    bool grow_ok = true;
    if (auto* r = ctx.find_slot<u64>(kEmitReserveBase)) {
        cur = *r;
        grow_ok = false;
    }
    const size_t span_bytes = static_cast<size_t>(span);
    const u64 mirror_off = emit_reserve_take(wvmp->data, cur, 8, span_bytes, grow_ok);
    const u64 mirror_rva = wvmp->requested_rva + mirror_off;
    for (size_t i = 0; i < span_bytes; ++i)
        wvmp->data[static_cast<size_t>(mirror_off) + i] =
            static_cast<u8>(ctx.rng.next() & 0xFF);
    const u64 oldprot_off = emit_reserve_take(wvmp->data, cur, 8, 8, grow_ok);
    const u64 oldprot_rva = wvmp->requested_rva + oldprot_off;
    if (auto* r = ctx.find_slot<u64>(kEmitReserveBase)) *r = cur;

    // 各描述符 FirstThunk RVA 原地重指镜像切片。先全部解析偏移再统一
    // 写入——消除写循环内二次映射失败的半改窗口（MIT-466 验收 issue）。
    std::vector<size_t> ft_offsets;
    ft_offsets.reserve(descs->size());
    for (const auto& d : *descs) {
        const auto off = pe->rva_to_offset(d.desc_entry_rva + 16);
        if (!off.has_value() || *off + 4 > ctx.image.size()) {
            ctx.diag.report(Severity::Error, name(), "描述符 RVA 不可映射，放弃 IAT 迁移（保守回退）");
            return;
        }
        ft_offsets.push_back(*off);
    }
    for (size_t i = 0; i < descs->size(); ++i) {
        const u32 new_ft = static_cast<u32>(mirror_rva + ((*descs)[i].first_thunk - base));
        for (size_t b = 0; b < 4; ++b)
            ctx.image[ft_offsets[i] + b] = static_cast<u8>((new_ft >> (8 * b)) & 0xFF);
    }

    // MIT-477 (T9.1)：x64 代码引用重写——.text 内 rip 相对引用原 IAT 的指
    // 令重指镜像等价槽。回填（TLS 回调）保留为兜底（未重写的引用——数据指
    // 针、x86 绝对寻址——仍可用），运行期调用面则提前到 loader 填镜像时刻。
    size_t refs_rewritten = 0;
    if (pe->machine != kMachineX86) {
        refs_rewritten = rewrite_iat_code_refs(ctx, *pe, base, span, mirror_rva);
    }

    import_protect::ImportPlan plan;
    plan.active = true;
    plan.iat_base_rva = base;
    plan.iat_bytes = span;
    plan.mirror_rva = mirror_rva;
    plan.slot_count = total_slots;
    plan.descriptor_count = static_cast<u32>(descs->size());
    plan.vp_slot_rva = vp_slot_rva;
    plan.page_rva = page_rva;
    plan.page_bytes = page_bytes;
    plan.oldprot_rva = oldprot_rva;
    ctx.slot<import_protect::ImportPlan>(kImportPlan) = plan;

    char buf[192];
    if (pe->machine != kMachineX86) {
        std::snprintf(buf, sizeof(buf),
                      "IAT 迁移：%u 描述符 / %u 槽（0x%llX 字节）→ .wvmp 镜像 @ RVA 0x%llX"
                      "（INT 原位；回填由 TLS 回调执行；代码引用重写 %zu 处）",
                      plan.descriptor_count, plan.slot_count,
                      static_cast<unsigned long long>(span),
                      static_cast<unsigned long long>(mirror_rva), refs_rewritten);
    } else {
        std::snprintf(buf, sizeof(buf),
                      "IAT 迁移：%u 描述符 / %u 槽（0x%llX 字节）→ .wvmp 镜像 @ RVA 0x%llX"
                      "（INT 原位；回填由 TLS 回调执行；x86 不做引用重写，回填兜底）",
                      plan.descriptor_count, plan.slot_count,
                      static_cast<unsigned long long>(span),
                      static_cast<unsigned long long>(mirror_rva));
    }
    ctx.diag.report(Severity::Note, name(), buf);
}

WVMP_REGISTER_PASS(ImportProtectPass)

} // namespace wvmp::passes
