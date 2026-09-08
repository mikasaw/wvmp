#include "wvmp/passes/import_protect/import_protect_pass.hpp"

#include "wvmp/passes/import_protect/import_plan.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/protect_levels.hpp"
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
// + 长度 + disp == 目标"回读校验兜底（不符即跳过，保守）。（x86 abs32
// 面见下方 rewrite_iat_code_refs_x86，MIT-486 起不再砍面。）
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
            if (b[0] == 0xFF && (b[1] == 0x15 || b[1] == 0x25 || b[1] == 0x35)) {
                clen = 6;  // FF /2 /4 /6：call/jmp/push [rip+disp32]（MIT-487 加 FF 35）
            } else if ((b[0] == 0x8B || (b[0] >= 0x40 && b[0] <= 0x4F)) &&
                       b[1] == 0x8B && (b[2] & 0xC7) == 0x05) {
                clen = (b[0] >= 0x40 && b[0] <= 0x4F) ? 7 : 6;  // (REX) 8B /r mov r32/r64
            } else if (b[0] == 0x0F && (b[2] & 0xC7) == 0x05 &&
                       (b[1] == 0x10 || b[1] == 0x11 || b[1] == 0x28 ||
                        b[1] == 0x29 || b[1] == 0x2E || b[1] == 0x2F ||
                        b[1] == 0xB6 || b[1] == 0xB7 || b[1] == 0xBE ||
                        b[1] == 0xBF)) {
                clen = 7;  // MIT-487：0F 前缀 mem 形（movups/movaps/movzx/movsx
                           // [rip+disp32]）——drift 防线扩展（线性路径本已覆盖）。
                           // 注：带 legacy prefix/REX 的变体不是被 size 判据
                           // "排除"——锚点落在 0F 字节位时尾解码 7 字节恰好
                           // size==clen 通过，且子解码与真指令的 disp 落点
                           // 一致（i+1+7 == 真指令尾），守卫照常生效。
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

// ---------------------------------------------------------------------------
// MIT-486 (T9.2 砍面①)：x86 绝对寻址代码引用重写——PE32 EXECUTE 节内
// abs32 直接编址（ea = disp32，无 rip 基）引用原 IAT 槽的指令，imm32
// 重写为镜像等价槽全 VA（image_base + mirror_rva + (target - iat_base)）。
// 与 x64 rip 范式同构的两级扫描（线性 + 锚点），守卫差异：
//   - 绝对编址 ea = disp（无"insn 尾 + disp"项）→ target == disp 本身；
//   - PE32 IAT 槽宽 4B → 槽对齐判据 (target - iat_base) % 4 == 0；
//   - 新 imm32 = 镜像槽全 VA，RVA 空间 < 4GB 恒可表示（无 disp32 界）。
// reloc 语义定案（MIT-477 砍面①复盘）：abs32 站点的 HIGHLOW reloc 项按
// delta 修正站点值——改写前后站点值均为 preferred-base 同镜像 VA，delta
// 线性作用于两者等价成立（新旧都随基址平移），无需增删 reloc 项；且
// pe_writer 恒清 DYNAMIC_BASE（delta=0），双重自洽。
// 锚点集 = FF 15/25（call/jmp [abs]）、A1/A3（mov eax,[abs] /
// mov [abs],eax）、泛 modrm mod=00/rm=101（8B/89/03/2B 等单字节 opcode
// 尾随 disp32 形；带尾随立即数的编码如 C7 05 disp32 imm32 由线性路径
// 覆盖——锚点缓冲截短会解码失败，按设计跳过）。
static size_t rewrite_iat_code_refs_x86(ProtectionContext& ctx, const PeImage& pe,
                                        u64 iat_base, u64 iat_span, u64 mirror_rva) {
    csh h = 0;
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &h) != CS_ERR_OK)
        throw std::runtime_error("import_protect: cs_open(x86) failed");
    cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn* insn = cs_malloc(h);
    if (insn == nullptr) {
        cs_close(&h);
        throw std::runtime_error("import_protect: cs_malloc failed");
    }
    const u64 ib = pe.image_base;
    // 站点改写核心（线性与锚点共享）：绝对编址命中判据 + imm32 位置
    // 回读校验 + 原位改写。raw32 == disp 校验的是"补丁位置正确"（disp
    // 再生自同一字段，语义载荷由 span + 槽对齐守卫承担）。
    const auto try_rewrite = [&](u8* raw, const cs_insn& c) -> bool {
        const cs_x86& x = c.detail->x86;
        bool hit = false;
        i64 disp = 0;
        for (size_t k = 0; k < x.op_count && !hit; ++k) {
            const cs_x86_op& op = x.operands[k];
            if (op.type != X86_OP_MEM) continue;
            if (op.mem.base != X86_REG_INVALID) continue;  // 仅 abs32 直接编址
            hit = true;
            disp = op.mem.disp;
        }
        if (!hit) return false;
        // abs32 disp 字段承载全 VA（real PE 链接器形态）——先减 image_base
        // 转 RVA 空间再对 span（iat_base 为 RVA）；< ib 即非镜像引用。
        const u64 abs = static_cast<u64>(disp);
        if (abs < ib) return false;
        const u64 target = abs - ib;
        if (target < iat_base || target + 4 > iat_base + iat_span) return false;
        if ((target - iat_base) % 4 != 0) return false;
        // disp32 定位：FF 15/25 与 A1/A3 无 modrm（disp 在 size-4）；
        // modrm 形（mod=00/rm=101 无 SIB）disp32 紧跟 modrm → offset + 1。
        const size_t disp_off =
            x.encoding.modrm_offset != 0 ? x.encoding.modrm_offset + 1 : c.size - 4;
        if (disp_off + 4 > c.size) return false;
        u32 raw32 = 0;
        std::memcpy(&raw32, c.bytes + disp_off, 4);
        if (raw32 != abs) return false;
        const u64 new_target = ib + mirror_rva + (target - iat_base);
        for (int b = 0; b < 4; ++b)
            raw[disp_off + b] = static_cast<u8>((new_target >> (8 * b)) & 0xFF);
        return true;
    };
    size_t rewritten = 0;
    for (const auto& sec : pe.sections) {
        if ((sec.characteristics & 0x2000'0000u) == 0) continue;  // EXECUTE
        const auto sec_off = pe.rva_to_offset(sec.virtual_addr);
        if (!sec_off.has_value()) continue;
        size_t len = sec.raw_size;
        if (static_cast<u64>(*sec_off) >= ctx.image.size()) continue;
        len = static_cast<size_t>(std::min<u64>(len, ctx.image.size() - *sec_off));
        if (len == 0) continue;
        const u8* cur = ctx.image.data() + *sec_off;
        size_t pos = 0;
        u64 va = sec.virtual_addr;
        while (pos < len) {
            size_t remain = len - pos;
            const u8* p = cur + pos;
            u64 at = va;
            if (!cs_disasm_iter(h, &p, &remain, &at, insn)) {
                ++pos;
                ++va;
                continue;
            }
            if (try_rewrite(ctx.image.data() + *sec_off + pos, *insn)) ++rewritten;
            pos += insn->size;
            va += insn->size;
        }
        // —— 锚点补漏扫描（对齐 MIT-477 范式）：数据混排区失步时线性
        // 漏过的真实引用由锚点独立解码补齐；对已重写位点幂等（新值不落
        // 原 span）。
        for (size_t i = 0; i + 3 <= len; ++i) {  // 上界 3：0F 前缀锚点读 b[2]
            const u8* b = cur + i;
            size_t clen = 0;
            if (b[0] == 0xFF && (b[1] == 0x15 || b[1] == 0x25)) {
                clen = 6;  // FF /2 /4：call/jmp [disp32]
            } else if (b[0] == 0xA1 || b[0] == 0xA3) {
                clen = 5;  // A1/A3：mov eax,[disp32] / mov [disp32],eax
            } else if (b[0] == 0x0F && (b[2] & 0xC7) == 0x05 &&
                       (b[1] == 0x10 || b[1] == 0x11 || b[1] == 0x28 ||
                        b[1] == 0x29 || b[1] == 0x2E || b[1] == 0x2F ||
                        b[1] == 0xB6 || b[1] == 0xB7 || b[1] == 0xBE ||
                        b[1] == 0xBF)) {
                clen = 7;  // MIT-487：0F movzx/movsx + SSE mem 形（与 x64 锚
                           // 点集对称；FF 35 已被泛 modrm 分支覆盖：
                           // 0x35 & 0xC7 == 0x05）
            } else if ((b[1] & 0xC7) == 0x05) {
                clen = 6;  // 泛单字节 opcode + modrm(00/101) + disp32
            } else {
                continue;
            }
            if (i + clen > len) continue;
            size_t remain = clen;
            const u8* p = b;
            u64 at = sec.virtual_addr + i;
            if (!cs_disasm_iter(h, &p, &remain, &at, insn)) continue;
            if (insn->size != clen) continue;
            if (try_rewrite(ctx.image.data() + *sec_off + i, *insn)) ++rewritten;
        }
    }
    cs_free(insn, 1);
    cs_close(&h);
    return rewritten;
}

// ---------------------------------------------------------------------------
// MIT-486 (T9.2 砍面②)：数据段指针重写——.reloc 目录全扫，非 EXECUTE
// 节内 DIR64 (PE32+) / HIGHLOW (PE32) 站点值（preferred-base 同镜像 VA）
// 落原 IAT span 的，重写为镜像等价槽全 VA。reloc 项保留不动：站点位置
// 不变、新值仍为 preferred-base 同镜像 VA，delta（若启 ASLR）线性作用
// 于新旧值等价成立。EXECUTE 节站点归代码重写面（x86 abs32 站点的
// HIGHLOW 项在此被分流，避免与数据路径重复处理）。返回改写条数。
static size_t rewrite_iat_data_refs(ProtectionContext& ctx, const PeImage& pe,
                                    u64 iat_base, u64 iat_span, u64 mirror_rva) {
    const bool plus = pe.is_pe32_plus;
    const size_t w = plus ? 8 : 4;
    const u16 want_type = plus ? 10 : 3;  // IMAGE_REL_BASED_DIR64 / HIGHLOW
    const size_t dd5 = size_t(pe.nt_headers_offset) + 24 + opt_data_dir_off(plus) +
                       5 * 8;  // DataDirectory[5] = BASERELOC
    if (dd5 + 8 > ctx.image.size()) return 0;
    const u32 reloc_rva = u32(rd_le(ctx.image.data() + dd5, 4));
    const u32 reloc_size = u32(rd_le(ctx.image.data() + dd5 + 4, 4));
    if (reloc_rva == 0 || reloc_size < 8) return 0;
    const auto reloc_off = pe.rva_to_offset(reloc_rva);
    if (!reloc_off.has_value() ||
        u64(*reloc_off) + reloc_size > ctx.image.size())
        return 0;
    const u64 ib = pe.image_base;
    size_t rewritten = 0;
    size_t pos = 0;
    const u8* rp = ctx.image.data() + *reloc_off;
    while (pos + 8 <= reloc_size) {
        const u32 page_rva = u32(rd_le(rp + pos, 4));
        const u32 block_size = u32(rd_le(rp + pos + 4, 4));
        if (block_size < 8 || pos + block_size > reloc_size) break;  // 损坏防御
        const size_t n_entries = (block_size - 8) / 2;
        for (size_t i = 0; i < n_entries; ++i) {
            const u16 e = u16(rd_le(rp + pos + 8 + i * 2, 2));
            if (u16(e >> 12) != want_type) continue;  // ABSOLUTE(0) 垫等跳过
            const u32 site_rva = page_rva + u32(e & 0x0FFF);
            const SectionInfo* sec = nullptr;
            for (const auto& s : pe.sections) {
                if (site_rva >= s.virtual_addr &&
                    u64(site_rva) + w <=
                        u64(s.virtual_addr) + s.virtual_size) {
                    sec = &s;
                    break;
                }
            }
            if (sec == nullptr || (sec->characteristics & 0x2000'0000u) != 0)
                continue;
            const auto so = pe.rva_to_offset(site_rva);
            if (!so.has_value() || u64(*so) + w > ctx.image.size()) continue;
            u64 v = 0;
            std::memcpy(&v, ctx.image.data() + *so, w);  // LE
            if (v < ib) continue;
            const u64 rva = v - ib;
            if (rva < iat_base || rva + 4 > iat_base + iat_span) continue;
            if ((rva - iat_base) % w != 0) continue;
            const u64 new_v = ib + mirror_rva + (rva - iat_base);
            for (size_t b = 0; b < w; ++b)
                ctx.image[*so + b] = static_cast<u8>((new_v >> (8 * b)) & 0xFF);
            ++rewritten;
        }
        pos += block_size;
    }
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

    // MIT-477/486 (T9.1/T9.2)：代码引用重写——x64 rip 相对（MIT-477）/
    // x86 abs32 直接编址（MIT-486 砍面①）；随后数据段指针重写（砍面②，
    // 双架构）。回填（TLS 回调）保留为兜底（未识别的引用形态仍可用），
    // 运行期调用面则提前到 loader 填镜像时刻。
    size_t refs_rewritten = 0;
    if (pe->machine != kMachineX86) {
        refs_rewritten = rewrite_iat_code_refs(ctx, *pe, base, span, mirror_rva);
    } else {
        refs_rewritten = rewrite_iat_code_refs_x86(ctx, *pe, base, span, mirror_rva);
    }
    const size_t data_rewritten = rewrite_iat_data_refs(ctx, *pe, base, span, mirror_rva);

    // MIT-488 (T9.3b)：[import] skip_backfill=true → 跳回填模式。依据
    // MIT-487 完备性证据链（形态全域普查 + 迁移零残留），整段跳过 TLS
    // 回填，去掉 .rdata 页 VirtualProtect 翻转面（检测敏感）；红线 =
    // 原 IAT 全槽（含 NULL 终止槽）写入 FailFast 桩 VA——完备性论证域
    // 内无引用落原 IAT，域外形态一旦漏引，调用侧确定性 AV（受控崩溃）
    // 而非野指针静默错行为。.wvmpc 缺席 / 任一槽不可映射 → 保守回退
    // 回填模式（红线覆盖不全时跳回填语义不成立）。
    bool skip_backfill = false;
    u64 failfast_rva = 0;
    if (auto* rules = ctx.find_slot<ProtectRules>(kProtectRules);
        rules != nullptr && rules->has_import_skip_backfill &&
        rules->import_skip_backfill) {
        NewSection* wvmpc = nullptr;
        if (auto* sections = ctx.find_slot<std::vector<NewSection>>(kNewSections))
            for (auto& s : *sections)
                if (s.name == ".wvmpc") { wvmpc = &s; break; }
        // 槽映射预检（MIT-488 验收建议 4）：任一槽不可映射 = 红线覆盖
        // 不全（漏填槽残留文件残值 → 漏引时非确定性 AV）→ 整单保守回退。
        bool all_mappable = true;
        for (u64 off_in = 0; off_in + w <= span; off_in += w) {
            const auto so = pe->rva_to_offset(u32(base + off_in));
            if (!so.has_value() || u64(*so) + w > ctx.image.size()) {
                all_mappable = false;
                break;
            }
        }
        if (wvmpc == nullptr || !all_mappable) {
            ctx.diag.report(Severity::Note, name(),
                            wvmpc == nullptr
                                ? "[import] skip_backfill=true 但无 .wvmpc 节，保守回退回填模式"
                                : "[import] skip_backfill=true 但原 IAT 存在不可映射槽，保守回退回填模式");
        } else {
            // FailFast 桩：8 字节 `xor eax,eax; mov dword ptr [eax],0`
            //（31 C0 C7 00 00 00 00 00，双架构同字节）→ 写 0 地址确定性
            // AV。⚠️ 落点 = .wvmpc **尾部追加**（16 对齐，grow 语义）——
            // kEmitReserveBase 游标是 .wvmp（数据节）专属预算，其值远小
            // 于 .wvmpc 代码节尺寸，误用作落点会静默覆写解释器代码
            //（MIT-488 验收 REJECT 实录）。.wvmpc 为末节，尾部追加不破坏
            // 任何后续节 RVA（与 tls_hook 回调桩同款语义，本 pass 先行
            // 无冲突）。
            u64 cur_ff = wvmpc->data.size();
            const u64 ff_off = emit_reserve_take(wvmpc->data, cur_ff, 16, 8, true);
            const u8 ff_stub[8] = {0x31, 0xC0, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00};
            std::memcpy(wvmpc->data.data() + ff_off, ff_stub, 8);
            const u64 stub_va = pe->image_base + wvmpc->requested_rva + ff_off;
            // MIT-494：skip 模式原 IAT 全槽 = 桩 VA → 全部为绝对 VA 站点，
            // 登记（.reloc 扩展数据源；backfill 模式无此面）。
            auto& sites = ctx.slot<std::vector<u32>>(kRelocSites);
            for (u64 off_in = 0; off_in + w <= span; off_in += w) {
                const auto so = pe->rva_to_offset(u32(base + off_in));
                for (size_t b = 0; b < w; ++b)
                    ctx.image[*so + b] =
                        static_cast<u8>((stub_va >> (8 * b)) & 0xFF);
                sites.push_back(u32(base + off_in));
            }
            skip_backfill = true;
            failfast_rva = wvmpc->requested_rva + ff_off;
        }
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
    plan.skip_backfill = skip_backfill;
    plan.failfast_stub_rva = failfast_rva;
    ctx.slot<import_protect::ImportPlan>(kImportPlan) = plan;

    char buf[288];
    if (pe->machine != kMachineX86) {
        std::snprintf(buf, sizeof(buf),
                      "IAT 迁移：%u 描述符 / %u 槽（0x%llX 字节）→ .wvmp 镜像 @ RVA 0x%llX"
                      "（INT 原位；回填由 TLS 回调执行；代码引用重写 %zu 处 / 数据指针重写 %zu 处）",
                      plan.descriptor_count, plan.slot_count,
                      static_cast<unsigned long long>(span),
                      static_cast<unsigned long long>(mirror_rva), refs_rewritten,
                      data_rewritten);
    } else {
        std::snprintf(buf, sizeof(buf),
                      "IAT 迁移：%u 描述符 / %u 槽（0x%llX 字节）→ .wvmp 镜像 @ RVA 0x%llX"
                      "（INT 原位；回填由 TLS 回调执行；x86 abs32 代码引用重写 %zu 处 / 数据指针重写 %zu 处）",
                      plan.descriptor_count, plan.slot_count,
                      static_cast<unsigned long long>(span),
                      static_cast<unsigned long long>(mirror_rva), refs_rewritten,
                      data_rewritten);
    }
    if (skip_backfill) {
        char buf2[128];
        std::snprintf(buf2, sizeof(buf2),
                      "[import] skip_backfill=true：TLS 回填已跳过，原 IAT 全槽 = FailFast 红线桩 @ RVA 0x%llX",
                      static_cast<unsigned long long>(failfast_rva));
        ctx.diag.report(Severity::Note, name(), buf2);
    }
    ctx.diag.report(Severity::Note, name(), buf);
}

WVMP_REGISTER_PASS(ImportProtectPass)

} // namespace wvmp::passes
