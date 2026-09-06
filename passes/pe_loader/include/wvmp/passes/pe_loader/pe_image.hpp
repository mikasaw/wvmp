// PE 只读结构模型（P2 泳道共享：pe_loader 解析产出，pe_writer 消费）。
//
// 轻量设计：只保存后续 pass 需要的字段，不做布局修复/重定位。
// 语义与 lifter 泳道的 pe_map（passes/lifter/src/pe_map.hpp）保持兼容：
//   - 节内按已初始化区间 [rva, rva + SizeOfRawData) 线性映射（与
//     pe_map::rva_to_offset 完全一致：未初始化尾部 / 纯 .bss 节不映射，
//     raw_size==0 的节跳过）；
//   - 额外支持文件头区间的恒等映射（pe_map 无此能力，属其超集），
//     M1 集成时可直接替换 pe_map 而不改变任何现有调用点的行为。
#pragma once

#include "wvmp/common/types.hpp"
#include "wvmp/framework/keys.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace wvmp::passes {

struct SectionInfo {
    std::string name;        // 节名（原始 8 字节，截断于首个 NUL）
    u32 characteristics = 0; // 节属性（CNT_CODE/MEM_EXECUTE/...）
    u32 virtual_size = 0;    // VirtualSize
    u32 virtual_addr = 0;    // VirtualAddress（RVA）
    u32 raw_size = 0;        // SizeOfRawData
    u32 raw_ptr = 0;         // PointerToRawData（文件偏移）
};

// 解析出的 PE 头部模型（只读快照，指向 ctx.image 解析时刻的状态）。
struct PeImage {
    bool is_pe32_plus = false;  // OptionalHeader Magic == 0x20B（PE32+）
    u16 machine = 0;            // IMAGE_FILE_MACHINE_*（0x14c x86 / 0x8664 x64）
    u32 entry_point_rva = 0;    // AddressOfEntryPoint
    u64 image_base = 0;         // PE optional header 的 ImageBase（PE32=4B / PE32+=8B；
                                // M2-8 起供 rip-relative 翻译期把 [rip+disp] 转 RVA 时
                                // 与 stub 协定的 image_base 字段互校）
    u32 section_alignment = 0;
    u32 file_alignment = 0;
    u16 num_sections = 0;
    u32 nt_headers_offset = 0;  // DOS 头 e_lfanew
    std::vector<SectionInfo> sections;

    // —— MIT-407: .pdata (IMAGE_DIRECTORY_ENTRY_EXCEPTION) 解析 ——
    // x64 RUNTIME_FUNCTION 表：12B/条 = BeginAddress(4) + EndAddress(4) +
    // UnwindInfoAddress(4)，按 BeginAddress 升序。越区跳转 ExitNative 上界
    // 算法 = RUNTIME_FUNCTION.EndAddress（triage §3 三候选实测 17/17 完胜）。
    // 无 .pdata / 无 DataDirectory[3] / 解析失败时 pdata_empty = true，
    // 调用方须回退 next-marker-begin / section-end 兜底，行为与修复前逐
    // 字节一致（保守 gate）。
    struct RuntimeFunction {
        u32 begin_rva = 0;       // 函数起始 RVA（含）
        u32 end_rva = 0;         // 函数结束 RVA（不含）
        u32 unwind_info_rva = 0; // UNWIND_INFO RVA（仅诊断，本单不消费）
    };
    std::vector<RuntimeFunction> pdata;
    bool pdata_empty = true;    // true = 未解析到或解析失败 → 回退链

    // 给定 begin_rva 查 .pdata 找到包含它的函数 EndAddress（含 begin_rva
    // 自身的 exact 命中优先；fallback = BeginAddress ≤ begin_rva < EndAddress
    // 的最长前缀）。找不到返回 std::nullopt（调用方决定 gate 还是回退）。
    // .pdata 按 BeginAddress 升序，二分 O(log N)；triage 实测 test_target.exe
    // .pdata 1805 条 0x549C B，二分毫秒级。
    std::optional<u64> find_function_end_rva(u64 begin_rva) const;

    // RVA → 文件偏移。文件头区间（首个含原始数据的节的 PointerToRawData
    // 之前，头在文件中线性铺开，RVA==偏移）直接返回；否则按节表已初始化
    // 区间映射；未映射（节间隙 / 未初始化尾部 / 越界）返回 nullopt。
    std::optional<u64> rva_to_offset(u64 rva) const;

    // 文件偏移 → RVA，rva_to_offset 的对称操作。
    std::optional<u64> offset_to_rva(u64 offset) const;

    // 按节名精确查找，找不到返回 nullptr。
    const SectionInfo* find_section(std::string_view name) const;

    // 文件头原始区间大小：各含原始数据节的 PointerToRawData 最小值；
    // 无含原始数据的节时为 0（此时头部恒等映射不可用）。
    u64 headers_raw_size() const;
};

// PE 解析错误（结构不合法 / 不支持的平台）。
class PeParseError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// 解析 image 的 DOS 头 / NT 头 / 节表。校验 MZ、e_lfanew 范围、PE 签名、
// Machine（x86 0x14c / x64 0x8664）、OptionalHeader Magic（PE32/PE32+）
// 及节表边界；结构不合法抛 PeParseError（含可读原因）。
PeImage parse_pe_image(std::span<const u8> image);

// context 扩展槽 key：pe_loader 存入 PeImage 模型，marker_scan/lifter 等
// 下游 pass 读取。M1 起提升为框架共享 key（framework/keys.hpp 的 kPeImage），
// 此处别名保持旧调用点不变。
inline constexpr std::string_view kImageMeta = wvmp::kPeImage;

// —— 新节请求/落位（M2：stub_link 产出 → pe_writer 落盘）——
//
// 请求方（stub_link）填充 NewSection 放入 kNewSections 槽；pe_writer 的
// add_sections 负责实际落位并返回 SectionPlacement（RVA 一旦定下，payload
// 内的 rip 相对引用即自洽——请求方按 placement 生成对外部 .text 的引用）。
struct NewSection {
    std::string name;      // <= 8 字节（PE 节名上限）
    std::vector<u8> data;  // 节内容（raw 数据，落盘时按 file_alignment 补齐）
    u32 characteristics = 0;
    u32 requested_rva = 0; // 0 = 自动分配（最后一个节末端对齐后）；非 0 则
                           // 校验无冲突后按请求落位（供 payload 预计算地址）。
};

struct SectionPlacement {
    u32 rva = 0;         // 落位后的 VirtualAddress
    u32 file_offset = 0; // 落盘 PointerToRawData
    u32 raw_size = 0;    // 对齐后的 SizeOfRawData
};

// ---------------------------------------------------------------------------
// MIT-476 (T20)：Emit 阶段数据节预留区协议。
//
// stub_link 生成 .wvmp 时把 payload 预扩至 blobs + kEmitReserveBytes，并把
// "下一个可写偏移"（= blobs 末端）放入 kEmitReserveBase 槽；后续 Emit pass
// （import_protect 镜像 IAT/oldprot、tls_hook CONTEXT/rdtsc/TLS 面）经
// emit_reserve_take 在预留区内对齐分配。节最终尺寸恒定 = blobs + 预留 →
// 代码节 requested_rva（stub 链接期已烘焙进 rel32）的连续性校验不再依赖
// 节对齐垫片吸收追加（T16 验收票①：追加超垫片即 "not contiguous" 硬失
// 败）；全 gate（零 blob）时数据节也恒非空（票②）。
inline constexpr u64 kEmitReserveBytes = 0x2000;  // 8KB（实测追加峰值 ~2KB）

// 从预留区对齐分配 bytes；返回区内偏移（调用方 + requested_rva 得 RVA）。
// grow_ok = 预留槽缺席（旧夹具/单测）时的旧"尾部追加"语义：空间不足即
// 扩容；协议模式下不足则抛错（明确预算超限，优于静默重叠）。
[[nodiscard]] inline u64 emit_reserve_take(std::vector<u8>& data, u64& cursor,
                                           u64 align, u64 bytes, bool grow_ok) {
    const u64 off = (cursor + align - 1) / align * align;
    if (off + bytes > data.size()) {
        if (!grow_ok)
            throw std::runtime_error("emit data reserve exhausted: need " +
                                     std::to_string(off + bytes) + ", budget " +
                                     std::to_string(data.size()));
        data.resize(static_cast<size_t>(off + bytes), 0);
    }
    cursor = off + bytes;
    return off;
}

} // namespace wvmp::passes
