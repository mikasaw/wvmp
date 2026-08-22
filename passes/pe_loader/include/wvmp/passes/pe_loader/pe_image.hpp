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
    u32 section_alignment = 0;
    u32 file_alignment = 0;
    u16 num_sections = 0;
    u32 nt_headers_offset = 0;  // DOS 头 e_lfanew
    std::vector<SectionInfo> sections;

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

} // namespace wvmp::passes
