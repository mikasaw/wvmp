#include "wvmp/passes/pe_loader/pe_image.hpp"

#include "wvmp/common/bytes.hpp"
#include "wvmp/pe_layout.hpp"

#include <algorithm>
#include <cstdio>
#include <limits>

namespace wvmp::passes {
namespace {

constexpr u16 kDosMagic = 0x5A4D;            // 'MZ'
constexpr u32 kPeSignature = 0x00004550;     // 'PE\0\0'
constexpr u16 kMachineX86 = 0x014C;
constexpr u16 kMachineX64 = 0x8664;
constexpr u16 kMagicPe32 = 0x10B;
constexpr u16 kMagicPe32Plus = 0x20B;

// 解析所需的最小 OptionalHeader 长度：覆盖到 FileAlignment @36+4。
constexpr u16 kMinOptionalHeaderSize = 64;

// MIT-525 (CR-06): OptionalHeader 内两处绝对偏移，单一真源。
// MIT-531 起数值本体上收到 common/include/wvmp/pe_layout.hpp（全仓单一真源，
// 清偿 MIT-525 GAPS「6 处本地定义」待办）；本文件保留同名薄委托，调用面零动。
constexpr u64 data_directory_offset(bool pe32_plus) {
    return wvmp::pe_data_dir_offset(pe32_plus);
}
// NumberOfRvaAndSizes 紧贴 DataDirectory 之前 4 字节（PE32 = 92 / PE32+ = 108）。
constexpr u64 num_rva_sizes_offset(bool pe32_plus) {
    return wvmp::pe_num_rva_sizes_offset(pe32_plus);
}

// DataDirectory 索引与表项宽度。
constexpr u32 kDirEntrySize = 8u;
constexpr u32 kExceptionDirIndex = 3u;   // IMAGE_DIRECTORY_ENTRY_EXCEPTION

std::string hex16(u16 v) {
    char buf[8];
    std::snprintf(buf, sizeof(buf), "0x%04X", v);
    return std::string(buf);
}

// MIT-407: 按 BeginAddress 二分查 .pdata 的实现在 PeImage::find_function_end_rva
// 内联方法（详见头文件注释）；本文件不再保留额外静态包装。

PeImage parse_impl(std::span<const u8> image) {
    if (image.size() < 0x40) throw PeParseError("文件太小，容纳不下 DOS 头");

    // —— DOS 头：'MZ' + e_lfanew @0x3C ——
    ByteReader r{image.data(), image.size()};
    if (r.read_u16() != kDosMagic) throw PeParseError("DOS 头魔数不是 'MZ'");
    r.skip(0x3A);
    const u32 pe_off = r.read_u32();
    if (pe_off < 0x40 || u64(pe_off) + 24 > image.size())
        throw PeParseError("e_lfanew 越界（" + std::to_string(pe_off) + "）");

    // —— NT 头：签名 + FILE_HEADER（20 字节）——
    r.off = pe_off;
    if (r.read_u32() != kPeSignature) throw PeParseError("PE 签名不是 'PE\\0\\0'");

    PeImage img;
    img.nt_headers_offset = pe_off;
    img.machine = r.read_u16();
    if (img.machine != kMachineX86 && img.machine != kMachineX64)
        throw PeParseError("不支持的 Machine " + hex16(img.machine) +
                           "（仅支持 x86 0x014C / x64 0x8664）");
    img.num_sections = r.read_u16();
    r.skip(12);                        // TimeDateStamp / 符号表指针 / 符号数
    const u16 opt_size = r.read_u16(); // SizeOfOptionalHeader（nt+20）
    r.skip(2);                         // FILE Characteristics → 可选头起点 nt+24

    // —— OptionalHeader：Magic 判 PE32/PE32+；EntryPoint @16、
    //    SectionAlignment @32、FileAlignment @36（两种格式偏移一致）——
    if (opt_size < kMinOptionalHeaderSize)
        throw PeParseError("SizeOfOptionalHeader 过小（" + std::to_string(opt_size) + "）");
    if (u64(r.off) + opt_size > image.size())
        throw PeParseError("OptionalHeader 越界（镜像被截断）");
    const u16 magic = r.read_u16();
    if (magic == kMagicPe32Plus) img.is_pe32_plus = true;
    else if (magic != kMagicPe32) throw PeParseError("OptionalHeader 魔数不是 PE32/PE32+");
    r.skip(14);                     // 到 AddressOfEntryPoint @16
    img.entry_point_rva = r.read_u32();
    if (img.is_pe32_plus) {
        // PE32+：BaseOfCode（4B）+ ImageBase（8B）= 12B；PE32：BaseOfCode（4B）+
        // BaseOfData（4B）+ ImageBase（4B）= 12B. 共同起点 = 紧跟 entry_point_rva 之后.
        r.skip(4);                  // BaseOfCode
        img.image_base = r.read_u64();
    } else {
        // MIT-414 (G7p2 B.1): PE32 真实布局 = BaseOfCode(4B) + BaseOfData(4B) +
        // ImageBase(4B)。漏读 BaseOfData 会让 image_base/section_alignment/
        // file_alignment 三字段整体错位 4B（image_base=BaseOfData、
        // section_alignment=ImageBase、file_alignment=SectionAlignment）——triage
        // §3.3 实测后果链：section_alignment 误读为 ImageBase(0x400000) →
        // stub_link 把 .wvmp RVA 对齐到 0x400000 → 加载器节 VA 连续性拒绝
        // (WinError 193)。BaseOfData 无下游消费（D2 决策不扩公共面），显式跳过。
        r.skip(8);                  // BaseOfCode + BaseOfData
        img.image_base = r.read_u32();
    }
    img.section_alignment = r.read_u32();
    img.file_alignment = r.read_u32();

    // —— MIT-407 / MIT-525 (CR-06): 暂存 DataDirectory[IMAGE_DIRECTORY_ENTRY_
    // EXCEPTION] (index=3) 的 RVA/Size，供节表解析之后读 .pdata 用（rva_to_offset
    // 依赖 sections，故此处只取目录表项，不读表体）。
    //
    // CR-06 改法 = 绝对定位：位置只由 opt_start（= pe_off + 24：NT 签名 4B +
    // FILE_HEADER 20B）+ data_directory_offset 派生，不再依赖前序逐字段读取
    // 留在 r.off 上的隐含落点。旧码的 `skip_to_dir = plus ? 0x48 : 0x3C` 与
    // 其注释算式 `0x60-0x24=0x3C` 里的 0x24 是"漏读 BaseOfData"（MIT-414 之前）
    // 时代 reader 的落点；MIT-414 补读 BaseOfData 后两种格式读完 FileAlignment
    // (@0x24) 都停在 0x28，PE32 的跳距应为 0x60-0x28=0x38 —— 旧值 0x3C 多跳
    // 4 字节，把 DataDirectory[3].Size 当成 RVA、把 DataDirectory[4].RVA 当成
    // Size（PE32+ 侧 0x70-0x28=0x48 本就对，所以只有 PE32 静默读空）。
    //
    // CR-07 三层校验，一律先于任何按 Size 派生的分配（下方 .pdata 扫描）：
    //  层①目录项落位：DataDirectory[0..3] 这 (3+1)*8 字节必须完整落在声明的
    //     SizeOfOptionalHeader 区间内。不满足即不读——连 NumberOfRvaAndSizes
    //     那 4 字节本身也在声明区外，读了就是拿节表字节当目录（旧码两问都不问）。
    //     本函数前面已校验 opt_start + opt_size <= image.size()，故落位即界内。
    //  层②目录计数：NumberOfRvaAndSizes >= 4，不足则本镜像没有异常目录可谈。
    //  层③表体可信性：见下方 .pdata 扫描的探尾 + 逐条映射校验。
    // 任一层不满足都记为"无异常目录"（pdata_rva 留 0 ⇒ 扫描整段跳过 ⇒
    // pdata_empty 保持初值 true），走调用方既有回退链，不抛错也不扩宽语义。
    const u64 opt_start = u64(pe_off) + 24;
    const u64 opt_end = opt_start + opt_size;
    const u64 dir_start = opt_start + data_directory_offset(img.is_pe32_plus);
    const u64 dir_slots_needed_end =
        dir_start + (kExceptionDirIndex + 1) * kDirEntrySize;
    u32 pdata_rva = 0, pdata_size = 0;
    if (dir_slots_needed_end <= opt_end) {                       // 层①
        r.off = num_rva_sizes_offset(img.is_pe32_plus) + opt_start;  // 紧前 4 字节
        const u32 num_rva_and_sizes = r.read_u32();
        if (num_rva_and_sizes >= kExceptionDirIndex + 1) {       // 层②
            r.off = dir_start + kExceptionDirIndex * kDirEntrySize;
            pdata_rva = r.read_u32();
            pdata_size = r.read_u32();
        }
    }

    // —— 节表：每项 40 字节，位于 NT 头 + 24 + SizeOfOptionalHeader ——
    r.off = opt_end;
    img.sections.reserve(img.num_sections);
    for (u16 i = 0; i < img.num_sections; ++i) {
        char raw_name[8];
        for (char& c : raw_name) c = static_cast<char>(r.read_u8());
        size_t len = 0;
        while (len < 8 && raw_name[len] != '\0') ++len;
        SectionInfo s;
        s.name.assign(raw_name, len);
        s.virtual_size = r.read_u32();
        s.virtual_addr = r.read_u32();
        s.raw_size = r.read_u32();
        s.raw_ptr = r.read_u32();
        r.skip(12);                 // 重定位/行号指针与计数
        s.characteristics = r.read_u32();
        img.sections.push_back(std::move(s));
    }

    // —— MIT-407: 解析 .pdata RUNTIME_FUNCTION 表（节表已就位）——
    // x64 RUNTIME_FUNCTION：12B/条 = BeginAddress(4) + EndAddress(4) +
    // UnwindInfoAddress(4)，按 BeginAddress 升序。
    //
    // MIT-525 架构口径（判据 3）：是否按 12B RUNTIME_FUNCTION 解释该目录，
    // 判据是"目录本身存在且三层校验通过"，**不是** machine 值。
    //  · x64（machine=0x8664）= 常态：表式 SEH 是 PE32+ 的强制组成，实测池内
    //    x64 样本 NumberOfRvaAndSizes=16、DataDirectory[3] 恒非空（Size 为 12
    //    的整倍数）；
    //  · x86（machine=0x014C）PE32 = 通常无此表：Microsoft 的 x86 SEH 是运行时
    //    链式登记，不由链接器落成静态表，`DataDirectory[3]` 写 0/0（MIT-453
    //    dumpbin 实测 + 本单全池 20 枚 x86 输入复测 = (0,0)）⇒ 本函数在真实 x86
    //    产物上自然落到 pdata_empty=true 的回退链，行为与修前逐字节一致。
    //  这里不设 machine 硬门，是为了不把"目录声明了就当没有"这一新语义塞进
    //  解析层：任何镜像（含合成夹具、非 MSVC 工具链产物）声明了异常目录，
    //  都按同一 12B 表式解释；解释不通（探尾/映射/升序/区间任一失败）一律回
    //  pdata_empty=true，由调用方回退。口径详见 docs/GAPS.md 的 MIT-525 节。
    // 防御：end <= begin 或 begin 逆序视为不可信，标记 pdata_empty=true
    // 回退；条目 RVA 无节内映射 / 超出文件边界同理（rva_to_offset 已做
    // 节映射 + 未初始化尾部防御）。
    // 教训（v1 实测）：曾用 `pdata_rva < image.size()` 比较 RVA 与**文件**
    // 大小做"文件边界防御"——RVA 空间与文件偏移空间不同构（.pdata 常在
    // 文件末尾之后，实测 test_target.exe pdata RVA=0x10D000 > 文件 0xE5C00），
    // 该防御恒为 0 → pdata_empty 恒 true → ExitNative 上界查询永远失败。
    if (pdata_rva != 0 && pdata_size >= 12) {
        const u64 entry_count = u64(pdata_size) / 12u;
        // 层③（MIT-525 CR-07）：先探尾，再决定读不读——声明区间的最后一条也必须
        // 可映射且 12 字节齐；不满足即整表不可信，一条都不读（pdata 保持空 ⇒
        // pdata_empty=true 走回退链）。旧码在这里无条件
        // `reserve(pdata_size/12)`：Size 未经任何校验，0xFFFFFFFF 就是
        // 357,913,941 条（≈4.3GB）的预分配。
        const u64 tail_rva = u64(pdata_rva) + (entry_count - 1) * 12u;
        const auto tail_off = img.rva_to_offset(tail_rva);
        bool ok = tail_off.has_value() && u64(*tail_off) + 12u <= image.size();
        u32 prev_begin = 0;
        for (u64 i = 0; ok && i < entry_count; ++i) {
            const u64 entry_rva = u64(pdata_rva) + i * 12u;
            const auto off = img.rva_to_offset(entry_rva);
            if (!off || u64(*off) + 12 > image.size()) {
                ok = false;
                break;
            }
            // ByteReader 无构造函数，按字段直填（避免 init-list 与设计意图混淆）
            ByteReader er;
            er.p = image.data() + *off;
            er.n = image.size() - *off;
            er.off = 0;
            PeImage::RuntimeFunction rf;
            rf.begin_rva = er.read_u32();
            rf.end_rva = er.read_u32();
            rf.unwind_info_rva = er.read_u32();
            if (rf.end_rva <= rf.begin_rva) { ok = false; break; }
            if (!img.pdata.empty() && rf.begin_rva < prev_begin) {
                // 乱序：MSVC 按序排放；stripped / 自改工具可能乱序——保守回退
                ok = false;
                break;
            }
            prev_begin = rf.begin_rva;
            img.pdata.push_back(rf);
        }
        img.pdata_empty = !ok || img.pdata.empty();
    }

    return img;
}

} // namespace

std::optional<u64> PeImage::find_function_end_rva(u64 begin_rva) const {
    if (pdata_empty || pdata.empty()) return std::nullopt;
    // 二分: 找 BeginAddress <= begin_rva 的最大条目, 验证 begin_rva < EndAddress
    size_t lo = 0, hi = pdata.size();
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        if (static_cast<u64>(pdata[mid].begin_rva) <= begin_rva) lo = mid + 1;
        else hi = mid;
    }
    if (lo == 0) return std::nullopt;
    const auto& cand = pdata[lo - 1];
    if (static_cast<u64>(cand.begin_rva) <= begin_rva &&
        begin_rva < static_cast<u64>(cand.end_rva)) {
        return static_cast<u64>(cand.end_rva);
    }
    return std::nullopt;
}

u64 PeImage::headers_raw_size() const {
    u64 hs = std::numeric_limits<u64>::max();
    for (const SectionInfo& s : sections)
        if (s.raw_ptr != 0) hs = hs < s.raw_ptr ? hs : s.raw_ptr;
    return hs == std::numeric_limits<u64>::max() ? 0 : hs;
}

std::optional<u64> PeImage::rva_to_offset(u64 rva) const {
    // 文件头区间：头在文件开头线性铺开，RVA == 文件偏移。
    if (rva < headers_raw_size()) return rva;
    for (const SectionInfo& s : sections) {
        if (s.raw_size == 0) continue; // 纯未初始化节（.bss 等）：无文件映射
        if (rva < s.virtual_addr || rva >= s.virtual_addr + u64(s.raw_size)) continue;
        return u64(s.raw_ptr) + (rva - s.virtual_addr);
    }
    return std::nullopt;
}

std::optional<u64> PeImage::offset_to_rva(u64 offset) const {
    if (offset < headers_raw_size()) return offset;
    for (const SectionInfo& s : sections) {
        if (s.raw_size == 0) continue;
        if (offset < s.raw_ptr || offset >= u64(s.raw_ptr) + s.raw_size) continue;
        return u64(s.virtual_addr) + (offset - s.raw_ptr);
    }
    return std::nullopt;
}

const SectionInfo* PeImage::find_section(std::string_view name) const {
    for (const SectionInfo& s : sections)
        if (s.name == name) return &s;
    return nullptr;
}

PeImage parse_pe_image(std::span<const u8> image) {
    try {
        return parse_impl(image);
    } catch (const std::out_of_range&) {
        // ByteReader 越界兜底（理论上前置边界检查已覆盖，双保险）。
        throw PeParseError("PE 结构被截断");
    }
}

} // namespace wvmp::passes
