#pragma once
// OptionalHeader 数据目录区布局偏移的全仓单一真源（MIT-531；清偿 MIT-525
// GAPS「6 处本地定义」待办）。
//
// 数值按 PE 规范（Common/include 于全部 pass 的 include 路径上，各模块不再
// 自持副本）：
//   - PE32+  OptionalHeader 定长区 112 字节 ⇒ DataDirectory @112，
//     NumberOfRvaAndSizes 紧贴其前 4 字节 @108；
//   - PE32   多一个 BaseOfData @24 ⇒ DataDirectory @96、计数 @92。
//
// 取用点（改值只许改本文件）：pe_image / pe_writer_pass / tls_hook_pass /
// import_protect_pass / stub_link_pass 及各测试副本。
#include <cstdint>

namespace wvmp {

constexpr std::uint32_t kDataDirOffsetPe32 = 96u;
constexpr std::uint32_t kDataDirOffsetPe32Plus = 112u;

// DataDirectory 区在 OptionalHeader 内的起点（= 目录表项 [0] 的偏移）。
constexpr std::uint32_t pe_data_dir_offset(bool pe32_plus) {
    return pe32_plus ? kDataDirOffsetPe32Plus : kDataDirOffsetPe32;
}

// NumberOfRvaAndSizes 字段偏移 = DataDirectory 起点前 4 字节。
constexpr std::uint32_t pe_num_rva_sizes_offset(bool pe32_plus) {
    return pe_data_dir_offset(pe32_plus) - 4u;
}

} // namespace wvmp
