#pragma once
#include "wvmp/passes/pe_loader/pe_image.hpp"

#include <vector>

namespace wvmp::passes {

// 向 PE 镜像追加新节（M2-2）：
//  - 节表必须还有头部空间（新表项全部落在首个原始数据节之前）；
//  - 数据追加文件尾，按 file_alignment 对齐；RVA 默认接最后一个节末端按
//    section_alignment 对齐；requested_rva 非 0 时校验与既有节区间无重叠，
//    且必须与前一节对齐端连续（无 VA 空洞——Windows 加载器拒绝空洞布局，
//    MIT-414 G7p2 B.4，triage §3.3 实测）；
//  - 顺序 = 先算完整落位表 → 对这张表做全部校验 → 只按这张表写盘
//    （CR-08/MIT-528：auto 游标不被 fixed 请求推位，混排下"校验通过的布局
//    == 实际写入布局"）；混排不成立（留洞/逆序/重叠）一律显式失败；
//  - 同步更新 NumberOfSections 与 SizeOfImage（后者 == 连续链末端）；
//  - 成功返回逐节落位（与请求同序，表序即地址序：RVA 严格单调）；失败抛
//    std::runtime_error（镜像不被部分修改——所有校验先行，通过后才动字节）。
std::vector<SectionPlacement> add_sections(std::vector<u8>& image,
                                           const std::vector<NewSection>& requests,
                                           u32 section_alignment, u32 file_alignment);

} // namespace wvmp::passes
