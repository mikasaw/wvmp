#pragma once
#include "wvmp/common/types.hpp"

#include <string>
#include <vector>

namespace wvmp::passes {

// 生成单个被虚拟化函数的入口 stub（x64，位置无关）。
//
// stub 运行时职责：
//   保存 callee-saved → 在栈上构造 VmContext → 预载全部 16 个 GP 虚拟寄存器
//   → 调用共享解释器入口 → HALT 返回后回写易失寄存器 → 恢复现场 →
//   jmp 回原区域 end_rva（恢复执行原 .text 中的 end 标记调用之后流程）。
//
// 地址约定（全 RVA 坐标，与镜像基址无关）：
//   - 以 at=stub_rva 汇编，`call <rt_entry_rva>` / `jmp <resume_rva>` 由
//     汇编器按相对位移编码（运行时随基址平移自动正确）；
//   - 唯一 rip 相对引用（blob 指令流指针）用占位 disp32 汇编后回填。
//
// image_base（PE optional header 的 ImageBase 字段）写入 VmContext+0x110
// （即 scratch_mem 槽 = 运行时 Load/Store/Push/Pop 用的内存基址）。rip-relative
// 翻译期把 [rip+disp] 算成绝对 RVA 存进字节码；运行时实际访存 = RVA + image_base。
// v1 测试用 image_base=0（绝对地址空间）；M2-8 真实 PE 保护时由 pe_loader
// 解析 PE optional header 取出，经 stub_link 传给本函数。
//
// 所有立即数经 hex() 生成——keystone 裸数字按 16 进制解析（P6 教训）。
[[nodiscard]] std::vector<u8> generate_entry_stub(u64 stub_rva, u64 blob_stream_rva,
                                                  u64 rt_entry_rva, u64 resume_rva,
                                                  u64 image_base);

} // namespace wvmp::passes
