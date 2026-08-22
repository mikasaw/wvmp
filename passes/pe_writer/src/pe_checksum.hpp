// PE 标准校验和（pe_writer 内部工具，不属于契约）。
#pragma once

#include "wvmp/common/types.hpp"

#include <cstddef>
#include <span>

namespace wvmp::passes {

// PE 标准校验和：镜像按小端 u16 累加，每步折进位（保持 ≤0xFFFF），
// 跳过 chk_off 处 4 字节的 CheckSum 字段（调用前应已清零/视作零），
// 奇数长度末字节按高字节补 0 计入，最后加上文件总长。
// 与 imagehlp!CheckSumMappedFile / vmprotect core 的算法一致。
// 要求：chk_off 为偶数且 chk_off + 4 <= img.size()。
u32 pe_checksum(std::span<const u8> img, size_t chk_off);

} // namespace wvmp::passes
