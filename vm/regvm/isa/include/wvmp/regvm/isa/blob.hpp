#pragma once
#include "wvmp/common/bytes.hpp"
#include "wvmp/common/types.hpp"
#include "wvmp/ir/arch.hpp"

#include <vector>

namespace wvmp::regvm::isa {

// 字节码 blob：32 字节定宽头 + 8×N 指令流。头字段全定宽，磁盘/内存布局一致（LE）。
struct VmBlobHeader {
    char magic[4];       // "WVMP"
    u16 version;         // = 1
    u16 arch;            // 0=x86, 1=x64（ir::Arch 数值）
    u32 entry_offset;    // 入口在指令流内的字节偏移（8 的倍数）
    u32 insn_count;      // 指令条数（流字节数 = count*8）
    u32 seed;            // 预留加密用，v1 恒 0
    u32 reserved;        // 恒 0
    u32 reserved2;       // 恒 0（预留：块表/入口表偏移）
    u32 reserved3;       // 恒 0
};
static_assert(sizeof(VmBlobHeader) == 32);

struct VmBlob {
    VmBlobHeader header{};
    std::vector<u8> stream;
};

[[nodiscard]] VmBlob make_blob(ir::Arch arch, u32 entry_offset, std::vector<u8> stream);

void write_blob(ByteWriter& w, const VmBlob& blob);

// magic / version / count 与流长度不一致时抛 std::runtime_error。
[[nodiscard]] VmBlob read_blob(ByteReader& r);

} // namespace wvmp::regvm::isa
