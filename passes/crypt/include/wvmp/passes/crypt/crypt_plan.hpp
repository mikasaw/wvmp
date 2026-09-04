#pragma once
#include "wvmp/common/types.hpp"

#include <string>
#include <vector>

namespace wvmp::passes::crypt {

// MIT-458 (crypt-v1)：crypt pass 与 stub_link pass 之间的契约（扩展槽
// kCryptPlan 传递；本头为两 pass 共享面——provider = crypt，consumer =
// stub_link，跨 pass 头引用先例 = stub_link → virtualize_pass.hpp）。

inline constexpr std::string_view kAlgoXorChain = "xor_chain";

// 密文流之后的 8B 尾区：[u32 flag][u32 crc32]（MIT-464：reserved 槽兑现
// 为密文流 CRC32——integrity_crc pass 计算写入，stub 解密前校验）。
// flag 初值 1 = 已加密待解密；stub 入口解密块 one-shot 语义（xor_chain
// 同段内存只可执行一次，重复执行 = 再加密）；解密后 stub 写 0。
// ⚠️ D1 边界（MIT-458 披露）：首入口并发（两线程同时见 flag=1）会双重
// 解密致损——v1 威胁模型为单线程初始化/顺序进入，多线程首次并发进入
// 含 crypt 区域属未定义面（与 G4 lock 原子性 D1 同级的显式边界）。
inline constexpr u64 kTrailerBytes = 8;
inline constexpr u32 kFlagEncrypted = 1;
inline constexpr u32 kFlagDecrypted = 0;

struct CryptedFunction {
    size_t vfs_index = 0;            // kVmProgram 向量下标（配对键，升序）
    std::string name;                // 诊断用（= vf.name）
    u32 key0 = 0;                    // xor_chain 初态（stub 侧嵌入同一常量）
    std::vector<u8> encrypted_blob;  // 32B 明文头 + 密文流 + 8B 尾区 [flag][crc32]
    u64 stream_bytes = 0;            // 流长（= 明文流长；加密定长）；尾区位于流起点 + stream_bytes
    // MIT-464: 密文流 CRC32（integrity_crc pass 计算写入尾区 reserved→crc32
    // 槽 + 本字段；stub 经 StubCrypt 拿到嵌入值做解密前校验）。
    bool has_crc = false;
    u32 crc32 = 0;
};

struct CryptPlan {
    std::string algo;  // = kAlgoXorChain（v1 恒；非此值的 plan 由 stub_link 拒）
    std::vector<CryptedFunction> functions;
};

} // namespace wvmp::passes::crypt
