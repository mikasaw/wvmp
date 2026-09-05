#pragma once
#include "wvmp/common/types.hpp"

namespace wvmp::passes::tls_hook {

// MIT-465 (TLS 回调基建 v1)：tls_hook pass 写入 → pe_writer 消费的契约。
// pe_writer 在 Write 阶段把 DataDirectory[9] (IMAGE_DIRECTORY_ENTRY_TLS)
// 指向 tls_dir_rva/tls_dir_size；其余字段仅供诊断输出。槽缺席 = 管道不含
// tls_hook，pe_writer 不动数据目录（无 TLS 管道镜像逐字节零回归）。
struct TlsPlan {
    u64 tls_dir_rva = 0;      // IMAGE_TLS_DIRECTORY 的 RVA（.wvmp 节内）
    u32 tls_dir_size = 0;     // 目录尺寸：PE32+ = 40 / PE32 = 24
    u64 callback_rva = 0;     // v1 占位回调桩 RVA（.wvmp 节内）
    u64 callback_va = 0;      // image_base + callback_rva（回调数组首项）
    u64 array_rva = 0;        // 回调数组 RVA（[our_va][…原回调…][NULL]）
    u32 merged_originals = 0; // 从原 PE TLS 回调数组并入的条数
};

} // namespace wvmp::passes::tls_hook
