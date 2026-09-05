#pragma once
#include "wvmp/common/types.hpp"

namespace wvmp::passes::import_protect {

// MIT-466 (import_protect v1)：IAT 迁移计划——import_protect 写入 →
// tls_hook 消费（TLS 回调把已解析的镜像 IAT 回填原 .rdata IAT 区）。
//
// 迁移语义（v1）：
//   - dd[1] 各描述符的 FirstThunk RVA 重指到 .wvmp 镜像切片；INT
//     (OriginalFirstThunk) 原位保留——loader 以 INT 解析名字、把真实地址
//     写进 .wvmp 镜像（文件态镜像 = 种子派生乱数，非真实地址）；
//   - TLS 回调（早于任何用户代码）把镜像整段 memcpy 回填原 IAT 区，
//     原生 FF15 引用与 VM 翻译期烙入的 IAT RVA 两侧零改写全兼容；
//   - 回退：dd1 缺失 / 绑定导入 / 槽扫描越界等任一异常 → 整单放弃迁移
//     （不写槽、不改镜像），保持原表原样。
struct ImportPlan {
    bool active = false;      // true = 已迁移；false = 未迁移（槽不写）
    u64 iat_base_rva = 0;     // 原 IAT 区起始 RVA（各描述符 FirstThunk 最小值）
    u64 iat_bytes = 0;        // 区总字节数（含各描述符的 NULL 终止槽）
    u64 mirror_rva = 0;       // .wvmp 内镜像起始 RVA（文件态 = 乱数）
    u32 slot_count = 0;       // 槽总数（8B/4B 按宿主位宽）
    u32 descriptor_count = 0; // 迁移的导入描述符数

    // —— 回填支持（TLS 回调执行面）——
    // 原始 IAT 所在页在 loader 解析完成并被重新保护后为只读：回填必须先
    // VirtualProtect 解除、回填后按保存值恢复。vp 槽 = 目标 IAT 中
    // kernel32!VirtualProtect 的槽 RVA（v1 硬依赖：目标未导入该 API 则
    // 整单放弃迁移）；oldprot = .wvmp 内 8 字节可写暂存（保存旧保护值）。
    u64 vp_slot_rva = 0;      // VirtualProtect 的 IAT 槽 RVA
    u64 page_rva = 0;         // 原 IAT 区所在首页 RVA（页对齐）
    u64 page_bytes = 0;       // 覆盖整个 IAT 区的页跨度
    u64 oldprot_rva = 0;      // .wvmp 内旧保护值暂存（u32，8B 对齐）
};

} // namespace wvmp::passes::import_protect
