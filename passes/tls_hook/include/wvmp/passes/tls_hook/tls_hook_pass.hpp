#pragma once
#include "wvmp/framework/pass.hpp"

namespace wvmp::passes {

// MIT-465：TLS 回调基建。在 .wvmp 节尾追加「占位回调桩 + 回调数组 +
// IMAGE_TLS_DIRECTORY」，经 kTlsPlan 槽把目录 RVA 交给 pe_writer 写
// DataDirectory[9]（tls_hook 只管 .wvmp 内容与计划，不动镜像头）。
//
// 原 PE 已有 TLS 目录时合并：原 6 字段（StartAddressOfRawData/End/IndexOf/
// SizeOfZeroFill/Characteristics）原样保留，回调数组重排为
// [我们的回调, 原回调…, NULL]——我们的回调排第一（先于 CRT/用户回调执行），
// 原数组所在节仍被加载、照常可读。原目录/数组不可解析时保守降级为新建。
//
// v1 回调体 = 立即返回占位（清 eax；x86 为 stdcall ret 0Ch 自清 12B 参数），
// 为 T9（import 解密）/T10（init 期反调试）预留进程入口前的执行时机。
//
// .wvmp 节缺席（stub_link 未产出）时本 pass 空转并留 Note：无 TLS 管道的
// 镜像逐字节零回归。
class TlsHookPass final : public Pass {
public:
    std::string_view name() const override { return "tls_hook"; }
    Phase phase() const override { return Phase::Emit; }
    std::span<const std::string_view> requires_keys() const override;
    std::span<const std::string_view> provides_keys() const override;
    void run(ProtectionContext& ctx) override;
};

} // namespace wvmp::passes
