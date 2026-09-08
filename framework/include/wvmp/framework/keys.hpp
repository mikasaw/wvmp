#pragma once
#include <string_view>
namespace wvmp {
inline constexpr std::string_view kImage="image", kFunctions="functions", kLiftedIr="ir.lifted", kVmProgram="vm.program", kVmRuntime="vm.runtime", kNewSections="pe.new_sections";
// MIT-476：.wvmp 数据节预留区"下一个可写偏移"（stub_link 置初值 = blobs
// 末端；import_protect/tls_hook 读写推进）。类型 u64，槽未置 = 旧"尾部
// 追加"语义（旧夹具/单测兼容）。
inline constexpr std::string_view kEmitReserveBase="pe.emit_reserve_base";
// MIT-494 ASLR 兼容：packer 发射的绝对 VA 站点 RVA 表（stub_link/tls_hook/
// import_protect 发射点登记 → pe_writer 消费生成 .reloc 扩展块）。类型
// std::vector<u32>（站点 RVA）。发射点登记优于全镜像事后扫描——扫描在
// 全镜像粒度存在结构化数据假阳（误登记 = loader 对非 VA 值加 delta =
// 静默数据损坏，MIT-494 开发实录）；生产方只扫自产小 buffer，命中即真。
inline constexpr std::string_view kRelocSites="pe.reloc_sites";
// pe_loader 产出的 PE 结构模型（PeImage）所在扩展槽——M1 起为 marker_scan/lifter
// 等分析类 pass 的共享依赖（提供方：pe_loader）。
inline constexpr std::string_view kPeImage="pe.image_meta";
// MIT-457 配置系统 v1：保护规则集（CLI 解析 TOML 后写入；virtualize 等
// pass 消费）。模型见 framework/protect_levels.hpp。
inline constexpr std::string_view kProtectRules="config.protect_rules";
// MIT-458 crypt-v1：字节码加密计划（crypt pass 写入 → stub_link 消费）。
// 契约模型见 passes/crypt/include/wvmp/passes/crypt/crypt_plan.hpp。
inline constexpr std::string_view kCryptPlan="crypt.plan";
// MIT-463 anti_debug-v1：反调试计划（anti_debug pass 写入 → stub_link 消费）。
// 契约模型见 passes/anti_debug/include/wvmp/passes/anti_debug/anti_debug_plan.hpp。
inline constexpr std::string_view kAntiDebugPlan="anti_debug.plan";
// MIT-465 TLS 回调基建：TLS 目录计划（tls_hook pass 写入 → pe_writer 消费，
// 落 DataDirectory[9]）。契约模型见 passes/tls_hook/include/wvmp/passes/
// tls_hook/tls_plan.hpp。
inline constexpr std::string_view kTlsPlan="tls.plan";
// MIT-466 import_protect v1：IAT 迁移计划（import_protect 写入 → tls_hook
// 消费，TLS 回调内回填原 IAT 区）。契约模型见 passes/import_protect/
// include/wvmp/passes/import_protect/import_plan.hpp。
inline constexpr std::string_view kImportPlan="import.plan";
}
