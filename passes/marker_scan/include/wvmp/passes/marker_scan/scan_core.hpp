#pragma once
#include "wvmp/common/types.hpp"
#include <array>
#include <cstddef>
#include <span>
#include <vector>

// marker_scan 泳道内部的扫描核心：纯函数（字节输入 → 调用点/区域输出），
// 不依赖 ProtectionContext / PE 结构，便于用手工构造的字节串做单元测试。
// 语义与 vmprotect core/intel.cc 的 ReadMarkerCommands 思路同源（自写实现）：
// 定位桩函数锚点 → 找出所有指向桩的调用 → 按地址序配对成保护区域。

namespace wvmp::passes::marker_scan {

// magic 字节模式（8 字节 LE），必须与 sdk/include/wvmp/sdk/markers.hpp 的
// kBeginMagic / kEndMagic 保持同步（跨模块不共享私有头，集成测试有断言）。
inline constexpr std::array<u8, 8> kBeginPattern{
    0x57, 0x56, 0x4D, 0x50, 0x42, 0x45, 0x47, 0x31}; // "WVMPBEG1"
inline constexpr std::array<u8, 8> kEndPattern{
    0x57, 0x56, 0x4D, 0x50, 0x45, 0x4E, 0x44, 0x31}; // "WVMPEND1"

// —— x86 (32 位) 双段 magic（X1a）——
// SDK 桩在 32 位编译下把 64 位 magic 拆成两条 imm32，8 字节 needle 不连续。
// cl v19.51.36256 x86 产物实测（dumpbin /disasm，2026-09-01，MIT-437 探针）：
//   /O1 /O2: C7 <mem>,<lo4> ; C7 <mem>,<hi4>           （lo→hi，紧邻，间隔 0）
//   /Od    : B8 <hi4> ; C7 <mem>,<lo4> ; 89 <mem>,reg  （hi→lo，间隔 3B）
// 优化档位决定顺序与间隔 → 两方向都必须识别；判据只认"两半共现 + 间隔
// ≤ kX86MaxHalfGap"，不钉具体 opcode（/Od 的 hi 半只经 B8 物化一次，靠
// 89 落盘的部分不含 imm，与 GAPS C5 旧记录的 C7×2 形同源不同档）。
struct X86DualMagic {
    std::array<u8, 4> lo; // magic 低 32 位（LE 字节 0..3，"WVMP"）
    std::array<u8, 4> hi; // magic 高 32 位（LE 字节 4..7，"BEG1"/"END1"）
};

// 两半允许的最大间隔（后半起点 − 前半终点）。宁窄勿宽：实测最大 3B（/Od）
// + 一条普通填充指令余量；任何放宽须配幻影锚点负例回归（424 §3.2 / 432 §6.2）。
inline constexpr size_t kX86MaxHalfGap = 8;

// 单一来源派生：x86 两半直接取自 8 字节模式的前/后 4 字节，禁止另写字面量
//（与 sdk markers.hpp 的同步性由 MagicSync 断言护栏，MIT-437 B.4）。
inline constexpr X86DualMagic x86_dual_of(const std::array<u8, 8>& m) {
    return X86DualMagic{{m[0], m[1], m[2], m[3]}, {m[4], m[5], m[6], m[7]}};
}
inline constexpr X86DualMagic kBeginPatternX86 = x86_dual_of(kBeginPattern);
inline constexpr X86DualMagic kEndPatternX86 = x86_dual_of(kEndPattern);

// magic 出现处前后各 64 字节视为桩函数体窗口：E8 目标落在窗口内即视为
// 对该桩的调用。不需要精确的函数边界（任务约定的简化）。
inline constexpr size_t kStubWindow = 64;

// 在 hay 中找出 needle 的所有出现位置（允许重叠出现）。
std::vector<size_t> find_all(std::span<const u8> hay, std::span<const u8> needle);

// 在 hay 中定位 x86 双段 magic 的物化起点（两半中较早出现的那个的偏移），
// 升序返回。识别 lo→hi / hi→lo 两方向；同一物化恰好命中一个方向（第二半
// 必须在第一半之后，两方向按构造互斥，不产生重复锚点）。8 字节连续 magic
// 是间隔 0 的退化双段，同样命中（x86 镜像容忍连续形态，X1a D1 实测兜底）。
std::vector<size_t> find_all_x86(std::span<const u8> hay, const X86DualMagic& m);

// 一条 E8 rel32 调用（文件偏移语义；base_off 是所扫片段在镜像中的起点）。
struct CallRef {
    size_t insn_off = 0;   // E8 指令偏移
    size_t next_off = 0;   // 下一条指令偏移（insn_off + 5，即保护区域起点）
    size_t target_off = 0; // call 目标偏移（桩函数入口）
};

// 枚举 code 中所有字节位置上的 E8 rel32 并计算 call 目标。
// v1 简化：按字节枚举而非精确反汇编，指令内部字节也可能被误当 E8，
// 由调用方用"目标必须落在桩窗口内"过滤（真实误报率可忽略，见 pass 注释）。
std::vector<CallRef> scan_calls(std::span<const u8> code, size_t base_off);

// 保护区域：[begin_off, end_off)。
//   begin_off = begin 调用点下一条指令偏移（call 之后，被保护代码起点）
//   end_off   = end 调用点指令偏移（call 之前，被保护代码终点）
struct Region {
    size_t begin_off = 0;
    size_t end_off = 0;
};

struct PairResult {
    std::vector<Region> regions; // 按闭合地址序产出（调用方需按 begin 排序）
    std::vector<size_t> unmatched_begins; // 未闭合的 begin（区域起点）
    std::vector<size_t> unmatched_ends;   // 无 begin 的 end（指令偏移）
};

// 栈式配对（支持嵌套标记）：输入各自升序，按地址序归并事件——
// begin 入栈；end 弹栈成区域，栈空则记 unmatched_end；剩余栈为 unmatched_begin。
PairResult pair_regions(std::vector<size_t> begin_nexts, std::vector<size_t> end_addrs);

// 一个 magic 锚点（出现位置 + 类别）。anchors 必须 magic_off 严格升序。
struct Anchor {
    size_t magic_off = 0;
    bool is_begin = false;
};

// 调用点归属结果：begin 调用点的下一条指令偏移 / end 调用点的指令偏移。
struct MarkerCalls {
    std::vector<size_t> begin_nexts;
    std::vector<size_t> end_addrs;
};

// 把每个 E8 调用点排他地归属到一个桩：桩入口必位于其 magic 之前，故
// target 归属"第一个 magic_off >= target 且距离 <= max_back"的锚。
// begin/end 两桩通常相邻（同一 sdk.cpp），朴素的双向 ±64 窗口会互相
// 串扰（把 end 调用也算成 begin），"紧随其后"规则天然排他。
MarkerCalls attribute_marker_calls(std::span<const CallRef> calls, std::span<const Anchor> anchors,
                                   size_t max_back);

} // namespace wvmp::passes::marker_scan
