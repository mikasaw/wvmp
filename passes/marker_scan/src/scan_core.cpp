#include <cstring>
#include <optional>
#include "wvmp/passes/marker_scan/scan_core.hpp"

#include <algorithm>

namespace wvmp::passes::marker_scan {

std::vector<size_t> find_all(std::span<const u8> hay, std::span<const u8> needle) {
    std::vector<size_t> hits;
    if (needle.empty() || hay.size() < needle.size()) return hits;
    const size_t last = hay.size() - needle.size();
    for (size_t i = 0; i <= last; ++i) {
        size_t j = 0;
        while (j < needle.size() && hay[i + j] == needle[j]) ++j;
        if (j == needle.size()) hits.push_back(i);
    }
    return hits;
}

std::vector<size_t> find_all_x86(std::span<const u8> hay, const X86DualMagic& m) {
    std::vector<size_t> hits;
    const auto lo_hits = find_all(hay, m.lo);
    const auto hi_hits = find_all(hay, m.hi);
    // 第二半起点窗口：[首半 + 4, 首半 + 4 + kX86MaxHalfGap]（不重叠共现）。
    // 两个独立方向各扫一遍：lo→hi（/O1 /O2 形）与 hi→lo（/Od 形）。同一
    // 物化只可能命中一个方向（第二半必须在第一半之后），不会重复计数；
    // lo4 ≠ hi4（"WVMP" vs "BEG1"/"END1"），两方向产出的锚点偏移必不相同。
    const size_t second_last = 4 + kX86MaxHalfGap;
    for (const size_t lo : lo_hits) {
        for (const size_t hi : hi_hits) {
            if (hi > lo + second_last) break; // hi_hits 升序，其后更远
            if (hi >= lo + 4) {
                hits.push_back(lo);
                break; // 窗内取首个共现 hi 即可，一处物化至多一个锚点
            }
        }
    }
    for (const size_t hi : hi_hits) {
        for (const size_t lo : lo_hits) {
            if (lo > hi + second_last) break;
            if (lo >= hi + 4) {
                hits.push_back(hi);
                break;
            }
        }
    }
    std::sort(hits.begin(), hits.end());
    return hits;
}

std::vector<CallRef> scan_calls(std::span<const u8> code, size_t base_off) {
    std::vector<CallRef> calls;
    if (code.size() < 5) return calls;
    const size_t last = code.size() - 5;
    for (size_t off = 0; off <= last; ++off) {
        if (code[off] != 0xE8) continue;
        const auto rel = static_cast<u32>(code[off + 1]) |
                         (static_cast<u32>(code[off + 2]) << 8) |
                         (static_cast<u32>(code[off + 3]) << 16) |
                         (static_cast<u32>(code[off + 4]) << 24);
        // next 指令绝对偏移 + 符号扩展的 rel32 = 目标；负地址（回绕）跳过。
        const auto next_abs = static_cast<i64>(base_off) + static_cast<i64>(off) + 5;
        const auto target = next_abs + static_cast<i64>(static_cast<i32>(rel));
        if (target < 0) continue;
        calls.push_back(CallRef{base_off + off, base_off + off + 5, static_cast<size_t>(target)});
    }
    return calls;
}

MarkerCalls attribute_marker_calls(std::span<const CallRef> calls, std::span<const Anchor> anchors,
                                   size_t max_back) {
    MarkerCalls out;
    std::vector<size_t> magic_offs;
    magic_offs.reserve(anchors.size());
    for (const auto& a : anchors) magic_offs.push_back(a.magic_off);
    for (const auto& c : calls) {
        // 第一个 magic_off >= target 的锚（桩入口在 magic 之前）
        const auto it = std::lower_bound(magic_offs.begin(), magic_offs.end(), c.target_off);
        if (it == magic_offs.end()) continue; // target 在所有锚之后
        const size_t idx = static_cast<size_t>(it - magic_offs.begin());
        if (magic_offs[idx] - c.target_off > max_back) continue; // 入口离 magic 过远
        if (anchors[idx].is_begin)
            out.begin_nexts.push_back(c.next_off);
        else
            out.end_addrs.push_back(c.insn_off);
    }
    return out;
}

PairResult pair_regions(std::vector<size_t> begin_nexts, std::vector<size_t> end_addrs) {
    PairResult res;
    std::vector<size_t> open; // 未闭合 begin 的区域起点栈
    size_t bi = 0, ei = 0;
    while (bi < begin_nexts.size() || ei < end_addrs.size()) {
        const bool take_begin = ei >= end_addrs.size() ||
            (bi < begin_nexts.size() && begin_nexts[bi] <= end_addrs[ei]);
        if (take_begin) {
            open.push_back(begin_nexts[bi++]);
        } else {
            const size_t end_off = end_addrs[ei++];
            if (!open.empty()) {
                res.regions.push_back(Region{open.back(), end_off});
                open.pop_back();
            } else {
                res.unmatched_ends.push_back(end_off);
            }
        }
    }
    res.unmatched_begins = std::move(open);
    return res;
}



std::optional<NameOperand> locate_name_operand(std::span<const u8> image,
                                               size_t call_next_off, bool is_x86) {
    const auto le32 = [&](size_t off) {
        return static_cast<i64>(static_cast<u32>(image[off])) |
               (static_cast<i64>(static_cast<u32>(image[off + 1])) << 8) |
               (static_cast<i64>(static_cast<u32>(image[off + 2])) << 16) |
               (static_cast<i64>(static_cast<u32>(image[off + 3])) << 24);
    };
    if (is_x86) {
        // push imm32（68 <abs32>）紧邻 E8。
        if (call_next_off < 10) return std::nullopt;
        const size_t base = call_next_off - 10;
        if (base + 10 > image.size()) return std::nullopt;
        if (image[base] != 0x68) return std::nullopt;
        return NameOperand{false, le32(base + 1)};
    }
    // x64: lea rcx,[rip+disp32]（48 8D 0D <disp32>）紧邻 E8。
    if (call_next_off < 12) return std::nullopt;
    const size_t base = call_next_off - 12;
    if (base + 12 > image.size()) return std::nullopt;
    if (image[base] != 0x48 || image[base + 1] != 0x8D || image[base + 2] != 0x0D)
        return std::nullopt;
    // disp 有符号（MIT-460 验收反馈：.rdata 在 lea 之前布局时 disp 为负，
    // 零扩展会算出偏大 2^32 的地址——经 i32 符号扩展修正）。
    const u32 raw = static_cast<u32>(le32(base + 3));
    i32 disp_signed = 0;
    std::memcpy(&disp_signed, &raw, sizeof(disp_signed));
    return NameOperand{true, static_cast<i64>(disp_signed)};
}

} // namespace wvmp::passes::marker_scan
