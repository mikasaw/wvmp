#include "lifter_core.hpp"

#include "x86_translate.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <string>

namespace wvmp::passes::lifter {

namespace {

LiftedItem::Ctl control_kind(ir::Op op) {
    switch (op) {
    case ir::Op::Jcc: return LiftedItem::Ctl::Jcc;
    case ir::Op::Jmp: return LiftedItem::Ctl::Jmp;
    case ir::Op::Call: return LiftedItem::Ctl::Call;
    case ir::Op::Ret: return LiftedItem::Ctl::Ret;
    default: return LiftedItem::Ctl::None;
    }
}

void append_unique(std::vector<u64>& v, u64 value) {
    if (std::find(v.begin(), v.end(), value) == v.end()) v.push_back(value);
}

} // namespace

void build_blocks(u64 begin_rva, u64 end_rva, std::span<const LiftedItem> items,
                  std::vector<ir::BasicBlock>& out) {
    out.clear();
    if (items.empty()) return;

    // 1) leader 集合：区域起点、各立即目标、jcc/call 后的 fallthrough 点、区域终点。
    std::set<u64> leaders;
    leaders.insert(begin_rva);
    leaders.insert(end_rva);
    for (const LiftedItem& it : items) {
        const u64 next = it.addr + it.raw_size;
        switch (it.ctl) {
        case LiftedItem::Ctl::Jcc:
            if (!it.indirect) leaders.insert(it.target);
            leaders.insert(next); // 条件跳转的两个出口之一
            break;
        case LiftedItem::Ctl::Jmp:
            if (!it.indirect) leaders.insert(it.target);
            break; // 无条件跳转后的字节不可达，不作为 leader（除非同时是其他目标）
        case LiftedItem::Ctl::Call:
            if (!it.indirect) leaders.insert(it.target);
            leaders.insert(next); // 返回点
            break;
        default:
            break;
        }
    }

    // 2) 按 leader 切块（items 已按地址升序排列）。块终结符（jmp/ret）之后
    //    的死代码不属于任何块。
    std::map<u64, size_t> block_index; // 块地址 → out 下标
    size_t current = SIZE_MAX;
    std::vector<const LiftedItem*> placement; // 与 out 平行：每块最后一条指令
    for (const LiftedItem& it : items) {
        const bool is_leader = leaders.count(it.addr) != 0;
        const bool prev_terminated =
            current != SIZE_MAX && placement[current] != nullptr &&
            (placement[current]->ctl == LiftedItem::Ctl::Jmp ||
             placement[current]->ctl == LiftedItem::Ctl::Ret);
        if (current == SIZE_MAX || is_leader) {
            ir::BasicBlock bb;
            bb.addr = it.addr;
            out.push_back(std::move(bb));
            block_index[it.addr] = out.size() - 1;
            current = out.size() - 1;
            placement.push_back(nullptr);
        } else if (prev_terminated) {
            continue; // 死代码
        }
        if (it.insn) out[current].insns.push_back(*it.insn);
        placement[current] = &it;
    }

    // 3) succs：看每块最后一条（被放置的）指令。
    for (size_t i = 0; i < out.size(); ++i) {
        const LiftedItem* last = placement[i];
        if (last == nullptr) continue; // 空块（理论上不会出现）
        const u64 next = last->addr + last->raw_size;
        switch (last->ctl) {
        case LiftedItem::Ctl::Jcc:
            if (!last->indirect) append_unique(out[i].succs, last->target);
            append_unique(out[i].succs, next); // fallthrough 必然是出口
            break;
        case LiftedItem::Ctl::Jmp:
            if (!last->indirect) append_unique(out[i].succs, last->target);
            break;
        case LiftedItem::Ctl::Ret:
            break;
        default: // 普通指令 / call：顺序落入下一块或区域出口
            if (next < end_rva) append_unique(out[i].succs, next);
            break;
        }
    }

    // 4) preds：succs 反推（仅区域内边）。
    for (const ir::BasicBlock& b : out) {
        for (u64 s : b.succs) {
            auto it = block_index.find(s);
            if (it != block_index.end()) append_unique(out[it->second].preds, b.addr);
        }
    }
}

u64 disassemble_and_lift(CapstoneSession& session, const u8* code, size_t size, u64 begin_rva,
                         u64 end_rva, std::string_view func_name, std::string_view pass_name,
                         Diagnostics& diag, ir::FunctionRegion& fr) {
    std::vector<LiftedItem> items;
    items.reserve(size / 4 + 4);

    const u8* p = code;
    size_t left = size;
    u64 address = begin_rva;
    u64 decoded = 0;

    while (left > 0 && address < end_rva) {
        const cs_insn* ci = session.next(p, left, address);
        if (ci == nullptr) {
            // 无效字节：线性扫描跳过 1 字节继续（保守策略，不失败）。
            diag.report(Severity::Note, pass_name,
                        std::string(func_name) + " @rva 0x" + std::to_string(address) +
                            ": 无法反汇编的字节，跳过 1 字节");
            ++p;
            --left;
            ++address;
            continue;
        }
        ++decoded;
        LiftedItem item;
        item.addr = ci->address;
        item.raw_size = ci->size;

        const TranslateResult tr = translate_insn(*ci, fr.arch);
        if (tr.status == TranslateStatus::Ok) {
            item.insn = tr.insn;
            item.ctl = control_kind(tr.insn.op);
            if ((item.ctl == LiftedItem::Ctl::Jcc || item.ctl == LiftedItem::Ctl::Jmp ||
                 item.ctl == LiftedItem::Ctl::Call) &&
                tr.insn.dst.kind == ir::Operand::Kind::Imm) {
                item.target = static_cast<u64>(tr.insn.dst.imm);
            } else if (item.ctl == LiftedItem::Ctl::Jmp ||
                       item.ctl == LiftedItem::Ctl::Call) {
                item.indirect = true; // jmp/call reg
            }
        } else {
            const char* why = (tr.status == TranslateStatus::Todo) ? "（TODO：v1 暂不支持）" : "";
            diag.report(Severity::Note, pass_name,
                        std::string(func_name) + " @rva 0x" + std::to_string(item.addr) +
                            ": 未支持指令 '" + ci->mnemonic + "' " + why + "，已跳过");
        }
        items.push_back(std::move(item));
    }

    build_blocks(begin_rva, end_rva, items, fr.blocks);
    return decoded;
}

} // namespace wvmp::passes::lifter
