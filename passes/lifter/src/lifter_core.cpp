#include "lifter_core.hpp"

#include "x86_translate.hpp"

#include <algorithm>
#include <cinttypes>
#include <cstdio>
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

// MIT-407: 越区跳转目标回跳检出（声明处注释见 lifter_core.hpp）。
// 必须在匿名 namespace 之外——lifter_pass.cpp 的 lambda 跨 TU 调用。
bool back_jump_reaches_region(CapstoneSession& session, std::span<const u8> image,
                              const PeSectionMap& pe, u64 target, u64 begin_rva, u64 end_rva) {
    struct Node { u64 addr; u32 layer; };
    std::vector<Node> queue{{target, 0}};
    std::set<u64> visited;
    size_t budget = 256;  // 防御：病态/自修改数据不炸穿
    while (!queue.empty()) {
        const Node n = queue.front();
        queue.erase(queue.begin());
        if (n.layer > 3) continue;
        if (n.addr >= begin_rva && n.addr < end_rva) return true;  // 回跳本区
        if (!visited.insert(n.addr).second) continue;
        if (budget-- == 0) break;
        const auto off = pe.rva_to_offset(n.addr);
        if (!off || *off >= image.size()) continue;
        const u8* p = image.data() + *off;
        size_t left = image.size() - *off;
        u64 addr = n.addr;
        const cs_insn* ci = session.next(p, left, addr);
        if (ci == nullptr) continue;  // 无效字节：死端
        const u64 next = ci->address + ci->size;
        // 分类优先走 translate_insn（与主循环同一判定，保证一致）；未分类
        // 分支（loop/jrcxz 等白名单外形态）回退 capstone 组并按条件分支处理
        // ——跟目标（有立即数时）+ fallthrough 两条边，保守方向（多检出）。
        const TranslateResult tr = translate_insn(*ci, session.arch());
        bool is_jmp = false, is_jcc = false, is_ret = false;
        bool direct_imm = false;
        u64 imm_target = 0;
        if (tr.status == TranslateStatus::Ok) {
            switch (tr.insn.op) {
            case ir::Op::Jmp: is_jmp = true; break;
            case ir::Op::Jcc: is_jcc = true; break;
            case ir::Op::Ret: is_ret = true; break;
            default: break;
            }
            if ((is_jmp || is_jcc) && tr.insn.dst.kind == ir::Operand::Kind::Imm) {
                direct_imm = true;
                imm_target = static_cast<u64>(tr.insn.dst.imm);
            }
        } else if (ci->detail != nullptr) {
            const cs_detail* det = ci->detail;
            bool grp_ret = false, grp_jump = false;
            for (size_t g = 0; g < det->groups_count; ++g) {
                if (det->groups[g] == X86_GRP_RET) grp_ret = true;
                if (det->groups[g] == X86_GRP_JUMP) grp_jump = true;
            }
            if (grp_ret) {
                is_ret = true;
            } else if (grp_jump) {
                if (det->x86.op_count > 0 && det->x86.operands[0].type == X86_OP_IMM) {
                    direct_imm = true;
                    imm_target = static_cast<u64>(det->x86.operands[0].imm);
                }
                is_jcc = true;
            }
        }
        if (is_ret) continue;  // 无后继
        if (is_jmp) {
            if (direct_imm) queue.push_back({imm_target, n.layer + 1});
            continue;  // 无条件 jmp 无 fallthrough
        }
        if (is_jcc) {
            if (direct_imm) queue.push_back({imm_target, n.layer + 1});
            queue.push_back({next, n.layer + 1});  // fallthrough
            continue;
        }
        // 普通指令 / call / 未分类：顺序续行。call 目标不跟——triage 走子
        // 为 jcc/jmp 边；跟 call 会把递归函数体（如 ackermann 自调）卷进
        // 来造成假阳性，且"回跳进区域"的危险面由 jcc/jmp 边覆盖（call 目标
        // 入区是另一类形态，不在本单 ExitNative 通道的判定面内）。
        queue.push_back({next, n.layer});
    }
    return false;
}

// MIT-497 (T50): 出口 esp-resync 前瞻（声明处注释见 lifter_core.hpp）。
// 必须在匿名 namespace 之外——lifter_pass.cpp 直接调用（MIT-407 同款）。
bool exit_resync_verified(CapstoneSession& session, std::span<const u8> image,
                          const PeSectionMap& pe, u64 target_rva) {
    const auto off = pe.rva_to_offset(target_rva);
    if (!off || *off >= image.size()) return false;
    const u8* p = image.data() + *off;
    size_t left = image.size() - *off;
    u64 addr = target_rva;
    // 线性扫窗；256 条为防御上限（现实形态 ≤32 条：mul64hi 实测）。
    // session.next 按引用自推进 p/left/addr（capstone_session.hpp 契约）。
    for (int budget = 0; budget < 256; ++budget) {
        const cs_insn* ci = session.next(p, left, addr);
        if (ci == nullptr) return false;  // 解码失败：不可证 → 保守拒
        static const cs_x86 kNoDetail{};
        const cs_x86& x = ci->detail != nullptr ? ci->detail->x86 : kNoDetail;
        const auto touches_sp = [&x]() {
            for (unsigned i = 0; i < x.op_count; ++i) {
                const cs_x86_op& op = x.operands[i];
                if (op.type == X86_OP_REG &&
                    (op.reg == X86_REG_ESP || op.reg == X86_REG_RSP ||
                     op.reg == X86_REG_SPL))
                    return true;
                if (op.type == X86_OP_MEM &&
                    (op.mem.base == X86_REG_ESP || op.mem.base == X86_REG_RSP ||
                     op.mem.index == X86_REG_ESP || op.mem.index == X86_REG_RSP))
                    return true;
            }
            return false;
        };
        // 终止符：绝对恢复（mov esp/rsp, ebp/rbp 或 leave）→ 窗口安全关闭。
        if (ci->id == X86_INS_MOV && x.op_count == 2 &&
            x.operands[0].type == X86_OP_REG &&
            (x.operands[0].reg == X86_REG_ESP || x.operands[0].reg == X86_REG_RSP) &&
            x.operands[1].type == X86_OP_REG &&
            (x.operands[1].reg == X86_REG_EBP || x.operands[1].reg == X86_REG_RBP))
            return true;
        if (ci->id == X86_INS_LEAVE) return true;
        // T50 验收 S-1/N-1 补拒：push/pop 族隐式 esp 不进 capstone 操作数
        // （实证 push eax operands 仅 [eax]、pushfd operands 空），上方
        // touches_sp 探不到——按 id 显式封禁；far call（LCALL，id≠CALL 不
        // 走下方 IMM 判据）/iret 族/中断系统调用入口一并保守拒。
        switch (ci->id) {
        case X86_INS_PUSH: case X86_INS_POP:
        case X86_INS_PUSHAL: case X86_INS_POPAL:
        case X86_INS_PUSHF: case X86_INS_PUSHFD: case X86_INS_PUSHFQ:
        case X86_INS_POPF: case X86_INS_POPFD: case X86_INS_POPFQ:
        case X86_INS_LCALL: case X86_INS_INT: case X86_INS_INT1:
        case X86_INS_INT3: case X86_INS_INTO:
        case X86_INS_IRET: case X86_INS_IRETD: case X86_INS_IRETQ:
        case X86_INS_SYSCALL: case X86_INS_SYSENTER:
            return false;
        default: break;
        }
        // 其余任何 esp/rsp 触碰（加移/xchg/[esp±k] 访存）→ 拒。
        if (touches_sp()) return false;
        // 控制流：任何 jmp/jcc/ret/间接 call 都可能离开窗口或无 resync → 拒；
        // 仅 E8 直呼（ABI 自配平）允许顺序续行。loop/jrcxz 族条件分支显式
        // 拒（capstone 分组不保证归 X86_GRP_JUMP）。
        if (ci->id == X86_INS_JMP || ci->id == X86_INS_RET ||
            ci->id == X86_INS_LOOP || ci->id == X86_INS_LOOPE ||
            ci->id == X86_INS_LOOPNE || ci->id == X86_INS_JRCXZ ||
            ci->id == X86_INS_JECXZ)
            return false;
        {
            const cs_detail* det = ci->detail;
            if (det != nullptr) {
                for (size_t g = 0; g < det->groups_count; ++g) {
                    if (det->groups[g] == X86_GRP_JUMP || det->groups[g] == X86_GRP_RET)
                        return false;
                }
            }
        }
        if (ci->id == X86_INS_CALL) {
            if (x.op_count != 1 || x.operands[0].type != X86_OP_IMM) return false;
        }
    }
    return false;  // 预算耗尽无终止符 → 不可证 → 拒
}

// MIT-500 (T54): callee 清理约定扫描（声明处注释见 lifter_core.hpp）。
// 必须在匿名 namespace 之外——lifter_pass.cpp 直接调用（MIT-407 同款）。
std::optional<u32> callee_ret_imm(CapstoneSession& session, std::span<const u8> image,
                                  const PeSectionMap& pe, u64 target) {
    std::vector<u64> queue{target};
    std::set<u64> visited;
    std::optional<u32> found;
    size_t budget = 256;
    while (!queue.empty()) {
        const u64 addr = queue.front();
        queue.erase(queue.begin());
        if (!visited.insert(addr).second) continue;
        if (budget-- == 0) return std::nullopt;
        const auto off = pe.rva_to_offset(addr);
        if (!off || *off >= image.size()) return std::nullopt;
        const u8* p = image.data() + *off;
        size_t left = image.size() - *off;
        u64 cur = addr;
        const cs_insn* ci = session.next(p, left, cur);
        if (ci == nullptr) return std::nullopt;  // 解码失败：不可判 → 放弃
        const cs_detail* det = ci->detail;
        // 终态：ret [imm16]——收集 imm，冲突即放弃。
        if (ci->id == X86_INS_RET) {
            u32 imm = 0;
            if (det != nullptr && det->x86.op_count == 1 &&
                det->x86.operands[0].type == X86_OP_IMM)
                imm = static_cast<u32>(det->x86.operands[0].imm);
            else if (det != nullptr && det->x86.op_count != 0)
                return std::nullopt;
            if (found.has_value() && *found != imm) return std::nullopt;
            found = imm;
            continue;  // 无后继
        }
        // call（含 far）/间接转移面：callee 体量与副作用不可界 → 放弃。
        if (ci->id == X86_INS_CALL || ci->id == X86_INS_LCALL)
            return std::nullopt;
        // T54 验收 S-1/S-2：id 级封禁移出 is_jump 门之外——capstone 实证
        // loop 族分组仅 [BRANCH_RELATIVE]（无 JUMP 组，id 拒在组门内 = 死
        // 代码且丢 taken 边）；retf/iretd 族 id≠RET、分组 [RET]/[IRET] 均
        // 不命中 → 会穿过远/中断返回终结符继续解码（假一致 imm 通道）。
        // 对齐 exit_resync_verified 先例：id 级显式封禁优先于分组分类。
        switch (ci->id) {
        case X86_INS_LOOP: case X86_INS_LOOPE: case X86_INS_LOOPNE:
        case X86_INS_JRCXZ: case X86_INS_JECXZ:
        case X86_INS_RETF: case X86_INS_IRET: case X86_INS_IRETD:
        case X86_INS_IRETQ:
        case X86_INS_INT: case X86_INS_INT1: case X86_INS_INT3:
        case X86_INS_INTO:
        case X86_INS_SYSCALL: case X86_INS_SYSENTER:
            return std::nullopt;
        default: break;
        }
        if (det != nullptr) {
            bool is_jump = false, direct_imm = false;
            u64 imm_target = 0;
            for (size_t g = 0; g < det->groups_count; ++g)
                if (det->groups[g] == X86_GRP_JUMP) is_jump = true;
            if (is_jump) {
                if (det->x86.op_count > 0 &&
                    det->x86.operands[0].type == X86_OP_IMM) {
                    direct_imm = true;
                    imm_target = static_cast<u64>(det->x86.operands[0].imm);
                } else {
                    return std::nullopt;  // 间接 jmp → 放弃
                }
                const u64 next = ci->address + ci->size;
                // 无条件 jmp（X86_INS_JMP）单后继；jcc 双后继（保守双跟；
                // loop/jrcxz 族已由上方 id 封禁拦截）。
                if (ci->id == X86_INS_JMP) {
                    queue.push_back(imm_target);
                    continue;
                }
                if (ci->id == X86_INS_LOOP || ci->id == X86_INS_LOOPE ||
                    ci->id == X86_INS_LOOPNE || ci->id == X86_INS_JRCXZ ||
                    ci->id == X86_INS_JECXZ)
                    return std::nullopt;
                queue.push_back(imm_target);
                queue.push_back(next);
                continue;
            }
        }
        // 普通指令：顺序续行。
        queue.push_back(ci->address + ci->size);
    }
    return found;  // 遍历完（可能 0 终态 = 纯循环无出口 → nullopt）
}

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
            // MIT-409: 死代码不再一律丢弃——MSVC 跳转表 case body 只经表可达,
            // 线性扫描已 lift 但被死代码规则丢弃; 翻译器跳转表特化 (预扫描 +
            // 目标块切分) 需要这些指令存在。不可 lift 的字节 (int3 填充等)
            // 根本不会成为 item (translate_insn 失败走 skipped_ranges 通道),
            // 此处只放行成功 lift 的指令, 天然免疫填充垃圾。新起一块; 后续
            // 指令并入, 直至下个 leader。死块前块以无条件 jmp/ret 终结,
            // VM 永不落入, 仅跳转表链可达——语义不变, 仅字节码多死块。
            ir::BasicBlock bb;
            bb.addr = it.addr;
            out.push_back(std::move(bb));
            block_index[it.addr] = out.size() - 1;
            current = out.size() - 1;
            placement.push_back(nullptr);
        }
        if (it.insn) {
            // MIT-426 (G6a): 前置 IR 先于主指令入块（pre_insns 与 insn 共享
            // 同一机器地址，顺序执行语义 = 折叠出的 Mov 前置 + 2-op 载体）。
            for (const ir::Insn& pre : it.pre_insns) out[current].insns.push_back(pre);
            out[current].insns.push_back(*it.insn);
        }
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
                         Diagnostics& diag, ir::FunctionRegion& fr, LiftMetadata& meta_out,
                         const ExitNativeGuardFn& exit_guard) {
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
            // MIT-249 follow-up (issue-09): 无效字节同样不入 IR, 视为跳过
            // 范围一并记录到 meta_out.skipped_ranges, 让 C1 gate 可见。
            meta_out.skipped_ranges.emplace_back(address, u64(1));
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
            // MIT-426 (G6a): VEX 三地址折叠前置 IR（dst 独立形态）透传。
            item.pre_insns = tr.extra;
            item.ctl = control_kind(tr.insn.op);
            if ((item.ctl == LiftedItem::Ctl::Jcc || item.ctl == LiftedItem::Ctl::Jmp ||
                 item.ctl == LiftedItem::Ctl::Call) &&
                tr.insn.dst.kind == ir::Operand::Kind::Imm) {
                item.target = static_cast<u64>(tr.insn.dst.imm);
            } else if (item.ctl == LiftedItem::Ctl::Jmp ||
                       item.ctl == LiftedItem::Ctl::Call) {
                item.indirect = true; // jmp/call reg
            }
            // MIT-407: 越区跳转目标回跳检出——直接 jcc/jmp 目标 ≥ end_rva 且
            // 可达集回跳本区时置 exit_native_blocked（下游 translator 上界
            // 查询返回 nullopt → C1 gate）。仅首个检出点跑走子（置位后
            // 后续目标无需再查），间接目标静态不可解不查。
            if (!meta_out.exit_native_blocked && exit_guard &&
                (item.ctl == LiftedItem::Ctl::Jcc || item.ctl == LiftedItem::Ctl::Jmp) &&
                !item.indirect && item.target >= end_rva && exit_guard(item.target)) {
                meta_out.exit_native_blocked = true;
                char rva_buf[32];
                std::snprintf(rva_buf, sizeof(rva_buf), "0x%" PRIX64, item.target);
                diag.report(Severity::Note, pass_name,
                            std::string(func_name) + " @rva " + rva_buf +
                                ": 越区跳转目标可达集回跳本区，ExitNative 禁用（保守 gate）");
            }
        } else {
            const char* why = (tr.status == TranslateStatus::Todo) ? "（TODO：v1 暂不支持）" : "";
            char rva_buf[32];
            std::snprintf(rva_buf, sizeof(rva_buf), "0x%" PRIX64, item.addr);
            diag.report(Severity::Note, pass_name,
                        std::string(func_name) + " @rva " + rva_buf +
                            ": 未支持指令 '" + ci->mnemonic + "' " + why + "，已跳过");
            // MIT-249 follow-up (issue-09): 累积跳过的字节范围, 供下游
            // C1 gate 识别 IR 缺字节。translator 看到该函数有 skipped_range
            // 即放弃虚拟化, 保持原生执行, 避免 stub_link 覆写造成静默错。
            meta_out.skipped_ranges.insert(meta_out.skipped_ranges.end(),
                                           tr.skipped_ranges.begin(),
                                           tr.skipped_ranges.end());
        }
        items.push_back(std::move(item));
    }

    build_blocks(begin_rva, end_rva, items, fr.blocks);
    return decoded;
}

} // namespace wvmp::passes::lifter
