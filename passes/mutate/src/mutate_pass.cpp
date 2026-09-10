#include "wvmp/passes/mutate/mutate_pass.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/protect_levels.hpp"
#include "wvmp/framework/registry.hpp"

#include <cstdlib>
#include <cstring>
#include <unordered_map>
#include <vector>

namespace wvmp::passes {
namespace {

// MIT-459 (mutate-v1)：IR 级确定性变异。安全-by-构造的两族：
//   (a) Nop 填充 —— 零寄存器/零 flags 面；
//   (b) 死寄存器垃圾 Mov（dst = 插入点到块尾之间"先写后读"判定为死的
//       GP 寄存器，src = 立即数）—— 值在下次读之前必被真实定义覆盖。
// 红线：不碰 CFG（不插块/不改跳转目标/不改块边界）；只插非 flags 写操作
// （Mov/Nop 均不写 flags）；rsp/Rip/Flags 哨兵永不作垃圾目的；x86 不用
// R8+（32 位不可编码）。垃圾 Mov 不携带 mem 操作数，栈深 walk 的 reach 面
// 零新增；walk 别名跟踪对"未知值"走保守披露方向，垃圾定义只会使别名信息
// 更保守、不会更激进。
// 确定性：独立 Rng（ctx.seed ^ 盐，不消费 ctx.rng —— 下游虚拟化/stub 的
// 随机序列零扰动，无 mutate 管道回归基线零回踩）；按 functions 序逐函数
// 逐块逐边界消费，同 seed 逐字节可复现。
// 密度：v1 代码常量 P(nop)=0.10、P(junk mov)=0.15；MIT-468 起 [mutate]
// density 可覆写 nop 密度（ProtectRules.has_mutate_density 在场时）。

constexpr u64 kMutateSeedSalt = 0x4D55544154452121ull;  // "MUTATE!!" LE
constexpr double kNopProbability = 0.10;
constexpr double kJunkMovProbability = 0.15;
// ⚠️ MIT-459 收口裁定（默认关闭，挂账 GAPS）：junk-Mov 的块内 liveness 在
// wvmpTest 全栈 E2E 仍未绿（callgate 参数寄存器 rcx/rdx/r8/r9/rax 隐式读
// 已修，仍有未定位的槽消费面——同地址原生代码执行发散实录见 GAPS
// mutate 节）。按"宁 gate 勿错"纪律 v1 只发 Nop 注入（E2E byte-exact 已证）；
// junk-Mov 挂账史（MIT-459 关闭 → 478 二次翻案失败 → 481 混杂揭示）与
// 终局裁定见 GAPS；此处只留最新结论：
// ⚠️ MIT-482 (T6.4 定案，2026-09-07)：junk-Mov **维持关闭，但缺陷已定位修
// 复**。MIT-478/479/481 时代全部 junk 崩溃的首恶 = insn_transfer 纯定义杀
// /use 标记次序缺陷——目的与自身 mem 基址/变址重叠的纯写指令（实录
// `movzx ecx, byte ptr [rdx + rcx]`，md5 区域 host 0xDF21）会把同指令正要
// 读的槽误杀成"边界死"，junk 注入紧邻读者指令之前 → VM 词流 Load 读 junk
// 槽作变址 → 野指针 segfault（junk imm 0x496E4B90 全链实证）。修复 = kill
// 先于 use（live_in = (live_out\def) ∪ use）；回归专测
// MutateLiveness.PureDefKillMustNotEraseMemOperandUse 钉死次序。修复后
// seed 12345 全量 165 junk Mov / 54 块 → wvmpTest 103/103 绿。
// **重启用阻塞已解除（MIT-484，T6.6）**：T6.5 根因 = asmgen build_callgate
// 双缺陷（step 1 快照 rax scratch 覆写 flags_/pc_ + epilogue 恢复冲掉
// 返回值），修复后 seeds 0..41 基线全扫 ALL GREEN + wvmpTest 双跑 +
// multiseed 335/335。T6.6 全 seed junk 双跑扫描转绿后生产重启用
//（kEnableJunkMov = true）。⚠️ 翻动本开关经 else-if 短路改变 mutate
// 局部 rng 抽取序——同 seed 产物相对关闭态构建必然不同（单方向差异，
// 属启用的固有后果）；下游 ctx.rng 流不受扰（Rng 独立 salt，MIT-485
// 验收核实）。
constexpr bool kEnableJunkMov = true;

// 垃圾目的的候选 GP 集（按 arch；rsp 排除——栈写语义由栈深 walk 专管，
// 任何额外 rsp 写都改变 walk 建模）。
std::vector<ir::Reg> gp_candidates(ir::Arch arch) {
    std::vector<ir::Reg> regs;
    for (int r = 0; r <= static_cast<int>(ir::Reg::Rdi); ++r)
        if (static_cast<ir::Reg>(r) != ir::Reg::Rsp)
            regs.push_back(static_cast<ir::Reg>(r));
    if (arch == ir::Arch::X64)
        for (int r = static_cast<int>(ir::Reg::R8); r <= static_cast<int>(ir::Reg::R15); ++r)
            regs.push_back(static_cast<ir::Reg>(r));
    return regs;
}

// MIT-482 (T6.4)：单注入点诊断行（聚合进 site_log，pass 末尾一次性披露）。
std::string site_note(const ir::FunctionRegion& fn, size_t bidx, size_t iidx,
                      u64 host, int slot, bool is_mov, u32 imm) {
    char buf[160];
    if (is_mov)
        std::snprintf(buf, sizeof(buf), "Mov v%d,0x%X", slot, imm);
    else
        std::snprintf(buf, sizeof(buf), "Nop");
    char out[224];
    std::snprintf(out, sizeof(out), "%s(fn=%s b%zu/i%zu @0x%llX) ",
                  buf, fn.name.c_str(), bidx, iidx,
                  static_cast<unsigned long long>(host));
    return out;
}

bool is_pure_def(const ir::Insn& in) {
    // 纯定义（目的为写、非读改写）集合：块内 liveness 专用。
    // 其余一切 op 一律按"目的也被读"保守处理（RMW / 条件定义 / flags 面）。
    switch (in.op) {
    case ir::Op::Mov:
    case ir::Op::Movzx:
    case ir::Op::Movsxd:
    case ir::Op::Lea:
    case ir::Op::Load:
    case ir::Op::Setcc:
        return true;
    default:
        return false;
    }
}

// 块内向后 liveness：dead[i] = 在"第 i 条指令之前"可安全插入垃圾定义的
// GP 寄存器集合（该定义会被块内后继真实定义覆盖、且不被中途读取）。
// 块尾保守置全活（后继块/区域出口的寄存器可见性不做跨块分析）。
// ⚠️ Call 隐式读（MIT-459 首通实录修正）：callgate 把客户 rcx/rdx/r8/r9
// 槽作为 Win64 原生参数传给被调方（rax 低 8 位 = 变参个数浮标）——这些
// 寄存器即使块内"再无读取"也必须视为 Call 处的活值，否则垃圾写入经
// callgate 漏进原生 callee（wvmpTest kern.md5 首通实录：junk rcx → 原生
// callee 拿野指针 → 崩溃）。x86 cdecl 参数走客户栈，无此面。
// 单条指令的反向转移：按读集点亮 live（含 MIT-478 隐式读补录），pure-def
// 目的随后熄灭（读写并存的非 pure-def 目的保持活）。
static void insn_transfer(const ir::Insn& in, std::vector<char>& live, ir::Arch arch) {
    const auto read_reg = [&](const ir::Operand& o) {
        if (o.kind == ir::Operand::Kind::Reg && o.reg != ir::Reg::Rip &&
            o.reg != ir::Reg::Flags)
            live[static_cast<size_t>(o.reg)] = 1;
    };
    // Call 隐式读（MIT-459 首通实录）：callgate 把客户 rcx/rdx/r8/r9 槽作
    // 为 Win64 原生参数传被调方，rax 低 8 位 = 变参浮标（x86 cdecl 走客户
    // 栈，无此面）。
    if (in.op == ir::Op::Call && arch == ir::Arch::X64) {
        for (ir::Reg r : {ir::Reg::Rcx, ir::Reg::Rdx, ir::Reg::R8, ir::Reg::R9,
                          ir::Reg::Rax})
            live[static_cast<size_t>(r)] = 1;
    }
    // MIT-478 (T6) 隐式读审计补录（IR 操作数未声明的槽消费面）：
    //   Ret        → Rax（区域返回值经 stub 写回原生 rax）；
    //   Div/Idiv   → Rax（dividend 低半槽，handler 从 Rax/Rdx 拼装，IR 仅
    //                dst=Rdx tag 声明高半——MIT-404 协议）；
    //   Mul        → Rax（隐式乘数 + 积低半写 Rax，dst=Rdx tag 同款）；
    //   Cmpxchg    → Rax（累加器比较，MIT-341 注明 "read Rax 槽"）；
    //   Cdq        → Rax（符号扩展源，零显式操作数——MIT-404；cdqe 归一
    //                为 dst=src=Rax 声明形，已覆盖）。
    // Div/Idiv/Mul 的 Rdx 侧由 dst-tag 非 pure-def 读路径天然覆盖。
    if (in.op == ir::Op::Ret || in.op == ir::Op::Div || in.op == ir::Op::Idiv ||
        in.op == ir::Op::Mul || in.op == ir::Op::Cmpxchg || in.op == ir::Op::Cdq) {
        live[static_cast<size_t>(ir::Reg::Rax)] = 1;
    }
    // MIT-482 (T6.4) 纯定义杀必须先于 use 标记：活性语义 =
    // live_in(i) = (live_out(i) \ def(i)) ∪ use(i)。若先 use 后 kill，则
    // 目的与自身 mem 基址/变址重叠的纯写指令（实录：md5 区域
    // `movzx ecx, byte ptr [rdx + rcx]`，rcx 既是 dst 又是变址——kern.md5
    // 野指针崩溃）会把同指令正要读的槽误杀成"边界死"，junk 注入到紧邻
    // 读者指令之前即产野地址。
    if (is_pure_def(in) && in.dst.kind == ir::Operand::Kind::Reg)
        live[static_cast<size_t>(in.dst.reg)] = 0;
    if (!is_pure_def(in)) read_reg(in.dst);
    read_reg(in.src);
    if (in.src2.kind == ir::Operand::Kind::Reg) read_reg(in.src2);
    const auto read_mem = [&](const ir::Operand& o) {
        if (o.kind != ir::Operand::Kind::Mem) return;
        if (o.mem.base != ir::Reg::Flags && o.mem.base != ir::Reg::Rip)
            live[static_cast<size_t>(o.mem.base)] = 1;
        if (o.mem.index != ir::Reg::Flags) live[static_cast<size_t>(o.mem.index)] = 1;
    };
    read_mem(in.dst);
    read_mem(in.src);
    // MIT-482：src2 的 Mem 形补录（此前只覆盖 Reg 形——完整性对账）。
    read_mem(in.src2);
}

std::vector<std::vector<ir::Reg>> dead_at_boundaries(const ir::BasicBlock& block,
                                                     const std::vector<ir::Reg>& candidates,
                                                     ir::Arch arch,
                                                     const std::vector<char>& live_out) {
    const size_t n = block.insns.size();
    std::vector<std::vector<ir::Reg>> dead(n + 1);
    // MIT-478 (T6)：块内活跃度从 live_out(B)（后继块 live_in 并集，区域级
    // CFG 反向不动点，见 run() 内构建）起步反向传播——替换旧"块尾保守全
    // 活"假设；跨块可见性洞（块内死 + 后继未重定义先读）由此闭合。
    std::vector<char> live(static_cast<size_t>(ir::Reg::Count), 0);
    for (size_t r = 0; r < live.size(); ++r)
        live[r] = r < live_out.size() ? live_out[r] : 0;

    for (size_t i = n; i-- > 0;) {
        const ir::Insn& in = block.insns[i];
        insn_transfer(in, live, arch);
        // 记录本边界（第 i 条之前）的死集；边界 n（块尾）由 live_out 覆盖。
        if (i < n)
            for (ir::Reg r : candidates)
                if (!live[static_cast<size_t>(r)]) dead[i].push_back(r);
    }
    return dead;
}

} // namespace

std::vector<std::vector<ir::Reg>> dead_at_boundaries_for_test(
    const ir::BasicBlock& block, const std::vector<ir::Reg>& candidates,
    ir::Arch arch, const std::vector<char>& live_out) {
    return dead_at_boundaries(block, candidates, arch, live_out);
}

void MutatePass::run(ProtectionContext& ctx) {
    // MIT-457 档位对齐：level=none 的函数不会被 virtualize 消费，跳过变异
    //（变异产物无人消费，省时且日志口径与虚拟化面一致）。
    const ProtectRules* rules = ctx.find_slot<ProtectRules>(kProtectRules);
    // MIT-468：[mutate] density 覆写 nop 概率（has_* 哨兵；缺省 = 0.10）。
    const double nop_probability =
        (rules != nullptr && rules->has_mutate_density)
            ? static_cast<double>(rules->mutate_density) / 100.0
            : kNopProbability;
    // MIT-489 (T21)：[mutate] junk_density 覆写 junk-Mov 概率（缺省 =
    // kJunkMovProbability）。T6.6 生产重启用后，密度跟随配置化披露落地；
    // rng 抽取序不受影响（chance() 消费序不变，仅阈值变）。
    const double junk_probability =
        (rules != nullptr && rules->has_mutate_junk_density)
            ? static_cast<double>(rules->mutate_junk_density) / 100.0
            : kJunkMovProbability;

    Rng rng(ctx.seed ^ kMutateSeedSalt);
    size_t junk_movs = 0, nops = 0, blocks_touched = 0;
    // MIT-482 (T6.4)：逐注入点日志（fn/block/idx/host/槽号）——junk 精确
    // 归因面。槽号 = ir::Reg 枚举值 = VM GP 槽号（VM 级消费面对账主键）。
    std::string site_log;
    bool region_allowed = true;  // MIT-482：诊断白名单（发射级丢弃）。

    for (size_t fn_index = 0; fn_index < ctx.functions.size(); ++fn_index) {
        ir::FunctionRegion& fn = ctx.functions[fn_index];
        if (fn.blocks.empty()) continue;
        // MIT-482 (T6.4 诊断钩子，实验分支专用)：WVMP_MUTATE_ALLOW_FN=<name 子串>
        // 只对 begin_rva 匹配的区域发射注入物。rng 抽取序保持全量语义
        //（发射级丢弃，非函数级 continue——否则 rng 状态耦合破坏二分）。
        {
            char* av = nullptr;
            size_t av_len = 0;
            if (_dupenv_s(&av, &av_len, "WVMP_MUTATE_ALLOW_FN") == 0 && av &&
                av_len > 1) {
                region_allowed =
                    fn.name.find(av) != std::string::npos;  // 子串匹配 marker 名
                if (fn_index == 0)
                    ctx.diag.report(Severity::Note, name(),
                                    std::string("诊断白名单激活: WVMP_MUTATE_ALLOW_FN=") +
                                        av);
                std::free(av);
            } else {
                std::free(av);
                region_allowed = true;
            }
        }
        if (rules != nullptr &&
            rules->level_for(fn.begin_rva, fn_index) == ProtectLevel::None)
            continue;

        const ir::Size junk_size =
            fn.arch == ir::Arch::X64 ? ir::Size::S64 : ir::Size::S32;
        const std::vector<ir::Reg> candidates = gp_candidates(fn.arch);

        // MIT-480 (T6.3)：跳表候选函数整体禁注入。含**寄存器间接跳转**
        // （Op::Jmp/Jcc dst=Reg）的函数会被 translator 跳表特化匹配——
        // mutate 插入改变 IR 序列/地址键后，匹配可半成功（split/翻译面
        // 部分 fail→Halt 折叠 + Call aux 错位，wvmpTest kern.md5 单 Nop
        // 实录），fallback 并非整体 gate → 保守跳过整函数注入。
        bool has_indirect_jump = false;
        bool has_string_op = false;
        for (const auto& b2 : fn.blocks)
            for (const auto& i2 : b2.insns) {
                if ((i2.op == ir::Op::Jmp || i2.op == ir::Op::Jcc) &&
                    i2.dst.kind == ir::Operand::Kind::Reg)
                    has_indirect_jump = true;
                // MIT-494h (T30-d)：串微程序区域 junk-Mov 禁注入判据——
                // rep 串指令经 Op::Mov + src2=imm(family) 编码（MIT-415：
                // rep 形 family 0..4 / plain 形 23..27；真实 mov 的立即数
                // 在 src，src2 恒空零碰撞；lock 载体 family 5..8 不在判据
                // 内——strip-and-execute 单 op 直发无 GetFlags/SetFlags 包
                // 裹，IR 活性与词流一致）。此类区域经微程序展开，IR 级死
                // 寄存器判定与词流发射活性口径不一致（MIT-494g TEMP3 对
                // 账：IR"死"边界的 junk 写仍可命中词流真活值链 → scas 比
                // 较子污染）。junk-Mov 禁用；Nop 面不写寄存器保留。
                if (i2.op == ir::Op::Mov && i2.src2.kind == ir::Operand::Kind::Imm) {
                    const i64 fam = i2.src2.imm;
                    if ((fam >= 0 && fam <= 4) || (fam >= 23 && fam <= 27))
                        has_string_op = true;
                }
            }

        // MIT-478 (T6)：区域级 CFG 反向活跃度不动点。live_out(B) = 后继
        // live_in 并集；间接跳转/不可解析目标 = 全活（保守）；区域出口
        // （Ret / 末块 fallthrough）= Rax 活（返回值经 stub 写回原生）。
        const size_t nb = fn.blocks.size();
        std::unordered_map<u64, size_t> bidx;
        for (size_t bi = 0; bi < nb; ++bi) bidx.emplace(fn.blocks[bi].addr, bi);
        std::vector<std::vector<size_t>> succs(nb);
        std::vector<char> unknown(nb, 0);
        std::vector<char> exit_fn(nb, 0);  // 区域出口 fallthrough（Rax 可见）
        for (size_t bi = 0; bi < nb; ++bi) {
            const auto& ins = fn.blocks[bi].insns;
            if (ins.empty()) continue;
            const ir::Insn& last = ins.back();
            auto add_target = [&](u64 t) {
                auto it = bidx.find(t);
                if (it != bidx.end()) succs[bi].push_back(it->second);
                else unknown[bi] = 1;
            };
            if (last.op == ir::Op::Jmp || last.op == ir::Op::Jcc) {
                if (last.dst.kind == ir::Operand::Kind::Imm)
                    add_target(static_cast<u64>(last.dst.imm));
                else
                    unknown[bi] = 1;
                if (last.op == ir::Op::Jcc) {
                    if (bi + 1 < nb) succs[bi].push_back(bi + 1);
                    else exit_fn[bi] = 1;
                }
            } else if (last.op == ir::Op::Ret) {
                // 区域出口（Ret 自身在 insn_transfer 强制 Rax 活）。
            } else {
                if (bi + 1 < nb) succs[bi].push_back(bi + 1);
                else exit_fn[bi] = 1;
            }
        }
        std::vector<std::vector<char>> live_in(nb, std::vector<char>(static_cast<size_t>(ir::Reg::Count), 0));
        std::vector<std::vector<char>> live_out_v(nb, std::vector<char>(static_cast<size_t>(ir::Reg::Count), 0));
        for (bool changed = true; changed;) {
            changed = false;
            for (size_t bi = nb; bi-- > 0;) {
                std::vector<char> out(static_cast<size_t>(ir::Reg::Count), 0);
                for (size_t s2 : succs[bi])
                    for (size_t r = 0; r < out.size(); ++r) out[r] |= live_in[s2][r];
                if (unknown[bi]) std::fill(out.begin(), out.end(), static_cast<char>(1));
                if (exit_fn[bi]) out[static_cast<size_t>(ir::Reg::Rax)] = 1;
                std::vector<char> in = out;
                const auto& ins2 = fn.blocks[bi].insns;
                for (size_t i = ins2.size(); i-- > 0;) insn_transfer(ins2[i], in, fn.arch);
                if (in != live_in[bi] || out != live_out_v[bi]) {
                    live_in[bi] = in;
                    live_out_v[bi] = out;
                    changed = true;
                }
            }
        }

        if (has_indirect_jump) {
            ctx.diag.report(Severity::Note, name(),
                            "函数 " + fn.name + " 含寄存器间接跳转（跳表候选），"
                            "跳过注入（MIT-480 跳表匹配保守门控）");
            continue;
        }
        if (has_string_op) {
            ctx.diag.report(Severity::Note, name(),
                            "函数 " + fn.name + " 含串微程序（rep 串载体），"
                            "junk-Mov 跳过（MIT-494h 活性口径不一致防线；Nop 面保留）");
        }

        for (size_t blk_i = 0; blk_i < fn.blocks.size(); ++blk_i) {
            ir::BasicBlock& block = fn.blocks[blk_i];
            if (block.insns.empty()) continue;
            const auto dead = dead_at_boundaries(block, candidates, fn.arch,
                                                 live_out_v[&block - fn.blocks.data()]);
            std::vector<ir::Insn> mutated;
            mutated.reserve(block.insns.size() + 8);
            bool inserted = false;
            for (size_t i = 0; i <= block.insns.size(); ++i) {
                // 边界 i = 第 i 条指令之前。块尾（i == n）不插：dead[n] 恒空
                //（块尾保守全活），天然短路。
                if (!dead[i].empty()) {
                    // MIT-480 (T6.3)：插入物 addr 纪律 = 共享**前一条**真实
                    // insn 的地址（语义 = 插入在 P 之后）。旧实现共享后一条
                    // insn 的地址 → 同址对 (NOP, I) 中 NOP 以 I.addr 为键先
                    // 写 next_ip_of[I.addr] = I.addr（自指）——在 I 的
                    // rip-relative 寻址/地址键消费面读到此自指值的窗口即断
                    //（wvmpTest kern.b64 单 Nop 复现）。share-prev 下同址对
                    // (P, NOP) 两写同值（P 的语义后继 = NOP 的后继 = I），
                    // 且与 MIT-426 同址先例同向。
                    const u64 host =
                        block.insns[i == 0 ? 0 : i - 1].addr;
                    if (rng.chance(nop_probability)) {
                        ++nops;  // rng 语义计数（发射受白名单门控）
                        if (region_allowed) {
                            ir::Insn nop;
                            nop.op = ir::Op::Nop;
                            nop.size = junk_size;
                            nop.addr = host;
                            mutated.push_back(nop);
                            inserted = true;
                            site_log += site_note(fn, blk_i, i, host, -1, false, 0);
                        }
                    } else if (kEnableJunkMov && !has_string_op &&
                               !dead[i].empty() &&
                               rng.chance(junk_probability)) {
                        // MIT-478 (T6)：dead[i] 已由区域级 CFG 反向活跃度背书
                        //（live_out(B) 折入后继可见性 + 隐式读补录），直接注入。
                        const size_t pick =
                            static_cast<size_t>(rng.uniform(0, dead[i].size() - 1));
                        const u32 junk_imm = static_cast<u32>(rng.next());
                        // 注意：junk_movs 在 region_allowed 判定之前自增
                        //（与 Nop 侧 "rng 语义计数" 注释同口径）——注入统计 note 的 Mov
                        // 计数是"rng 语义计数"，白名单丢弃也计入，与产物
                        // 字节对账时需知悉（MIT-485 验收建议 2）。
                        ++junk_movs;
                        if (region_allowed) {
                            ir::Insn junk;
                            junk.op = ir::Op::Mov;
                            junk.size = junk_size;
                            junk.dst = ir::Operand::reg_(dead[i][pick]);
                            junk.src = ir::Operand::imm_(static_cast<i64>(junk_imm));
                            junk.addr = host;
                            mutated.push_back(junk);
                            inserted = true;
                            site_log += site_note(fn, blk_i, i, host,
                                                  static_cast<int>(dead[i][pick]), true,
                                                  junk_imm);
                        }
                    }
                }
                if (i < block.insns.size()) mutated.push_back(block.insns[i]);
            }
            if (inserted) {
                block.insns = std::move(mutated);
                ++blocks_touched;
            }
        }
    }

    if (junk_movs + nops > 0) {
        ctx.diag.report(Severity::Note, name(),
                        "已注入 " + std::to_string(junk_movs + nops) + " 个垃圾指令（Mov " +
                            std::to_string(junk_movs) + " / Nop " + std::to_string(nops) +
                            "，" + std::to_string(blocks_touched) + " 个基本块，seed 派生确定性）");
        // MIT-482：逐注入点披露（单行聚合，诊断面；不影响产物字节）。
        ctx.diag.report(Severity::Note, name(), "注入点清单: " + site_log);
    } else
        ctx.diag.report(Severity::Note, name(), "本次未注入垃圾指令（密度抽样为空）");
}

WVMP_REGISTER_PASS(MutatePass)

} // namespace wvmp::passes
