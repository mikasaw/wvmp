#include "wvmp/passes/mutate/mutate_pass.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/protect_levels.hpp"
#include "wvmp/framework/registry.hpp"

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
// junk-Mov 需系统性审计槽隐式消费面（callgate/ExitNative/xmm 同步/参数窗）
// 后另行翻案。
constexpr bool kEnableJunkMov = false;

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
std::vector<std::vector<ir::Reg>> dead_at_boundaries(const ir::BasicBlock& block,
                                                     const std::vector<ir::Reg>& candidates,
                                                     ir::Arch arch) {
    const size_t n = block.insns.size();
    std::vector<std::vector<ir::Reg>> dead(n + 1);
    std::vector<char> live(static_cast<size_t>(ir::Reg::Count), 1);

    for (size_t i = n; i-- > 0;) {
        const ir::Insn& in = block.insns[i];
        // 读集：Reg 源 + mem 基址/变址 + （非纯定义的）目的 + Call 隐式读。
        const auto read_reg = [&](const ir::Operand& o) {
            if (o.kind == ir::Operand::Kind::Reg && o.reg != ir::Reg::Rip &&
                o.reg != ir::Reg::Flags)
                live[static_cast<size_t>(o.reg)] = 1;
        };
        if (in.op == ir::Op::Call && arch == ir::Arch::X64) {
            for (ir::Reg r : {ir::Reg::Rcx, ir::Reg::Rdx, ir::Reg::R8, ir::Reg::R9,
                              ir::Reg::Rax})
                live[static_cast<size_t>(r)] = 1;
        }
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
        // 纯定义杀：目的在更早边界（含本插入点）不再活。
        if (is_pure_def(in) && in.dst.kind == ir::Operand::Kind::Reg)
            live[static_cast<size_t>(in.dst.reg)] = 0;
        // 记录本边界（第 i 条之前）的死集；边界 n（块尾）恒空，不记录。
        if (i < n)
            for (ir::Reg r : candidates)
                if (!live[static_cast<size_t>(r)]) dead[i].push_back(r);
    }
    return dead;
}

} // namespace

void MutatePass::run(ProtectionContext& ctx) {
    // MIT-457 档位对齐：level=none 的函数不会被 virtualize 消费，跳过变异
    //（变异产物无人消费，省时且日志口径与虚拟化面一致）。
    const ProtectRules* rules = ctx.find_slot<ProtectRules>(kProtectRules);
    // MIT-468：[mutate] density 覆写 nop 概率（has_* 哨兵；缺省 = 0.10）。
    const double nop_probability =
        (rules != nullptr && rules->has_mutate_density)
            ? static_cast<double>(rules->mutate_density) / 100.0
            : kNopProbability;

    Rng rng(ctx.seed ^ kMutateSeedSalt);
    size_t junk_movs = 0, nops = 0, blocks_touched = 0;

    for (size_t fn_index = 0; fn_index < ctx.functions.size(); ++fn_index) {
        ir::FunctionRegion& fn = ctx.functions[fn_index];
        if (fn.blocks.empty()) continue;
        if (rules != nullptr &&
            rules->level_for(fn.begin_rva, fn_index) == ProtectLevel::None)
            continue;

        const ir::Size junk_size =
            fn.arch == ir::Arch::X64 ? ir::Size::S64 : ir::Size::S32;
        const std::vector<ir::Reg> candidates = gp_candidates(fn.arch);

        for (ir::BasicBlock& block : fn.blocks) {
            if (block.insns.empty()) continue;
            const auto dead = dead_at_boundaries(block, candidates, fn.arch);
            std::vector<ir::Insn> mutated;
            mutated.reserve(block.insns.size() + 8);
            bool inserted = false;
            for (size_t i = 0; i <= block.insns.size(); ++i) {
                // 边界 i = 第 i 条指令之前。块尾（i == n）不插：dead[n] 恒空
                //（块尾保守全活），天然短路。
                if (!dead[i].empty()) {
                    const u64 host = block.insns[i == block.insns.size() ? i - 1 : i].addr;
                    if (rng.chance(nop_probability)) {
                        ir::Insn nop;
                        nop.op = ir::Op::Nop;
                        nop.size = junk_size;
                        nop.addr = host;
                        mutated.push_back(nop);
                        ++nops;
                        inserted = true;
                    } else if (kEnableJunkMov && rng.chance(kJunkMovProbability)) {
                        const size_t pick =
                            static_cast<size_t>(rng.uniform(0, dead[i].size() - 1));
                        ir::Insn junk;
                        junk.op = ir::Op::Mov;
                        junk.size = junk_size;
                        junk.dst = ir::Operand::reg_(dead[i][pick]);
                        junk.src =
                            ir::Operand::imm_(static_cast<i64>(static_cast<u32>(rng.next())));
                        junk.addr = host;
                        mutated.push_back(junk);
                        ++junk_movs;
                        inserted = true;
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

    if (junk_movs + nops > 0)
        ctx.diag.report(Severity::Note, name(),
                        "已注入 " + std::to_string(junk_movs + nops) + " 个垃圾指令（Mov " +
                            std::to_string(junk_movs) + " / Nop " + std::to_string(nops) +
                            "，" + std::to_string(blocks_touched) + " 个基本块，seed 派生确定性）");
    else
        ctx.diag.report(Severity::Note, name(), "本次未注入垃圾指令（密度抽样为空）");
}

WVMP_REGISTER_PASS(MutatePass)

} // namespace wvmp::passes
