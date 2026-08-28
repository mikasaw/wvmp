// P6：regvm 运行时生成器。
//
// 保护期用 Keystone（KS_ARCH_X86 + KS_MODE_64，Intel 语法）汇编出一段
// **位置无关**的 x64 解释器机器码，可在 RWX 内存中执行 regvm 字节码。
//
// ============================== 机器码布局 ==============================
//
//   [entry][dispatch][handler..（码序随机）][0x90 垫片至 8 对齐][跳转表 64xu64]
//    ^入口    ^取指/跳表   ^各自独立 ks_asm          ^表项=handler 相对码基址偏移
//
//   - 入口在 code 偏移 0：`lea BASE,[rip-7]` 取得码基址（位置无关），
//     保存 Win64 callee-saved（rbx/rbp/rdi/rsi/r12-r15 共 8 个），RCX 的
//     VmContext* 存入随机指派的 CTX 寄存器，初始化后跌入 dispatch 循环；
//   - dispatch：fetch `T8=[BYTE+PC*8]` → `and T0,0x3F` →
//     `T1=[BASE+T0*8+表偏移]` → `add T1,BASE` → `jmp T1`（表偏移为 disp32）；
//   - 每个 handler 末尾 `add PC,1; jmp dispatch`（Jmp/Jcc 直接改写 PC）；
//   - Halt：写回 ctx->pc 与 ctx->ret_value(=regs[v0])，恢复现场 ret。
//
// ============================ 两遍法（跳转表） ===========================
//
//   表项是 handler 相对码基址的偏移，只有全部 handler 汇编完才知道；而表
//   的位置（=码尾）作为 disp32 编码在 dispatch 的访存指令里。故：
//     第 1 遍：dispatch 以哑位移 0x40000000 汇编（强制 disp32 编码）→ 尺寸；
//     逐 handler 以“运行地址 = 入口+dispatch 尺寸+已累计尺寸”独立汇编，
//     各自内部标签互不冲突，天然拿到精确偏移；
//     第 2 遍：dispatch 以真实表偏移重汇编——disp32 定宽，尺寸与第 1 遍
//     一致（生成后断言校验），最后把 64 个 u64 表项原样追加进码尾。
//
// ============================ 寄存器随机化 ==============================
//
//   可分配池 = 16 GPR - rsp（宿主栈）- rcx（保留：shl/shr 的 cl 计数）= 14。
//   每次生成 shuffle 后指派：
//     持久（跨指令存活）：CTX(上下文) PC FLAGS BYTE(字节码基址) BASE(码基址)
//     临时 T0..T9：T8=当前指令字、T2=尺寸/条件、T3..T7/T9=handler 内暂存
//   callee-saved 无论是否被选中一律入口保存/出口恢复，随机分配永不出错。
//   handler 内尺寸分支顺序、Jcc 条件分派顺序、handler 码序亦随机。
//
// ============================== codec 织入点 ============================
//
//   dispatch 的 fetch 之后、跳表之前是流解密钩子的织入位置。v1 为直通
//   （asm_dump 中 “codec: none” 注释行标注）；M3 只需在该处插入对 T8 的
//   解密指令序列（密钥经 VmContext 扩展字段传入），机器码布局不变。
//
// ============================== Size 语义 ===============================
//
//   计算类 handler 按 cond_or_size 的 ir::Size 四路展开：
//   读操作数 = alias_read（零扩展截取），写回 = alias_write——直接用 x86
//   子寄存器写实现别名合并：
//     mov T5,[slot]; mov T5b,T0b; mov [slot],T5   （等价 alias_write）
//   flags 由对应宽度的本机运算产生（CF=无符号进位/OF=有符号溢出/ZF/SF/PF，
//   位布局同 isa::kFlag*），setcc 抽取后装配进 FLAGS 缓存并同步 regs[v17]。
//   Inc/Dec 按 x86 规则保留 CF；Shl/Shr 计数为 0 时整条等价 no-op（不更新
//   flags），计数掩码沿用本机规则（8/16 位 &31，32/64 位 &63）。
// ========================================================================

#include "wvmp/regvm/runtime/runtime.hpp"

#include "wvmp/ir/insn.hpp"
#include "wvmp/regvm/isa/vm_op.hpp"
#include "wvmp/regvm/isa/vm_reg.hpp"

#include <keystone/keystone.h>

#include <array>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace wvmp::regvm::runtime {
namespace {

// ---------------------------------------------------------------------------
// Keystone 会话（RAII）。Intel 语法、x86-64。
// ---------------------------------------------------------------------------
class KsSession {
public:
    KsSession() {
        if (ks_open(KS_ARCH_X86, KS_MODE_64, &ks_) != KS_ERR_OK)
            throw std::runtime_error("regvm runtime: ks_open(KS_ARCH_X86, KS_MODE_64) failed");
        if (ks_option(ks_, KS_OPT_SYNTAX, KS_OPT_SYNTAX_INTEL) != KS_ERR_OK) {
            ks_close(ks_);
            throw std::runtime_error("regvm runtime: ks_option(KS_OPT_SYNTAX_INTEL) failed");
        }
    }
    ~KsSession() {
        if (ks_) ks_close(ks_);
    }
    KsSession(const KsSession&) = delete;
    KsSession& operator=(const KsSession&) = delete;

    // 汇编一段文本到地址 at；失败抛 std::runtime_error（含 errno + 定位行）。
    std::vector<u8> assemble(std::string_view text, u64 at, std::string_view what) {
        const std::string src(text);
        unsigned char* enc = nullptr;
        size_t size = 0, count = 0;
        if (ks_asm(ks_, src.c_str(), at, &enc, &size, &count) != 0) {
            const ks_err err = ks_errno(ks_);
            if (enc) ks_free(enc);
            // 定位失败语句（count = 已成功的语句数）。
            std::string failing = "?";
            size_t seen = 0, pos = 0;
            while (pos < src.size()) {
                const size_t nl = src.find('\n', pos);
                const std::string line = src.substr(pos, nl == std::string::npos ? nl : nl - pos);
                pos = nl == std::string::npos ? src.size() : nl + 1;
                if (line.empty() || line.find_first_not_of(" \t") == std::string::npos) continue;
                if (seen++ == count) {
                    failing = line;
                    break;
                }
            }
            // 调试：失败全文落盘（ks_asm 失败时 count 恒 0，逐行定位需外部二分）。
            char* dbg = nullptr;
            size_t dbg_len = 0;
            if (_dupenv_s(&dbg, &dbg_len, "WVMP_ASM_FAIL_DUMP") == 0 && dbg && dbg_len > 1) {
                FILE* f = nullptr;
                if (fopen_s(&f, dbg, "wb") == 0 && f) {
                    std::fwrite(src.data(), 1, src.size(), f);
                    std::fclose(f);
                }
            }
            std::free(dbg);
            throw std::runtime_error("regvm runtime: ks_asm failed (" + std::string(what) +
                                     "), ks_errno=" + std::to_string(int(err)) +
                                     ", stmt#" + std::to_string(count) + ": [" + failing + "]");
        }
        std::vector<u8> out(enc, enc + size);
        if (enc) ks_free(enc);
        if (out.empty()) {
            char* dbg = nullptr;
            size_t dbg_len = 0;
            if (_dupenv_s(&dbg, &dbg_len, "WVMP_ASM_FAIL_DUMP") == 0 && dbg && dbg_len > 1) {
                FILE* f = nullptr;
                if (fopen_s(&f, dbg, "wb") == 0 && f) {
                    std::fwrite(src.data(), 1, src.size(), f);
                    std::fclose(f);
                }
            }
            std::free(dbg);
            throw std::runtime_error("regvm runtime: ks_asm produced no code (" +
                                     std::string(what) + "), stmts=" +
                                     std::to_string(count) + ", src_bytes=" +
                                     std::to_string(src.size()));
        }
        return out;
    }

private:
    ks_engine* ks_ = nullptr;
};

// ---------------------------------------------------------------------------
// 物理寄存器名表（64/32/16/8 位形式）。池内序号即分配单位。
// rsp 恒不参与；rcx 保留为移位计数寄存器（不进池）。
// ---------------------------------------------------------------------------
struct PhysNames {
    const char* r64;
    const char* r32;
    const char* r16;
    const char* r8;
};
constexpr PhysNames kPhys[14] = {
    {"rax", "eax", "ax", "al"},      {"rdx", "edx", "dx", "dl"},
    {"rbx", "ebx", "bx", "bl"},      {"rbp", "ebp", "bp", "bpl"},
    {"rsi", "esi", "si", "sil"},     {"rdi", "edi", "di", "dil"},
    {"r8", "r8d", "r8w", "r8b"},     {"r9", "r9d", "r9w", "r9b"},
    {"r10", "r10d", "r10w", "r10b"}, {"r11", "r11d", "r11w", "r11b"},
    {"r12", "r12d", "r12w", "r12b"}, {"r13", "r13d", "r13w", "r13b"},
    {"r14", "r14d", "r14w", "r14b"}, {"r15", "r15d", "r15w", "r15b"},
};
constexpr int kPersistent = 4;
static_assert(kPersistent + 10 == 14, "4 持久 + 10 临时 = 14 可分配");

// 跳转表：opcode 低 6 位索引（合法 opcode 1..32；0/越界折叠到 Halt=非法停机）。
constexpr u64 kTableEntries = 64;

// 立即数一律 0x 十六进制书写：keystone 的 Intel 语法把裸数字按 16 进制
// 解析（`and r15, 15` 会编码成 0x15），十进制值必须显式 0x 换算。
std::string imm(u64 v) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(v));
    return buf;
}

std::string hex(u64 v) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(v));
    return buf;
}

// ---------------------------------------------------------------------------
// 生成器主体。
// ---------------------------------------------------------------------------
class AsmGen {
public:
    explicit AsmGen(Rng& rng) : rng_(rng) {}

    void roll() {
        // ctx_ 必须 callee-saved：callgate handler 跨 native call 用 r64(ctx_)
        // 寻址 VmContext（step 9-10 push/pop 完后从 VmContext 读 pc/flags/base），
        // 若 ctx_ 落到 caller-saved（rax/rdx/r8-r11），callee 按 Win64 ABI clobber，
        // 寻址读到垃圾 → segfault（rc=139 SIGSEGV）。见 issue-10 修复：
        //   .multica/issue-10-callgate-ctx-callee-saved.md
        // kPhys[14] 索引下，callee-saved = {rbx=2, rbp=3, rsi=4, rdi=5,
        //                                  r12=10, r13=11, r14=12, r15=13}
        ctx_ = kCalleeSavedIdx[rng_.uniform(0u, u64(kCalleeSavedIdx.size()) - 1u)];

        // base_ 也必须 callee-saved：vm_entry push base_ + push 7 rest(跳过 base_)
        // = 8 个 push, host_rsp = native_sp - 0x1C8. 若 base_ 是 caller-saved
        // (如 rax), 它不在 rest 数组里, push 数变成 9, host_rsp = native_sp
        // - 0x1D0. callgate step 7 `sub rsp, 0x1A8` 按 0x1C8 算, 实际需 0x1A0
        // (少 8 字节), pop ctx_ 时读错地址, ctx_ 被破坏 → 跨 native call
        // 后寻址 VmContext 读到垃圾 → segfault.
        int base_idx = ctx_;
        while (base_idx == ctx_) {
            base_idx = kCalleeSavedIdx[rng_.uniform(0u, u64(kCalleeSavedIdx.size()) - 1u)];
        }

        // t_[0] (目标 VA) 和 t_[5] (aux 立即数) 都必须 callee-saved:
        // callgate step 5 写物理 rcx/rdx/r8/r9 (Win64 ABI 参数寄存器)。若
        // t_[0] = rdx/r8/r9, step 5 clobber 目标 VA, step 6 call 错误地址。
        // 若 t_[5] = rdx/r8/r9, step 5 clobber aux 立即数, step 1 算出错的
        // 目标 VA。两者都得避 {rdx=1, r8=6, r9=7}, 即限定 callee-saved 池。
        int t0_idx = ctx_;
        while (t0_idx == ctx_ || t0_idx == base_idx) {
            t0_idx = kCalleeSavedIdx[rng_.uniform(0u, u64(kCalleeSavedIdx.size()) - 1u)];
        }
        int t5_idx = ctx_;
        while (t5_idx == ctx_ || t5_idx == base_idx || t5_idx == t0_idx) {
            t5_idx = kCalleeSavedIdx[rng_.uniform(0u, u64(kCalleeSavedIdx.size()) - 1u)];
        }

        // 其余 10 个寄存器（除 ctx_/base_/t_[0]/t_[5]）随机洗牌给 pc_/flags_/t_[1..9]
        std::array<int, 10> pool{};
        int j = 0;
        for (int i = 0; i < 14; ++i) {
            if (i == ctx_ || i == base_idx || i == t0_idx || i == t5_idx) continue;
            pool[j++] = i;
        }
        rng_.shuffle(pool.begin(), pool.end());
        pc_    = pool[0];
        flags_ = pool[1];
        // t_[0] 和 t_[5] 已固定, 其余 t_[i] 从 pool 填 (i=1..4, 6..9 = 8 个)
        for (int i = 0; i < 4; ++i) t_[i + 1] = pool[2 + i];     // t_[1..4]
        for (int i = 0; i < 4; ++i) t_[i + 6] = pool[6 + i];     // t_[6..9] (跳过 t_[5])
        t_[0] = t0_idx;
        t_[5] = t5_idx;
        base_ = base_idx;
        for (int i = 0; i < 4; ++i) size_perm_[i] = i;
        rng_.shuffle(size_perm_.begin(), size_perm_.end());
        for (int i = 0; i < 16; ++i) cond_perm_[i] = i;
        rng_.shuffle(cond_perm_.begin(), cond_perm_.end());
    }

    // ---- 名字辅助 -------------------------------------------------------
    const char* r64(int r) const { return kPhys[r].r64; }
    // 尺寸化寄存器名：size 0..3 → byte/word/dword/qword 形式。
    const char* rs(int r, int size) const {
        switch (size) {
            case 0: return kPhys[r].r8;
            case 1: return kPhys[r].r16;
            case 2: return kPhys[r].r32;
            default: return kPhys[r].r64;
        }
    }
    // 尺寸关键字。keystone 0.9.2（Intel 语法）的两个坑：
    //   1) 裸 `byte/word/dword/qword`（无 ptr）被静默吞掉——rc=0 且零编码，
    //      故 " ptr" 后缀必须保留；
    //   2) `mov/movzx r64, dword ptr [SIB/REX 基址]`（32 位读→64 位目的）
    //      直接报 KS_ERR_ASM_ARCH；改用 32 位目的寄存器（`mov r8d, dword ptr
    //      [...]`）——写 32 位寄存器本机即零扩展，语义恰为 alias_read(S32)。
    //      byte/word（movzx）与 qword（mov r64）形式均正常。
    static const char* mptr(int size) {
        switch (size) {
            case 0: return "byte ptr";
            case 1: return "word ptr";
            case 2: return "dword ptr";
            default: return "qword ptr";
        }
    }
    // 每次调用递增的标签序号：保证同一生成内所有标签全局唯一（即使
    // keystone 引擎把符号表维持在多次 ks_asm 之间也不冲突）。
    int seq() const { return seq_++; }

    // ---- 入口块（地址 0；跌入 dispatch，无跨块跳转；位置无关取码基址） ----
    std::string build_entry() const {
        std::string o;
        o += "vm_entry:\n";
        // base 寄存器的原值必须先压栈再被 lea 覆盖——否则 halt 的 pop 恢复的是
        // 码基址，调用方现场被毁（callee-saved 契约破坏）。压栈序 = 其余 7 个
        // callee-saved 保持在后，halt 按完全逆序弹出，对称成立。
        // push 编码 1 字节（非 REX 寄存器）或 2 字节（r8-r15），lea 的 rip 位移
        // 必须据此回指镜像起点。
        const unsigned push_bytes = base_ < 6 ? 1 : 2;
        o += std::string("    push ") + r64(base_) + "\n";
        o += std::string("    lea ") + r64(base_) + ", [rip - " +
             std::to_string(push_bytes + 7) + "]\n";
        // 其余 Win64 callee-saved 全量保存（随机分配可能选中其中任意几个）。
        {
            const char* rest[] = {"rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15"};
            for (const char* r : rest) {
                if (std::string_view(r) == std::string_view(kPhys[base_].r64)) continue;
                o += std::string("    push ") + r + "\n";
            }
        }
        o += std::string("    mov ") + r64(ctx_) + ", rcx\n";
        // M2-9 call gate: 把当前 host rsp 写入 VmContext.host_rsp (+0x128)，
        // callgate handler 在 native call 返回后据此把 rsp 切回解释器栈。
        // 必须用 t_[0]（pool[4] 一定是 scratch，不是持久寄存器）——rax
        // 可能在随机分配里落到 ctx/pc/flags/base 之一，把它当 scratch 用会
        // 把持久寄存器覆盖掉。
        o += std::string("    mov ") + r64(t_[0]) + ", rsp\n";
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + 0x128], " + r64(t_[0]) + "\n";
        o += std::string("    mov ") + r64(pc_) + ", qword ptr [" + r64(ctx_) + " + 0x8]\n";
        o += std::string("    mov ") + r64(flags_) + ", qword ptr [" + r64(ctx_) + " + 0x98]\n";
        return o;
    }

    // ---- dispatch 块（table_off 为码内偏移；哑值 0x40000000 强制 disp32）。
    // 无标签（避免两遍汇编时符号重定义；dump 侧另行注释标注）。
    // 字节码基址不占持久寄存器：每次 fetch 从 [CTX] 重取（每条指令多一 mov）。
    std::string build_dispatch(u64 table_off) const {
        std::string o;
        o += std::string("    mov ") + r64(t_[0]) + ", qword ptr [" + r64(ctx_) + "]\n";
        o += std::string("    mov ") + r64(t_[8]) + ", qword ptr [" + r64(t_[0]) + " + " +
             r64(pc_) + "*8]\n";
        o += std::string("    mov ") + r64(t_[0]) + ", " + r64(t_[8]) + "\n";
        o += std::string("    and ") + r64(t_[0]) + ", 0x3F\n";
        o += std::string("    mov ") + r64(t_[1]) + ", qword ptr [" + r64(base_) + " + " +
             r64(t_[0]) + "*8 + " + hex(table_off) + "]\n";
        o += std::string("    add ") + r64(t_[1]) + ", " + r64(base_) + "\n";
        o += std::string("    jmp ") + r64(t_[1]) + "\n";
        return o;
    }

    // ---- 公共构件 --------------------------------------------------------
    // 指令字（T8）→ T2=尺寸/条件 T3=a_kind T4=reg_a T5=aux(零扩展) T6=b_kind T7=reg_b。
    // 首条固定为 `mov Tn, T8`（从指令字取），随后 shr/and 逐步抽取位域。
    std::string decode_prelude() const {
        struct F {
            const char* op;   // "mov" = 从 T8 取字；"shr"/"and" = 移位掩码
            int dst;          // T 寄存器下标
            int imm;          // shr/and 的立即数
        };
        const F fields[] = {
            {"mov", 2, 0},  {"shr", 2, 18}, {"and", 2, 15},  // T2 = (w>>18)&15
            {"mov", 3, 0},  {"shr", 3, 14}, {"and", 3, 3},   // T3 = (w>>14)&3
            {"mov", 4, 0},  {"shr", 4, 22}, {"and", 4, 31},  // T4 = (w>>22)&31
            {"mov", 5, 0},  {"shr", 5, 32},                  // T5 = w>>32（零扩展）
            {"mov", 6, 0},  {"shr", 6, 16}, {"and", 6, 3},   // T6 = (w>>16)&3
            {"mov", 7, 0},  {"shr", 7, 27}, {"and", 7, 31},  // T7 = (w>>27)&31
        };
        std::string o;
        for (const auto& f : fields) {
            o += std::string("    ") + f.op + " " + r64(t_[f.dst]) + ", ";
            if (f.op == std::string("mov"))
                o += r64(t_[8]);
            else
                o += imm(f.imm);   // 一律 0x 前缀：keystone Intel 裸数字按 16 进制解析！
            o += "\n";
        }
        return o;
    }

    // 取操作数：kind==1 → 寄存器槽（按尺寸零扩展=alias_read）；否则立即数
    //（T5=aux 零扩展，按尺寸截取）。结果放 T[dst]（0 或 1）。
    // S32 读用 32 位目的寄存器（mov r8d, dword ptr [...]，写 32 位寄存器本机
    // 即零扩展）；S8/S16 用 movzx；S64 全宽（见 mptr 的坑位注记）。
    std::string load_operand(int size, int kind, int idx, int dst, const std::string& tag) const {
        const std::string l_imm = "limm" + std::to_string(kind) + "_" + tag;
        const std::string l_done = "ldone" + std::to_string(kind) + "_" + tag;
        std::string o;
        o += std::string("    cmp ") + r64(t_[kind]) + ", 1\n";
        o += "    jne " + l_imm + "\n";
        if (size == 3)
            o += std::string("    mov ") + r64(t_[dst]) + ", qword ptr [" + r64(ctx_) + " + " +
                 r64(t_[idx]) + "*8 + 0x10]\n";
        else if (size == 2)
            o += std::string("    mov ") + rs(t_[dst], 2) + ", dword ptr [" + r64(ctx_) + " + " +
                 r64(t_[idx]) + "*8 + 0x10]\n";
        else
            o += std::string("    movzx ") + r64(t_[dst]) + ", " + mptr(size) + " [" + r64(ctx_) +
                 " + " + r64(t_[idx]) + "*8 + 0x10]\n";
        o += "    jmp " + l_done + "\n";
        o += l_imm + ":\n";
        if (size == 3)
            o += std::string("    mov ") + r64(t_[dst]) + ", " + r64(t_[5]) + "\n";
        else
            o += std::string("    mov ") + rs(t_[dst], size) + ", " + rs(t_[5], size) + "\n";
        o += l_done + ":\n";
        return o;
    }

    // 别名写回：T0 结果按 alias_write 合并进 regs[T[idxreg]]。
    //（子寄存器写本机即别名语义：S8/S16 保高位；S32 写 32 位寄存器自动零扩展。）
    std::string writeback(int size, int idxreg) const {
        const std::string slot =
            std::string("[") + r64(ctx_) + " + " + r64(t_[idxreg]) + "*8 + 0x10]";
        std::string o;
        if (size == 3) {
            o += std::string("    mov qword ptr ") + slot + ", " + r64(t_[0]) + "\n";
        } else {
            o += std::string("    mov ") + r64(t_[5]) + ", qword ptr " + slot + "\n";
            o += std::string("    mov ") + rs(t_[5], size) + ", " + rs(t_[0], size) + "\n";
            o += std::string("    mov qword ptr ") + slot + ", " + r64(t_[5]) + "\n";
        }
        return o;
    }

    // 从指令字（T8 仍存活）重提 reg_a 到 T[reg]（写回前 T4 可能已被清零）。
    // 22/31 必须经 imm()：裸数字被 keystone 按 16 进制解析（22→0x22=34、
    // 31→0x31=49），写回目标寄存器算错——aux=0 时恒写 reg0，dec/jne 死循环（已踩）。
    std::string reextract_a(int reg) const {
        std::string o;
        o += std::string("    mov ") + r64(t_[reg]) + ", " + r64(t_[8]) + "\n";
        o += std::string("    shr ") + r64(t_[reg]) + ", " + imm(22) + "\n";
        o += std::string("    and ") + r64(t_[reg]) + ", " + imm(31) + "\n";
        return o;
    }

    // flags 装配 + 同步 v17 + 前进 + 回 dispatch。
    // 标准：T6=ZF T3=CF(0/1) T4=OF T7=SF T9=PF。
    // cf_preset：Inc/Dec 变体——T3 已是旧 CF 的 bit1 值（保留语义），不再移位。
    std::string flags_tail(u64 dispatch, bool cf_preset) const {
        std::string o;
        o += std::string("    mov ") + r64(flags_) + ", " + r64(t_[6]) + "\n";
        if (!cf_preset) o += std::string("    shl ") + r64(t_[3]) + ", 1\n";
        o += std::string("    or ") + r64(flags_) + ", " + r64(t_[3]) + "\n";
        o += std::string("    shl ") + r64(t_[4]) + ", 2\n";
        o += std::string("    or ") + r64(flags_) + ", " + r64(t_[4]) + "\n";
        o += std::string("    shl ") + r64(t_[7]) + ", 3\n";
        o += std::string("    or ") + r64(flags_) + ", " + r64(t_[7]) + "\n";
        o += std::string("    shl ") + r64(t_[9]) + ", 4\n";
        o += std::string("    or ") + r64(flags_) + ", " + r64(t_[9]) + "\n";
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + 0x98], " + r64(flags_) + "\n";
        o += advance(dispatch);
        return o;
    }

    std::string advance(u64 dispatch) const {
        return std::string("    add ") + r64(pc_) + ", 1\n    jmp " + hex(dispatch) + "\n";
    }

    // 尺寸链：cmp/je 检查 perm[0..2]；perm[3] 为链尾顺延跌入情形，故其块
    // 最先排放。每个块自带终结跳转（jmp <tail>），块间绝不串行跌落。
    std::string size_chain(const std::array<std::string, 4>& blocks, const std::string& tag) const {
        std::string o;
        for (int i = 0; i < 3; ++i) {
            o += std::string("    cmp ") + r64(t_[2]) + ", " + imm(size_perm_[i]) + "\n";
            o += "    je sz" + std::to_string(size_perm_[i]) + "_" + tag + "\n";
        }
        o += "sz" + std::to_string(size_perm_[3]) + "_" + tag + ":\n" + blocks[size_perm_[3]];
        for (int i = 0; i < 3; ++i) {
            const int s = size_perm_[i];
            o += "sz" + std::to_string(s) + "_" + tag + ":\n" + blocks[s];
        }
        return o;
    }

    // setcc 抽取（本机 flags 刚由宽度匹配的运算产生；T3/T4/T6/T7/T9 上位已清零）。
    std::string setcc5() const {
        std::string o;
        o += std::string("    setc ") + rs(t_[3], 0) + "\n";
        o += std::string("    seto ") + rs(t_[4], 0) + "\n";
        o += std::string("    setz ") + rs(t_[6], 0) + "\n";
        o += std::string("    sets ") + rs(t_[7], 0) + "\n";
        o += std::string("    setp ") + rs(t_[9], 0) + "\n";
        return o;
    }
    std::string zero5() const {
        std::string o;
        for (int r : {3, 4, 6, 7, 9}) o += std::string("    xor ") + r64(t_[r]) + ", " + r64(t_[r]) + "\n";
        return o;
    }
    std::string zero4() const {  // Inc/Dec：T3 保留旧 CF
        std::string o;
        for (int r : {4, 6, 7, 9}) o += std::string("    xor ") + r64(t_[r]) + ", " + r64(t_[r]) + "\n";
        return o;
    }

    // ---- handler 构造 ----------------------------------------------------

    // 二元计算（native=add/sub/and/or/xor/test；Cmp 用 sub 无写回）。
    std::string build_binary(const char* native, u64 dispatch, bool do_wb) const {
        const std::string tag = std::string(native) + std::to_string(seq());
        const std::string tail_lbl = "ftail_" + tag;
        std::array<std::string, 4> blocks;
        for (int s = 0; s < 4; ++s) {
            const std::string stag = tag + "_" + std::to_string(s);
            std::string o;
            o += load_operand(s, 3, 4, 0, "a" + stag);   // A（目的）
            o += load_operand(s, 6, 7, 1, "b" + stag);   // B（源）
            o += zero5();
            o += std::string("    ") + native + " " + rs(t_[0], s) + ", " + rs(t_[1], s) + "\n";
            o += setcc5();
            if (do_wb) {
                o += reextract_a(1);
                o += writeback(s, 1);
            }
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude() + size_chain(blocks, tag) + tail_lbl + ":\n" +
               flags_tail(dispatch, false);
    }

    // Mov / Lea（v1 Lea=值传送：地址展开已在翻译器完成）。不更新 flags。
    std::string build_mov(u64 dispatch) const {
        const std::string tag = "mov" + std::to_string(seq());
        const std::string tail_lbl = "atail_" + tag;
        std::array<std::string, 4> blocks;
        for (int s = 0; s < 4; ++s) {
            std::string o;
            // 源 = b 操作数；目的 = reg_a。
            o += load_operand(s, 6, 7, 0, "b" + tag + "_" + std::to_string(s));
            o += writeback(s, 4);
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude() + size_chain(blocks, tag) + tail_lbl + ":\n" + advance(dispatch);
    }

    // Not（无 flags）。
    std::string build_not(u64 dispatch) const {
        const std::string tag = "not" + std::to_string(seq());
        const std::string tail_lbl = "atail_" + tag;
        std::array<std::string, 4> blocks;
        for (int s = 0; s < 4; ++s) {
            std::string o;
            o += load_operand(s, 3, 4, 0, "a" + tag + "_" + std::to_string(s));
            o += std::string("    not ") + rs(t_[0], s) + "\n";
            o += reextract_a(1);
            o += writeback(s, 1);
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude() + size_chain(blocks, tag) + tail_lbl + ":\n" + advance(dispatch);
    }

    // Neg（flags 全量）。
    std::string build_neg(u64 dispatch) const {
        const std::string tag = "neg" + std::to_string(seq());
        const std::string tail_lbl = "ftail_" + tag;
        std::array<std::string, 4> blocks;
        for (int s = 0; s < 4; ++s) {
            std::string o;
            o += load_operand(s, 3, 4, 0, "a" + tag + "_" + std::to_string(s));
            o += zero5();
            o += std::string("    neg ") + rs(t_[0], s) + "\n";
            o += setcc5();
            o += reextract_a(1);
            o += writeback(s, 1);
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude() + size_chain(blocks, tag) + tail_lbl + ":\n" +
               flags_tail(dispatch, false);
    }

    // Inc/Dec（x86 语义：CF 保留，ZF/SF/OF/PF 更新）。
    std::string build_incdec(const char* native, u64 dispatch) const {
        const std::string tag = std::string(native) + std::to_string(seq());
        const std::string tail_lbl = "ftail_" + tag;
        std::array<std::string, 4> blocks;
        for (int s = 0; s < 4; ++s) {
            std::string o;
            o += load_operand(s, 3, 4, 0, "a" + tag + "_" + std::to_string(s));
            o += zero4();
            o += std::string("    mov ") + r64(t_[3]) + ", " + r64(flags_) + "\n";
            o += std::string("    and ") + r64(t_[3]) + ", 2\n";   // 旧 CF 留在 bit1
            o += std::string("    ") + native + " " + rs(t_[0], s) + "\n";
            o += std::string("    setz ") + rs(t_[6], 0) + "\n";
            o += std::string("    seto ") + rs(t_[4], 0) + "\n";
            o += std::string("    sets ") + rs(t_[7], 0) + "\n";
            o += std::string("    setp ") + rs(t_[9], 0) + "\n";
            o += reextract_a(1);
            o += writeback(s, 1);
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude() + size_chain(blocks, tag) + tail_lbl + ":\n" +
               flags_tail(dispatch, true);
    }

    // Shl/Shr（计数=cl；掩码后计数 0 → 整条 no-op 不动 flags；本机掩码规则）。
    std::string build_shift(const char* native, u64 dispatch) const {
        const std::string tag = std::string(native) + std::to_string(seq());
        const std::string adv_lbl = "adv_" + tag;
        const std::string tail_lbl = "ftail_" + tag;
        std::array<std::string, 4> blocks;
        for (int s = 0; s < 4; ++s) {
            const std::string stag = std::to_string(s) + "_" + tag;
            std::string o;
            o += load_operand(s, 3, 4, 0, "a" + stag);
            // 计数 → T1（Imm=aux / Reg=寄存器全宽，本机再按宽度掩码）。
            o += std::string("    cmp ") + r64(t_[6]) + ", 1\n";
            o += "    jne cnti" + stag + "\n";
            o += std::string("    mov ") + r64(t_[1]) + ", qword ptr [" + r64(ctx_) + " + " +
                 r64(t_[7]) + "*8 + 0x10]\n";
            o += "    jmp cntg" + stag + "\n";
            o += "cnti" + stag + ":\n";
            o += std::string("    mov ") + r64(t_[1]) + ", " + r64(t_[5]) + "\n";
            o += "cntg" + stag + ":\n";
            o += std::string("    mov cl, ") + rs(t_[1], 0) + "\n";
            o += std::string("    and cl, ") + (s <= 1 ? "0x1F" : "0x3F") + "\n";
            o += "    jz " + adv_lbl + "\n";   // 计数 0：值与 flags 均不变
            o += zero5();
            o += std::string("    ") + native + " " + rs(t_[0], s) + ", cl\n";
            o += setcc5();
            o += reextract_a(1);
            o += writeback(s, 1);
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        std::string out = decode_prelude() + size_chain(blocks, tag);
        out += adv_lbl + ":\n" + advance(dispatch);   // 计数 0 出口
        out += tail_lbl + ":\n" + flags_tail(dispatch, false);
        return out;
    }

    // Load：a=数据目的，b=地址；mem = scratch_mem + [b]。
    std::string build_load(u64 dispatch) const {
        const std::string tag = "ld" + std::to_string(seq());
        const std::string tail_lbl = "atail_" + tag;
        std::array<std::string, 4> blocks;
        for (int s = 0; s < 4; ++s) {
            std::string o;
            o += std::string("    mov ") + r64(t_[1]) + ", qword ptr [" + r64(ctx_) + " + " +
                 r64(t_[7]) + "*8 + 0x10]\n";
            if (s == 3)
                o += std::string("    mov ") + r64(t_[0]) + ", qword ptr [" + r64(t_[1]) +
                     "]\n";
            else if (s == 2)
                o += std::string("    mov ") + rs(t_[0], 2) + ", dword ptr [" + r64(t_[1]) +
                     "]\n";
            else
                o += std::string("    movzx ") + r64(t_[0]) + ", " + mptr(s) + " [" + r64(t_[1]) +
                     "]\n";
            o += writeback(s, 4);
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude() + size_chain(blocks, tag) + tail_lbl + ":\n" + advance(dispatch);
    }

    // LoadRva：M2-8 rip-relative 配套——a=数据目的, b=地址(RVA);
    // 实际访存 = RVA + scratch_mem (= image_base) = VA.
    std::string build_loadrva(u64 dispatch) const {
        const std::string tag = "ldrva" + std::to_string(seq());
        const std::string tail_lbl = "atail_" + tag;
        std::array<std::string, 4> blocks;
        for (int s = 0; s < 4; ++s) {
            std::string o;
            o += std::string("    mov ") + r64(t_[1]) + ", qword ptr [" + r64(ctx_) + " + " +
                 r64(t_[7]) + "*8 + 0x10]\n";
            o += std::string("    add ") + r64(t_[1]) + ", qword ptr [" + r64(ctx_) + " + 0x110]\n";
            if (s == 3)
                o += std::string("    mov ") + r64(t_[0]) + ", qword ptr [" + r64(t_[1]) +
                     "]\n";
            else if (s == 2)
                o += std::string("    mov ") + rs(t_[0], 2) + ", dword ptr [" + r64(t_[1]) +
                     "]\n";
            else
                o += std::string("    movzx ") + r64(t_[0]) + ", " + mptr(s) + " [" + r64(t_[1]) +
                     "]\n";
            o += writeback(s, 4);
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude() + size_chain(blocks, tag) + tail_lbl + ":\n" + advance(dispatch);
    }

    // LeaRva: MIT-322 lea rip-relative 配套——a=目的寄存器(写入 VA), b=地址(RVA).
    // 与 LoadRva 同形态但**不访存**: 读 reg_b 槽 (RVA) → 加 image_base → 直接
    // 写回 reg_a 槽 (VA). 修复 snake_sample `lea rcx, [rip+0x6dfa]` 后
    // 紧跟 `[rcx + rax*4]` Load 的 RVA→VA 转换缺失.
    // a_kind=Reg reg_a=dst, b_kind=Reg reg_b=RVA 槽, aux=0.
    // cond_or_size = size (lea 不写子寄存器别名, 但保持字节码格式一致).
    std::string build_lea_rva(u64 dispatch) const {
        const std::string tag = "learva" + std::to_string(seq());
        const std::string tail_lbl = "atail_" + tag;
        std::array<std::string, 4> blocks;
        for (int s = 0; s < 4; ++s) {
            std::string o;
            // 读 reg_b 槽 (= RVA) 到 T1, 加 image_base (在 ctx+0x110) → VA
            o += std::string("    mov ") + r64(t_[1]) + ", qword ptr [" + r64(ctx_) + " + " +
                 r64(t_[7]) + "*8 + 0x10]\n";
            o += std::string("    add ") + r64(t_[1]) + ", qword ptr [" + r64(ctx_) + " + 0x110]\n";
            // VA 直接写回 reg_a 槽 (不访存, 不写子寄存器别名)
            o += std::string("    mov qword ptr [") + r64(ctx_) + " + " + r64(t_[4]) +
                 "*8 + 0x10], " + r64(t_[1]) + "\n";
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude() + size_chain(blocks, tag) + tail_lbl + ":\n" + advance(dispatch);
    }

    // Store：a=地址，b=数据（按宽度掩码写）。
    std::string build_store(u64 dispatch) const {
        const std::string tag = "st" + std::to_string(seq());
        const std::string tail_lbl = "atail_" + tag;
        std::array<std::string, 4> blocks;
        for (int s = 0; s < 4; ++s) {
            std::string o;
            o += std::string("    mov ") + r64(t_[1]) + ", qword ptr [" + r64(ctx_) + " + " +
                 r64(t_[4]) + "*8 + 0x10]\n";
            if (s == 3)
                o += std::string("    mov ") + r64(t_[0]) + ", qword ptr [" + r64(ctx_) + " + " +
                     r64(t_[7]) + "*8 + 0x10]\n";
            else if (s == 2)
                o += std::string("    mov ") + rs(t_[0], 2) + ", dword ptr [" + r64(ctx_) + " + " +
                     r64(t_[7]) + "*8 + 0x10]\n";
            else
                o += std::string("    movzx ") + r64(t_[0]) + ", " + mptr(s) + " [" + r64(ctx_) +
                     " + " + r64(t_[7]) + "*8 + 0x10]\n";
            o += std::string("    mov ") + mptr(s) + " [" + r64(t_[1]) + "], " + rs(t_[0], s) + "\n";
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude() + size_chain(blocks, tag) + tail_lbl + ":\n" + advance(dispatch);
    }

    // StoreRva：M2-8 rip-relative 配套——a=地址(RVA), b=数据; 写 RVA+image_base.
    std::string build_storerva(u64 dispatch) const {
        const std::string tag = "strva" + std::to_string(seq());
        const std::string tail_lbl = "atail_" + tag;
        std::array<std::string, 4> blocks;
        for (int s = 0; s < 4; ++s) {
            std::string o;
            o += std::string("    mov ") + r64(t_[1]) + ", qword ptr [" + r64(ctx_) + " + " +
                 r64(t_[4]) + "*8 + 0x10]\n";
            o += std::string("    add ") + r64(t_[1]) + ", qword ptr [" + r64(ctx_) + " + 0x110]\n";
            if (s == 3)
                o += std::string("    mov ") + r64(t_[0]) + ", qword ptr [" + r64(ctx_) + " + " +
                     r64(t_[7]) + "*8 + 0x10]\n";
            else if (s == 2)
                o += std::string("    mov ") + rs(t_[0], 2) + ", dword ptr [" + r64(ctx_) + " + " +
                     r64(t_[7]) + "*8 + 0x10]\n";
            else
                o += std::string("    movzx ") + r64(t_[0]) + ", " + mptr(s) + " [" + r64(ctx_) +
                     " + " + r64(t_[7]) + "*8 + 0x10]\n";
            o += std::string("    mov ") + mptr(s) + " [" + r64(t_[1]) + "], " + rs(t_[0], s) + "\n";
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude() + size_chain(blocks, tag) + tail_lbl + ":\n" + advance(dispatch);
    }

    // Push：v4(rsp) -= 8；[scratch+rsp] = 源（S64）。
    std::string build_push(u64 dispatch) const {
        const std::string tag = "push" + std::to_string(seq());
        std::string o = decode_prelude();
        o += std::string("    mov ") + r64(t_[0]) + ", qword ptr [" + r64(ctx_) + " + 0x30]\n";
        o += std::string("    sub ") + r64(t_[0]) + ", 8\n";
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + 0x30], " + r64(t_[0]) + "\n";
        o += std::string("    cmp ") + r64(t_[3]) + ", 1\n";
        o += "    jne pimm" + tag + "\n";
        o += std::string("    mov ") + r64(t_[1]) + ", qword ptr [" + r64(ctx_) + " + " +
             r64(t_[4]) + "*8 + 0x10]\n";
        o += "    jmp pgo" + tag + "\n";
        o += "pimm" + tag + ":\n";
        o += std::string("    mov ") + r64(t_[1]) + ", " + r64(t_[5]) + "\n";
        o += "pgo" + tag + ":\n";
        o += std::string("    mov qword ptr [") + r64(t_[0]) + "], " + r64(t_[1]) + "\n";
        o += advance(dispatch);
        return o;
    }

    // Pop：目的=reg_a（S64）；v4(rsp) += 8。同 Push，**不加** scratch_mem。
    std::string build_pop(u64 dispatch) const {
        std::string o = decode_prelude();
        o += std::string("    mov ") + r64(t_[0]) + ", qword ptr [" + r64(ctx_) + " + 0x30]\n";
        o += std::string("    mov ") + r64(t_[1]) + ", qword ptr [" + r64(t_[0]) + "]\n";
        o += std::string("    mov ") + r64(t_[9]) + ", qword ptr [" + r64(ctx_) + " + 0x30]\n";
        o += std::string("    add ") + r64(t_[9]) + ", 8\n";
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + 0x30], " + r64(t_[9]) + "\n";
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + " + r64(t_[4]) + "*8 + 0x10], " +
             r64(t_[1]) + "\n";
        o += advance(dispatch);
        return o;
    }

    // 相对跳转共通：pc += sext32(aux)（aux 为**条数**差，负数以补码存 u32）。
    // movsxd 等价实现：左移 32 再算术右移 32（不依赖汇编器对 movsxd 的支持面）。
    std::string emit_jump_taken() const {
        std::string o;
        o += std::string("    mov ") + r64(t_[0]) + ", " + r64(t_[8]) + "\n";
        // 32 必须经 imm()（→"0x20"）：裸 "32" 被按 16 进制解析成 0x32=50，
        // sext 退化为移 50 位——taken 跳转量恒 0，jcc 原地死循环（已踩）。
        o += std::string("    shr ") + r64(t_[0]) + ", " + imm(32) + "\n";
        o += std::string("    shl ") + r64(t_[0]) + ", " + imm(32) + "\n";
        o += std::string("    sar ") + r64(t_[0]) + ", " + imm(32) + "\n";
        o += std::string("    add ") + r64(pc_) + ", " + r64(t_[0]) + "\n";
        o += "    jmp {DISPATCH}\n";
        return o;
    }

    // Jmp。
    std::string build_jmp(u64 dispatch) const {
        std::string o = emit_jump_taken();
        const std::string target = hex(dispatch);
        size_t p = o.find("{DISPATCH}");
        o.replace(p, 10, target);
        return o;
    }

    // 条件求值：按 ir::Cond 序号生成把 0/1 放入 T0 的指令串。
    //（FLAGS 位布局同 isa::kFlag*：ZF=bit0 CF=bit1 OF=bit2 SF=bit3 PF=bit4。）
    std::string cond_eval(int cond) const {
        const std::string F = r64(flags_);
        const std::string D = r64(t_[0]);
        const std::string S = r64(t_[1]);
        auto bit = [&](int b) {
            std::string o = "    mov " + D + ", " + F + "\n";
            if (b) o += "    shr " + D + ", " + imm(b) + "\n";
            o += "    and " + D + ", 1\n";
            return o;
        };
        auto invert = [&]() { return std::string("    xor ") + D + ", 1\n"; };
        switch (static_cast<ir::Cond>(cond)) {
            case ir::Cond::O:  return bit(2);
            case ir::Cond::No: return bit(2) + invert();
            case ir::Cond::B:  return bit(1);
            case ir::Cond::Ae: return bit(1) + invert();
            case ir::Cond::E:  return bit(0);
            case ir::Cond::Ne: return bit(0) + invert();
            case ir::Cond::S:  return bit(3);
            case ir::Cond::Ns: return bit(3) + invert();
            case ir::Cond::P:  return bit(4);
            case ir::Cond::Np: return bit(4) + invert();
            case ir::Cond::Be:  // CF | ZF
            case ir::Cond::A: { // !(CF|ZF)
                std::string o;
                o += "    mov " + D + ", " + F + "\n    shr " + D + ", 1\n";
                o += "    or " + D + ", " + F + "\n    and " + D + ", 1\n";
                if (cond == int(ir::Cond::A)) o += invert();
                return o;
            }
            case ir::Cond::L:  // SF != OF
            case ir::Cond::Ge: { // !(SF != OF)
                std::string o;
                o += "    mov " + D + ", " + F + "\n    shr " + D + ", 3\n";
                o += "    mov " + S + ", " + F + "\n    shr " + S + ", 2\n";
                o += "    xor " + D + ", " + S + "\n    and " + D + ", 1\n";
                if (cond == int(ir::Cond::Ge)) o += invert();
                return o;
            }
            case ir::Cond::Le:  // ZF | (SF != OF)
            case ir::Cond::G: { // !(ZF | (SF != OF))
                std::string o;
                o += "    mov " + D + ", " + F + "\n    shr " + D + ", 3\n";
                o += "    mov " + S + ", " + F + "\n    shr " + S + ", 2\n";
                o += "    xor " + D + ", " + S + "\n    and " + D + ", 1\n";
                o += "    mov " + S + ", " + F + "\n    and " + S + ", 1\n";
                o += "    or " + D + ", " + S + "\n";
                if (cond == int(ir::Cond::G)) o += invert();
                return o;
            }
        }
        throw std::runtime_error("regvm runtime: bad cond");
    }

    // Jcc：cond=cond_or_size（ir::Cond 0..15）；成立 pc += sext32(aux)，否则 +1。
    std::string build_jcc(u64 dispatch) const {
        const std::string tag = "jcc" + std::to_string(seq());
        const std::string test_lbl = "jtest" + tag;
        const std::string fall_lbl = "jfall" + tag;
        std::string out = decode_prelude();
        // 链式分派（顺序随机；末条件 perm[15] 为链尾顺延跌入，其块最先排放）。
        // imm() 必须用：keystone Intel 裸数字按 16 进制解析（"14"→0x14=20），
        // 十进制字符串会让条件 10..15 永远错配到链尾。
        for (int i = 0; i < 15; ++i) {
            const int c = cond_perm_[i];
            out += std::string("    cmp ") + r64(t_[2]) + ", " + imm(c) + "\n";
            out += "    je cc" + std::to_string(c) + "_" + tag + "\n";
        }
        out += "cc" + std::to_string(cond_perm_[15]) + "_" + tag + ":\n" +
               cond_eval(cond_perm_[15]) + "    jmp " + test_lbl + "\n";
        for (int i = 0; i < 15; ++i) {
            const int c = cond_perm_[i];
            out += "cc" + std::to_string(c) + "_" + tag + ":\n";
            out += cond_eval(c);
            out += "    jmp " + test_lbl + "\n";
        }
        out += test_lbl + ":\n";
        out += std::string("    test ") + r64(t_[0]) + ", " + r64(t_[0]) + "\n";
        out += "    jz " + fall_lbl + "\n";
        out += build_jmp(dispatch);   // taken：pc += sext(aux)
        out += fall_lbl + ":\n";
        out += advance(dispatch);
        return out;
    }

    // Halt：写回 pc（指向 halt 之后，便于将来恢复执行）与 ret_value(=regs[v0])，
    // 恢复现场，ret。弹出序 = 入口压栈序的严格镜像：base 最先压、最后弹。
    std::string build_halt(u64 /*dispatch*/) const {
        std::string o;
        o += std::string("    add ") + r64(pc_) + ", 1\n";
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + 0x8], " + r64(pc_) + "\n";
        o += std::string("    mov ") + r64(t_[0]) + ", qword ptr [" + r64(ctx_) + " + 0x10]\n";
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + 0x118], " + r64(t_[0]) + "\n";
        {
            const char* rest[] = {"r15", "r14", "r13", "r12", "rsi", "rdi", "rbp", "rbx"};
            for (const char* r : rest) {
                if (std::string_view(r) == std::string_view(kPhys[base_].r64)) continue;
                o += std::string("    pop ") + r + "\n";
            }
            o += std::string("    pop ") + r64(base_) + "\n";
        }
        o += "    ret\n";
        return o;
    }

    std::string build_nop(u64 dispatch) const { return advance(dispatch); }

    // GetFlags：reg_a = v17（S64 全宽）。
    std::string build_getflags(u64 dispatch) const {
        std::string o = decode_prelude();
        o += std::string("    mov ") + r64(t_[0]) + ", " + r64(flags_) + "\n";
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + " + r64(t_[4]) +
             "*8 + 0x10], " + r64(t_[0]) + "\n";
        o += advance(dispatch);
        return o;
    }

    // SetFlags：v17/缓存 = reg_a 低 5 位。
    std::string build_setflags(u64 dispatch) const {
        std::string o = decode_prelude();
        o += std::string("    mov ") + r64(t_[0]) + ", qword ptr [" + r64(ctx_) + " + " +
             r64(t_[4]) + "*8 + 0x10]\n";
        o += std::string("    and ") + r64(t_[0]) + ", 0x1F\n";
        o += std::string("    mov ") + r64(flags_) + ", " + r64(t_[0]) + "\n";
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + 0x98], " + r64(flags_) + "\n";
        o += advance(dispatch);
        return o;
    }

    // M2-9 CallGate：VM 字节码遇到 call 时由翻译器发出。
    //
    // 语义（v1：arg_count = 0）：
    //   - aux = 目标 RVA（u32，零扩展至 u64）
    //   - cond_or_size = arg_count（v1 必须 0）
    //   - 运行时：目标 VA = RVA + image_base（scratch_mem），
    //     调目标函数，callee ret 后 RAX 写回 regs[v0]，dispatch 继续。
    //
    // 寄存器/栈语义（核心约束）：
    //   1) 持久寄存器 pc/flags/base 跨 native call 必须保留——随机分配可能让
    //      它们落在 caller-saved GPR（rax/rcx/rdx/r8-r11），native callee 会
    //      按 Win64 ABI 自由 clobber；故入 handler 先写到 VmContext 槽。
    //   2) ctx 寄存器必须保留——call 后用来回写 VmContext。随机分配同样可能
    //      让 ctx 落 caller-saved；故 push 到 host stack 暂存，ret 后 pop 恢复。
    //   3) rsp 必须切到 caller 原始 frame（= native_sp），否则 [rsp+0..32] 是
    //      解释器 VmContext，callee 写阴影区/栈参数会破坏 VmContext。
    //      切 rsp 前预留 32 字节 Win64 阴影 + 8 字节对齐垫（40），使 call 前
    //      rsp 16 对齐（callee 进入看到 8 mod 16，符合 Win64）。
    //
    // 栈回退算术（host_rsp = native_sp - 0x1C8 = 解释器执行期 rsp）：
    //   stub 8 push + sub 0x140 + call 返回 8 + entry 8 push = 0x1C8
    //   push ctx → rsp = host_rsp - 8 = native_sp - 0x1D0
    //   mov rsp, native_sp - 0x28
    //   call/ret → rsp = native_sp - 0x28
    //   sub rsp, 0x1A8 → rsp = host_rsp - 8
    //   pop ctx → rsp = host_rsp
    //
    // Win64 ABI：callee 允许 clobber rcx/rdx/r8/r9。callgate 必须**保证
    // call 之前**它们持有调用参数——但 VM 翻译器把 mov/load 结果写到
    // VmContext.regs[]（内存槽），物理 rcx/rdx/r8/r9 不一定更新（被随机
    // 寄存器池当 scratch 用）。callgate 必须显式把 regs[1/2/8/9]
    // （VM 的 rcx/rdx/r8/r9 语义槽，对应 Win64 ABI 整数参数 1~4）搬到
    // 物理寄存器再 call。MIT-249 v1 不暴露 arg_count 字段——一律按 4 个
    // 准备，callee 用不到也无所谓（额外赋值是 no-op）。
    //
    // reserved 槽位（v24..v27 = regs[24..27]）用于透传快照，与翻译器
    // scratch 池 v18..v23 不重叠：
    //   +0xD0 = regs[24] = callgate 入口的 regs[1]（VM 的 Rcx）
    //   +0xD8 = regs[25] = callgate 入口的 regs[2]（VM 的 Rdx）
    //   +0xE0 = regs[26] = callgate 入口的 regs[8]（VM 的 R8）
    //   +0xE8 = regs[27] = callgate 入口的 regs[9]（VM 的 R9）
    std::string build_callgate(u64 dispatch) const {
        std::string o = decode_prelude();
        // 0) 把 VM 整数参数槽（regs[1]=Rcx, /[2]=Rdx, /[8]=R8, /[9]=R9）
        // 先搬到 reserved 槽位，防 callgate 自己的 prelude/pre-call 路径
        // 在 push ctx 之后又读 VmContext 时被外部指令序串改坏——保留独立
        // 通道供后续 load 物理寄存器用。
        o += std::string("    mov rax, qword ptr [") + r64(ctx_) + " + 0x18]\n";   // regs[1] (Rcx)
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + 0xD0], rax\n";
        o += std::string("    mov rax, qword ptr [") + r64(ctx_) + " + 0x20]\n";   // regs[2] (Rdx)
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + 0xD8], rax\n";
        o += std::string("    mov rax, qword ptr [") + r64(ctx_) + " + 0x48]\n";   // regs[8] (R8)
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + 0xE0], rax\n";
        o += std::string("    mov rax, qword ptr [") + r64(ctx_) + " + 0x50]\n";   // regs[9] (R9)
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + 0xE8], rax\n";
        // 1) 目标 VA = 目标 RVA (T5, aux) + image_base ([ctx + 0x110])
        o += std::string("    mov ") + r64(t_[0]) + ", " + r64(t_[5]) + "\n";
        o += std::string("    add ") + r64(t_[0]) + ", qword ptr [" + r64(ctx_) +
             " + 0x110]\n";
        // 2) 保存 pc/flags/base 到 VmContext 槽
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + 0x8], " + r64(pc_) + "\n";
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + 0x98], " + r64(flags_) + "\n";
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + 0x130], " + r64(base_) + "\n";
        // 3) push ctx 到 host stack
        o += std::string("    push ") + r64(ctx_) + "\n";
        // 4) 切 rsp → native_sp - 40（32 shadow + 8 对齐）
        o += std::string("    mov ") + r64(t_[1]) + ", qword ptr [" + r64(ctx_) +
             " + 0x120]\n";
        o += std::string("    sub ") + r64(t_[1]) + ", 0x28\n";
        o += std::string("    mov rsp, ") + r64(t_[1]) + "\n";
        // 5) 把 reserved slots 抬到物理 rcx/rdx/r8/r9。
        // 关键：必须用 r64(ctx_) 而非硬编码 "r14" —— ctx_ 由 AsmGen::roll()
        // 从 14 GPR 池随机洗牌 (pool[0]) 选出，当前 seed=12345 下恰好是
        // r14 是"巧合可行"而非设计。任何 seed 改动都会让此 4 行访问野地址。
        // 其余 callgate 步骤（1-4, 9-11）一致用 r64(ctx_)，本步骤同步。
        o += std::string("    mov rcx, qword ptr [") + r64(ctx_) + " + 0xD0]\n";
        o += std::string("    mov rdx, qword ptr [") + r64(ctx_) + " + 0xD8]\n";
        o += std::string("    mov r8,  qword ptr [") + r64(ctx_) + " + 0xE0]\n";
        o += std::string("    mov r9,  qword ptr [") + r64(ctx_) + " + 0xE8]\n";
        // 6) 调 native（目标 VA 在 t_[0]，参数已就位）
        o += std::string("    call ") + r64(t_[0]) + "\n";
        // 7) rsp 回到 host stack 上 push ctx 处（native_sp - 0x1D0）
        o += "    sub rsp, 0x1A8\n";
        // 8) pop 回 ctx_
        o += std::string("    pop ") + r64(ctx_) + "\n";
        // 9) 从 VmContext 恢复 pc/flags/base
        o += std::string("    mov ") + r64(pc_) + ", qword ptr [" + r64(ctx_) + " + 0x8]\n";
        o += std::string("    mov ") + r64(flags_) + ", qword ptr [" + r64(ctx_) + " + 0x98]\n";
        o += std::string("    mov ") + r64(base_) + ", qword ptr [" + r64(ctx_) + " + 0x130]\n";
        // 10) RAX (callee 返回值) 写回 regs[v0]
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + 0x10], rax\n";
        // 11) advance（PC += 1; jmp dispatch）
        o += advance(dispatch);
        return o;
    }

    // MIT-371 Addss: scalar single-precision FP add (xmm1 = xmm1 + xmm2)。
    //   字节结构: F3 0F 58 /r (3 字节 REG-REG, mod=11)。
    //   编码: reg_a=xmm_dst_slot (24..31, translator 从 IR 0..7 加 24 偏移),
    //         reg_b=xmm_src_slot (24..31), aux=0, cond_or_size=ir::Size::S32。
    //   xmm 槽位: VmContext.xmm[8] @ +0x140（MIT-371 SSE 跟踪区）;
    //   xmm 索引 = reg - 24, 槽位偏移 = 0x140 + (reg-24)*16。
    //   handler: 算 dst/src 槽位偏移 → movups 读/写 128-bit → addss。
    //   不影响 EFLAGS; 不调 setcc5 也不走 flags_tail, 直接 advance(dispatch)。
    std::string build_addss(u64 dispatch) const {
        const std::string tag = "addss" + std::to_string(seq());
        std::string o = decode_prelude();
        // T4 = reg_a (24..31). 算 xmm 槽位偏移到 T9 (Keystone 不支持 (reg-24)*16,
        // 拆为 sub 24 → shl 4 → add 0x140)。
        auto emit_xmm_offset_into_t9 = [&](int reg_t) {
            o += std::string("    mov ") + r64(t_[9]) + ", " + r64(reg_t) + "\n";
            o += std::string("    sub ") + r64(t_[9]) + ", " + imm(24) + "\n";
            o += std::string("    shl ") + r64(t_[9]) + ", " + imm(4) + "\n";
            o += std::string("    add ") + r64(t_[9]) + ", " + imm(0x140) + "\n";
        };
        emit_xmm_offset_into_t9(t_[4]);  // T9 = dst 偏移
        o += std::string("    movups xmm0, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        emit_xmm_offset_into_t9(t_[7]);  // T9 = src 偏移
        o += std::string("    movups xmm1, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        o += "    addss xmm0, xmm1\n";
        emit_xmm_offset_into_t9(t_[4]);  // 重算 dst 偏移写回
        o += std::string("    movups [") + r64(ctx_) + " + " + r64(t_[9]) + "], xmm0\n";
        o += advance(dispatch);
        (void)tag;
        return o;
    }

    // MIT-371 Addps: packed single-precision FP add (4xf32 lane-parallel)。
    //   字节结构: 0F 58 /r (3 字节 REG-REG, mod=11)。
    //   编码: reg_a=24..31 (xmm_dst_slot), reg_b=24..31 (xmm_src_slot),
    //         aux=0, cond_or_size=ir::Size::S64 (packed 128-bit 占位)。
    std::string build_addps(u64 dispatch) const {
        const std::string tag = "addps" + std::to_string(seq());
        std::string o = decode_prelude();
        auto emit_xmm_offset_into_t9 = [&](int reg_t) {
            o += std::string("    mov ") + r64(t_[9]) + ", " + r64(reg_t) + "\n";
            o += std::string("    sub ") + r64(t_[9]) + ", " + imm(24) + "\n";
            o += std::string("    shl ") + r64(t_[9]) + ", " + imm(4) + "\n";
            o += std::string("    add ") + r64(t_[9]) + ", " + imm(0x140) + "\n";
        };
        emit_xmm_offset_into_t9(t_[4]);
        o += std::string("    movups xmm0, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        emit_xmm_offset_into_t9(t_[7]);
        o += std::string("    movups xmm1, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        o += "    addps xmm0, xmm1\n";
        emit_xmm_offset_into_t9(t_[4]);
        o += std::string("    movups [") + r64(ctx_) + " + " + r64(t_[9]) + "], xmm0\n";
        o += advance(dispatch);
        (void)tag;
        return o;
    }

    // MIT-371 Addpd: packed double-precision FP add (2xf64 lane-parallel)。
    //   字节结构: 66 0F 58 /r (3 字节 REG-REG, mod=11, 0x66 prefix 隐式)。
    //   编码: reg_a=24..31 (xmm_dst_slot), reg_b=24..31 (xmm_src_slot),
    //         aux=0, cond_or_size=ir::Size::S64。
    std::string build_addpd(u64 dispatch) const {
        const std::string tag = "addpd" + std::to_string(seq());
        std::string o = decode_prelude();
        auto emit_xmm_offset_into_t9 = [&](int reg_t) {
            o += std::string("    mov ") + r64(t_[9]) + ", " + r64(reg_t) + "\n";
            o += std::string("    sub ") + r64(t_[9]) + ", " + imm(24) + "\n";
            o += std::string("    shl ") + r64(t_[9]) + ", " + imm(4) + "\n";
            o += std::string("    add ") + r64(t_[9]) + ", " + imm(0x140) + "\n";
        };
        emit_xmm_offset_into_t9(t_[4]);
        o += std::string("    movups xmm0, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        emit_xmm_offset_into_t9(t_[7]);
        o += std::string("    movups xmm1, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        o += "    addpd xmm0, xmm1\n";
        emit_xmm_offset_into_t9(t_[4]);
        o += std::string("    movups [") + r64(ctx_) + " + " + r64(t_[9]) + "], xmm0\n";
        o += advance(dispatch);
        (void)tag;
        return o;
    }

    // MIT-373 Subss: scalar single-precision FP sub (xmm1 = xmm1 - xmm2)。
    //   字节结构: F3 0F 5C /r (REG-REG, mod=11)。
    //   编码: reg_a=xmm_dst_slot (24..31, translator 从 IR 0..7 加 24 偏移),
    //         reg_b=xmm_src_slot (24..31), aux=0, cond_or_size=ir::Size::S32。
    //   xmm 槽位: VmContext.xmm[8] @ +0x140（MIT-371 SSE 跟踪区, MIT-373 复用,
    //   无需改 VmContext 布局 / stub_gen kCtxSize）。
    //   handler: 算 dst/src 槽位偏移 → movups 读/写 128-bit → subss。
    //   不影响 EFLAGS; 不调 setcc5 也不走 flags_tail, 直接 advance(dispatch)。
    std::string build_subss(u64 dispatch) const {
        const std::string tag = "subss" + std::to_string(seq());
        std::string o = decode_prelude();
        // T4 = reg_a (24..31). 算 xmm 槽位偏移到 T9 (Keystone 不支持 (reg-24)*16,
        // 拆为 sub 24 → shl 4 → add 0x140)。
        auto emit_xmm_offset_into_t9 = [&](int reg_t) {
            o += std::string("    mov ") + r64(t_[9]) + ", " + r64(reg_t) + "\n";
            o += std::string("    sub ") + r64(t_[9]) + ", " + imm(24) + "\n";
            o += std::string("    shl ") + r64(t_[9]) + ", " + imm(4) + "\n";
            o += std::string("    add ") + r64(t_[9]) + ", " + imm(0x140) + "\n";
        };
        emit_xmm_offset_into_t9(t_[4]);  // T9 = dst 偏移
        o += std::string("    movups xmm0, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        emit_xmm_offset_into_t9(t_[7]);  // T9 = src 偏移
        o += std::string("    movups xmm1, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        o += "    subss xmm0, xmm1\n";
        emit_xmm_offset_into_t9(t_[4]);  // 重算 dst 偏移写回
        o += std::string("    movups [") + r64(ctx_) + " + " + r64(t_[9]) + "], xmm0\n";
        o += advance(dispatch);
        (void)tag;
        return o;
    }

    // MIT-373 Subps: packed single-precision FP sub (4xf32 lane-parallel)。
    //   字节结构: 0F 5C /r (REG-REG, mod=11)。
    //   编码: reg_a=24..31 (xmm_dst_slot), reg_b=24..31 (xmm_src_slot),
    //         aux=0, cond_or_size=ir::Size::S64 (packed 128-bit 占位)。
    std::string build_subps(u64 dispatch) const {
        const std::string tag = "subps" + std::to_string(seq());
        std::string o = decode_prelude();
        auto emit_xmm_offset_into_t9 = [&](int reg_t) {
            o += std::string("    mov ") + r64(t_[9]) + ", " + r64(reg_t) + "\n";
            o += std::string("    sub ") + r64(t_[9]) + ", " + imm(24) + "\n";
            o += std::string("    shl ") + r64(t_[9]) + ", " + imm(4) + "\n";
            o += std::string("    add ") + r64(t_[9]) + ", " + imm(0x140) + "\n";
        };
        emit_xmm_offset_into_t9(t_[4]);
        o += std::string("    movups xmm0, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        emit_xmm_offset_into_t9(t_[7]);
        o += std::string("    movups xmm1, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        o += "    subps xmm0, xmm1\n";
        emit_xmm_offset_into_t9(t_[4]);
        o += std::string("    movups [") + r64(ctx_) + " + " + r64(t_[9]) + "], xmm0\n";
        o += advance(dispatch);
        (void)tag;
        return o;
    }

    // MIT-373 Subpd: packed double-precision FP sub (2xf64 lane-parallel)。
    //   字节结构: 66 0F 5C /r (REG-REG, mod=11, 0x66 prefix 隐式)。
    //   编码: reg_a=24..31 (xmm_dst_slot), reg_b=24..31 (xmm_src_slot),
    //         aux=0, cond_or_size=ir::Size::S64。
    std::string build_subpd(u64 dispatch) const {
        const std::string tag = "subpd" + std::to_string(seq());
        std::string o = decode_prelude();
        auto emit_xmm_offset_into_t9 = [&](int reg_t) {
            o += std::string("    mov ") + r64(t_[9]) + ", " + r64(reg_t) + "\n";
            o += std::string("    sub ") + r64(t_[9]) + ", " + imm(24) + "\n";
            o += std::string("    shl ") + r64(t_[9]) + ", " + imm(4) + "\n";
            o += std::string("    add ") + r64(t_[9]) + ", " + imm(0x140) + "\n";
        };
        emit_xmm_offset_into_t9(t_[4]);
        o += std::string("    movups xmm0, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        emit_xmm_offset_into_t9(t_[7]);
        o += std::string("    movups xmm1, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        o += "    subpd xmm0, xmm1\n";
        emit_xmm_offset_into_t9(t_[4]);
        o += std::string("    movups [") + r64(ctx_) + " + " + r64(t_[9]) + "], xmm0\n";
        o += advance(dispatch);
        (void)tag;
        return o;
    }

    // ---- 一元包装（HandlerDef 需要无参差成员函数指针） ----
    std::string build_add(u64 d) const { return build_binary("add", d, true); }
    std::string build_sub(u64 d) const { return build_binary("sub", d, true); }
    std::string build_and(u64 d) const { return build_binary("and", d, true); }
    std::string build_or(u64 d) const { return build_binary("or", d, true); }
    std::string build_xor(u64 d) const { return build_binary("xor", d, true); }
    std::string build_cmp(u64 d) const { return build_binary("sub", d, false); }
    std::string build_test(u64 d) const { return build_binary("test", d, false); }

    // MIT-339 cmovcc: dst = cond(flags) ? src : dst, 2 操作数 (reg_a=dst, reg_b=src)。
    // 编码约定 (与 translator 一致):
    //   - cond_or_size = ir::Size (asmgen size_chain 用 T2 派发 S32/S64)
    //   - aux[31..28] = ir::Cond 0..15 (cc 派发用)
    //   - aux[27..0] = 0 (cmovcc 无 aux 立即数)
    //
    // 设计：
    //   - REG-REG (mod=11) 路径: emit 单条 cmovcc r64/r32, dst, src。
    //   - MEM (mod=00) 路径: 翻译器已折成 Load(tmp, [m]) + Cmovcc(dst, tmp) 两条
    //     拆条；本 handler 只接 REG-REG 路径 (b_kind=Reg)。
    //   - cmovcc **reads** flags (CF/OF/SF/ZF/PF) 决定是否赋值, **不**改 flags
    //     (CF/OF/SF/ZF/PF 不变); 不调用 setcc5 也不走 flags_tail。
    //   - size 链 4 路: S64 (r64) / S32 (r32) / S8/S16 (cmovcc 无 8/16-bit 形式,
    //     lifter 不产此 size, 此处 defensive no-op, 沿用 bswap/xchg 模式)
    //   - cond 来自 aux[31..28], 16 variants 各自 emit cond_eval + 条件赋值。
    //
    // **关键 catch (经试错发现)**: 不能用 native cmovcc 直接读 HOST FLAGS, 因为
    // cc chain 派发的 `cmp T9, imm(c)` 会覆盖 HOST FLAGS (CF/OF/SF/ZF/PF), 让
    // native cmovcc 看到派发的 FLAGS 而不是前置 Cmp/Test 留下的 FLAGS → 条件赋值
    // 错乱 (CMOVcc handler 第一次实现踩坑, pushfq/popfq 路径也失败, 经调试发现
    // keystone 0.9.2 在某些情况下 pushfq/popfq 编码被吞掉)。
    //
    // **解决方案**: 用 cond_eval + bitwise 条件赋值, 完全不依赖 HOST FLAGS:
    //   1) 加载 src 到 T1 (r64/r32 by size).
    //   2) 加载 dst 到 T_dst_orig (T3 = r15, 空闲寄存器).
    //   3) 提取 cond (T9 from aux high bits, 不影响 FLAGS).
    //   4) cmp T9, imm(c) 链式派发 (clobbers HOST FLAGS, 但**不**影响 r10=flags_).
    //   5) cc block: cond_eval(<cond>) → T0 (0 或 1, 读 flags_=r10, 正确!).
    //   6) bitwise 条件赋值: T0 = T0 ? T1 : T_dst_orig (用 neg+mask 实现).
    //   7) alias_write T0 → dst slot (S32 保留 slot 高 32 位).
    std::string build_cmovcc(u64 dispatch) const {
        const std::string tag = "cmovcc" + std::to_string(seq());
        const std::string tail_lbl = "tail_" + tag;
        std::array<std::string, 4> blocks;
        for (int s = 0; s < 4; ++s) {
            const std::string stag = tag + "_" + std::to_string(s);
            std::string o;
            // 1) 读 src 槽到 T1 (按宽度读)
            if (s == 3)
                o += std::string("    mov ") + r64(t_[1]) + ", qword ptr [" + r64(ctx_) +
                     " + " + r64(t_[7]) + "*8 + 0x10]\n";
            else if (s == 2)
                o += std::string("    mov ") + rs(t_[1], 2) + ", dword ptr [" + r64(ctx_) +
                     " + " + r64(t_[7]) + "*8 + 0x10]\n";
            else
                o += std::string("    movzx ") + r64(t_[1]) + ", " + mptr(s) + " [" +
                     r64(ctx_) + " + " + r64(t_[7]) + "*8 + 0x10]\n";
            // 2) 读 dst 槽到 T_dst_orig = T3 (r15, 空闲寄存器 — decode_prelude
            //    把 T3 用作 a_kind, 但 cmovcc handler 不读 a_kind, T3 在此处空闲).
            if (s == 3)
                o += std::string("    mov ") + r64(t_[3]) + ", qword ptr [" + r64(ctx_) +
                     " + " + r64(t_[4]) + "*8 + 0x10]\n";
            else if (s == 2)
                o += std::string("    mov ") + rs(t_[3], 2) + ", dword ptr [" + r64(ctx_) +
                     " + " + r64(t_[4]) + "*8 + 0x10]\n";
            else
                o += std::string("    movzx ") + r64(t_[3]) + ", " + mptr(s) + " [" +
                     r64(ctx_) + " + " + r64(t_[4]) + "*8 + 0x10]\n";
            // 3) 提取 cond from aux[31..28]: T9 = (T8 >> 60) & 0xF (no FLAGS clobber).
            o += std::string("    mov ") + r64(t_[9]) + ", " + r64(t_[8]) + "\n";
            o += std::string("    shr ") + r64(t_[9]) + ", " + imm(60) + "\n";
            o += std::string("    and ") + r64(t_[9]) + ", 0xF\n";
            if (s == 3 || s == 2) {
                // 4) cc chain 派发 (cmp T9, imm(c) clobbers HOST FLAGS, 但 r10=flags_ 保留).
                for (int i = 0; i < 15; ++i) {
                    const int c = cond_perm_[i];
                    o += std::string("    cmp ") + r64(t_[9]) + ", " + imm(c) + "\n";
                    o += "    je cc" + std::to_string(c) + "_" + stag + "\n";
                }
                // 5) 每个 cc block: cond_eval → T0 (读 r10 保留的 flags_), 然后
                //    bitwise 条件赋值 (T0 = mask & src | ~mask & dst_orig) + alias_write.
                //    cond_eval 用 flags_ (r10), 不被 cmp clobber, 拿到正确 FLAGS.
                // T0 = cond result; T1 = src (在 cond_eval 前保存到 T6, 因为 L/G/LE/GE/BE/A
                // 这几个 cond_eval 会 clobber T1); T3 = dst_orig; T5 空闲作 mask scratch.
                auto emit_cc_block = [&](int c) -> std::string {
                    std::string b;
                    b += std::string("    mov ") + r64(t_[6]) + ", " + r64(t_[1]) + "\n";  // T6 = src (保存, 避开 cond_eval clobber)
                    b += cond_eval(c);                            // T0 = cond result (0/1)
                    b += std::string("    neg ") + r64(t_[0]) + "\n";        // T0 = -cond (mask: 0 or -1)
                    b += std::string("    mov ") + r64(t_[5]) + ", " + r64(t_[0]) + "\n";  // T5 = mask
                    b += std::string("    and ") + r64(t_[0]) + ", " + r64(t_[6]) + "\n";  // T0 = src & mask
                    b += std::string("    not ") + r64(t_[5]) + "\n";        // T5 = ~mask
                    b += std::string("    and ") + r64(t_[5]) + ", " + r64(t_[3]) + "\n";  // T5 = dst_orig & ~mask
                    b += std::string("    or ") + r64(t_[0]) + ", " + r64(t_[5]) + "\n";   // T0 = (src & mask) | (dst_orig & ~mask)
                    // alias_write T0 → dst slot (reg_a 索引)
                    if (s == 3) {
                        b += std::string("    mov qword ptr [") + r64(ctx_) + " + " +
                             r64(t_[4]) + "*8 + 0x10], " + r64(t_[0]) + "\n";
                    } else {
                        // S32: 读 slot → 写低 32 位 → qword 写回 (alias_write, 保留 slot 高 32 位)
                        b += std::string("    mov ") + r64(t_[3]) + ", qword ptr [" +
                             r64(ctx_) + " + " + r64(t_[4]) + "*8 + 0x10]\n";
                        b += std::string("    mov ") + rs(t_[3], 2) + ", " + rs(t_[0], 2) + "\n";
                        b += std::string("    mov qword ptr [") + r64(ctx_) + " + " +
                             r64(t_[4]) + "*8 + 0x10], " + r64(t_[3]) + "\n";
                    }
                    b += "    jmp " + tail_lbl + "\n";
                    return b;
                };
                // 末 cond (perm[15]) 为链尾顺延跌入, 其块最先排放
                o += "cc" + std::to_string(cond_perm_[15]) + "_" + stag + ":\n";
                o += emit_cc_block(cond_perm_[15]);
                for (int i = 0; i < 15; ++i) {
                    const int c = cond_perm_[i];
                    o += "cc" + std::to_string(c) + "_" + stag + ":\n";
                    o += emit_cc_block(c);
                }
            } else {
                // S8/S16: defensive no-op (lifter 不产此 size cmovcc)
                o += "    jmp " + tail_lbl + "\n";
            }
            blocks[s] = o;
        }
        return decode_prelude() + size_chain(blocks, tag) + tail_lbl + ":\n" +
               advance(dispatch);
    }

    // MIT-341 Cmpxchg: 比较并交换 r/m, r, 隐式 Rax 累加器。
    //   字节结构: [48] (REX.W 可选) | 0F B0 (S8) / 0F B1 (S16/S32/S64) + ModR/M
    //   语义 (Intel SDM Vol. 2 CMPXCHG):
    //     IF (accumulator == r/m)  ZF ← 1; r/m ← r
    //     ELSE                       ZF ← 0; accumulator ← r/m
    //   隐式 accumulator = Rax (8/16/32/64 位由 IR.size 决定, 不入 IR 字段;
    //     沿用 pitfall #34 additive enum append-only 不破坏 Insn 布局)。
    //
    // 编码约定: a_kind=Reg reg_a=dst, b_kind=Reg reg_b=src, aux=0,
    //     cond_or_size=ir::Size (S8/S16/S32/S64, 与 ALU binop 共享 2 bits)。
    //
    // 实现思路 (与 build_imul/build_adc/build_mul 对齐):
    //   1. load dst → T0 (按宽度读, alias_read 零扩展)
    //   2. load src → T1 (按宽度读; src 不动以备 cmpxchg 消耗)
    //   3. zero5() — 清 flag scratch; 副作用宿主 CF/OF/SF/ZF/PF ← 0
    //   4. load Rax 槽 (= vm_reg_of(Rax), 固定 slot 0) → T5 (按宽度 alias_read)
    //   5. mov rax/eax/ax/al, T5 — 物理 RAX = Rax 槽值 (native cmpxchg 隐式用)
    //   6. cmpxchg <sz> T0, T1 — native 完成比较+条件赋值; 自动:
    //      - ZF=1 时 T0 ← T1 (dst = src), RAX 不变
    //      - ZF=0 时 RAX.low ← T0.low (accumulator = dst), T0 不变
    //      - 全 flags 由 setcc5 捕 host CPU 真值 (与 cmp 一致)
    //   7. setcc5() — 抽取 CF/OF/SF/ZF/PF 进 FLAGS 缓存
    //   8. writeback RAX → Rax 槽 (按宽度 alias_write, 保留高位)
    //   9. reextract_a(1) + writeback T0 → dst 槽 (按宽度 alias_write)
    //
    // 关键 catch:
    //   - native cmpxchg 隐式用 RAX 作 accumulator, 故必须先把 regs[Rax] 搬到
    //     物理 RAX (类似 build_mul 的隐式 RAX 处理)。这里 T5 仅作 slot 临时
    //     (roll() 保证 T5 ∈ callee-saved 池, 不与 RAX 物理寄存器冲突),
    //     然后 `mov rax/eax/ax/al, T5` 把 T5 拷到物理 RAX, 不论 T5 与 RAX
    //     物理寄存器是否相同都能正确搬运。
    //   - 写回 Rax 槽走 alias_write 模式 (与 build_mul Rax 写回同): S64 直写
    //     qword; S32/S16/S8 读 qword 改低 32/16/8 位再写 qword (保留 Rax 槽高位
    //     与 native 写语义一致 — native 写 8/16 位不影响高位, 写 32 位零扩展
    //     高 32 位)。T1 在 setcc5 后被 reextract_a 占用, 此处先写回 Rax 再
    //     reextract_a 不会冲突: 写回 Rax 用 T1 作临时; reextract_a 重写 T1。
    //   - S8/S16 在 64-bit 模式下 REX.W 必不带, native cmpxchg 用 8/16 位物理
    //     寄存器 (al/ax 等); 与 x64 cmp/test 隐式 acc 一致。lifter 不产 S16
    //     cmpxchg (因 0x66 prefix 被 prefix[0] 检查拒, 见 translate_insn 入口),
    //     此处 S16 块保留以保持 4 路 size_chain 完整。
    //   - src 操作数 (reg_b → T1) 不被 cmpxchg 修改, 不需要 T6 保存 (与
    //     build_cmovcc 的 cond_eval clobber T1 情形不同, pitfall #37 不适用)。
    //   - S8 S16 路径保留 native cmpxchg emit, 但 defensive 兜底 (lifter 不产
    //     此 size 时该分支不会被执行)。
    std::string build_cmpxchg(u64 dispatch) const {
        const std::string tag = "cmpxchg" + std::to_string(seq());
        const std::string tail_lbl = "ftail_" + tag;
        const u8 rax_slot = isa::vm_reg_of(ir::Reg::Rax);  // = 0
        const std::string rax_slot_off =
            imm(static_cast<u64>(rax_slot) * 8 + 0x10);
        const std::string rax_slot_qp = std::string("qword ptr [") +
                                        std::string(r64(ctx_)) + " + " + rax_slot_off + "]";
        std::array<std::string, 4> blocks;
        for (int s = 0; s < 4; ++s) {
            const std::string stag = tag + "_" + std::to_string(s);
            std::string o;
            // 1) 读 dst → T0 (按宽度 alias_read 零扩展)
            o += load_operand(s, 3, 4, 0, "a" + stag);
            // 2) 读 src → T1 (按宽度 alias_read 零扩展; src 不动以备 cmpxchg 用)
            o += load_operand(s, 6, 7, 1, "b" + stag);
            // 3) zero5 — 清 flag scratch (副作用宿主 CF/OF/SF/ZF/PF ← 0)
            o += zero5();
            // 4) 读 Rax 槽 → T5 (按宽度 alias_read, 与 build_mul Rax 读同思路 —
            //    必须先经临时再拷到物理 RAX, 不能直接 `mov rax, [...]`, 因为
            //    `mov rax, [ctx + ...]` 与 load_operand 的 imm 路径都可能 clobber
            //    T0/T1 等关键寄存器)。用 std::to_string(rax_slot) 输出字面量槽号 (0),
            //    不能用 r64(rax_slot) — 那是 kPhys[0]="rax" 物理寄存器名, 与内存
            //    地址混用会出错 (与 build_mul 同模式)。
            if (s == 3)
                o += std::string("    mov ") + r64(t_[5]) + ", qword ptr [" + r64(ctx_) +
                     " + " + std::to_string(rax_slot) + "*8 + 0x10]\n";
            else if (s == 2)
                o += std::string("    mov ") + rs(t_[5], 2) + ", dword ptr [" + r64(ctx_) +
                     " + " + std::to_string(rax_slot) + "*8 + 0x10]\n";
            else if (s == 1)
                o += std::string("    mov ") + rs(t_[5], 1) + ", word ptr [" + r64(ctx_) +
                     " + " + std::to_string(rax_slot) + "*8 + 0x10]\n";
            else
                o += std::string("    movzx ") + r64(t_[5]) + ", byte ptr [" + r64(ctx_) +
                     " + " + std::to_string(rax_slot) + "*8 + 0x10]\n";
            // 5) 物理 RAX = Rax 槽值 (按宽度; native cmpxchg 隐式读 RAX 作 accumulator)
            if (s == 3)
                o += std::string("    mov rax, ") + r64(t_[5]) + "\n";
            else if (s == 2)
                o += std::string("    mov eax, ") + rs(t_[5], 2) + "\n";
            else if (s == 1)
                o += std::string("    mov ax, ") + rs(t_[5], 1) + "\n";
            else
                o += std::string("    mov al, ") + rs(t_[5], 0) + "\n";
            // 6) native cmpxchg <sz> T0, T1 — 隐式用 RAX 作 accumulator。
            //    ZF=1 时 T0 ← T1 (dst = src), 否则 RAX ← T0 (accumulator = dst)。
            //    flags 全量更新 (CF/OF/SF/ZF/PF, 与 cmp 同语义)。
            o += std::string("    cmpxchg ") + rs(t_[0], s) + ", " + rs(t_[1], s) + "\n";
            // 6.5) [关键] 把 cmpxchg 之后的 RAX 拷到 T1, 避开 setcc5 对 T4 低字节
            //      的 clobber (当 T4 == 物理 RAX 时, seto al 会覆盖 cmpxchg 结果的
            //      al 字节; 这会导致 Rax 槽写回读到被污染的值)。
            //      T1 在此之前是 src (reg_b 槽), 但 cmpxchg 不修改 src, 之后也
            //      不再需要 src, 故可直接覆写 T1。T1 不在 setcc5 clobber 集合
            //      {T3,T4,T6,T7,T9} 中, 安全。
            o += std::string("    mov ") + r64(t_[1]) + ", " + r64(0) + "\n";
            // 7) setcc5 — 抽取 CF/OF/SF/ZF/PF 进 FLAGS 缓存 (与 cmp 同语义)。
            //    此时 RAX 低字节已被 seto al clobber, 但 T1 已保存完整 cmpxchg 结果。
            o += setcc5();
            // 8) writeback Rax 槽 (alias-write 保留高位)。
            //    用 T1 (cmpxchg 结果) 与 T5 (原始 Rax 槽) 组合:
            //    - S64: 直写 T1 到 Rax 槽 (full 64-bit overwrite)
            //    - S32: T5.low32 = T1.low32; 写 T5 (preserve upper 32)
            //    - S16: T5.low16 = T1.low16; 写 T5 (preserve upper 48)
            //    - S8:  T5.low8  = T1.low8;  写 T5 (preserve upper 56)
            //    注: T1 在 reextract_a(1) 后会被覆写为 reg_a 槽位, 顺序不能颠倒
            //    (先做 Rax 写回再做 dst 写回)。
            if (s == 3) {
                o += std::string("    mov ") + rax_slot_qp + ", " + r64(t_[1]) + "\n";
            } else if (s == 2) {
                o += std::string("    mov ") + rs(t_[5], 2) + ", " + rs(t_[1], 2) + "\n";
                o += std::string("    mov ") + rax_slot_qp + ", " + r64(t_[5]) + "\n";
            } else if (s == 1) {
                o += std::string("    mov ") + rs(t_[5], 1) + ", " + rs(t_[1], 1) + "\n";
                o += std::string("    mov ") + rax_slot_qp + ", " + r64(t_[5]) + "\n";
            } else {
                o += std::string("    mov ") + rs(t_[5], 0) + ", " + rs(t_[1], 0) + "\n";
                o += std::string("    mov ") + rax_slot_qp + ", " + r64(t_[5]) + "\n";
            }
            // 9) reextract_a(1) + writeback(s, 1): 把 T0 写回 dst 槽 (按宽度 alias_write)。
            //    setcc5 clobber 了 T4 的低字节 (用作 OF 临时), 故 writeback 前必重提
            //    reg_a 槽位到 T1 (reextract_a 模式), 与 build_imul/build_adc 同源。
            o += reextract_a(1);
            o += writeback(s, 1);
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude() + size_chain(blocks, tag) + tail_lbl + ":\n" +
               flags_tail(dispatch, false);
    }

    // cc_name: ir::Cond (0..15) → Intel 语法 cmovcc 后缀字符串
    // (与 cond_eval 的 cond 命名严格一致).
    static const char* cc_name(int cond) {
        switch (static_cast<ir::Cond>(cond)) {
            case ir::Cond::O:  return "o";
            case ir::Cond::No: return "no";
            case ir::Cond::B:  return "b";
            case ir::Cond::Ae: return "ae";
            case ir::Cond::E:  return "e";
            case ir::Cond::Ne: return "ne";
            case ir::Cond::Be: return "be";
            case ir::Cond::A:  return "a";
            case ir::Cond::S:  return "s";
            case ir::Cond::Ns: return "ns";
            case ir::Cond::P:  return "p";
            case ir::Cond::Np: return "np";
            case ir::Cond::L:  return "l";
            case ir::Cond::Ge: return "ge";
            case ir::Cond::Le: return "le";
            case ir::Cond::G:  return "g";
        }
        return "?";
    }
    std::string build_inc(u64 d) const { return build_incdec("inc", d); }
    std::string build_dec(u64 d) const { return build_incdec("dec", d); }
    std::string build_shl(u64 d) const { return build_shift("shl", d); }
    std::string build_shr(u64 d) const { return build_shift("shr", d); }
    // Sar 复用 build_shift：x86 sar 与 shr 的写值差异仅在符号扩展；
    // flags 统一由 setcc5 捕获（CF=末位移出位、OF/SF/ZF/PF 按结果）。
    // count=0 走 adv_lbl 不动值/flags（与 shr/shl 一致）。
    std::string build_sar(u64 d) const { return build_shift("sar", d); }

    // Rol/Ror 复用 build_shift：与 build_sar 同理, 仅 native op 不同。x86
    // rol/ror 与 shl/shr 的语义差异仅在循环性, 无 CF_in 概念（单条指令内
    // 闭环, 不接受跨指令 carry——与 adc/sbb 的 CF_in 完全不同）。flags 全量
    // 由 setcc5 捕 host CPU 真值, 与 Intel SDM Vol. 2 ROL/ROR 一一对应:
    //   CF  = 循环移出位 (looped-out bit; 即从循环另一端被踢出的那一位,
    //         不同于 shr 的"末位 carry", 是闭环的对端位)
    //   OF  = 仅 count==1 时按结果最高两位异或 (bit[N-1] XOR bit[N-2]);
    //         count>1 时 undefined (Intel SDM 标 undefined), host CPU 仍写
    //         一个值, setcc5 照样捕获——与 SDM "undefined" 一致
    //   SF  = 结果 MSB
    //   ZF  = 结果 == 0
    //   PF  = 结果低 8 位偶校验
    // 关键 catch：build_shift 不能直接复用于 build_adc/build_sbb（zero5 清
    // 宿主 CF 导致 CF_in 丢失）；反之 build_adc/build_sbb 不能复用 build_shift
    //（CF_in 路径不对）。Rol/Ror 走 build_shift 是对称的——它们无 CF_in 概念。
    // count=0 走 adv_lbl 不动值/flags（与 shr/shl/sar 一致；x86 原生语义）。
    std::string build_rol(u64 d) const { return build_shift("rol", d); }
    std::string build_ror(u64 d) const { return build_shift("ror", d); }

    // MIT-301 cl 变体 shift: D3 /5 形式，计数源自 RCX 低 8 位（cl）而非 aux。
    // 翻译器对 src.kind=Reg 的 shift 发射新 VmOp (ShlCl/ShrCl/SarCl/RolCl/
    // RorCl), b_kind=OpKind::Reg, reg_b=RCX 槽。handler 复用 build_shift:
    //   - b_kind=Reg 路径永远走 T6=1 分支，count 从 regs[T7] 取（即 RCX）
    //   - 与 imm 变体共享同一段汇编，唯一差异是 VmOp 编号让 dispatch 跳此处
    //   - 五个 cl 变体仅 native op 字符串不同 ("shl"/"shr"/"sar"/"rol"/"ror")
    // 独立 VmOp 编码让字节码语义显式、asm_dump 可读、与 imm 变体严格区分。
    std::string build_shl_cl(u64 d) const { return build_shift("shl", d); }
    std::string build_shr_cl(u64 d) const { return build_shift("shr", d); }
    std::string build_sar_cl(u64 d) const { return build_shift("sar", d); }
    std::string build_rol_cl(u64 d) const { return build_shift("rol", d); }
    std::string build_ror_cl(u64 d) const { return build_shift("ror", d); }

    // MIT-307 Movsxd (Reg-Reg): dst = sign_ext_32(src)。
    // 用 native movsxd 一次完成 32→64 符号扩展：把 src VM 槽当 dword ptr
    // (内存读取自动只取低 32 位), movsxd 把它符号扩展到 64 位目的物理寄存器,
    // 最后写回 dst VM 槽 (qword)。不更新 flags（movsxd 不影响 CF/OF/SF/ZF/PF）。
    // size 恒为 S64（movsxd 必 32→64），跳过 size_chain。
    std::string build_movsxd(u64 dispatch) const {
        const std::string tag = "movsxd" + std::to_string(seq());
        std::string o = decode_prelude();
        // 1. movsxd t_[0], dword ptr [ctx_ + reg_b*8 + 0x10]
        //   把 src 32 位值（VM 槽当 dword 内存读）符号扩展到 t_[0] (64-bit)
        o += std::string("    movsxd ") + r64(t_[0]) + ", dword ptr [" + r64(ctx_) +
             " + " + r64(t_[7]) + "*8 + 0x10]\n";
        // 2. mov qword ptr [ctx_ + reg_a*8 + 0x10], t_[0]
        //   64 位写回 dst VM 槽
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + " + r64(t_[4]) +
             "*8 + 0x10], " + r64(t_[0]) + "\n";
        o += advance(dispatch);
        (void)tag;
        return o;
    }

    // MIT-307 MovsxdMem (Reg-Mem): dst = sign_ext_32([addr])，
    // addr 是翻译器 emit_address 写到 reg_b VM 槽里的 64 位地址。
    // handler: 取地址到 t_[1] → 32 位 load + 符号扩展到 t_[0] → 64 位写回 dst。
    // 不更新 flags。
    std::string build_movsxd_mem(u64 dispatch) const {
        const std::string tag = "movsxdm" + std::to_string(seq());
        std::string o = decode_prelude();
        // 1. mov t_[1], qword ptr [ctx_ + reg_b*8 + 0x10]
        //   把 reg_b 槽里 64 位地址取到 t_[1]
        o += std::string("    mov ") + r64(t_[1]) + ", qword ptr [" + r64(ctx_) +
             " + " + r64(t_[7]) + "*8 + 0x10]\n";
        // 2. movsxd t_[0], dword ptr [t_[1]]
        //   从 [t_[1]] 读 32 位, 符号扩展到 t_[0] (64-bit)
        o += std::string("    movsxd ") + r64(t_[0]) + ", dword ptr [" + r64(t_[1]) + "]\n";
        // 3. mov qword ptr [ctx_ + reg_a*8 + 0x10], t_[0]
        //   64 位写回 dst VM 槽
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + " + r64(t_[4]) +
             "*8 + 0x10], " + r64(t_[0]) + "\n";
        o += advance(dispatch);
        (void)tag;
        return o;
    }

    // MIT-315 Movzx (Reg-Reg): dst = zero_extend_8(src)。
    // MIT-345 扩: src 可为 S8 (0F B6, byte ptr) 或 S16 (0F B7, word ptr)。
    //   src_size 编码在 aux[0] (T5&1): 0=S8, 1=S16。lifter 据 0x0F B6/B7 派活单
    //   决策时填进 aux 传给 asmgen；handler 运行时 cmp/jne 选 byte ptr vs word ptr。
    // native movzx 一次完成 8/16 位零扩展到 64 位目的物理寄存器, VM 槽 qword
    // 写回。size 字段 (T2=cond_or_size) 决定目的寄存器宽度但 handler 不分支
    // （native movzx 自动按目的寄存器 emit 正确 REX.W / 0x66 前缀, VM 槽 qword
    // 总是 64 位写回）。不更新 flags（movzx 不影响 CF/OF/SF/ZF/PF）。
    std::string build_movzx(u64 dispatch) const {
        const std::string tag = "movzx" + std::to_string(seq());
        const std::string l_sz8 = "movzx_sz8_" + tag;
        const std::string l_done = "movzx_done_" + tag;
        std::string o = decode_prelude();
        // MIT-345: src_size 提取到 T1 (decode_prelude 不写 T1)。
        o += std::string("    mov ") + r64(t_[1]) + ", " + r64(t_[5]) + "\n";   // T1 = aux
        o += std::string("    and ") + r64(t_[1]) + ", " + imm(1) + "\n";       // T1 = src_size bit
        o += std::string("    cmp ") + r64(t_[1]) + ", " + imm(1) + "\n";
        o += std::string("    jne ") + l_sz8 + "\n";
        // S16 路径: word ptr (src = 16-bit)
        o += std::string("    movzx ") + r64(t_[0]) + ", word ptr [" + r64(ctx_) +
             " + " + r64(t_[7]) + "*8 + 0x10]\n";
        o += std::string("    jmp ") + l_done + "\n";
        o += l_sz8 + ":\n";
        // S8 路径: byte ptr (src = 8-bit)
        o += std::string("    movzx ") + r64(t_[0]) + ", byte ptr [" + r64(ctx_) +
             " + " + r64(t_[7]) + "*8 + 0x10]\n";
        o += l_done + ":\n";
        // qword 写回 dst VM 槽（movzx 自动填 0 到上 56/48 位）
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + " + r64(t_[4]) +
             "*8 + 0x10], " + r64(t_[0]) + "\n";
        o += advance(dispatch);
        (void)tag;
        return o;
    }

    // MIT-315 MovzxMem (Reg-Mem): dst = zero_extend_8([addr])，
    // MIT-345 扩: src 8/16 位同 build_movzx。
    // addr 是翻译器 emit_address 写到 reg_b VM 槽里的 64 位地址。
    // handler: 取地址到 T1 → byte/word ptr 读 + 零扩展到 T0 → qword 写回 dst。
    // 不更新 flags。
    std::string build_movzx_mem(u64 dispatch) const {
        const std::string tag = "movzxm" + std::to_string(seq());
        const std::string l_sz8 = "movzxm_sz8_" + tag;
        const std::string l_done = "movzxm_done_" + tag;
        std::string o = decode_prelude();
        // MIT-345: src_size 提取到 T6 (decode_prelude 用 T6=b_kind, 本 handler 不复用)。
        o += std::string("    mov ") + r64(t_[6]) + ", " + r64(t_[5]) + "\n";
        o += std::string("    and ") + r64(t_[6]) + ", " + imm(1) + "\n";
        // 1. mov T1, qword ptr [ctx + reg_b*8 + 0x10]   (T1 = address)
        o += std::string("    mov ") + r64(t_[1]) + ", qword ptr [" + r64(ctx_) +
             " + " + r64(t_[7]) + "*8 + 0x10]\n";
        // 2. movzx T0, byte/word ptr [T1]  (src_size 决定 ptr 大小)
        o += std::string("    cmp ") + r64(t_[6]) + ", " + imm(1) + "\n";
        o += std::string("    jne ") + l_sz8 + "\n";
        o += std::string("    movzx ") + r64(t_[0]) + ", word ptr [" + r64(t_[1]) + "]\n";
        o += std::string("    jmp ") + l_done + "\n";
        o += l_sz8 + ":\n";
        o += std::string("    movzx ") + r64(t_[0]) + ", byte ptr [" + r64(t_[1]) + "]\n";
        o += l_done + ":\n";
        // 3. mov qword ptr [ctx + reg_a*8 + 0x10], T0   (写回 dst VM 槽)
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + " + r64(t_[4]) +
             "*8 + 0x10], " + r64(t_[0]) + "\n";
        o += advance(dispatch);
        (void)tag;
        return o;
    }

    // MIT-347 Movsx (Reg-Reg): dst = sign_extend_8/16(src)。
    // 与 build_movzx 1:1 对偶，唯一区别是 native `movsx` 而非 `movzx`（符号扩展 vs 零扩展）。
    // src_size 编码在 aux[0] (T5&1): 0=S8, 1=S16。lifter 据 0x0F BE/BF 派活单决策
    // 时填进 aux 传给 asmgen；handler 运行时 cmp/jne 选 byte ptr vs word ptr。
    // native movsx 一次完成 8/16 位符号扩展到 64 位目的物理寄存器, VM 槽 qword
    // 写回。size 字段 (T2=cond_or_size) 决定目的寄存器宽度但 handler 不分支
    // （native movsx 自动按目的寄存器 emit 正确 REX.W / 0x66 前缀, VM 槽 qword
    // 总是 64 位写回）。不更新 flags（movsx 不影响 CF/OF/SF/ZF/PF）。
    std::string build_movsx(u64 dispatch) const {
        const std::string tag = "movsx" + std::to_string(seq());
        const std::string l_sz8 = "movsx_sz8_" + tag;
        const std::string l_done = "movsx_done_" + tag;
        std::string o = decode_prelude();
        // MIT-347: src_size 提取到 T1 (decode_prelude 不写 T1)。与 build_movzx 同款。
        o += std::string("    mov ") + r64(t_[1]) + ", " + r64(t_[5]) + "\n";   // T1 = aux
        o += std::string("    and ") + r64(t_[1]) + ", " + imm(1) + "\n";       // T1 = src_size bit
        o += std::string("    cmp ") + r64(t_[1]) + ", " + imm(1) + "\n";
        o += std::string("    jne ") + l_sz8 + "\n";
        // S16 路径: word ptr (src = 16-bit)
        o += std::string("    movsx ") + r64(t_[0]) + ", word ptr [" + r64(ctx_) +
             " + " + r64(t_[7]) + "*8 + 0x10]\n";
        o += std::string("    jmp ") + l_done + "\n";
        o += l_sz8 + ":\n";
        // S8 路径: byte ptr (src = 8-bit)
        o += std::string("    movsx ") + r64(t_[0]) + ", byte ptr [" + r64(ctx_) +
             " + " + r64(t_[7]) + "*8 + 0x10]\n";
        o += l_done + ":\n";
        // qword 写回 dst VM 槽（movsx 把符号位扩展到上 56/48 位，负数填 1 正数填 0）
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + " + r64(t_[4]) +
             "*8 + 0x10], " + r64(t_[0]) + "\n";
        o += advance(dispatch);
        (void)tag;
        return o;
    }

    // MIT-347 MovsxMem (Reg-Mem): dst = sign_extend_8/16([addr])。
    // 与 build_movzx_mem 1:1 对偶，唯一区别是 native `movsx` 而非 `movzx`。
    // addr 是翻译器 emit_address 写到 reg_b VM 槽里的 64 位地址。
    // handler: 取地址到 T1 → byte/word ptr 读 + 符号扩展到 T0 → qword 写回 dst。
    // 不更新 flags。
    std::string build_movsx_mem(u64 dispatch) const {
        const std::string tag = "movsxm" + std::to_string(seq());
        const std::string l_sz8 = "movsxm_sz8_" + tag;
        const std::string l_done = "movsxm_done_" + tag;
        std::string o = decode_prelude();
        // MIT-347: src_size 提取到 T6 (decode_prelude 用 T6=b_kind, 本 handler 不复用)。
        // 与 build_movzx_mem 同款。
        o += std::string("    mov ") + r64(t_[6]) + ", " + r64(t_[5]) + "\n";
        o += std::string("    and ") + r64(t_[6]) + ", " + imm(1) + "\n";
        // 1. mov T1, qword ptr [ctx + reg_b*8 + 0x10]   (T1 = address)
        o += std::string("    mov ") + r64(t_[1]) + ", qword ptr [" + r64(ctx_) +
             " + " + r64(t_[7]) + "*8 + 0x10]\n";
        // 2. movsx T0, byte/word ptr [T1]  (src_size 决定 ptr 大小, 符号扩展)
        o += std::string("    cmp ") + r64(t_[6]) + ", " + imm(1) + "\n";
        o += std::string("    jne ") + l_sz8 + "\n";
        o += std::string("    movsx ") + r64(t_[0]) + ", word ptr [" + r64(t_[1]) + "]\n";
        o += std::string("    jmp ") + l_done + "\n";
        o += l_sz8 + ":\n";
        o += std::string("    movsx ") + r64(t_[0]) + ", byte ptr [" + r64(t_[1]) + "]\n";
        o += l_done + ":\n";
        // 3. mov qword ptr [ctx + reg_a*8 + 0x10], T0   (写回 dst VM 槽)
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + " + r64(t_[4]) +
             "*8 + 0x10], " + r64(t_[0]) + "\n";
        o += advance(dispatch);
        (void)tag;
        return o;
    }

    // MIT-333 Bswap: dst = byte_swap(dst), 单操作数 (dst only, no src).
    // a_kind=Reg reg_a=dst, b_kind=None, aux=0, cond_or_size=size (S32/S64).
    //
    // size 链 4 路:
    //   - s=3 (S64): mov rax, qword ptr [...] ; bswap rax ; mov qword ptr [...], rax
    //   - s=2 (S32): mov eax, dword ptr [...] ; bswap eax ; mov qword ptr [...], rax
    //                (32 位寄存器读自动 zero-extend 上 32 位, bswap 后上 32 位仍 0,
    //                 qword 写回完整 64 位 = 上 32 位 0 + 下 32 位字节反转结果)
    //   - s=0/1 (S8/S16): bswap 不存在 (Intel SDM Vol. 2 BSWAP 仅 32/64-bit);
    //                     lifter 不产 S8/S16 bswap, 此处 defensive no-op
    //
    // bswap 不影响 flags (CF/OF/SF/ZF/PF 不变)。handler 不调用 setcc5 也不
    // 走 flags_tail, 直接 advance(dispatch)。
    std::string build_bswap(u64 dispatch) const {
        const std::string tag = "bswap" + std::to_string(seq());
        const std::string tail_lbl = "atail_" + tag;
        std::array<std::string, 4> blocks;
        for (int s = 0; s < 4; ++s) {
            std::string o;
            if (s == 3) {
                // S64: 64 位读 + 64 位 bswap + 64 位写回
                o += std::string("    mov ") + r64(t_[0]) + ", qword ptr [" + r64(ctx_) +
                     " + " + r64(t_[4]) + "*8 + 0x10]\n";
                o += std::string("    bswap ") + r64(t_[0]) + "\n";
                o += std::string("    mov qword ptr [") + r64(ctx_) + " + " +
                     r64(t_[4]) + "*8 + 0x10], " + r64(t_[0]) + "\n";
            } else if (s == 2) {
                // S32: 32 位读 (自动 zero-extend 上 32 位) + 32 位 bswap + qword 写回
                //   mov eax, dword ptr [...] 上 32 位 rax 自动清 0
                //   bswap eax  仅低 32 位字节反转, 上 32 位保持 0
                //   mov qword ptr [...], rax  qword 写回完整 64 位 (上 32 位 0)
                o += std::string("    mov ") + rs(t_[0], 2) + ", dword ptr [" + r64(ctx_) +
                     " + " + r64(t_[4]) + "*8 + 0x10]\n";
                o += std::string("    bswap ") + rs(t_[0], 2) + "\n";
                o += std::string("    mov qword ptr [") + r64(ctx_) + " + " +
                     r64(t_[4]) + "*8 + 0x10], " + r64(t_[0]) + "\n";
            } else {
                // S8/S16: defensive no-op (lifter 不产此 size bswap)
            }
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude() + size_chain(blocks, tag) + tail_lbl + ":\n" +
               advance(dispatch);
    }

    // MIT-349 Popcnt: dst = count_ones(src), 2 操作数 (reg_a=dst, reg_b=src)。
    // 字节结构: [48] (REX.W 可选) | F3 0F B8 | ModR/M (mod=11 REG-REG)。
    // a_kind=Reg, reg_a=dst, b_kind=Reg, reg_b=src, aux=0, cond_or_size=size
    //   (S32 或 S64 由 REX.W 决定, lifter 已传过来)。
    //
    // 派活单限定不支持 MEM 形式 (沿用 movzx/movsx 限定风格, 完全不支持 MEM 不像
    // movzx/movsx 沿用 MovzxMem/MovsxMem 单独处理)——翻译器只产 REG-REG 路径。
    //
    // size 链 4 路:
    //   - s=3 (S64): qword 读 src 槽 → popcnt r64, r64 → qword 写回 dst 槽
    //   - s=2 (S32): dword 读 src 槽 (alias_read 自动 zero-extend 上 32 位)
    //                → popcnt r32, r32 → qword 写回 dst 槽 (上 32 位 0, popcnt
    //                  结果 0..32 自动 zero-extend 上 32 位, 与 native popcnt
    //                  32-bit → 32-bit 寄存器零扩展上 32 位语义一致)
    //   - s=0/1 (S8/S16): popcnt 无 8/16-bit 形式 (Intel SDM Vol. 2 POPCNT 仅
    //                     16/32/64-bit); lifter 不产此 size, 此处 defensive no-op
    //
    // popcnt 不影响 flags (CF/OF/SF/ZF/PF 不变, SSE4.2 popcnt 仅 ZF 与结果 0/非0
    // 相关)。handler 不调用 setcc5 也不走 flags_tail, 直接 advance(dispatch)。
    //
    // **pitfall #37 复用**: native popcnt 是 2 操作数 REG-REG, src 被 popcnt 消耗
    // (不保留), 不需要 save src to T6 (与 build_cmpxchg 的 "src 不被 cmpxchg 修改,
    // 不需 T6 保存" 同源)。但 T1 仍作 src slot index 临时——必须先 qword/dword 读
    // src 槽到 T1, 再 popcnt T1, T1 in-place, 然后 qword 写回 T1 到 reg_a (dst)
    // 槽。整个流程 T1 是唯一的载体寄存器, 不需要 T6 守恒。
    std::string build_popcnt(u64 dispatch) const {
        const std::string tag = "popcnt" + std::to_string(seq());
        const std::string tail_lbl = "atail_" + tag;
        std::array<std::string, 4> blocks;
        for (int s = 0; s < 4; ++s) {
            std::string o;
            if (s == 3) {
                // S64: qword 读 src 槽 → popcnt in-place → qword 写回 dst 槽
                o += std::string("    mov ") + r64(t_[1]) + ", qword ptr [" + r64(ctx_) +
                     " + " + r64(t_[7]) + "*8 + 0x10]\n";  // T1 = src (qword)
                o += std::string("    popcnt ") + r64(t_[1]) + ", " + r64(t_[1]) + "\n";  // T1 = popcnt(T1)
                o += std::string("    mov qword ptr [") + r64(ctx_) + " + " +
                     r64(t_[4]) + "*8 + 0x10], " + r64(t_[1]) + "\n";  // qword 写回 dst
            } else if (s == 2) {
                // S32: dword 读 src (alias_read 自动 zero-extend 上 32 位)
                //      → popcnt r32,r32 in-place → qword 写回 dst 槽
                // 32 位寄存器 popcnt 结果 (eax) 自动 zero-extend 上 32 位, qword
                // 写回完整 64 位 (上 32 位 0)。
                o += std::string("    mov ") + rs(t_[1], 2) + ", dword ptr [" + r64(ctx_) +
                     " + " + r64(t_[7]) + "*8 + 0x10]\n";  // T1 = src (alias_read)
                o += std::string("    popcnt ") + rs(t_[1], 2) + ", " + rs(t_[1], 2) + "\n";
                o += std::string("    mov qword ptr [") + r64(ctx_) + " + " +
                     r64(t_[4]) + "*8 + 0x10], " + r64(t_[1]) + "\n";  // qword 写回
            } else {
                // S8/S16: defensive no-op (lifter 不产此 size popcnt)
            }
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude() + size_chain(blocks, tag) + tail_lbl + ":\n" +
               advance(dispatch);
    }

    // MIT-353 Lzcount: 前导零计数 (lzcnt r, r/m, BMI1)。
    //   字节结构: [48] (REX.W 可选) | F3 0F BD | ModR/M
    //   语义 (Intel SDM Vol. 2 LZCNT): dst = count_leading_zeros(src),
    //     src 寄存器保留 (不像 popcnt 派活单 "src 被消耗 in-place")。
    //   a_kind=Reg, reg_a=dst, b_kind=Reg, reg_b=src, aux=0, cond_or_size=size
    //     (S32 或 S64 由 REX.W 决定, lifter 已传过来)。
    //
    // 编码约定: a_kind=Reg reg_a=dst, b_kind=Reg reg_b=src, aux=0,
    //     cond_or_size=ir::Size (S32/S64, 与 popcnt 共享 2 bits size_chain)。
    //
    // 实现思路 (与 build_popcnt 同模式但 src 必须保留):
    //   1. load src → T1 (按宽度读, alias_read 零扩展)
    //   2. save T1 → T6 (pitfall #37 — 避开未来 cond_eval / size_chain 扩展 clobber T1)
    //   3. lzcnt <sz> T1, T6 — native 完成前导零计数; T1 = count(T6), T6 保留
    //      (native lzcnt 只写 dst, src 寄存器保留 — 与 popcnt "src 被消耗可重用 T1"
    //       的本质差异, popcnt 派活单不需 T6 守恒, lzcnt 派活单必 save src)
    //   4. writeback T1 → dst 槽 (按宽度 alias_write, S32 自动零扩展上 32 位)
    //
    // 关键 catch:
    //   - size_chain 不 clobber T1 (只用 T2 cmp/je 派发), 但保守 save T1→T6
    //     留余地: 即使未来 cond_eval 加入或 size_chain 路径变化, src 仍可保.
    //   - S32 lzcnt 路径用 32 位寄存器读 + lzcnt r32,r32, 上 32 位自动 zero-extend;
    //     qword 写回完整 64 位 (上 32 位 0, lzcnt 32-bit 结果 0..32 自动 zero-extend).
    //   - S64 lzcnt 路径全 64 位读写, T1 = lzcnt(T6).
    //   - S8/S16: defensive no-op (lifter 不产此 size lzcnt, Intel SDM Vol. 2 LZCNT
    //     仅 16/32/64-bit 寄存器形式).
    //   - 不影响 flags (CF/OF/SF/ZF/PF 不变, BMI1 lzcnt 仅 ZF 与结果 0/非0 相关);
    //     handler 不调用 setcc5 也不走 flags_tail, 直接 advance(dispatch).
    std::string build_lzcnt(u64 dispatch) const {
        const std::string tag = "lzcnt" + std::to_string(seq());
        const std::string tail_lbl = "atail_" + tag;
        std::array<std::string, 4> blocks;
        for (int s = 0; s < 4; ++s) {
            std::string o;
            if (s == 3) {
                // S64: qword 读 src 槽 → save to T6 → lzcnt r64, r64 → qword 写回 dst
                o += std::string("    mov ") + r64(t_[1]) + ", qword ptr [" + r64(ctx_) +
                     " + " + r64(t_[7]) + "*8 + 0x10]\n";  // T1 = src (qword)
                o += std::string("    mov ") + r64(t_[6]) + ", " + r64(t_[1]) +
                     "\n";  // T6 = src (save, pitfall #37)
                o += std::string("    lzcnt ") + r64(t_[1]) + ", " + r64(t_[6]) +
                     "\n";  // T1 = lzcnt(T6), T6 保留
                o += std::string("    mov qword ptr [") + r64(ctx_) + " + " +
                     r64(t_[4]) + "*8 + 0x10], " + r64(t_[1]) + "\n";  // qword 写回 dst
            } else if (s == 2) {
                // S32: dword 读 src (alias_read 自动 zero-extend 上 32 位)
                //      → save to T6 → lzcnt r32, r32 → qword 写回 dst
                // 32 位寄存器读自动 zero-extend 上 32 位, T1 上 32 位 0.
                o += std::string("    mov ") + rs(t_[1], 2) + ", dword ptr [" + r64(ctx_) +
                     " + " + r64(t_[7]) + "*8 + 0x10]\n";  // T1 = src (alias_read)
                o += std::string("    mov ") + r64(t_[6]) + ", " + r64(t_[1]) +
                     "\n";  // T6 = src (save, pitfall #37)
                o += std::string("    lzcnt ") + rs(t_[1], 2) + ", " + rs(t_[6], 2) +
                     "\n";  // T1 = lzcnt(T6), 32-bit 路径, 上 32 位自动 0
                o += std::string("    mov qword ptr [") + r64(ctx_) + " + " +
                     r64(t_[4]) + "*8 + 0x10], " + r64(t_[1]) + "\n";  // qword 写回
            } else {
                // S8/S16: defensive no-op (lifter 不产此 size lzcnt)
            }
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude() + size_chain(blocks, tag) + tail_lbl + ":\n" +
               advance(dispatch);
    }

    // MIT-353 Tzcount: 末尾零计数 (tzcnt r, r/m, BMI1)。
    //   字节结构: [48] (REX.W 可选) | F3 0F BC | ModR/M
    //   语义 (Intel SDM Vol. 2 TZCNT): dst = count_trailing_zeros(src),
    //     src 寄存器保留 (与 lzcnt 同源, 与 popcnt 派活单 "src 被消耗 in-place" 不同)。
    //   a_kind=Reg, reg_a=dst, b_kind=Reg, reg_b=src, aux=0, cond_or_size=size
    //     (S32 或 S64 由 REX.W 决定, lifter 已传过来)。
    //
    // 实现思路 (与 build_lzcnt 同模式, src 必须保留):
    //   1. load src → T1 (按宽度读, alias_read 零扩展)
    //   2. save T1 → T6 (pitfall #37 — 避开未来 cond_eval / size_chain 扩展 clobber T1)
    //   3. tzcnt <sz> T1, T6 — native 完成末尾零计数; T1 = count(T6), T6 保留
    //   4. writeback T1 → dst 槽 (按宽度 alias_write, S32 自动零扩展上 32 位)
    //
    // 关键 catch: 与 build_lzcnt 完全同源 (lzcnt/tzcnt 是一对 BMI1 bit-scan 指令,
    //   派活单 §D 限定一致, src 保留, 走同模式 save T6 + 写回 dst).
    //   S32/S64 路径同 lzcnt, S8/S16 defensive no-op.
    //   不影响 flags; 不调 setcc5; 直接 advance(dispatch).
    std::string build_tzcnt(u64 dispatch) const {
        const std::string tag = "tzcnt" + std::to_string(seq());
        const std::string tail_lbl = "atail_" + tag;
        std::array<std::string, 4> blocks;
        for (int s = 0; s < 4; ++s) {
            std::string o;
            if (s == 3) {
                // S64: qword 读 src 槽 → save to T6 → tzcnt r64, r64 → qword 写回 dst
                o += std::string("    mov ") + r64(t_[1]) + ", qword ptr [" + r64(ctx_) +
                     " + " + r64(t_[7]) + "*8 + 0x10]\n";  // T1 = src (qword)
                o += std::string("    mov ") + r64(t_[6]) + ", " + r64(t_[1]) +
                     "\n";  // T6 = src (save, pitfall #37)
                o += std::string("    tzcnt ") + r64(t_[1]) + ", " + r64(t_[6]) +
                     "\n";  // T1 = tzcnt(T6), T6 保留
                o += std::string("    mov qword ptr [") + r64(ctx_) + " + " +
                     r64(t_[4]) + "*8 + 0x10], " + r64(t_[1]) + "\n";  // qword 写回 dst
            } else if (s == 2) {
                // S32: dword 读 src (alias_read 自动 zero-extend 上 32 位)
                //      → save to T6 → tzcnt r32, r32 → qword 写回 dst
                o += std::string("    mov ") + rs(t_[1], 2) + ", dword ptr [" + r64(ctx_) +
                     " + " + r64(t_[7]) + "*8 + 0x10]\n";  // T1 = src (alias_read)
                o += std::string("    mov ") + r64(t_[6]) + ", " + r64(t_[1]) +
                     "\n";  // T6 = src (save, pitfall #37)
                o += std::string("    tzcnt ") + rs(t_[1], 2) + ", " + rs(t_[6], 2) +
                     "\n";  // T1 = tzcnt(T6), 32-bit 路径, 上 32 位自动 0
                o += std::string("    mov qword ptr [") + r64(ctx_) + " + " +
                     r64(t_[4]) + "*8 + 0x10], " + r64(t_[1]) + "\n";  // qword 写回
            } else {
                // S8/S16: defensive no-op (lifter 不产此 size tzcnt)
            }
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude() + size_chain(blocks, tag) + tail_lbl + ":\n" +
               advance(dispatch);
    }

    // MIT-334 Xchg: dst ↔ src, 2 操作数 (reg_a=dst, reg_b=src). xchg 是对称
    // 操作 (Intel SDM: xchg a, b == xchg b, a), 但 IR.dst/src 顺序编码 (语义等价).
    // a_kind=Reg, reg_a=dst, b_kind=Reg, reg_b=src, aux=0, cond_or_size=size (S32/S64).
    //
    // size 链 4 路:
    //   - s=3 (S64): t0=t1=t_[0]/t_[1] qword 读两槽, native `xchg t0, t1` swap
    //                full 64 位, qword 写回两槽
    //   - s=2 (S32): dword 读两槽 (32 位寄存器读自动 zero-extend 上 32 位),
    //                native `xchg eax, ebx` swap 低 32 位 (上 32 位 rax/rbx 保留),
    //                dword 写回两槽 (上 32 位 slot 保留, 保留 slot 高位语义)
    //   - s=0/1 (S8/S16): xchg 无 8/16-bit 形式 (Intel SDM Vol. 2 XCHG 仅 16/32/64-bit);
    //                     lifter 不产 S8/S16 xchg, 此处 defensive no-op
    //
    // xchg 不影响 flags (CF/OF/SF/ZF/PF 不变). handler 不调用 setcc5 也不
    // 走 flags_tail, 直接 advance(dispatch).
    std::string build_xchg(u64 dispatch) const {
        const std::string tag = "xchg" + std::to_string(seq());
        const std::string tail_lbl = "atail_" + tag;
        std::array<std::string, 4> blocks;
        for (int s = 0; s < 4; ++s) {
            std::string o;
            if (s == 3) {
                // S64: qword 读两槽 + native xchg swap full 64 + qword 写回
                o += std::string("    mov ") + r64(t_[0]) + ", qword ptr [" + r64(ctx_) +
                     " + " + r64(t_[4]) + "*8 + 0x10]\n";
                o += std::string("    mov ") + r64(t_[1]) + ", qword ptr [" + r64(ctx_) +
                     " + " + r64(t_[7]) + "*8 + 0x10]\n";
                o += std::string("    xchg ") + r64(t_[0]) + ", " + r64(t_[1]) + "\n";
                o += std::string("    mov qword ptr [") + r64(ctx_) + " + " +
                     r64(t_[4]) + "*8 + 0x10], " + r64(t_[0]) + "\n";
                o += std::string("    mov qword ptr [") + r64(ctx_) + " + " +
                     r64(t_[7]) + "*8 + 0x10], " + r64(t_[1]) + "\n";
            } else if (s == 2) {
                // S32: dword 读两槽 (上 32 位 rax/rbx 自动 0) + native xchg swap
                // 低 32 位 (上 32 位 rax/rbx 保留 = 0, 但只写 dword 故 slot 上
                // 32 位保留) + dword 写回两槽 (slot 上 32 位保留)
                o += std::string("    mov ") + rs(t_[0], 2) + ", dword ptr [" + r64(ctx_) +
                     " + " + r64(t_[4]) + "*8 + 0x10]\n";
                o += std::string("    mov ") + rs(t_[1], 2) + ", dword ptr [" + r64(ctx_) +
                     " + " + r64(t_[7]) + "*8 + 0x10]\n";
                o += std::string("    xchg ") + rs(t_[0], 2) + ", " + rs(t_[1], 2) + "\n";
                o += std::string("    mov dword ptr [") + r64(ctx_) + " + " +
                     r64(t_[4]) + "*8 + 0x10], " + rs(t_[0], 2) + "\n";
                o += std::string("    mov dword ptr [") + r64(ctx_) + " + " +
                     r64(t_[7]) + "*8 + 0x10], " + rs(t_[1], 2) + "\n";
            } else {
                // S8/S16: defensive no-op (lifter 不产此 size xchg)
            }
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude() + size_chain(blocks, tag) + tail_lbl + ":\n" +
               advance(dispatch);
    }

    // MIT-336 Setcc: dst = (cond(flags) ? 1 : 0), 单操作数 (dst only, no src).
    // a_kind=Reg reg_a=dst, b_kind=None, aux=0, cond_or_size=ir::Cond (0..15).
    //
    // 设计：
    //   - MEM 形式 (setcc [m]) 由翻译器折成 Load+Setcc+Store 三条拆条；
    //     本 handler 只接 REG-REG 路径 (a_kind=Reg)。
    //   - setcc 不影响 flags (CF/OF/SF/ZF/PF 不变)；reads flags 决定结果 0/1。
    //   - size 恒为 S8 (r/m8, 1 字节固定), 但 alias_write 必须保留 dst 高 56 位——
    //     handler 读 full qword 到 T9, 评估 cond 到 T0 (0/1), 清 T9 低字节,
    //     OR with T0, qword 写回。
    //   - cond 来自 cond_or_size (T2, 4 位 0..15), 16 variants 共用 cond_eval。
    //   - 16-way 链式分派 (仿 build_jcc): 每个 ccXX 块 emit cond_eval(XX),
    //     末尾统一 tail 做 combine + writeback + advance(dispatch)。
    std::string build_setcc(u64 dispatch) const {
        const std::string tag = "setcc" + std::to_string(seq());
        const std::string tail_lbl = "tail_" + tag;
        std::string o = decode_prelude();  // T2=cond(0..15), T4=reg_a
        // 1) 读 dst full qword 到 T9 (preserve 高 56 位; alias_write 前提)。
        o += std::string("    mov ") + r64(t_[9]) + ", qword ptr [" + r64(ctx_) +
             " + " + r64(t_[4]) + "*8 + 0x10]\n";
        // 2) 16-way 链式分派：每 cond 评估 cond_eval 到 T0 (= 0 或 1)。
        for (int i = 0; i < 15; ++i) {
            const int c = cond_perm_[i];
            o += std::string("    cmp ") + r64(t_[2]) + ", " + imm(c) + "\n";
            o += "    je cc" + std::to_string(c) + "_" + tag + "\n";
        }
        o += "cc" + std::to_string(cond_perm_[15]) + "_" + tag + ":\n" +
               cond_eval(cond_perm_[15]) + "    jmp " + tail_lbl + "\n";
        for (int i = 0; i < 15; ++i) {
            const int c = cond_perm_[i];
            o += "cc" + std::to_string(c) + "_" + tag + ":\n";
            o += cond_eval(c);
            o += "    jmp " + tail_lbl + "\n";
        }
        // 3) tail: 清 T9 低字节, OR with T0 (= cond 结果 0/1), qword 写回。
        o += tail_lbl + ":\n";
        // 0xFFFFFFFFFFFFFF00 清低 8 位; imm 必须 0x 前缀避免 keystone 按 16 进制
        // 解析 (pitfall #1 keystone Intel 裸数字按 16 进制解析)。
        o += std::string("    and ") + r64(t_[9]) + ", 0xFFFFFFFFFFFFFF00\n";
        o += std::string("    or ") + r64(t_[9]) + ", " + r64(t_[0]) + "\n";
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + " + r64(t_[4]) +
             "*8 + 0x10], " + r64(t_[9]) + "\n";
        o += advance(dispatch);
        return o;
    }

    // Adc: dst = dst + src + CF_in（Intel SDM Vol. 2 ADC）。
    // 与 Add/Sub 不可共用 build_binary：zero5() 用 xor 清 scratch 寄存器，
    // 副作用把宿主 CPU 的 CF 也清零（XOR 写 CF=0），后续 native adc 看到的
    // CF_in=0 退化成 add。
    // 故这里不复用 build_binary, 按下列顺序显式保 CF_in：
    //   load A → T0      (mov/movzx 不改 flags)
    //   load B → T1      (mov/movzx 不改 flags)
    //   zero5            (清 flag scratch, 副作用宿主 CF←0)
    //   bt  flags_, 1    (宿主 CF = flags_ bit 1 = CF_in; flags_ 不在 zero5 范围)
    //   adc  T0, T1      (CPU 完成 A+B+CF_in, flags 由 setcc5 捕真值)
    //   setcc5
    //   writeback
    // flags 语义：CF=全加最高位 carryout; OF=两操作数同号且结果异号; SF/ZF/PF 按结果。
    // size 0/1/2/3 由 rs(t_[0], s) 选 al/ax/eax/rax, adc native 按宽度处理。
    // 注意：早期版本把 CF_in 先存到 T3, 再 zero5 把它清零, 退化成 add。
    // bt flags_, 1 路径绕开 zero5 的清零范围（zero5 仅清 {T3,T4,T6,T7,T9}）。
    std::string build_adc(u64 dispatch) const {
        const std::string tag = "adc" + std::to_string(seq());
        const std::string tail_lbl = "ftail_" + tag;
        std::array<std::string, 4> blocks;
        for (int s = 0; s < 4; ++s) {
            const std::string stag = tag + "_" + std::to_string(s);
            std::string o;
            o += load_operand(s, 3, 4, 0, "a" + stag);   // A（目的）→ T0
            o += load_operand(s, 6, 7, 1, "b" + stag);   // B（源）→ T1
            o += zero5();     // 清 flag scratch；副作用宿主 CF←0
            o += std::string("    bt ") + r64(flags_) + ", 1\n";  // 宿主 CF = flags_ bit 1 = CF_in
            o += std::string("    adc ") + rs(t_[0], s) + ", " + rs(t_[1], s) + "\n";
            o += setcc5();
            o += reextract_a(1);
            o += writeback(s, 1);
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude() + size_chain(blocks, tag) + tail_lbl + ":\n" +
               flags_tail(dispatch, false);
    }

    // Sbb: dst = dst - src - CF_in（Intel SDM Vol. 2 SBB）。
    // 与 Adc 结构对称：同样不能复用 build_binary（zero5 把宿主 CF 清零），
    // 同样必须显式保 CF_in：
    //   load A → T0      (mov/movzx 不改 flags)
    //   load B → T1      (mov/movzx 不改 flags)
    //   zero5            (清 flag scratch, 副作用宿主 CF←0)
    //   bt  flags_, 1    (宿主 CF = flags_ bit 1 = CF_in; flags_ 不在 zero5 范围)
    //   sbb  T0, T1      (CPU 完成 A-B-CF_in, flags 由 setcc5 捕真值)
    //   setcc5
    //   writeback
    // flags 语义（与 Adc 的不对称点）：
    //   CF  = 借位 (CF=1 表示 borrow 发生, 与 add 的 carry 含义相反——CF=1 表下溢)。
    //         x86 sbb native CF_out 直接对应 Intel SDM: 1 iff (A < B + CF_in)。
    //   OF  = 仅当两操作数符号**异**且结果符号与 dst 符号**异** (signed underflow
    //         顶端；与 Adc 的"两操作数同号"形成 XOR 对称——加法/减法的 OF 判别
    //         条件互补)。
    //   SF/ZF/PF 按结果。setcc5 抽取的是 native CF/OF/SF/ZF/PF 直读, 不做语义
    //   变换——x86 native 与 Intel SDM 描述直接对齐, 寄存器布局 (bit1=CF,
    //   bit2=OF, bit3=SF, bit0=ZF, bit4=PF) 与 setcc5 完全一致。
    // size 0/1/2/3 由 rs(t_[0], s) 选 al/ax/eax/rax, sbb native 按宽度处理。
    // 关键 catch：build_binary("sub") 用 zero5 把宿主 CF 清零, 不会保留 CF_in；
    // bt flags_, 1 路径绕开 zero5 的清零范围（同 Adc, zero5 仅清 {T3,T4,T6,T7,T9}）。
    std::string build_sbb(u64 dispatch) const {
        const std::string tag = "sbb" + std::to_string(seq());
        const std::string tail_lbl = "ftail_" + tag;
        std::array<std::string, 4> blocks;
        for (int s = 0; s < 4; ++s) {
            const std::string stag = tag + "_" + std::to_string(s);
            std::string o;
            o += load_operand(s, 3, 4, 0, "a" + stag);   // A（被减数）→ T0
            o += load_operand(s, 6, 7, 1, "b" + stag);   // B（减数）→ T1
            o += zero5();     // 清 flag scratch；副作用宿主 CF←0
            o += std::string("    bt ") + r64(flags_) + ", 1\n";  // 宿主 CF = flags_ bit 1 = CF_in
            o += std::string("    sbb ") + rs(t_[0], s) + ", " + rs(t_[1], s) + "\n";
            o += setcc5();
            o += reextract_a(1);
            o += writeback(s, 1);
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude() + size_chain(blocks, tag) + tail_lbl + ":\n" +
               flags_tail(dispatch, false);
    }

    // MIT-302 Imul 2-op reg 形式 (0F AF /r)：dst = dst * src。
    // 不能直接复用 build_binary("imul", ...) —— 8-bit imul 无 2-op 形式
    // (Intel SDM: IMUL 仅 r16/r32/r64 有 2-op, r/m8 仅有 1-op 写 AX)。S8 块
    // 跳过 native imul，只保留 jmp tail 防 keystone 装配失败。lifter 已拒 S8
    // imul 2-op（C1 gate 兜底），但 handler 文本仍按 4 路展开, S8 块必须
    // 不带无效指令。
    // flags 语义：与 add/sub 不同——CF/OF 当低半 != 高半时 set, 由 native imul
    // 直接产生; setcc5 直读 host CPU 真值。
    // 3-op imm 形式（dst = src * imm32）在翻译器层拆为 mov_scratch + Imul(dst, scratch)
    // 两条：先 mov scratch, imm（VmOp::Mov w/ aux=imm32），再 Imul(dst, scratch)
    // 复用本 handler 的 2-op 路径——避免 native imul 第 3 操作数必须为汇编期立即数
    // 的硬限制（x86 imul r, r, imm 形式要求 imm 是汇编期常量，运行时不可）。
    std::string build_imul(u64 dispatch) const {
        const std::string tag = "imul" + std::to_string(seq());
        const std::string tail_lbl = "ftail_" + tag;
        std::array<std::string, 4> blocks;
        for (int s = 0; s < 4; ++s) {
            const std::string stag = tag + "_" + std::to_string(s);
            std::string o;
            if (s == 0) {
                // S8：imul 无 2-op 形式，跳过 native insn + flags_tail（仍按规范
                // 走 ftail + flags_tail: load A → 立即 jmp tail → flags_tail 用 zero5
                // 占位保持位布局一致）。实际 S8 imul 2-op 不应到达（C1 gate 兜底），
                // 本路径为防御。
                o += load_operand(s, 3, 4, 0, "a" + stag);
                o += "    jmp " + tail_lbl + "\n";
            } else {
                o += load_operand(s, 3, 4, 0, "a" + stag);
                o += load_operand(s, 6, 7, 1, "b" + stag);
                o += zero5();
                o += std::string("    imul ") + rs(t_[0], s) + ", " + rs(t_[1], s) + "\n";
                o += setcc5();
                o += reextract_a(1);
                o += writeback(s, 1);
                o += "    jmp " + tail_lbl + "\n";
            }
            blocks[s] = o;
        }
        return decode_prelude() + size_chain(blocks, tag) + tail_lbl + ":\n" +
               flags_tail(dispatch, false);
    }

    // MIT-302 Mul 单操作数（F7 /4）：rdx:rax = rax * src（无符号）。
    // a_kind=Reg reg_a=Rdx 槽（仅作 tag）, b_kind=Reg reg_b=src, aux=0。
    // 关键路径：native "mul <sz> reg_b" 隐式用 RAX 作被乘数，结果写物理 RDX:RAX。
    // 但 VM regs[Rax] / regs[Rdx] 才是真状态——必须先把 regs[Rax] 搬到 T1（物理
    // RAX 兼容），mul 后把物理 rax/rdx 重新捕获到 T1/T0，再写回 regs 槽。
    // 与 build_binary 不同：load_operand 读 dst=Reg (Rdx) 没意义——Rdx 是要被
    // 写入的目的，不是被读取的源；native mul 自然产生新 Rdx。所以本 handler
    // 只读 src 槽（reg_b → T0）与 regs[Rax]（→ T1），mul 后**重新捕获** rax/rdx
    // 再用 alias_write 合并写回（因为 T1/T0 仍持有旧值/旧 src, 不重新捕获会写错）。
    // size 链 4 路：native mul al/ax/eax/rax 按宽度处理。
    //   s=0/1：mul 仅修改 ax；rdx 不变（m=0）或上 48 位未定义（m=1）——跳过 Rdx 写回。
    //   s=2/3：mul 修改 edx:eax / rdx:rax；rax 自动零/符号扩展，rdx 同。
    std::string build_mul(u64 dispatch) const {
        const std::string tag = "mul" + std::to_string(seq());
        const std::string tail_lbl = "ftail_" + tag;
        const u8 rax_slot = isa::vm_reg_of(ir::Reg::Rax);
        const u8 rdx_slot = isa::vm_reg_of(ir::Reg::Rdx);
        std::array<std::string, 4> blocks;
        for (int s = 0; s < 4; ++s) {
            const std::string stag = tag + "_" + std::to_string(s);
            std::string o;
            // src → T0（按宽度读 src 寄存器槽；size=0/1 用 movzx, 2/3 用 mov）
            if (s == 3)
                o += std::string("    mov ") + r64(t_[0]) + ", qword ptr [" + r64(ctx_) +
                     " + " + r64(t_[7]) + "*8 + 0x10]\n";
            else if (s == 2)
                o += std::string("    mov ") + rs(t_[0], 2) + ", dword ptr [" + r64(ctx_) +
                     " + " + r64(t_[7]) + "*8 + 0x10]\n";
            else
                o += std::string("    movzx ") + r64(t_[0]) + ", " + mptr(s) + " [" +
                     r64(ctx_) + " + " + r64(t_[7]) + "*8 + 0x10]\n";
            // Rax（隐式被乘数）→ T1（按宽度读 Rax 槽）。
            // **注意**: 用 std::to_string(rax_slot) 输出字面量槽号（0），
            // 不能用 r64(rax_slot) — 那是 kPhys[0]="rax" 物理寄存器名。
            if (s == 3)
                o += std::string("    mov ") + r64(t_[1]) + ", qword ptr [" + r64(ctx_) +
                     " + " + std::to_string(rax_slot) + "*8 + 0x10]\n";
            else if (s == 2)
                o += std::string("    mov ") + rs(t_[1], 2) + ", dword ptr [" + r64(ctx_) +
                     " + " + std::to_string(rax_slot) + "*8 + 0x10]\n";
            else
                o += std::string("    movzx ") + r64(t_[1]) + ", " + mptr(s) + " [" +
                     r64(ctx_) + " + " + std::to_string(rax_slot) + "*8 + 0x10]\n";
            o += zero5();
            // [关键 catch] native mul <sz> T0 用物理 RAX 作隐式被乘数, 但
            // decode_prelude 已把 T4 (rax 物理寄存器) 写成 reg_a 解码值,
            // 不能直接用。须先把 T1 (= Rax 槽内容) 搬到 RAX 再 mul:
            //   mov rax, rbp   ; 物理 rax = Rax 槽值
            //   mul rbx         ; rdx:rax = rax * rbx
            if (s == 3)
                o += std::string("    mov rax, ") + r64(t_[1]) + "\n";
            else if (s == 2)
                o += std::string("    mov eax, ") + rs(t_[1], 2) + "\n";
            else if (s == 1)
                o += std::string("    mov ax, ") + rs(t_[1], 1) + "\n";
            else
                o += std::string("    mov al, ") + rs(t_[1], 0) + "\n";
            // native mul <sz> T0 (rdx:rax = rax * T0；ax/ax 仅低 m 位有意义, 上位未定义)
            o += std::string("    mul ") + rs(t_[0], s) + "\n";
            // [关键 catch 2]**立即**将物理 rax/rdx 写回 regs 槽——必须在 setcc5 之前。
            {
                // 用 imm(slot*8) 拼 rax_offset = regs[Rax] 绝对地址 (slot=0 → 0x10):
                const std::string rax_slot_off = imm(static_cast<u64>(rax_slot) * 8 + 0x10);
                const std::string rax_slot_qp = "qword ptr [" + std::string(r64(ctx_)) + " + " + rax_slot_off + "]";
                if (s == 3) {
                    o += std::string("    mov ") + rax_slot_qp + ", rax\n";
                } else {
                    o += std::string("    mov ") + r64(t_[1]) + ", " + rax_slot_qp + "\n";
                    o += std::string("    mov ") + rs(t_[1], s) + ", " + rs(0, s) + "\n";
                    o += std::string("    mov ") + rax_slot_qp + ", " + r64(t_[1]) + "\n";
                }
            }
            if (s >= 2) {
                const std::string rdx_slot_off = imm(static_cast<u64>(rdx_slot) * 8 + 0x10);
                const std::string rdx_slot_qp = "qword ptr [" + std::string(r64(ctx_)) + " + " + rdx_slot_off + "]";
                if (s == 3) {
                    o += std::string("    mov ") + rdx_slot_qp + ", rdx\n";
                } else {
                    o += std::string("    mov ") + r64(t_[1]) + ", " + rdx_slot_qp + "\n";
                    o += std::string("    mov ") + rs(t_[1], s) + ", " + rs(1, s) + "\n";
                    o += std::string("    mov ") + rdx_slot_qp + ", " + r64(t_[1]) + "\n";
                }
            }
            o += setcc5();
            // [写回已在 mul 后立即完成, 此处不再写]
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude() + size_chain(blocks, tag) + tail_lbl + ":\n" +
               flags_tail(dispatch, false);
    }

private:
    Rng& rng_;
    int ctx_ = 0, pc_ = 0, flags_ = 0, base_ = 0;
    int t_[10] = {};
    std::array<int, 4> size_perm_{};
    std::array<int, 16> cond_perm_{};
    mutable int seq_ = 0;
};

struct HandlerDef {
    int opcode;
    const char* name;
    std::string (AsmGen::*build)(u64) const;
};

} // namespace

RuntimeGenResult generate_runtime(wvmp::Rng& rng) {
    using isa::VmOp;
    AsmGen g(rng);
    g.roll();
    KsSession ks;

    // —— 入口块（地址 0；跌入 dispatch，无跨块引用）——
    const std::string entry_text = g.build_entry();
    const std::vector<u8> entry_code = ks.assemble(entry_text, 0, "entry");
    const u64 dispatch_addr = entry_code.size();

    // —— dispatch 第 1 遍（哑表偏移，强制 disp32 编码）——
    constexpr u64 kDummyTableOff = 0x4000'0000ull;
    const std::vector<u8> dispatch1 =
        ks.assemble(g.build_dispatch(kDummyTableOff), dispatch_addr, "dispatch pass1");
    const u64 dispatch_size = dispatch1.size();

    // —— handler 清单（v1 覆盖集；Call/Ret 的表项指向
    //    Halt——遇到即停机，语义保守且不越界。Sar 在 MIT-244 已接管。
    //    Adc 在 MIT-245 已接管；Sbb 在 MIT-246 已接管；Rol/Ror 在 MIT-247 已接管。
    //    CallGate 在 MIT-249 已接管。）——
    std::vector<HandlerDef> handlers = {
        {int(VmOp::Mov), "mov", &AsmGen::build_mov},
        {int(VmOp::Lea), "lea", &AsmGen::build_mov},
        {int(VmOp::Add), "add", &AsmGen::build_add},
        {int(VmOp::Sub), "sub", &AsmGen::build_sub},
        {int(VmOp::And), "and", &AsmGen::build_and},
        {int(VmOp::Or), "or", &AsmGen::build_or},
        {int(VmOp::Xor), "xor", &AsmGen::build_xor},
        {int(VmOp::Not), "not", &AsmGen::build_not},
        {int(VmOp::Neg), "neg", &AsmGen::build_neg},
        {int(VmOp::Inc), "inc", &AsmGen::build_inc},
        {int(VmOp::Dec), "dec", &AsmGen::build_dec},
        {int(VmOp::Shl), "shl", &AsmGen::build_shl},
        {int(VmOp::Shr), "shr", &AsmGen::build_shr},
        {int(VmOp::Sar), "sar", &AsmGen::build_sar},
        {int(VmOp::Rol), "rol", &AsmGen::build_rol},
        {int(VmOp::Ror), "ror", &AsmGen::build_ror},
        // MIT-301 cl 变体 shift（D3 /5, 计数源自 RCX 低 8 位）。
        {int(VmOp::ShlCl), "shlcl", &AsmGen::build_shl_cl},
        {int(VmOp::ShrCl), "shrcl", &AsmGen::build_shr_cl},
        {int(VmOp::SarCl), "sarcl", &AsmGen::build_sar_cl},
        {int(VmOp::RolCl), "rolcl", &AsmGen::build_rol_cl},
        {int(VmOp::RorCl), "rorcl", &AsmGen::build_ror_cl},
        {int(VmOp::Adc), "adc", &AsmGen::build_adc},
        {int(VmOp::Sbb), "sbb", &AsmGen::build_sbb},
        {int(VmOp::Imul), "imul", &AsmGen::build_imul},
        {int(VmOp::Mul), "mul", &AsmGen::build_mul},
        {int(VmOp::Movsxd), "movsxd", &AsmGen::build_movsxd},
        {int(VmOp::MovsxdMem), "movsxdmem", &AsmGen::build_movsxd_mem},
        {int(VmOp::Movzx), "movzx", &AsmGen::build_movzx},
        {int(VmOp::MovzxMem), "movzxmem", &AsmGen::build_movzx_mem},
        {int(VmOp::Bswap), "bswap", &AsmGen::build_bswap},
        {int(VmOp::Xchg), "xchg", &AsmGen::build_xchg},
        {int(VmOp::Setcc), "setcc", &AsmGen::build_setcc},
        {int(VmOp::Cmovcc), "cmovcc", &AsmGen::build_cmovcc},
        {int(VmOp::Cmpxchg), "cmpxchg", &AsmGen::build_cmpxchg},
        {int(VmOp::Movsx), "movsx", &AsmGen::build_movsx},
        {int(VmOp::MovsxMem), "movsxmem", &AsmGen::build_movsx_mem},
        {int(VmOp::Popcnt), "popcnt", &AsmGen::build_popcnt},
        // MIT-353: lzcnt + tzcnt (BMI1 bit-scan, 沿用 popcnt 模板 + T6 save pitfall #37).
        {int(VmOp::Lzcount), "lzcnt", &AsmGen::build_lzcnt},
        {int(VmOp::Tzcount), "tzcnt", &AsmGen::build_tzcnt},
        // MIT-371: SSE 浮点加 addss/addps/addpd (3 形式, REG-REG only, 沿用
        // popcnt/lzcnt/tzcnt 模板 + 硬编码 xmm0/xmm1 物理寄存器; 无需
        // MASM helper 强制 codegen — MSVC /Od SSE 浮点编译直接 emit 真字节).
        {int(VmOp::Addss), "addss", &AsmGen::build_addss},
        {int(VmOp::Addps), "addps", &AsmGen::build_addps},
        {int(VmOp::Addpd), "addpd", &AsmGen::build_addpd},
        // MIT-373: SSE 浮点减 subss/subps/subpd (3 形式, REG-REG only, 沿用
        // MIT-371 addss/addps/addpd 模板 + 硬编码 xmm0/xmm1 物理寄存器; 复用
        // VmContext.xmm[8] 跟踪区, 无需 MASM helper 强制 codegen).
        {int(VmOp::Subss), "subss", &AsmGen::build_subss},
        {int(VmOp::Subps), "subps", &AsmGen::build_subps},
        {int(VmOp::Subpd), "subpd", &AsmGen::build_subpd},
        {int(VmOp::Cmp), "cmp", &AsmGen::build_cmp},
        {int(VmOp::Test), "test", &AsmGen::build_test},
        {int(VmOp::Load), "load", &AsmGen::build_load},
        {int(VmOp::Store), "store", &AsmGen::build_store},
        {int(VmOp::LoadRva), "loadrva", &AsmGen::build_loadrva},
        {int(VmOp::StoreRva), "storeriva", &AsmGen::build_storerva},
        {int(VmOp::LeaRva), "learva", &AsmGen::build_lea_rva},
        {int(VmOp::Push), "push", &AsmGen::build_push},
        {int(VmOp::Pop), "pop", &AsmGen::build_pop},
        {int(VmOp::Jmp), "jmp", &AsmGen::build_jmp},
        {int(VmOp::Jcc), "jcc", &AsmGen::build_jcc},
        {int(VmOp::Nop), "nop", &AsmGen::build_nop},
        {int(VmOp::Halt), "halt", &AsmGen::build_halt},
        {int(VmOp::GetFlags), "getflags", &AsmGen::build_getflags},
        {int(VmOp::SetFlags), "setflags", &AsmGen::build_setflags},
        {int(VmOp::CallGate), "callgate", &AsmGen::build_callgate},
    };
    rng.shuffle(handlers.begin(), handlers.end());   // 码序随机

    // —— 逐 handler 以真实运行地址独立汇编（内部标签互不冲突）——
    std::vector<u8> handler_code;
    std::map<int, u64> handler_off;
    std::map<int, std::string> handler_text;   // dump 复用（标签序号勿再递增）
    u64 cursor = dispatch_addr + dispatch_size;
    for (const auto& h : handlers) {
        std::string text = (g.*h.build)(dispatch_addr);
        const std::vector<u8> code = ks.assemble(text, cursor, h.name);
        handler_off[h.opcode] = cursor;
        handler_text[h.opcode] = std::move(text);
        handler_code.insert(handler_code.end(), code.begin(), code.end());
        cursor += code.size();
    }

    // —— 跳转表（码尾，8 对齐垫片 0x90）——
    const u64 table_off = (cursor + 7) & ~u64(7);
    handler_code.insert(handler_code.end(), size_t(table_off - cursor), 0x90);

    // —— dispatch 第 2 遍：真实表偏移；disp32 定宽 → 尺寸必须与第 1 遍一致 ——
    const std::string dispatch_text = g.build_dispatch(table_off);
    const std::vector<u8> dispatch2 =
        ks.assemble(dispatch_text, dispatch_addr, "dispatch pass2");
    if (dispatch2.size() != dispatch_size)
        throw std::runtime_error("regvm runtime: dispatch pass2 size drifted (two-pass broken)");

    // —— 装配：[entry][dispatch][handlers][pad][table] ——
    vm::RuntimeImage image;
    image.vm_entry_offset = 0;
    image.code.reserve(size_t(table_off) + size_t(kTableEntries * 8));
    image.code.insert(image.code.end(), entry_code.begin(), entry_code.end());
    image.code.insert(image.code.end(), dispatch2.begin(), dispatch2.end());
    image.code.insert(image.code.end(), handler_code.begin(), handler_code.end());
    const u64 halt_off = handler_off.at(int(VmOp::Halt));
    auto push_u64 = [&image](u64 v) {
        for (int b = 0; b < 8; ++b) image.code.push_back(u8((v >> (8 * b)) & 0xFF));
    };
    for (u64 op = 0; op < kTableEntries; ++op)
        push_u64(handler_off.count(int(op)) ? handler_off.at(int(op)) : halt_off);

    // —— asm_dump（带布局注释的最终汇编文本）——
    std::string dump;
    dump += "; regvm runtime image: entry=+0x0, dispatch=+" + hex(dispatch_addr) +
            ", table=+" + hex(table_off) + ", total=" + hex(image.code.size()) + "\n";
    dump += "; codec: none (v1 直通；M3 织入点 = dispatch fetch 之后、跳表之前，对 T8 解密)\n";
    dump += entry_text + "\n";
    dump += "dispatch:\n" + dispatch_text + "\n";
    for (const auto& h : handlers)
        dump += "; ---- handler " + std::string(h.name) + " @ +" + hex(handler_off.at(h.opcode)) +
                " ----\n" + handler_text.at(h.opcode) + "\n";
    dump += "; ---- jump table @ +" + hex(table_off) +
            " (64 x u64 LE, 项 = handler 相对码基址偏移；0/未实现 → halt) ----\n";
    for (u64 op = 0; op < kTableEntries; ++op)
        if (handler_off.count(int(op)))
            dump += ";   [" + std::to_string(op) + "] = " + hex(handler_off.at(int(op))) + "\n";
    dump += ";   [0] (illegal/未实现折叠) = " + hex(halt_off) + "\n";

    // 调试钩子（排查用）：WVMP_RUNTIME_DUMP=<win 路径> 时把 asm_dump 落盘，
    // 方便直接读 .wvmp 节汇编（含 callgate handler）。不影响产物字节。
    {
        char* dp = nullptr;
        size_t dp_len = 0;
        if (_dupenv_s(&dp, &dp_len, "WVMP_RUNTIME_DUMP") == 0 && dp && dp_len > 1) {
            FILE* f = nullptr;
            if (fopen_s(&f, dp, "wb") == 0 && f) {
                std::fwrite(dump.data(), 1, dump.size(), f);
                std::fclose(f);
            }
        }
        std::free(dp);
    }

    return {std::move(image), std::move(dump)};
}

} // namespace wvmp::regvm::runtime
