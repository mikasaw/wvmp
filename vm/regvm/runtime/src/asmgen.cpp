// P6：regvm 运行时生成器。
//
// 保护期用 Keystone（KS_ARCH_X86 + KS_MODE_64，Intel 语法）汇编出一段
// **位置无关**的 x64 解释器机器码，可在 RWX 内存中执行 regvm 字节码。
//
// ============================== 机器码布局 ==============================
//
//   [entry][dispatch][handler..（码序随机）][0x90 垫片至 8 对齐][跳转表 128xu64]
//    ^入口    ^取指/跳表   ^各自独立 ks_asm          ^表项=handler 相对码基址偏移
//   [cond 表 16xu64]（MIT-494s：jcc 私有 cc 块跳表，紧随跳转表之后；表项同构）
//
//   - 入口在 code 偏移 0：`lea BASE,[rip-7]` 取得码基址（位置无关），
//     保存 Win64 callee-saved（rbx/rbp/rdi/rsi/r12-r15 共 8 个），RCX 的
//     VmContext* 存入随机指派的 CTX 寄存器，初始化后跌入 dispatch 循环；
//   - dispatch：fetch `T8=[BYTE+PC*8]` → `and T0,kTableEntries-1`（=0x7F，
//     MIT-374 起 7 位）→
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
//     一致（生成后断言校验），最后把 kTableEntries 个 u64 表项原样追加进码尾。
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
//
// ============================ x86 (KS_MODE_32) 双模 =====================
//
//   MIT-443 (X3a)：asmgen 双模化。AsmGen::HostArch 分叉点收敛为四处 ——
//   KsSession 汇编模式、roll() 分配器、build_entry/build_dispatch 文本、
//   handler 表选择；x64 路径在分叉点后逐字保留（D6：x64 输出按同 seed
//   dump 逐字节恒等，48 单史 sha 纪律）。x86 面设计（X3b 起 57 handler，
//   真可跑 = x64 表 96 唯一 VmOp 补集的整数面 + GP/RVA 面）：
//
//   - 池 = kPhys[0..5]（eax/edx/ebx/ebp/esi/edi）6 个：esp 恒不在 kPhys、
//     ecx 保留（cl 移位计数 + rep 串）、kPhys[6..13]（r8-r15）32 位模式无
//     REX 不可编码。ctx_/base_ 各占 callee-saved {ebx,ebp,esi,edi} 之一
//     （随机，callgate 未来的 callee-saved 约束预保留）；pc_/flags_ 内存
//     常驻既有 ctx 槽（+0x8/+0x98，零新字段 —— D4 kCtxSize 冻结不破）；
//     临时 4 个，其中数据临时 t_[0]/t_[1] 字节可编码约束（al/dl/bl 可用，
//     bpl/sil/dil 是 REX 专属名 32 位不可编码）。
//   - 执行帧 = entry `sub esp,0x24` 常量槽（decode 位域/aux/setcc 捕获区），
//     esp 跨指令稳定（x86 handler 无动态 push/pop）；setcc 直写槽全字节 +
//     movzx 全字节读取 ⇒ zero5 x86 形 = 空。
//   - entry BASE 取址 = call/pop idiom（D2 拍板）；dispatch 跳表保 8B 表项
//     （D3 拍板：读表项低 dword，表字节格式与 x64 逐位一致）。
//   - 保存区裁决（B.4）：维持 442 规则 "guest 栈写恒 ≥ ns"，不重排 —— x86
//     epilogue 与 x64 同构（4 callee-saved push/pop + ret），保存区冲突形
//     同构（x86 侧 [ns-4..ns-0x10] 更小），重排必牵 stub_gen = X4 范围且
//     lifter 保守 gate 已兜底反例形。
//   - size 链 3 路（S8/S16/S32；S64 块防御 no-op —— x86 翻译器不产 S64）；
//     写回维持 "slot 高半字恒 0" 不变量（x86 guest 值域 ≤32 位）。
// ========================================================================

#include "wvmp/regvm/runtime/runtime.hpp"
#include "wvmp/regvm/runtime/runtime_x86.hpp"

#include "wvmp/ir/insn.hpp"
#include "wvmp/regvm/isa/vm_op.hpp"
#include "wvmp/regvm/isa/vm_reg.hpp"

#include <keystone/keystone.h>

#include <array>
#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace wvmp::regvm::runtime {
namespace {

// ---------------------------------------------------------------------------
// Keystone 会话（RAII）。Intel 语法、x86-64。
// ---------------------------------------------------------------------------
class KsSession {
public:
    // MIT-443 (X3a)：汇编模式参数化 —— x64 路径默认 KS_MODE_64（行为逐字节
    // 不变）；x86 码体传 KS_MODE_32（Intel 语法 32 位：无 REX/r8-r15 名、
    // dword 主宽、ModRM/短跳转全族按 32 位编码）。
    explicit KsSession(unsigned ks_mode = KS_MODE_64) {
        if (ks_open(KS_ARCH_X86, ks_mode, &ks_) != KS_ERR_OK)
            throw std::runtime_error("regvm runtime: ks_open(KS_ARCH_X86, mode) failed");
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

// ---------------------------------------------------------------------------
// MIT-443 (X3a)：x86 (KS_MODE_32) 可分配池与执行帧。
//
// 池实测 = kPhys[0..5]（eax/edx/ebx/ebp/esi/edi）共 6 个（X0 §3.1 粗算复核）：
//   - esp 恒不在 kPhys（宿主栈）；ecx 保留（cl 移位计数 + rep 串，X0 §3 注）；
//   - kPhys[6..13]（r8..r15）32 位模式无 REX 前缀不可编码；
//   - callee-saved 仅 4（ebx/ebp/esi/edi），ctx_/base_ 各占其一（随机，保留
//     callgate 未来的 callee-saved 约束），剩余 = eax/edx + 2 callee-saved
//     = 4 临时（X0 粗算 2 的实测修正：pc_/flags_ 内存常驻后释放 2 个）。
// pc_/flags_ x86 不占寄存器：内存常驻既有 ctx 槽（+0x8 / +0x98 —— 两个槽本
// 就是持久语义），零新 ctx 字段（D4 kCtxSize/runtime.hpp 冻结不破）。
// 字节档约束：数据临时 t_[0]/t_[1] 强制从 {eax,edx,ebx} 抽取 —— S8 native
// 子寄存器名 al/dl/bl 可编码，bpl/sil/dil 是 REX 专属名、32 位模式不可编码
//（kPhys 四名列对 x86 只有字节档不就位 —— B.1 "rs() 复用度真验" 的答案）。
// spill 纪律 = 固定宿主栈帧（kX86FrameSize）：entry `sub esp,帧` 后 esp 跨指
// 令稳定（x86 handler 无动态 push/pop），decode 位域/aux/setcc 捕获区全落常
// 量槽 [esp+off]；setcc 直写槽全字节 + movzx 全字节读取 ⇒ zero5 x86 形 = 空。
// ---------------------------------------------------------------------------
constexpr int kX86PoolSize = 6;
constexpr int kX86CalleeSaved[4] = {2, 3, 4, 5};  // ebx/ebp/esi/edi（x86 ABI callee-saved）
constexpr int kX86ByteCapable[3] = {0, 1, 2};     // eax/edx/ebx（8 位名可编码）

// x86 执行帧槽布局（[esp+off]，dword 槽；kX86FCC 区为 5 个独立字节）。
constexpr u64 kX86FInsnLo = 0x00;    // 指令字低 32 位（域 0..31）
constexpr u64 kX86FAux    = 0x04;    // 指令字高 32 位 = aux（dispatch 落帧，无需抽取）
constexpr u64 kX86FRegA   = 0x08;    // reg_a（5 位）
constexpr u64 kX86FRegB   = 0x0C;    // reg_b（5 位）
constexpr u64 kX86FSize   = 0x10;    // cond_or_size（4 位；x86 无 S64 VmOp）
constexpr u64 kX86FAKind  = 0x14;    // a_kind（2 位）
constexpr u64 kX86FBKind  = 0x18;    // b_kind（2 位）
constexpr u64 kX86FCC     = 0x1C;    // setcc 捕获区：ZF/CF/OF/SF/PF @ +0..+4
constexpr u64 kX86FrameSize = 0x24;  // 0x1C+5=0x21 → 4 对齐取 0x24
static_assert(kX86FCC + 5 <= kX86FrameSize, "x86 setcc capture area must fit the frame");

// MIT-445 (X3c B.1)：x86 callgate callee 专用窗口（406 x64 同款纪律：16
// 对齐窗口 + 底部探针写）。窗口锚 = host_rsp（[ctx+0x128]，entry 落账，
// 自洽无需 native_sp 预置）；call 站位 = 对齐后窗口顶。
constexpr u64 kX86CallgateWindow = 0x1000;  // 4KB callee 窗口
static_assert(kX86CallgateWindow % 16 == 0,
              "x86 callee window must be 16-aligned to keep the call-site rsp residue unchanged");

// MIT-446 (X4) B.1：x86 callgate cdecl 参数窗宽度（dword 计数）。
// 协议（build_callgate_x86 与 stub_gen 两处同步锚④的落地形态）：
//   guest 侧 = 区域代码把 cdecl 栈参数写在 [v4 + 4*i]（i=0..N-1，v4 = guest
//   esp = ctx rsp 槽）——即原生 `push` 反序后的内存形，且全部落在
//   "guest 栈写恒 ≥ ns" 规则的安全区（v4 起、向上）。真实样本按此约定手编
//   （prologue 预留 esp 上方 scratch：`mov [esp+k], arg; call f`）。
//   handler 侧 = call 前从 [v4 + 4*i] 固定预置 kX86CallgateArgDwords 个
//   dword 到 callee 窗口（i 逆序 push → arg0 落最低），cdecl caller-cleans
//   语义下多预置无害：0-arg callee 不读参数、esp 由 host_rsp 重基统一回收。
//   固定宽 = 翻译层无需 arg_count 通路（cond_or_size 维持 0），零协议新面。
// MIT-451 (X5b) B.2：窗宽 4→8（X5 B.4 留 X5b 备选，随 guard 垫栈一并行使）。
// guard 使真实 /Od 的 push 形参数（push arg; call f，参数落 [v4..] = guard
// 区）行为安全后，4 dword 窗成为 5+ 参调用的确定性丢参点（X5 B.4 实测
// arg4 丢失）。8 dword = 32B 覆盖实测形态 + 余量；多预置 cdecl 无害语义
// 不变；**> 8 dword 仍超窗静默丢参**（宁窄勿宽边界，如实披露——arg_count
// 静态通路仍为零新面，超窗形态归 translator 后续单裁决）。
constexpr u64 kX86CallgateArgDwords = 8;
static_assert(kX86CallgateArgDwords * 4 <= kX86CallgateWindow,
              "x86 callgate fixed argument window must fit the callee window");

// MIT-445 (X3c B.2)：x86 4B 退出槽深度 —— MIT-446 (X4) 起定义上移
// runtime_x86.hpp（stub_gen 读侧跨 TU 消费的单一来源）；本文件保留
// static_assert 防漂移。MIT-451 (X5b) B.2：派生式含 kX86GuardBytes 项
// （guard 垫栈，runtime_x86.hpp 注）。
static_assert(kX86ExitSlotDepth == kX86GuardBytes + 4 * 4 + kCtxSize + 0x80,
              "kX86ExitSlotDepth derivation drifted from runtime_x86.hpp");

// MIT-445 (X3c B.3)：Ret x86 出口栈坐标（build_ret_x86 专用派生）。
// handler 中段把 v4'（清栈后 guest esp）push 到宿主栈暂存——出口时刻
// callee-saved 已被 pop 恢复为宿主值，ctx 寄存器不可用（x64 以 [rsp-0x1D8]
// 栈坐标读 ctx 区同哲学；x86 的 ctx 结构位置不定（电池/未来 stub 布局），
// 故以"push 暂存 + 终态 esp 相对读"表达）：
//   终态 esp 前进量 = kX86FrameSize + 4（弃帧 + 顶出 v4' 暂存槽）
//   v4' 暂存槽相对终态 esp 偏移 = 前进量 + 4 pop（= 0x38，读发生在变更前）
constexpr u64 kX86RetExitFrameAdvance = kX86FrameSize + 4;
constexpr u64 kX86RetV4SlotFromExitRsp = kX86RetExitFrameAdvance + 4 * 4;
static_assert(kX86RetV4SlotFromExitRsp == 0x38, "x86 ret exit rsp coordinates regressed");

// x86 guest rsp 槽偏移（v4 = vm_reg_of(Rsp) = 4 → 4*8+0x10）。8B 槽、值恒 32
// 位零扩展（"槽高半字恒 0" 不变量）⇒ 槽算术走 dword 低半字（4B 步进裁决，
// build_push_x86 注）。
constexpr u64 kX86RspSlotOff = 0x30;
static_assert(kX86RspSlotOff == static_cast<u64>(isa::vm_reg_of(ir::Reg::Rsp)) * 8 + 0x10,
              "x86 rsp slot offset must track vm_reg_of(Rsp)");

// 跳转表：dispatch 用 opcode 低 log2(kTableEntries) 位索引；0/越界折叠到
// Halt=非法停机。
//
// MIT-374 阻断性缺陷（诚实披露，改修复方向）：本表原为 64 项 + `and T0,0x3F`
// （6 位）。VmOp 是 append-only 枚举，MIT-373 合入后 Subpd 已占满最后一个
// 6 位槽位（值 63），Divss/Divps/Divpd = 64/65/66 **越过 6 位跳表空间** →
// `and 0x3F` 把它们掩成 0 → 折叠到 halt handler → Halt 写回 pc+1 且恢复 ctx
// （陷阱 #7 的"恢复友好"语义），于是区域照跑、xmm 槽照恢复、退出码照 0，
// 只是浮点除**整条空转**——与 MIT-371 裸立即数空转同一表象、不同根因。
// 字节码字段的 opcode 本身是 14 位（isa/encoding.cpp kOpMask），不受此限制，
// 需要加宽的只有运行时的跳表与掩码。故 64 → 128（7 位，Divpd 之后还能再放
// 61 个 op，覆盖 MIT-375/376 的 SSE 传送/位运算批次），并加 static_assert
// 把"枚举越界"从**运行时空转**升级为**编译期失败**。
constexpr u64 kTableEntries = 128;
static_assert(isa::kVmOpMax < kTableEntries,
              "VmOp 枚举已越过 dispatch 跳表空间：新 opcode 会被掩码折叠到 halt "
              "并静默空转（MIT-374 根因）。请加宽 kTableEntries（2 的幂）并同步 "
              "build_dispatch 的掩码（自动由 kTableEntries-1 导出）。");

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
// M2-9 callgate 栈回退常量（MIT-B2）——从 kCtxSize 编译期派生，禁止硬编码。
//
// 栈算术（native_sp = 进入 stub 时刻的 rsp；host_rsp = 解释器执行期 rsp）：
//   host_rsp = native_sp - (kCalleeSavedPushBytes + kCtxSize + kCallRetBytes
//              + kCalleeSavedPushBytes)
//     stub: 8 push(callee-saved 全量) + sub rsp,kCtxSize；`call rt_entry`
//     压返回地址；入口块再 8 push（base_ + rest 7，见 build_entry）。
//   callgate step 3 push ctx 槽 = host_rsp - kCtxPushBytes
//   step 4/6 后 rsp = native_sp - kWinShadowBytes
//   step 7 sub 后必须回到 push ctx 槽：
//     kCallgateSpRollback = kCalleeSavedPushBytes + kCtxSize + kCallRetBytes
//                           + kCalleeSavedPushBytes + kCtxPushBytes
//                           - kWinShadowBytes
//     = kCtxSize + 0x68 （kCtxSize=0x1C8 → 0x230；0x140 时代 → 0x1A8 ✓）
//
// MIT-371 把 kCtxSize 0x140→0x1C8 时本处曾硬编码 0x1A8 未跟随：push/pop ctx
// 槽错开 0x88，pop 读到 stub VmContext 帧内宿主 RBP(=0) → ctx_=0 → 下一指令
// 寻址 0xC0000005（MIT-393 四路互证，5 坏样本崩点 .wvmp+0x37C0）。常量改由
// kCtxSize（runtime.hpp，sizeof(VmContext) 派生）自动跟随，同类漂移断根。
// ---------------------------------------------------------------------------
constexpr u64 kCalleeSavedPushBytes = kCalleeSavedIdx.size() * 8;  // 0x40
constexpr u64 kCallRetBytes   = 0x8;   // stub `call rt_entry` 的返回地址
constexpr u64 kCtxPushBytes   = 0x8;   // callgate step 3 push ctx
constexpr u64 kWinShadowBytes = 0x28;  // step 4: 32B shadow + 8B 对齐
constexpr u64 kCallgateSpRollback = kCalleeSavedPushBytes + kCtxSize +
                                    kCallRetBytes + kCalleeSavedPushBytes +
                                    kCtxPushBytes - kWinShadowBytes;
// 回落后 rsp = push ctx 槽：host_rsp - 8。host_rsp ≡ 8 (mod 16)（stub 入口
// rsp ≡ 8，两次 8 push 与 call ret 均不动 16 余数）→ 槽 ≡ 0 (mod 16)，
// 故回退量本身必 ≡ 0 (mod 16)——公式错位在此当场炸编译期。
static_assert(kCallgateSpRollback % 16 == 0,
              "callgate step7 rollback must land on the 16-aligned push-ctx slot");

// ---------------------------------------------------------------------------
// MIT-406 (MIT-E1): callgate callee 专用栈窗口。
//
// 预算推导: 修复前 callee 树从 native_sp-0x28 向下生长, 到 VmContext 顶
// (native_sp-0x208) 只有 0x1D8 预算 (0x208 - 0x28 - 8ret)。wvmpTest sha256
// 调用树 sha256_K→frac_cbrt_prime→wvpow13→pow/floor 实测栈深 ~0x250B, 砸穿
// ctx → VM 状态毁坏 → packed.exe 0xC0000005 (MIT-404 合入暴露, 非引入)。
// 实测最深树 0x250 → 0x1000 ≈ 6.5x 余量 + CRT 深链防御; 单调用树 > 4KB
// 时症状从"砸穿 ctx"变为"砸穿窗口下 guard page"——明确崩溃非静默。
//
// 窗口位置: host_rsp (= native_sp-0x250) 以下当前无任何消费者 (entry 的
// 8 push 在 host_rsp 之上; dispatch 纯跳表无递归; handler 仅 callgate 动
// rsp) —— 干净窗口。step 4 把 rsp 切到 native_sp-kWinShadowBytes-窗口,
// callee 树在窗口内生长, 与 ctx / stub 8 push 保存区零重叠。
// 16 对齐: 窗口是 16 的倍数, 切换前后 call 前 rsp 的 16 余数不变 (Win64
// call 站位语义与 0x28 基线完全一致)。
// ---------------------------------------------------------------------------
constexpr u64 kCallgateCalleeWindow = 0x1000;  // 4KB callee 专用窗口
static_assert(kCallgateCalleeWindow % 16 == 0,
              "callee window must be 16-aligned to keep the call-site rsp residue unchanged");

// step 7 回退量 (MIT-406): 窗口 + 运行时对齐使 call/ret 后 rsp 相对
// native_sp 的偏移含逐 stub 变化的对齐余数 (见 step 4 and 掩码), 常量
// 回退不再可解——改为从 ctx+0x120 (native_sp, stub_gen 一次性写入, 跨
// call 稳定) 重基数再减常量:
//   kPushCtxDepth = native_sp 到 push ctx 槽的距离
//                 = kWinShadowBytes + kCallgateSpRollback (0x28 + 0x230)
//                 = 2*kCalleeSavedPushBytes + kCtxSize + kCallRetBytes
//                   + kCtxPushBytes = 0x258
// 不变量: pop ctx 落在 push ctx 槽 (host_rsp - 8), host_rsp = ns-0x250 恒成立。
constexpr u64 kPushCtxDepth = kWinShadowBytes + kCallgateSpRollback;
// 注意: push ctx 槽 (= ns - kPushCtxDepth) 的 16 余数随 ns 变化 (ns ≡ 8
// mod 16 只是"区域函数序言为偶数个 push + N≡0"时的隐含假设, 非不变量);
// step 7 从 ctx+0x120 (ns) 重基数后再减本常量, 对任意余数都精确落槽,
// 不依赖该假设。槽本身的读写 (push/pop ctx) 也无对齐要求。

// step 4 对齐移位 (MIT-406): call 前 rsp 必须 16 对齐 (Win64: callee 入口
// 看 rsp ≡ 8 mod 16)。原 0x28 垫只做了相对 native_sp 的对齐, 而 ns 自身
// 余数随区域函数序言深度变化 (wvmpTest sha256 区域 ns ≡ 0 mod 16 → callee
// 入口 ≡ 0 → CRT 浮点 helper 的 movaps [rsp+..] #GP → 0xC0000005, cdb
// 实证 packed+0xd389 movaps 崩点)。此处把 call 站位动态归一到 16 对齐:
// 实现为 shr/shl 各 4 位 (丢低 4 位余数)。不用 and r,0xFFFFFFF0 —— keystone
// 拒绝 >INT32_MAX 的 and 立即数 (errno 512 实证), shr/shl 小立即数无此限。
constexpr u64 kCallgateAlignShift = 4;  // 2^4 = 16 对齐

// ---------------------------------------------------------------------------
// MIT-407: ExitNative 退出槽（从 kExitSlotDepth 单一来源派生，MIT-B2 纪律）。
//
// 槽地址 = native_sp - kExitSlotDepth（runtime.hpp，与 stub_gen.cpp 共用）。
// handler 内 rsp = host_rsp = native_sp - kHostRspDepth（VM entry 8 push +
// call ret 之后，跨指令稳定——callgate step 7-8 亦回落到该值），故槽 =
// [rsp - kExitSlotFromHostRsp]。v1 曾把写回链搬进 handler 并直接
// `add rsp, kCtxSize` 想回 stub 帧：handler 内 rsp 比 stub 帧顶低 0x48
// （entry 8 push + call ret），add 后落在 ctx 区中部、8 pop 读到 ctx 内容、
// 终态 jmp 槽地址错位 0x48 → 读垃圾目标（segfault 根因之一）。新设计
// handler 只写槽 + 弹 entry 8 push + ret，寄存器/xmm 写回链留在 stub HALT
// 段（一字未动）——写/读/预写三处按各自 rsp 基准落到同一地址。
// ---------------------------------------------------------------------------
constexpr u64 kHostRspDepth = kCalleeSavedPushBytes + kCtxSize + kCallRetBytes +
                              kCalleeSavedPushBytes;  // 0x250（与文件头推导一致）
static_assert(kHostRspDepth == 0x250, "host_rsp depth regressed");
constexpr u64 kExitSlotFromHostRsp = kExitSlotDepth - kHostRspDepth;  // 0x288-0x250 = 0x38
static_assert(kExitSlotFromHostRsp == 0x38, "exit slot must sit 0x38 below host_rsp");

// MIT-438 (X1b)：Ret 清栈返回出口的两组派生常量（build_ret 专用，见函数注释）。
//
//   kRetFrameDiscard：handler 入口（rsp = ns - kHostRspDepth）一次性弃掉的
//     解释器帧——entry 8 push + call rt_entry 返回地址 + ctx 区。解释器 8 push
//     与 stub 8 push 的值冗余（stub 在 call 前不触碰 callee-saved），跳过弹弃
//     由 stub 的 8 pop 统一恢复，故不是 7 次单独 pop。
//   kRetGuestRspFromNs：终态 `mov rsp,[rsp-...]` 的偏移 = ns 到 ctx+0x30
//     （guest rsp 槽）。stub 8 pop 之后 rsp = ns，该读取发生于 rsp 变更前。
constexpr u64 kRetFrameDiscard =
    kCalleeSavedPushBytes + kCallRetBytes + kCtxSize;  // 0x40+0x8+0x1C8 = 0x210
static_assert(kRetFrameDiscard == 0x210, "ret exit frame discard regressed");
constexpr u64 kRetGuestRspFromNs = kCalleeSavedPushBytes + kCtxSize - 0x30;  // 0x1D8
static_assert(kRetGuestRspFromNs == 0x1D8, "ret exit guest-rsp slot offset regressed");

// ---------------------------------------------------------------------------
// 生成器主体。
// ---------------------------------------------------------------------------
class AsmGen {
public:
    // MIT-443 (X3a)：生成码体位宽双模。默认 X64 —— 既有路径逐字节不变（D6：
    // x64 输出按同 seed dump 对账恒等）；X86 = KS_MODE_32 码体（x86 电池面）。
    enum class HostArch { X64, X86 };
    explicit AsmGen(Rng& rng, HostArch arch = HostArch::X64, bool fetch_decrypt = false)
        : rng_(rng), arch_(arch), fetch_decrypt_(fetch_decrypt) {}

    void roll() {
        if (arch_ == HostArch::X86) { roll_x86(); return; }
        // ctx_ 必须 callee-saved：callgate handler 跨 native call 用 r64(ctx_)
        // 寻址 VmContext（step 9-10 push/pop 完后从 VmContext 读 pc/flags/base），
        // 若 ctx_ 落到 caller-saved（rax/rdx/r8-r11），callee 按 Win64 ABI clobber，
        // 寻址读到垃圾 → segfault（rc=139 SIGSEGV）。见 issue-10 修复：
        //   .multica/issue-10-callgate-ctx-callee-saved.md
        // kPhys[14] 索引下，callee-saved = {rbx=2, rbp=3, rsi=4, rdi=5,
        //                                  r12=10, r13=11, r14=12, r15=13}
        ctx_ = kCalleeSavedIdx[static_cast<size_t>(rng_.uniform(0u, u64(kCalleeSavedIdx.size()) - 1u))];

        // base_ 也必须 callee-saved：vm_entry push base_ + push 7 rest(跳过 base_)
        // = 8 个 push, host_rsp = native_sp - 0x250（= kCtxSize + 0x88, 见文件头
        // kCallgateSpRollback 推导）. 若 base_ 是 caller-saved (如 rax), 它不在
        // rest 数组里, push 数变成 9, host_rsp 再低 8 字节. callgate step 7 的
        // 回退量按 8 push 口径派生, pop ctx_ 时读错地址, ctx_ 被破坏 → 跨
        // native call 后寻址 VmContext 读到垃圾 → segfault.
        int base_idx = ctx_;
        while (base_idx == ctx_) {
            base_idx = kCalleeSavedIdx[static_cast<size_t>(rng_.uniform(0u, u64(kCalleeSavedIdx.size()) - 1u))];
        }

        // t_[0] (目标 VA) 和 t_[5] (aux 立即数) 都必须 callee-saved:
        // callgate step 5 写物理 rcx/rdx/r8/r9 (Win64 ABI 参数寄存器)。若
        // t_[0] = rdx/r8/r9, step 5 clobber 目标 VA, step 6 call 错误地址。
        // 若 t_[5] = rdx/r8/r9, step 5 clobber aux 立即数, step 1 算出错的
        // 目标 VA。两者都得避 {rdx=1, r8=6, r9=7}, 即限定 callee-saved 池。
        int t0_idx = ctx_;
        while (t0_idx == ctx_ || t0_idx == base_idx) {
            t0_idx = kCalleeSavedIdx[static_cast<size_t>(rng_.uniform(0u, u64(kCalleeSavedIdx.size()) - 1u))];
        }
        int t5_idx = ctx_;
        while (t5_idx == ctx_ || t5_idx == base_idx || t5_idx == t0_idx) {
            t5_idx = kCalleeSavedIdx[static_cast<size_t>(rng_.uniform(0u, u64(kCalleeSavedIdx.size()) - 1u))];
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

    // MIT-443 (X3a)：x86 分配器（池 6 = 2 持久 + 4 临时；seed 随机化保留，
    // 机制与 x64 roll() 同款 —— uniform 抽取 + shuffle）。x64 分叉在 roll()
    // 顶部，本函数只服务 X86 码体（D6 x64 恒等不受影响）。
    void roll_x86() {
        // ctx_/base_ 从 x86 callee-saved 池（4 个）随机去重抽取（callgate
        // 未来的 callee-saved 约束预保留；base_ 同时是 dispatch 跳表基址）。
        const u64 ci = rng_.uniform(0u, 3u);
        u64 bi = rng_.uniform(0u, 2u);
        if (bi >= ci) ++bi;   // 均匀映射到 {0..3} \ {ci}
        ctx_ = kX86CalleeSaved[ci];
        base_ = kX86CalleeSaved[bi];
        // 数据临时 t_[0]/t_[1]：字节可编码集 {eax,edx,ebx} 均匀抽 2（S8
        // native 子寄存器名硬约束 —— bpl/sil/dil 为 REX 专属名 32 位不可编
        // 码，见文件头 kX86 池注）。⚠️ MIT-476：候选集必须先剔除 ctx_/base_
        // 已占用的 ebx（kX86ByteCapable ∩ kX86CalleeSaved = {ebx}）——旧实
        // 现无剔除，t0/t1 撞上 ctx_=ebx 时 rest 填充塌缩成 3 项 →
        // std::array<int,2> 越界写（Debug assert / Release 静默损坏），且
        // t0==ctx_ 本身即角色冲突（scratch 写毁 ctx 指针）。候选剔除后
        // 恒剩 ≥2（ebx 至多被占一次，eax/edx 恒空闲）。
        int cand[3];
        int nc = 0;
        for (int i = 0; i < 3; ++i) {
            const int r = kX86ByteCapable[i];
            if (r == ctx_ || r == base_) continue;
            cand[nc++] = r;
        }
        const u64 a0 = rng_.uniform(0u, static_cast<u64>(nc - 1));
        u64 a1 = rng_.uniform(0u, static_cast<u64>(nc - 2));
        if (a1 >= a0) ++a1;
        t_[0] = cand[a0];
        t_[1] = cand[a1];
        // 寻址临时 t_[2]/t_[3]：池剩余 2 位随机洗牌（无宽度名约束）。
        std::array<int, 2> rest{};
        int j = 0;
        for (int i = 0; i < kX86PoolSize; ++i) {
            if (i == ctx_ || i == base_ || i == t_[0] || i == t_[1]) continue;
            rest[j++] = i;
        }
        if (j != 2) throw std::runtime_error("regvm runtime x86: pool accounting broken");
        rng_.shuffle(rest.begin(), rest.end());
        t_[2] = rest[0];
        t_[3] = rest[1];
        // pc MIT-494t②：ecx 寄存器常驻（x86 池 6 寄存器全占，ecx 唯一机动
        // ——保留移位计数；Cl 族/dispatch 解密/CallGate 三处 sync 纪律见各
        // build_*_x86 注；flags_ 仍内存常驻 [ctx+0x98]）。置负值防误用
        //（x86 emit 面禁触 r64()/r64(pc_)/r64(flags_)）。
        pc_ = -1;
        flags_ = -1;
        // 尺寸链 3 路随机（x86 无 S64 VmOp）+ 条件链 16 路随机（同 x64 机制）。
        for (int i = 0; i < 3; ++i) x86_size_perm_[i] = i;
        rng_.shuffle(x86_size_perm_.begin(), x86_size_perm_.end());
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
        if (arch_ == HostArch::X86) return build_entry_x86();
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
        if (arch_ == HostArch::X86) return build_dispatch_x86(table_off);
        std::string o;
        o += std::string("    mov ") + r64(t_[0]) + ", qword ptr [" + r64(ctx_) + "]\n";
        o += std::string("    mov ") + r64(t_[8]) + ", qword ptr [" + r64(t_[0]) + " + " +
             r64(pc_) + "*8]\n";
        if (fetch_decrypt_) {
            // MIT-473 (C 点取指级加密)：fetch 后原位解密。位置键流 K =
            // seed + PC × STEP（u32 环加，仅依赖字序 → 跳转/循环/imm aux
            // 字任意取指序全兼容）；字内 lo/hi 两半同 xor K（与 codec
            // encrypt_fetch_with_key 逐位一致）；初态在 blob 头 seed 字段 =
            // 流基址 -0x10。
            // ⚠️ K 先全 32 位环加（add/imul r64 变体 + imm32 会符号扩展且被
            // keystone 拒，errno 512，实测），再复制到 64 位上下两半、一次
            // 64 位 xor 解密整个字——**绝不能对 T8 做 32 位 xor**：x86-64
            // 32 位写零扩展会把寄存器高 32 位（= 加密的 hi 半字）清零
            //（单步实测：w0 0x0000004D_000E4001 经首次 xor 后高半即毁）。
            // 立即数必须 hex()——keystone 裸数字按 16 进制解析（P6）。
            o += std::string("    mov ") + rs(t_[0], 2) + ", dword ptr [" + r64(t_[0]) + " - " + hex(16) + "]\n";  // key0
            o += std::string("    mov ") + rs(t_[2], 2) + ", " + rs(pc_, 2) + "\n";       // 字序 = PC
            o += std::string("    mov ") + rs(t_[3], 2) + ", " + rs(t_[2], 2) + "\n";
            o += std::string("    imul ") + rs(t_[3], 2) + ", " + rs(t_[3], 2) + ", " +
                 hex(0x9E3779B1ull) + "\n";
            o += std::string("    add ") + rs(t_[3], 2) + ", " + rs(t_[0], 2) + "\n";   // K（32 位环加）
            o += std::string("    mov ") + rs(t_[2], 2) + ", " + rs(t_[3], 2) + "\n";   // 暂存 K（t2 dispatch 内已死）
            o += std::string("    shl ") + r64(t_[3]) + ", " + hex(32) + "\n";          // K << 32
            o += std::string("    or ") + r64(t_[3]) + ", " + r64(t_[2]) + "\n";        // K 复制到上下两半
            o += std::string("    xor ") + r64(t_[8]) + ", " + r64(t_[3]) + "\n";       // 64 位一次解密 lo+hi
        }
        o += std::string("    mov ") + r64(t_[0]) + ", " + r64(t_[8]) + "\n";
        o += std::string("    and ") + r64(t_[0]) + ", " + imm(kTableEntries - 1) + "\n";
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
    // MIT-433 (MIT-P1)：本函数是"五标志全量装配"通路——适用于按结果写全部
    // 五位的指令族（add/sub/and/or/xor/test/cmp/neg/sar/shl/shr/adc/sbb/
    // cmpxchg/ucomis…）。只写部分标志的指令族不得走此全量装配（会把 guest
    // 应保留的位覆写成 handler 内部宿主状态），见 flags_tail_partial。
    std::string flags_tail(u64 dispatch, bool cf_preset) const {
        const std::string skip = "fskip" + std::to_string(seq());
        std::string o;
        // MIT-474 (T18) flags-dead 标记路由：cond 位 2 = 翻译期 liveness 证
        // 明本写无读者 → 整段捕获/装配跳过，VM flags 保持前值（正确性契约
        // 见 encoding.hpp kFlagsDeadBit 注：欠实现安全，过实现禁止）。
        o += std::string("    test ") + r64(t_[8]) + ", " + hex(1u << 20) + "\n";
        o += "    jnz " + skip + "\n";
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
        o += skip + ":\n";
        o += advance(dispatch);
        return o;
    }

    // MIT-433 (MIT-P1) flags partial-preserve 装配：Inc/Dec cf_preset 先例
    // （"保留位不经 setcc5、直接从 ctx 旧值搬运合并"）的三位推广版。
    //
    // 语义依据（Intel SDM Vol. 2 ROL/ROR；MIT-432 G9r §6.1 本案）：
    //   ROL/ROR 只写 CF（循环移出位）与 OF（仅 count==1 有定义，count>1 时
    //   SDM 标 undefined——宿主 CPU 仍写一个值，seto 照捕，与 SDM 不冲突）；
    //   ZF/SF/PF **unaffected**——guest 视角必须原样保留。
    //
    // 为何不能复用 flags_tail：handler 内部 zero5() 的 `xor r,r` 已把宿主
    // ZF/SF/PF 打成 1/0/1，setcc5 捕到的是宿主 handler 内部状态，与 guest
    // 语义无关（MIT-432 复现：native ror 后 setz 应得 0，packed 得 1）。
    //
    // 实现：flags_ 寄存器 = ctx+0x98 的活镜像（vm_entry 载入、flags_tail/
    // SetFlags 同步、callgate 跨 native call 后重载——不变量），故旧值直接
    // `and flags_, 0x19`（ZF=bit0|SF=bit3|PF=bit4）原位保留，CF/OF 照旧由
    // T3/T4 移位或入；T6/T7/T9（setcc5 捕得的宿主垃圾）不再消费。比全量
    // 装配省 4 条（无 T6 装载与 T7/T9 两次移位或入）。
    //
    // G8a 接口预留（本单只留声明，不实现，G8a §C D2 依赖本单合入）：
    // flagless 变体（rorx/shlx/sarx/shrx 等 BMI2 族，全不写 flags）的接入点
    // = 本函数的"保留掩码 + 部分或入"骨架——届时把 CF/OF 也并入保留掩码
    // （掩码 0x1F 全保留、零 or 入、zero5/setcc5 整段省略），零新 VmOp。
    std::string flags_tail_partial(u64 dispatch) const {
        const std::string skip = "fskip" + std::to_string(seq());
        std::string o;
        // MIT-474: 同 flags_tail 的标记路由（合并型写：无读者时跳过 = 状态
        // 保持前值，与"合并结果无读者"等价）。
        o += std::string("    test ") + r64(t_[8]) + ", " + hex(1u << 20) + "\n";
        o += "    jnz " + skip + "\n";
        o += std::string("    and ") + r64(flags_) + ", " + imm(0x19) + "\n";
        o += std::string("    shl ") + r64(t_[3]) + ", 1\n";
        o += std::string("    or ") + r64(flags_) + ", " + r64(t_[3]) + "\n";
        o += std::string("    shl ") + r64(t_[4]) + ", 2\n";
        o += std::string("    or ") + r64(flags_) + ", " + r64(t_[4]) + "\n";
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + 0x98], " + r64(flags_) + "\n";
        o += skip + ":\n";
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
        // MIT-474：cond 位 2 = flags-dead 标记随 4 位域一起被抽到这里——
        // 尺寸语义只看低 2 位（标记由 tail 的独立 test 消费），链头先掩码。
        o += std::string("    and ") + r64(t_[2]) + ", 3\n";
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

    // Shl/Shr/Sar（计数=cl；掩码后计数 0 → 整条 no-op 不动 flags；本机掩码
    // 规则）。shl/shr/sar 按结果写全部五标志 → flags_tail 全量装配。
    // MIT-433 (MIT-P1)：rol/ror 与本族解耦——尾部换 flags_tail_partial
    // （ZF/SF/PF 从 ctx 旧值保留，见该函数注）。块体逐字节同构（load/count
    // 掩码/zero5/native/setcc5/writeback/计数 0 出口全部一致），仅 tail 一处
    // 分叉，shl/shr/sar 生成字节码不受影响（D3 sha 逐字节对账保证）。
    std::string build_shift(const char* native, u64 dispatch, bool partial_flags = false) const {
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
        out += tail_lbl + ":\n" +
               (partial_flags ? flags_tail_partial(dispatch) : flags_tail(dispatch, false));
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
    // ---- MIT-494s (T42)：cond 链 → handler 私有 16 项 cond 跳表 ----------
    // T41 侦察（GAPS MIT-494r）：15 路线性 cmp/je 链每 Jcc 词平均白走 ~15
    // 条宿主指令，是热词流唯一大体量 handler（147 指令）的慢点主项。结构
    // 复用 dispatch 跳表 D3 机制：私有 16×8B 表挂 dispatch 表之后
    //（condtable_off = table_off + kTableEntries*8，数据区常量位——静态
    // 审门的线性反汇编扫至 dispatch 表为止，cond 表在其后零触碰），表项 =
    // cc 块相对码基址偏移，运行时 base 寄存器加算（位置无关，ASLR 安全；
    // x86 读低 dword 同 D3 口径）。cond_perm_ 随机置换保留（表项布局熵等
    // 价）。块偏移经分量哑汇编测量：jmp 恒 E9 rel32 / SIB disp 恒 32 定宽
    // → 子块编码与整装逐字节同宽，算术布局即真布局（keystone 无符号表回
    // 读能力，此法绕开）。setcc/cmovcc/条件 ExitNative 的链保持原样（本
    // 矩阵冷面，收益为零白付 128B/handler 静态尺寸），留待测温推广。
    mutable std::array<u64, 16> last_cond_table_{};   // 最近一次 build_*_jcc_at 填写
    const std::array<u64, 16>& last_cond_table() const { return last_cond_table_; }

    // HandlerDef 表项兼容包装（generate_runtime_arch 按 "jcc" 名特殊化接管，
    // 本包装不进主装配路径；哑偏移 0x40000000 强制 SIB disp32 定宽）。
    std::string build_jcc(u64 dispatch) const {
        return build_jcc_at(dispatch, 0, 0x4000'0000ull);
    }

    std::string build_jcc_at(u64 dispatch, u64 self_off, u64 ctbl_off) const {
        const std::string tag = "jcc" + std::to_string(seq());
        const std::string test_lbl = "jtest" + tag;
        const std::string fall_lbl = "jfall" + tag;
        const std::string prelude = decode_prelude();
        // 取表三连：t_[2] 持 cond（decode_prelude 落点，先读后写一次取表），
        // 表项 + base = cc 块运行地址（dispatch 跳表 add base 同构）。
        const std::string fetch =
            std::string("    mov ") + r64(t_[2]) + ", qword ptr [" + r64(base_) +
            " + " + r64(t_[2]) + "*8 + " + hex(ctbl_off) + "]\n" +
            "    add " + r64(t_[2]) + ", " + r64(base_) + "\n" +
            "    jmp " + r64(t_[2]) + "\n";
        // 尾部段前置（test/取径/顺延在块前）：块内 jmp test_lbl 全为已定义
        // 背向引用。⚠️ 布局测量铁律：keystone 对 jmp 按"实际距离"选宽——
        // 前向未知标签近距编 EB rel8（2B）、远距/绝对编 E9 rel32（5B），
        // 哑绝对目标测量会系统性虚大 3B/块（T42 实测：FiveSeedStability
        // 错块路由 + 挂死，capstone 实锤 eb04 序列）。前缀累进汇编量块偏
        // 移：前缀与整装逐字节同前缀 → 块 k 偏移 = 前 k 块前缀的装配尺寸。
        const std::string tail =
            test_lbl + ":\n" +
            std::string("    test ") + r64(t_[0]) + ", " + r64(t_[0]) + "\n" +
            "    jz " + fall_lbl + "\n" +
            build_jmp(dispatch) +   // taken：pc += sext(aux)
            fall_lbl + ":\n" + advance(dispatch);
        // 块发射序 = 原链序（perm[15] 最先顺延，perm[0..14] 随后）——顺序随
        // 机保留。分量测量用局部会话（标签不污染主会话符号表）。
        int order[16];
        order[0] = cond_perm_[15];
        for (int i = 0; i < 15; ++i) order[i + 1] = cond_perm_[i];
        auto blk_text = [&](int k) {
            return "cc" + std::to_string(order[k]) + "_" + tag + ":\n" +
                   cond_eval(order[k]) + "    jmp " + test_lbl + "\n";
        };
        {
            KsSession ks;
            std::string prefix = prelude + fetch + tail;
            for (int k = 0; k < 16; ++k) {
                // ⚠️ 测量必须用真实 self_off：jmp dispatch（数值目标）的
                // EB/E9 选宽取决于绝对距离，at=0 会编 EB、真址编 E9。
                last_cond_table_[order[k]] =
                    self_off + ks.assemble(prefix, self_off, "jcc prefix").size();
                prefix += blk_text(k);
            }
        }
        std::string out = prelude + fetch + tail;
        for (int k = 0; k < 16; ++k) out += blk_text(k);
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

    // MIT-407: ExitNative 主 handler（区域外跳转单向退出到 native）。
    //   - aux = 目标 RVA（u32，零扩展入 t_[5]）
    //   - 无条件直退: a_kind=Imm（decode_prelude 解到 t_[3]==2）。不能用
    //     cond 字段的 0xFF sentinel——cond 仅 4 位（encode 端 validate_insn
    //     拒绝 >15，v1 的 0xFF 设计启用即抛），a_kind 对 ExitNative 本无
    //     语义，借为无条件标记（编码合法、译码零开销）。
    //   - 条件退出: cond_or_size = ir::Cond 0..15（12/17 站点），复用 build_jcc
    //     的 cond_eval 链；不满足 → advance 继续 VM。
    //   - 退出路径: 目标 VA = aux + image_base（[ctx+0x110]，与 Load/Store 同一
    //     访存约定——裸 RVA 进槽 = v1 segfault 根因，cdb 实证 rip=裸 RVA）
    //     → 写 EXIT_SLOT（[rsp - 0x38]，rsp = host_rsp → 槽 = native_sp -
    //     kExitSlotDepth，与 stub 入口预写 / HALT 终态同址）→ 弹 VM entry
    //     8 push + ret（与 build_halt 同构）→ 回 stub HALT 段：寄存器/xmm
    //     写回 + add rsp + pop 后 jmp 槽间接跳出。
    //   - v1 教训: 写回链不能搬进 handler（rsp 算术错位见文件头 kHostRspDepth
    //     注释）；写槽也不能用 [rsp-0x50] 这种"handler 视角"偏移——读槽在
    //     entry rsp 坐标系，两套基准必然错位。全链路单基准 = native_sp。
    std::string build_exitnative(u64 dispatch) const {
        const std::string tag = "exitn" + std::to_string(seq());
        const std::string test_lbl = "exitn_test_" + tag;
        const std::string exit_lbl = "exitn_exit_" + tag;
        const std::string adv_lbl = "exitn_adv_" + tag;

        std::string o = decode_prelude();   // t_[5]=aux, t_[2]=cond_or_size, t_[3]=a_kind
        // 0) 无条件直退: a_kind==Imm(2) → 跳过条件链直接退出。
        o += std::string("    cmp ") + r64(t_[3]) + ", " + imm(2) + "\n";
        o += "    je " + exit_lbl + "\n";
        // 1) 条件退出链 (cond_or_size 0..15): 仿 build_jcc 链式 cond_perm_[15] 分派。
        for (int i = 0; i < 15; ++i) {
            const int c = cond_perm_[i];
            o += std::string("    cmp ") + r64(t_[2]) + ", " + imm(c) + "\n";
            o += "    je cc" + std::to_string(c) + "_" + tag + "\n";
        }
        o += "cc" + std::to_string(cond_perm_[15]) + "_" + tag + ":\n" +
             cond_eval(cond_perm_[15]) + "    jmp " + test_lbl + "\n";
        for (int i = 0; i < 15; ++i) {
            const int c = cond_perm_[i];
            o += "cc" + std::to_string(c) + "_" + tag + ":\n";
            o += cond_eval(c);
            o += "    jmp " + test_lbl + "\n";
        }
        o += test_lbl + ":\n";
        // 条件求值: t_[0] = 0 (false) 或 1 (true)。jz → 条件不满足, 继续 VM。
        o += std::string("    test ") + r64(t_[0]) + ", " + r64(t_[0]) + "\n";
        o += "    jz " + adv_lbl + "\n";
        // 2) 退出路径（无条件直退 / 条件满足在此汇合）:
        //    目标 VA = aux + image_base（RVA→VA，候选 A 修复）→ EXIT_SLOT。
        o += exit_lbl + ":\n";
        o += std::string("    mov ") + r64(t_[0]) + ", " + r64(t_[5]) + "\n";
        o += std::string("    add ") + r64(t_[0]) + ", qword ptr [" + r64(ctx_) +
             " + 0x110]\n";
        o += std::string("    mov qword ptr [rsp - ") + imm(kExitSlotFromHostRsp) + "], " +
             r64(t_[0]) + "\n";
        // 3) VM 退出（与 build_halt 完全同构: 弹 entry 8 push + ret → 回 stub
        //    HALT 段；stub 段负责寄存器/xmm 写回并 jmp 槽间接跳出）。
        {
            const char* rest[] = {"r15", "r14", "r13", "r12", "rsi", "rdi", "rbp", "rbx"};
            for (const char* r : rest) {
                if (std::string_view(r) == std::string_view(kPhys[base_].r64)) continue;
                o += std::string("    pop ") + r + "\n";
            }
            o += std::string("    pop ") + r64(base_) + "\n";
        }
        o += "    ret\n";
        o += adv_lbl + ":\n";
        o += advance(dispatch);  // 条件不满足 → 继续 VM
        return o;
    }

    // MIT-438 (X1b)：Ret 清栈返回——pop 返回地址 + rsp += imm 后**退出 VM 直接
    // 返回 guest caller**（x86/x64 双 arch 共享语义；x64 现网 ret imm16 合法编码
    // 的既有正确性缺口收口，X0 §7/派活单 §A.1）。
    //
    // 语义（SDM Vol.2 RET.Near imm16）：ret_addr = [v4]；v4 += 8 + imm（imm 为
    // 字节数，无符号零扩展——translator 已按 0xFFFF 掩码；imm=0 ≡ plain ret，
    // D3 边界）。退出口径对齐 ExitNative 的"handler 内直接退出"先例（不回
    // stub HALT 段、不写 EXIT_SLOT），差异 = 终态物理 rsp 不是 entry rsp 而是
    // **清栈后的 guest rsp**——stdcall 被调方清栈是本 op 的全部意义。
    //
    // 出口机制（为何不能走 stub HALT 通道）：stub 终态 `jmp [rsp-kExitSlotDepth]`
    // 恒在 rsp = native_sp 处转移，物理 rsp 无法表达清栈。故 handler 自行完成
    // stub HALT 段的全部工作（易失寄存器 + xmm 写回、宿主 callee-saved 恢复）
    // 后把物理 rsp 调到 guest 视角：
    //   1) ret_addr 与 v4' 先落盘：ret_addr → [v4'-8]（终态 jmp 槽，在终态
    //      rsp 下方的死栈区），v4' → ctx+0x30（guest rsp 持久化）——此后 T0/T1
    //      可被写回/pop 任意覆盖，终态零活寄存器依赖；
    //   2) `add rsp, kRetFrameDiscard`（0x210：解释器 8 push + call 返回地址 +
    //      ctx 区）——解释器 8 push 的值与 stub 8 push 冗余（stub 在 call 前不
    //      改 callee-saved），跳过弹弃、由 stub 的 8 个 pop 统一恢复宿主值；
    //   3) pop stub 的 8 push（rbx,rbp,rdi,rsi,r12-r15 固定 push 序的逆序，
    //      与 stub_gen 尾部同款）→ rsp = native_sp；
    //   4) `mov rsp,[rsp-0x1D8]`（= ctx+0x30，读取发生于 rsp 变更前）→ 物理rsp
    //      := v4'；`jmp qword ptr [rsp-8]` → ret_addr（[v4'-8] 槽），rsp 保持
    //      v4'——与原生 ret 后的 caller 视角逐字节一致。
    //
    // ⚠️ 继承既有边界（ExitNative 同款披露）：guest 未配平 push 的区域会把
    // 物理 rsp 带到 stub 帧之下（push 写 [v4-8] 本就覆盖 stub 保存区），属
    // "区域含未配平 push"登记面（asmgen 文件头 ExitNative 注释），本 handler
    // 不新增防线；[v4'-8] 终态槽写在清栈后 rsp 之下（Win64 死栈区），与
    // EXIT_SLOT（native_sp-0x288）重叠仅在 v4' < native_sp 的病态形出现。
    //
    // #33 对账（派活单 §E）：本 op 此前**无 handler**（跳表项指向 Halt，文件头
    // handler 清单注释），无既有 aux 读路径可冲突；X0 §3.1 所指 "pop-ret-addr
    // 的 handler" 即本函数（此前不存在，由本单实现）。
    std::string build_ret(u64 /*dispatch*/) const {
        std::string o = decode_prelude();   // T5 = aux = imm（零扩展）
        // 1) 栈语义：ret_addr = [v4]；v4' = v4 + 8 + imm；ret_addr → [v4'-8]。
        o += std::string("    mov ") + r64(t_[0]) + ", qword ptr [" + r64(ctx_) +
             " + 0x30]\n";
        o += std::string("    mov ") + r64(t_[1]) + ", qword ptr [" + r64(t_[0]) + "]\n";
        o += std::string("    add ") + r64(t_[0]) + ", " + imm(8) + "\n";
        o += std::string("    add ") + r64(t_[0]) + ", " + r64(t_[5]) + "\n";
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + 0x30], " +
             r64(t_[0]) + "\n";                          // guest rsp 持久化（ctx+0x30）
        o += std::string("    sub ") + r64(t_[0]) + ", " + imm(8) + "\n";
        o += std::string("    mov qword ptr [") + r64(t_[0]) + "], " + r64(t_[1]) + "\n";
        // 2) 易失寄存器写回（stub HALT 写回链同款：rax/rcx/rdx/r8-r11 ← ctx）。
        {
            const u64 slots[] = {0x10, 0x18, 0x20, 0x50, 0x58, 0x60, 0x68};
            const char* regs[] = {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"};
            for (int i = 0; i < 7; ++i)
                o += std::string("    mov ") + regs[i] + ", qword ptr [" + r64(ctx_) +
                     " + " + hex(slots[i]) + "]\n";
        }
        // 3) xmm0-7 写回（stub 同款，kCtxXmmBase + N*16）。
        for (int i = 0; i < 8; ++i)
            o += std::string("    movups xmm") + std::to_string(i) + ", [" + r64(ctx_) +
                 " + " + hex(kCtxXmmBase + u64(i) * 16) + "]\n";
        // 4) 弃解释器帧（8 push + call 返回地址 + ctx 区）→ rsp = ns-0x40。
        o += std::string("    add rsp, ") + hex(kRetFrameDiscard) + "\n";
        // 5) 恢复宿主 callee-saved（stub push 序 rbx,rbp,rdi,rsi,r12-r15 的逆序，
        //    与 stub_gen 尾部逐字对齐）。
        o += "    pop r15\n pop r14\n pop r13\n pop r12\n";
        o += "    pop rsi\n pop rdi\n pop rbp\n pop rbx\n";
        // 6) 终态：物理 rsp := v4'（读 ctx+0x30 于 rsp 变更前），间接跳 [v4'-8]。
        o += std::string("    mov rsp, qword ptr [rsp - ") +
             hex(kRetGuestRspFromNs) + "]\n";
        o += "    jmp qword ptr [rsp - 8]\n";
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
    //   - aux = 目标 RVA（u32，零扩展至 u64）；cond_or_size = arg_count
    //     （v1 必须 0）。
    //   - MIT-445 (X3c B.1) reg 值目标形（call reg / call [mem] 折条落地，
    //     442 D4 停手挂账翻案）：a_kind 判别位双形共用 VmOp::CallGate
    //     （零新 VmOp，派单 D1 拍板），字节级布局：
    //       RVA 形（既有）: a_kind=None, reg_a 无义, aux=目标 RVA
    //                        → VA = aux + image_base([ctx+0x110])
    //       reg 形（新增）: a_kind=Reg,  reg_a=目标槽(0..31), aux 无义(0)
    //                        → VA = regs[reg_a]（槽全宽读；VM 槽值 = 绝对
    //                        VA——IAT 项/函数指针经 Load/LoadRva 装入）
    //   - 运行时：目标 VA 就位后调目标函数，callee ret 后 RAX 写回
    //     regs[0]，dispatch 继续。
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
    // 栈回退算术（host_rsp = native_sp - 0x250 = 解释器执行期 rsp；常量由
    // 文件头从 kCtxSize 编译期派生，MIT-B2；MIT-406 加 callee 窗口后重推）：
    //   stub 8 push + sub kCtxSize + call 返回 8 + entry 8 push = 0x250
    //   push ctx → rsp = host_rsp - 8 = native_sp - 0x258
    //   t1 = native_sp - kWinShadowBytes - kCallgateCalleeWindow
    //      = native_sp - 0x1028          ← callee 专用窗口 (MIT-406)
    //   t1 &= ~15                        ← 运行时对齐 (MIT-406 缺陷二)
    //   mov rsp, t1
    //   mov qword ptr [t1], 0            ← 窗口底探针写 (防御性)
    //   call/ret → rsp = t1 (对齐后, 距 ns 含 0..15B 对齐余数)
    //   mov rsp, [ctx + 0x120]           ← native_sp 重基数 (跨 call 稳定)
    //   sub rsp, kPushCtxDepth(0x258)    → rsp = native_sp - 0x258 = host_rsp - 8
    //   pop ctx → rsp = host_rsp         (不变量保持)
    // 缺陷一 (窗口): 修复前 call 站位 native_sp-0x28 距 ctx 顶仅 0x1D8
    // 预算, 深树砸穿 ctx (wvmpTest sha256 调用树 ~0x250B, MIT-404 暴露)。
    // 缺陷二 (对齐): 原 0x28 垫只相对 ns 对齐, ns 余数随区域函数序言变
    // 化; sha256 树内 CRT 浮点 helper 的 movaps [rsp+..] 对 8 mod 16 的
    // callee 入口 rsp 直接 #GP (cdb 实证 packed+0xd389 崩点)。两缺陷正交,
    // 单修一不转绿——本单双修。
    //
    // 契约（MIT-406 §B.5）: 区域 VM 栈 (v4 = regs[4], VM Push/Pop 按
    // [v4+disp] 绝对寻址) 与 native 窗口互斥——v4 以 native_sp 为基准,
    // 区域栈向下越界属未配平 push 的潜在约束 (MIT-405 §2.4, 已知边界,
    // 本单不修); native 窗口在 host_rsp 下方独立生长, 两者互不重叠。
    // MIT-371 把 kCtxSize 0x140→0x1C8 时此处曾硬编码 0x1A8（0x140 时代值）
    // 未跟随：push/pop ctx 槽错开 0x88，pop 读到 stub 帧内宿主 RBP(=0) →
    // ctx_=0 → callgate 样本全线 0xC0000005（MIT-393）。
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
        // 0) 目标 VA 双形分派（MIT-445 X3c B.1）：a_kind==Reg(T3==1) →
        //    t0 = regs[reg_a]（绝对 VA，槽全宽读）；否则 t0 = T5(aux RVA) +
        //    image_base([ctx+0x110])（既有 RVA 形，行为逐位不变）。T3/T4 已
        //    由 decode_prelude 解出；t_[0] 恒 callee-saved（roll() 约束），
        //    跨 step 5 物理参数装载存活到 step 6 call。
        //    ⚠️ 本块必须在参数快照（下一 step）之前：快照覆写 reserved
        //    24..27 槽，先读保 reg_a∈24..27 病态形的语义（translator 恒
        //    emit ≤23，双保险）。（MIT-484 后快照 scratch = t_[1]，与
        //    t_[3]/t_[4] 互斥、不再覆写 T3/T4，但先读次序仍保双保险。）
        {
            // 标签用固定名（不吃 seq()）：seq 号被消费会让后续全部 handler
            // 的内部标签顺移，x64 dump delta 将扩散到无关 op 的标签文本——
            // 固定名全码体唯一（x86 面为 xcgrva_/xcghave_ 前缀，不同代际），
            // 本 handler 每镜像只 emit 一次，无重定义风险。
            const std::string lbl_rva = "cgrva";
            const std::string lbl_have = "cghave";
            o += std::string("    cmp ") + r64(t_[3]) + ", " + imm(1) + "\n";
            o += "    jne " + lbl_rva + "\n";
            o += std::string("    mov ") + r64(t_[0]) + ", qword ptr [" + r64(ctx_) +
                 " + " + r64(t_[4]) + "*8 + 0x10]\n";
            o += "    jmp " + lbl_have + "\n";
            o += lbl_rva + ":\n";
            o += std::string("    mov ") + r64(t_[0]) + ", " + r64(t_[5]) + "\n";
            o += std::string("    add ") + r64(t_[0]) + ", qword ptr [" + r64(ctx_) +
                 " + 0x110]\n";
            o += lbl_have + ":\n";
        }
        // 1) 把 VM 整数参数槽（regs[1]=Rcx, /[2]=Rdx, /[8]=R8, /[9]=R9）
        // 先搬到 reserved 槽位，防 callgate 自己的 prelude/pre-call 路径
        // 在 push ctx 之后又读 VmContext 时被外部指令序串改坏——保留独立
        // 通道供后续 load 物理寄存器用。
        // ⚠️ MIT-484 (T6.5)：搬运 scratch 禁用物理 rax——roll 可能把
        // flags_ 或 pc_ 分到 rax（pool 恒含 rax），step 2 随即把被 snapshot
        // 覆写的 rax 当 flags/pc 存进 ctx（实录：seed 3 构建生成的
        // `mov [ctx+0x98], rax` 存的是 v9 残值）。改用 t_[1]：角色互斥保证
        // ≠ ctx_/base_/pc_/flags_，其原值在本块前无任何读者、step 4 首条
        // 指令即纯写覆盖（decode_prelude 只用 t_[2..8]，step 0 只用
        // t_[0]/t_[3]/t_[4]/t_[5]）。
        const std::string snap = r64(t_[1]);
        o += std::string("    mov ") + snap + ", qword ptr [" + r64(ctx_) + " + 0x18]\n";   // regs[1] (Rcx)
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + 0xD0], " + snap + "\n";
        o += std::string("    mov ") + snap + ", qword ptr [" + r64(ctx_) + " + 0x20]\n";   // regs[2] (Rdx)
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + 0xD8], " + snap + "\n";
        o += std::string("    mov ") + snap + ", qword ptr [" + r64(ctx_) + " + 0x48]\n";   // regs[8] (R8)
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + 0xE0], " + snap + "\n";
        o += std::string("    mov ") + snap + ", qword ptr [" + r64(ctx_) + " + 0x50]\n";   // regs[9] (R9)
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + 0xE8], " + snap + "\n";
        // 2) 保存 pc/flags/base 到 VmContext 槽
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + 0x8], " + r64(pc_) + "\n";
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + 0x98], " + r64(flags_) + "\n";
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + 0x130], " + r64(base_) + "\n";
        // 3) push ctx 到 host stack
        o += std::string("    push ") + r64(ctx_) + "\n";
        // 4) 切 rsp → native_sp - 0x28 - kCallgateCalleeWindow（32 shadow
        //    + 8 对齐 + callee 专用窗口, MIT-406）。立即数经 imm() 从常量
        //    派生, 禁字面量第二份拷贝 (MIT-B2 纪律)。
        o += std::string("    mov ") + r64(t_[1]) + ", qword ptr [" + r64(ctx_) +
             " + 0x120]\n";
        o += std::string("    sub ") + r64(t_[1]) + ", " +
             imm(kWinShadowBytes + kCallgateCalleeWindow) + "\n";
        // 运行时对齐 (MIT-406 缺陷二): ns 自身余数随区域函数序言深度变化,
        // 0x28 垫只能相对对齐 — 此处把 call 站位归一到 16 对齐, 保证
        // callee 入口 rsp ≡ 8 (mod 16) 恒成立 (Win64 ABI, movaps 栈槽)。
        o += std::string("    shr ") + r64(t_[1]) + ", " +
             imm(kCallgateAlignShift) + "\n";
        o += std::string("    shl ") + r64(t_[1]) + ", " +
             imm(kCallgateAlignShift) + "\n";
        o += std::string("    mov rsp, ") + r64(t_[1]) + "\n";
        // 探针写 (MIT-406 §B.2 / D3.1): 窗口底一次触碰, 防御性——本跳幅
        // (自 push ctx 槽 ns-0x258 至 ns-0x1028 共 0xDD0) < 1 页, Win64
        // guard page 自动扩栈本应覆盖 (栈探测规则: 触碰点距已提交区不超
        // 一页即自动生长); 显式探针消除边界条件。窗口若调大过一页, 此写
        // 从防御升级为必需。
        o += std::string("    mov qword ptr [") + r64(t_[1]) + "], 0\n";
        // 5) 把 reserved slots 抬到物理 rcx/rdx/r8/r9。
        // 关键：必须用 r64(ctx_) 而非硬编码 "r14" —— ctx_ 由 AsmGen::roll()
        // 从 14 GPR 池随机洗牌 (pool[0]) 选出，当前 seed=12345 下恰好是
        // r14 是"巧合可行"而非设计。任何 seed 改动都会让此 4 行访问野地址。
        // 其余 callgate 步骤（1-4, 9-11）一致用 r64(ctx_)，本步骤同步。
        o += std::string("    mov rcx, qword ptr [") + r64(ctx_) + " + 0xD0]\n";
        o += std::string("    mov rdx, qword ptr [") + r64(ctx_) + " + 0xD8]\n";
        o += std::string("    mov r8,  qword ptr [") + r64(ctx_) + " + 0xE0]\n";
        o += std::string("    mov r9,  qword ptr [") + r64(ctx_) + " + 0xE8]\n";
        // 5.5) MIT-417 (P0): Win64 FP 参数槽 xmm0..3 ← ctx.xmm[0..3]。
        // 此前 step 0/5 只搬整数参数 (rcx/rdx/r8/r9), 区域内对带
        // double/float 参数的 native 调用 FP 参数断链 → 静默错乱零告警
        // (g5r_p0: native fp_sum=15.00 → packed fp_sum=3.00; G5r triage
        // §6.1)。全 16B movups 对 float/double/packed 全安全: Win64 ABI
        // 规定 FP 参数高位 undefined, 全宽搬运与原生行为精确一致 (ctx.xmm
        // 槽由 408 Movss S32/Movsd S64 通路正确维护, 低部有效即可)。
        // movaps 禁用 (406 movaps 对齐 #GP 先例; ctx.xmm 区 16B 对齐但
        // 物理侧无保证)。xmm base 经 kCtxXmmBase + 16*N 编译期派生, 禁
        // 字面量第二份拷贝 (B2/E1 纪律)。
        // 时序安全 (B.2 实测): 全部 handler 的物理 xmm0..3 均为指令内
        // 临时 (读 ctx → 算 → 写 ctx → advance), 指令边界无活值; 此处
        // 无条件覆写不破坏任何跨指令状态 (审读见 MIT-417 报告)。
        for (int n = 0; n < 4; ++n) {
            o += std::string("    movups xmm") + std::to_string(n) + ", [" +
                 r64(ctx_) + " + " + imm(kCtxXmmBase + 16 * n) + "]\n";
        }
        // 6) 调 native（目标 VA 在 t_[0]，参数已就位）
        o += std::string("    call ") + r64(t_[0]) + "\n";
        // 7) rsp 回到 host stack 上 push ctx 处（host_rsp - 8）。窗口 +
        //    运行时对齐使 call/ret 后 rsp 相对 ns 的偏移含逐 stub 余数,
        //    常量回退不可解 — 从 ctx+0x120 (native_sp, stub_gen 一次性
        //    写入, 跨 call 稳定; ctx_ 抽自 callee-saved 池, 跨 call 存活)
        //    重基数, 再减常量 kPushCtxDepth (kCtxSize 编译期派生链,
        //    MIT-B2 纪律, kCtxSize 再变时自动跟随)。
        o += std::string("    mov rsp, qword ptr [") + r64(ctx_) + " + 0x120]\n";
        o += "    sub rsp, " + imm(kPushCtxDepth) + "\n";
        // 8) pop 回 ctx_
        o += std::string("    pop ") + r64(ctx_) + "\n";
        // 10) RAX (callee 返回值) 写回 regs[v0]
        // ⚠️ MIT-484 (T6.5)：必须先于下方 pc/flags/base 恢复——roll 可能把
        // flags_ 或 pc_ 分到物理 rax，恢复指令会把 rax 里的 callee 返回值
        // 冲掉，v0 随即写入污染值（实录：seed 3 构建
        // `mov rax,[ctx+0x98]; mov [ctx+0x10],rax` → v0 恒 0，kern.md5
        // 野指针）。v0 先写（此时 rax 仍持 native 返回），后恢复三角色。
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + 0x10], rax\n";
        // 9) 从 VmContext 恢复 pc/flags/base
        o += std::string("    mov ") + r64(pc_) + ", qword ptr [" + r64(ctx_) + " + 0x8]\n";
        o += std::string("    mov ") + r64(flags_) + ", qword ptr [" + r64(ctx_) + " + 0x98]\n";
        o += std::string("    mov ") + r64(base_) + ", qword ptr [" + r64(ctx_) + " + 0x130]\n";
        // 10.5) MIT-417 (P0): callee 标量 FP 返回值 xmm0 → ctx.xmm[0]。
        // Win64 标量 FP 返回恒 xmm0 单槽, 无需 xmm1 (__vectorcall 多槽
        // 返回不在 v1 面, GAPS C3 登记)。全 16B movups 捕获 callee 实际
        // xmm0 全宽 — 后续 movsd/movss 低部读取与 addps 等全宽读取均与
        // 原生残留语义一致 (未修复时 ctx.xmm[0] 保持 call 前旧值, 区域内
        // 用返回值的 SSE 运算全部错值)。必须位于 step 8 pop ctx 之后
        // (r64(ctx_) 已恢复)。
        o += std::string("    movups [") + r64(ctx_) + " + " +
             imm(kCtxXmmBase) + "], xmm0\n";
        // 11) advance（PC += 1; jmp dispatch）
        o += advance(dispatch);
        return o;
    }

    // MIT-408: 读 reg_b (T7) 指向的 128-bit 槽到物理 xmm1 — **双语义寻址**:
    //   reg_b >= 24 → ctx.xmm 区 (0x140 + (reg-24)*16, 既有公式);
    //   reg_b <  24 → GP scratch 双槽 (0x10 + reg*8, 16B 覆盖 vN+vN+1) —
    //     XmmLoad 的临时槽编码 (ALU src=mem 形式的落点, 翻译器取 v18..v23
    //     两两作 xmm 宽临时, 指令边界后即死, 不与 xmm 槽互踩)。
    // 静态文本同时含两条公式: verifier 的常量闸按 xmm 公式计数 (sub 0x18/
    // shl 4/add 0x140), GP 分支的 0x10 是寻址位移非立即数, 不稀释闸面。
    // 硬约束: 24/4/0x140 一律经 imm() (pitfall #78)。
    std::string load_src_slot_into_xmm1(const std::string& tag) const {
        const std::string lbl_x = "srcx_" + tag;
        const std::string lbl_d = "srcd_" + tag;
        std::string o;
        o += std::string("    cmp ") + r64(t_[7]) + ", " + imm(24) + "\n";
        o += "    jae " + lbl_x + "\n";
        // GP 双槽: 16B 直读 (0x10 为寻址位移)
        o += std::string("    movups xmm1, [") + r64(ctx_) + " + " + r64(t_[7]) + "*8 + 0x10]\n";
        o += "    jmp " + lbl_d + "\n";
        o += lbl_x + ":\n";
        // xmm 区: 0x140 + (reg-24)*16 (Keystone 不支持 (reg-24)*16, 拆步)
        o += std::string("    mov ") + r64(t_[9]) + ", " + r64(t_[7]) + "\n";
        o += std::string("    sub ") + r64(t_[9]) + ", " + imm(24) + "\n";
        o += std::string("    shl ") + r64(t_[9]) + ", " + imm(4) + "\n";
        o += std::string("    add ") + r64(t_[9]) + ", " + imm(kCtxXmmBase) + "\n";
        o += std::string("    movups xmm1, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        o += lbl_d + ":\n";
        return o;
    }

    // 槽位偏移公式 (既有 xmm 区专用, dst 写回路径沿用): T9 = 0x140+(reg-24)*16。
    // 硬约束: 24/4/0x140 一律经 imm() (pitfall #78)。
    std::string xmm_offset_into_t9_text(int reg_t) const {
        std::string o;
        o += std::string("    mov ") + r64(t_[9]) + ", " + r64(reg_t) + "\n";
        o += std::string("    sub ") + r64(t_[9]) + ", " + imm(24) + "\n";
        o += std::string("    shl ") + r64(t_[9]) + ", " + imm(4) + "\n";
        o += std::string("    add ") + r64(t_[9]) + ", " + imm(kCtxXmmBase) + "\n";
        return o;
    }

    // MIT-408 XmmLoad: 内存 → xmm/GP 槽。a_kind=Reg reg_a=目的槽 (>=24 xmm 区
    // / <24 GP 双槽), b_kind=Reg reg_b=地址槽 (绝对 VA), aux=访存宽度 (4/8/16),
    // cond_or_size=Size (S64 占位)。handler:
    //   mov T1, [ctx + reg_b*8 + 0x10]   (取地址)
    //   cmp T5, 4 → movss / 8 → movsd / else movups xmm0, [T1]   (宽度链,
    //     内存源清零语义由 native movss/movsd 直产: SDM 内存源清零高位)
    //   cmp T4, 24 → jae xmm 区: T9=0x140+(reg_a-24)*16; movups [ctx+T9], xmm0
    //             → else GP 双槽: movups [ctx + reg_a*8 + 0x10], xmm0
    //   advance。
    std::string build_xmm_load(u64 dispatch) const {
        const std::string tag = "xmmld" + std::to_string(seq());
        const std::string lbl4 = "ld4_" + tag;
        const std::string lbl8 = "ld8_" + tag;
        const std::string lbl16 = "ld16_" + tag;
        const std::string lblx = "ldx_" + tag;
        const std::string lbld = "ldd_" + tag;
        std::string o = decode_prelude();
        // 地址 → T1
        o += std::string("    mov ") + r64(t_[1]) + ", qword ptr [" + r64(ctx_) + " + " +
             r64(t_[7]) + "*8 + 0x10]\n";
        // 宽度链: aux ∈ {4, 8, 16} (翻译器恒发合法值; 16 为链尾顺延)
        o += std::string("    cmp ") + r64(t_[5]) + ", " + imm(4) + "\n";
        o += "    je " + lbl4 + "\n";
        o += std::string("    cmp ") + r64(t_[5]) + ", " + imm(8) + "\n";
        o += "    je " + lbl8 + "\n";
        o += "    jmp " + lbl16 + "\n";
        o += lbl4 + ":\n";
        o += std::string("    movss xmm0, dword ptr [") + r64(t_[1]) + "]\n";
        o += "    jmp " + lblx + "\n";
        o += lbl8 + ":\n";
        o += std::string("    movsd xmm0, qword ptr [") + r64(t_[1]) + "]\n";
        o += "    jmp " + lblx + "\n";
        o += lbl16 + ":\n";
        o += std::string("    movups xmm0, xmmword ptr [") + r64(t_[1]) + "]\n";
        // 目的槽: reg_a >= 24 → xmm 区 (双公式, 0x10 是寻址位移非立即数)
        o += lblx + ":\n";
        o += std::string("    cmp ") + r64(t_[4]) + ", " + imm(24) + "\n";
        o += "    jae " + lbld + "\n";
        o += std::string("    movups [") + r64(ctx_) + " + " + r64(t_[4]) + "*8 + 0x10], xmm0\n";
        o += "    jmp " + std::string("done_") + tag + "\n";
        o += lbld + ":\n";
        o += xmm_offset_into_t9_text(t_[4]);
        o += std::string("    movups [") + r64(ctx_) + " + " + r64(t_[9]) + "], xmm0\n";
        o += "done_" + tag + ":\n";
        o += advance(dispatch);
        return o;
    }

    // MIT-408 XmmStore: xmm/GP 槽 → 内存。a_kind=Reg reg_a=地址槽 (绝对 VA),
    // b_kind=Reg reg_b=源槽 (>=24 xmm 区 / <24 GP 双槽), aux=访存宽度。
    // handler: 槽 128-bit 读进物理 xmm1 (双语义寻址) → 宽度链
    //   movss/movsd/movups [addr], xmm1 → advance。
    std::string build_xmm_store(u64 dispatch) const {
        const std::string tag = "xmmst" + std::to_string(seq());
        const std::string lbl4 = "st4_" + tag;
        const std::string lbl8 = "st8_" + tag;
        const std::string lbl16 = "st16_" + tag;
        std::string o = decode_prelude();
        // 地址 → T1; 源槽 128-bit → xmm1
        o += std::string("    mov ") + r64(t_[1]) + ", qword ptr [" + r64(ctx_) + " + " +
             r64(t_[4]) + "*8 + 0x10]\n";
        o += load_src_slot_into_xmm1(tag);
        // 宽度链 (按 xmm1 落盘, 低宽度截断)
        o += std::string("    cmp ") + r64(t_[5]) + ", " + imm(4) + "\n";
        o += "    je " + lbl4 + "\n";
        o += std::string("    cmp ") + r64(t_[5]) + ", " + imm(8) + "\n";
        o += "    je " + lbl8 + "\n";
        o += "    jmp " + lbl16 + "\n";
        o += lbl4 + ":\n";
        o += std::string("    movss dword ptr [") + r64(t_[1]) + "], xmm1\n";
        o += "    jmp " + std::string("done_") + tag + "\n";
        o += lbl8 + ":\n";
        o += std::string("    movsd qword ptr [") + r64(t_[1]) + "], xmm1\n";
        o += "    jmp " + std::string("done_") + tag + "\n";
        o += lbl16 + ":\n";
        o += std::string("    movups xmmword ptr [") + r64(t_[1]) + "], xmm1\n";
        o += "done_" + tag + ":\n";
        o += advance(dispatch);
        return o;
    }

    // MIT-427 (G1c) XmmFromGp: movd/movq GP↔xmm 桥 load 方向 — src 槽低
    // 4/8 字节 → dst xmm 槽, **dst 槽其余字节清零** (SDM MOVD 清 bits
    // 127:32 / MOVQ 清 bits 127:64; F3 0F 7E xmm 源同)。
    //   编码: a_kind=Reg reg_a=xmm_dst_slot (24..31), b_kind=Reg reg_b=src
    //   槽 (GP 0..15 或 xmm 24..31 双语义), aux=宽度 (4|8), cond_or_size 占位。
    //   handler: src 槽域分派 —
    //     reg_b < 24 (GP 槽): 宽度链 movd/movq xmm0, [GP 槽] (mem 形式
    //       native 自产清零语义);
    //     reg_b >= 24 (xmm 槽, 仅 width=8 — F3 0F 7E 形态): movsd xmm0,
    //       [xmm 槽低 64] (mem 形式清零高 64)。
    //   dst 槽 16B 全量写回 (movups) — 清零语义落槽。
    //   不影响 EFLAGS; 直接 advance。
    std::string build_xmm_from_gp(u64 dispatch) const {
        const std::string tag = "xmmfg" + std::to_string(seq());
        const std::string lbl4 = "fg4_" + tag;
        const std::string lblsx = "fgsx_" + tag;
        const std::string lbld = "fgd_" + tag;
        std::string o = decode_prelude();
        // src 槽域分派: T7 = reg_b
        o += std::string("    cmp ") + r64(t_[7]) + ", " + imm(24) + "\n";
        o += "    jae " + lblsx + "\n";
        // GP 槽: 宽度链 (aux ∈ {4, 8}; 8 为链尾顺延)
        o += std::string("    cmp ") + r64(t_[5]) + ", " + imm(4) + "\n";
        o += "    je " + lbl4 + "\n";
        o += std::string("    movq xmm0, qword ptr [") + r64(ctx_) + " + " +
             r64(t_[7]) + "*8 + 0x10]\n";
        o += "    jmp " + lbld + "\n";
        o += lbl4 + ":\n";
        o += std::string("    movd xmm0, dword ptr [") + r64(ctx_) + " + " +
             r64(t_[7]) + "*8 + 0x10]\n";
        o += "    jmp " + lbld + "\n";
        // xmm 槽: 低 64 读 + 高 64 清零 (movsd mem 形式语义)
        o += lblsx + ":\n";
        o += xmm_offset_into_t9_text(t_[7]);
        o += std::string("    movsd xmm0, qword ptr [") + r64(ctx_) + " + " +
             r64(t_[9]) + "]\n";
        // dst xmm 槽 16B 全量写
        o += lbld + ":\n";
        o += xmm_offset_into_t9_text(t_[4]);
        o += std::string("    movups [") + r64(ctx_) + " + " + r64(t_[9]) + "], xmm0\n";
        o += advance(dispatch);
        return o;
    }

    // MIT-427 (G1c) GpFromXmm: movd/movq GP↔xmm 桥 store 方向 — src xmm
    // 槽低 4/8 字节截取 → dst GP 槽。
    //   编码: a_kind=Reg reg_a=gp_dst_slot (0..15), b_kind=Reg reg_b=
    //   xmm_src_slot (24..31), aux=宽度 (4|8), cond_or_size 占位。
    //   handler: src xmm 槽 128-bit 读 (movups) → 宽度链截取落盘:
    //     width=8: movq qword [GP 槽], xmm0 (低 64 截取);
    //     width=4: movd dword [GP 槽], xmm0 + **高 4 字节清零** — native
    //       movd r32 写 32 位寄存器本机零扩展 (SDM), 与 writeback 的 S32
    //       零扩展语义对齐 (asmgen writeback: "S32 写 32 位寄存器自动零
    //       扩展"), 双 store (低 4 截取 + 高 4 置零) 逐位等价。
    //   不影响 EFLAGS; 直接 advance。
    std::string build_gp_from_xmm(u64 dispatch) const {
        const std::string tag = "gpfx" + std::to_string(seq());
        const std::string lbl4 = "fx4_" + tag;
        const std::string lbld = "fxd_" + tag;
        std::string o = decode_prelude();
        // src xmm 槽 128-bit 读: T9 = 0x140+(reg_b-24)*16
        o += xmm_offset_into_t9_text(t_[7]);
        o += std::string("    movups xmm0, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        // dst GP 槽宽度链截取: T4 = reg_a
        o += std::string("    cmp ") + r64(t_[5]) + ", " + imm(4) + "\n";
        o += "    je " + lbl4 + "\n";
        o += std::string("    movq qword ptr [") + r64(ctx_) + " + " +
             r64(t_[4]) + "*8 + 0x10], xmm0\n";
        o += "    jmp " + lbld + "\n";
        o += lbl4 + ":\n";
        o += std::string("    movd dword ptr [") + r64(ctx_) + " + " +
             r64(t_[4]) + "*8 + 0x10], xmm0\n";
        o += std::string("    mov dword ptr [") + r64(ctx_) + " + " +
             r64(t_[4]) + "*8 + 0x14], " + imm(0) + "\n";
        o += lbld + ":\n";
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
            o += std::string("    add ") + r64(t_[9]) + ", " + imm(kCtxXmmBase) + "\n";
        };
        emit_xmm_offset_into_t9(t_[4]);  // T9 = dst 偏移
        o += std::string("    movups xmm0, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        o += load_src_slot_into_xmm1(tag);  // src: xmm 区或 GP 双槽 (MIT-408)
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
            o += std::string("    add ") + r64(t_[9]) + ", " + imm(kCtxXmmBase) + "\n";
        };
        emit_xmm_offset_into_t9(t_[4]);
        o += std::string("    movups xmm0, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        o += load_src_slot_into_xmm1(tag);  // src: xmm 区或 GP 双槽 (MIT-408)
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
            o += std::string("    add ") + r64(t_[9]) + ", " + imm(kCtxXmmBase) + "\n";
        };
        emit_xmm_offset_into_t9(t_[4]);
        o += std::string("    movups xmm0, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        o += load_src_slot_into_xmm1(tag);  // src: xmm 区或 GP 双槽 (MIT-408)
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
            o += std::string("    add ") + r64(t_[9]) + ", " + imm(kCtxXmmBase) + "\n";
        };
        emit_xmm_offset_into_t9(t_[4]);  // T9 = dst 偏移
        o += std::string("    movups xmm0, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        o += load_src_slot_into_xmm1(tag);  // src: xmm 区或 GP 双槽 (MIT-408)
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
            o += std::string("    add ") + r64(t_[9]) + ", " + imm(kCtxXmmBase) + "\n";
        };
        emit_xmm_offset_into_t9(t_[4]);
        o += std::string("    movups xmm0, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        o += load_src_slot_into_xmm1(tag);  // src: xmm 区或 GP 双槽 (MIT-408)
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
            o += std::string("    add ") + r64(t_[9]) + ", " + imm(kCtxXmmBase) + "\n";
        };
        emit_xmm_offset_into_t9(t_[4]);
        o += std::string("    movups xmm0, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        o += load_src_slot_into_xmm1(tag);  // src: xmm 区或 GP 双槽 (MIT-408)
        o += "    subpd xmm0, xmm1\n";
        emit_xmm_offset_into_t9(t_[4]);
        o += std::string("    movups [") + r64(ctx_) + " + " + r64(t_[9]) + "], xmm0\n";
        o += advance(dispatch);
        (void)tag;
        return o;
    }

    // MIT-374 Divss: scalar single-precision FP div (xmm1 = xmm1 / xmm2)。
    //   字节结构: F3 0F 5E /r (REG-REG, mod=11; capstone 实证 F30F5EC1)。
    //   编码: reg_a=xmm_dst_slot (24..31, translator 从 IR 0..7 加 24 偏移),
    //         reg_b=xmm_src_slot (24..31), aux=0, cond_or_size=ir::Size::S32。
    //   xmm 槽位: VmContext.xmm[8] @ +0x140（MIT-371 SSE 跟踪区, MIT-374 复用,
    //   无需改 VmContext 布局 / stub_gen kCtxSize）。
    //   handler: 算 dst/src 槽位偏移 → movups 读/写 128-bit → divss。
    //   硬约束 (SSE/Block 模板 #1): 槽位偏移公式的 24/4/0x140 一律经 imm(),
    //   禁止裸多位数字 (MIT-371 空转 / MIT-373 8ed50b0 根因)。
    //   不影响 EFLAGS; 不调 setcc5 也不走 flags_tail, 直接 advance(dispatch)。
    std::string build_divss(u64 dispatch) const {
        const std::string tag = "divss" + std::to_string(seq());
        std::string o = decode_prelude();
        // T4 = reg_a (24..31). 算 xmm 槽位偏移到 T9 (Keystone 不支持 (reg-24)*16,
        // 拆为 sub 24 → shl 4 → add 0x140, 三个常量全走 imm())。
        auto emit_xmm_offset_into_t9 = [&](int reg_t) {
            o += std::string("    mov ") + r64(t_[9]) + ", " + r64(reg_t) + "\n";
            o += std::string("    sub ") + r64(t_[9]) + ", " + imm(24) + "\n";
            o += std::string("    shl ") + r64(t_[9]) + ", " + imm(4) + "\n";
            o += std::string("    add ") + r64(t_[9]) + ", " + imm(kCtxXmmBase) + "\n";
        };
        emit_xmm_offset_into_t9(t_[4]);  // T9 = dst 偏移
        o += std::string("    movups xmm0, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        o += load_src_slot_into_xmm1(tag);  // src: xmm 区或 GP 双槽 (MIT-408)
        o += "    divss xmm0, xmm1\n";
        emit_xmm_offset_into_t9(t_[4]);  // 重算 dst 偏移写回
        o += std::string("    movups [") + r64(ctx_) + " + " + r64(t_[9]) + "], xmm0\n";
        o += advance(dispatch);
        (void)tag;
        return o;
    }

    // MIT-374 Divps: packed single-precision FP div (4xf32 lane-parallel)。
    //   字节结构: 0F 5E /r (REG-REG, mod=11; capstone 实证 0F5EC1)。
    //   编码: reg_a=24..31 (xmm_dst_slot), reg_b=24..31 (xmm_src_slot),
    //         aux=0, cond_or_size=ir::Size::S64 (packed 128-bit 占位)。
    std::string build_divps(u64 dispatch) const {
        const std::string tag = "divps" + std::to_string(seq());
        std::string o = decode_prelude();
        auto emit_xmm_offset_into_t9 = [&](int reg_t) {
            o += std::string("    mov ") + r64(t_[9]) + ", " + r64(reg_t) + "\n";
            o += std::string("    sub ") + r64(t_[9]) + ", " + imm(24) + "\n";
            o += std::string("    shl ") + r64(t_[9]) + ", " + imm(4) + "\n";
            o += std::string("    add ") + r64(t_[9]) + ", " + imm(kCtxXmmBase) + "\n";
        };
        emit_xmm_offset_into_t9(t_[4]);
        o += std::string("    movups xmm0, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        o += load_src_slot_into_xmm1(tag);  // src: xmm 区或 GP 双槽 (MIT-408)
        o += "    divps xmm0, xmm1\n";
        emit_xmm_offset_into_t9(t_[4]);
        o += std::string("    movups [") + r64(ctx_) + " + " + r64(t_[9]) + "], xmm0\n";
        o += advance(dispatch);
        (void)tag;
        return o;
    }

    // MIT-374 Divpd: packed double-precision FP div (2xf64 lane-parallel)。
    //   字节结构: 66 0F 5E /r (REG-REG, mod=11, 0x66 prefix 隐式; 实证 660F5EC1)。
    //   编码: reg_a=24..31 (xmm_dst_slot), reg_b=24..31 (xmm_src_slot),
    //         aux=0, cond_or_size=ir::Size::S64。
    std::string build_divpd(u64 dispatch) const {
        const std::string tag = "divpd" + std::to_string(seq());
        std::string o = decode_prelude();
        auto emit_xmm_offset_into_t9 = [&](int reg_t) {
            o += std::string("    mov ") + r64(t_[9]) + ", " + r64(reg_t) + "\n";
            o += std::string("    sub ") + r64(t_[9]) + ", " + imm(24) + "\n";
            o += std::string("    shl ") + r64(t_[9]) + ", " + imm(4) + "\n";
            o += std::string("    add ") + r64(t_[9]) + ", " + imm(kCtxXmmBase) + "\n";
        };
        emit_xmm_offset_into_t9(t_[4]);
        o += std::string("    movups xmm0, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        o += load_src_slot_into_xmm1(tag);  // src: xmm 区或 GP 双槽 (MIT-408)
        o += "    divpd xmm0, xmm1\n";
        emit_xmm_offset_into_t9(t_[4]);
        o += std::string("    movups [") + r64(ctx_) + " + " + r64(t_[9]) + "], xmm0\n";
        o += advance(dispatch);
        (void)tag;
        return o;
    }


    // ---- MIT-408: SSE scalar-double 族 addsd/subsd/divsd ----
    //
    // 与 ss/ps/pd 三族同构 (读 dst 槽 → 读 src 槽 → native sd 指令 → 写回
    // dst 槽 → advance), 仅 native 助记符不同 (F2 0F 58/5C/5E, 低 64 位
    // 标量运算, 高 64 位保持 — movups 全 128-bit 读写自然保高位)。src 读
    // 走 load_src_slot_into_xmm1 双语义 (MIT-408: MEM 源经 GP 双槽)。
    // 不影响 EFLAGS; 不调 setcc5/flags_tail, 直接 advance。
    std::string build_addsd(u64 dispatch) const {
        const std::string tag = "addsd" + std::to_string(seq());
        std::string o = decode_prelude();
        auto emit_xmm_offset_into_t9 = [&](int reg_t) {
            o += std::string("    mov ") + r64(t_[9]) + ", " + r64(reg_t) + "\n";
            o += std::string("    sub ") + r64(t_[9]) + ", " + imm(24) + "\n";
            o += std::string("    shl ") + r64(t_[9]) + ", " + imm(4) + "\n";
            o += std::string("    add ") + r64(t_[9]) + ", " + imm(kCtxXmmBase) + "\n";
        };
        emit_xmm_offset_into_t9(t_[4]);  // T9 = dst 偏移
        o += std::string("    movups xmm0, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        o += load_src_slot_into_xmm1(tag);  // src: xmm 区或 GP 双槽 (MIT-408)
        o += "    addsd xmm0, xmm1\n";
        emit_xmm_offset_into_t9(t_[4]);  // 重算 dst 偏移写回
        o += std::string("    movups [") + r64(ctx_) + " + " + r64(t_[9]) + "], xmm0\n";
        o += advance(dispatch);
        (void)tag;
        return o;
    }

    // MIT-408 Subsd: 同 build_addsd, native "subsd" (F2 0F 5C)。
    std::string build_subsd(u64 dispatch) const {
        const std::string tag = "subsd" + std::to_string(seq());
        std::string o = decode_prelude();
        auto emit_xmm_offset_into_t9 = [&](int reg_t) {
            o += std::string("    mov ") + r64(t_[9]) + ", " + r64(reg_t) + "\n";
            o += std::string("    sub ") + r64(t_[9]) + ", " + imm(24) + "\n";
            o += std::string("    shl ") + r64(t_[9]) + ", " + imm(4) + "\n";
            o += std::string("    add ") + r64(t_[9]) + ", " + imm(kCtxXmmBase) + "\n";
        };
        emit_xmm_offset_into_t9(t_[4]);  // T9 = dst 偏移
        o += std::string("    movups xmm0, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        o += load_src_slot_into_xmm1(tag);  // src: xmm 区或 GP 双槽 (MIT-408)
        o += "    subsd xmm0, xmm1\n";
        emit_xmm_offset_into_t9(t_[4]);  // 重算 dst 偏移写回
        o += std::string("    movups [") + r64(ctx_) + " + " + r64(t_[9]) + "], xmm0\n";
        o += advance(dispatch);
        (void)tag;
        return o;
    }

    // MIT-408 Divsd: 同 build_addsd, native "divsd" (F2 0F 5E)。
    std::string build_divsd(u64 dispatch) const {
        const std::string tag = "divsd" + std::to_string(seq());
        std::string o = decode_prelude();
        auto emit_xmm_offset_into_t9 = [&](int reg_t) {
            o += std::string("    mov ") + r64(t_[9]) + ", " + r64(reg_t) + "\n";
            o += std::string("    sub ") + r64(t_[9]) + ", " + imm(24) + "\n";
            o += std::string("    shl ") + r64(t_[9]) + ", " + imm(4) + "\n";
            o += std::string("    add ") + r64(t_[9]) + ", " + imm(kCtxXmmBase) + "\n";
        };
        emit_xmm_offset_into_t9(t_[4]);  // T9 = dst 偏移
        o += std::string("    movups xmm0, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        o += load_src_slot_into_xmm1(tag);  // src: xmm 区或 GP 双槽 (MIT-408)
        o += "    divsd xmm0, xmm1\n";
        emit_xmm_offset_into_t9(t_[4]);  // 重算 dst 偏移写回
        o += std::string("    movups [") + r64(ctx_) + " + " + r64(t_[9]) + "], xmm0\n";
        o += advance(dispatch);
        (void)tag;
        return o;
    }
    //      (+ MIT-408: movsd 经 (Movss,S64) 编码 = VmOp::Movsd) ----
    //
    // 五条共用模板 (hotfix v6 重建, 独立成员函数): 读 dst 槽 -> 读 src 槽 ->
    // 就地执行被虚拟化的那条 native 指令 -> 写回 dst 槽 -> advance。
    // 与 div 族唯一差别: 浮点传送不影响 EFLAGS, 不调 setcc5/flags_tail。
    // 读 dst 槽这一步对 movss 是语义必需 (寄存器形式只改低 32 位, 高 96 位
    // 保持不变), 对 aps/apd/ups/upd 是无害统一模板。
    // 硬约束: 槽位偏移公式的 24/4/0x140 一律经 imm(), 禁止裸多位数字
    // (pitfall #78: Keystone Intel 语法裸数字按 16 进制解析)。
    //
    // MIT-408 (C4b): xorps/orps/andps (位运算) 的 MEM 源折条把 src 槽编码为
    // GP 双槽 (reg < 24, XmmLoad 落点) → dual_src=true 时 src 读走
    // load_src_slot_into_xmm1 双语义寻址; mov 族 (reg-reg 或 XmmLoad 直落
    // xmm 槽) 保持既有 xmm 区单公式 (dual_src=false, 文本与修复前逐字节一致)。
    std::string build_xmm_transfer(u64 dispatch, const char* native_mn,
                                   bool dual_src = false) const {
        std::string o = decode_prelude();
        const std::string tag = std::string(native_mn) + std::to_string(seq());
        auto emit_xmm_offset_into_t9 = [&](int reg_t) {
            o += std::string("    mov ") + r64(t_[9]) + ", " + r64(reg_t) + "\n";
            o += std::string("    sub ") + r64(t_[9]) + ", " + imm(24) + "\n";
            o += std::string("    shl ") + r64(t_[9]) + ", " + imm(4) + "\n";
            o += std::string("    add ") + r64(t_[9]) + ", " + imm(kCtxXmmBase) + "\n";
        };
        emit_xmm_offset_into_t9(t_[4]);  // T9 = dst 槽偏移
        o += std::string("    movups xmm0, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        if (dual_src) {
            o += load_src_slot_into_xmm1(tag);  // src: xmm 区或 GP 双槽
        } else {
            emit_xmm_offset_into_t9(t_[7]);  // T9 = src 槽偏移
            o += std::string("    movups xmm1, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        }
        o += std::string("    ") + native_mn + " xmm0, xmm1\n";
        emit_xmm_offset_into_t9(t_[4]);  // 重算 dst 偏移写回
        o += std::string("    movups [") + r64(ctx_) + " + " + r64(t_[9]) + "], xmm0\n";
        o += advance(dispatch);
        return o;
    }

    // 五条各自的中间指令文本不同, 其余完全一致 (movss 只改 lane0/高位保持,
    // aps/apd/ups/upd 全 128-bit 搬)。
    std::string build_movss(u64 d)  const { return build_xmm_transfer(d, "movss"); }
    std::string build_movaps(u64 d) const { return build_xmm_transfer(d, "movaps"); }
    std::string build_movapd(u64 d) const { return build_xmm_transfer(d, "movapd"); }
    std::string build_movups(u64 d) const { return build_xmm_transfer(d, "movups"); }
    std::string build_movupd(u64 d) const { return build_xmm_transfer(d, "movupd"); }
    // MIT-408: movsd (F2 0F 10, scalar double) — 8B 搬, 高 64 位保持不变
    // (寄存器形式; 内存源清零语义由 XmmLoad 的 native movsd 直产)。
    std::string build_movsd(u64 d)  const { return build_xmm_transfer(d, "movsd"); }

    // ---- MIT-376: SSE 浮点位运算 xorps / orps / andps ----
    //
    // 三条完全复用 MIT-375 build_xmm_transfer 四步模板 (读 dst 槽 → 读 src 槽
    // → 就地执行被虚拟化的那条 native 指令 → 写回 dst 槽 → advance): 中间行
    // 分别是 xorps/orps/andps xmm0, xmm1 (全 128-bit 按位, 不解释浮点值)。
    // 与浮点传送唯一差别: 位运算不改 EFLAGS 也不产 NaN (无序不存在), 与 mov
    // 族同为"无 flags 尾巴"路径。
    // 硬约束: 槽位偏移公式的 24/4/0x140 一律经 imm(), 禁止裸多位数字
    // (pitfall #78)。
    std::string build_xorps(u64 d) const { return build_xmm_transfer(d, "xorps", /*dual_src=*/true); }
    std::string build_orps(u64 d)  const { return build_xmm_transfer(d, "orps", /*dual_src=*/true); }
    std::string build_andps(u64 d) const { return build_xmm_transfer(d, "andps", /*dual_src=*/true); }

    // ---- MIT-425 (G1b): SSE 浮点乘 mul 族 + andnps/andnpd/pandn 折叠 ----
    //
    // 四条 mul 复用 build_xmm_transfer 四步模板 (读 dst 槽 → 读 src 槽
    // [load_src_slot_into_xmm1 双语义, MIT-408 MEM 源经 GP 双槽] → native
    // mul* → 写回 dst 槽 → advance), 与 xorps/orps/andps 唯一差别是中间行
    // 助记符。槽位偏移常量 24/4/0x140 全走 imm() (pitfall #78)。
    // Andnps 同模板 (native "andnps": dst = ~dst & src, 逐位, 不解释浮点
    // 值); andnpd/pandn (66 前缀) 由翻译器按 411 ps/pd 互认折叠到本 op
    // (位运算逐位同语义, 见 translator.cpp translate_sse_andn)。
    // 不影响 EFLAGS; 不调 setcc5/flags_tail, 直接 advance。
    std::string build_mulss(u64 d)  const { return build_xmm_transfer(d, "mulss", /*dual_src=*/true); }
    std::string build_mulsd(u64 d)  const { return build_xmm_transfer(d, "mulsd", /*dual_src=*/true); }
    std::string build_mulps(u64 d)  const { return build_xmm_transfer(d, "mulps", /*dual_src=*/true); }
    std::string build_mulpd(u64 d)  const { return build_xmm_transfer(d, "mulpd", /*dual_src=*/true); }
    std::string build_andnps(u64 d) const { return build_xmm_transfer(d, "andnps", /*dual_src=*/true); }

    // ---- MIT-376: SSE 浮点比较 ucomiss / ucomisd ----
    //
    // Ucomis* 与位运算/传送族本质不同: **只写 EFLAGS (ZF/PF/CF), 不改 xmm
    // 操作数** — 没有写回步 (2 次 movups 读, 无 store), 但必须走 ALU binop
    // 同一条 flags 通路, 让区域内紧随的 setcc/jcc (Setcc/Jcc handler 读同一
    // flags_ 寄存器) 拿到真比较结果 (派活单 §D D1.1 决策: 禁止
    // decode+advance 空转, pitfall #79)。
    //
    // 顺序严格性 (与 build_binary 一致): 槽位偏移计算 (sub/shl/add 会改宿主
    // EFLAGS) → zero5() 清 flag scratch → native ucomis* 产真值 → setcc5()
    // 紧随抽取 (中间不得插入任何改 EFLAGS 的指令) → flags_tail 装配。
    //
    // Intel SDM UCOMISD/UCOMISS 真值表 (native ucomis* 直产, setcc5 直读):
    //   greater than → ZF=0 CF=0 / less than → ZF=0 CF=1 / equal → ZF=1 CF=0 /
    //   unordered (NaN) → ZF=PF=CF=1; OF/SF/AF 由 native 清 0 (SDM: "The OF,
    //   SF, AF flags are set to 0"), flags_tail 按 ZF/CF/OF/SF/PF=bit0..4
    //   装配即得 SDM 语义, 与 setcc/jcc handler 的 cond_eval 布局一致。
    //
    // 无 size 链: 每条 VmOp 是独立 handler, 中间行固定 (ucomiss ↔ S32 tag /
    // ucomisd ↔ S64 tag), 不像 ALU binop 按 cond_or_size 四路展开。
    std::string build_ucomis_flags(u64 dispatch, const char* native_mn) const {
        std::string o = decode_prelude();
        const std::string tag = std::string(native_mn) + std::to_string(seq());
        auto emit_xmm_offset_into_t9 = [&](int reg_t) {
            o += std::string("    mov ") + r64(t_[9]) + ", " + r64(reg_t) + "\n";
            o += std::string("    sub ") + r64(t_[9]) + ", " + imm(24) + "\n";
            o += std::string("    shl ") + r64(t_[9]) + ", " + imm(4) + "\n";
            o += std::string("    add ") + r64(t_[9]) + ", " + imm(kCtxXmmBase) + "\n";
        };
        emit_xmm_offset_into_t9(t_[4]);  // T9 = dst 槽偏移 (reg_a = 24..31)
        o += std::string("    movups xmm0, [") + r64(ctx_) + " + " + r64(t_[9]) + "]\n";
        o += load_src_slot_into_xmm1(tag);  // src: xmm 区或 GP 双槽 (MIT-408)
        o += zero5();                    // 清 flag scratch (T3/T4/T6/T7/T9)
        o += std::string("    ") + native_mn + " xmm0, xmm1\n";
        o += setcc5();                   // T3=CF T4=OF(=0) T6=ZF T7=SF(=0) T9=PF
        o += flags_tail(dispatch, false);  // 装配 flags_ + 同步 ctx+0x98 + advance
        return o;
    }
    std::string build_ucomiss(u64 d) const { return build_ucomis_flags(d, "ucomiss"); }
    std::string build_ucomisd(u64 d) const { return build_ucomis_flags(d, "ucomisd"); }

    // ---- MIT-404: 整数除法族 div/idiv + 符号扩展 cdq/cqo ----
    //
    // 生成器期防护 (本族 handler 特有): div/idiv/cdq 是首批**直写物理
    // rax/rdx** 的 handler (native 指令隐式操作数), 而 pc_/flags_ 随机分配
    // 可能落在物理 rax(kPhys[0])/rdx(kPhys[1]) 上 — roll() 的 10 寄存器
    // pool 恒含 rax/rdx (4 个固定位 ctx_/base_/t_[0]/t_[5] 全在 callee-saved
    // 池 kCalleeSavedIdx, 不含 rax/rdx, 免疫)。pc_/flags_ 落在 rax/rdx 时
    // native 直写会摧毁 VM 状态 → 生成器期检测并 push/pop 暂存/恢复
    // (build_callgate 中途 push 有先例)。T3/T4/T6/T7/T9 (=pool[2..9] 子集)
    // 与 pc_/flags_ (=pool[0]/pool[1]) 互斥, setcc5/zero5 无需防护。
    std::string spill_pcflags_raxrdx_pre() const {
        std::string o;
        if (pc_ == 0 || pc_ == 1)
            o += std::string("    push ") + r64(pc_) + "\n";
        if (flags_ == 0 || flags_ == 1)
            o += std::string("    push ") + r64(flags_) + "\n";
        return o;
    }
    // 恢复序 = 压栈序的严格镜像 (LIFO)。div 路径里 flags_ 稍后由 flags_tail
    // 重赋值, 恢复无害; cdq 路径不写 flags, 恢复是语义必需。
    std::string spill_pcflags_raxrdx_post() const {
        std::string o;
        if (flags_ == 0 || flags_ == 1)
            o += std::string("    pop ") + r64(flags_) + "\n";
        if (pc_ == 0 || pc_ == 1)
            o += std::string("    pop ") + r64(pc_) + "\n";
        return o;
    }

    // MIT-404 Cdq: 隐式 rax → rdx 符号扩展 (cdq=99 S32 / cqo=48 99 S64 /
    // cwd=66 99 S16)。零显式操作数 (a/b/aux 全空), cond_or_size=size。
    // 读 Rax 槽 → 物理 RAX → native cdq/cqo 直通 (§D.6 真 99 字节回读锚点)
    // → 物理 RDX 写回 Rdx 槽 (S32 dword store 保槽高位, 对齐 build_xchg S32)
    // → advance。Intel SDM: CDQ/CQO 不影响 EFLAGS — 不调 setcc5 也不走
    // flags_tail (零 flags 写回, flags_ 原样保留); 仅需 pc_/flags_ 落在物理
    // rax/rdx 的 push/pop 防护。S8 分支 defensive no-op (cbw=98 是独立指令,
    // dividend=AX 语义不同, 不在本单 §F); S16 (cwd) 因 0x66 prefix 在 lifter
    // 入口被拒不可达, 保留分支仅为改动 5 模板完备 (66 99 / 99 / 48 99)。
    std::string build_cdq(u64 dispatch) const {
        const std::string tag = "cdq" + std::to_string(seq());
        const std::string tail_lbl = "atail_" + tag;
        const u8 rax_slot = isa::vm_reg_of(ir::Reg::Rax);  // = 0
        const u8 rdx_slot = isa::vm_reg_of(ir::Reg::Rdx);  // = 2
        // 槽号是字面量 (0/2), 偏移经 imm() 派生 — 禁裸数字 (MIT-B2 纪律);
        // 与 build_mul 同款: 槽号拼进乘法地址, 不走 r64() (那是物理寄存器名)。
        const std::string rax_slot_off = imm(static_cast<u64>(rax_slot) * 8 + 0x10);
        const std::string rdx_slot_off = imm(static_cast<u64>(rdx_slot) * 8 + 0x10);
        std::array<std::string, 4> blocks;
        for (int s = 0; s < 4; ++s) {
            std::string o;
            if (s == 2) {
                // S32: cdq (99) — edx = sext(eax)
                o += spill_pcflags_raxrdx_pre();
                o += std::string("    mov eax, dword ptr [") + r64(ctx_) + " + " +
                     rax_slot_off + "]\n";
                o += "    cdq\n";
                o += std::string("    mov dword ptr [") + r64(ctx_) + " + " +
                     rdx_slot_off + "], edx\n";
                o += spill_pcflags_raxrdx_post();
            } else if (s == 3) {
                // S64: cqo (48 99) — rdx = sext(rax)
                o += spill_pcflags_raxrdx_pre();
                o += std::string("    mov rax, qword ptr [") + r64(ctx_) + " + " +
                     rax_slot_off + "]\n";
                o += "    cqo\n";
                o += std::string("    mov qword ptr [") + r64(ctx_) + " + " +
                     rdx_slot_off + "], rdx\n";
                o += spill_pcflags_raxrdx_post();
            } else if (s == 1) {
                // S16: cwd (66 99) — 防御路径 (lifter 入口拒 0x66, 不可达)
                o += spill_pcflags_raxrdx_pre();
                o += std::string("    mov ax, word ptr [") + r64(ctx_) + " + " +
                     rax_slot_off + "]\n";
                o += "    cwd\n";
                o += std::string("    mov word ptr [") + r64(ctx_) + " + " +
                     rdx_slot_off + "], dx\n";
                o += spill_pcflags_raxrdx_post();
            } else {
                // S8: cbw (98) 独立指令不在本单 — defensive no-op (§F)
            }
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude() + size_chain(blocks, tag) + tail_lbl + ":\n" +
               advance(dispatch);
    }

    // MIT-404 Div/Idiv: 隐式 dividend = rdx:rax (S32: edx:eax), 商→Rax 槽,
    // 余→Rdx 槽 (native 语义直通, 对齐 build_mul 双结果槽写回先例)。
    //   1) 除数 → T0 (t_[0] ∈ callee-saved 池, 后续物理 rax/rdx 写不触及)
    //   2) zero5 — 清 flag scratch; 必须在物理 RAX/RDX 载入**之前** (xor 的
    //      scratch 可能就是物理 rax/rdx, 载入后再 zero 会毁 dividend)
    //   3) 物理 RDX ← Rdx 槽 / RAX ← Rax 槽 (先高位后低位, 槽偏移经 imm())
    //   4) native div/idiv <sz> T0 直通 — 除零/商溢出 = 真 #DE (D2.1),
    //      崩溃形态与未加壳一致, 不做 VM 内拦截
    //   5) 商 (rax) 写 Rax 槽 + 余 (rdx) 写 Rdx 槽 — S64 qword store;
    //      S32 dword store 保槽高位 (build_xchg S32 同款, 沿用 slot 高位
    //      保留语义); 写回全部经内存直写, 不经 T 寄存器 (setcc5 之前,
    //      中间无改 EFLAGS 指令)
    //   6) 恢复 pc_/flags_ 防护 + setcc5 → flags_tail
    // flags 按 Intel undefined (D4.1): 处置方式**照抄 build_imul 现状**
    // (asmgen.cpp build_imul: load → load → zero5 → native → setcc5 →
    // flags_tail(dispatch,false), 本函数对齐其 2371-2381 行同序) — VM flags
    // = 同一 CPU 同一指令的真值, 与 native 执行逐位一致。
    // S8/S16 defensive no-op (div r/m8 dividend=AX 语义不符; S16 需 0x66
    // prefix 入口已拒, §F)。
    std::string build_div_idiv(u64 dispatch, const char* native_mn) const {
        const std::string tag = std::string(native_mn) + std::to_string(seq());
        const std::string tail_lbl = "ftail_" + tag;
        const u8 rax_slot = isa::vm_reg_of(ir::Reg::Rax);  // = 0
        const u8 rdx_slot = isa::vm_reg_of(ir::Reg::Rdx);  // = 2
        const std::string rax_slot_off = imm(static_cast<u64>(rax_slot) * 8 + 0x10);
        const std::string rdx_slot_off = imm(static_cast<u64>(rdx_slot) * 8 + 0x10);
        std::array<std::string, 4> blocks;
        for (int s = 0; s < 4; ++s) {
            std::string o;
            if (s == 2 || s == 3) {
                // 0) pc_/flags_ 落在物理 rax/rdx 时 push 暂存 (漏 push 会让
                //    pop 读栈垃圾 → pc_ 错乱 → 0xC0000005, seed 99999 实测)
                o += spill_pcflags_raxrdx_pre();
                // 1) 除数 → T0
                if (s == 3)
                    o += std::string("    mov ") + r64(t_[0]) + ", qword ptr [" +
                         r64(ctx_) + " + " + r64(t_[7]) + "*8 + 0x10]\n";
                else
                    o += std::string("    mov ") + rs(t_[0], 2) + ", dword ptr [" +
                         r64(ctx_) + " + " + r64(t_[7]) + "*8 + 0x10]\n";
                // 2) zero5 (物理 RAX/RDX 载入前)
                o += zero5();
                // 3) 物理 RDX:RAX ← 双槽 (先 RDX 后 RAX; T0 callee-saved 不受影响)
                if (s == 3) {
                    o += std::string("    mov rdx, qword ptr [") + r64(ctx_) + " + " +
                         rdx_slot_off + "]\n";
                    o += std::string("    mov rax, qword ptr [") + r64(ctx_) + " + " +
                         rax_slot_off + "]\n";
                } else {
                    o += std::string("    mov edx, dword ptr [") + r64(ctx_) + " + " +
                         rdx_slot_off + "]\n";
                    o += std::string("    mov eax, dword ptr [") + r64(ctx_) + " + " +
                         rax_slot_off + "]\n";
                }
                // 4) native 直通: rdx:rax ÷ T0 → 商 rax, 余 rdx
                o += std::string("    ") + native_mn + " " + rs(t_[0], s) + "\n";
                // 5) 商/余双槽写回 (内存直写, 不经 T 寄存器)
                if (s == 3) {
                    o += std::string("    mov qword ptr [") + r64(ctx_) + " + " +
                         rax_slot_off + "], rax\n";
                    o += std::string("    mov qword ptr [") + r64(ctx_) + " + " +
                         rdx_slot_off + "], rdx\n";
                } else {
                    o += std::string("    mov dword ptr [") + r64(ctx_) + " + " +
                         rax_slot_off + "], eax\n";
                    o += std::string("    mov dword ptr [") + r64(ctx_) + " + " +
                         rdx_slot_off + "], edx\n";
                }
                // 6) 恢复 pc_/flags_ → setcc5 (捕获 native 直产真值)
                o += spill_pcflags_raxrdx_post();
                o += setcc5();
            } else {
                // S8/S16: defensive no-op (§F)
            }
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude() + size_chain(blocks, tag) + tail_lbl + ":\n" +
               flags_tail(dispatch, false);
    }
    std::string build_div(u64 d) const { return build_div_idiv(d, "div"); }
    std::string build_idiv(u64 d) const { return build_div_idiv(d, "idiv"); }

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

    // MIT-419 (G4): Xadd — [addr] = [addr] + reg_b; reg_b = 旧 [addr]
    // (InterlockedAdd 真产物 lock xadd [m], r 返回旧值语义)。
    // a_kind=Reg reg_a=地址槽 (翻译器 emit_address), b_kind=Reg reg_b=源
    // 寄存器槽, aux=0, cond_or_size=size (S8/S32/S64; S16 需 66 前缀 lifter
    // 入口已拒, S16 块防御 no-op)。
    //
    // **单 VmOp 直执行 native lock xadd [addr], reg** — 一条指令完成读改写
    // + 加锁, 硬件原子性保真 (D1 的 strip-and-execute 折条妥协不适用于本
    // 指令; [addr] 是宿主进程真实内存, VM 与原生共享地址空间)。flags =
    // add 语义 (CF/OF/SF/ZF/PF 全更新), zero5 → native → setcc5 →
    // flags_tail (与 cmpxchg/ALU 同通路)。
    //
    // 寄存器安全 (对齐 build_cmpxchg): setcc5 clobber 集合 {T3,T4,T6,T7,T9};
    // T0 (结果) / T1 (地址) 安全。写回 reg_b 槽前从 T8 重提 reg_b 位域
    // (27..31) 到 T1 (T7 已被 setcc5 clobber; T1 地址已消费可复用)。
    std::string build_xadd(u64 dispatch) const {
        const std::string tag = "xadd" + std::to_string(seq());
        const std::string tail_lbl = "ftail_" + tag;
        std::array<std::string, 4> blocks;
        for (int s = 0; s < 4; ++s) {
            const std::string stag = tag + "_" + std::to_string(s);
            std::string o;
            if (s == 1) {  // S16 防御 no-op (66 前缀入口已拒)
                o += "    jmp " + tail_lbl + "\n";
                blocks[s] = o;
                continue;
            }
            // 1) 地址 → T1 (reg_a 槽 = 翻译器 emit_address 产出的绝对 VA)
            o += std::string("    mov ") + r64(t_[1]) + ", qword ptr [" + r64(ctx_) +
                 " + " + r64(t_[4]) + "*8 + 0x10]\n";
            // 2) 源寄存器值 → T0 (alias_read, 按宽度零扩展)
            o += load_operand(s, 6, 7, 0, "b" + stag);
            // 3) zero5 — 清 flag scratch (副作用宿主 CF/OF/SF/ZF/PF ← 0)
            o += zero5();
            // 4) native lock xadd [T1], T0 — T0 = 旧 [addr], [addr] = 旧+源。
            //    lock 前缀保硬件原子性 (与原生 InterlockedAdd 同真值)。
            o += std::string("    lock xadd ") + mptr(s) + " [" + r64(t_[1]) + "], " +
                 rs(t_[0], s) + "\n";
            // 5) setcc5 — 捕获 add 语义 flags (CF/OF/SF/ZF/PF)
            o += setcc5();
            // 6) 重提 reg_b (27..31) 到 T1, 写回 T0 (旧 [addr]) 到 reg_b 槽
            //    (alias_write 保高位; S32 dword store 与 build_cmpxchg 同款)
            o += std::string("    mov ") + r64(t_[1]) + ", " + r64(t_[8]) + "\n";
            o += std::string("    shr ") + r64(t_[1]) + ", " + imm(27) + "\n";
            o += std::string("    and ") + r64(t_[1]) + ", " + imm(31) + "\n";
            o += writeback(s, 1);
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude() + size_chain(blocks, tag) + tail_lbl + ":\n" +
               flags_tail(dispatch, false);
    }

    // MIT-419 (G4): Bts/Btr/Btc — CF = bit[位号] of [addr]; [addr] = 1/0/^1
    // (按族) (InterlockedBitTest* 真产物 lock bts [m], imm8 高频, D3; reg
    // 位号形式一并支持)。
    // a_kind=Reg reg_a=地址槽, b_kind=Reg (reg_b=位号寄存器槽) 或
    // Imm (aux=imm8 位号), cond_or_size=size (S32/S64; bts 无字节形式,
    // S8/S16 块防御 no-op)。
    //
    // 位号装载: Imm 形态的 aux 是**运行时值** (T5), native bts r/m, imm8
    // 要求静态立即数 — 统一走 reg 形态 (`bts [t1], t0`), 位号先按**全宽**
    // 装进 T0 (Reg: 读 reg_b 槽; Imm: mov t0, t5), 再用 rs(t_[0], s) 取
    // 与操作数同宽的名字 — keystone 0.9.2 实测只接受 `bts qword ptr [m],
    // rbx` / `bts dword ptr [m], ebx` 全宽形式, `bts [m], bl` 字节形式
    // 拒汇编 (KS_ERR_ASM_INVALIDOPERAND, 416 同族 ml64/ks 部分拒汇编坑
    // 先例, probe 实测 2026-08-30)。CPU 对位号自动按操作数宽度掩码
    // (64 位 &63, 32 位 &31), 与 imm8 形式语义一致 (imm8 亦被掩码)。
    // flags: 仅 CF 有定义 (SDM: 其余未定义) — setcc5 捕 host CPU 真值,
    // flags_tail 装配, 与原生执行同 CPU 行为 (undefined 位逐 CPU 一致)。
    std::string build_bit_op(const char* native, u64 dispatch) const {
        const std::string tag = std::string(native) + std::to_string(seq());
        const std::string tail_lbl = "ftail_" + tag;
        std::array<std::string, 4> blocks;
        for (int s = 0; s < 4; ++s) {
            const std::string stag = tag + "_" + std::to_string(s);
            std::string o;
            if (s == 0 || s == 1) {  // S8/S16 防御 no-op (bts 无字节形式)
                o += "    jmp " + tail_lbl + "\n";
                blocks[s] = o;
                continue;
            }
            // 1) 地址 → T1 (reg_a 槽)
            o += std::string("    mov ") + r64(t_[1]) + ", qword ptr [" + r64(ctx_) +
                 " + " + r64(t_[4]) + "*8 + 0x10]\n";
            // 2) 位号 → T0 (全宽: b_kind==1 读 reg_b 槽, 否则用 aux 的 T5;
            //    取 rs(t_[0], s) 与操作数同宽 — keystone 拒字节形式)
            o += std::string("    cmp ") + r64(t_[6]) + ", 1\n";
            o += "    jne bimm_" + stag + "\n";
            if (s == 3)
                o += std::string("    mov ") + r64(t_[0]) + ", qword ptr [" + r64(ctx_) +
                     " + " + r64(t_[7]) + "*8 + 0x10]\n";
            else
                o += std::string("    mov ") + rs(t_[0], 2) + ", dword ptr [" + r64(ctx_) +
                     " + " + r64(t_[7]) + "*8 + 0x10]\n";
            o += "    jmp bdone_" + stag + "\n";
            o += "bimm_" + stag + ":\n";
            o += std::string("    mov ") + rs(t_[0], s) + ", " + rs(t_[5], s) + "\n";
            o += "bdone_" + stag + ":\n";
            // 3) zero5 — 清 flag scratch
            o += zero5();
            // 4) native lock bts/btr/btc [T1], T0 — 单指令直执行 (硬件原子)
            o += std::string("    lock ") + native + " " + mptr(s) + " [" + r64(t_[1]) +
                 "], " + rs(t_[0], s) + "\n";
            // 5) setcc5 — CF 有定义 (其余未定义位 = host CPU 真值, 与原生同)
            o += setcc5();
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude() + size_chain(blocks, tag) + tail_lbl + ":\n" +
               flags_tail(dispatch, false);
    }

    std::string build_bts(u64 dispatch) const { return build_bit_op("bts", dispatch); }
    std::string build_btr(u64 dispatch) const { return build_bit_op("btr", dispatch); }
    std::string build_btc(u64 dispatch) const { return build_bit_op("btc", dispatch); }
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

    // Rol/Ror（MIT-433 MIT-P1 起与 build_shift 尾部解耦，走 partial 装配）。
    // x86 rol/ror 与 shl/shr/sar 的语义差异有二：
    //   1. 循环性：无 CF_in 概念（单条指令内闭环, 不接受跨指令 carry——与
    //      adc/sbb 的 CF_in 完全不同）。
    //   2. **flags 写入面（本单修的缺口）**：SDM Vol. 2 ROL/ROR 只写
    //        CF  = 循环移出位 (looped-out bit; 即从循环另一端被踢出的那一位,
    //            不同于 shr 的"末位 carry", 是闭环的对端位)
    //        OF  = 仅 count==1 时有定义 (ROL: MSB(result) XOR CF;
    //              ROR: result 最高两位异或), count>1 时 undefined
    //              (宿主 CPU 仍写一个值, setcc5 照捕——与 SDM 一致)
    //      **ZF/SF/PF unaffected**——guest 视角必须从 ctx 旧值原样保留。
    //      旧实现（本单前）把 SHL/SHR/SAR 组的"SF/ZF/PF 按结果"语义误安到
    //      ROL/ROR 头上（SDM 误读），且 flags_tail 全量装配把 zero5 的宿主
    //      内部 ZF/SF/PF（xor 致 1/0/1）覆写进 guest flags——MIT-432 §6.1
    //      项目主独立复现：native ror 后 setz=0，packed=1（旋转结果非零、
    //      ZF 应保留 0）。修复 = flags_tail_partial（本文件 flags_tail 注）。
    // 关键 catch：build_shift 不能直接复用于 build_adc/build_sbb（zero5 清
    // 宿主 CF 导致 CF_in 丢失）；反之 build_adc/build_sbb 不能复用 build_shift
    //（CF_in 路径不对）。Rol/Ror 的 CF 是纯输出（无 CF_in 概念），块体
    // （load/count 掩码/zero5/native/setcc5/writeback）与 shift 同构安全。
    // count=0 走 adv_lbl 不动值/flags（SDM: count&31 == 0 时 flags 不受影响，
    // 与 shl/shr/sar 一致；rol/ror 的 adv 出口本就不写 flags，无需分叉）。
    std::string build_rol(u64 d) const { return build_shift("rol", d, true); }
    std::string build_ror(u64 d) const { return build_shift("ror", d, true); }

    // MIT-301 cl 变体 shift: D3 /5 形式，计数源自 RCX 低 8 位（cl）而非 aux。
    // 翻译器对 src.kind=Reg 的 shift 发射新 VmOp (ShlCl/ShrCl/SarCl/RolCl/
    // RorCl), b_kind=OpKind::Reg, reg_b=RCX 槽。handler 复用 build_shift:
    //   - b_kind=Reg 路径永远走 T6=1 分支，count 从 regs[T7] 取（即 RCX）
    //   - 与 imm 变体共享同一段汇编，唯一差异是 VmOp 编号让 dispatch 跳此处
    //   - 五个 cl 变体仅 native op 字符串不同 ("shl"/"shr"/"sar"/"rol"/"ror")
    // 独立 VmOp 编码让字节码语义显式、asm_dump 可读、与 imm 变体严格区分。
    // MIT-433: rolcl/rorcl 与 imm 形同面——native ROL/ROR 的 flags 写入面
    // 与计数来源无关，同样走 flags_tail_partial（与 build_rol/build_ror 对齐）。
    std::string build_shl_cl(u64 d) const { return build_shift("shl", d); }
    std::string build_shr_cl(u64 d) const { return build_shift("shr", d); }
    std::string build_sar_cl(u64 d) const { return build_shift("sar", d); }
    std::string build_rol_cl(u64 d) const { return build_shift("rol", d, true); }
    std::string build_ror_cl(u64 d) const { return build_shift("ror", d, true); }

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

    // =======================================================================
    // MIT-443 (X3a)：x86 (KS_MODE_32) 码体生成面 —— X3b 起 57 handler
    //（X3c 批次三后 60：协议面三件套收口）。
    //
    // 与 x64 面的关系：x64 emit 代码一概不经此处（arch 分叉收敛在 KsSession
    // 模式 / roll / build_entry / build_dispatch / handler 表选择五处），x64
    // 输出逐字节不变（D6）。x86 寄存器/栈/flags 模型见文件头 kX86 池注：
    //   - 寄存器：ctx_/base_（callee-saved）+ 临时 t_[0..3]（t_[0]/t_[1] =
    //     数据临时，字节可编码约束；t_[2]/t_[3] = 寻址临时）；pc_ = ecx 寄
    //     存器常驻（MIT-494t②，同步点：dispatch 解密 t_[1] 往返 / Cl 移位
    //     族块内 sync+还原 / CallGate 窗口前后 / Halt 出口写回）；flags_ 内
    //     存常驻 [ctx+0x98]（既有持久槽，零新字段，D4）。
    //   - 执行帧：kX86FrameSize 常量槽（decode 位域/aux/setcc 捕获区）。
    //   - flags：ctx+0x98 dword 访问，位布局 ZF/CF/OF/SF/PF = bit0..4 不变。
    //   - size：S8/S16/S32 三路（S64 块防御 no-op —— x86 翻译器不产 S64）。
    //   - 写回：slot 高半字恒 0 不变量（x86 guest 值域 ≤32 位，ctx 零初始化
    //     + 全部写路径只触低 dword 共同维持）；S8/S16 低 dword RMW 保高位 =
    //     x64 alias_write 的 32 位等价，S32 直写低 dword。
    // =======================================================================

    // ---- x86 名字辅助 -----------------------------------------------------
    // 32 位寄存器名（dword 形式）。x86 路径禁用 r64()（rax 等 64 位名 32 位
    // 模式不可编码），统一走本函数 / rs(r,2)；8 位名仅对字节可编码寄存器
    //（t_[0]/t_[1]，roll_x86 约束）经 rs(r,0) 触达。
    const char* r32x(int r) const { return kPhys[r].r32; }

    // x86 执行帧槽文本。
    std::string xf(u64 off) const { return std::string("[esp + ") + imm(off) + "]"; }
    // VM 寄存器槽寻址文本（idx = 寻址临时；宽度形式由调用方配 mptr）。
    std::string xslot(int idx_temp) const {
        return std::string("[") + r32x(ctx_) + " + " + r32x(idx_temp) + "*8 + 0x10]";
    }

    // x86 callee-saved 压栈/恢复序（单一来源）：[base_, 其余 3 个按
    // kX86CalleeSaved 序]。entry 按序 push（base_ 最先，供 call/pop idiom），
    // halt 按严格逆序 pop（对称镜像，x64 build_entry/build_halt 同款纪律）。
    std::array<int, 4> x86_save_order() const {
        std::array<int, 4> order{};
        order[0] = base_;
        int j = 1;
        for (int r : kX86CalleeSaved)
            if (r != base_) order[j++] = r;
        return order;
    }

    // ---- x86 入口块（地址 0；跌入 dispatch） ------------------------------
    std::string build_entry_x86() const {
        const auto order = x86_save_order();
        std::string o;
        o += "vm_entry:\n";
        // D2（项目主拍板）：BASE 取址 = call/pop idiom —— push(1B) +
        // call rel32(5B) 确定性 6 字节，pop 得 .next 码内偏移 6，sub 回指码
        // 基址（vm_entry @ 0）。base 寄存器原值必须先压栈（callee-saved 契
        // 约），压栈序 = 其余 3 个保持在后，halt 按严格逆序弹出。
        // x86 push r32 恒 1 字节（无 REX）、call rel32 恒 5 字节 —— 偏移常
        // 量 6 = 1+5 确定性；漂移由 x86 电池反汇编断言当场炸出。
        o += std::string("    push ") + r32x(order[0]) + "\n";
        o += "    call x86_base_next\n";
        o += "x86_base_next:\n";
        o += std::string("    pop ") + r32x(order[0]) + "\n";
        o += std::string("    sub ") + r32x(order[0]) + ", " + imm(6) + "\n";
        // 其余 3 个 x86 callee-saved 全量保存（随机分配可能选中其中任意两个
        // 作 ctx_/base_，宿主原值一律保存/恢复）。
        for (int i = 1; i < 4; ++i)
            o += std::string("    push ") + r32x(order[i]) + "\n";
        // cdecl：[esp]=ret、[esp+4]=ctx；4 push 后 ctx 指针 = [esp + 0x14]
        //（4*4 push + 4 retaddr）。
        o += std::string("    mov ") + r32x(ctx_) + ", dword ptr [esp + " +
             imm(0x14) + "]\n";
        // 执行帧（常量槽；esp 此后跨指令稳定 —— x86 handler 无动态 push/pop）。
        o += std::string("    sub esp, ") + imm(kX86FrameSize) + "\n";
        // host_rsp 记账（callgate X3c B.1 消费：窗口锚 + 调后重基；槽高半
        // 字依赖零初始化不变量）。
        o += std::string("    mov dword ptr [") + r32x(ctx_) + " + 0x128], esp\n";
        // pc MIT-494t②：装载进 ecx（寄存器常驻——dispatch 以 [t0+ecx*8] 取
        // 指、advance/taken 加算；flags_ 仍内存常驻 [ctx+0x98]）。同步点 =
        // dispatch 解密（t_[1] 往返）/ Cl 移位族（cl 复用）/ CallGate
        //（native call 毁 ecx）/ Halt 出口写回，见各 build_*_x86 注。
        o += std::string("    mov ecx, dword ptr [") + r32x(ctx_) + " + 0x8]\n";
        return o;
    }

    // ---- x86 dispatch 块（table_off 两遍法同 x64；哑值强制 disp32）--------
    // D3（项目主拍板）：跳表保 8B 表项 —— x86 读表项低 dword（handler 偏移
    // <4GB），表字节格式与 x64 逐位一致，掩码/两遍法逻辑零改动。
    std::string build_dispatch_x86(u64 table_off) const {
        std::string o;
        // MIT-494t②：pc 寄存器常驻 ecx —— 取指索引直达（省 [ctx+0x8] 装载；
        // advance/jmp/jcc-taken 同步省 RMW）。同步点三处：dispatch 解密
        // （ecx 复用前 t_[1] 存取往返）、Cl 移位族（cl 复用，块内 sync+还
        // 原）、CallGate（native call 毁 caller-saved ecx，窗口前后 sync）。
        o += std::string("    mov ") + r32x(t_[0]) + ", dword ptr [" + r32x(ctx_) + "]\n";
        // MIT-494t③'：lo 取指后经 t_[3] 交接 decode_prelude_x86（5 次帧槽
        // 装载 → 5 次寄存器传送；帧槽本身仍落帧——handler 尾段 flags-dead
        // test / reextract 类读发生在数据临时消费之后，寄存器不保真）。
        // 指令字 64 位双字取指落帧（lo=域 0..31 → kX86FInsnLo；hi=aux → kX86FAux）。
        o += std::string("    mov ") + r32x(t_[2]) + ", dword ptr [" + r32x(t_[0]) +
             " + ecx*8]\n";
        o += std::string("    mov ") + r32x(t_[3]) + ", dword ptr [" + r32x(t_[0]) +
             " + ecx*8 + " + imm(4) + "]\n";
        o += std::string("    mov dword ptr ") + xf(kX86FInsnLo) + ", " + r32x(t_[2]) + "\n";
        o += std::string("    mov dword ptr ") + xf(kX86FAux) + ", " + r32x(t_[3]) + "\n";
        if (fetch_decrypt_) {
            // MIT-473: x86 织入——lo/hi 已落帧（帧槽 RW），位置键流解密
            //（K = blob 头 seed + 字序 × STEP，仅依赖字序；初态 = blob 头
            // seed 字段 = 流基址 -16）。
            // ⚠️ 别名纪律（MIT-494t 验收 C1）：key0 载体固定 eax，而
            // t_[0..3] 两两互异（roll_x86 去重保证）→ t_[1..3] 至多一个是
            // eax——pc 暂存目标由生成期选定 t_scratch = 第一个非 eax 的
            // t_[1..3]（恒可选），顺序 = 先暂存 pc、再读 key0、后乘加。首
            // 版曾把 key0 读进 eax 之后再 `mov t_[1], ecx` 暂存——t_[1]==eax
            // 时把 key0 覆盖成 pc → K = pc*STEP+pc → 语义损坏（100 seed 探
            // 针 37% 失败，100% 与 t_[1]==eax 相关；电池旧种子集
            // {1,7,0xC0FFEE} 恰全非 eax 故漏网）。旧 MIT-473 序"先取 PC 再
            // 读 key0"的纪律同源，勿再重排。
            int t_scratch = 1;
            for (int j = 1; j <= 3; ++j) {
                if (t_[j] != 0) { t_scratch = j; break; }   // 0 = kPhys eax
            }
            o += std::string("    mov ") + r32x(t_[t_scratch]) + ", ecx\n";                        // pc 暂存（先于一切复用）
            o += std::string("    mov eax, dword ptr [") + r32x(t_[0]) + " - " + hex(16) + "]\n";  // key0（eax 此刻可毁）
            o += std::string("    imul ecx, ecx, ") + hex(0x9E3779B1ull) + "\n";                   // STEP（ecx 已持 pc）
            o += std::string("    add ecx, eax\n");                                                // K
            o += std::string("    xor dword ptr ") + xf(kX86FInsnLo) + ", ecx\n";
            o += std::string("    xor dword ptr ") + xf(kX86FAux) + ", ecx\n";
            o += std::string("    mov ecx, ") + r32x(t_[t_scratch]) + "\n";                        // pc 还原
            o += std::string("    mov ") + r32x(t_[2]) + ", dword ptr " + xf(kX86FInsnLo) + "\n";  // 解密后 lo
        }
        o += std::string("    mov ") + r32x(t_[3]) + ", " + r32x(t_[2]) + "\n";   // lo 交接（③'）
        o += std::string("    and ") + r32x(t_[2]) + ", " + imm(kTableEntries - 1) + "\n";
        o += std::string("    mov ") + r32x(t_[1]) + ", dword ptr [" + r32x(base_) +
             " + " + r32x(t_[2]) + "*8 + " + hex(table_off) + "]\n";
        o += std::string("    add ") + r32x(t_[1]) + ", " + r32x(base_) + "\n";
        o += std::string("    jmp ") + r32x(t_[1]) + "\n";
        return o;
    }

    // ---- x86 decode：六位域落帧 -------------------------------------------
    // lo 双字 → shr/and → [esp+off]；aux 无需抽取（dispatch 已把指令字高 32
    // 位落帧 kX86FAux，等价 x64 T5=w>>32 的常驻化）。
    // MIT-494t③'：lo 源 = dispatch 交接的 t_[3]（寄存器）——5 次帧槽装载
    // → 5 次寄存器传送；帧槽仍由 dispatch 落帧（handler 尾段 flags-dead
    // test / reextract 类读发生在数据临时消费之后，寄存器不保真）。
    std::string decode_prelude_x86() const {
        struct Field { int shr; int mask; u64 slot; };
        static constexpr Field kFields[] = {
            {18, 0xF,  kX86FSize},
            {14, 0x3,  kX86FAKind},
            {22, 0x1F, kX86FRegA},
            {27, 0x1F, kX86FRegB},
            {16, 0x3,  kX86FBKind},
        };
        std::string o;
        for (const auto& f : kFields) {
            o += std::string("    mov ") + r32x(t_[0]) + ", " + r32x(t_[3]) + "\n";
            o += std::string("    shr ") + r32x(t_[0]) + ", " + imm(f.shr) + "\n";
            o += std::string("    and ") + r32x(t_[0]) + ", " + imm(f.mask) + "\n";
            o += std::string("    mov dword ptr ") + xf(f.slot) + ", " + r32x(t_[0]) + "\n";
        }
        return o;
    }

    // x86 取操作数（load_operand 的 32 位版）：kind==1 → 寄存器槽 dword 读
    //（S32）或 movzx（S8/S16，alias_read 零扩展）；否则立即数（aux 槽按宽度
    // 截取）。结果放 dst（数据临时；字节可编码约束保证 S8 宽度下游 native
    // 子寄存器名可用）。寻址临时固定 t_[2]。
    std::string load_operand_x86(int size, u64 kind_slot, u64 idx_slot, int dst,
                                 const std::string& tag) const {
        const std::string l_imm = "xli" + tag;
        const std::string l_done = "xld" + tag;
        std::string o;
        o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kind_slot) + "\n";
        o += std::string("    cmp ") + r32x(t_[2]) + ", " + imm(1) + "\n";
        o += "    jne " + l_imm + "\n";
        o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(idx_slot) + "\n";
        if (size == 2)
            o += std::string("    mov ") + r32x(dst) + ", dword ptr " + xslot(t_[2]) + "\n";
        else
            o += std::string("    movzx ") + r32x(dst) + ", " + mptr(size) + " " +
                 xslot(t_[2]) + "\n";
        o += "    jmp " + l_done + "\n";
        o += l_imm + ":\n";
        if (size == 2)
            o += std::string("    mov ") + r32x(dst) + ", " + xf(kX86FAux) + "\n";
        else
            o += std::string("    movzx ") + r32x(dst) + ", " + mptr(size) + " " +
                 xf(kX86FAux) + "\n";
        o += l_done + ":\n";
        return o;
    }

    // x86 别名写回（writeback 的 32 位版）：
    //   S32：直写低 dword（32 位 guest 全宽；槽高半字不变量维持 0）。
    //   S8/S16：低 dword RMW 保高位（native 子寄存器写语义 = x64 alias_write
    //     等价；scratch = 另一数据临时，字节可编码约束保证子寄存器名可用）。
    std::string writeback_x86(int size, u64 idx_slot, int val, int scratch) const {
        std::string o;
        o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(idx_slot) + "\n";
        if (size == 2) {
            o += std::string("    mov dword ptr ") + xslot(t_[2]) + ", " + r32x(val) + "\n";
        } else {
            o += std::string("    mov ") + r32x(scratch) + ", dword ptr " + xslot(t_[2]) + "\n";
            o += std::string("    mov ") + rs(scratch, size) + ", " + rs(val, size) + "\n";
            o += std::string("    mov dword ptr ") + xslot(t_[2]) + ", " + r32x(scratch) + "\n";
        }
        return o;
    }

    // x86 setcc 捕获：5 标志落帧捕获区（setcc 全字节写 + movzx 全字节读 ⇒
    // 无需预清零 —— zero5 x86 形 = 空）。Inc/Dec 变体不捕 CF（保留语义，
    // 捕获区 +1 字节为陈旧值不消费）。
    std::string setcc5_x86() const {
        std::string o;
        o += std::string("    setz byte ptr ") + xf(kX86FCC + 0) + "\n";
        o += std::string("    setc byte ptr ") + xf(kX86FCC + 1) + "\n";
        o += std::string("    seto byte ptr ") + xf(kX86FCC + 2) + "\n";
        o += std::string("    sets byte ptr ") + xf(kX86FCC + 3) + "\n";
        o += std::string("    setp byte ptr ") + xf(kX86FCC + 4) + "\n";
        return o;
    }
    std::string setcc4_x86() const {
        std::string o;
        o += std::string("    setz byte ptr ") + xf(kX86FCC + 0) + "\n";
        o += std::string("    seto byte ptr ") + xf(kX86FCC + 2) + "\n";
        o += std::string("    sets byte ptr ") + xf(kX86FCC + 3) + "\n";
        o += std::string("    setp byte ptr ") + xf(kX86FCC + 4) + "\n";
        return o;
    }

    // x86 flags 装配（flags_tail 的 32 位版）+ advance：捕获区 5 字节 → 位
    // 布局 ZF/CF/OF/SF/PF = bit0..4 → [ctx+0x98]（= regs[17] 同槽，一处写两
    // 见，x64 flags_tail 同款）。cf_from_old（Inc/Dec 保留语义）：CF 不取捕
    // 获区，取 [ctx+0x98] 旧值 bit1 —— 读取发生在新值写入前（装配首段读、
    // 末条才写）。
    std::string flags_tail_x86(bool cf_from_old, u64 dispatch) const {
        const std::string skip = "fskip" + std::to_string(seq());
        const std::string A = r32x(t_[0]);
        const std::string B = r32x(t_[1]);
        std::string o;
        // MIT-474 (T18) flags-dead 标记路由（x86 版）：标记在指令字 lo 双字
        // 的 cond 位 2（帧槽内存 test，无寄存器压力）。
        o += std::string("    test dword ptr ") + xf(kX86FInsnLo) + ", " +
             hex(1u << 20) + "\n";
        o += "    jnz " + skip + "\n";
        o += std::string("    movzx ") + A + ", byte ptr " + xf(kX86FCC + 0) + "\n";
        if (cf_from_old) {
            o += std::string("    mov ") + B + ", dword ptr [" + r32x(ctx_) + " + 0x98]\n";
            o += std::string("    shr ") + B + ", " + imm(1) + "\n";
            o += std::string("    and ") + B + ", " + imm(1) + "\n";
            o += std::string("    shl ") + B + ", " + imm(1) + "\n";
            o += std::string("    or ") + A + ", " + B + "\n";
        } else {
            o += std::string("    movzx ") + B + ", byte ptr " + xf(kX86FCC + 1) + "\n";
            o += std::string("    shl ") + B + ", " + imm(1) + "\n";
            o += std::string("    or ") + A + ", " + B + "\n";
        }
        o += std::string("    movzx ") + B + ", byte ptr " + xf(kX86FCC + 2) + "\n";
        o += std::string("    shl ") + B + ", " + imm(2) + "\n";
        o += std::string("    or ") + A + ", " + B + "\n";
        o += std::string("    movzx ") + B + ", byte ptr " + xf(kX86FCC + 3) + "\n";
        o += std::string("    shl ") + B + ", " + imm(3) + "\n";
        o += std::string("    or ") + A + ", " + B + "\n";
        o += std::string("    movzx ") + B + ", byte ptr " + xf(kX86FCC + 4) + "\n";
        o += std::string("    shl ") + B + ", " + imm(4) + "\n";
        o += std::string("    or ") + A + ", " + B + "\n";
        o += std::string("    mov dword ptr [") + r32x(ctx_) + " + 0x98], " + A + "\n";
        o += skip + ":\n";
        o += advance_x86(dispatch);
        return o;
    }

    // x86 flags partial-preserve 装配（flags_tail_partial 的 32 位版，MIT-433
    // MIT-P1 同案平移）：ROL/ROR 只写 CF/OF（SDM Vol. 2），ZF/SF/PF 必须从
    // [ctx+0x98] 旧值原位保留 —— 捕获区的 ZF/SF/PF 是宿主 handler 内部状态
    // （本 path 前置 and/移位的宿主 flags），消费即污染 guest 视角（432 复现
    // 形态）。x86 无 zero5（setcc 落帧），污染源 = 捕获前最后一条宿主指令，
    // 与 x64 xor 污染同理，故 rot 族尾部独立走本装配：
    //   new_flags = (old & 0x19) | (CF<<1) | (OF<<2)
    // 旧值读取发生在写入前（首段读、末条写 —— flags_tail_x86 cf_from_old 同款
    // 顺序纪律）。G8a flagless 变体（rorx/shlx/sarx/shrx）接入点预留同 x64
    // flags_tail_partial 注（届时并入保留掩码 0x1F 全保留、零 or 入）。
    std::string flags_tail_partial_x86(u64 dispatch) const {
        const std::string skip = "fskip" + std::to_string(seq());
        const std::string A = r32x(t_[0]);
        const std::string B = r32x(t_[1]);
        std::string o;
        // MIT-474: 同 flags_tail_x86 的标记路由（合并型写，x86 版）。
        o += std::string("    test dword ptr ") + xf(kX86FInsnLo) + ", " +
             hex(1u << 20) + "\n";
        o += "    jnz " + skip + "\n";
        o += std::string("    mov ") + A + ", dword ptr [" + r32x(ctx_) + " + 0x98]\n";
        o += std::string("    and ") + A + ", " + imm(0x19) + "\n";
        o += std::string("    movzx ") + B + ", byte ptr " + xf(kX86FCC + 1) + "\n";
        o += std::string("    shl ") + B + ", " + imm(1) + "\n";
        o += std::string("    or ") + A + ", " + B + "\n";
        o += std::string("    movzx ") + B + ", byte ptr " + xf(kX86FCC + 2) + "\n";
        o += std::string("    shl ") + B + ", " + imm(2) + "\n";
        o += std::string("    or ") + A + ", " + B + "\n";
        o += std::string("    mov dword ptr [") + r32x(ctx_) + " + 0x98], " + A + "\n";
        o += skip + ":\n";
        o += advance_x86(dispatch);
        return o;
    }

    // x86 advance：pc 寄存器常驻（ecx，MIT-494t②），+1 后回 dispatch。
    // Cl 移位族在块内 sync/还原 ecx（mov 不改 flags，jz 判据保真）后仍走
    // 本寄存器形。
    std::string advance_x86(u64 dispatch) const {
        return std::string("    add ecx, ") + imm(1) + "\n    jmp " + hex(dispatch) + "\n";
    }

    // x86 尺寸链：3 路各带显式 cmp/je（S8/S16/S32，perm 随机）+ 链尾顺延 =
    // S64 防御 no-op（直接前进 —— x86 翻译器不产 S64 VmOp；命中即整条
    // no-op；X0 "断言 qword/REX 形不可达" 的落地形态）。首版只放 2 个 cmp
    // 让 perm[2] 块顺延跌入是错误结构 —— S16 曾因此整路空转（电池当场
    // 炸出）；三路必须全部显式分派，链尾只属于防御出口。
    std::string size_chain_x86(const std::string blocks[3], const std::string& tag,
                               u64 dispatch) const {
        std::string o;
        // MIT-474：同 x64——cond 位 2 标记随域落帧，链头先掩码低 2 位。
        o += std::string("    and dword ptr ") + xf(kX86FSize) + ", 3\n";
        for (int i = 0; i < 3; ++i) {
            o += std::string("    cmp dword ptr ") + xf(kX86FSize) + ", " +
                 imm(x86_size_perm_[i]) + "\n";
            o += "    je xsz" + std::to_string(x86_size_perm_[i]) + "_" + tag + "\n";
        }
        o += advance_x86(dispatch);   // S64 防御 no-op 出口（链尾顺延）
        for (int i = 0; i < 3; ++i) {
            const int s = x86_size_perm_[i];
            o += "xsz" + std::to_string(s) + "_" + tag + ":\n" + blocks[s];
        }
        return o;
    }

    // x86 二元计算（native=add/sub/and/or/xor/test；Cmp 用 sub 无写回）。
    // 与 x64 build_binary 同构：load A → load B → native（本机宽度直产真
    // flags）→ setcc 捕获 → 写回 → flags 装配。zero5 x86 形 = 空。
    std::string build_binary_x86(const char* native, u64 dispatch, bool do_wb) const {
        const std::string tag = std::string(native) + std::to_string(seq());
        const std::string tail_lbl = "xtail_" + tag;
        std::string blocks[3];
        for (int s = 0; s < 3; ++s) {
            const std::string stag = tag + "_" + std::to_string(s);
            std::string o;
            o += load_operand_x86(s, kX86FAKind, kX86FRegA, t_[0], "a" + stag);
            o += load_operand_x86(s, kX86FBKind, kX86FRegB, t_[1], "b" + stag);
            o += std::string("    ") + native + " " + rs(t_[0], s) + ", " + rs(t_[1], s) + "\n";
            o += setcc5_x86();
            if (do_wb) o += writeback_x86(s, kX86FRegA, t_[0], t_[1]);
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude_x86() + size_chain_x86(blocks, tag, dispatch) +
               tail_lbl + ":\n" + flags_tail_x86(false, dispatch);
    }

    // x86 Mov/Lea（v1 Lea=值传送）：b 操作数 → a 槽。无 flags。
    std::string build_mov_x86(u64 dispatch) const {
        const std::string tag = "xmov" + std::to_string(seq());
        const std::string tail_lbl = "xtail_" + tag;
        std::string blocks[3];
        for (int s = 0; s < 3; ++s) {
            const std::string stag = tag + "_" + std::to_string(s);
            std::string o;
            o += load_operand_x86(s, kX86FBKind, kX86FRegB, t_[0], "b" + stag);
            o += writeback_x86(s, kX86FRegA, t_[0], t_[1]);
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude_x86() + size_chain_x86(blocks, tag, dispatch) +
               tail_lbl + ":\n" + advance_x86(dispatch);
    }

    // x86 Inc/Dec（CF 保留，ZF/SF/OF/PF 更新 —— build_incdec 的 32 位版；
    // flags_tail_x86(true) 从 ctx+0x98 旧值取 CF）。
    std::string build_incdec_x86(const char* native, u64 dispatch) const {
        const std::string tag = std::string(native) + std::to_string(seq());
        const std::string tail_lbl = "xtail_" + tag;
        std::string blocks[3];
        for (int s = 0; s < 3; ++s) {
            const std::string stag = tag + "_" + std::to_string(s);
            std::string o;
            o += load_operand_x86(s, kX86FAKind, kX86FRegA, t_[0], "a" + stag);
            o += std::string("    ") + native + " " + rs(t_[0], s) + "\n";
            o += setcc4_x86();
            o += writeback_x86(s, kX86FRegA, t_[0], t_[1]);
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude_x86() + size_chain_x86(blocks, tag, dispatch) +
               tail_lbl + ":\n" + flags_tail_x86(true, dispatch);
    }

    // x86 Load：a=数据目的槽，b=地址槽（dword VA）；[addr] 宽度读 → 写回。
    std::string build_load_x86(u64 dispatch) const {
        const std::string tag = "xld" + std::to_string(seq());
        const std::string tail_lbl = "xtail_" + tag;
        std::string blocks[3];
        for (int s = 0; s < 3; ++s) {
            const std::string stag = tag + "_" + std::to_string(s);
            std::string o;
            o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegB) + "\n";
            o += std::string("    mov ") + r32x(t_[1]) + ", dword ptr " + xslot(t_[2]) + "\n";
            if (s == 2)
                o += std::string("    mov ") + r32x(t_[0]) + ", dword ptr [" +
                     r32x(t_[1]) + "]\n";
            else
                o += std::string("    movzx ") + r32x(t_[0]) + ", " + mptr(s) + " [" +
                     r32x(t_[1]) + "]\n";
            o += writeback_x86(s, kX86FRegA, t_[0], t_[1]);
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude_x86() + size_chain_x86(blocks, tag, dispatch) +
               tail_lbl + ":\n" + advance_x86(dispatch);
    }

    // x86 Store：a=地址槽（dword VA），b=数据；宽度写 [addr]。
    std::string build_store_x86(u64 dispatch) const {
        const std::string tag = "xst" + std::to_string(seq());
        const std::string tail_lbl = "xtail_" + tag;
        std::string blocks[3];
        for (int s = 0; s < 3; ++s) {
            const std::string stag = tag + "_" + std::to_string(s);
            std::string o;
            o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegA) + "\n";
            o += std::string("    mov ") + r32x(t_[1]) + ", dword ptr " + xslot(t_[2]) + "\n";
            o += load_operand_x86(s, kX86FBKind, kX86FRegB, t_[0], "b" + stag);
            o += std::string("    mov ") + mptr(s) + " [" + r32x(t_[1]) + "], " +
                 rs(t_[0], s) + "\n";
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude_x86() + size_chain_x86(blocks, tag, dispatch) +
               tail_lbl + ":\n" + advance_x86(dispatch);
    }

    // x86 条件求值（cond_eval 的 32 位版）：[ctx+0x98] dword 位域 → t_[0] =
    // 0/1（flags_ 内存常驻；t_[1] 作第二临时，调用点两临时均空闲）。
    std::string cond_eval_x86(int cond) const {
        const std::string F = std::string("dword ptr [") + r32x(ctx_) + " + 0x98]";
        const std::string D = r32x(t_[0]);
        const std::string S = r32x(t_[1]);
        auto bit = [&](int b) {
            std::string o = "    mov " + D + ", " + F + "\n";
            if (b) o += "    shr " + D + ", " + imm(b) + "\n";
            o += "    and " + D + ", " + imm(1) + "\n";
            return o;
        };
        auto invert = [&]() { return std::string("    xor ") + D + ", " + imm(1) + "\n"; };
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
                o += "    mov " + D + ", " + F + "\n    mov " + S + ", " + D + "\n";
                o += "    shr " + D + ", " + imm(1) + "\n";
                o += "    or " + D + ", " + S + "\n    and " + D + ", " + imm(1) + "\n";
                if (cond == int(ir::Cond::A)) o += invert();
                return o;
            }
            case ir::Cond::L:  // SF != OF
            case ir::Cond::Ge: { // !(SF != OF)
                std::string o;
                o += "    mov " + D + ", " + F + "\n    mov " + S + ", " + D + "\n";
                o += "    shr " + D + ", " + imm(3) + "\n    shr " + S + ", " + imm(2) + "\n";
                o += "    xor " + D + ", " + S + "\n    and " + D + ", " + imm(1) + "\n";
                if (cond == int(ir::Cond::Ge)) o += invert();
                return o;
            }
            case ir::Cond::Le:  // ZF | (SF != OF)
            case ir::Cond::G: { // !(ZF | (SF != OF))
                std::string o;
                o += "    mov " + D + ", " + F + "\n    mov " + S + ", " + D + "\n";
                o += "    shr " + D + ", " + imm(3) + "\n    shr " + S + ", " + imm(2) + "\n";
                o += "    xor " + D + ", " + S + "\n    and " + D + ", " + imm(1) + "\n";
                o += "    mov " + S + ", " + F + "\n    and " + S + ", " + imm(1) + "\n";
                o += "    or " + D + ", " + S + "\n";
                if (cond == int(ir::Cond::G)) o += invert();
                return o;
            }
        }
        throw std::runtime_error("regvm runtime: bad cond");
    }

    // x86 Jcc：cond = cond_or_size（帧槽）；16 路链（cond_perm 随机，同 x64
    // 机制）→ cond_eval_x86 → t_[0]=0/1。taken：pc dword += aux 原始双字
    //（32 位模加 ≡ x64 sext32 加法 —— pc 恒在 32 位值域）；不取 +1。
    // HandlerDef 表项兼容包装（generate_runtime_arch 按 "jcc" 名特殊化接管）。
    std::string build_x86_jcc(u64 dispatch) const {
        return build_x86_jcc_at(dispatch, 0, 0x4000'0000ull);
    }

    // x86 cond 跳表（MIT-494s，build_jcc_at 的 KS_MODE_32 镜像；机制与块序
    // 见 x64 侧注）。差异：cond 在 kX86FSize 帧槽（decode_prelude_x86 首字
    // 段落点）→ fetch 先装载 t_[2] 再取表；表项 8B 步距读低 dword（D3）。
    std::string build_x86_jcc_at(u64 dispatch, u64 self_off, u64 ctbl_off) const {
        const std::string tag = "xjcc" + std::to_string(seq());
        const std::string test_lbl = "xjt_" + tag;
        const std::string fall_lbl = "xjf_" + tag;
        const std::string prelude = decode_prelude_x86();
        const std::string fetch =
            std::string("    mov ") + r32x(t_[2]) + ", dword ptr " + xf(kX86FSize) + "\n" +
            "    mov " + r32x(t_[2]) + ", dword ptr [" + r32x(base_) + " + " +
            r32x(t_[2]) + "*8 + " + hex(ctbl_off) + "]\n" +
            "    add " + r32x(t_[2]) + ", " + r32x(base_) + "\n" +
            "    jmp " + r32x(t_[2]) + "\n";
        // 尾部段前置 + 前缀累进测量（EB/E9 距离选宽铁律见 x64 侧注）。
        const std::string tail =
            test_lbl + ":\n" +
            std::string("    test ") + r32x(t_[0]) + ", " + r32x(t_[0]) + "\n" +
            "    jz " + fall_lbl + "\n" +
            std::string("    mov ") + r32x(t_[0]) + ", " + xf(kX86FAux) + "\n" +
            "    add ecx, " + r32x(t_[0]) + "\n" +   // pc（MIT-494t② 寄存器常驻）
            "    jmp " + hex(dispatch) + "\n" +
            fall_lbl + ":\n" + advance_x86(dispatch);
        int order[16];
        order[0] = cond_perm_[15];
        for (int i = 0; i < 15; ++i) order[i + 1] = cond_perm_[i];
        auto blk_text = [&](int k) {
            return "xcc" + std::to_string(order[k]) + "_" + tag + ":\n" +
                   cond_eval_x86(order[k]) + "    jmp " + test_lbl + "\n";
        };
        {
            KsSession ks{unsigned(KS_MODE_32)};   // 花括号：防 most-vexing-parse
            std::string prefix = prelude + fetch + tail;
            for (int k = 0; k < 16; ++k) {
                // 测量用真实 self_off（EB/E9 距离铁律，见 x64 侧注）。
                last_cond_table_[order[k]] =
                    self_off + ks.assemble(prefix, self_off, "xjcc prefix").size();
                prefix += blk_text(k);
            }
        }
        std::string out = prelude + fetch + tail;
        for (int k = 0; k < 16; ++k) out += blk_text(k);
        return out;
    }

    // x86 Jmp：pc（ecx，MIT-494t②）+= aux 原始双字，无条件。
    std::string build_jmp_x86(u64 dispatch) const {
        std::string o;
        o += std::string("    mov ") + r32x(t_[0]) + ", " + xf(kX86FAux) + "\n";
        o += std::string("    add ecx, ") + r32x(t_[0]) + "\n";
        o += "    jmp " + hex(dispatch) + "\n";
        return o;
    }

    // x86 Halt：写回 pc+1（恢复友好）与 ret_value（=regs[0] 低 dword；槽高
    // 半字清零维持不变量），弃执行帧，逆序恢复 callee-saved，ret（cdecl：
    // 不清调用方参数）。弹出序 = 入口压栈序的严格镜像：base 最先压、最后弹。
    std::string build_halt_x86(u64 /*dispatch*/) const {
        const auto order = x86_save_order();
        std::string o;
        // pc+1（寄存器常驻）+ 出口同步写回 [ctx+0x8]（恢复友好语义不变）。
        o += std::string("    add ecx, ") + imm(1) + "\n";
        o += std::string("    mov dword ptr [") + r32x(ctx_) + " + 0x8], ecx\n";
        o += std::string("    mov ") + r32x(t_[0]) + ", dword ptr [" + r32x(ctx_) +
             " + 0x10]\n";
        o += std::string("    mov dword ptr [") + r32x(ctx_) + " + 0x118], " +
             r32x(t_[0]) + "\n";
        o += std::string("    mov dword ptr [") + r32x(ctx_) + " + 0x11C], " + imm(0) + "\n";
        o += std::string("    add esp, ") + imm(kX86FrameSize) + "\n";
        for (int i = 3; i >= 0; --i)
            o += std::string("    pop ") + r32x(order[i]) + "\n";
        o += "    ret\n";
        return o;
    }

    // x86 Nop：直接前进。
    std::string build_nop_x86(u64 dispatch) const { return advance_x86(dispatch); }

    // x86 GetFlags：reg_a 槽 = [ctx+0x98]（dword；槽高半字不变量维持 0）。
    std::string build_getflags_x86(u64 dispatch) const {
        std::string o = decode_prelude_x86();
        o += std::string("    mov ") + r32x(t_[0]) + ", dword ptr [" + r32x(ctx_) +
             " + 0x98]\n";
        o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegA) + "\n";
        o += std::string("    mov dword ptr ") + xslot(t_[2]) + ", " + r32x(t_[0]) + "\n";
        o += advance_x86(dispatch);
        return o;
    }

    // x86 SetFlags：[ctx+0x98] = reg_a 槽低 5 位。
    std::string build_setflags_x86(u64 dispatch) const {
        std::string o = decode_prelude_x86();
        o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegA) + "\n";
        o += std::string("    mov ") + r32x(t_[0]) + ", dword ptr " + xslot(t_[2]) + "\n";
        o += std::string("    and ") + r32x(t_[0]) + ", " + imm(0x1F) + "\n";
        o += std::string("    mov dword ptr [") + r32x(ctx_) + " + 0x98], " + r32x(t_[0]) + "\n";
        o += advance_x86(dispatch);
        return o;
    }

    // ---- x86 批迁 builder（X3b：A 档宽度模板平移 + B 档 GP） ----------------
    //
    // 与 x64 模板的关系：逐 op 以 x64 同名 builder 为蓝本做 32 位平移（数据
    // 临时 t_[0]/t_[1] 字节可编码约束、setcc 落帧捕获区、3 路尺寸链、S64 块
    // 防御出口经 size_chain_x86 链尾顺延）。与 x64 的结构性差异三处：
    //   1. pc_/flags_ 内存常驻 ⇒ x64 的 spill_pcflags_raxrdx / zero5 全族
    //      不需要（物理 eax/edx 是临时，毁之为无害；宿主 flags 由 bt/捕获区
    //      协议显式搬运，不经 xor 清零通路）；
    //   2. 寄存器槽索引/位域一律从执行帧槽（kX86F*）重取，替代 x64 的
    //      reextract_a（从 T8 重提）—— setcc5_x86 不写寄存器，帧槽即真相源；
    //   3. 隐式寄存器指令（mul 的 eax、cmpxchg 的 al/ax/eax、cdq 的 edx）与
    //      数据临时可能物理重合（t_[0]/t_[1] ∈ {eax,edx,ebx}），载入顺序按
    //      "被隐式指令覆写的物理寄存器最后装载 / 跨越隐式写存活的值不落该
    //      物理寄存器" 排布 —— 生成期已知 t_[0..3] 物理指派，静态可证。

    // x86 Not（无 flags —— build_not 的 32 位版）。
    std::string build_not_x86(u64 dispatch) const {
        const std::string tag = "xnot" + std::to_string(seq());
        const std::string tail_lbl = "xtail_" + tag;
        std::string blocks[3];
        for (int s = 0; s < 3; ++s) {
            const std::string stag = tag + "_" + std::to_string(s);
            std::string o;
            o += load_operand_x86(s, kX86FAKind, kX86FRegA, t_[0], "a" + stag);
            o += std::string("    not ") + rs(t_[0], s) + "\n";
            o += writeback_x86(s, kX86FRegA, t_[0], t_[1]);
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude_x86() + size_chain_x86(blocks, tag, dispatch) +
               tail_lbl + ":\n" + advance_x86(dispatch);
    }

    // x86 Neg（flags 全量 —— build_neg 的 32 位版）。neg 0 → CF=0、neg 非 0
    // → CF=1，其余标志 native 直产；setcc5_x86 落帧后 flags_tail_x86 全量装配。
    std::string build_neg_x86(u64 dispatch) const {
        const std::string tag = "xneg" + std::to_string(seq());
        const std::string tail_lbl = "xtail_" + tag;
        std::string blocks[3];
        for (int s = 0; s < 3; ++s) {
            const std::string stag = tag + "_" + std::to_string(s);
            std::string o;
            o += load_operand_x86(s, kX86FAKind, kX86FRegA, t_[0], "a" + stag);
            o += std::string("    neg ") + rs(t_[0], s) + "\n";
            o += setcc5_x86();
            o += writeback_x86(s, kX86FRegA, t_[0], t_[1]);
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude_x86() + size_chain_x86(blocks, tag, dispatch) +
               tail_lbl + ":\n" + flags_tail_x86(false, dispatch);
    }

    // x86 Adc/Sbb（flags 全量 + CF_in —— build_adc/build_sbb 的 32 位版）。
    // 与 build_binary_x86 不可共用：CF_in 必须显式搬进宿主 CF。x64 用
    // zero5→bt flags_ 链路；x86 无 zero5（捕获落帧、宿主 flags 无人为污染），
    // 直接 bt [ctx+0x98], 1（flags 位布局 bit1 = CF，isa::kFlagCF 同源）：
    //   load A → t0   (mov/movzx 不改宿主 flags)
    //   load B → t1   (同上)
    //   bt  [ctx+0x98], 1   (宿主 CF = guest CF_in)
    //   adc/sbb T0, T1      (native 全 flags 直产)
    //   setcc5_x86 → writeback → flags_tail_x86(false)
    // Sbb 借位语义（CF=1 iff 下溢）与 Adc 进位语义均由 native 直读，与 SDM
    // 逐位一致（x64 build_adc/build_sbb 注同源）。
    std::string build_adc_sbb_x86(const char* native, u64 dispatch) const {
        const std::string tag = std::string(native) + std::to_string(seq());
        const std::string tail_lbl = "xtail_" + tag;
        std::string blocks[3];
        for (int s = 0; s < 3; ++s) {
            const std::string stag = tag + "_" + std::to_string(s);
            std::string o;
            o += load_operand_x86(s, kX86FAKind, kX86FRegA, t_[0], "a" + stag);
            o += load_operand_x86(s, kX86FBKind, kX86FRegB, t_[1], "b" + stag);
            o += std::string("    bt dword ptr [") + r32x(ctx_) + " + 0x98], " + imm(1) + "\n";
            o += std::string("    ") + native + " " + rs(t_[0], s) + ", " + rs(t_[1], s) + "\n";
            o += setcc5_x86();
            o += writeback_x86(s, kX86FRegA, t_[0], t_[1]);
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude_x86() + size_chain_x86(blocks, tag, dispatch) +
               tail_lbl + ":\n" + flags_tail_x86(false, dispatch);
    }

    // x86 Imul 2-op（build_imul 的 32 位版）。S8 块防御（imul 无 2-op 字节
    // 形式，lifter 亦拒 —— x64 build_imul s=0 同款）；S16 native 合法但 x86
    // lifter 66 前缀入口不产，保留完整实现（reachable 面 = S32）。
    std::string build_imul_x86(u64 dispatch) const {
        const std::string tag = "ximul" + std::to_string(seq());
        const std::string tail_lbl = "xtail_" + tag;
        std::string blocks[3];
        for (int s = 0; s < 3; ++s) {
            const std::string stag = tag + "_" + std::to_string(s);
            std::string o;
            o += load_operand_x86(s, kX86FAKind, kX86FRegA, t_[0], "a" + stag);
            if (s == 0) {
                // S8：imul 无 2-op 形式 —— 防御（x64 s=0 同款：load 后直落 tail）。
            } else {
                o += load_operand_x86(s, kX86FBKind, kX86FRegB, t_[1], "b" + stag);
                o += std::string("    imul ") + rs(t_[0], s) + ", " + rs(t_[1], s) + "\n";
                o += setcc5_x86();
                o += writeback_x86(s, kX86FRegA, t_[0], t_[1]);
            }
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude_x86() + size_chain_x86(blocks, tag, dispatch) +
               tail_lbl + ":\n" + flags_tail_x86(false, dispatch);
    }

    // x86 Mul 单操作数（build_mul 的 32 位版，S32 真面）。
    // native "mul r/m32" 隐式被乘数 = 物理 EAX、结果 = 物理 EDX:EAX —— 与
    // 数据临时物理重合的排布纪律（本节首注 ③）：被 mul 覆写的 EAX/EDX 必须
    // 最后装载，且源操作数不落 EAX（mul eax = eax*eax 错乘）。生成期选
    // 源槽 ts = (t_[0] != eax_idx) ? t_[0] : t_[1]（t_[0]/t_[1] 相异，恒有
    // 非 eax 解）；EDX 可作源（mul r/m 先读后写，"mul edx" 语义正确）。
    // 双槽写回 = build_mul 双结果槽协议的 32 位形：商 Rax 槽低 dword 直写
    //（native 32 位写零扩展高半字，"槽高半字恒 0" 不变量维持）+ Rdx 槽低
    // dword 直写。S8/S16/S64 块防御（x86 lifter 拒 S8 mul、66 前缀拒 S16、
    // S64 不可达 —— 与 x64 s=0/1"仅改 ax"防御面口径一致，此处干脆空块）。
    std::string build_mul_x86(u64 dispatch) const {
        const std::string tag = "xmul" + std::to_string(seq());
        const std::string tail_lbl = "xtail_" + tag;
        constexpr int kEaxIdx = 0;  // kPhys[0] = rax/eax —— 隐式被乘数物理位
        const u8 rax_slot = isa::vm_reg_of(ir::Reg::Rax);  // = 0
        const u8 rdx_slot = isa::vm_reg_of(ir::Reg::Rdx);  // = 2
        const std::string rax_slot_off = imm(static_cast<u64>(rax_slot) * 8 + 0x10);
        const std::string rdx_slot_off = imm(static_cast<u64>(rdx_slot) * 8 + 0x10);
        const int ts = t_[0] != kEaxIdx ? t_[0] : t_[1];  // 源槽 ≠ 物理 eax
        std::string blocks[3];
        for (int s = 0; s < 3; ++s) {
            const std::string stag = tag + "_" + std::to_string(s);
            std::string o;
            if (s == 2) {
                // 源 → ts（reg_b 槽 dword 直读）
                o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegB) + "\n";
                o += std::string("    mov ") + r32x(ts) + ", dword ptr " + xslot(t_[2]) + "\n";
                // 物理 EAX = Rax 槽（被乘数；载入在源之后 —— ts ≠ eax 静态保证）
                o += std::string("    mov eax, dword ptr [") + r32x(ctx_) + " + " +
                     rax_slot_off + "]\n";
                // native mul：edx:eax = eax * ts
                o += std::string("    mul ") + r32x(ts) + "\n";
                // 双槽写回（内存直写，不经临时 —— setcc5_x86 无寄存器副作用）
                o += std::string("    mov dword ptr [") + r32x(ctx_) + " + " +
                     rax_slot_off + "], eax\n";
                o += std::string("    mov dword ptr [") + r32x(ctx_) + " + " +
                     rdx_slot_off + "], edx\n";
                o += setcc5_x86();
            }
            // s=0/1：防御空块（S8 mul 源被 lifter 拒、S16 66 前缀入口拒）
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude_x86() + size_chain_x86(blocks, tag, dispatch) +
               tail_lbl + ":\n" + flags_tail_x86(false, dispatch);
    }

    // x86 Cdq（build_cdq 的 32 位版，S32 真面）：edx = sext(eax)。
    // native cdq 覆写 eax/edx —— x86 无 pc_/flags_ 寄存器常驻（内存槽），无
    // x64 spill_pcflags_raxrdx 对应面；临时毁之为无害。零 flags（SDM：CDQ 不
    // 影响 EFLAGS —— 不捕获不装配，x64 同口径）。S8/S16/S64 块防御（cbw/cwd
    // 非 cdq 家族同形、S64 不可达）。
    std::string build_cdq_x86(u64 dispatch) const {
        const std::string tag = "xcdq" + std::to_string(seq());
        const std::string tail_lbl = "xtail_" + tag;
        const u8 rax_slot = isa::vm_reg_of(ir::Reg::Rax);  // = 0
        const u8 rdx_slot = isa::vm_reg_of(ir::Reg::Rdx);  // = 2
        const std::string rax_slot_off = imm(static_cast<u64>(rax_slot) * 8 + 0x10);
        const std::string rdx_slot_off = imm(static_cast<u64>(rdx_slot) * 8 + 0x10);
        std::string blocks[3];
        for (int s = 0; s < 3; ++s) {
            std::string o;
            if (s == 2) {
                o += std::string("    mov eax, dword ptr [") + r32x(ctx_) + " + " +
                     rax_slot_off + "]\n";
                o += "    cdq\n";
                o += std::string("    mov dword ptr [") + r32x(ctx_) + " + " +
                     rdx_slot_off + "], edx\n";
            }
            // s=0/1：防御空块（cbw/cwd 语义不符 lifter 拒面）
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude_x86() + size_chain_x86(blocks, tag, dispatch) +
               tail_lbl + ":\n" + advance_x86(dispatch);
    }

    // x86 Div/Idiv（build_div_idiv 的 32 位版，S32 真面）—— MIT-X7 批二：
    // X5c 收口钉死的 453 b59b 残面（VmOp::Div/Idiv 78/79 折叠 Halt → x86
    // 白名单闸整函数 gate）解除。D4 语义基准 = x64 build_div_idiv 真镜像
    // （不造第三套语义）：native "div/idiv r/m32" 隐式 dividend = 物理
    // EDX:EAX、商→EAX、余→EDX；除零/商溢出 = 真 #DE（x64 D2.1 同口径：
    // 崩溃形态与未加壳一致，不做 VM 内拦截）；flags 按 Intel undefined ——
    // setcc5_x86 捕 native 真值（照抄 build_imul 处置，同 build_mul_x86 序）。
    // 与数据临时物理重合的排布纪律（本节首注 ③ + build_mul_x86 先例）：
    //   - 除数 → ts：t_[0..3] 首个 ∉ {eax,edx} 的物理位。build_mul_x86 只
    //     需避 eax（mul 装载 EAX），div 装载 EDX:EAX 双位 —— 除数临时若与
    //     EDX 重合会被 dividend 第二步装载覆盖（错除数）。t_[0..3] 四个互异
    //     池位中 {eax,edx} 至多占 2 ⇒ 恒有安全解（生成期静态可判，保险丝
    //     兜底）。t_[2] 是 load_operand_x86 的寻址 scratch，本 handler 用
    //     t_[2] 做槽索引后即空闲，除数落 ts 后不再触任何数据临时。
    //   - 物理 EDX ← Rdx 槽 / EAX ← Rax 槽（先高后低；ts ∉ {eax,edx} 静态
    //     保证除数不被冲）
    //   - native div/idiv ts 直通
    //   - 商(eax)/余(edx) 双槽写回（内存直写；32 位写零扩展高半字，"槽高
    //     半字恒 0"不变量维持，build_xchg S32 同款）
    // 除数读法同 build_mul_x86：reg_b 槽 dword 直读（translator
    // translate_div_idiv 对 Div/Idiv 的 b_kind 恒为 Reg —— REG 直发 / MEM
    // 经 emit_load 折条入 scratch VM reg）。
    // S8/S16 块防御（lifter translate_div_idiv 拒 S8/S16 —— dividend=AX /
    // 0x66 前缀面，x64 s=0/1 空块同款）。
    std::string build_div_idiv_x86(u64 dispatch, const char* native_mn) const {
        const std::string tag =
            std::string("x") + native_mn + std::to_string(seq());
        const std::string tail_lbl = "xtail_" + tag;
        constexpr int kEaxIdx = 0;  // kPhys[0] = rax/eax
        constexpr int kEdxIdx = 1;  // kPhys[1] = rdx/edx
        const u8 rax_slot = isa::vm_reg_of(ir::Reg::Rax);  // = 0
        const u8 rdx_slot = isa::vm_reg_of(ir::Reg::Rdx);  // = 2
        const std::string rax_slot_off = imm(static_cast<u64>(rax_slot) * 8 + 0x10);
        const std::string rdx_slot_off = imm(static_cast<u64>(rdx_slot) * 8 + 0x10);
        int ts = -1;
        for (int i = 0; i < 4; ++i) {
            if (t_[i] != kEaxIdx && t_[i] != kEdxIdx) { ts = t_[i]; break; }
        }
        if (ts < 0)
            throw std::runtime_error("regvm runtime x86: div temp pool broken");
        std::string blocks[3];
        for (int s = 0; s < 3; ++s) {
            std::string o;
            if (s == 2) {
                // 除数 → ts（reg_b 槽 dword 直读；t_[2] = 槽索引 scratch）
                o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegB) + "\n";
                o += std::string("    mov ") + r32x(ts) + ", dword ptr " + xslot(t_[2]) + "\n";
                // dividend：物理 EDX ← Rdx 槽 / EAX ← Rax 槽（先高后低）
                o += std::string("    mov edx, dword ptr [") + r32x(ctx_) + " + " +
                     rdx_slot_off + "]\n";
                o += std::string("    mov eax, dword ptr [") + r32x(ctx_) + " + " +
                     rax_slot_off + "]\n";
                // native 直通: edx:eax ÷ ts → 商 eax, 余 edx
                o += std::string("    ") + native_mn + " " + r32x(ts) + "\n";
                // 商/余双槽写回（内存直写，不经临时 —— setcc5_x86 无寄存器副作用）
                o += std::string("    mov dword ptr [") + r32x(ctx_) + " + " +
                     rax_slot_off + "], eax\n";
                o += std::string("    mov dword ptr [") + r32x(ctx_) + " + " +
                     rdx_slot_off + "], edx\n";
                o += setcc5_x86();
            }
            // s=0/1：防御空块（S8 dividend=AX 语义不符 / S16 0x66 前缀入口拒）
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude_x86() + size_chain_x86(blocks, tag, dispatch) +
               tail_lbl + ":\n" + flags_tail_x86(false, dispatch);
    }

    // x86 Shl/Shr/Sar/Rol/Ror（imm/cl 双形式 —— build_shift 的 32 位版）。
    // 块体与 x64 逐段同构（load A → 计数装载（b_kind 分支）→ 掩码 → 计数 0
    // 出口 → native → setcc5 → 写回），仅三处分叉：
    //   1. 计数掩码 = **0x1F 全宽**：SDM Vol. 2 —— 6 位掩码仅 64 位模式
    //      REX.W 生效，legacy/compat（含 32 位模式）恒 5 位。计数 32..63 在
    //      S32 档：0x1F 掩码 → 0 → 走计数 0 出口（值与 flags 均不动，native
    //      语义）；若沿用 x64 S32 的 0x3F 掩码，计数 32 会漏进 native（内部
    //      再掩 0）且把 and 的宿主 flags 经 setcc 装配进 guest —— 静默污染
    //      （x64 侧同形缺口属既有面，X3b 不触碰，报告披露）。电池
    //      ShiftImmMask 实测钉死（count=0x20 值+flags 双不变）。
    //   2. 计数 0 出口在 flags 装配**前**旁路（x64 同构）—— rol/ror 的
    //      partial 装配同理（SDM: count&31 == 0 时 flags 不受影响）。
    //   3. rol/ror 尾部 = flags_tail_partial_x86（ZF/SF/PF 从 [ctx+0x98] 旧值
    //      保留，仅 CF/OF 照捕装配 —— MIT-433 MIT-P1 案的 32 位平移）。
    // cl 变体与 imm 形式共享本 builder：translator 对 src=Reg 的 shift 发
    // b_kind=Reg（reg_b = RCX 槽），计数装载走同一 b_kind 分支（x64
    // build_shl_cl 同款）；物理 cl = ecx 恒保留于池外，零冲突。
    std::string build_shift_x86(const char* native, u64 dispatch,
                                bool partial_flags = false) const {
        const std::string tag = std::string(native) + std::to_string(seq());
        const std::string adv_lbl = "xadv_" + tag;
        const std::string tail_lbl = "xtail_" + tag;
        std::string blocks[3];
        for (int s = 0; s < 3; ++s) {
            const std::string stag = std::to_string(s) + "_" + tag;
            std::string o;
            o += load_operand_x86(s, kX86FAKind, kX86FRegA, t_[0], "a" + stag);
            // 计数 → t1（Imm=aux 帧槽 / Reg=reg_b 槽 dword 读）。
            o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FBKind) + "\n";
            o += std::string("    cmp ") + r32x(t_[2]) + ", " + imm(1) + "\n";
            o += "    jne xcnti" + stag + "\n";
            o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegB) + "\n";
            o += std::string("    mov ") + r32x(t_[1]) + ", dword ptr " + xslot(t_[2]) + "\n";
            o += "    jmp xcntg" + stag + "\n";
            o += "xcnti" + stag + ":\n";
            o += std::string("    mov ") + r32x(t_[1]) + ", " + xf(kX86FAux) + "\n";
            o += "xcntg" + stag + ":\n";
            // cl 计数装载 + 5 位掩码（32 位模式全宽统一，见上注）。
            // MIT-494t②：pc 常驻 ecx —— 计数即 cl（= ecx 低字节），计数驻
            // 留期间 pc 只存 [ctx+0x8]（sync 于 cl 装载前）；还原在两个出
            // 口（移位路径 writeback 后 / 计数 0 出口 adv_lbl），寄存器
            // advance 才能吃到正确 pc。⚠️ 不可在 jz 前还原——mov ecx 覆盖
            // cl = 计数（T43 电池实测：ShiftCl 语义全错）。
            o += std::string("    mov dword ptr [") + r32x(ctx_) + " + 0x8], ecx\n";
            o += std::string("    mov cl, ") + rs(t_[1], 0) + "\n";
            o += std::string("    and cl, ") + imm(0x1F) + "\n";
            o += "    jz " + adv_lbl + "\n";   // 计数 0：值与 flags 均不变
            o += std::string("    ") + native + " " + rs(t_[0], s) + ", cl\n";
            o += setcc5_x86();
            o += writeback_x86(s, kX86FRegA, t_[0], t_[1]);
            o += std::string("    mov ecx, dword ptr [") + r32x(ctx_) + " + 0x8]\n";
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        std::string out = decode_prelude_x86() + size_chain_x86(blocks, tag, dispatch);
        // 计数 0 出口：块内 jz 前未还原（见上注），此处先还原再寄存器 advance。
        out += adv_lbl + ":\n" +
               std::string("    mov ecx, dword ptr [") + r32x(ctx_) + " + 0x8]\n" +
               advance_x86(dispatch);
        out += tail_lbl + ":\n" +
               (partial_flags ? flags_tail_partial_x86(dispatch) : flags_tail_x86(false, dispatch));
        return out;
    }

    // x86 Movzx/Movsx（build_movzx/build_movsx 的 32 位版）：dst 恒 32 位
    // 槽（x86 lifter dst 宽 = pointer_size = S32），aux[0] = src_size 位
    //（0=S8 / 1=S16 —— MIT-345 编码约定）；native movzx/movsx r32, byte/word
    // ptr [src 槽] 一次完成截取+扩展，dword 直写 dst 槽（"槽高半字恒 0" 不
    // 变量维持）。无 flags、无尺寸链（x64 版 qword 写回对应面的 32 位形）。
    std::string build_extend_x86(const char* native, u64 dispatch) const {
        const std::string tag = std::string(native) + std::to_string(seq());
        const std::string l_sz8 = tag + "_sz8";
        const std::string l_done = tag + "_done";
        std::string o = decode_prelude_x86();
        o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FAux) + "\n";
        o += std::string("    and ") + r32x(t_[2]) + ", " + imm(1) + "\n";
        o += std::string("    cmp ") + r32x(t_[2]) + ", " + imm(1) + "\n";
        o += "    jne " + l_sz8 + "\n";
        // S16 源：word ptr 读 src 槽低 16 位。
        o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegB) + "\n";
        o += std::string("    ") + native + " " + r32x(t_[0]) + ", word ptr " +
             xslot(t_[2]) + "\n";
        o += "    jmp " + l_done + "\n";
        o += l_sz8 + ":\n";
        o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegB) + "\n";
        o += std::string("    ") + native + " " + r32x(t_[0]) + ", byte ptr " +
             xslot(t_[2]) + "\n";
        o += l_done + ":\n";
        o += writeback_x86(2, kX86FRegA, t_[0], t_[1]);
        o += advance_x86(dispatch);
        return o;
    }

    // x86 MovzxMem/MovsxMem（build_movzx_mem/build_movsx_mem 的 32 位版）：
    // reg_b 槽 = 32 位地址（dword），byte/word ptr 读 + 扩展 → dst 槽。
    std::string build_extend_mem_x86(const char* native, u64 dispatch) const {
        const std::string tag = std::string(native) + "m" + std::to_string(seq());
        const std::string l_sz8 = tag + "_sz8";
        const std::string l_done = tag + "_done";
        std::string o = decode_prelude_x86();
        o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FAux) + "\n";
        o += std::string("    and ") + r32x(t_[2]) + ", " + imm(1) + "\n";
        o += std::string("    cmp ") + r32x(t_[2]) + ", " + imm(1) + "\n";
        o += "    jne " + l_sz8 + "\n";
        // S16 源：取地址 → word ptr [addr]。
        o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegB) + "\n";
        o += std::string("    mov ") + r32x(t_[1]) + ", dword ptr " + xslot(t_[2]) + "\n";
        o += std::string("    ") + native + " " + r32x(t_[0]) + ", word ptr [" +
             r32x(t_[1]) + "]\n";
        o += "    jmp " + l_done + "\n";
        o += l_sz8 + ":\n";
        o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegB) + "\n";
        o += std::string("    mov ") + r32x(t_[1]) + ", dword ptr " + xslot(t_[2]) + "\n";
        o += std::string("    ") + native + " " + r32x(t_[0]) + ", byte ptr [" +
             r32x(t_[1]) + "]\n";
        o += l_done + ":\n";
        o += writeback_x86(2, kX86FRegA, t_[0], t_[1]);
        o += advance_x86(dispatch);
        return o;
    }

    // x86 Bswap（build_bswap 的 32 位版，S32 真面）：dword 读 + bswap + dword
    // 直写。S8/S16 块防御（bswap 无 8/16 位形式，SDM Vol. 2；x86 lifter 亦
    // 不产）、S64 走链尾防御出口。
    std::string build_bswap_x86(u64 dispatch) const {
        const std::string tag = "xbswap" + std::to_string(seq());
        const std::string tail_lbl = "xtail_" + tag;
        std::string blocks[3];
        for (int s = 0; s < 3; ++s) {
            std::string o;
            if (s == 2) {
                o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegA) + "\n";
                o += std::string("    mov ") + r32x(t_[0]) + ", dword ptr " + xslot(t_[2]) + "\n";
                o += std::string("    bswap ") + r32x(t_[0]) + "\n";
                o += std::string("    mov dword ptr ") + xslot(t_[2]) + ", " + r32x(t_[0]) + "\n";
            }
            // s=0/1：防御空块（bswap 仅 32/64 位形式）
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude_x86() + size_chain_x86(blocks, tag, dispatch) +
               tail_lbl + ":\n" + advance_x86(dispatch);
    }

    // x86 Xchg（build_xchg 的 32 位版，S32 真面）：双槽 dword 读 + native
    // xchg r32, r32 + 双槽 dword 写回（槽高位保留语义 = x64 S32 档同款）。
    // t_[2] 恒作槽索引载体（roll_x86 保证 t_[2] ∉ {t_[0], t_[1]}，读/写四段
    // 复用零冲突）；t_[0]/t_[1] 为交换值对。S8/S16 块防御（MIT-334 派活单
    // 限定 S32/S64 面，REG-REG 形 lifter 强制 S32 —— x64 同口径）。
    std::string build_xchg_x86(u64 dispatch) const {
        const std::string tag = "xxchg" + std::to_string(seq());
        const std::string tail_lbl = "xtail_" + tag;
        std::string blocks[3];
        for (int s = 0; s < 3; ++s) {
            std::string o;
            if (s == 2) {
                o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegA) + "\n";
                o += std::string("    mov ") + r32x(t_[0]) + ", dword ptr " + xslot(t_[2]) + "\n";
                o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegB) + "\n";
                o += std::string("    mov ") + r32x(t_[1]) + ", dword ptr " + xslot(t_[2]) + "\n";
                o += std::string("    xchg ") + r32x(t_[0]) + ", " + r32x(t_[1]) + "\n";
                o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegA) + "\n";
                o += std::string("    mov dword ptr ") + xslot(t_[2]) + ", " + r32x(t_[0]) + "\n";
                o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegB) + "\n";
                o += std::string("    mov dword ptr ") + xslot(t_[2]) + ", " + r32x(t_[1]) + "\n";
            }
            // s=0/1：防御空块
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude_x86() + size_chain_x86(blocks, tag, dispatch) +
               tail_lbl + ":\n" + advance_x86(dispatch);
    }

    // x86 Setcc（build_setcc 的 32 位版）：cond_or_size = ir::Cond 0..15（与
    // Jcc 共享字段，无尺寸链），dst 槽低字节 = cond ? 1 : 0、高 24 位保留
    //（x64 清低字节 or 结果的 dword 对应形）。cond_eval_x86 读内存 flags
    //（[ctx+0x98]），链式 cmp/je 的宿主 flags clobber 无害；槽原值 t_[3]、
    // 结果 t_[0]、索引载体 t_[2] 三寄存器分工（cond_eval_x86 只触 t_[0]/
    // t_[1]，t_[2]/t_[3] 跨链存活）。reads-only flags：不捕获不装配。
    std::string build_setcc_x86(u64 dispatch) const {
        const std::string tag = "xsetcc" + std::to_string(seq());
        const std::string tail_lbl = "xtail_" + tag;
        std::string o = decode_prelude_x86();
        // 1) dst 槽 dword → t_[3]（保留高 24 位）。
        o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegA) + "\n";
        o += std::string("    mov ") + r32x(t_[3]) + ", dword ptr " + xslot(t_[2]) + "\n";
        // 2) cond = cond_or_size 帧槽 → t_[2]（索引载体消费后复用），16 路链。
        o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FSize) + "\n";
        for (int i = 0; i < 15; ++i) {
            const int c = cond_perm_[i];
            o += std::string("    cmp ") + r32x(t_[2]) + ", " + imm(c) + "\n";
            o += "    je xcc" + std::to_string(c) + "_" + tag + "\n";
        }
        o += "xcc" + std::to_string(cond_perm_[15]) + "_" + tag + ":\n" +
             cond_eval_x86(cond_perm_[15]) + "    jmp " + tail_lbl + "\n";
        for (int i = 0; i < 15; ++i) {
            const int c = cond_perm_[i];
            o += "xcc" + std::to_string(c) + "_" + tag + ":\n";
            o += cond_eval_x86(c);
            o += "    jmp " + tail_lbl + "\n";
        }
        // 3) tail：清低字节 + or 结果 + dword 写回（t_[2] 已被链复用为 cond
        //    值载体，写回前必须重提 reg_a 槽索引 —— x64 reextract_a 同纪律）。
        o += tail_lbl + ":\n";
        o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegA) + "\n";
        o += std::string("    and ") + r32x(t_[3]) + ", " + imm(0xFFFFFF00ull) + "\n";
        o += std::string("    or ") + r32x(t_[3]) + ", " + r32x(t_[0]) + "\n";
        o += std::string("    mov dword ptr ") + xslot(t_[2]) + ", " + r32x(t_[3]) + "\n";
        o += advance_x86(dispatch);
        return o;
    }

    // x86 Cmovcc（build_cmovcc 的 32 位版，S32 真面）：dst = cond ? src : dst。
    // cond 编码 = aux[31..28]（translator translate_cmovcc 约定，x64 T8>>60
    // 的 32 位等价 = aux 帧槽 shr 28）；size 恒 S32（native cmovcc 无 r8 形、
    // r16 需 66 前缀 lifter 入口拒 —— S8/S16 块防御、S64 走链尾出口）。
    // 条件赋值 = bitwise 双边合并（x64 同款，免短跳依赖）：
    //   result = (src & -cond) | (dst_orig & ~(-cond))
    //   t_[0]=cond 结果→mask、t_[2]=src、t_[3]=dst_orig、t_[1]=mask 副本；
    //   cond_eval_x86 读内存 flags（链式 cmp/je 宿主 clobber 无害，同 Setcc）。
    std::string build_cmovcc_x86(u64 dispatch) const {
        const std::string tag = "xcmov" + std::to_string(seq());
        const std::string tail_lbl = "xtail_" + tag;
        std::string blocks[3];
        for (int s = 0; s < 3; ++s) {
            std::string o;
            if (s == 2) {
                // 1) src 槽 dword → t_[2]；dst 槽 dword → t_[3]。
                o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegB) + "\n";
                o += std::string("    mov ") + r32x(t_[2]) + ", dword ptr " + xslot(t_[2]) + "\n";
                o += std::string("    mov ") + r32x(t_[1]) + ", " + xf(kX86FRegA) + "\n";
                o += std::string("    mov ") + r32x(t_[3]) + ", dword ptr " + xslot(t_[1]) + "\n";
                // 2) cond = aux[31..28] → t_[1]。
                o += std::string("    mov ") + r32x(t_[1]) + ", " + xf(kX86FAux) + "\n";
                o += std::string("    shr ") + r32x(t_[1]) + ", " + imm(28) + "\n";
                o += std::string("    and ") + r32x(t_[1]) + ", " + imm(0xF) + "\n";
                // 3) 16 路条件链 → t_[0] = 0/1。
                for (int i = 0; i < 15; ++i) {
                    const int c = cond_perm_[i];
                    o += std::string("    cmp ") + r32x(t_[1]) + ", " + imm(c) + "\n";
                    o += "    je xcc" + std::to_string(c) + "_" + tag + "\n";
                }
                o += "xcc" + std::to_string(cond_perm_[15]) + "_" + tag + ":\n" +
                     cond_eval_x86(cond_perm_[15]) + "    jmp " + tail_lbl + "\n";
                for (int i = 0; i < 15; ++i) {
                    const int c = cond_perm_[i];
                    o += "xcc" + std::to_string(c) + "_" + tag + ":\n";
                    o += cond_eval_x86(c);
                    o += "    jmp " + tail_lbl + "\n";
                }
            }
            // s=0/1：防御空块（native cmovcc 无 8/16 位 REG 形可达面）
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        std::string out = decode_prelude_x86() + size_chain_x86(blocks, tag, dispatch);
        // 4) tail：bitwise 合并 + dst 槽 dword 写回。
        out += tail_lbl + ":\n";
        out += std::string("    neg ") + r32x(t_[0]) + "\n";
        out += std::string("    mov ") + r32x(t_[1]) + ", " + r32x(t_[0]) + "\n";
        out += std::string("    and ") + r32x(t_[0]) + ", " + r32x(t_[2]) + "\n";
        out += std::string("    not ") + r32x(t_[1]) + "\n";
        out += std::string("    and ") + r32x(t_[1]) + ", " + r32x(t_[3]) + "\n";
        out += std::string("    or ") + r32x(t_[0]) + ", " + r32x(t_[1]) + "\n";
        out += std::string("    mov ") + r32x(t_[1]) + ", " + xf(kX86FRegA) + "\n";
        out += std::string("    mov dword ptr ") + xslot(t_[1]) + ", " + r32x(t_[0]) + "\n";
        out += advance_x86(dispatch);
        return out;
    }

    // x86 Popcnt/Lzcnt/Tzcnt（build_popcnt/build_lzcnt/build_tzcnt 的 32 位
    // 版，S32 真面）：REG-REG（派活单限定，MEM 拒 → C1 gate），dword 读 src
    // 槽 → native r32,r32 → dword 写回 dst 槽。lzcnt/tzcnt 源保留纪律
    //（pitfall #37）平移：src 先存 t_[2]（索引载体消费后空闲）再 native；
    // popcnt src 被消耗、in-place。S8/S16 块防御（x64 同口径）、S64 链尾
    // 出口。零 flags（不捕获不装配）。
    std::string build_bitcount_x86(const char* native, bool preserve_src,
                                   u64 dispatch) const {
        const std::string tag = std::string(native) + std::to_string(seq());
        const std::string tail_lbl = "xtail_" + tag;
        std::string blocks[3];
        for (int s = 0; s < 3; ++s) {
            std::string o;
            if (s == 2) {
                o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegB) + "\n";
                o += std::string("    mov ") + r32x(t_[1]) + ", dword ptr " + xslot(t_[2]) + "\n";
                if (preserve_src)
                    o += std::string("    mov ") + r32x(t_[2]) + ", " + r32x(t_[1]) + "\n";
                o += std::string("    ") + native + " " + rs(t_[1], 2) + ", " +
                     rs(preserve_src ? t_[2] : t_[1], 2) + "\n";
                o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegA) + "\n";
                o += std::string("    mov dword ptr ") + xslot(t_[2]) + ", " + r32x(t_[1]) + "\n";
            }
            // s=0/1：防御空块（native 无 8 位形式、16 位 66 面 lifter 不产）
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude_x86() + size_chain_x86(blocks, tag, dispatch) +
               tail_lbl + ":\n" + advance_x86(dispatch);
    }

    // x86 Cmpxchg（build_cmpxchg 的 32 位版，S8/S16/S32 全 native 真面）：
    // 内存目的形式直打 dst 槽 —— native "cmpxchg <mptr> [ctx + idx*8 + 0x10],
    // src" 一条完成比较+条件赋值（ZF=1 → dst 槽 ← src；ZF=0 → 累加器 ← 旧
    // dst），零 dst 值临时。累加器 = 物理 AL/AX/EAX（Rax 槽 = vm_reg_of(Rax)
    // 直载，槽高半字恒 0 不变量下 dword 直写等价 x64 alias_write）。
    // **寄存器排布纪律（生成期静态可证）**：物理 EAX 跨 acc 装载存活的两个
    // 载体 —— 槽索引 t_i 与源值 sreg —— 都从非 eax 临时集合选取（t_[0..3]
    // 至多一个物理 eax，非 eax 集合 ≥3）；src 经 32 位零扩展读（S8 byte
    // ptr 读 + movzx 语义），native 按宽度截取。
    // flags 全量（与 cmp 同语义）→ setcc5_x86 → flags_tail_x86(false)。
    // Rax 槽写回 = acc 物理寄存器按宽度直存（ZF=0 时 acc=旧 dst 由 native
    // 写入；ZF=1 时 acc 原值原样写回 —— 幂等）。
    std::string build_cmpxchg_x86(u64 dispatch) const {
        const std::string tag = "xcmpxchg" + std::to_string(seq());
        const std::string tail_lbl = "xtail_" + tag;
        constexpr int kEaxIdx = 0;  // kPhys[0] = rax/eax —— 累加器物理位
        const u8 rax_slot = isa::vm_reg_of(ir::Reg::Rax);  // = 0
        const std::string rax_slot_off = imm(static_cast<u64>(rax_slot) * 8 + 0x10);
        // 载体选取（生成期静态可证）：
        //   t_s = {t_[0],t_[1]} 中非 eax 者 —— 恒字节可编码（S8 native 源名
        //         dl/bl 硬约束，roll_x86 字节可编码集纪律）且跨 acc 装载存活；
        //   t_i = 非 eax 且 ≠ t_s —— dst 槽索引，跨 acc 装载存活
        //         （t_[0..3] 至多一个物理 eax ⇒ 非 eax 集合 ≥3，恒有解）；
        //   t_j = src 索引载体（acc 装载前消费，无存活要求）。
        const int t_s = t_[0] != kEaxIdx ? t_[0] : t_[1];
        int t_i = t_[3];
        for (int t : {t_[0], t_[1], t_[2], t_[3]})
            if (t != kEaxIdx && t != t_s) { t_i = t; break; }
        const int t_j = t_[1] != t_i ? t_[1] : t_[0];
        std::string blocks[3];
        for (int s = 0; s < 3; ++s) {
            const std::string stag = tag + "_" + std::to_string(s);
            std::string o;
            // 1) src 槽 → t_s（按宽度零扩展读）。
            o += std::string("    mov ") + r32x(t_j) + ", " + xf(kX86FRegB) + "\n";
            if (s == 0)
                o += std::string("    movzx ") + r32x(t_s) + ", byte ptr " + xslot(t_j) + "\n";
            else
                o += std::string("    mov ") + r32x(t_s) + ", dword ptr " + xslot(t_j) + "\n";
            // 2) dst 槽索引 → t_i（跨 acc 装载存活）。
            o += std::string("    mov ") + r32x(t_i) + ", " + xf(kX86FRegA) + "\n";
            // 3) 累加器 ← Rax 槽（按宽度；最后装载 —— t_i/t_s ≠ eax 静态保证）。
            if (s == 0)
                o += std::string("    mov al, byte ptr [") + r32x(ctx_) + " + " +
                     rax_slot_off + "]\n";
            else if (s == 1)
                o += std::string("    mov ax, word ptr [") + r32x(ctx_) + " + " +
                     rax_slot_off + "]\n";
            else
                o += std::string("    mov eax, dword ptr [") + r32x(ctx_) + " + " +
                     rax_slot_off + "]\n";
            // 4) native cmpxchg <mptr> [dst 槽], src —— ZF=1: 槽←src；ZF=0: acc←旧槽。
            o += std::string("    cmpxchg ") + mptr(s) + " " + xslot(t_i) + ", " +
                 rs(t_s, s) + "\n";
            // 5) flags 捕获 + 6) Rax 槽按宽度直写回。
            o += setcc5_x86();
            if (s == 0)
                o += std::string("    mov byte ptr [") + r32x(ctx_) + " + " +
                     rax_slot_off + "], al\n";
            else if (s == 1)
                o += std::string("    mov word ptr [") + r32x(ctx_) + " + " +
                     rax_slot_off + "], ax\n";
            else
                o += std::string("    mov dword ptr [") + r32x(ctx_) + " + " +
                     rax_slot_off + "], eax\n";
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude_x86() + size_chain_x86(blocks, tag, dispatch) +
               tail_lbl + ":\n" + flags_tail_x86(false, dispatch);
    }

    // x86 Xadd（build_xadd 的 32 位版，S8/S32 真面 + S16 防御）：reg_a 槽 =
    // guest 绝对 VA（翻译器 emit_address 产物），native "lock xadd <mptr>
    // [addr], src" 单指令读改写（硬件原子性保真，x64 同口径）—— 旧值回写
    // reg_b 槽（writeback_x86 帧槽索引 RMW）。flags = add 语义全量。
    // S16 块防御（66 前缀 lifter 入口拒 —— x64 s=1 同款）。
    // MIT-451 (X5b) B.4：REG-dst 形（b_kind==None 判别 — MEM 形恒 Reg/Imm）
    // —— reg_a 域 = dst VM 槽索引、reg_b 域 = src VM 槽索引：lea 出 dst 槽
    // 地址做 native RMW（ctx 槽即内存），旧值写回 src 槽（序 = xadd r,r
    // 同寄存器病态形已在 translator gate，此处无需分叉）。S8/S32 同构。
    std::string build_xadd_x86(u64 dispatch) const {
        const std::string tag = "xxadd" + std::to_string(seq());
        const std::string tail_lbl = "xtail_" + tag;
        std::string blocks[3];
        for (int s = 0; s < 3; ++s) {
            const std::string stag = tag + "_" + std::to_string(s);
            std::string o;
            if (s == 1) {
                // S16 防御（66 前缀入口拒）
                o += "    jmp " + tail_lbl + "\n";
                blocks[s] = o;
                continue;
            }
            const std::string l_reg = "xxregr_" + stag;
            const std::string l_done = "xxregd_" + stag;
            // b_kind 判别：0 = REG-dst 形（B.4），1/2 = MEM 形（既有路径）。
            o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FBKind) + "\n";
            o += "    test " + std::string(r32x(t_[2])) + ", " + r32x(t_[2]) + "\n";
            o += "    jz " + l_reg + "\n";
            // —— MEM 形（既有路径逐字节不变）——
            // 1) guest 地址 → t_[1]；2) src → t_[0]。
            o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegA) + "\n";
            o += std::string("    mov ") + r32x(t_[1]) + ", dword ptr " + xslot(t_[2]) + "\n";
            o += load_operand_x86(s, kX86FBKind, kX86FRegB, t_[0], "b" + stag);
            // 3) native lock xadd —— [addr] = 旧+src，t_[0] = 旧值。
            o += std::string("    lock xadd ") + mptr(s) + " [" + r32x(t_[1]) + "], " +
                 rs(t_[0], s) + "\n";
            // 4) flags 捕获 + 5) 旧值写回 reg_b 槽（kX86FRegB = reg_b 索引槽
            //    —— kX86FBKind 是 b_kind 值槽，误用会把旧值写进槽 0/1）。
            o += setcc5_x86();
            o += writeback_x86(s, kX86FRegB, t_[0], t_[1]);
            o += "    jmp " + l_done + "\n";
            // —— REG-dst 形（B.4）：dst/src = VM 槽，槽址 lea 自 reg_a/reg_b 域。
            o += l_reg + ":\n";
            o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegA) + "\n";
            o += std::string("    lea ") + r32x(t_[1]) + ", [" + r32x(ctx_) + " + " +
                 r32x(t_[2]) + "*8 + 0x10]\n";
            o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegB) + "\n";
            o += (s == 0
                      ? std::string("    movzx ") + r32x(t_[0]) + ", byte ptr " +
                            xslot(t_[2]) + "\n"
                      : std::string("    mov ") + r32x(t_[0]) + ", dword ptr " +
                            xslot(t_[2]) + "\n");
            o += std::string("    lock xadd ") + mptr(s) + " [" + r32x(t_[1]) + "], " +
                 rs(t_[0], s) + "\n";
            o += setcc5_x86();
            o += writeback_x86(s, kX86FRegB, t_[0], t_[1]);
            o += l_done + ":\n";
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude_x86() + size_chain_x86(blocks, tag, dispatch) +
               tail_lbl + ":\n" + flags_tail_x86(false, dispatch);
    }

    // x86 Bts/Btr/Btc（build_bit_op 的 32 位版，S32 真面）：CF = 位号处的位、
    // [addr] 位改写，native "lock bts/btr/btc dword ptr [addr], bit" 直执行。
    // 位号 b_kind 双形（Reg=reg_b 槽 / Imm=aux 帧槽）装载 t_[0] 后统一 reg 形
    // （keystone 拒 [m], imm8 静态形式 —— x64 416 注同源）；CPU 按操作数宽
    // 度自动掩码位号。flags 仅 CF 有定义（SDM），setcc5 捕宿主真值装配。
    // S8/S16 块防御（x64 同口径：G4 派活单 S32/S64 面）。
    // MIT-451 (X5b) B.4：REG-dst 形（b_kind==None 判别）—— reg_a 域 = dst
    // 槽索引、reg_b 域 = src（位号）槽索引；位号先读后 RMW（bts r,r 自测
    // 语义 = native，无 xadd 同槽写序问题）。
    std::string build_bit_op_x86(const char* native, u64 dispatch) const {
        const std::string tag = std::string(native) + std::to_string(seq());
        const std::string tail_lbl = "xtail_" + tag;
        std::string blocks[3];
        for (int s = 0; s < 3; ++s) {
            const std::string stag = tag + "_" + std::to_string(s);
            std::string o;
            if (s == 2) {
                const std::string l_reg = "xbregr_" + stag;
                const std::string l_done = "xbregd_" + stag;
                // b_kind 判别：0 = REG-dst 形（B.4），1/2 = MEM 形（既有路径）。
                o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FBKind) + "\n";
                o += "    test " + std::string(r32x(t_[2])) + ", " + r32x(t_[2]) + "\n";
                o += "    jz " + l_reg + "\n";
                // —— MEM 形（既有路径逐字节不变）——
                // 1) guest 地址 → t_[1]。
                o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegA) + "\n";
                o += std::string("    mov ") + r32x(t_[1]) + ", dword ptr " + xslot(t_[2]) + "\n";
                // 2) 位号 → t_[0]（b_kind 分支：Reg=reg_b 槽 / Imm=aux）。
                o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FBKind) + "\n";
                o += std::string("    cmp ") + r32x(t_[2]) + ", " + imm(1) + "\n";
                o += "    jne xbimm_" + stag + "\n";
                o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegB) + "\n";
                o += std::string("    mov ") + r32x(t_[0]) + ", dword ptr " + xslot(t_[2]) + "\n";
                o += "    jmp xbdone_" + stag + "\n";
                o += "xbimm_" + stag + ":\n";
                o += std::string("    mov ") + r32x(t_[0]) + ", " + xf(kX86FAux) + "\n";
                o += "xbdone_" + stag + ":\n";
                // 3) native lock bts/btr/btc [addr], bit（reg 形）。
                o += std::string("    lock ") + native + " dword ptr [" + r32x(t_[1]) +
                     "], " + rs(t_[0], 2) + "\n";
                // 4) flags 捕获（CF）。
                o += setcc5_x86();
                o += "    jmp " + l_done + "\n";
                // —— REG-dst 形（B.4）：dst 槽址 lea 自 reg_a 域，位号读自
                //     reg_b 域槽（先读后 RMW）。⚠️ 位号必须显式 and 0x1F：
                //     native 寄存器形 bts r,r 按操作数宽掩码位号，而槽实现
                //     的 RMW 目标 = 内存形（[slot]）——内存形位号不掩码（≥32
                //     时跨界触碰后续字节 = 摸邻槽，电池 XaddBitOpsRegDstForm
                //     v2=35 当场炸出 0x800000000）。and 后 = 寄存器形语义。
                o += l_reg + ":\n";
                o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegA) + "\n";
                o += std::string("    lea ") + r32x(t_[1]) + ", [" + r32x(ctx_) + " + " +
                     r32x(t_[2]) + "*8 + 0x10]\n";
                o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegB) + "\n";
                o += std::string("    mov ") + r32x(t_[0]) + ", dword ptr " + xslot(t_[2]) + "\n";
                o += std::string("    and ") + r32x(t_[0]) + ", " + imm(0x1F) + "\n";
                o += std::string("    lock ") + native + " dword ptr [" + r32x(t_[1]) +
                     "], " + rs(t_[0], 2) + "\n";
                o += setcc5_x86();
                o += l_done + ":\n";
            }
            // s=0/1：防御空块
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude_x86() + size_chain_x86(blocks, tag, dispatch) +
               tail_lbl + ":\n" + flags_tail_x86(false, dispatch);
    }

    // x86 Push（build_push 的 32 位版 —— **4B 槽裁决**的落地形）：
    //   - guest esp 步进 = 4B（S32 push，x86 栈宽）；
    //   - ctx 的 rsp 槽 = 8B u64（VM 槽宽，与 arch 无关 —— 442 译注），槽内
    //     值恒 32 位零扩展（"槽高半字恒 0" 不变量）⇒ 槽算术用 **dword sub**
    //     等价 64 位 sub 且溢出 = 32 位回绕（native esp 语义）；qword 运算在
    //     32 位模式不可编码，dword 低半字运算即正确形。
    //   - 内存写 = dword [esp值]（x86 push 4B）；
    //   - 源 a_kind 双形（Reg=reg_a 槽 / Imm=aux 槽）。
    // S8/S16 块防御（translator translate_push 对 ir::Op::Push S16/S8 gate
    // —— 442 裁决"栈推进 2B 不在 VM 栈模型内"；S64 链尾出口）。零 flags。
    std::string build_push_x86(u64 dispatch) const {
        const std::string tag = "xpush" + std::to_string(seq());
        const std::string tail_lbl = "xtail_" + tag;
        std::string blocks[3];
        for (int s = 0; s < 3; ++s) {
            const std::string stag = tag + "_" + std::to_string(s);
            std::string o;
            if (s == 2) {
                // 1) esp -= 4（dword 槽算术 —— 4B 步进裁决，见上注）。
                o += std::string("    sub dword ptr [") + r32x(ctx_) + " + " +
                     imm(kX86RspSlotOff) + "], " + imm(4) + "\n";
                // 2) 源 → t_[1]（a_kind 双形）。
                o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FAKind) + "\n";
                o += std::string("    cmp ") + r32x(t_[2]) + ", " + imm(1) + "\n";
                o += "    jne xpimm_" + stag + "\n";
                o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegA) + "\n";
                o += std::string("    mov ") + r32x(t_[1]) + ", dword ptr " + xslot(t_[2]) + "\n";
                o += "    jmp xpgo_" + stag + "\n";
                o += "xpimm_" + stag + ":\n";
                o += std::string("    mov ") + r32x(t_[1]) + ", " + xf(kX86FAux) + "\n";
                o += "xpgo_" + stag + ":\n";
                // 3) dword [esp值] ← 源。
                o += std::string("    mov ") + r32x(t_[0]) + ", dword ptr [" + r32x(ctx_) +
                     " + " + imm(kX86RspSlotOff) + "]\n";
                o += std::string("    mov dword ptr [") + r32x(t_[0]) + "], " + r32x(t_[1]) + "\n";
            }
            // s=0/1：防御空块
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude_x86() + size_chain_x86(blocks, tag, dispatch) +
               tail_lbl + ":\n" + advance_x86(dispatch);
    }

    // x86 Pop（build_pop 的 32 位版）：dword [esp值] → reg_a 槽 + esp += 4
    // （4B 步进裁决同 build_push_x86 注）。S8/S16/S64 块防御。零 flags。
    std::string build_pop_x86(u64 dispatch) const {
        const std::string tag = "xpop" + std::to_string(seq());
        const std::string tail_lbl = "xtail_" + tag;
        std::string blocks[3];
        for (int s = 0; s < 3; ++s) {
            std::string o;
            if (s == 2) {
                o += std::string("    mov ") + r32x(t_[0]) + ", dword ptr [" + r32x(ctx_) +
                     " + " + imm(kX86RspSlotOff) + "]\n";
                o += std::string("    mov ") + r32x(t_[1]) + ", dword ptr [" + r32x(t_[0]) +
                     "]\n";
                o += std::string("    add dword ptr [") + r32x(ctx_) + " + " +
                     imm(kX86RspSlotOff) + "], " + imm(4) + "\n";
                o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegA) + "\n";
                o += std::string("    mov dword ptr ") + xslot(t_[2]) + ", " + r32x(t_[1]) + "\n";
            }
            // s=0/1：防御空块
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude_x86() + size_chain_x86(blocks, tag, dispatch) +
               tail_lbl + ":\n" + advance_x86(dispatch);
    }

    // =======================================================================
    // MIT-454 (X6 A=X3d)：x86 SSE handler 面 —— x64 表 32 op SSE 族的 32 位
    // 镜像（批二 30：算术 16 + 传送 6 + 位运算 4 + mem 原语 2 + GP↔xmm 桥 2；
    // 批三 2：ucomis flags 族）。x64 SSE builder 家族（build_addss …
    // build_gp_from_xmm）逐 op 以本组 32 位模板平移：
    //   - 编码双平台同（X0 §7 实测兜底 + 电池 DisasmX86SseEncodingDualMode
    //     capstone 双模逐 op 断言钉死）：SSE 基础编码无 REX 依赖，
    //     CS_MODE_32/64 同字节；x86 物理 xmm 仅 xmm0-7（无 REX 不可编码
    //     xmm8-15）—— guest 槽域 24..31 结构性覆盖全部可达形（x86 侧
    //     capstone 只产 xmm0-7，槽 32..47 不可达）。
    //   - ctx.xmm 区（kCtxXmmBase=0x140，8×16B）布局与 arch 无关（regs
    //     u64[32] + xmm[8] 均 VM 槽宽），x86 帧公式 = (slot-24)*16 + 0x140，
    //     32 位寻址 [ctx + t]（base+index；Keystone 不支持 (reg-24)*16 内联，
    //     拆步 mov/sub/shl/add —— 24/4/0x140 一律 imm()，pitfall #78）。
    //   - 物理寄存器：xmm0/xmm1 = 指令内临时（读 ctx → 算 → 写 ctx，指令
    //     边界无活值 —— x64 callgate 5.5 无条件覆写同款安全性论证）；寻址
    //     临时 t_[0]/t_[1]（SSE handler 不用 load_operand_x86，与 GP 面
    //     t_[2]/t_[3] 寻址约定互不干扰）。
    //   - stub 侧配套（stub_gen.cpp X6）：x86 stub 入口 host→ctx.xmm 同步 +
    //     出口 ctx→host 同步（Win32 ABI xmm 全易失；x64 371 面的 32 位镜像，
    //     446 "xmm 同步不适用" 注的前提"x86 运行时无 SSE handler"随本批
    //     翻转）；ExitNative/Ret 直退 handler 内联 ctx→xmm 恢复（不经 stub
    //     出口，x64 build_ret 步 3 同款镜像）。
    // =======================================================================

    // xmm 区槽偏移入临时：t = (slot - 24)*16 + kCtxXmmBase。slot_text =
    // 帧槽 xf(kX86FRegA/kX86FRegB)（读槽号）或已含槽号的临时。
    std::string xmm_offset_into_t_x86(int reg_t, const std::string& slot_text) const {
        std::string o;
        o += std::string("    mov ") + r32x(reg_t) + ", " + slot_text + "\n";
        o += std::string("    sub ") + r32x(reg_t) + ", " + imm(24) + "\n";
        o += std::string("    shl ") + r32x(reg_t) + ", " + imm(4) + "\n";
        o += std::string("    add ") + r32x(reg_t) + ", " + imm(kCtxXmmBase) + "\n";
        return o;
    }

    // 读 src 槽 → 物理 xmm1（load_src_slot_into_xmm1 的 32 位版，MIT-408
    // 双语义寻址）：reg_b >= 24 → xmm 区公式；reg_b < 24 → GP 双槽
    //（[ctx + reg_b*8 + 0x10]，16B 覆盖 vN+vN+1 —— ALU mem 源折条的
    // XmmLoad 临时落点）。寻址临时 tmp（调用方保证与自有寻址临时不冲突
    // —— XmmStore 的地址临时用 t_[0]，本 helper 用 t_[1]，x64 T1/T9 分工
    // 同款纪律）。
    std::string load_src_slot_into_xmm1_x86(const std::string& tag, int tmp = 1) const {
        const std::string lbl_x = "xsrcx_" + tag;
        const std::string lbl_d = "xsrcd_" + tag;
        std::string o;
        o += std::string("    mov ") + r32x(tmp) + ", " + xf(kX86FRegB) + "\n";
        o += std::string("    cmp ") + r32x(tmp) + ", " + imm(24) + "\n";
        o += "    jae " + lbl_x + "\n";
        // GP 双槽: 16B 直读（0x10 为寻址位移非立即数，verifier 闸面同 x64）
        o += std::string("    movups xmm1, [") + r32x(ctx_) + " + " + r32x(tmp) +
             "*8 + 0x10]\n";
        o += "    jmp " + lbl_d + "\n";
        o += lbl_x + ":\n";
        o += xmm_offset_into_t_x86(tmp, xf(kX86FRegB));
        o += std::string("    movups xmm1, [") + r32x(ctx_) + " + " + r32x(tmp) + "]\n";
        o += lbl_d + ":\n";
        return o;
    }

    // x86 SSE 二元运算/传送共通模板（build_addss / build_xmm_transfer 的
    // 32 位镜像）：dst 槽 128-bit 读 xmm0 → src 槽读 xmm1 → native op →
    // dst 128-bit 写回 → advance。零 flags（ucomis 族批三独立 builder）。
    // dual_src（x64 命名沿用）：true = src 走双语义寻址（ALU 族 mem 源折条
    // 把 src 编码为 GP 双槽）；false = src 恒 xmm 槽（mov 族 —— mem 源经
    // XmmLoad 直落 xmm 槽）。
    std::string build_x86_sse_binop(u64 dispatch, const char* native_mn,
                                    bool dual_src) const {
        const std::string tag = std::string(native_mn) + std::to_string(seq());
        std::string o = decode_prelude_x86();
        o += xmm_offset_into_t_x86(t_[0], xf(kX86FRegA));   // t0 = dst 偏移
        o += std::string("    movups xmm0, [") + r32x(ctx_) + " + " + r32x(t_[0]) + "]\n";
        if (dual_src) {
            o += load_src_slot_into_xmm1_x86(tag);
        } else {
            o += xmm_offset_into_t_x86(t_[1], xf(kX86FRegB));  // t1 = src 偏移
            o += std::string("    movups xmm1, [") + r32x(ctx_) + " + " +
                 r32x(t_[1]) + "]\n";
        }
        o += std::string("    ") + native_mn + " xmm0, xmm1\n";
        o += xmm_offset_into_t_x86(t_[0], xf(kX86FRegA));   // 重算 dst 偏移写回
        o += std::string("    movups [") + r32x(ctx_) + " + " + r32x(t_[0]) + "], xmm0\n";
        o += advance_x86(dispatch);
        return o;
    }

    // 算术族 16（x64 同名 builder 镜像；中间行 = native mn，其余全同）：
    //   addss F3 0F 58 / addps 0F 58 / addpd 66 0F 58
    //   subss F3 0F 5C / subps 0F 5C / subpd 66 0F 5C
    //   mulss F3 0F 59 / mulsd F2 0F 59 / mulps 0F 59 / mulpd 66 0F 59
    //   divss F3 0F 5E / divsd F2 0F 5E / divps 0F 5E / divpd 66 0F 5E
    //   addsd F2 0F 58 / subsd F2 0F 5C
    // 除法族 = IEEE inf 语义非 #DE（x64 电池先例平移，G8 GP Div 例外不适用）。
    std::string build_x86_addss(u64 d) const { return build_x86_sse_binop(d, "addss", true); }
    std::string build_x86_addps(u64 d) const { return build_x86_sse_binop(d, "addps", true); }
    std::string build_x86_addpd(u64 d) const { return build_x86_sse_binop(d, "addpd", true); }
    std::string build_x86_subss(u64 d) const { return build_x86_sse_binop(d, "subss", true); }
    std::string build_x86_subps(u64 d) const { return build_x86_sse_binop(d, "subps", true); }
    std::string build_x86_subpd(u64 d) const { return build_x86_sse_binop(d, "subpd", true); }
    std::string build_x86_mulss(u64 d) const { return build_x86_sse_binop(d, "mulss", true); }
    std::string build_x86_mulsd(u64 d) const { return build_x86_sse_binop(d, "mulsd", true); }
    std::string build_x86_mulps(u64 d) const { return build_x86_sse_binop(d, "mulps", true); }
    std::string build_x86_mulpd(u64 d) const { return build_x86_sse_binop(d, "mulpd", true); }
    std::string build_x86_divss(u64 d) const { return build_x86_sse_binop(d, "divss", true); }
    std::string build_x86_divsd(u64 d) const { return build_x86_sse_binop(d, "divsd", true); }
    std::string build_x86_divps(u64 d) const { return build_x86_sse_binop(d, "divps", true); }
    std::string build_x86_divpd(u64 d) const { return build_x86_sse_binop(d, "divpd", true); }
    std::string build_x86_addsd(u64 d) const { return build_x86_sse_binop(d, "addsd", true); }
    std::string build_x86_subsd(u64 d) const { return build_x86_sse_binop(d, "subsd", true); }
    // 传送族 6（dual_src=false —— src 恒 xmm 槽）：movss F3 0F 10（只改
    // lane0 高 96 保持 —— dst 预读模板语义必需）/ movsd F2 0F 10（高 64
    // 保持）/ movaps 0F 28 / movapd 66 0F 28 / movups 0F 10 / movupd 66 0F 10。
    std::string build_x86_movss(u64 d) const { return build_x86_sse_binop(d, "movss", false); }
    std::string build_x86_movsd(u64 d) const { return build_x86_sse_binop(d, "movsd", false); }
    std::string build_x86_movaps(u64 d) const { return build_x86_sse_binop(d, "movaps", false); }
    std::string build_x86_movapd(u64 d) const { return build_x86_sse_binop(d, "movapd", false); }
    std::string build_x86_movups(u64 d) const { return build_x86_sse_binop(d, "movups", false); }
    std::string build_x86_movupd(u64 d) const { return build_x86_sse_binop(d, "movupd", false); }
    // 位运算族 4（dual_src=true —— 408 mem 源折条 GP 双槽）：
    //   xorps 0F 57 / orps 0F 56 / andps 0F 54 / andnps 0F 55（dst=~dst&src）。
    std::string build_x86_xorps(u64 d) const { return build_x86_sse_binop(d, "xorps", true); }
    std::string build_x86_orps(u64 d) const { return build_x86_sse_binop(d, "orps", true); }
    std::string build_x86_andps(u64 d) const { return build_x86_sse_binop(d, "andps", true); }
    std::string build_x86_andnps(u64 d) const { return build_x86_sse_binop(d, "andnps", true); }

    // MIT-408 XmmLoad 的 32 位版：内存 → 槽。a 槽 = 目的（>=24 xmm 区 /
    // <24 GP 双槽），b 槽 = 地址槽（绝对 VA；dword 读 —— guest VA < 4GB，
    // 槽高半字 0 不变量），aux = 访存宽度（4/8/16，翻译器恒发合法值，
    // 16 为链尾顺延）。内存源清零语义由 native movss/movsd 直产（SDM）。
    std::string build_xmm_load_x86(u64 dispatch) const {
        const std::string tag = "xxmmld" + std::to_string(seq());
        const std::string lbl4 = "xld4_" + tag;
        const std::string lbl8 = "xld8_" + tag;
        const std::string lbl16 = "xld16_" + tag;
        const std::string lblx = "xldx_" + tag;
        const std::string lbld = "xldd_" + tag;
        std::string o = decode_prelude_x86();
        // 地址 → t1（b 槽 dword 读）
        o += std::string("    mov ") + r32x(t_[1]) + ", " + xf(kX86FRegB) + "\n";
        o += std::string("    mov ") + r32x(t_[1]) + ", dword ptr " + xslot(t_[1]) + "\n";
        // 宽度链: aux ∈ {4, 8, 16}
        o += std::string("    cmp dword ptr ") + xf(kX86FAux) + ", " + imm(4) + "\n";
        o += "    je " + lbl4 + "\n";
        o += std::string("    cmp dword ptr ") + xf(kX86FAux) + ", " + imm(8) + "\n";
        o += "    je " + lbl8 + "\n";
        o += "    jmp " + lbl16 + "\n";
        o += lbl4 + ":\n";
        o += std::string("    movss xmm0, dword ptr [") + r32x(t_[1]) + "]\n";
        o += "    jmp " + lblx + "\n";
        o += lbl8 + ":\n";
        o += std::string("    movsd xmm0, qword ptr [") + r32x(t_[1]) + "]\n";
        o += "    jmp " + lblx + "\n";
        o += lbl16 + ":\n";
        o += std::string("    movups xmm0, xmmword ptr [") + r32x(t_[1]) + "]\n";
        // 目的槽: reg_a >= 24 → xmm 区公式；< 24 → GP 双槽
        o += lblx + ":\n";
        o += std::string("    mov ") + r32x(t_[0]) + ", " + xf(kX86FRegA) + "\n";
        o += std::string("    cmp ") + r32x(t_[0]) + ", " + imm(24) + "\n";
        o += "    jae " + lbld + "\n";
        o += std::string("    movups [") + r32x(ctx_) + " + " + r32x(t_[0]) +
             "*8 + 0x10], xmm0\n";
        o += "    jmp done_" + tag + "\n";
        o += lbld + ":\n";
        o += xmm_offset_into_t_x86(t_[0], xf(kX86FRegA));
        o += std::string("    movups [") + r32x(ctx_) + " + " + r32x(t_[0]) + "], xmm0\n";
        o += "done_" + tag + ":\n";
        o += advance_x86(dispatch);
        return o;
    }

    // MIT-408 XmmStore 的 32 位版：槽 → 内存。a 槽 = 地址槽，b 槽 = 源槽
    // （双语义寻址），aux = 访存宽度。128-bit 读进 xmm1 → 宽度链低宽度截断
    // 落盘（movss/movsd store 只写低 4/8B —— SDM 内存写语义）。
    std::string build_xmm_store_x86(u64 dispatch) const {
        const std::string tag = "xxmmst" + std::to_string(seq());
        const std::string lbl4 = "xst4_" + tag;
        const std::string lbl8 = "xst8_" + tag;
        const std::string lbl16 = "xst16_" + tag;
        std::string o = decode_prelude_x86();
        // 地址 → t0（a 槽 dword 读；⚠️ src 寻址用 t1 —— 临时分工纪律见
        // load_src_slot_into_xmm1_x86 注，电池 XmmStore 首炸实证）
        o += std::string("    mov ") + r32x(t_[0]) + ", " + xf(kX86FRegA) + "\n";
        o += std::string("    mov ") + r32x(t_[0]) + ", dword ptr " + xslot(t_[0]) + "\n";
        o += load_src_slot_into_xmm1_x86(tag, t_[1]);
        // 宽度链（按 xmm1 落盘，低宽度截断）
        o += std::string("    cmp dword ptr ") + xf(kX86FAux) + ", " + imm(4) + "\n";
        o += "    je " + lbl4 + "\n";
        o += std::string("    cmp dword ptr ") + xf(kX86FAux) + ", " + imm(8) + "\n";
        o += "    je " + lbl8 + "\n";
        o += "    jmp " + lbl16 + "\n";
        o += lbl4 + ":\n";
        o += std::string("    movss dword ptr [") + r32x(t_[0]) + "], xmm1\n";
        o += "    jmp done_" + tag + "\n";
        o += lbl8 + ":\n";
        o += std::string("    movsd qword ptr [") + r32x(t_[0]) + "], xmm1\n";
        o += "    jmp done_" + tag + "\n";
        o += lbl16 + ":\n";
        o += std::string("    movups xmmword ptr [") + r32x(t_[0]) + "], xmm1\n";
        o += "done_" + tag + ":\n";
        o += advance_x86(dispatch);
        return o;
    }

    // MIT-427 XmmFromGp 的 32 位版（movd/movq 桥 load 方向）：src 槽低 4/8
    // 字节 → dst xmm 槽，dst 槽其余字节清零（SDM MOVD 清 127:32 / MOVQ 清
    // 127:64 —— mem 形式 native 直产）。编码: a=xmm_dst 槽 (24..31)，
    // b=src 槽（GP 0..15 或 xmm 24..31 双语义），aux=宽度 (4|8)。
    std::string build_xmm_from_gp_x86(u64 dispatch) const {
        const std::string tag = "xxmmfg" + std::to_string(seq());
        const std::string lblx = "xfgx_" + tag;
        const std::string lbl4 = "xfg4_" + tag;
        const std::string lbld = "xfgd_" + tag;
        std::string o = decode_prelude_x86();
        // src 槽域分派: reg_b >= 24 → xmm 槽（仅 width=8 —— F3 0F 7E 形态，
        // movsd mem 形式 = 低 64 读 + 高 64 清零）；< 24 → GP 槽宽度链
        o += std::string("    mov ") + r32x(t_[1]) + ", " + xf(kX86FRegB) + "\n";
        o += std::string("    cmp ") + r32x(t_[1]) + ", " + imm(24) + "\n";
        o += "    jae " + lblx + "\n";
        o += std::string("    cmp dword ptr ") + xf(kX86FAux) + ", " + imm(4) + "\n";
        o += "    je " + lbl4 + "\n";
        o += std::string("    movq xmm0, qword ptr [") + r32x(ctx_) + " + " +
             r32x(t_[1]) + "*8 + 0x10]\n";
        o += "    jmp " + lbld + "\n";
        o += lbl4 + ":\n";
        o += std::string("    movd xmm0, dword ptr [") + r32x(ctx_) + " + " +
             r32x(t_[1]) + "*8 + 0x10]\n";
        o += "    jmp " + lbld + "\n";
        o += lblx + ":\n";
        o += xmm_offset_into_t_x86(t_[1], xf(kX86FRegB));
        o += std::string("    movsd xmm0, qword ptr [") + r32x(ctx_) + " + " +
             r32x(t_[1]) + "]\n";
        // dst xmm 槽 16B 全量写（清零语义落槽）
        o += lbld + ":\n";
        o += xmm_offset_into_t_x86(t_[0], xf(kX86FRegA));
        o += std::string("    movups [") + r32x(ctx_) + " + " + r32x(t_[0]) + "], xmm0\n";
        o += advance_x86(dispatch);
        return o;
    }

    // MIT-427 GpFromXmm 的 32 位版（桥 store 方向）：src xmm 槽低 4/8 字节
    // 截取 → dst GP 槽。width=8: movq（低 64 截取）；width=4: movd + 高 4
    // 字节清零（native movd r32 写 32 位零扩展对齐 —— x64 双 store 等价形）。
    std::string build_gp_from_xmm_x86(u64 dispatch) const {
        const std::string tag = "xgpfx" + std::to_string(seq());
        const std::string lbl4 = "xfx4_" + tag;
        const std::string lbld = "xfxd_" + tag;
        std::string o = decode_prelude_x86();
        // src xmm 槽 128-bit 读 → xmm0
        o += xmm_offset_into_t_x86(t_[1], xf(kX86FRegB));
        o += std::string("    movups xmm0, [") + r32x(ctx_) + " + " + r32x(t_[1]) + "]\n";
        // dst GP 槽宽度链截取: T0 = reg_a 槽号
        o += std::string("    mov ") + r32x(t_[0]) + ", " + xf(kX86FRegA) + "\n";
        o += std::string("    cmp dword ptr ") + xf(kX86FAux) + ", " + imm(4) + "\n";
        o += "    je " + lbl4 + "\n";
        o += std::string("    movq qword ptr [") + r32x(ctx_) + " + " + r32x(t_[0]) +
             "*8 + 0x10], xmm0\n";
        o += "    jmp " + lbld + "\n";
        o += lbl4 + ":\n";
        o += std::string("    movd dword ptr [") + r32x(ctx_) + " + " + r32x(t_[0]) +
             "*8 + 0x10], xmm0\n";
        o += std::string("    mov dword ptr [") + r32x(ctx_) + " + " + r32x(t_[0]) +
             "*8 + 0x14], " + imm(0) + "\n";
        o += lbld + ":\n";
        o += advance_x86(dispatch);
        return o;
    }

    // =======================================================================
    // MIT-454 (X6 A=X3d 批次三)：x86 SSE 比较族 —— ucomiss/ucomisd flags 面
    //（32 op SSE 名单收尾 2 op）。
    //
    // Ucomis* 与位运算/传送族本质不同: **只写 EFLAGS (ZF/PF/CF), 不改 xmm
    // 操作数** — 无 dst 写回步, 走 ALU binop 同一条 flags 通路 (setcc 落帧
    // 捕获区 → flags_tail_x86 装配), 与 setcc/jcc handler 共享 [ctx+0x98]
    // flags 槽 (x64 build_ucomis_flags 的 32 位镜像; x86 无 zero5 —— setcc
    // 直写帧捕获区全字节, zero5 x86 形 = 空)。
    //
    // 顺序严格性 (与 build_binary_x86 一致): 槽位偏移计算 (mov/sub/shl/add
    // 改宿主 EFLAGS) → native ucomis* 产真值 → setcc5_x86 紧随捕获 (中间
    // 不得插入任何改 EFLAGS 的指令) → flags_tail_x86 装配。
    //
    // SDM UCOMISS/UCOMISD 真值表 (native 直产): greater → ZF=0 CF=0 /
    // less → ZF=0 CF=1 / equal → ZF=1 CF=0 / unordered (NaN) → ZF=PF=CF=1;
    // OF/SF/AF 清 0 — flags_tail_x86 按 ZF/CF/OF/SF/PF=bit0..4 装配即得。
    std::string build_ucomis_flags_x86(u64 dispatch, const char* native_mn) const {
        const std::string tag = std::string(native_mn) + std::to_string(seq());
        std::string o = decode_prelude_x86();
        o += xmm_offset_into_t_x86(t_[0], xf(kX86FRegA));   // t0 = dst 偏移
        o += std::string("    movups xmm0, [") + r32x(ctx_) + " + " + r32x(t_[0]) + "]\n";
        o += load_src_slot_into_xmm1_x86(tag, t_[1]);
        o += std::string("    ") + native_mn + " xmm0, xmm1\n";
        o += setcc5_x86();
        o += flags_tail_x86(false, dispatch);
        return o;
    }
    std::string build_x86_ucomiss(u64 d) const { return build_ucomis_flags_x86(d, "ucomiss"); }
    std::string build_x86_ucomisd(u64 d) const { return build_ucomis_flags_x86(d, "ucomisd"); }

    // =======================================================================
    // MIT-445 (X3c B.1)：x86 CallGate（reg 值目标 + RVA 双形，零新 VmOp）。
    //
    // 编码（x64 build_callgate 同协议，a_kind 判别）：RVA 形 a_kind=None +
    // aux=目标 RVA；reg 形 a_kind=Reg + reg_a=目标槽（→ VA = regs[reg_a]
    // 低 dword，槽值 = 绝对 VA，"槽高半字恒 0" 不变量下 dword 读即全值）。
    //
    // x86 协议面与 x64 的结构差异（逐条对账）：
    //   1) 参数窗：Win32 cdecl 参数走栈——MIT-446 (X4) B.1 落地固定参数窗
    //      预置（step 2.5，guest [v4+4i] → 窗口，协议见 kX86CallgateArgDwords
    //      注；445 D2 "不特化" 挂账翻案，build_callgate_x86 与 stub_gen 两处
    //      同步锚④闭合）。
    //   2) 窗口锚：host_rsp（[ctx+0x128]，entry 落账）自洽，无需 native_sp
    //      预置（x64 用 [ctx+0x120]+kPushCtxDepth 常量回退——stub 帧 ctx 区
    //      固定位移；x86 直接重读 host_rsp，跨 call 稳定语义相同且电池/
    //      未来 stub 皆零耦合）。窗口 = 对齐(host_rsp - kX86CallgateWindow)，
    //      探针写消除 guard page 边界（406 同款）；shr/shl 4 对齐
    //      （kCallgateAlignShift 复用）。
    //   3) pc（MIT-494t② 常驻 ecx）/flags（[ctx+0x98]）——pc 经 step 1.5
    //      落槽跨 call（native callee 毁 caller-saved ecx），step 4 后还原；
    //      flags 内存常驻，native callee 不识 ctx 无需 save/restore。
    //      base_/ctx_ 恒 callee-saved（roll_x86
    //      约束）跨 call 存活；esp 经 host_rsp 重基（step 4）。
    //   4) 返回值：eax → regs[0] 低 dword（槽高半字清零不变量维持）。MIT-498
    //      (T51) 寄存器参数桥：call 前 guest eax/ecx/edx（ctx 槽 +0x10/
    //      +0x18/+0x20）→ 物理寄存器（fastcall/自定义约定 callee 参数面——
    //      __aullshr 类 RTL helper 经 ecx 取移位量此前读垃圾 = wv_mul64hi
    //      E2E 错值根因）；call 后 edx → +0x20 写回（edx:eax 64 位返回对 +
    //      in-place 移位 helper 半积；cdecl volatile 下写垃圾值亦合法）。
    //      call 目标载体易失（t_[0] ∈ {eax,edx}）时先转存 t_[2]（此时恒
    //      callee-saved，论证见 step 2.6 注）。guest flags 天然存活（内存
    //      常驻，native call 不触 ctx）。x87/MMX callee 副作用不建模（x86
    //      面 D1 恒 gate，无 SSE/x87 handler）。
    //   5) rsp 纪律：call 前切 esp 到窗口、call 后重读 host_rsp，handler
    //      出口 esp 恢复原值——"x86 执行帧 esp 跨指令稳定"既有不变量不受扰
    //      （执行帧槽在窗口上方，callee 栈活动只向下生长，零重叠）。
    // =======================================================================
    std::string build_callgate_x86(u64 dispatch) const {
        // 标签固定名（不吃 seq()，理由同 x64 build_callgate 注）：seq 号被
        // 消费会让后续 handler 的内部标签顺移，污染 x86 dump 对账口径。
        const std::string lbl_rva = "xcgrva";
        const std::string lbl_have = "xcghave";
        std::string o = decode_prelude_x86();
        // step 1: 目标 VA 双形分派（a_kind 判别，x64 build_callgate step 1 同构）
        o += std::string("    mov ") + r32x(t_[0]) + ", " + xf(kX86FAKind) + "\n";
        o += std::string("    cmp ") + r32x(t_[0]) + ", " + imm(1) + "\n";
        o += "    jne " + lbl_rva + "\n";
        o += std::string("    mov ") + r32x(t_[0]) + ", " + xf(kX86FRegA) + "\n";
        o += std::string("    mov ") + r32x(t_[0]) + ", dword ptr [" + r32x(ctx_) +
             " + " + r32x(t_[0]) + "*8 + 0x10]\n";
        o += "    jmp " + lbl_have + "\n";
        o += lbl_rva + ":\n";
        o += std::string("    mov ") + r32x(t_[0]) + ", " + xf(kX86FAux) + "\n";
        o += std::string("    add ") + r32x(t_[0]) + ", dword ptr [" + r32x(ctx_) +
             " + 0x110]\n";
        o += lbl_have + ":\n";
        // step 1.5（MIT-494t②）：pc 出 ecx 落槽 —— native call 毁 caller-
        // saved ecx；esp 切窗前同步（窗口 push 不触 ctx）。
        o += std::string("    mov dword ptr [") + r32x(ctx_) + " + 0x8], ecx\n";
        // step 2: 切 esp → callee 窗口（16 对齐 + 底部探针写）
        o += std::string("    mov ") + r32x(t_[1]) + ", dword ptr [" + r32x(ctx_) +
             " + 0x128]\n";
        o += std::string("    sub ") + r32x(t_[1]) + ", " + imm(kX86CallgateWindow) + "\n";
        o += std::string("    shr ") + r32x(t_[1]) + ", " + imm(kCallgateAlignShift) + "\n";
        o += std::string("    shl ") + r32x(t_[1]) + ", " + imm(kCallgateAlignShift) + "\n";
        o += std::string("    mov esp, ") + r32x(t_[1]) + "\n";
        o += std::string("    mov dword ptr [") + r32x(t_[1]) + "], 0\n";
        // step 2.5: cdecl 参数窗预置（MIT-446 X4 B.1，协议见
        // kX86CallgateArgDwords 注——guest [v4+4i] 固定 4 dword 逆序 push，
        // arg0 落最低；多预置在 cdecl caller-cleans + host_rsp 重基下无害）。
        // t_[1]（窗口已切，值已消费）改载 guest v4；t_[0] = 目标 VA 跨步存活。
        o += std::string("    mov ") + r32x(t_[1]) + ", dword ptr [" + r32x(ctx_) +
             " + " + imm(kX86RspSlotOff) + "]\n";
        for (u64 i = kX86CallgateArgDwords; i-- > 0;) {
            o += std::string("    push dword ptr [") + r32x(t_[1]) + " + " +
                 imm(i * 4) + "]\n";
        }
        // step 2.6 (MIT-498 T51)：目标 VA 转存 callee-saved 载体（仅 t_[0]
        // ∈ {eax,edx} 易失时）——step 2.7 桥接覆盖物理 eax/edx，t_[0]
        //（call 目标）可能正是其一。
        // 载体选择（T51 验收 C 修复）：t_[0]/t_[1] 从 cand =
        // {eax,edx,ebx}\{ctx_,base_} **独立**抽 2，{t0=eax, t1=ebx} 混合对
        // 为合法抽取（首版"t_[2] 恒 callee-saved"论证漏此分支——验收穷举
        // 8.3% seed 落坏配置，seed 67 真执行复现 = 转存被桥接覆写 →
        // call guest edx 槽值，静默劫持面）。修复 = t0 易失时在
        // t_[2]/t_[3] 中**恒选 callee-saved 者**：池 6 = 2 易失(eax/edx)
        // + 4 callee-saved；t0 吃 1 易失、ctx_/base_ 吃 2 callee-saved 后
        // 剩 {1 易失 + 2 callee-saved}，t1 至多吃走 1 个 ⟹ t_[2]/t_[3]
        // **至少一个 callee-saved**，选择恒命中。t_[0] 非 易失（=ebx，
        // callee-saved）时直接作 call 载体（桥接不触及）。
        const bool t0_volatile = (t_[0] == 0 || t_[0] == 1);
        int call_carrier = t_[0];
        if (t0_volatile) {
            const bool t2_saved =
                std::find(std::begin(kX86CalleeSaved), std::end(kX86CalleeSaved),
                          t_[2]) != std::end(kX86CalleeSaved);
            call_carrier = t2_saved ? t_[2] : t_[3];
            o += std::string("    mov ") + r32x(call_carrier) + ", " +
                 r32x(t_[0]) + "\n";
        }
        // step 2.7 (MIT-498 T51)：guest 易失寄存器 → 物理——fastcall/自定义
        // 约定 callee 参数面（__aullshr 类 RTL helper 经 ecx 取移位量、
        // edx:eax 取值，此前读到的是垃圾 = wv_mul64hi E2E 错值根因，GAPS
        // MIT-497）。pc 已 step 1.5 落槽（physical ecx 可安全改写）；此时
        // eax/edx 上唯一活值 = call 载体（易失形已转存 callee-saved）。
        // cdecl callee 不读寄存器实参 → 桥入值被忽略，无害。
        o += std::string("    mov eax, dword ptr [") + r32x(ctx_) + " + 0x10]\n";
        o += std::string("    mov ecx, dword ptr [") + r32x(ctx_) + " + 0x18]\n";
        o += std::string("    mov edx, dword ptr [") + r32x(ctx_) + " + 0x20]\n";
        // step 3: call native（cdecl 参数窗已预置；esp 由 step 4 host_rsp 重基回收）
        o += std::string("    call ") + r32x(call_carrier) + "\n";
        // step 4: esp 重基（host_rsp 单一来源，跨 call 稳定）
        o += std::string("    mov esp, dword ptr [") + r32x(ctx_) + " + 0x128]\n";
        // pc 还原（MIT-494t②；step 1.5 的同步配对）。
        o += std::string("    mov ecx, dword ptr [") + r32x(ctx_) + " + 0x8]\n";
        // step 5: 返回值写回 regs[0] 低 dword（槽高半字 0 不变量维持）
        o += std::string("    mov dword ptr [") + r32x(ctx_) + " + 0x10], eax\n";
        // step 5.5 (MIT-498 T51)：edx 写回——edx:eax 64 位返回对（__allmul
        // 类）与 in-place 移位 helper（__aullshr 类，结果 edx:eax）的半积
        // 通路；纯 cdecl 32 位 callee 下 edx = caller-saved 被毁垃圾，写回
        // 同样合法（volatile 语义 guest 不得跨 call 依赖 edx）。
        o += std::string("    mov dword ptr [") + r32x(ctx_) + " + 0x20], edx\n";
        o += advance_x86(dispatch);
        return o;
    }

    // =======================================================================
    // MIT-445 (X3c B.2)：x86 ExitNative（区域外跳转单向退出, 4B 退出槽）。
    //
    // 编码（x64 build_exitnative 同协议）：无条件 a_kind=Imm(2)（Jmp 越区
    // 形）；条件 a_kind=None + cond_or_size=ir::Cond 0..15（Jcc 越区形）。
    //
    // 退出协议 = 4B 槽（X0 §3.2-C(4) x86 形）：目标 VA（dword = aux +
    // image_base 低 dword）写 [native_sp - kX86ExitSlotDepth]（native_sp =
    // [ctx+0x120]，stub/电池预置；X4 stub_gen 读侧对接锚）。随后 x86
    // epilogue（add esp,0x24 帧回收 + 4 callee-saved 逆序 pop + ret）退出
    // 解释器——x64 面退出后经 stub HALT 段 jmp 槽；x86 无 stub（X4 前电池
    // 直执），entry 调用方拿到控制后按同址读槽（电池断言即此语义）。
    //
    // 与 x64 的结构差异（逐条对账）：
    //   1) 槽宽 4B（dword；x64 = qword [rsp-0x38] host_rsp 坐标）；
    //   2) pc 不写回（x64 同——退出路径不 advance，调用方语义）；
    //   3) 易失寄存器/xmm 写回链不在 handler（x64 在 stub HALT 段；X4 stub
    //      对接时同位实现，电池直执下 ctx 槽即真相源）；
    //   4) 条件链 cond_eval_x86（flags 常驻 [ctx+0x98]，cond_perm 随机，
    //      build_jcc_x86 同构）；无条件判据 = 帧槽 kX86FAKind==2（x64 用
    //      T3 寄存器同判）。
    // =======================================================================
    std::string build_exitnative_x86(u64 dispatch) const {
        const std::string test_lbl = "xen_t";
        const std::string exit_lbl = "xen_x";
        const std::string adv_lbl = "xen_a";
        std::string o = decode_prelude_x86();
        // 0) 无条件直退: a_kind==Imm(2)（固定标签, 不吃 seq(), 理由同 callgate）
        o += std::string("    mov ") + r32x(t_[0]) + ", " + xf(kX86FAKind) + "\n";
        o += std::string("    cmp ") + r32x(t_[0]) + ", " + imm(2) + "\n";
        o += "    je " + exit_lbl + "\n";
        // 1) 条件链 (cond 0..15, build_jcc_x86 同构: 16 路随机分派)
        for (int i = 0; i < 15; ++i) {
            const int c = cond_perm_[i];
            o += std::string("    cmp dword ptr ") + xf(kX86FSize) + ", " + imm(c) + "\n";
            o += "    je xcc" + std::to_string(c) + "_" + test_lbl + "\n";
        }
        o += "xcc" + std::to_string(cond_perm_[15]) + "_" + test_lbl + ":\n" +
             cond_eval_x86(cond_perm_[15]) + "    jmp " + test_lbl + "\n";
        for (int i = 0; i < 15; ++i) {
            const int c = cond_perm_[i];
            o += "xcc" + std::to_string(c) + "_" + test_lbl + ":\n";
            o += cond_eval_x86(c);
            o += "    jmp " + test_lbl + "\n";
        }
        o += test_lbl + ":\n";
        o += std::string("    test ") + r32x(t_[0]) + ", " + r32x(t_[0]) + "\n";
        o += "    jz " + adv_lbl + "\n";
        // 2) 退出路径: 目标 VA = aux + image_base → 4B 退出槽
        //    （槽地址 = [ctx+0x120] - kX86ExitSlotDepth, 标签不吃 seq()）
        o += exit_lbl + ":\n";
        // pc 出口同步（MIT-494t②）：[ctx+0x8] 须停在本条（电池契约 "退出
        // 路径不 advance"）——pc 常驻 ecx 后寄存器值即真相源，落槽一次。
        o += std::string("    mov dword ptr [") + r32x(ctx_) + " + 0x8], ecx\n";
        o += std::string("    mov ") + r32x(t_[1]) + ", " + xf(kX86FAux) + "\n";
        o += std::string("    add ") + r32x(t_[1]) + ", dword ptr [" + r32x(ctx_) +
             " + 0x110]\n";
        o += std::string("    mov ") + r32x(t_[0]) + ", dword ptr [" + r32x(ctx_) +
             " + 0x120]\n";
        o += std::string("    sub ") + r32x(t_[0]) + ", " + imm(kX86ExitSlotDepth) + "\n";
        o += std::string("    mov dword ptr [") + r32x(t_[0]) + "], " + r32x(t_[1]) + "\n";
        // 2.5) X6 A: xmm0-7 写回（ctx.xmm → 物理 —— SSE 面；ExitNative x86
        //      内联 epilogue 直退不经 stub 出口，与 Halt 面 stub 出口同步
        //      语义对齐 —— x64 ExitNative 经 Halt→stub 出口吃同步，x86 因
        //      X3c 内联 epilogue 结构须自带）。
        for (int i = 0; i < 8; ++i)
            o += std::string("    movups xmm") + std::to_string(i) + ", [" +
                 r32x(ctx_) + " + " + imm(kCtxXmmBase + u64(i) * 16) + "]\n";
        // 3) x86 epilogue: 帧回收 + callee-saved 逆序恢复 + ret（build_halt_x86 同构）
        o += std::string("    add esp, ") + imm(kX86FrameSize) + "\n";
        const auto order = x86_save_order();
        for (int i = 3; i >= 0; --i)
            o += std::string("    pop ") + r32x(order[i]) + "\n";
        o += "    ret\n";
        o += adv_lbl + ":\n";
        o += advance_x86(dispatch);
        return o;
    }

    // =======================================================================
    // MIT-445 (X3c B.3)：x86 Ret 清栈返回（4B 栈宽, x64 build_ret 的 32 位
    // 形, 438 aux 语义 arch 分叉落地）。
    //
    // 语义（SDM RET.Near imm16 的 x86 形 + 444 裁决表"零扩展不变量 + dword
    // 低半字算术"）：ret_addr = dword [v4]；v4' = v4 + 4 + imm（imm 零扩展
    // u16 字节数——translator 既有 0xFFFF 掩码；dword 回绕 = native esp 语
    // 义，"槽高半字恒 0" 不变量下 dword 运算等价 64 位槽算术）；ret_addr →
    // [v4'-4]（终态 jmp 槽 = 清栈后 esp 之下的死栈区）。
    //
    // 出口 = 退出 VM 直接返回 guest caller（x64 build_ret"handler 内直接退
    // 出"先例，不走 Halt/stub 通道）：终态物理 esp := v4'、jmp [v4'-4]——
    // 与原生 ret imm 后 caller 视角逐位一致。终态零活寄存器依赖：v4' 持久
    // 化 [ctx+0x30] + 宿主栈 push 暂存（出口坐标见 kX86RetV4SlotFromExitRsp
    // 注），ret_addr 落死槽（438 x64 [v4'-8] 同款落盘纪律，x86 死槽 4B 宽）。
    //
    // 与 x64 的结构差异（逐条对账）：
    //   1) 4B 栈宽：pop 返回地址 dword 读、esp 步进 4+imm（x64 = 8+imm）；
    //   2) 易失寄存器写回 = cdecl 面 eax/ecx/edx ← ctx 槽（x64 = Win64 面
    //      rax/rcx/rdx/r8-r11 七槽）；xmm 写回不适用（x86 面无 SSE handler，
    //      x87/MMX callee 副作用不建模，D1 恒 gate）；
    //   3) 弃帧 = add esp,0x24（x64 = add rsp,0x210）；callee-saved pop = 4
    //      个（x64 = 8 个），序 = entry push 严格逆序（x86_save_order）；
    //   4) 终态 esp := v4' 宿主栈坐标读（x64 = [rsp-0x1D8] 读 stub 帧 ctx
    //      区——x86 ctx 结构位置不定，改 push 暂存坐标，见常量注）；
    //   5) 438"guest 栈写恒 ≥ ns"对账：[v4'-4] 死槽写与 x64 [v4'-8] 同形
    //      ——清栈后 esp 之下的死栈区写；与 x86 保存区 [ns-4..ns-0x10] 重叠
    //      仅在 v4' > ns-0x10 的病态形（未配平 ret），同 x64 EXIT_SLOT 重叠
    //      披露，不新增防线（继承既有边界登记）；电池 guest 栈 = 静态缓冲，
    //      零碰撞。
    // =======================================================================
    std::string build_ret_x86(u64 /*dispatch*/) const {
        std::string o = decode_prelude_x86();   // aux 帧槽 = imm（零扩展）
        // 1) 栈语义：ret_addr = dword [v4]；v4' = v4 + 4 + imm；v4' 持久化；
        //    ret_addr → [v4'-4] 死槽。
        o += std::string("    mov ") + r32x(t_[0]) + ", dword ptr [" + r32x(ctx_) +
             " + 0x30]\n";                        // t0 = v4（低 dword, 零扩展不变量）
        o += std::string("    mov ") + r32x(t_[1]) + ", dword ptr [" + r32x(t_[0]) +
             "]\n";                               // t1 = ret_addr
        o += std::string("    add ") + r32x(t_[0]) + ", " + imm(4) + "\n";
        o += std::string("    add ") + r32x(t_[0]) + ", " + xf(kX86FAux) + "\n";
        o += std::string("    mov dword ptr [") + r32x(ctx_) + " + 0x30], " +
             r32x(t_[0]) + "\n";                  // v4' 持久化（低 dword；高半字 0 维持）
        // 2) v4' 宿主栈暂存（出口坐标, 见 kX86RetV4SlotFromExitRsp 常量注）。
        //    ⚠️ 必须在死槽指针 (t0 -= 4) 之前 push——push 的必须是 v4' 本体，
        //    先减后 push 会把死槽地址当 v4' 存入（E2E 实证：esp 终态 = top-4,
        //    jmp [esp-4] 落 memset 零页 → eip=0）。
        o += std::string("    push ") + r32x(t_[0]) + "\n";
        o += std::string("    sub ") + r32x(t_[0]) + ", " + imm(4) + "\n";
        o += std::string("    mov dword ptr [") + r32x(t_[0]) + "], " + r32x(t_[1]) + "\n";
        // 3) 易失寄存器写回（cdecl: eax/ecx/edx ← ctx 槽；可覆盖 t0/t1——
        //    终态已零活寄存器依赖）。
        o += std::string("    mov eax, dword ptr [") + r32x(ctx_) + " + 0x10]\n";
        o += std::string("    mov ecx, dword ptr [") + r32x(ctx_) + " + 0x18]\n";
        o += std::string("    mov edx, dword ptr [") + r32x(ctx_) + " + 0x20]\n";
        // 3.5) X6 A: xmm0-7 写回（ctx.xmm → 物理 —— SSE 面；Ret 直退不经
        //      stub 出口，x64 build_ret 步 3 同款镜像）。
        for (int i = 0; i < 8; ++i)
            o += std::string("    movups xmm") + std::to_string(i) + ", [" +
                 r32x(ctx_) + " + " + imm(kCtxXmmBase + u64(i) * 16) + "]\n";
        // 4) 弃帧（含暂存槽顶出）+ 恢复宿主 callee-saved（entry push 序严格逆序）。
        o += std::string("    add esp, ") + imm(kX86RetExitFrameAdvance) + "\n";
        const auto order = x86_save_order();
        for (int i = 3; i >= 0; --i)
            o += std::string("    pop ") + r32x(order[i]) + "\n";
        // 5) 终态：物理 esp := v4'（宿主栈坐标读, 读发生在 esp 变更前），
        //    jmp [esp-4] 死槽 → ret_addr（esp 保持 v4' = 原生 ret imm 后态）。
        o += std::string("    mov esp, dword ptr [esp - ") +
             hex(kX86RetV4SlotFromExitRsp) + "]\n";
        o += "    jmp dword ptr [esp - " + imm(4) + "]\n";
        return o;
    }

    std::string build_x86_ret(u64 d) const { return build_ret_x86(d); }

    std::string build_x86_exitnative(u64 d) const { return build_exitnative_x86(d); }

    std::string build_x86_callgate(u64 d) const { return build_callgate_x86(d); }

    // x86 LoadRva（build_loadrva 的 32 位版）：b 槽 = RVA（u32），+ image_base
    //（ctx+0x110 scratch_mem 低 dword —— PE32 ImageBase < 2^31 值域，u32 加法
    // 即 VA，**非 identity**：电池 RvaFamily 以 base≠0 钉死 base+RVA 公式）→
    // VA 宽度读 → reg_a 槽。三路宽度链（S8/S16/S32）。
    std::string build_loadrva_x86(u64 dispatch) const {
        const std::string tag = "xldrva" + std::to_string(seq());
        const std::string tail_lbl = "xtail_" + tag;
        std::string blocks[3];
        for (int s = 0; s < 3; ++s) {
            std::string o;
            o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegB) + "\n";
            o += std::string("    mov ") + r32x(t_[1]) + ", dword ptr " + xslot(t_[2]) + "\n";
            o += std::string("    add ") + r32x(t_[1]) + ", dword ptr [" + r32x(ctx_) +
                 " + 0x110]\n";
            if (s == 2)
                o += std::string("    mov ") + r32x(t_[0]) + ", dword ptr [" + r32x(t_[1]) +
                     "]\n";
            else
                o += std::string("    movzx ") + r32x(t_[0]) + ", " + mptr(s) + " [" +
                     r32x(t_[1]) + "]\n";
            o += writeback_x86(s, kX86FRegA, t_[0], t_[1]);
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude_x86() + size_chain_x86(blocks, tag, dispatch) +
               tail_lbl + ":\n" + advance_x86(dispatch);
    }

    // x86 StoreRva（build_storerva 的 32 位版）：a 槽 = RVA → +image_base →
    // VA，b 操作数按宽度写 [VA]。三路宽度链。
    std::string build_storerva_x86(u64 dispatch) const {
        const std::string tag = "xstrva" + std::to_string(seq());
        const std::string tail_lbl = "xtail_" + tag;
        std::string blocks[3];
        for (int s = 0; s < 3; ++s) {
            const std::string stag = tag + "_" + std::to_string(s);
            std::string o;
            o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegA) + "\n";
            o += std::string("    mov ") + r32x(t_[1]) + ", dword ptr " + xslot(t_[2]) + "\n";
            o += std::string("    add ") + r32x(t_[1]) + ", dword ptr [" + r32x(ctx_) +
                 " + 0x110]\n";
            o += load_operand_x86(s, kX86FBKind, kX86FRegB, t_[0], "b" + stag);
            o += std::string("    mov ") + mptr(s) + " [" + r32x(t_[1]) + "], " +
                 rs(t_[0], s) + "\n";
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        return decode_prelude_x86() + size_chain_x86(blocks, tag, dispatch) +
               tail_lbl + ":\n" + advance_x86(dispatch);
    }

    // x86 LeaRva（build_lea_rva 的 32 位版）：a 槽 ← RVA + image_base（不访存
    // —— M2-8/MIT-322 通路）。无尺寸链（lea 不写子寄存器别名，x64 qword 直写
    // 的 32 位形 = dword 直写）。
    std::string build_lea_rva_x86(u64 dispatch) const {
        const std::string tag = "xlearva" + std::to_string(seq());
        const std::string tail_lbl = "xtail_" + tag;
        std::string o = decode_prelude_x86();
        o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegB) + "\n";
        o += std::string("    mov ") + r32x(t_[1]) + ", dword ptr " + xslot(t_[2]) + "\n";
        o += std::string("    add ") + r32x(t_[1]) + ", dword ptr [" + r32x(ctx_) +
             " + 0x110]\n";
        o += std::string("    mov ") + r32x(t_[2]) + ", " + xf(kX86FRegA) + "\n";
        o += std::string("    mov dword ptr ") + xslot(t_[2]) + ", " + r32x(t_[1]) + "\n";
        o += advance_x86(dispatch);
        return o;
    }

    // ---- x86 一元包装（HandlerDef 需要无参差成员函数指针） ----------------
    std::string build_x86_add(u64 d) const { return build_binary_x86("add", d, true); }
    std::string build_x86_sub(u64 d) const { return build_binary_x86("sub", d, true); }
    std::string build_x86_and(u64 d) const { return build_binary_x86("and", d, true); }
    std::string build_x86_or(u64 d)  const { return build_binary_x86("or", d, true); }
    std::string build_x86_xor(u64 d) const { return build_binary_x86("xor", d, true); }
    std::string build_x86_cmp(u64 d) const { return build_binary_x86("sub", d, false); }
    std::string build_x86_test(u64 d) const { return build_binary_x86("test", d, false); }
    std::string build_x86_inc(u64 d) const { return build_incdec_x86("inc", d); }
    std::string build_x86_dec(u64 d) const { return build_incdec_x86("dec", d); }
    std::string build_x86_mov(u64 d) const { return build_mov_x86(d); }
    std::string build_x86_load(u64 d) const { return build_load_x86(d); }
    std::string build_x86_store(u64 d) const { return build_store_x86(d); }
    // build_x86_jcc = MIT-494s 跳表化包装（build_x86_jcc_at），原别名删除。
    std::string build_x86_jmp(u64 d) const { return build_jmp_x86(d); }
    std::string build_x86_nop(u64 d) const { return build_nop_x86(d); }
    std::string build_x86_halt(u64 d) const { return build_halt_x86(d); }
    std::string build_x86_getflags(u64 d) const { return build_getflags_x86(d); }
    std::string build_x86_setflags(u64 d) const { return build_setflags_x86(d); }
    // X3b 批迁包装（A 档批次一：一元/带进借位二元/乘法/符号扩展族）。
    std::string build_x86_not(u64 d) const { return build_not_x86(d); }
    std::string build_x86_neg(u64 d) const { return build_neg_x86(d); }
    std::string build_x86_adc(u64 d) const { return build_adc_sbb_x86("adc", d); }
    std::string build_x86_sbb(u64 d) const { return build_adc_sbb_x86("sbb", d); }
    std::string build_x86_imul(u64 d) const { return build_imul_x86(d); }
    std::string build_x86_mul(u64 d) const { return build_mul_x86(d); }
    std::string build_x86_cdq(u64 d) const { return build_cdq_x86(d); }
    // MIT-X7 批二：Div/Idiv x86 白名单闸解除（453 b59b 残面收口）。
    std::string build_x86_div(u64 d) const { return build_div_idiv_x86(d, "div"); }
    std::string build_x86_idiv(u64 d) const { return build_div_idiv_x86(d, "idiv"); }
    // X3b 批次二：移位/旋转族（imm 与 cl 变体共享 builder，b_kind 分支分流）。
    std::string build_x86_shl(u64 d) const { return build_shift_x86("shl", d); }
    std::string build_x86_shr(u64 d) const { return build_shift_x86("shr", d); }
    std::string build_x86_sar(u64 d) const { return build_shift_x86("sar", d); }
    std::string build_x86_rol(u64 d) const { return build_shift_x86("rol", d, true); }
    std::string build_x86_ror(u64 d) const { return build_shift_x86("ror", d, true); }
    std::string build_x86_shl_cl(u64 d) const { return build_shift_x86("shl", d); }
    std::string build_x86_shr_cl(u64 d) const { return build_shift_x86("shr", d); }
    std::string build_x86_sar_cl(u64 d) const { return build_shift_x86("sar", d); }
    std::string build_x86_rol_cl(u64 d) const { return build_shift_x86("rol", d, true); }
    std::string build_x86_ror_cl(u64 d) const { return build_shift_x86("ror", d, true); }
    // X3b 批次三：扩展传送 / 字节序 / 交换族。
    std::string build_x86_movzx(u64 d) const { return build_extend_x86("movzx", d); }
    std::string build_x86_movzx_mem(u64 d) const { return build_extend_mem_x86("movzx", d); }
    std::string build_x86_movsx(u64 d) const { return build_extend_x86("movsx", d); }
    std::string build_x86_movsx_mem(u64 d) const { return build_extend_mem_x86("movsx", d); }
    std::string build_x86_bswap(u64 d) const { return build_bswap_x86(d); }
    std::string build_x86_xchg(u64 d) const { return build_xchg_x86(d); }
    // X3b 批次四：条件族（reads-flags 面）。
    std::string build_x86_setcc(u64 d) const { return build_setcc_x86(d); }
    std::string build_x86_cmovcc(u64 d) const { return build_cmovcc_x86(d); }
    // X3b 批次五：位计数 / 锁原子族。
    std::string build_x86_popcnt(u64 d) const { return build_bitcount_x86("popcnt", false, d); }
    std::string build_x86_lzcnt(u64 d) const { return build_bitcount_x86("lzcnt", true, d); }
    std::string build_x86_tzcnt(u64 d) const { return build_bitcount_x86("tzcnt", true, d); }
    std::string build_x86_cmpxchg(u64 d) const { return build_cmpxchg_x86(d); }
    std::string build_x86_xadd(u64 d) const { return build_xadd_x86(d); }
    std::string build_x86_bts(u64 d) const { return build_bit_op_x86("bts", d); }
    std::string build_x86_btr(u64 d) const { return build_bit_op_x86("btr", d); }
    std::string build_x86_btc(u64 d) const { return build_bit_op_x86("btc", d); }
    // X3b 批次六：B 档 GP（栈原语 + RVA 族）。
    std::string build_x86_push(u64 d) const { return build_push_x86(d); }
    std::string build_x86_pop(u64 d) const { return build_pop_x86(d); }
    std::string build_x86_loadrva(u64 d) const { return build_loadrva_x86(d); }
    std::string build_x86_storerva(u64 d) const { return build_storerva_x86(d); }
    std::string build_x86_learva(u64 d) const { return build_lea_rva_x86(d); }

private:
    Rng& rng_;
    HostArch arch_ = HostArch::X64;
    // MIT-473: 取指级解密织入开关（缺省 false = 缺省管道解释器字节与锚点
    // dump 逐字节恒等；true 时 dispatch fetch 后织入 xor_chain 原位解密）。
    bool fetch_decrypt_ = false;
    int ctx_ = 0, pc_ = 0, flags_ = 0, base_ = 0;
    int t_[10] = {};
    std::array<int, 4> size_perm_{};
    std::array<int, 16> cond_perm_{};
    std::array<int, 3> x86_size_perm_{};
    mutable int seq_ = 0;
};

struct HandlerDef {
    int opcode;
    const char* name;
    std::string (AsmGen::*build)(u64) const;
};

// MIT-446 (X4)：x86 handler 表定义提为独立函数 —— generate_runtime_arch 的
// X86 分支与 x86_handler_opcodes()（stub_link 白名单 gate）共用同一份清单，
// 表加行两处自动跟随，禁第二份手抄（MIT-B2 单一来源纪律）。
std::vector<HandlerDef> x86_handler_table() {
    using isa::VmOp;
    return {
        {int(VmOp::Mov), "mov", &AsmGen::build_x86_mov},
        {int(VmOp::Lea), "lea", &AsmGen::build_x86_mov},
        {int(VmOp::Add), "add", &AsmGen::build_x86_add},
        {int(VmOp::Sub), "sub", &AsmGen::build_x86_sub},
        {int(VmOp::And), "and", &AsmGen::build_x86_and},
        {int(VmOp::Or), "or", &AsmGen::build_x86_or},
        {int(VmOp::Xor), "xor", &AsmGen::build_x86_xor},
        {int(VmOp::Cmp), "cmp", &AsmGen::build_x86_cmp},
        {int(VmOp::Test), "test", &AsmGen::build_x86_test},
        {int(VmOp::Inc), "inc", &AsmGen::build_x86_inc},
        {int(VmOp::Dec), "dec", &AsmGen::build_x86_dec},
        {int(VmOp::Load), "load", &AsmGen::build_x86_load},
        {int(VmOp::Store), "store", &AsmGen::build_x86_store},
        {int(VmOp::Jmp), "jmp", &AsmGen::build_x86_jmp},
        {int(VmOp::Jcc), "jcc", &AsmGen::build_x86_jcc},
        {int(VmOp::Nop), "nop", &AsmGen::build_x86_nop},
        {int(VmOp::Halt), "halt", &AsmGen::build_x86_halt},
        {int(VmOp::GetFlags), "getflags", &AsmGen::build_x86_getflags},
        {int(VmOp::SetFlags), "setflags", &AsmGen::build_x86_setflags},
        // —— X3b (MIT-444) A 档批次一：一元 / 带进借位二元 / 乘法 / 符号扩展 ——
        {int(VmOp::Not), "not", &AsmGen::build_x86_not},
        {int(VmOp::Neg), "neg", &AsmGen::build_x86_neg},
        {int(VmOp::Adc), "adc", &AsmGen::build_x86_adc},
        {int(VmOp::Sbb), "sbb", &AsmGen::build_x86_sbb},
        {int(VmOp::Imul), "imul", &AsmGen::build_x86_imul},
        {int(VmOp::Mul), "mul", &AsmGen::build_x86_mul},
        {int(VmOp::Cdq), "cdq", &AsmGen::build_x86_cdq},
        // —— X7 (MIT-455) 批二：Div/Idiv 32 位真 handler（build_div_idiv
        // 镜像；453 b59b 残面收口，除零=真 #DE 直通 x64 D2.1 同口径）——
        {int(VmOp::Div), "div", &AsmGen::build_x86_div},
        {int(VmOp::Idiv), "idiv", &AsmGen::build_x86_idiv},
        // —— X3b (MIT-444) A 档批次二：移位/旋转族（imm + cl 变体）——
        {int(VmOp::Shl), "shl", &AsmGen::build_x86_shl},
        {int(VmOp::Shr), "shr", &AsmGen::build_x86_shr},
        {int(VmOp::Sar), "sar", &AsmGen::build_x86_sar},
        {int(VmOp::Rol), "rol", &AsmGen::build_x86_rol},
        {int(VmOp::Ror), "ror", &AsmGen::build_x86_ror},
        {int(VmOp::ShlCl), "shlcl", &AsmGen::build_x86_shl_cl},
        {int(VmOp::ShrCl), "shrcl", &AsmGen::build_x86_shr_cl},
        {int(VmOp::SarCl), "sarcl", &AsmGen::build_x86_sar_cl},
        {int(VmOp::RolCl), "rolcl", &AsmGen::build_x86_rol_cl},
        {int(VmOp::RorCl), "rorcl", &AsmGen::build_x86_ror_cl},
        // —— X3b (MIT-444) A 档批次三：扩展传送 / 字节序 / 交换族 ——
        {int(VmOp::Movzx), "movzx", &AsmGen::build_x86_movzx},
        {int(VmOp::MovzxMem), "movzxmem", &AsmGen::build_x86_movzx_mem},
        {int(VmOp::Movsx), "movsx", &AsmGen::build_x86_movsx},
        {int(VmOp::MovsxMem), "movsxmem", &AsmGen::build_x86_movsx_mem},
        {int(VmOp::Bswap), "bswap", &AsmGen::build_x86_bswap},
        {int(VmOp::Xchg), "xchg", &AsmGen::build_x86_xchg},
        // —— X3b (MIT-444) A 档批次四：条件族（reads-flags 面）——
        {int(VmOp::Setcc), "setcc", &AsmGen::build_x86_setcc},
        {int(VmOp::Cmovcc), "cmovcc", &AsmGen::build_x86_cmovcc},
        // —— X3b (MIT-444) A 档批次五：位计数 / 锁原子族 ——
        {int(VmOp::Popcnt), "popcnt", &AsmGen::build_x86_popcnt},
        {int(VmOp::Lzcount), "lzcnt", &AsmGen::build_x86_lzcnt},
        {int(VmOp::Tzcount), "tzcnt", &AsmGen::build_x86_tzcnt},
        {int(VmOp::Cmpxchg), "cmpxchg", &AsmGen::build_x86_cmpxchg},
        {int(VmOp::Xadd), "xadd", &AsmGen::build_x86_xadd},
        {int(VmOp::Bts), "bts", &AsmGen::build_x86_bts},
        {int(VmOp::Btr), "btr", &AsmGen::build_x86_btr},
        {int(VmOp::Btc), "btc", &AsmGen::build_x86_btc},
        // —— X3b (MIT-444) B 档 GP：栈原语（4B 槽裁决）+ RVA 族 ——
        {int(VmOp::Push), "push", &AsmGen::build_x86_push},
        {int(VmOp::Pop), "pop", &AsmGen::build_x86_pop},
        {int(VmOp::LoadRva), "loadrva", &AsmGen::build_x86_loadrva},
        {int(VmOp::StoreRva), "storeriva", &AsmGen::build_x86_storerva},
        {int(VmOp::LeaRva), "learva", &AsmGen::build_x86_learva},
        // —— X3c (MIT-445) 协议面批次一：CallGate reg 值目标 + RVA 双形 ——
        {int(VmOp::CallGate), "callgate", &AsmGen::build_x86_callgate},
        // —— X3c (MIT-445) 协议面批次二：ExitNative 4B 退出槽 ——
        {int(VmOp::ExitNative), "exitnative", &AsmGen::build_x86_exitnative},
        // —— X3c (MIT-445) 协议面批次三：Ret 4B 清栈返回 ——
        {int(VmOp::Ret), "ret", &AsmGen::build_x86_ret},
        // —— X6 (MIT-454) A=X3d 批次二：SSE 32 位镜像（算术 16 + 传送 6 +
        // 位运算 4 + mem 原语 2 + GP↔xmm 桥 2；批三 ucomis 2）——
        {int(VmOp::Addss), "addss", &AsmGen::build_x86_addss},
        {int(VmOp::Addps), "addps", &AsmGen::build_x86_addps},
        {int(VmOp::Addpd), "addpd", &AsmGen::build_x86_addpd},
        {int(VmOp::Subss), "subss", &AsmGen::build_x86_subss},
        {int(VmOp::Subps), "subps", &AsmGen::build_x86_subps},
        {int(VmOp::Subpd), "subpd", &AsmGen::build_x86_subpd},
        {int(VmOp::Mulss), "mulss", &AsmGen::build_x86_mulss},
        {int(VmOp::Mulsd), "mulsd", &AsmGen::build_x86_mulsd},
        {int(VmOp::Mulps), "mulps", &AsmGen::build_x86_mulps},
        {int(VmOp::Mulpd), "mulpd", &AsmGen::build_x86_mulpd},
        {int(VmOp::Divss), "divss", &AsmGen::build_x86_divss},
        {int(VmOp::Divsd), "divsd", &AsmGen::build_x86_divsd},
        {int(VmOp::Divps), "divps", &AsmGen::build_x86_divps},
        {int(VmOp::Divpd), "divpd", &AsmGen::build_x86_divpd},
        {int(VmOp::Addsd), "addsd", &AsmGen::build_x86_addsd},
        {int(VmOp::Subsd), "subsd", &AsmGen::build_x86_subsd},
        {int(VmOp::Movss), "movss", &AsmGen::build_x86_movss},
        {int(VmOp::Movsd), "movsd", &AsmGen::build_x86_movsd},
        {int(VmOp::Movaps), "movaps", &AsmGen::build_x86_movaps},
        {int(VmOp::Movapd), "movapd", &AsmGen::build_x86_movapd},
        {int(VmOp::Movups), "movups", &AsmGen::build_x86_movups},
        {int(VmOp::Movupd), "movupd", &AsmGen::build_x86_movupd},
        {int(VmOp::Xorps), "xorps", &AsmGen::build_x86_xorps},
        {int(VmOp::Orps), "orps", &AsmGen::build_x86_orps},
        {int(VmOp::Andps), "andps", &AsmGen::build_x86_andps},
        {int(VmOp::Andnps), "andnps", &AsmGen::build_x86_andnps},
        {int(VmOp::XmmLoad), "xmmload", &AsmGen::build_xmm_load_x86},
        {int(VmOp::XmmStore), "xmmstore", &AsmGen::build_xmm_store_x86},
        {int(VmOp::XmmFromGp), "xmmfromgp", &AsmGen::build_xmm_from_gp_x86},
        {int(VmOp::GpFromXmm), "gpfromxmm", &AsmGen::build_gp_from_xmm_x86},
        // —— X6 (MIT-454) A=X3d 批次三：SSE 比较族（flags 面，32 op 收尾）——
        {int(VmOp::Ucomiss), "ucomiss", &AsmGen::build_x86_ucomiss},
        {int(VmOp::Ucomisd), "ucomisd", &AsmGen::build_x86_ucomisd},
    };
}

} // namespace

// MIT-443 (X3a)：双模管线。x64 路径（arch=X64）逐字保留既有序列 —— roll/
// 两遍法/handler 表/dump 输出全部原样，D6 恒等按同 seed dump 逐字节对账。
RuntimeGenResult generate_runtime_arch(wvmp::Rng& rng, AsmGen::HostArch arch,
                                       bool fetch_decrypt = false) {
    using isa::VmOp;
    AsmGen g(rng, arch, fetch_decrypt);
    g.roll();
    KsSession ks(arch == AsmGen::HostArch::X86 ? unsigned(KS_MODE_32)
                                               : unsigned(KS_MODE_64));

    // —— 入口块（地址 0；跌入 dispatch，无跨块引用）——
    const std::string entry_text = g.build_entry();
    const std::vector<u8> entry_code = ks.assemble(entry_text, 0, "entry");
    const u64 dispatch_addr = entry_code.size();

    // —— dispatch 第 1 遍（哑表偏移，强制 disp32 编码）——
    constexpr u64 kDummyTableOff = 0x4000'0000ull;
    const std::vector<u8> dispatch1 =
        ks.assemble(g.build_dispatch(kDummyTableOff), dispatch_addr, "dispatch pass1");
    const u64 dispatch_size = dispatch1.size();

    // —— handler 清单（按 arch 选择；x64 面 Call 的表项指向
    //    Halt——遇到即停机，语义保守且不越界（call 由 CallGate 接管）。
    //    Sar 在 MIT-244 已接管。Adc 在 MIT-245 已接管；Sbb 在 MIT-246 已接管；
    //    Rol/Ror 在 MIT-247 已接管。CallGate 在 MIT-249 已接管。
    //    Ret 在 MIT-438 已接管（清栈返回，见 build_ret 注释）。）
    //    x86 面（MIT-445 (X3c) 批次三后）：60 行 = 电池集 19（X3a）+ A 档
    //    整数面 29（一元/进借位/乘除扩展/移位旋转/扩展传送/条件/位计数/原子）
    //    + B 档 GP 5（Push/Pop + RVA 族）+ G4 原子 4（Xadd/Bts/Btr/Btc）
    //    + 协议面 3（X3c 收口：CallGate reg 值目标 + RVA 双形 / ExitNative
    //    4B 退出槽 / Ret 4B 清栈返回）。
    //    仍纸面（折叠 Halt，恢复友好）= Movsxd/MovsxdMem（x86 不可达）、
    //    SSE 族 32（X2b/X3c 面）—— 精确清单见 docs/GAPS.md X3b/X3c 节。
    //    MIT-X7 批二：Div/Idiv 出纸面入真表（build_div_idiv_x86，D2 除零
    //    折叠 → x64 真 #DE 直通口径镜像，92 → 94 行）。
    std::vector<HandlerDef> handlers;
    if (arch == AsmGen::HostArch::X86) {
        // MIT-446 (X4)：表定义提为 x86_handler_table()（与 x86_handler_opcodes
        // 白名单 gate 共用单一来源，本文件上方注）。
        handlers = x86_handler_table();
    } else {
        handlers = {
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
        // MIT-419 (G4): lock 前缀原子族 — xadd (InterlockedAdd 真产物,
        // native lock xadd [addr],reg 单指令直执行, 硬件原子性保真) +
        // bts/btr/btc (InterlockedBitTest* 真产物, imm8/reg 双形式)。
        {int(VmOp::Xadd), "xadd", &AsmGen::build_xadd},
        {int(VmOp::Bts), "bts", &AsmGen::build_bts},
        {int(VmOp::Btr), "btr", &AsmGen::build_btr},
        {int(VmOp::Btc), "btc", &AsmGen::build_btc},
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
        // MIT-374: SSE 浮点除 divss/divps/divpd (3 形式, REG-REG only, 沿用
        // MIT-371 add / MIT-373 sub 模板 + 硬编码 xmm0/xmm1 物理寄存器; 复用
        // VmContext.xmm[8] 跟踪区 @ +0x140, 槽位偏移常量全走 imm()).
        {int(VmOp::Divss), "divss", &AsmGen::build_divss},
        {int(VmOp::Divps), "divps", &AsmGen::build_divps},
        {int(VmOp::Divpd), "divpd", &AsmGen::build_divpd},
        {int(VmOp::Movss), "movss", &AsmGen::build_movss},
        {int(VmOp::Movaps), "movaps", &AsmGen::build_movaps},
        {int(VmOp::Movapd), "movapd", &AsmGen::build_movapd},
        {int(VmOp::Movups), "movups", &AsmGen::build_movups},
        {int(VmOp::Movupd), "movupd", &AsmGen::build_movupd},
        // MIT-376: SSE 浮点位运算 xorps/orps/andps (3 形式, REG-REG only, 复用
        // MIT-375 build_xmm_transfer 四步模板, 中间行换成 native 位运算; 复用
        // VmContext.xmm[8] 跟踪区 @ +0x140, 槽位偏移常量全走 imm()).
        {int(VmOp::Xorps), "xorps", &AsmGen::build_xorps},
        {int(VmOp::Orps), "orps", &AsmGen::build_orps},
        {int(VmOp::Andps), "andps", &AsmGen::build_andps},
        // MIT-425 (G1b): SSE 浮点乘 mul 族 (mulss/mulsd/mulps/mulpd, 与
        // add/sub/div 族同模板; MSVC /Od 对 double/float 乘法天然直产
        // mulsd/mulss, intrinsic 直产 mulps/mulpd) + andnps (dst=~dst&src,
        // _mm_andnot_si128/_mm_andnot_pd 真产物 0F 55; andnpd/pandn 折叠)。
        {int(VmOp::Mulss), "mulss", &AsmGen::build_mulss},
        {int(VmOp::Mulsd), "mulsd", &AsmGen::build_mulsd},
        {int(VmOp::Mulps), "mulps", &AsmGen::build_mulps},
        {int(VmOp::Mulpd), "mulpd", &AsmGen::build_mulpd},
        {int(VmOp::Andnps), "andnps", &AsmGen::build_andnps},
        // MIT-376: SSE 浮点比较 ucomiss/ucomisd (REG-REG only, 只写 EFLAGS 不改
        // xmm; 走 ALU binop 同一条 flags 通路 zero5 → native → setcc5 →
        // flags_tail, 与 setcc/jcc handler 共享 flags_ 寄存器 — 派活单 §D D1.1,
        // 禁止 decode+advance 空转 pitfall #79).
        {int(VmOp::Ucomiss), "ucomiss", &AsmGen::build_ucomiss},
        {int(VmOp::Ucomisd), "ucomisd", &AsmGen::build_ucomisd},
        // MIT-404: 整数除法族 div/idiv + 符号扩展 cdq/cqo (native 直通, 双槽
        // rax/rdx 协议对齐 build_mul; CDQE 归一 Movsxd 走既有 build_movsxd
        // handler, 不单独注册)。
        {int(VmOp::Cdq), "cdq", &AsmGen::build_cdq},
        {int(VmOp::Div), "div", &AsmGen::build_div},
        {int(VmOp::Idiv), "idiv", &AsmGen::build_idiv},
        {int(VmOp::Cmp), "cmp", &AsmGen::build_cmp},
        {int(VmOp::Test), "test", &AsmGen::build_test},
        {int(VmOp::Load), "load", &AsmGen::build_load},
        {int(VmOp::Store), "store", &AsmGen::build_store},
        {int(VmOp::LoadRva), "loadrva", &AsmGen::build_loadrva},
        {int(VmOp::StoreRva), "storeriva", &AsmGen::build_storerva},
        {int(VmOp::LeaRva), "learva", &AsmGen::build_lea_rva},
        {int(VmOp::Push), "push", &AsmGen::build_push},
        {int(VmOp::Pop), "pop", &AsmGen::build_pop},
        // MIT-438 (X1b): ret imm16 清栈返回（aux 载 imm，D2 选型 (i) 零新 VmOp）。
        {int(VmOp::Ret), "ret", &AsmGen::build_ret},
        {int(VmOp::Jmp), "jmp", &AsmGen::build_jmp},
        {int(VmOp::Jcc), "jcc", &AsmGen::build_jcc},
        {int(VmOp::Nop), "nop", &AsmGen::build_nop},
        {int(VmOp::Halt), "halt", &AsmGen::build_halt},
        {int(VmOp::GetFlags), "getflags", &AsmGen::build_getflags},
        {int(VmOp::SetFlags), "setflags", &AsmGen::build_setflags},
        {int(VmOp::CallGate), "callgate", &AsmGen::build_callgate},
        {int(VmOp::ExitNative), "exitnative", &AsmGen::build_exitnative},
        // MIT-408: SSE scalar-double 族 (addsd/subsd/divsd/movsd, REG-REG,
        // 与 ss/ps/pd 同模板; MOVSD 是 F2 0F 10 传送, build_movsd 走
        // build_xmm_transfer) + mem 形式原语 XmmLoad/XmmStore (宽度经 aux,
        // 双语义槽寻址, 一律 movups 非对齐语义 D2)。
        {int(VmOp::Movsd), "movsd", &AsmGen::build_movsd},
        {int(VmOp::Addsd), "addsd", &AsmGen::build_addsd},
        {int(VmOp::Subsd), "subsd", &AsmGen::build_subsd},
        {int(VmOp::Divsd), "divsd", &AsmGen::build_divsd},
        {int(VmOp::XmmLoad), "xmmload", &AsmGen::build_xmm_load},
        {int(VmOp::XmmStore), "xmmstore", &AsmGen::build_xmm_store},
        // MIT-427 (G1c): movd/movq GP↔xmm 桥原语 (xmm 槽 ↔ GP 槽, 高位
        // 清零/截取语义经 native movd/movq/movsd mem 形式直产; dump 门
        // BRIDGE_HANDLERS 注册表同步, scripts/verifier/dump_handler_xmm_check.py)。
        {int(VmOp::XmmFromGp), "xmmfromgp", &AsmGen::build_xmm_from_gp},
        {int(VmOp::GpFromXmm), "gpfromxmm", &AsmGen::build_gp_from_xmm},
        };
    }
    rng.shuffle(handlers.begin(), handlers.end());   // 码序随机

    // —— 逐 handler 以真实运行地址独立汇编（内部标签互不冲突）——
    std::vector<u8> handler_code;
    std::map<int, u64> handler_off;
    std::map<int, std::string> handler_text;   // dump 复用（标签序号勿再递增）
    u64 cursor = dispatch_addr + dispatch_size;
    // MIT-494s 验收 Nit1：两遍法按表项名 "jcc" 特殊化——表项改名会静默落
    // 入兼容包装（哑 +1GB 偏移路径，且无 pass2 尺寸断言可拦）。fail-fast。
    if (std::count_if(handlers.begin(), handlers.end(),
                      [](const HandlerDef& h) {
                          return std::string_view(h.name) == "jcc";
                      }) != 1)
        throw std::runtime_error(
            "regvm runtime: exactly one handler must be named \"jcc\" "
            "(cond-table two-pass contract, MIT-494s)");
    // MIT-494s (T42)：jcc 带 handler 私有 cond 跳表，表偏移依赖 table_off →
    // dispatch 同款两遍法：先以哑偏移占位装配定尺寸（SIB disp32 定宽 → 与
    // 真偏移逐字节同宽），表偏移已知后重汇编覆写（循环后）。
    u64 jcc_off = 0, jcc_size = 0;
    for (const auto& h : handlers) {
        std::string text;
        if (std::string_view(h.name) == "jcc") {
            text = (arch == AsmGen::HostArch::X86)
                       ? g.build_x86_jcc_at(dispatch_addr, cursor, kDummyTableOff)
                       : g.build_jcc_at(dispatch_addr, cursor, kDummyTableOff);
            const std::vector<u8> code = ks.assemble(text, cursor, h.name);
            handler_off[h.opcode] = cursor;
            jcc_off = cursor;
            jcc_size = code.size();
            handler_text[h.opcode] = std::move(text);   // pass1 占位（pass2 覆写）
            handler_code.insert(handler_code.end(), code.begin(), code.end());
            cursor += code.size();
            continue;
        }
        text = (g.*h.build)(dispatch_addr);
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

    // —— MIT-494s：jcc 第 2 遍（真实 cond 表偏移 = dispatch 表紧随区）+
    //    覆写占位码。尺寸必须与第 1 遍恒等（SIB disp32 定宽不变量）。——
    const u64 condtable_off = table_off + kTableEntries * 8;
    {
        const std::string jcc_text2 =
            (arch == AsmGen::HostArch::X86)
                ? g.build_x86_jcc_at(dispatch_addr, jcc_off, condtable_off)
                : g.build_jcc_at(dispatch_addr, jcc_off, condtable_off);
        const std::vector<u8> jcc_code2 = ks.assemble(jcc_text2, jcc_off, "jcc pass2");
        if (jcc_code2.size() != jcc_size)
            throw std::runtime_error("regvm runtime: jcc pass2 size drifted (two-pass broken)");
        const u64 jcc_pos = jcc_off - (dispatch_addr + dispatch_size);
        std::copy(jcc_code2.begin(), jcc_code2.end(),
                  handler_code.begin() + static_cast<std::ptrdiff_t>(jcc_pos));
        // dump 覆写为 pass2 文本 + cond 表注记（透明度对齐 dispatch 表节）。
        std::string dt = jcc_text2;
        dt += "; ---- cond table @ +" + hex(condtable_off) +
              " (16 x u64 LE, 项 = cc 块相对码基址偏移；x86 读低 dword；MIT-494s) ----\n";
        for (int c = 0; c < 16; ++c)
            dt += ";   [" + std::to_string(c) + "] = " + hex(g.last_cond_table()[c]) + "\n";
        handler_text.at(int(VmOp::Jcc)) = std::move(dt);
    }

    // —— 装配：[entry][dispatch][handlers][pad][table][cond table] ——
    vm::RuntimeImage image;
    image.vm_entry_offset = 0;
    image.code.reserve(size_t(table_off) + size_t(kTableEntries * 8) + 16 * 8);
    image.code.insert(image.code.end(), entry_code.begin(), entry_code.end());
    image.code.insert(image.code.end(), dispatch2.begin(), dispatch2.end());
    image.code.insert(image.code.end(), handler_code.begin(), handler_code.end());
    const u64 halt_off = handler_off.at(int(VmOp::Halt));
    auto push_u64 = [&image](u64 v) {
        for (int b = 0; b < 8; ++b) image.code.push_back(u8((v >> (8 * b)) & 0xFF));
    };
    for (u64 op = 0; op < kTableEntries; ++op)
        push_u64(handler_off.count(int(op)) ? handler_off.at(int(op)) : halt_off);
    // MIT-494s：jcc 私有 cond 表（16×8B，紧跟 dispatch 表之后；表项 = cc 块
    // 相对码基址偏移，x86 消费低 dword）。
    for (int c = 0; c < 16; ++c)
        push_u64(g.last_cond_table()[static_cast<size_t>(c)]);

    // —— asm_dump（带布局注释的最终汇编文本）——
    std::string dump;
    dump += "; regvm runtime image: entry=+0x0, dispatch=+" + hex(dispatch_addr) +
            ", table=+" + hex(table_off) + ", total=" + hex(image.code.size()) + "\n";
    if (arch == AsmGen::HostArch::X86)
        dump += "; arch: x86 (KS_MODE_32, MIT-443 X3a 电池集 handler 面)\n";
    dump += "; codec: none (v1 直通；M3 织入点 = dispatch fetch 之后、跳表之前，对 T8 解密)\n";
    dump += entry_text + "\n";
    dump += "dispatch:\n" + dispatch_text + "\n";
    for (const auto& h : handlers)
        dump += "; ---- handler " + std::string(h.name) + " @ +" + hex(handler_off.at(h.opcode)) +
                " ----\n" + handler_text.at(h.opcode) + "\n";
    dump += "; ---- jump table @ +" + hex(table_off) +
            " (" + std::to_string(kTableEntries) +
            " x u64 LE, 项 = handler 相对码基址偏移；0/未实现 → halt) ----\n";
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

// x64 入口（runtime.hpp 契约，冻结签名）：默认位宽路径，行为与本单合入前
// 逐字节一致（D6 —— 同 seed asm_dump 对账）。
RuntimeGenResult generate_runtime(wvmp::Rng& rng) {
    return generate_runtime_arch(rng, AsmGen::HostArch::X64);
}

// MIT-473: 取指级加密变体（fetch_decrypt = dispatch 织入 xor_chain 原位解
// 密；缺省重载保持锚点恒等）。运行时契约头随本单同步（append-only 重载）。
RuntimeGenResult generate_runtime(wvmp::Rng& rng, bool fetch_decrypt) {
    return generate_runtime_arch(rng, AsmGen::HostArch::X64, fetch_decrypt);
}

// x86 入口（runtime_x86.hpp，MIT-443 (X3a)）：KS_MODE_32 码体 + 电池集 handler。
RuntimeGenResult generate_runtime_x86(wvmp::Rng& rng) {
    return generate_runtime_arch(rng, AsmGen::HostArch::X86);
}

// MIT-473: x86 取指级加密变体（weave 见 build_dispatch_x86）。
RuntimeGenResult generate_runtime_x86(wvmp::Rng& rng, bool fetch_decrypt) {
    return generate_runtime_arch(rng, AsmGen::HostArch::X86, fetch_decrypt);
}

// MIT-446 (X4)：x86 已登记 opcode 清单（runtime_x86.hpp 契约）。单一来源 =
// x86_handler_table()；函数级 static 保证只构建一次。stub_link 的 x86 白名
// 单 gate 据此在覆写 .text 前拦截"字节码含跳表缺项 VmOp"的函数（整函数保
// 持原生），把跳表折叠 Halt 的 C2 类静默错变成 C1 类显式 gate。
std::span<const int> x86_handler_opcodes() {
    static const std::vector<int> ops = [] {
        std::vector<int> v;
        v.reserve(x86_handler_table().size());
        for (const HandlerDef& h : x86_handler_table()) v.push_back(h.opcode);
        return v;
    }();
    return ops;
}

} // namespace wvmp::regvm::runtime
