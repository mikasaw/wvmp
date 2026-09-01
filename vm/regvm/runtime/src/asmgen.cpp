// P6：regvm 运行时生成器。
//
// 保护期用 Keystone（KS_ARCH_X86 + KS_MODE_64，Intel 语法）汇编出一段
// **位置无关**的 x64 解释器机器码，可在 RWX 内存中执行 regvm 字节码。
//
// ============================== 机器码布局 ==============================
//
//   [entry][dispatch][handler..（码序随机）][0x90 垫片至 8 对齐][跳转表 128xu64]
//    ^入口    ^取指/跳表   ^各自独立 ks_asm          ^表项=handler 相对码基址偏移
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
//   dump 逐字节恒等，48 单史 sha 纪律）。x86 面设计（电池 19 handler）：
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
    explicit AsmGen(Rng& rng, HostArch arch = HostArch::X64) : rng_(rng), arch_(arch) {}

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
        // 码，见文件头 kX86 池注）。
        const u64 a0 = rng_.uniform(0u, 2u);
        u64 a1 = rng_.uniform(0u, 1u);
        if (a1 >= a0) ++a1;
        t_[0] = kX86ByteCapable[a0];
        t_[1] = kX86ByteCapable[a1];
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
        // pc_/flags_ x86 内存常驻（[ctx+0x8] / [ctx+0x98] 既有槽），不占寄
        // 存器 —— 置负值防误用（x86 emit 面禁触 r64()/r64(pc_)/r64(flags_)）。
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
        std::string o;
        o += std::string("    and ") + r64(flags_) + ", " + imm(0x19) + "\n";
        o += std::string("    shl ") + r64(t_[3]) + ", 1\n";
        o += std::string("    or ") + r64(flags_) + ", " + r64(t_[3]) + "\n";
        o += std::string("    shl ") + r64(t_[4]) + ", 2\n";
        o += std::string("    or ") + r64(flags_) + ", " + r64(t_[4]) + "\n";
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
        // 9) 从 VmContext 恢复 pc/flags/base
        o += std::string("    mov ") + r64(pc_) + ", qword ptr [" + r64(ctx_) + " + 0x8]\n";
        o += std::string("    mov ") + r64(flags_) + ", qword ptr [" + r64(ctx_) + " + 0x98]\n";
        o += std::string("    mov ") + r64(base_) + ", qword ptr [" + r64(ctx_) + " + 0x130]\n";
        // 10) RAX (callee 返回值) 写回 regs[v0]
        o += std::string("    mov qword ptr [") + r64(ctx_) + " + 0x10], rax\n";
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
    // MIT-443 (X3a)：x86 (KS_MODE_32) 码体生成面 —— 电池集 19 handler。
    //
    // 与 x64 面的关系：x64 emit 代码一概不经此处（arch 分叉收敛在 KsSession
    // 模式 / roll / build_entry / build_dispatch / handler 表选择五处），x64
    // 输出逐字节不变（D6）。x86 寄存器/栈/flags 模型见文件头 kX86 池注：
    //   - 寄存器：ctx_/base_（callee-saved）+ 临时 t_[0..3]（t_[0]/t_[1] =
    //     数据临时，字节可编码约束；t_[2]/t_[3] = 寻址临时）；pc_/flags_ 内存
    //     常驻 [ctx+0x8] / [ctx+0x98]（既有持久槽，零新字段，D4）。
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
        // host_rsp 记账（callgate X3c 预留；槽高半字依赖零初始化不变量）。
        o += std::string("    mov dword ptr [") + r32x(ctx_) + " + 0x128], esp\n";
        // pc_/flags_ 内存常驻（[ctx+0x8]/[ctx+0x98]），无需寄存器装载；跌入 dispatch。
        return o;
    }

    // ---- x86 dispatch 块（table_off 两遍法同 x64；哑值强制 disp32）--------
    // D3（项目主拍板）：跳表保 8B 表项 —— x86 读表项低 dword（handler 偏移
    // <4GB），表字节格式与 x64 逐位一致，掩码/两遍法逻辑零改动。
    std::string build_dispatch_x86(u64 table_off) const {
        std::string o;
        o += std::string("    mov ") + r32x(t_[0]) + ", dword ptr [" + r32x(ctx_) + "]\n";
        o += std::string("    mov ") + r32x(t_[1]) + ", dword ptr [" + r32x(ctx_) +
             " + 0x8]\n";
        // 指令字 64 位双字取指落帧（lo=域 0..31 → kX86FInsnLo；hi=aux → kX86FAux）。
        o += std::string("    mov ") + r32x(t_[2]) + ", dword ptr [" + r32x(t_[0]) +
             " + " + r32x(t_[1]) + "*8]\n";
        o += std::string("    mov ") + r32x(t_[3]) + ", dword ptr [" + r32x(t_[0]) +
             " + " + r32x(t_[1]) + "*8 + " + imm(4) + "]\n";
        o += std::string("    mov dword ptr ") + xf(kX86FInsnLo) + ", " + r32x(t_[2]) + "\n";
        o += std::string("    mov dword ptr ") + xf(kX86FAux) + ", " + r32x(t_[3]) + "\n";
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
            o += std::string("    mov ") + r32x(t_[0]) + ", " + xf(kX86FInsnLo) + "\n";
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
        const std::string A = r32x(t_[0]);
        const std::string B = r32x(t_[1]);
        std::string o;
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
        const std::string A = r32x(t_[0]);
        const std::string B = r32x(t_[1]);
        std::string o;
        o += std::string("    mov ") + A + ", dword ptr [" + r32x(ctx_) + " + 0x98]\n";
        o += std::string("    and ") + A + ", " + imm(0x19) + "\n";
        o += std::string("    movzx ") + B + ", byte ptr " + xf(kX86FCC + 1) + "\n";
        o += std::string("    shl ") + B + ", " + imm(1) + "\n";
        o += std::string("    or ") + A + ", " + B + "\n";
        o += std::string("    movzx ") + B + ", byte ptr " + xf(kX86FCC + 2) + "\n";
        o += std::string("    shl ") + B + ", " + imm(2) + "\n";
        o += std::string("    or ") + A + ", " + B + "\n";
        o += std::string("    mov dword ptr [") + r32x(ctx_) + " + 0x98], " + A + "\n";
        o += advance_x86(dispatch);
        return o;
    }

    // x86 advance：pc 内存常驻（[ctx+0x8] dword），+1 后回 dispatch。
    std::string advance_x86(u64 dispatch) const {
        return std::string("    add dword ptr [") + r32x(ctx_) + " + 0x8], " + imm(1) +
               "\n    jmp " + hex(dispatch) + "\n";
    }

    // x86 尺寸链：3 路各带显式 cmp/je（S8/S16/S32，perm 随机）+ 链尾顺延 =
    // S64 防御 no-op（直接前进 —— x86 翻译器不产 S64 VmOp；命中即整条
    // no-op；X0 "断言 qword/REX 形不可达" 的落地形态）。首版只放 2 个 cmp
    // 让 perm[2] 块顺延跌入是错误结构 —— S16 曾因此整路空转（电池当场
    // 炸出）；三路必须全部显式分派，链尾只属于防御出口。
    std::string size_chain_x86(const std::string blocks[3], const std::string& tag,
                               u64 dispatch) const {
        std::string o;
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
    std::string build_jcc_x86(u64 dispatch) const {
        const std::string tag = "xjcc" + std::to_string(seq());
        const std::string test_lbl = "xjt_" + tag;
        const std::string fall_lbl = "xjf_" + tag;
        std::string out = decode_prelude_x86();
        // 链式分派（顺序随机；末条件 perm[15] 为链尾顺延跌入，其块最先排放）。
        for (int i = 0; i < 15; ++i) {
            const int c = cond_perm_[i];
            out += std::string("    cmp dword ptr ") + xf(kX86FSize) + ", " + imm(c) + "\n";
            out += "    je xcc" + std::to_string(c) + "_" + tag + "\n";
        }
        out += "xcc" + std::to_string(cond_perm_[15]) + "_" + tag + ":\n" +
               cond_eval_x86(cond_perm_[15]) + "    jmp " + test_lbl + "\n";
        for (int i = 0; i < 15; ++i) {
            const int c = cond_perm_[i];
            out += "xcc" + std::to_string(c) + "_" + tag + ":\n";
            out += cond_eval_x86(c);
            out += "    jmp " + test_lbl + "\n";
        }
        out += test_lbl + ":\n";
        out += std::string("    test ") + r32x(t_[0]) + ", " + r32x(t_[0]) + "\n";
        out += "    jz " + fall_lbl + "\n";
        out += std::string("    mov ") + r32x(t_[0]) + ", " + xf(kX86FAux) + "\n";
        out += std::string("    add dword ptr [") + r32x(ctx_) + " + 0x8], " +
               r32x(t_[0]) + "\n";
        out += "    jmp " + hex(dispatch) + "\n";
        out += fall_lbl + ":\n";
        out += advance_x86(dispatch);
        return out;
    }

    // x86 Jmp：pc dword += aux 原始双字（同 Jcc taken 路径，无条件）。
    std::string build_jmp_x86(u64 dispatch) const {
        std::string o;
        o += std::string("    mov ") + r32x(t_[0]) + ", " + xf(kX86FAux) + "\n";
        o += std::string("    add dword ptr [") + r32x(ctx_) + " + 0x8], " +
             r32x(t_[0]) + "\n";
        o += "    jmp " + hex(dispatch) + "\n";
        return o;
    }

    // x86 Halt：写回 pc+1（恢复友好）与 ret_value（=regs[0] 低 dword；槽高
    // 半字清零维持不变量），弃执行帧，逆序恢复 callee-saved，ret（cdecl：
    // 不清调用方参数）。弹出序 = 入口压栈序的严格镜像：base 最先压、最后弹。
    std::string build_halt_x86(u64 /*dispatch*/) const {
        const auto order = x86_save_order();
        std::string o;
        o += std::string("    add dword ptr [") + r32x(ctx_) + " + 0x8], " + imm(1) + "\n";
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
            o += std::string("    mov cl, ") + rs(t_[1], 0) + "\n";
            o += std::string("    and cl, ") + imm(0x1F) + "\n";
            o += "    jz " + adv_lbl + "\n";   // 计数 0：值与 flags 均不变
            o += std::string("    ") + native + " " + rs(t_[0], s) + ", cl\n";
            o += setcc5_x86();
            o += writeback_x86(s, kX86FRegA, t_[0], t_[1]);
            o += "    jmp " + tail_lbl + "\n";
            blocks[s] = o;
        }
        std::string out = decode_prelude_x86() + size_chain_x86(blocks, tag, dispatch);
        out += adv_lbl + ":\n" + advance_x86(dispatch);   // 计数 0 出口
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
    std::string build_x86_jcc(u64 d) const { return build_jcc_x86(d); }
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

private:
    Rng& rng_;
    HostArch arch_ = HostArch::X64;
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

} // namespace

// MIT-443 (X3a)：双模管线。x64 路径（arch=X64）逐字保留既有序列 —— roll/
// 两遍法/handler 表/dump 输出全部原样，D6 恒等按同 seed dump 逐字节对账。
RuntimeGenResult generate_runtime_arch(wvmp::Rng& rng, AsmGen::HostArch arch) {
    using isa::VmOp;
    AsmGen g(rng, arch);
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
    //    x86 面（MIT-443 (X3a)）：电池集 19 handler；其余 op 沿既有机制折叠
    //    Halt（跳表缺项 → halt，恢复友好）；全 95 op 批迁 = X3b（在此加行）。
    std::vector<HandlerDef> handlers;
    if (arch == AsmGen::HostArch::X86) {
        handlers = {
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
        };
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

// x86 入口（runtime_x86.hpp，MIT-443 (X3a)）：KS_MODE_32 码体 + 电池集 handler。
RuntimeGenResult generate_runtime_x86(wvmp::Rng& rng) {
    return generate_runtime_arch(rng, AsmGen::HostArch::X86);
}

} // namespace wvmp::regvm::runtime
