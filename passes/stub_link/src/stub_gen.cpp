#include "stub_gen.hpp"

#include "wvmp/passes/anti_debug/anti_debug_plan.hpp"
#include "wvmp/regvm/codecs/xor_chain.hpp"
#include "wvmp/regvm/runtime/runtime.hpp"
#include "wvmp/regvm/runtime/runtime_x86.hpp"

#include <keystone/keystone.h>

#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <utility>

namespace wvmp::passes {
namespace {

std::string hex(u64 v) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(v));
    return std::string(buf);
}

// VmContext 常量（见 regvm/runtime/runtime.hpp，布局即 ABI）。
constexpr u64 kCtxRegs = 0x10;      // regs[0]
constexpr u64 kCtxRsp = 0x30;       // regs[4]
constexpr u64 kCtxScratch = 0x110;
constexpr u64 kCtxNativeSp = 0x120; // M2-9 call gate: caller 原始 frame 基址
// MIT-371: XMM VM 槽位。VmContext.xmm[8] @ 0x140（8 槽 16B = 128B）= xmm0..xmm7。
// MIT-B2: kCtxSize/kCtxXmmBase 的单一事实来源移至 runtime.hpp（kCtxSize 由
// sizeof(VmContext) 上取 16 对齐 + 8 派生）——本文件与 asmgen.cpp（callgate
// step 7 栈回退）都是消费方，禁止再各持硬编码副本（MIT-371 漂移根因）。
using wvmp::regvm::runtime::kCtxSize;
using wvmp::regvm::runtime::kCtxXmmBase;
// MIT-407: ExitNative 退出槽深度（距 native_sp 的单一事实来源，runtime.hpp）。
// 槽地址 = native_sp - kExitSlotDepth；本文件两处消费点按各自 rsp 基准换算：
//   入口预写（rsp = ns - kStubPushBytes - kCtxSize）→ [rsp - 0x80]
//   HALT 终态（rsp = ns）                             → [rsp - 0x288]
// v1 曾在本文件/asmgen 各持字面量并写/读错位——segfault 根因，禁止第二份。
using wvmp::regvm::runtime::kExitSlotDepth;
// MIT-446 (X4) B.1：x86 退出槽深度单一来源迁至 runtime_x86.hpp（原 asmgen
// 匿名 namespace 常量上移），x86 stub 两处消费点据此换算。
using wvmp::regvm::runtime::kX86ExitSlotDepth;
// MIT-451 (X5b) B.2：entry guard 垫栈深度（单一来源 runtime_x86.hpp）。
using wvmp::regvm::runtime::kX86GuardBytes;

// 占位 disp32（回填目标 = blob 指令流）：选罕见值便于汇编后定位。
constexpr u32 kBlobDispDummy = 0xDEAD'0001;

// stub 序言 push 的 callee-saved 全量字节数。与 runtime.hpp 的 kCalleeSavedIdx
// 是同一 8 寄存器集合（rbx/rbp/rdi/rsi/r12-r15），由集合大小结构化导出——
// 若 push 行增删，此值自动跟随（MIT-B2: 0x208 = 8*push + kCtxSize 曾整体
// 硬编码，属 kCtxSize 漂移同族缺陷，一并派生）。
constexpr u64 kStubPushBytes = wvmp::regvm::runtime::kCalleeSavedIdx.size() * 8;

// MIT-446 (X4) B.1：x86 callee-saved 面与 mod-16 静态钉（派单 A.2 派生式
// 纪律）。x86 ABI callee-saved = ebx/ebp/esi/edi 4 个（= asmgen kX86CalleeSaved
// 同集合），4×4B = 0x10；kX86ExitSlotDepth 的派生式（runtime_x86.hpp）内含
// 同一 push 面，两处由 static_assert 锁死零漂移。
// MIT-451 (X5b) B.2：entry guard 垫栈（runtime_x86.hpp kX86GuardBytes 单一
// 来源）——序言最前 sub esp,G 使保存区/ctx 下移，guest push（净深 <= G，由
// translator 栈深 walk gate 保证）先吃 guard 区 [ns-G..ns-4]，不再写穿保存
// 区 + ctx 区（X5 mul64hi 缺陷修复，见 runtime_x86.hpp 注）。出口槽换算、
// v4/native_sp 还原、尾声 unwind 三处随 G 联动，全部由派生式表达，禁字面
// 量第二份。
constexpr u64 kStubPushBytesX86 = 4 * 4;  // ebx/ebp/esi/edi
static_assert(kStubPushBytesX86 % 16 == 0, "x86 stub push face must stay 16-aligned");
static_assert(kX86ExitSlotDepth ==
                  kX86GuardBytes + kStubPushBytesX86 + kCtxSize + 0x80,
              "x86 stub push face drifted from kX86ExitSlotDepth derivation");
static_assert(kCtxSize % 4 == 0, "x86 stub ctx zero-fill must be dword-granular");

// 入口预写相对当前 rsp（= ns - kX86GuardBytes - kStubPushBytesX86 - kCtxSize）
// 的槽偏移。guard 下移后 esp 与槽同步位移，差值恒 0x80（disp8 编码边界纪律
// 不变；keystone 大负 disp 截断坑规避）。
constexpr u64 kExitSlotFromStubEntry = kExitSlotDepth - kStubPushBytes - kCtxSize;
// x86 同构换算（kX86ExitSlotDepth - G - 0x10 - kCtxSize = 0x80；MIT-511 起 0x4D8-0x80-0x10-0x3C8）.
constexpr u64 kX86ExitSlotFromStubEntry =
    kX86ExitSlotDepth - kX86GuardBytes - kStubPushBytesX86 - kCtxSize;
static_assert(kX86ExitSlotFromStubEntry == 0x80,
              "x86 exit slot entry prewrite must stay disp8-encodable");

// =============================================================================
// MIT-458 (crypt-v1)：xor_chain one-shot 解密块（stub 序言之前执行）。
//
// 递推（与 vm/regvm/codecs/xor_chain.hpp 加密侧同递推，常数同步纪律见彼处）：
//   k = state; c = [mem]; state = state*G + c; [mem] = c ^ k   （state 吃密文）
// one-shot：尾旗标 [flag]==1 才解密、解完写 0（xor_chain 同段内存重复执行 =
// 再加密）。被蹭 GP 寄存器全部 push/pop 保存恢复——本块在 stub 序言之前
// 运行，x64 预载面 / x86 ctx 预载读的都是"进入时刻"的寄存器值，解密块
// 不得留痕（flags 不保全：序言 sub 既有先例）。esp 平衡（x86 形 6 push/6 pop）。
// =============================================================================
std::string build_crypt_asm_x64(const StubCrypt& c) {
    std::string o;
    o += "push rax\n push rcx\n push rdx\n push r8\n push r10\n push r11\n";
    o += "mov r10, " + hex(c.flag_va) + "\n";
    o += "cmp dword ptr [r10], 0\n";
    o += "je wvcrypt_done\n";
    // MIT-464: 密文 CRC32 校验（解密之前；bitwise 无表，poly 0xEDB88320，
    // 常数单一来源 = common/crc32.hpp）。mismatch = 密文被篡改 → FailFast。
    if (c.verify_crc) {
        o += "mov r11, " + hex(c.stream_va) + "\n";
        o += "mov r8d, " + hex(c.byte_count) + "\n";
        o += "mov eax, 0xFFFFFFFF\n";
        o += "wvcrc_byte:\n";
        o += "movzx edx, byte ptr [r11]\n";
        o += "xor eax, edx\n";
        o += "mov edx, eax\n and edx, 1\n neg edx\n and edx, " + hex(0xEDB88320u) + "\n";
        o += "shr eax, 1\n xor eax, edx\n";
        o += "mov edx, eax\n and edx, 1\n neg edx\n and edx, " + hex(0xEDB88320u) + "\n";
        o += "shr eax, 1\n xor eax, edx\n";
        o += "mov edx, eax\n and edx, 1\n neg edx\n and edx, " + hex(0xEDB88320u) + "\n";
        o += "shr eax, 1\n xor eax, edx\n";
        o += "mov edx, eax\n and edx, 1\n neg edx\n and edx, " + hex(0xEDB88320u) + "\n";
        o += "shr eax, 1\n xor eax, edx\n";
        o += "mov edx, eax\n and edx, 1\n neg edx\n and edx, " + hex(0xEDB88320u) + "\n";
        o += "shr eax, 1\n xor eax, edx\n";
        o += "mov edx, eax\n and edx, 1\n neg edx\n and edx, " + hex(0xEDB88320u) + "\n";
        o += "shr eax, 1\n xor eax, edx\n";
        o += "mov edx, eax\n and edx, 1\n neg edx\n and edx, " + hex(0xEDB88320u) + "\n";
        o += "shr eax, 1\n xor eax, edx\n";
        o += "mov edx, eax\n and edx, 1\n neg edx\n and edx, " + hex(0xEDB88320u) + "\n";
        o += "shr eax, 1\n xor eax, edx\n";
        o += "inc r11\n dec r8d\n jnz wvcrc_byte\n";
        o += "xor eax, 0xFFFFFFFF\n";
        o += "cmp eax, dword ptr [r10+4]\n";
        o += "jne wvcrc_bad\n";
    }
    o += "mov r11, " + hex(c.stream_va) + "\n";
    o += "mov eax, " + hex(c.key0) + "\n";
    o += "mov ecx, " + hex(c.dword_count) + "\n";
    o += "wvcrypt_loop:\n";
    o += "mov edx, dword ptr [r11]\n";
    o += "mov r8d, eax\n";
    o += "imul eax, eax, " + hex(wvmp::regvm::codecs::kXorChainMult) + "\n";
    o += "add eax, edx\n";
    o += "xor edx, r8d\n";
    o += "mov dword ptr [r11], edx\n";
    o += "add r11, 4\n";
    o += "dec ecx\n";
    o += "jnz wvcrypt_loop\n";
    o += "mov dword ptr [r10], 0\n";
    if (c.verify_crc) {  // MIT-464 验收披露②修正：无 CRC 时不发空转 jmp（2B 差异）
        o += "jmp wvcrypt_done\n";
        o += "wvcrc_bad:\n";
        o += "xor eax, eax\n";
        o += "mov qword ptr [rax], 0\n";
    }
    o += "wvcrypt_done:\n";
    o += "pop r11\n pop r10\n pop r8\n pop rdx\n pop rcx\n pop rax\n";
    return o;
}

std::string build_crypt_asm_x86(const StubCrypt& c) {
    std::string o;
    // esp 平衡 6 push/6 pop（ebx/esi/edi 为 callee-saved 必还；eax/ecx/edx
    // 为预载面必还原原值）。PE32 VA 恒 imm32 可编码（407 v2 铁律同源）。
    o += "push eax\n push ecx\n push edx\n push ebx\n push esi\n push edi\n";
    o += "mov esi, " + hex(c.flag_va) + "\n";
    o += "cmp dword ptr [esi], 0\n";
    o += "je wvcrypt_done\n";
    // MIT-464: 密文 CRC32 校验（同 x64 形；acc=eax, cursor=edi, count=ebx,
    // tmp=edx——均在本块 push 集内，解密段自行重置）。
    if (c.verify_crc) {
        o += "mov edi, " + hex(c.stream_va) + "\n";
        o += "mov ebx, " + hex(c.byte_count) + "\n";
        o += "mov eax, 0xFFFFFFFF\n";
        o += "wvcrc_byte:\n";
        o += "movzx edx, byte ptr [edi]\n";
        o += "xor eax, edx\n";
        o += "mov edx, eax\n and edx, 1\n neg edx\n and edx, " + hex(0xEDB88320u) + "\n";
        o += "shr eax, 1\n xor eax, edx\n";
        o += "mov edx, eax\n and edx, 1\n neg edx\n and edx, " + hex(0xEDB88320u) + "\n";
        o += "shr eax, 1\n xor eax, edx\n";
        o += "mov edx, eax\n and edx, 1\n neg edx\n and edx, " + hex(0xEDB88320u) + "\n";
        o += "shr eax, 1\n xor eax, edx\n";
        o += "mov edx, eax\n and edx, 1\n neg edx\n and edx, " + hex(0xEDB88320u) + "\n";
        o += "shr eax, 1\n xor eax, edx\n";
        o += "mov edx, eax\n and edx, 1\n neg edx\n and edx, " + hex(0xEDB88320u) + "\n";
        o += "shr eax, 1\n xor eax, edx\n";
        o += "mov edx, eax\n and edx, 1\n neg edx\n and edx, " + hex(0xEDB88320u) + "\n";
        o += "shr eax, 1\n xor eax, edx\n";
        o += "mov edx, eax\n and edx, 1\n neg edx\n and edx, " + hex(0xEDB88320u) + "\n";
        o += "shr eax, 1\n xor eax, edx\n";
        o += "mov edx, eax\n and edx, 1\n neg edx\n and edx, " + hex(0xEDB88320u) + "\n";
        o += "shr eax, 1\n xor eax, edx\n";
        o += "inc edi\n dec ebx\n jnz wvcrc_byte\n";
        o += "xor eax, 0xFFFFFFFF\n";
        o += "cmp eax, dword ptr [esi+4]\n";
        o += "jne wvcrc_bad\n";
    }
    o += "mov edi, " + hex(c.stream_va) + "\n";
    o += "mov eax, " + hex(c.key0) + "\n";
    o += "mov ecx, " + hex(c.dword_count) + "\n";
    o += "wvcrypt_loop:\n";
    o += "mov edx, dword ptr [edi]\n";
    o += "mov ebx, eax\n";
    o += "imul eax, eax, " + hex(wvmp::regvm::codecs::kXorChainMult) + "\n";
    o += "add eax, edx\n";
    o += "xor edx, ebx\n";
    o += "mov dword ptr [edi], edx\n";
    o += "add edi, 4\n";
    o += "dec ecx\n";
    o += "jnz wvcrypt_loop\n";
    o += "mov dword ptr [esi], 0\n";
    if (c.verify_crc) {  // MIT-464 验收披露②修正：同 x64 形
        o += "jmp wvcrypt_done\n";
        o += "wvcrc_bad:\n";
        o += "xor eax, eax\n";
        o += "mov dword ptr [eax], 0\n";
    }
    o += "wvcrypt_done:\n";
    o += "pop edi\n pop esi\n pop ebx\n pop edx\n pop ecx\n pop eax\n";
    return o;
}

// =============================================================================
// MIT-463 (anti_debug-v1)：PEB 反调试检查块（stub 序言之前，解密块之前）。
//
// 双检查（零误报用户态面）：
//   BeingDebugged: x64 PEB=[gs:0x30]+0x60 / x86 PEB=[fs:0x18]+0x30；byte [PEB+2]
//   NtGlobalFlag:  & 0x70 != 0；x64 [PEB+0xBC] / x86 [PEB+0x68]
// 命中响应 = FailFast（清零 acc 后写 [0] → 确定性 AV 终止；与天然空指针
// 崩溃不可区分 = 无反调试行为泄露，D1 披露）。被蹭 acc 寄存器 push/pop
// 保存恢复（预载面纪律同解密块）；flags 不保全（序言先例）。检查每次
// stub 进入都执行（十余条指令/调用，v1 接受）。
// =============================================================================
std::string build_adb_asm_x64(u32 techniques) {
    std::string o;
    o += "push rax\n";
    o += "mov rax, qword ptr gs:[0x30]\n";   // TEB
    o += "mov rax, qword ptr [rax+0x60]\n";  // PEB
    if (techniques & wvmp::passes::anti_debug::tech::kBeingDebugged) {
        o += "cmp byte ptr [rax+2], 0\n";
        o += "jne wvadb_fail\n";
    }
    if (techniques & wvmp::passes::anti_debug::tech::kNtGlobalFlag) {
        o += "mov eax, dword ptr [rax+0xBC]\n";
        o += "test eax, " + hex(0x70) + "\n";
        o += "jne wvadb_fail\n";
    }
    o += "pop rax\n";
    o += "jmp wvadb_done\n";
    o += "wvadb_fail:\n";
    o += "xor eax, eax\n";
    o += "mov qword ptr [rax], 0\n";
    o += "wvadb_done:\n";
    return o;
}

std::string build_adb_asm_x86(u32 techniques) {
    std::string o;
    o += "push eax\n";
    o += "mov eax, dword ptr fs:[0x18]\n";   // TEB
    o += "mov eax, dword ptr [eax+0x30]\n";  // PEB
    if (techniques & wvmp::passes::anti_debug::tech::kBeingDebugged) {
        o += "cmp byte ptr [eax+2], 0\n";
        o += "jne wvadb_fail\n";
    }
    if (techniques & wvmp::passes::anti_debug::tech::kNtGlobalFlag) {
        o += "mov eax, dword ptr [eax+0x68]\n";
        o += "test eax, " + hex(0x70) + "\n";
        o += "jne wvadb_fail\n";
    }
    o += "pop eax\n";
    o += "jmp wvadb_done\n";
    o += "wvadb_fail:\n";
    o += "xor eax, eax\n";
    o += "mov dword ptr [eax], 0\n";
    o += "wvadb_done:\n";
    return o;
}

// x64 stub 汇编（MIT-446 (X4) B.1 起更名 x64 专形；D2 恒等铁约束：函数体
// 逐字保留，x64 asm_dump sha ffd47289(旧, MIT-474 换代→67cfa727)… 恒等是机器证明项）。
std::string build_stub_asm_x64(u64 rt_entry_rva, u64 resume_rva, u64 image_base,
                               const StubCrypt* crypt, const StubAntiDebug* adb) {
    std::string o;
    // MIT-458: 加密函数在序言之前织入 one-shot 解密块（nullptr = 无加密，
    // 本函数体其余部分逐字节不变）。
    if (crypt) o += build_crypt_asm_x64(*crypt);
    // MIT-463: 反调试检查块（解密块之后、序言之前；nullptr = 无检查）。
    if (adb) o += build_adb_asm_x64(adb->techniques);
    o += "push rbx\n push rbp\n push rdi\n push rsi\n";
    o += "push r12\n push r13\n push r14\n push r15\n";
    o += "sub rsp, " + hex(kCtxSize) + "\n";
    // 预载宿主 GP 寄存器 → 虚拟寄存器堆（r12-r15/rbx 等仍在压栈前的值可读）。
    for (int i = 0; i < 16; ++i) {
        const char* src = nullptr;
        switch (i) {  // ir::Reg 序：rax rcx rdx rbx rsp rbp rsi rdi r8..r15
            case 0: src = "rax"; break;
            case 1: src = "rcx"; break;
            case 2: src = "rdx"; break;
            case 3: src = "rbx"; break;
            case 4: continue;  // rsp 单独处理
            case 5: src = "rbp"; break;
            case 6: src = "rsi"; break;
            case 7: src = "rdi"; break;
            default: src = nullptr; break;
        }
        if (i >= 8) {
            o += std::string("mov [rsp + ") + hex(kCtxRegs + u64(i) * 8) + "], r" +
                 std::to_string(i) + "\n";
        } else {
            o += std::string("mov [rsp + ") + hex(kCtxRegs + u64(i) * 8) + "], " + src + "\n";
        }
    }
    // v4 = 原始 rsp（区域代码按原函数帧的 rsp 相对寻址）：当前 rsp 比原始值
    // 低 kStubPushBytes(0x40) + kCtxSize(MIT-511 起 0x3C8) = 0x408，用 lea 还原。rax 的原值已在
    // slot0 保存，可复用。同一份原始 rsp 同时写到 native_sp（M2-9 call gate
    // 需要稳定的 caller frame 基址——v4 会被 VM 自身 push/pop 改写，native_sp
    // 跨指令不变，供 callgate handler 把 rsp 切回 caller frame 跑 native）。
    o += "lea rax, [rsp + " + hex(kStubPushBytes + kCtxSize) + "]\n";
    o += "mov [rsp + " + hex(kCtxRsp) + "], rax\n";
    o += "mov [rsp + " + hex(kCtxNativeSp) + "], rax\n";
    // image_base（PE optional header 的 ImageBase 字段）→ scratch_mem 槽：
    // Load/Store/Push/Pop 的访存汇编 `[addr + ctx+0x110]` 即 + image_base。
    // rip-relative 翻译期把 [rip+disp] 转 RVA 写进字节码；运行时按此槽加基址
    // 还原 VA。ASLR 下 Windows 加载器把整 image 重定位, RVA 不变, 槽值不变.
    // PE32+ ImageBase 8B 可 >0x7FFFFFFF（典型 0x140000000）, 不能直接走
    // `mov [mem], imm32` (符号扩展至 64 位) 编码——必须经 rax 中转。
    o += "mov rax, " + hex(image_base) + "\n";
    o += "mov qword ptr [rsp + " + hex(kCtxScratch) + "], rax\n";
    // MIT-407: ExitNative 退出槽入口预写。Halt 路径的终态 jmp 经此槽间接
    // 跳回 resume 点，故预写值必须是**生成期常量 VA = image_base + resume_rva**
    // （不是裸 resume_rva——v1 崩溃根因，cdb 实证 rip=裸 RVA；直跳
    // `jmp <resume_rva>` 能工作是 keystone 以链接期为装配基址算 rel32 的
    // RVA 差自洽，间接跳的槽值是绝对 VA，两套地址体系不可混用）。
    // 槽地址 = [rsp - 0x80]（rsp = ns - 0x408 → ns - kExitSlotDepth）。
    // imm64 同样必须经 rax 中转（>0x7FFFFFFF 不可走 imm32）。
    o += "mov rax, " + hex(image_base + resume_rva) + "\n";
    o += "mov qword ptr [rsp - " + hex(kExitSlotFromStubEntry) + "], rax\n";
    o += "mov qword ptr [rsp + 0x8], 0\n";                   // pc = 0
    o += "lea rax, [rip + " + hex(kBlobDispDummy) + "]\n";   // blob 指令流（回填）
    o += "mov [rsp], rax\n";                                 // ctx.bytecode
    // MIT-371: 把宿主 xmm0..xmm7 同步到 VmContext.xmm[0..7]（VM 槽）。
    // 区域代码如 addss/addps/addpd 需要读取当前 xmm 值（Win64 ABI 调用约定把
    // 浮点参数 / 返回值放在 xmm0..xmm7），若不同步则 VM 读到的是 VmContext
    // 槽位的未初始化值（栈内存）。movups 每次 16 字节；xmm0..xmm7 8 个
    // 寄存器 = 128 字节写入。xmm 槽位位于 VmContext.xmm[8] @ 0x148。
    for (int i = 0; i < 8; ++i) {
        o += std::string("movups [rsp + ") + hex(kCtxXmmBase + u64(i) * 16) +
             "], xmm" + std::to_string(i) + "\n";
    }
    o += "mov rcx, rsp\n";                                   // Win64 第一参数 = ctx
    o += "call " + hex(rt_entry_rva) + "\n";
    // HALT 返回：回写易失寄存器（callee-saved 由 pop 恢复）。
    for (const auto& [slot, reg] : {
             std::pair<u64, const char*>{kCtxRegs + 0 * 8, "rax"},
             {kCtxRegs + 1 * 8, "rcx"},
             {kCtxRegs + 2 * 8, "rdx"},
             {kCtxRegs + 8 * 8, "r8"},
             {kCtxRegs + 9 * 8, "r9"},
             {kCtxRegs + 10 * 8, "r10"},
             {kCtxRegs + 11 * 8, "r11"},
         }) {
        o += std::string("mov ") + reg + ", [rsp + " + hex(slot) + "]\n";
    }
    // MIT-371: 把 VmContext.xmm[0..7] 同步回宿主 xmm0..xmm7。SSE 加 handler
    // 写回的 xmm 值（addss/addps/addpd 的 dst 通常是 xmm0）通过此步骤回到
    // 原 caller 可见的物理寄存器 — 与 Win64 ABI xmm caller-saved 语义一致。
    for (int i = 0; i < 8; ++i) {
        o += std::string("movups xmm") + std::to_string(i) + ", [rsp + " +
             hex(kCtxXmmBase + u64(i) * 16) + "]\n";
    }
    o += "add rsp, " + hex(kCtxSize) + "\n";
    o += "pop r15\n pop r14\n pop r13\n pop r12\n";
    o += "pop rsi\n pop rdi\n pop rbp\n pop rbx\n";
    // MIT-407: 终态改经 EXIT_SLOT 间接跳（rsp 此时 = entry rsp = native_sp；
    // 槽 = [rsp - kExitSlotDepth]，入口已预写 VA(resume_rva)；ExitNative
    // handler 命中时覆写为目标 VA）。Halt 与 ExitNative 两条出口共用此通道，
    // 单一路径便于验证。disp32（-0x288）编码实测正常（v1 验证 `ff a4 24
    // 78 fd ff ff`）；若未来调整槽位超出 disp8/disp32 边界须先验证编码。
    o += "jmp qword ptr [rsp - " + hex(kExitSlotDepth) + "]\n";
    return o;
}

// =============================================================================
// MIT-446 (X4) B.1：x86 (Win32 cdecl) stub 汇编 —— x64 形的 32 位镜像重写。
//
// 与 x64 形的逐项差异（交接锚①-④对账）：
//   1. callee-saved push 面 = 4（ebx/ebp/esi/edi，kStubPushBytesX86=0x10，
//      与 runtime_x86.hpp kX86ExitSlotDepth 派生式 static_assert 锁死）；
//   2. ctx 传递 = cdecl 栈参：`push esp; call rt_entry`，runtime_x86 entry
//      在自身 4 push 后经 [esp+0x14] 读 ctx 指针（443 电池 entry 亲验形）；
//   3. ctx 区必须先清零（rep stosd）：x86 handler 写回仅触槽低 dword，
//      "槽高半字恒 0" 不变量依赖 ctx 零初始化（电池 = C++ 零初始化 struct
//      同款）；eax/ecx/edx 原值先经 3 个临时 push 捕获再恢复后预载；
//   4. 预载面 = 8 GP 槽（eax..edi，无 r8+）；esp 槽单独经 v4/native_sp；
//   5. 易失回写表 = eax/ecx/edx 三槽（cdecl 易失面；callee-saved 由出口
//      pop 恢复原值，绝不从 ctx 回写——区域未含函数 epilogue 时 guest 槽
//      的 callee-saved 值不可信，回写会破坏原调用方 ABI）；
//   6. ExitNative/HALT 终态 = jmp dword ptr [esp - kX86ExitSlotDepth]
//      （4B 槽，X3c epilogue ret 回 stub 后由 stub 消费；槽值 = imm32 VA，
//      PE32 VA < 4GB——407 v2 RVA/VA 铁律：裸 RVA 进槽 = 野跳）；
//   7. blob 指针 = image_base + blob_stream_rva 立即数（32 位模式无 rip
//      寻址，无需 disp32 回填；generate_entry_stub 的 x64 回填面 x86 跳过）；
//   8. xmm 同步：X6 (MIT-454) A=X3d 起**适用**（x86 运行时 SSE handler 面
//      落地，446 "ctx.xmm 面未消费" 前提翻转）——入口 host xmm0..7 →
//      ctx.xmm（Win32 ABI xmm 全易失，区域读取进入时刻 xmm 值须有源；
//      x64 371 面的 32 位镜像）、出口 ctx.xmm → host xmm0..7（区域结果
//      回到 caller 可见物理寄存器）。callgate callee 副作用不建模不变
//      （Win32 cdecl FP 参数走栈、返回走 ST(0)，无 xmm 协议面）。
//
// MIT-451 (X5b) B.2：帧形更新（guard 垫栈）。序言最前 `sub esp,
// kX86GuardBytes` 垫出保护区 [ns-G..ns-4]，4 callee-saved push 与 ctx 区整体
// 下移 G；guest push（净深 <= G，translator 栈深 walk gate 保证）先吃 guard，
// 不再写穿保存区 + ctx 区。联动点（全部派生式，禁字面量第二份）：
//   - 保存区读回偏移 esp-相对公式不变（esp 与保存区同步下移）；
//   - v4/native_sp 还原 lea 补 G（v4 恒 = ns = 区域进入时刻 esp）；
//   - 出口槽预写 [esp-0x80] 不变（esp 与槽同步位移，kX86ExitSlotFromStubEntry
//     派生式含 G 项）；
//   - 尾声 4 pop 后 `add esp, G` 回到 esp = ns 再终态 jmp（ExitNative 落点
//     esp = ns 语义不变；guard 区此时为纯 scratch，Halt d==0 walk gate 保证
//     guest 未写）。
// guest 栈写语义（X5b 后）: 净深 <= G 的 push/[esp-负位移]/[ebp-X] 落 guard
// 区 = 真实内存真实写，行为保真；净深 > G 的函数由 translator 栈深 walk
// 整函数 C1 gate 保原生（translator.cpp stack-walk）。
// =============================================================================
std::string build_stub_asm_x86(u64 rt_entry_rva, u64 blob_stream_rva,
                               u64 resume_rva, u64 image_base,
                               const StubCrypt* crypt, const StubAntiDebug* adb) {
    std::string o;
    // MIT-458: 同 x64 形——序言前解密块（esp 平衡，见 build_crypt_asm_x86 注）。
    if (crypt) o += build_crypt_asm_x86(*crypt);
    // MIT-463: 反调试检查块（解密块之后、序言之前）。
    if (adb) o += build_adb_asm_x86(adb->techniques);
    // —— 序言：guard 垫栈（X5b）+ 4 callee-saved push + ctx 区（kStubPushBytesX86
    //      + kCtxSize + kX86GuardBytes 参与出口槽换算，禁字面量第二份）。
    //      guard 最前垫（[ns-G..ns-4] 吸收 guest push），push 序固定 ebx→edi
    //      （先 push 在高址）。——
    o += "sub esp, " + hex(kX86GuardBytes) + "\n";
    o += "push ebx\n push ebp\n push esi\n push edi\n";
    o += "sub esp, " + hex(kCtxSize) + "\n";
    // —— ctx 区清零（槽高半字恒 0 不变量的栈帧来源）。eax/ecx/edx/edi 是
    //      待预载的原值，先经 4 个临时 push 捕获再恢复（⚠️ edi 必须恢复：
    //      VmOp::Ret 的直退路径不经 stub 出口 pop，runtime 出口恢复的是
    //      "进入 runtime 时刻"的 callee-saved——若此处留下碎 edi，guest
    //      caller 收到坏 edi（x86 E2E 首通实录：stdout 空 + rc=0））；
    //      rep stosd 以 eax/ecx/edi 为工作寄存器。cld 防御 DF 残留
    //      （Win32 ABI DF=0 惯例，1B 保险）。——
    o += "push eax\n push ecx\n push edx\n push edi\n";
    o += "cld\n";
    o += "lea edi, [esp + " + hex(4 * 4) + "]\n";
    o += "mov ecx, " + hex(kCtxSize / 4) + "\n";
    o += "xor eax, eax\n";
    o += "rep stosd\n";
    o += "pop edi\n pop edx\n pop ecx\n pop eax\n";
    // —— 预载宿主 GP 寄存器 → 虚拟寄存器堆（x86 GP = eax..edi 槽 0..7，
    //      dword 写、高半字由清零保证 0）。ebx/ebp/esi/edi 原值从 stub 自己
    //      的保存区读回：压栈序 ebx→edi（ebx 最高址），从 ctx_base 看第 i 个
    //      push 位于 [esp + kCtxSize + kStubPushBytesX86 - 4*(i+1)]。
    //      ⚠️ X4 首通实录：偏移若顺序写反，slot5(ebp) 装进原 esi 值，leave/
    //      ret 面 [ebp-4] 写飞（cdb 铁证 0x7717667C）——偏移必须按"先 push
    //      在高址"推导，禁拍脑袋顺序。——
    o += "mov [esp + " + hex(kCtxRegs + 0 * 8) + "], eax\n";
    o += "mov [esp + " + hex(kCtxRegs + 1 * 8) + "], ecx\n";
    o += "mov [esp + " + hex(kCtxRegs + 2 * 8) + "], edx\n";
    o += "mov eax, [esp + " +
         hex(kCtxSize + kStubPushBytesX86 - 4 * 1) + "]\n";  // 原 ebx（第 1 push）
    o += "mov [esp + " + hex(kCtxRegs + 3 * 8) + "], eax\n";
    o += "mov eax, [esp + " +
         hex(kCtxSize + kStubPushBytesX86 - 4 * 2) + "]\n";  // 原 ebp（第 2 push）
    o += "mov [esp + " + hex(kCtxRegs + 5 * 8) + "], eax\n";
    o += "mov eax, [esp + " +
         hex(kCtxSize + kStubPushBytesX86 - 4 * 3) + "]\n";  // 原 esi（第 3 push）
    o += "mov [esp + " + hex(kCtxRegs + 6 * 8) + "], eax\n";
    o += "mov eax, [esp + " +
         hex(kCtxSize + kStubPushBytesX86 - 4 * 4) + "]\n";  // 原 edi（第 4 push）
    o += "mov [esp + " + hex(kCtxRegs + 7 * 8) + "], eax\n";
    // v4 = 原始 rsp（区域代码按原函数帧的 rsp 相对寻址）：当前 esp 比原始
    // 值低 kX86GuardBytes + kStubPushBytesX86(0x10) + kCtxSize(MIT-511 起 0x3C8)，用 lea
    // 还原（X5b：lea 补 guard 项——v4 恒 = ns，与 guard 深度无关）。同一
    // 原始 esp 写 native_sp（callgate 窗口锚/ExitNative 槽基准，跨指令
    // 不变）。eax 原值已在 slot0 保存，可复用。
    o += "lea eax, [esp + " + hex(kX86GuardBytes + kStubPushBytesX86 + kCtxSize) + "]\n";
    o += "mov [esp + " + hex(kCtxRsp) + "], eax\n";
    o += "mov [esp + " + hex(kCtxNativeSp) + "], eax\n";
    // image_base → scratch_mem 槽（PE32 ImageBase 恒 imm32 可编码；Load/
    // Store/Push/Pop 访存 = RVA + image_base。ASLR 由 pe_writer 清
    // DYNAMIC_BASE 兜底，槽值不变）。
    o += "mov dword ptr [esp + " + hex(kCtxScratch) + "], " + hex(image_base) + "\n";
    // ExitNative 退出槽入口预写：生成期常量 VA = image_base + resume_rva
    // （407 v2 铁律：裸 RVA 进槽 = 野跳）。槽地址 = [esp - 0x80]
    // （esp = ns - G - 0x1D8 → 槽 = ns - kX86ExitSlotDepth，差值恒 0x80，
    //   G 双侧同消）。
    o += "mov eax, " + hex(image_base + resume_rva) + "\n";
    o += "mov [esp - " + hex(kX86ExitSlotFromStubEntry) + "], eax\n";
    o += "mov dword ptr [esp + 0x8], 0\n";                  // pc = 0（高半字已清零）
    // blob 指令流指针 = image_base + blob_stream_rva（imm32 VA；32 位模式
    // 无 rip 寻址，无需 x64 disp32 回填；pe_writer 清 DYNAMIC_BASE 下与
    // x64 rip-relative 形等价）。
    o += "mov dword ptr [esp], " + hex(image_base + blob_stream_rva) + "\n";
    // —— X6 (MIT-454) A: host xmm0..7 → ctx.xmm 同步（SSE face；x64 371 面
    //      的 32 位镜像。Win32 ABI xmm 全易失，区域若读取进入时刻的 xmm
    //      值（caller 遗留 / 前序计算）必须以 ctx.xmm 为源 —— 零初始化值
    //      与原生语义不符）。esp 此刻 = ctx 基址，disp32 直达 0x140 区。——
    for (int i = 0; i < 8; ++i) {
        o += std::string("movups [esp + ") + hex(kCtxXmmBase + u64(i) * 16) +
             "], xmm" + std::to_string(i) + "\n";
    }
    // —— 调共享解释器（cdecl：ctx 指针经栈参，runtime_x86 entry [esp+0x14] 读）。
    o += "push esp\n";
    o += "call " + hex(rt_entry_rva) + "\n";
    // —— HALT/ExitNative 返回：cdecl 调用方清参 + 回写易失寄存器
    //      （callee-saved 由 pop 恢复原值，见差异 5）。——
    o += "add esp, " + hex(4) + "\n";
    o += "mov eax, [esp + " + hex(kCtxRegs + 0 * 8) + "]\n";
    o += "mov ecx, [esp + " + hex(kCtxRegs + 1 * 8) + "]\n";
    o += "mov edx, [esp + " + hex(kCtxRegs + 2 * 8) + "]\n";
    // —— X6 (MIT-454) A: ctx.xmm → host xmm0..7 同步（SSE handler 写回的
    //      结果经此回到 caller 可见物理寄存器 —— Win32 易失语义下 caller
    //      不依赖跨调用存续，但区域退出时刻的原生可见面须如实还原；与
    //      x64 stub 出口 movups 链同构。esp 此刻 = ctx 基址）。——
    for (int i = 0; i < 8; ++i) {
        o += std::string("movups xmm") + std::to_string(i) + ", [esp + " +
             hex(kCtxXmmBase + u64(i) * 16) + "]\n";
    }
    o += "add esp, " + hex(kCtxSize) + "\n";
    o += "pop edi\n pop esi\n pop ebp\n pop ebx\n";
    // X5b：unwind guard 区回到 esp = ns 再终态跳（ExitNative 落点 esp = ns
    // 语义不变；此时 guard 区为纯 scratch——Halt d==0 由 translator 栈深
    // walk gate 保证 guest 未写）。
    o += "add esp, " + hex(kX86GuardBytes) + "\n";
    // 终态：esp = entry rsp = native_sp；经 4B 退出槽间接跳（入口已预写
    // VA(resume_rva)，ExitNative handler 命中时覆写为目标 VA）。Halt 与
    // ExitNative 两条出口共用此通道（x64 形同构）。
    o += "jmp dword ptr [esp - " + hex(kX86ExitSlotDepth) + "]\n";
    return o;
}

} // namespace

std::vector<u8> generate_entry_stub(u64 stub_rva, u64 blob_stream_rva, u64 rt_entry_rva,
                                    u64 resume_rva, u64 image_base, StubArch arch,
                                    const StubCrypt* crypt, const StubAntiDebug* adb,
                                    std::vector<u64>* abs_vas) {
    ks_engine* ks = nullptr;
    if (ks_open(KS_ARCH_X86, arch == StubArch::X86 ? KS_MODE_32 : KS_MODE_64, &ks) !=
        KS_ERR_OK)
        throw std::runtime_error("stub_link: ks_open failed");
    ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_INTEL);
    // MIT-494：本 stub 内嵌的全部绝对 VA（ASLR reloc 站点登记源）。集合
    // 与 build_stub_asm_* 的发射点一一对应：scratch_mem = image_base、
    // EXIT_SLOT 预写 = image_base + resume_rva、x86 blob 指针 =
    // image_base + blob_stream_rva（x64 走 rip-relative 免登记）、crypt
    // 流/旗标 VA。
    if (abs_vas != nullptr) {
        abs_vas->clear();
        abs_vas->push_back(image_base);
        abs_vas->push_back(image_base + resume_rva);
        if (arch == StubArch::X86)
            abs_vas->push_back(image_base + blob_stream_rva);
        if (crypt != nullptr) {
            abs_vas->push_back(crypt->stream_va);
            abs_vas->push_back(crypt->flag_va);
        }
    }

    const std::string src =
        arch == StubArch::X86
            ? build_stub_asm_x86(rt_entry_rva, blob_stream_rva, resume_rva, image_base, crypt, adb)
            : build_stub_asm_x64(rt_entry_rva, resume_rva, image_base, crypt, adb);
    // 调试钩子（排查用）：WVMP_STUB_DUMP=<win 路径> 时落盘汇编文本。
    {
        char* dp = nullptr;
        size_t dp_len = 0;
        if (_dupenv_s(&dp, &dp_len, "WVMP_STUB_DUMP") == 0 && dp && dp_len > 1) {
            FILE* f = nullptr;
            if (fopen_s(&f, dp, "wb") == 0 && f) {
                std::fwrite(src.data(), 1, src.size(), f);
                std::fclose(f);
            }
        }
        std::free(dp);
    }
    unsigned char* enc = nullptr;
    size_t size = 0, count = 0;
    const int rc = ks_asm(ks, src.c_str(), stub_rva, &enc, &size, &count);
    std::vector<u8> code;
    if (rc == 0 && enc) code.assign(enc, enc + size);
    const ks_err err = ks_errno(ks);
    if (enc) ks_free(enc);
    ks_close(ks);
    if (rc != 0)
        throw std::runtime_error("stub_link: ks_asm failed errno=" + std::to_string(int(err)) +
                                 " stmt#" + std::to_string(count));

    // 回填 blob 指令流的 rip 相对 disp32（x64 形专属——x86 形 blob 指针为
    // imm32 立即数，无占位）。定位 dummy 值（LE 序列），计算真实位移。
    // lea rax,[rip+disp32] 编码 48 8D 05 xx xx xx xx —— disp 起始在 dummy 处。
    if (arch == StubArch::X64) {
    const u8 pat[4] = {u8(kBlobDispDummy & 0xFF), u8((kBlobDispDummy >> 8) & 0xFF),
                       u8((kBlobDispDummy >> 16) & 0xFF), u8((kBlobDispDummy >> 24) & 0xFF)};
    size_t found = SIZE_MAX;
    for (size_t i = 0; i + 4 <= code.size(); ++i) {
        if (code[i] == pat[0] && code[i + 1] == pat[1] && code[i + 2] == pat[2] &&
            code[i + 3] == pat[3]) {
            found = i;
            break;
        }
    }
    if (found == SIZE_MAX)
        throw std::runtime_error("stub_link: blob disp placeholder not found in stub code");
    // disp = 目标 RVA - (下一条指令 RVA)。lea 指令起点 = found - 3（REX+opcode+modrm）。
    const u64 next_rip = stub_rva + (found - 3) + 7;
    const i64 disp = static_cast<i64>(blob_stream_rva) - static_cast<i64>(next_rip);
    const u32 disp_u = static_cast<u32>(disp);
    for (int b = 0; b < 4; ++b)
        code[found + b] = u8((disp_u >> (8 * b)) & 0xFF);
    }
    return code;
}

} // namespace wvmp::passes
