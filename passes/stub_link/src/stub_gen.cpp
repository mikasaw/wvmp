#include "stub_gen.hpp"

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
constexpr u64 kStubPushBytesX86 = 4 * 4;  // ebx/ebp/esi/edi
static_assert(kStubPushBytesX86 % 16 == 0, "x86 stub push face must stay 16-aligned");
static_assert(kX86ExitSlotDepth == kStubPushBytesX86 + kCtxSize + 0x80,
              "x86 stub push face drifted from kX86ExitSlotDepth derivation");
static_assert(kCtxSize % 4 == 0, "x86 stub ctx zero-fill must be dword-granular");

// 入口预写相对当前 rsp（= ns - kStubPushBytes - kCtxSize）的槽偏移。
// 选 0x80：disp8 恰好 -128 可编码（keystone 大负 disp 截断坑规避），且
// 换算到 native_sp 坐标系恰为 kExitSlotDepth（见 runtime.hpp 注释）。
constexpr u64 kExitSlotFromStubEntry = kExitSlotDepth - kStubPushBytes - kCtxSize;
// x86 同构换算（kX86ExitSlotDepth - 0x10 - 0x1C8 = 0x80，disp8 边界同款）。
constexpr u64 kX86ExitSlotFromStubEntry =
    kX86ExitSlotDepth - kStubPushBytesX86 - kCtxSize;
static_assert(kX86ExitSlotFromStubEntry == 0x80,
              "x86 exit slot entry prewrite must stay disp8-encodable");

// x64 stub 汇编（MIT-446 (X4) B.1 起更名 x64 专形；D2 恒等铁约束：函数体
// 逐字保留，x64 asm_dump sha ffd47289… 恒等是机器证明项）。
std::string build_stub_asm_x64(u64 rt_entry_rva, u64 resume_rva, u64 image_base) {
    std::string o;
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
    // 低 kStubPushBytes(0x40) + kCtxSize(0x1C8) = 0x208，用 lea 还原。rax 的原值已在
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
    // 槽地址 = [rsp - 0x80]（rsp = ns - 0x208 → ns - kExitSlotDepth）。
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
//   8. xmm 同步不适用（x86 运行时无 SSE handler，ctx.xmm 面未消费；
//      Win32 ABI xmm 全易失，callgate callee 副作用不建模）。
//
// guest 栈写恒 ≥ ns 规则（442 区1 实证）下，Guest cdecl 栈参数经
// build_callgate_x86 的固定参数窗预置消费（kX86CallgateArgDwords 协议，
// stub 帧形 = 锚③不变量 "entry 4 push + kCtxSize"）。
// =============================================================================
std::string build_stub_asm_x86(u64 rt_entry_rva, u64 blob_stream_rva,
                               u64 resume_rva, u64 image_base) {
    std::string o;
    // —— 序言：4 callee-saved push + ctx 区（kStubPushBytesX86 + kCtxSize
    //      参与出口槽换算，禁字面量第二份）。push 序固定 ebx→edi。——
    o += "push ebx\n push ebp\n push esi\n push edi\n";
    o += "sub esp, " + hex(kCtxSize) + "\n";
    // —— ctx 区清零（槽高半字恒 0 不变量的栈帧来源）。eax/ecx/edx 是待预载
    //      的易失原值，先经 3 个临时 push 捕获（位于 ctx 区之下、出口槽
    //      [esp-0x80] 之上，pop 后痕迹归零）；edi/ecx/eax 作 rep stosd
    //      工作寄存器（原值已捕获/已压栈）。cld 防御 DF 残留（Win32 ABI
    //      DF=0 惯例，1B 保险）。——
    o += "push eax\n push ecx\n push edx\n";
    o += "cld\n";
    o += "lea edi, [esp + " + hex(3 * 4) + "]\n";
    o += "mov ecx, " + hex(kCtxSize / 4) + "\n";
    o += "xor eax, eax\n";
    o += "rep stosd\n";
    o += "pop edx\n pop ecx\n pop eax\n";
    // —— 预载宿主 GP 寄存器 → 虚拟寄存器堆（x86 GP = eax..edi 槽 0..7，
    //      dword 写、高半字由清零保证 0）。ebx/ebp/esi/edi 原值从 stub 自己
    //      的保存区（ctx 区上方 [esp + kCtxSize + 4k]）读回。——
    o += "mov [esp + " + hex(kCtxRegs + 0 * 8) + "], eax\n";
    o += "mov [esp + " + hex(kCtxRegs + 1 * 8) + "], ecx\n";
    o += "mov [esp + " + hex(kCtxRegs + 2 * 8) + "], edx\n";
    o += "mov eax, [esp + " + hex(kCtxSize + 0 * 4) + "]\n";  // 原 ebx
    o += "mov [esp + " + hex(kCtxRegs + 3 * 8) + "], eax\n";
    o += "mov eax, [esp + " + hex(kCtxSize + 1 * 4) + "]\n";  // 原 ebp
    o += "mov [esp + " + hex(kCtxRegs + 5 * 8) + "], eax\n";
    o += "mov eax, [esp + " + hex(kCtxSize + 2 * 4) + "]\n";  // 原 esi
    o += "mov [esp + " + hex(kCtxRegs + 6 * 8) + "], eax\n";
    o += "mov eax, [esp + " + hex(kCtxSize + 3 * 4) + "]\n";  // 原 edi
    o += "mov [esp + " + hex(kCtxRegs + 7 * 8) + "], eax\n";
    // v4 = 原始 rsp（区域代码按原函数帧的 rsp 相对寻址）：当前 esp 比原始
    // 值低 kStubPushBytesX86(0x10) + kCtxSize(0x1C8) = 0x1D8，用 lea 还原。
    // 同一原始 esp 写 native_sp（callgate 窗口锚/ExitNative 槽基准，跨指令
    // 不变）。eax 原值已在 slot0 保存，可复用。
    o += "lea eax, [esp + " + hex(kStubPushBytesX86 + kCtxSize) + "]\n";
    o += "mov [esp + " + hex(kCtxRsp) + "], eax\n";
    o += "mov [esp + " + hex(kCtxNativeSp) + "], eax\n";
    // image_base → scratch_mem 槽（PE32 ImageBase 恒 imm32 可编码；Load/
    // Store/Push/Pop 访存 = RVA + image_base。ASLR 由 pe_writer 清
    // DYNAMIC_BASE 兜底，槽值不变）。
    o += "mov dword ptr [esp + " + hex(kCtxScratch) + "], " + hex(image_base) + "\n";
    // ExitNative 退出槽入口预写：生成期常量 VA = image_base + resume_rva
    // （407 v2 铁律：裸 RVA 进槽 = 野跳）。槽地址 = [esp - 0x80]
    // （esp = ns - 0x1D8 → ns - kX86ExitSlotDepth）。
    o += "mov eax, " + hex(image_base + resume_rva) + "\n";
    o += "mov [esp - " + hex(kX86ExitSlotFromStubEntry) + "], eax\n";
    o += "mov dword ptr [esp + 0x8], 0\n";                  // pc = 0（高半字已清零）
    // blob 指令流指针 = image_base + blob_stream_rva（imm32 VA；32 位模式
    // 无 rip 寻址，无需 x64 disp32 回填；pe_writer 清 DYNAMIC_BASE 下与
    // x64 rip-relative 形等价）。
    o += "mov dword ptr [esp], " + hex(image_base + blob_stream_rva) + "\n";
    // —— 调共享解释器（cdecl：ctx 指针经栈参，runtime_x86 entry [esp+0x14] 读）。
    o += "push esp\n";
    o += "call " + hex(rt_entry_rva) + "\n";
    // —— HALT/ExitNative 返回：cdecl 调用方清参 + 回写易失寄存器
    //      （callee-saved 由 pop 恢复原值，见差异 5）。——
    o += "add esp, " + hex(4) + "\n";
    o += "mov eax, [esp + " + hex(kCtxRegs + 0 * 8) + "]\n";
    o += "mov ecx, [esp + " + hex(kCtxRegs + 1 * 8) + "]\n";
    o += "mov edx, [esp + " + hex(kCtxRegs + 2 * 8) + "]\n";
    o += "add esp, " + hex(kCtxSize) + "\n";
    o += "pop edi\n pop esi\n pop ebp\n pop ebx\n";
    // 终态：esp = entry rsp = native_sp；经 4B 退出槽间接跳（入口已预写
    // VA(resume_rva)，ExitNative handler 命中时覆写为目标 VA）。Halt 与
    // ExitNative 两条出口共用此通道（x64 形同构）。
    o += "jmp dword ptr [esp - " + hex(kX86ExitSlotDepth) + "]\n";
    return o;
}

} // namespace

std::vector<u8> generate_entry_stub(u64 stub_rva, u64 blob_stream_rva, u64 rt_entry_rva,
                                    u64 resume_rva, u64 image_base, StubArch arch) {
    ks_engine* ks = nullptr;
    if (ks_open(KS_ARCH_X86, arch == StubArch::X86 ? KS_MODE_32 : KS_MODE_64, &ks) !=
        KS_ERR_OK)
        throw std::runtime_error("stub_link: ks_open failed");
    ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_INTEL);

    const std::string src =
        arch == StubArch::X86
            ? build_stub_asm_x86(rt_entry_rva, blob_stream_rva, resume_rva, image_base)
            : build_stub_asm_x64(rt_entry_rva, resume_rva, image_base);
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
