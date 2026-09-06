#include "wvmp/passes/tls_hook/tls_hook_pass.hpp"

#include "wvmp/passes/tls_hook/tls_plan.hpp"

#include "wvmp/passes/import_protect/import_plan.hpp"

#include "wvmp/passes/anti_debug/anti_debug_plan.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/protect_levels.hpp"
#include "wvmp/framework/registry.hpp"
#include "wvmp/passes/pe_loader/pe_image.hpp"

#include <keystone/keystone.h>

#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace wvmp::passes {
namespace {

// IMAGE_FILE_MACHINE_I386（与 stub_link 同值独立声明：模块边界约定，
// pe_image.cpp 解析白名单为单一语义源）。
constexpr u16 kMachineX86 = 0x014C;
// DataDirectory[9] = IMAGE_DIRECTORY_ENTRY_TLS。
constexpr size_t kTlsDirIndex = 9;
// 原回调数组并入条数上限：防御原目录字段损坏时的无界扫描（真实镜像的
// CRT/用户回调个位数）。触顶视为损坏，按已读到的条数保守并入。
constexpr size_t kMaxOriginalCallbacks = 256;
constexpr size_t kMaxDescriptors = 1024;   // MIT-470: 描述符链上限（同 import_protect 口径）
constexpr size_t kMaxSlotsPerDesc = 4096;  // MIT-470: 单描述符槽上限

// MIT-471：rdtsc 计时检查阈值（周期数，单一来源）。判据 = 包裹检查窗的
// 两读数差。正常执行（数十条指令）≈ 10^2-10^3 周期；任务切换/中断毛刺
// ≈ 10^4-10^5；单步调试（每条指令一次陷阱，调试器往返 ≫10^4 周期/步 ×
// 全窗）≥ 10^6。0x7A120 = 500k：高于毛刺、远低于单步全程——本机校准
// 脚本 scripts/calibrate_rdtsc.sh 提供分布依据（ calibration 记录见
// STATUS T15 行）。改阈值须重跑校准并在提交中披露。
constexpr u64 kRdtscThresholdCycles = 500000;

// MIT-470：DRx 检查面装配参数（GetThreadContext IAT 槽 + CONTEXT 暂存）。
struct DrxInfo {
    u64 gtc_slot_va = 0;   // GetThreadContext 的 IAT 槽 VA（迁移态 = 镜像槽）
    u64 ctx_va = 0;        // CONTEXT 暂存 VA（.wvmp 内，16 对齐）
    u32 ctx_flags = 0;     // CONTEXT_DEBUG_REGISTERS（按位宽）
};

// OptionalHeader 内数据目录区的布局偏移（PE32/PE32+ 可选头定长区不同）。
size_t opt_num_rva_sizes_off(bool plus) { return plus ? 108u : 92u; }
size_t opt_data_dir_off(bool plus) { return plus ? 112u : 96u; }

u64 rd_le(const u8* p, size_t n) {
    u64 v = 0;
    for (size_t i = 0; i < n; ++i) v |= u64(p[i]) << (8 * i);
    return v;
}
void append_le(std::vector<u8>& out, u64 v, size_t n) {
    for (size_t i = 0; i < n; ++i) out.push_back(u8((v >> (8 * i)) & 0xFF));
}

u64 align_up(u64 v, u64 a) { return a == 0 ? v : ((v + a - 1) / a) * a; }

// IMAGE_TLS_DIRECTORY 的 6 个逻辑字段（宿主宽度在编码期按 PE32+/PE32 定）。
struct TlsDirFields {
    u64 start = 0;
    u64 end = 0;
    u64 index = 0;
    u64 callbacks = 0;
    u32 zero_fill = 0;
    u32 characteristics = 0;
};

// 原 PE 的 TLS 目录 + 回调数组快照。present=false = 原 PE 无 TLS 目录
// （或目录 RVA 为 0）。array_lost=true = 目录存在但回调数组不可达
// （越界/损坏）——6 字段仍保留，仅回调并入被放弃（诊断面）。
struct OriginalTls {
    bool present = false;
    bool array_lost = false;
    TlsDirFields fields;
    std::vector<u64> callbacks;  // 原数组的绝对 VA（host 序 u64 承载）
};

OriginalTls read_original_tls(ProtectionContext& ctx, const PeImage& pe) {
    OriginalTls res;
    const bool plus = pe.is_pe32_plus;
    const size_t opt = size_t(pe.nt_headers_offset) + 24;
    const size_t dd = opt + opt_data_dir_off(plus) + kTlsDirIndex * 8;
    if (dd + 8 > ctx.image.size()) return res;
    const u32 dir_rva = u32(rd_le(&ctx.image[dd], 4));
    if (dir_rva == 0) return res;

    const auto dir_off = pe.rva_to_offset(dir_rva);
    if (!dir_off.has_value()) return res;
    const size_t w = plus ? 8 : 4;
    // 目录本体 = 4 个指针宽字段 + 2 个 dword = w*4 + 8 字节。
    if (*dir_off + w * 4 + 8 > ctx.image.size()) return res;
    const u8* p = ctx.image.data() + *dir_off;
    res.fields.start = rd_le(p, w);
    res.fields.end = rd_le(p + w, w);
    res.fields.index = rd_le(p + 2 * w, w);
    res.fields.callbacks = rd_le(p + 3 * w, w);
    res.fields.zero_fill = u32(rd_le(p + 4 * w, 4));
    res.fields.characteristics = u32(rd_le(p + 4 * w + 4, 4));
    res.present = true;

    // 回调数组：绝对 VA → RVA → 文件偏移，逐项读到 NULL。不可达 = 保守
    // 放弃并入（array_lost，诊断面），目录字段仍保留。
    if (res.fields.callbacks < pe.image_base) {
        res.array_lost = true;
        return res;
    }
    const u64 arr_rva = res.fields.callbacks - pe.image_base;
    const auto arr_off = pe.rva_to_offset(arr_rva);
    if (!arr_off.has_value()) {
        res.array_lost = true;
        return res;
    }
    for (size_t i = 0; i < kMaxOriginalCallbacks; ++i) {
        const size_t e = *arr_off + i * w;
        if (e + w > ctx.image.size()) break;
        const u64 va = rd_le(&ctx.image[e], w);
        if (va == 0) break;  // NULL 终止符
        res.callbacks.push_back(va);
    }
    return res;
}

// MIT-467：init 期 PEB 检查块（TLS 回调执行面，早于进程入口——抓附加型
// 调试器）。字节面与 T5 stub 入口前缀同模板（gs/fs → TEB → PEB →
// BeingDebugged / NtGlobalFlag，命中 FailFast 写 [0] 确定性 AV）。独立
// 装配（stub_gen 为 stub_link 内部头）；rax 被蹭 push/pop 保存。
std::string build_adb_init_asm(bool is_x86, u32 techniques) {
    std::string o;
    namespace tech = wvmp::passes::anti_debug::tech;
    const char* kNl = "\n";
    if (is_x86) {
        o += std::string("push eax") + kNl;
        o += std::string("mov eax, dword ptr fs:[0x18]") + kNl;   // TEB
        o += std::string("mov eax, dword ptr [eax+0x30]") + kNl;  // PEB
        if (techniques & tech::kBeingDebugged) {
            o += std::string("cmp byte ptr [eax+2], 0") + kNl;
            o += std::string("jne wvadb_fail") + kNl;
        }
        if (techniques & tech::kNtGlobalFlag) {
            o += std::string("mov eax, dword ptr [eax+0x68]") + kNl;
            o += std::string("test eax, 0x70") + kNl;
            o += std::string("jne wvadb_fail") + kNl;
        }
        o += std::string("pop eax") + kNl;
        o += std::string("jmp wvadb_done") + kNl;
        o += std::string("wvadb_fail:") + kNl;
        o += std::string("xor eax, eax") + kNl;
        o += std::string("mov dword ptr [eax], 0") + kNl;
        o += std::string("wvadb_done:") + kNl;
    } else {
        o += std::string("push rax") + kNl;
        o += std::string("mov rax, qword ptr gs:[0x30]") + kNl;   // TEB
        o += std::string("mov rax, qword ptr [rax+0x60]") + kNl;  // PEB
        if (techniques & tech::kBeingDebugged) {
            o += std::string("cmp byte ptr [rax+2], 0") + kNl;
            o += std::string("jne wvadb_fail") + kNl;
        }
        if (techniques & tech::kNtGlobalFlag) {
            o += std::string("mov eax, dword ptr [rax+0xBC]") + kNl;
            o += std::string("test eax, 0x70") + kNl;
            o += std::string("jne wvadb_fail") + kNl;
        }
        o += std::string("pop rax") + kNl;
        o += std::string("jmp wvadb_done") + kNl;
        o += std::string("wvadb_fail:") + kNl;
        o += std::string("xor eax, eax") + kNl;
        o += std::string("mov qword ptr [rax], 0") + kNl;
        o += std::string("wvadb_done:") + kNl;
    }
    return o;
}

std::string hex64(u64 v) {
    char b[32];
    std::snprintf(b, sizeof(b), "%llX", static_cast<unsigned long long>(v));
    return b;
}

// MIT-471：rdtsc 计时检查（包裹检查窗）。open = 第一次读数（存易失寄存
// 器/x86 存 .wvmp 暂存）；close = 第二次读数 + 64 位差（x64）/ 32 位低差
// + 进位警戒（x86 用 sbb，进位即超阈——窗口内 TSC 64 位回绕概率≈0）。
// 阈值以上 → FailFast。寄存器纪律：x64 用 r11（volatile，检查窗内无人用）；
// x86 全走绝对寻址暂存。
std::string build_rdtsc_open_asm(bool is_x86, u64 scratch_va) {
    std::string o;
    if (is_x86) {
        o += std::string("rdtsc") + char(10);
        o += std::string("mov dword ptr [0x" + hex64(scratch_va) + "], eax") + char(10);
        o += std::string("mov dword ptr [0x" + hex64(scratch_va + 4) + "], edx") + char(10);
    } else {
        o += std::string("rdtsc") + char(10);
        o += std::string("mov r11, rax") + char(10);
    }
    return o;
}

std::string build_rdtsc_close_asm(bool is_x86, u64 scratch_va) {
    std::string o;
    const std::string th = hex64(kRdtscThresholdCycles);
    // fail 标签在本块内自定义（rdtsc 面可独立于 DRx 面出现——纯 rdtsc 时
    // drx_fail 不存在，ja 悬空 = 装配失败，验收实测 errno=144）。
    if (is_x86) {
        o += std::string("rdtsc") + char(10);
        o += std::string("sub eax, dword ptr [0x" + hex64(scratch_va) + "]") + char(10);
        o += std::string("sbb edx, dword ptr [0x" + hex64(scratch_va + 4) + "]") + char(10);
        o += std::string("cmp edx, 0") + char(10);
        o += std::string("jne rdtsc_fail") + char(10);
        o += std::string("cmp eax, 0x" + th) + char(10);
        o += std::string("ja rdtsc_fail") + char(10);
        o += std::string("jmp rdtsc_done") + char(10);
        o += std::string("rdtsc_fail:") + char(10);
        o += std::string("xor eax, eax") + char(10);
        o += std::string("mov dword ptr [eax], 0") + char(10);
        o += std::string("rdtsc_done:") + char(10);
    } else {
        o += std::string("rdtsc") + char(10);
        o += std::string("sub rax, r11") + char(10);
        o += std::string("cmp rax, 0x" + th) + char(10);
        o += std::string("ja rdtsc_fail") + char(10);
        o += std::string("jmp rdtsc_done") + char(10);
        o += std::string("rdtsc_fail:") + char(10);
        o += std::string("xor eax, eax") + char(10);
        o += std::string("mov qword ptr [rax], 0") + char(10);
        o += std::string("rdtsc_done:") + char(10);
    }
    return o;
}

// TLS 回调体装配：
//   - adb_init != 0：init 期 PEB 检查块前缀（MIT-467）。
//   - imp == nullptr：v1 占位（清返回值立即返回；x86 stdcall ret 0Ch 自清
//     12B 栈参）。
//   - imp != nullptr（MIT-466）：IAT 回填——原 IAT 页已被 loader 重新只读
//     保护，先 VirtualProtect（经其 IAT 槽调用，此时导入解析已完成）解除
//     写保护 → rep movs 把 .wvmp 镜像整段回填原 .rdata IAT 区 → 按保存值
//     恢复保护 → 占位收尾。绝对立即数 = image_base + RVA（本机非 ASLR
//     约定，与 stub 链一致）。DF=0 为 ABI 既有约定。
std::vector<u8> assemble_callback_stub(bool is_x86,
                                       const import_protect::ImportPlan* imp,
                                       u64 image_base,
                                       u32 adb_init,
                                       const DrxInfo* drx,
                                       bool rdtsc_on,
                                       u64 rdtsc_scratch_va) {
    ks_engine* ks = nullptr;
    if (ks_open(KS_ARCH_X86, is_x86 ? KS_MODE_32 : KS_MODE_64, &ks) != KS_ERR_OK)
        throw std::runtime_error("tls_hook: ks_open failed");
    ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_INTEL);
    std::string body;
    if (rdtsc_on) body += build_rdtsc_open_asm(is_x86, rdtsc_scratch_va);
    if (adb_init != 0) body += build_adb_init_asm(is_x86, adb_init);
    // MIT-471 窗口口径：rdtsc close 紧跟 PEB 块（测量窗 = 确定性指令序列）。
    // DRx 的 GTC 系统调用在窗外——系统调用时长波动大（合法大差值），包进
    // 窗内会误报（实测 x64 rc=139）。
    if (rdtsc_on) body += build_rdtsc_close_asm(is_x86, rdtsc_scratch_va);
    if (drx != nullptr && drx->gtc_slot_va != 0) {
        // MIT-470：DRx 硬件断点检查——GetThreadContext(伪句柄 -2, CONTEXT)
        // 取 CONTEXT_DEBUG_REGISTERS，Dr0-Dr3 任一非零 → FailFast。GTC 调用
        // 失败（al=0）静默跳过（保守：不误杀）。x64 块内 sub/add 8 保 16 对齐；
        // FailFast 路径栈不再复用（进程即死）。drx_cleanup 为唯一汇合点，
        // 各路径栈平衡。
        char db[700];
        if (is_x86) {
            std::snprintf(db, sizeof(db),
                          "mov eax, 0x%llX%c"
                          "push eax%c"
                          "mov dword ptr [eax], 0x%08X%c"
                          "push 0xFFFFFFFE%c"
                          "mov eax, 0x%llX%c"
                          "call dword ptr [eax]%c"
                          "test al, al%c"
                          "je drx_cleanup%c"
                          "mov eax, 0x%llX%c"
                          "cmp dword ptr [eax+4], 0%c"
                          "jne drx_fail%c"
                          "cmp dword ptr [eax+8], 0%c"
                          "jne drx_fail%c"
                          "cmp dword ptr [eax+0xC], 0%c"
                          "jne drx_fail%c"
                          "cmp dword ptr [eax+0x10], 0%c"
                          "jne drx_fail%c"
                          "jmp drx_cleanup%c"
                          "drx_fail:%c"
                          "xor eax, eax%c"
                          "mov dword ptr [eax], 0%c"
                          "drx_cleanup:%c",
                          drx->ctx_va, char(10),
                          char(10),
                          drx->ctx_flags, char(10),
                          char(10),
                          drx->gtc_slot_va, char(10),
                          char(10),
                          char(10),
                          char(10),
                          drx->ctx_va, char(10),
                          char(10), char(10),
                          char(10), char(10),
                          char(10), char(10),
                          char(10), char(10),
                          char(10),
                          char(10),
                          char(10),
                          char(10),
                          char(10));
        } else {
            std::snprintf(db, sizeof(db),
                          "sub rsp, 8%c"
                          "mov rcx, -2%c"
                          "mov rdx, 0x%llX%c"
                          "mov dword ptr [rdx+0x30], 0x%08X%c"
                          "mov rax, 0x%llX%c"
                          "call qword ptr [rax]%c"
                          "test al, al%c"
                          "je drx_cleanup%c"
                          "mov rdx, 0x%llX%c"
                          "cmp qword ptr [rdx+0x48], 0%c"
                          "jne drx_fail%c"
                          "cmp qword ptr [rdx+0x50], 0%c"
                          "jne drx_fail%c"
                          "cmp qword ptr [rdx+0x58], 0%c"
                          "jne drx_fail%c"
                          "cmp qword ptr [rdx+0x60], 0%c"
                          "jne drx_fail%c"
                          "jmp drx_cleanup%c"
                          "drx_fail:%c"
                          "xor eax, eax%c"
                          "mov qword ptr [rax], 0%c"
                          "drx_cleanup:%c"
                          "add rsp, 8%c",
                          char(10),
                          char(10),
                          drx->ctx_va, char(10),
                          drx->ctx_flags, char(10),
                          drx->gtc_slot_va, char(10),
                          char(10),
                          char(10),
                          char(10),
                          drx->ctx_va, char(10),
                          char(10), char(10),
                          char(10), char(10),
                          char(10), char(10),
                          char(10), char(10),
                          char(10),
                          char(10),
                          char(10),
                          char(10),
                          char(10),
                          char(10));
        }
        body += db;
    }
    if (imp == nullptr) {
        body += is_x86 ? "xor eax, eax\nret 0Ch" : "xor eax, eax\nret";
    } else {
        const u64 mirror_va = image_base + imp->mirror_rva;
        const u64 orig_va = image_base + imp->iat_base_rva;
        const u64 page_va = image_base + imp->page_rva;
        const u64 oldprot_va = image_base + imp->oldprot_rva;
        // VirtualProtect 调用走「镜像中对应槽」：loader 只解析镜像（dd1 已
        // 重指），原 IAT 槽仍是文件残值（hint RVA），直接调用必跳飞。
        const u64 vp_iat_va =
            image_base + imp->mirror_rva + (imp->vp_slot_rva - imp->iat_base_rva);
        char buf[700];
        if (is_x86) {
            // x86：绝对内存立即数可直接编码；VirtualProtect = stdcall。
            // esi/edi 为 callee-saved（被 rep movsd 使用），必须保存/恢复，
            // 否则破坏 loader 回调链状态（实测：数组第 2 项不再被调用）。
            std::snprintf(buf, sizeof(buf),
                          "push 0x%llX\n"                       // lpflOldProtect
                          "push 0x04\n"                          // flNewProtect = PAGE_READWRITE
                          "push 0x%llX\n"                        // dwSize
                          "push 0x%llX\n"                        // lpAddress（页基）
                          "call dword ptr [0x%llX]\n"            // VirtualProtect(IAT 槽)
                          "push esi\npush edi\n"
                          "mov esi, 0x%llX\n"
                          "mov edi, 0x%llX\n"
                          "mov ecx, 0x%llX\n"
                          "rep movsd dword ptr [edi], dword ptr [esi]\n"
                          "pop edi\npop esi\n"
                          "push 0x%llX\n"                        // lpflOldProtect（暂存）
                          "push dword ptr [0x%llX]\n"            // flNewProtect = 保存的旧保护值
                          "push 0x%llX\n"                        // dwSize
                          "push 0x%llX\n"                        // lpAddress（页基）
                          "call dword ptr [0x%llX]\n"
                          "xor eax, eax\nret 0Ch",
                          oldprot_va, imp->page_bytes, page_va, vp_iat_va,
                          mirror_va, orig_va, imp->iat_bytes / 4,
                          oldprot_va, oldprot_va, imp->page_bytes, page_va,
                          vp_iat_va);
            body += buf;
        } else {
            // x64：VirtualProtect(rcx=addr, rdx=size, r8d=new, r9=&old)，
            // 槽地址经 rax 间接调用；恢复时旧保护值经 r10 读出。rsi/rdi 为
            // callee-saved（x64 ABI），回填前后必须保存/恢复。回调自身作为
            // 调用方需提供 32B shadow space（push×2 + sub 0x28 = 0x38：
            // 入口 rsp≡8 mod 16 → 8-0x38 ≡ 0 对齐保持）。
            std::snprintf(buf, sizeof(buf),
                          "push rsi\npush rdi\n"
                          "sub rsp, 0x28\n"
                          "mov rcx, 0x%llX\n"
                          "mov edx, 0x%llX\n"
                          "mov r8d, 0x04\n"
                          "mov r9, 0x%llX\n"
                          "mov rax, 0x%llX\n"
                          "call qword ptr [rax]\n"
                          "mov rsi, 0x%llX\n"
                          "mov rdi, 0x%llX\n"
                          "mov rcx, 0x%llX\n"
                          "rep movsq qword ptr [rdi], qword ptr [rsi]\n"
                          "mov rcx, 0x%llX\n"
                          "mov edx, 0x%llX\n"
                          "mov r10, 0x%llX\n"
                          "mov r8d, dword ptr [r10]\n"
                          "mov r9, 0x%llX\n"
                          "mov rax, 0x%llX\n"
                          "call qword ptr [rax]\n"
                          "add rsp, 0x28\n"
                          "pop rdi\npop rsi\n"
                          "xor eax, eax\nret",
                          page_va, imp->page_bytes, oldprot_va, vp_iat_va,
                          mirror_va, orig_va, imp->iat_bytes / 8,
                          page_va, imp->page_bytes, oldprot_va, oldprot_va, vp_iat_va);
            body += buf;
        }
    }
    unsigned char* enc = nullptr;
    size_t size = 0, count = 0;
    const int rc = ks_asm(ks, body.c_str(), 0, &enc, &size, &count);
    std::vector<u8> out;
    if (rc == KS_ERR_OK && enc != nullptr && size > 0)
        out.assign(enc, enc + size);
    const ks_err err = ks_errno(ks);
    if (enc) ks_free(enc);
    ks_close(ks);
    if (out.empty()) {
        // 诊断面：装配串随异常带出（源码 review 与验收取证用）。
        throw std::runtime_error("tls_hook: ks_asm failed errno=" +
                                 std::to_string(int(err)) + " src=[" + body + "]");
    }
    return out;
}

} // namespace

std::span<const std::string_view> TlsHookPass::requires_keys() const {
    static constexpr std::string_view kRequires[] = {kNewSections, kPeImage, kImage};
    return kRequires;
}

std::span<const std::string_view> TlsHookPass::provides_keys() const {
    static constexpr std::string_view kProvides[] = {kTlsPlan};
    return kProvides;
}

void TlsHookPass::run(ProtectionContext& ctx) {
    // MIT-468：[tls] enabled=false → 本 pass 空转（配置关断，镜像零改动）。
    if (const ProtectRules* rules = ctx.find_slot<ProtectRules>(kProtectRules);
        rules != nullptr && rules->has_tls_enabled && !rules->tls_enabled) {
        ctx.diag.report(Severity::Note, name(), "TLS 回调基建已按配置关闭（[tls] enabled=false）");
        return;
    }
    // MIT-472 W^X 拆节：回调桩（代码）→ .wvmpc（RX）；index/数组/目录/暂存
    // （数据）→ .wvmp（RW）。两节（stub_link 产出）任一缺席 → 空转。
    NewSection* wvmp = nullptr;    // 数据节（RW）
    NewSection* wvmpc = nullptr;   // 代码节（RX）
    if (auto* sections = ctx.find_slot<std::vector<NewSection>>(kNewSections))
        for (auto& s : *sections) {
            if (s.name == ".wvmp") wvmp = &s;
            if (s.name == ".wvmpc") wvmpc = &s;
        }
    if (wvmp == nullptr || wvmpc == nullptr) {
        ctx.diag.report(Severity::Note, name(),
                        "无 .wvmp/.wvmpc 节（stub_link 未产出），跳过 TLS 回调基建");
        return;
    }
    const PeImage* pe = ctx.find_slot<PeImage>(kPeImage);
    if (pe == nullptr) {
        ctx.diag.report(Severity::Error, name(), "PeImage 模型缺失，无法装配 TLS 目录");
        throw std::runtime_error(std::string(name()) + ": pe image model missing");
    }

    const bool is_x86 = pe->machine == kMachineX86;
    const bool plus = pe->is_pe32_plus;
    const size_t ptr_w = plus ? 8 : 4;      // 指针宽度（数组项 / 目录字段）
    const u64 sec_rva = wvmp->requested_rva;
    const u64 base = pe->image_base;
    // MIT-476 预留区游标（stub_link 置初值 = blobs 末端；槽缺席 = 旧尾部
    // 追加语义，grow_ok = 允许扩容）。
    u64 cur = wvmp->data.size();
    bool grow_ok = true;
    if (auto* r = ctx.find_slot<u64>(kEmitReserveBase)) {
        cur = *r;
        grow_ok = false;
    }

    // —— 追加布局：回调桩 → .wvmpc（16 对齐）；[index 槽 8][回调数组 8]
    // [TLS 目录 8] → .wvmp 尾部（8 对齐）——
    // MIT-466：kImportPlan 在场（import_protect 先行）时回调体携带 IAT
    // 回填循环；槽缺席 = v1 占位体。
    const auto* imp = ctx.find_slot<import_protect::ImportPlan>(kImportPlan);
    // MIT-467：init 期检查位（anti_debug 计划；0 = 关闭）。
    u32 adb_init = 0;
    if (const auto* adb = ctx.find_slot<wvmp::passes::anti_debug::AntiDebugPlan>(kAntiDebugPlan))
        adb_init = adb->init_techniques;
    // MIT-470：DRx 检查面（bit2）。经 IAT 调 GetThreadContext（伪句柄 -2
    // 免导入）。GetThreadContext 槽定位：描述符 FT 已反映迁移后状态（迁移
    // 时被重指镜像切片；未迁移 = 原 IAT，loader 解析）→ 同一扫描两态皆准。
    // 目标未导入 GetThreadContext → 该面静默跳过（Note 留痕）。
    DrxInfo drx{};
    const bool drx_requested = (adb_init & wvmp::passes::anti_debug::tech::kHardwareBreakpoints) != 0;
    if (drx_requested) {
        const size_t dd1 = size_t(pe->nt_headers_offset) + 24 +
                           (plus ? 112u : 96u) + 1u * 8u;
        bool gtc_found = false;
        if (dd1 + 8 <= ctx.image.size()) {
            const u32 desc_rva = u32(rd_le(ctx.image.data() + dd1, 4));
            if (desc_rva != 0) {
                const auto desc_off = pe->rva_to_offset(desc_rva);
                if (desc_off.has_value()) {
                    for (size_t i = 0; i < kMaxDescriptors && !gtc_found; ++i) {
                        const size_t e = *desc_off + i * 20;
                        if (e + 20 > ctx.image.size()) break;
                        const u64 int_rva = rd_le(&ctx.image[e], 4);
                        const u64 ft_rva = rd_le(&ctx.image[e] + 16, 4);
                        if (int_rva == 0 && ft_rva == 0) break;
                        const auto int_off = pe->rva_to_offset(u32(int_rva));
                        if (!int_off.has_value()) continue;
                        for (size_t s = 0; s < kMaxSlotsPerDesc; ++s) {
                            const size_t se = *int_off + s * ptr_w;
                            if (se + ptr_w > ctx.image.size()) break;
                            const u64 thunk = rd_le(&ctx.image[se], ptr_w);
                            if (thunk == 0) break;
                            if (thunk & (u64(1) << 63)) continue;  // x64 ordinal
                            const auto n_off = pe->rva_to_offset(u32(thunk & 0xFFFFFFFFu));
                            if (!n_off.has_value() || *n_off + 18 > ctx.image.size()) continue;
                            if (std::memcmp(ctx.image.data() + *n_off + 2,
                                            "GetThreadContext", 16) == 0 &&
                                ctx.image[*n_off + 18] == 0) {
                                drx.gtc_slot_va = base + ft_rva + u64(s) * ptr_w;
                                gtc_found = true;
                                break;
                            }
                        }
                    }
                }
            }
        }
        if (gtc_found) {
            // CONTEXT 暂存（MIT-476 预留区，16 对齐；x64 0x4D0 / x86 0x2CC）。
            const size_t ctx_size = plus ? 0x4D0u : 0x2CCu;
            const u64 ctx_off = emit_reserve_take(wvmp->data, cur, 16, ctx_size, grow_ok);
            drx.ctx_va = base + wvmp->requested_rva + ctx_off;
            drx.ctx_flags = plus ? 0x00100010u : 0x00010010u;  // CONTEXT_DEBUG_REGISTERS
        } else {
            ctx.diag.report(Severity::Note, name(),
                            "目标未导入 kernel32!GetThreadContext，DRx 检查面跳过（保守降级）");
        }
    }
    // MIT-471：rdtsc 暂存（仅 x86 需要；x64 存 r11）。8 字节 .wvmp 尾部。
    u64 rdtsc_scratch_va = 0;
    const bool rdtsc_requested = (adb_init & 0x8) != 0;
    if (rdtsc_requested && is_x86) {
        const u64 sc_off = emit_reserve_take(wvmp->data, cur, 8, 8, grow_ok);
        rdtsc_scratch_va = base + wvmp->requested_rva + sc_off;
    }
    const std::vector<u8> stub =
        assemble_callback_stub(is_x86, (imp != nullptr && imp->active) ? imp : nullptr,
                               pe->image_base, adb_init,
                               (drx_requested && drx.gtc_slot_va != 0) ? &drx : nullptr,
                               rdtsc_requested,
                               rdtsc_requested ? rdtsc_scratch_va : 0);
    // 代码节偏移（.wvmpc 尾部 16 对齐；代码节后无节，保持尾部追加）。
    const u64 cb_off = align_up(wvmpc->data.size(), 16);
    // 数据节（MIT-476 预留区）：index 槽 8B → 回调数组 → TLS 目录。
    const u64 idx_off = emit_reserve_take(wvmp->data, cur, 8, 8, grow_ok);
    const OriginalTls orig = read_original_tls(ctx, *pe);
    const u64 array_off = emit_reserve_take(wvmp->data, cur, 8,
                                            (2 + orig.callbacks.size()) * ptr_w,
                                            grow_ok);
    const u64 dir_size_bytes = plus ? 40u : 24u;
    const u64 dir_off = emit_reserve_take(wvmp->data, cur, 8, dir_size_bytes, grow_ok);

    const u64 cb_rva = wvmpc->requested_rva + cb_off;
    const u64 cb_va = base + cb_rva;
    const u64 idx_va = base + sec_rva + idx_off;
    const u64 array_rva = sec_rva + array_off;
    const u64 array_va = base + array_rva;
    const u64 dir_rva = sec_rva + dir_off;
    const u32 dir_size = static_cast<u32>(dir_size_bytes);

    // 回调数组：[我们的回调, …原回调…, NULL]（我们的排第一，先于原回调执行）。
    std::vector<u8> array_bytes;
    append_le(array_bytes, cb_va, ptr_w);
    for (const u64 va : orig.callbacks) append_le(array_bytes, va, ptr_w);
    append_le(array_bytes, 0, ptr_w);

    // TLS 目录：原目录存在则 6 字段原样保留（CRT/用户的 TLS 数据面不动），
    // 仅回调数组换成本 pass 重排后的新表；无原目录则给零长 raw 区间 +
    // index 槽（start=end=index，SizeOfZeroFill=0）——加载器为 EXE 建 TLS
    // 数据时零拷贝零填充，仅走回调链。
    TlsDirFields dir;
    if (orig.present) {
        dir = orig.fields;
        dir.callbacks = array_va;
    } else {
        dir.start = idx_va;
        dir.end = idx_va;
        dir.index = idx_va;
        dir.callbacks = array_va;
    }

    // 回调桩 → 代码节 .wvmpc（RX）；index/数组/目录 → 数据节 .wvmp（RW）。
    wvmpc->data.resize(static_cast<size_t>(cb_off), 0);
    wvmpc->data.insert(wvmpc->data.end(), stub.begin(), stub.end());
    {
        // index 槽（加载器写 TLS slot index）+ 数组 + 目录字段：预留区内直写。
        u8* base_p = wvmp->data.data();
        for (int i = 0; i < 8; ++i) base_p[idx_off + i] = 0;
        std::memcpy(base_p + array_off, array_bytes.data(), array_bytes.size());
        const u64 fields[6] = {dir.start, dir.end, dir.index, dir.callbacks,
                               dir.zero_fill, dir.characteristics};
        const u32 fw[6] = {static_cast<u32>(ptr_w), static_cast<u32>(ptr_w),
                           static_cast<u32>(ptr_w), static_cast<u32>(ptr_w), 4, 4};
        u64 at = dir_off;
        for (int i = 0; i < 6; ++i) {
            for (u32 b = 0; b < fw[i]; ++b)
                base_p[at + b] = u8((fields[i] >> (8 * b)) & 0xFF);
            at += fw[i];
        }
    }

    if (auto* r = ctx.find_slot<u64>(kEmitReserveBase)) *r = cur;

    tls_hook::TlsPlan plan;
    plan.tls_dir_rva = dir_rva;
    plan.tls_dir_size = dir_size;
    plan.callback_rva = cb_rva;
    plan.callback_va = cb_va;
    plan.array_rva = array_rva;
    plan.merged_originals = static_cast<u32>(orig.callbacks.size());
    ctx.slot<tls_hook::TlsPlan>(kTlsPlan) = plan;

    // 合并降级诊断：原目录存在但回调数组不可达（越界/损坏）→ 只保留 6
    // 字段、放弃并入。静默降级是 C2 类隐患，必须留痕。
    if (orig.present && orig.array_lost) {
        ctx.diag.report(Severity::Warning, name(),
                        "原 TLS 回调数组不可达（VA 越界或损坏），放弃并入；"
                        "目录 6 字段已保留，新数组仅含本 pass 占位回调");
    }

    char buf[160];
    std::snprintf(buf, sizeof(buf),
                  "TLS 回调桩 @ RVA 0x%llX（VA 0x%llX），回调数组 %u 项 @ RVA 0x%llX，"
                  "TLS 目录 @ RVA 0x%llX，并入原回调 %u 个",
                  static_cast<unsigned long long>(cb_rva),
                  static_cast<unsigned long long>(cb_va),
                  static_cast<unsigned>(orig.callbacks.size() + 1),
                  static_cast<unsigned long long>(array_rva),
                  static_cast<unsigned long long>(dir_rva),
                  plan.merged_originals);
    ctx.diag.report(Severity::Note, name(), buf);
}

WVMP_REGISTER_PASS(TlsHookPass)

} // namespace wvmp::passes
