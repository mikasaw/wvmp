// MIT-526 (CR-04)：x64 TLS 回调 ABI 真执行探针（测试夹具，非产品码）。
//
// 形态：跑真实的 TlsHookPass 产出 .wvmpc 回调桩字节 → 连同 .text/.wvmp 一起
// 镜像进一块 RWX 内存（VA = 合成 image_base ⇒ 桩内烘焙的绝对 VA 原样可用）→
// 把 GetThreadContext / VirtualProtect 的 IAT 槽指向 Keystone 现编的「模拟被调」
// （按 x64 约定把自己那 4 个 home slot [rsp+8]/[+0x10]/[+0x18]/[+0x20] 全写脏）
// → 由另一段现编的调用 thunk 真跳进回调。
//
// 判据物理量（写进 readings 文件，由 test_tls_abi_exec.cpp 断言）：
//   H        = thunk 在 call 回调那一刻的 rsp（回调入口 E = H - 8）
//   M        = 模拟被调入口 rsp
//   gap      = H - M ⇒ 调用方留了 0x28（32B shadow + 8B 对齐）时恰为 0x38
//              （thunk call push 8 + 回调 sub 0x28 + 回调 call push 8）；
//              只 sub 8（CR-04 现场）退化成 0x18 ⇒ 写脏的 [M+0x10] 正落在 E 上
//              = 回调自己的返回地址 ⇒ 回调 ret 回飞（VEH 记 fault_rip）。
//   post_rsp = 回调返回后 thunk 的 rsp ⇒ 与 H 相等即「出口 RSP == 入口 RSP」。
//
// 进程隔离：修前的失败形态是回飞/AV（asm 帧无 unwind 信息，测试进程内 __try
// 捕获不了），故本探针独立成 exe，由 gtest 以子进程跑并读退出码 + readings。
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "wvmp/passes/tls_hook/tls_hook_pass.hpp"
#include "wvmp/passes/tls_hook/tls_plan.hpp"
#include "wvmp/passes/anti_debug/anti_debug_plan.hpp"
#include "wvmp/passes/import_protect/import_plan.hpp"
#include "wvmp/passes/pe_loader/pe_image.hpp"
#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"

#include <keystone/keystone.h>

#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace wvmp;
using namespace wvmp::passes;

// —— 合成镜像布局（.text：RVA 0x1000 ↔ 文件 0x400）——
constexpr size_t kNt = 0x80;
constexpr size_t kOpt = kNt + 24;
constexpr u32 kDescRva = 0x1000;   // IMAGE_IMPORT_DESCRIPTOR[0]
constexpr u32 kFtRva = 0x1040;     // FirstThunk（[0] = GetThreadContext 槽）
constexpr u32 kIntRva = 0x1080;    // OriginalFirstThunk
constexpr u32 kNameRva = 0x10C0;   // hint(2) + "GetThreadContext" + NUL
constexpr u32 kDllNameRva = 0x1100;
constexpr u32 kTextRva = 0x1000;
constexpr u32 kTextRaw = 0x400;
constexpr u32 kDataRva = 0x2000;   // .wvmp（RW）
constexpr u32 kCodeRva = 0x3000;   // .wvmpc（RX）
constexpr u32 kCtxOff = 0x10;      // MIT-476 预留区首块 = CONTEXT 暂存（16 对齐）
constexpr u32 kMirrorRva = 0x2800; // 镜像 IAT（回填源；[0] = VirtualProtect 槽）
constexpr u32 kOldprotRva = 0x2900;
constexpr size_t kRegionBytes = 0x6000;

// —— scratch 观测区槽位 ——
constexpr u32 kScMockRsp = 0x00;
constexpr u32 kScSave08 = 0x08;
constexpr u32 kScSave10 = 0x10;
constexpr u32 kScSave18 = 0x18;
constexpr u32 kScSave20 = 0x20;
constexpr u32 kScCallRsp = 0x28;   // H
constexpr u32 kScPostRsp = 0x30;
constexpr u32 kScReturned = 0x38;
constexpr u32 kScCbRet = 0x40;
constexpr u32 kScGtcPoison = 0x50;
constexpr u32 kScVpPoison = 0x58;
constexpr u32 kScGtcCalls = 0x60;
constexpr u32 kScVpCalls = 0x68;
constexpr u32 kScVpMockRsp = 0x70;
constexpr u32 kScVpSave10 = 0x78;
constexpr size_t kScratchBytes = 0x200;

// DR7 邻域写脏标记（模拟被调确认自己真的执行过写槽那一段）。
constexpr u64 kPoison = 0x4141414141414141ull;

// 四象限（drx 开/关 × rdtsc 开/关）+ 分支反证 + 第二 call 站点。
struct Mode {
    const char* name;
    bool drx;
    bool rdtsc;
    bool imp;
    u64 drval;   // 模拟被调写进 Dr0..Dr3 的值（非 0 = 命中 drx_fail）
    u64 retval;  // 模拟被调返回值（0 = GTC 失败 → je drx_cleanup）
};
constexpr Mode kModes[] = {
    {"plain", false, false, false, 0, 1},        // 象限：全关
    {"rdtsc_only", false, true, false, 0, 1},    // 象限：仅 rdtsc（无 call）
    {"drx_clean", true, false, false, 0, 1},     // 象限：仅 DRx，Dr0-3 = 0
    {"drx_rdtsc", true, true, false, 0, 1},      // 象限：DRx + rdtsc 全开
    {"drx_gtcfail", true, false, false, 0, 0},   // 分支：je drx_cleanup
    {"drx_hit", true, false, false, 1, 1},       // 分支：drx_fail（FailFast）
    {"backfill", true, false, true, 0, 1},       // 第二 call 站点（VirtualProtect）
};

HANDLE g_out = INVALID_HANDLE_VALUE;
u8* g_sc = nullptr;   // 观测区（VEH 里也要读，崩溃现场才留得下 gap 读数）
u64 g_cb = 0;         // 回调桩入口
size_t g_stub_size = 0;

unsigned long long ull(u64 v) { return static_cast<unsigned long long>(v); }

u64 load64(const void* p) {
    u64 v = 0;
    std::memcpy(&v, p, 8);
    return v;
}

u64 scratch_at(const u8* sc, u32 off) { return load64(sc + off); }

void reportf(const char* fmt, ...) {
    if (g_out == INVALID_HANDLE_VALUE) return;
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    const int n = std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    DWORD wr = 0;
    WriteFile(g_out, buf, static_cast<DWORD>(n), &wr, nullptr);
    FlushFileBuffers(g_out);
}

// 崩溃现场的物理量：VEH 直接在故障线程栈上跑（asm 帧无 unwind 信息，
// __try/__except 到不了），读数逐行 flush ⇒ 进程随后死掉也留得住。
LONG WINAPI veh(struct _EXCEPTION_POINTERS* ep) {
    const ULONG_PTR* info = ep->ExceptionRecord->ExceptionInformation;
    const CONTEXT* cr = ep->ContextRecord;
    reportf("fault_code=0x%08X\n", static_cast<u32>(ep->ExceptionRecord->ExceptionCode));
    reportf("fault_dir=%llu\n", ull(static_cast<u64>(info[0])));  // 0=写 1=读 8=取指
    reportf("fault_addr=0x%llX\n", ull(static_cast<u64>(info[1])));
    reportf("fault_rip=0x%llX\n", ull(static_cast<u64>(cr->Rip)));
    reportf("fault_rsp=0x%llX\n", ull(static_cast<u64>(cr->Rsp)));
    reportf("fault_rax=0x%llX\n", ull(static_cast<u64>(cr->Rax)));
    reportf("fault_rcx=0x%llX\n", ull(static_cast<u64>(cr->Rcx)));
    reportf("fault_rdx=0x%llX\n", ull(static_cast<u64>(cr->Rdx)));
    reportf("fault_r8=0x%llX\n", ull(static_cast<u64>(cr->R8)));
    reportf("fault_r9=0x%llX\n", ull(static_cast<u64>(cr->R9)));
    reportf("fault_r10=0x%llX\n", ull(static_cast<u64>(cr->R10)));
    reportf("fault_r11=0x%llX\n", ull(static_cast<u64>(cr->R11)));
    reportf("fault_rbp=0x%llX\n", ull(static_cast<u64>(cr->Rbp)));
    if (cr->Rip >= g_cb && g_stub_size != 0 && cr->Rip < g_cb + g_stub_size)
        reportf("fault_rip_stub_off=0x%llX\n", ull(cr->Rip - g_cb));
    {
        char hex[3 * 24 + 4] = {0};
        const u8* p = reinterpret_cast<const u8*>(cr->Rip);
        int at = 0;
        for (int i = 0; i < 24; ++i)
            at += std::snprintf(hex + at, sizeof(hex) - at, "%02X ", p[i]);
        reportf("code_at_rip=%s\n", hex);
    }
    // 栈面取证：[rsp-0x20, rsp+0x28) —— 回调返回地址槽若被写脏，这里直接现形。
    if (cr->Rsp > 0x10000 && cr->Rsp < 0x00007FFFFFFFFFFFull) {
        const u8* sp = reinterpret_cast<const u8*>(cr->Rsp);
        for (int i = -4; i <= 5; ++i) {
            const u8* p = sp + i * 8;
            reportf("stk[%+d]=0x%llX\n", i * 8, ull(load64(p)));
        }
    }
    if (g_sc != nullptr) {
        const u64 h = scratch_at(g_sc, kScCallRsp);
        const u64 mm = scratch_at(g_sc, kScMockRsp);
        reportf("veh_H=0x%llX\n", ull(h));
        reportf("veh_M=0x%llX\n", ull(mm));
        reportf("veh_gap=0x%llX\n", ull(h - mm));
        reportf("veh_gtc_calls=%llu\n", ull(scratch_at(g_sc, kScGtcCalls)));
        reportf("veh_gtc_poison=%llu\n", ull(scratch_at(g_sc, kScGtcPoison)));
        reportf("veh_vp_calls=%llu\n", ull(scratch_at(g_sc, kScVpCalls)));
        reportf("veh_vp_poison=%llu\n", ull(scratch_at(g_sc, kScVpPoison)));
        reportf("veh_vp_m=0x%llX\n", ull(scratch_at(g_sc, kScVpMockRsp)));
        reportf("veh_returned=%llu\n", ull(scratch_at(g_sc, kScReturned)));
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void wr_le(std::vector<u8>& img, size_t off, u64 v, size_t w) {
    for (size_t i = 0; i < w; ++i) img[off + i] = u8((v >> (8 * i)) & 0xFF);
}

// 合成 PE32+ 镜像：单 .text + dd[1] 指向一个导入 kernel32!GetThreadContext 的
// 描述符（tls_hook 的 DRx 面靠它把 IAT 槽定位到 base + kFtRva）。
std::vector<u8> build_image(u64 base) {
    constexpr size_t kOptSize = 240;
    const size_t table = kOpt + kOptSize;
    std::vector<u8> img(table + 40 + 0x800, 0);
    img[0] = 'M';
    img[1] = 'Z';
    wr_le(img, 0x3C, kNt, 4);
    img[kNt] = 'P';
    img[kNt + 1] = 'E';
    wr_le(img, kNt + 4, 0x8664, 2);      // Machine
    wr_le(img, kNt + 6, 1, 2);           // NumberOfSections
    wr_le(img, kNt + 20, kOptSize, 2);   // SizeOfOptionalHeader
    wr_le(img, kNt + 22, 0x0022, 2);     // Characteristics
    wr_le(img, kOpt, 0x020B, 2);         // Magic = PE32+
    wr_le(img, kOpt + 16, 0x1000, 4);    // SectionAlignment
    wr_le(img, kOpt + 20, 0x200, 4);     // FileAlignment
    wr_le(img, kOpt + 24, base, 8);      // ImageBase
    wr_le(img, kOpt + 56, 0x6000, 4);    // SizeOfImage
    wr_le(img, kOpt + 60, 0x200, 4);     // SizeOfHeaders
    wr_le(img, kOpt + 108, 16, 4);       // NumberOfRvaAndSizes
    const size_t sh = table;
    std::memcpy(&img[sh], ".text", 5);
    wr_le(img, sh + 8, 0x800, 4);        // VirtualSize
    wr_le(img, sh + 12, kTextRva, 4);    // VirtualAddress
    wr_le(img, sh + 16, 0x800, 4);       // SizeOfRawData
    wr_le(img, sh + 20, kTextRaw, 4);    // PointerToRawData
    wr_le(img, sh + 36, 0x60000020, 4);  // Characteristics

    const size_t dd1 = kOpt + 112 + 1 * 8;
    wr_le(img, dd1, kDescRva, 4);
    wr_le(img, dd1 + 4, 20, 4);
    const size_t d = kTextRaw + (kDescRva - kTextRva);
    wr_le(img, d + 0, kIntRva, 4);
    wr_le(img, d + 12, kDllNameRva, 4);
    wr_le(img, d + 16, kFtRva, 4);
    const size_t ft = kTextRaw + (kFtRva - kTextRva);
    const size_t in = kTextRaw + (kIntRva - kTextRva);
    wr_le(img, ft, kNameRva, 8);
    wr_le(img, ft + 8, 0, 8);
    wr_le(img, in, kNameRva, 8);
    wr_le(img, in + 8, 0, 8);
    const size_t nm = kTextRaw + (kNameRva - kTextRva);
    wr_le(img, nm, 0, 2);
    std::memcpy(&img[nm + 2], "GetThreadContext", 16);
    img[nm + 18] = 0;
    const size_t dn = kTextRaw + (kDllNameRva - kTextRva);
    std::memcpy(&img[dn], "kernel32.dll", 13);
    return img;
}

PeImage build_meta(u64 base) {
    PeImage m;
    m.is_pe32_plus = true;
    m.machine = 0x8664;
    m.image_base = base;
    m.section_alignment = 0x1000;
    m.file_alignment = 0x200;
    m.num_sections = 1;
    m.nt_headers_offset = u32(kNt);
    SectionInfo s;
    s.name = ".text";
    s.virtual_size = 0x800;
    s.virtual_addr = kTextRva;
    s.raw_size = 0x800;
    s.raw_ptr = kTextRaw;
    s.characteristics = 0x60000020;
    m.sections.push_back(s);
    return m;
}

// Keystone x64（Intel 语法）装配。所有立即数/位移一律 0x 前缀（裸多位数字被
// Keystone 按十六进制读，MIT-371 教训）。
std::vector<u8> assemble64(const std::string& text, const char* what) {
    ks_engine* ks = nullptr;
    if (ks_open(KS_ARCH_X86, KS_MODE_64, &ks) != KS_ERR_OK)
        throw std::runtime_error(std::string("probe: ks_open failed for ") + what);
    ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_INTEL);
    unsigned char* enc = nullptr;
    size_t size = 0, count = 0;
    const int rc = ks_asm(ks, text.c_str(), 0, &enc, &size, &count);
    std::vector<u8> out;
    if (rc == KS_ERR_OK && enc != nullptr && size > 0) out.assign(enc, enc + size);
    const ks_err err = ks_errno(ks);
    if (enc) ks_free(enc);
    ks_close(ks);
    if (out.empty()) {
        char b[160];
        std::snprintf(b, sizeof(b), "probe: %s assemble failed errno=%d", what, int(err));
        throw std::runtime_error(b);
    }
    return out;
}

void* alloc_rw_x(size_t bytes) {
    void* p = VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT,
                           PAGE_EXECUTE_READWRITE);
    if (p == nullptr) throw std::runtime_error("probe: VirtualAlloc(RWX) failed");
    std::memset(p, 0, bytes);
    return p;
}

bool bytes_contain(const std::vector<u8>& hay, const std::vector<u8>& needle) {
    if (needle.size() > hay.size()) return false;
    for (size_t i = 0; i + needle.size() <= hay.size(); ++i)
        if (std::memcmp(hay.data() + i, needle.data(), needle.size()) == 0) return true;
    return false;
}

int find_sub_rsp(const std::vector<u8>& stub, u32 v) {
    const u8 pat32[8] = {0x48, 0x81, 0xEC, u8(v & 0xFF), u8((v >> 8) & 0xFF), 0, 0, 0};
    for (size_t i = 0; i + 8 <= stub.size(); ++i)
        if (std::memcmp(stub.data() + i, pat32, 8) == 0) return int(i);
    const u8 pat8[4] = {0x48, 0x83, 0xEC, u8(v & 0xFF)};
    for (size_t i = 0; i + 4 <= stub.size(); ++i)
        if (std::memcmp(stub.data() + i, pat8, 4) == 0) return int(i);
    return -1;
}

// —— 模拟被调（GetThreadContext）：先记录、再按 x64 约定写脏自己 4 个 home slot。
constexpr const char* kMockGtcAsm =
    "mov rax, 0x%llX\n"                        // SCRATCH
    "mov qword ptr [rax+0x00], rsp\n"          // M
    "mov rcx, qword ptr [rax+0x60]\n"
    "add rcx, 0x1\n"
    "mov qword ptr [rax+0x60], rcx\n"          // gtc_calls++
    "mov rcx, qword ptr [rsp+0x08]\n"
    "mov qword ptr [rax+0x08], rcx\n"          // 存档 [rsp+8]
    "mov rcx, qword ptr [rsp+0x10]\n"
    "mov qword ptr [rax+0x10], rcx\n"          // 存档 [rsp+0x10]（= 修前的回调返回地址槽）
    "mov rcx, qword ptr [rsp+0x18]\n"
    "mov qword ptr [rax+0x18], rcx\n"
    "mov rcx, qword ptr [rsp+0x20]\n"
    "mov qword ptr [rax+0x20], rcx\n"
    "mov rcx, 0x%llX\n"                        // CTXVA
    "mov rdx, 0x%llX\n"                        // DRVAL
    "mov qword ptr [rcx+0x48], rdx\n"          // Dr0
    "mov qword ptr [rcx+0x50], rdx\n"          // Dr1
    "mov qword ptr [rcx+0x58], rdx\n"          // Dr2
    "mov qword ptr [rcx+0x60], rdx\n"          // Dr3
    "mov rdx, 0x4141414141414141\n"
    "mov qword ptr [rsp+0x08], rdx\n"          // 写脏 4 槽（合法被调行为）
    "mov qword ptr [rsp+0x10], rdx\n"
    "mov qword ptr [rsp+0x18], rdx\n"
    "mov qword ptr [rsp+0x20], rdx\n"
    "mov rdx, 0x1\n"
    "mov qword ptr [rax+0x50], rdx\n"          // gtc_poison
    "mov eax, 0x%llX\n"                        // RETVAL
    "ret\n";

// —— 模拟 VirtualProtect：写回 lpflOldProtect（r9），再写脏 4 个 home slot。
constexpr const char* kMockVpAsm =
    "mov rax, 0x%llX\n"                        // SCRATCH
    "mov qword ptr [rax+0x70], rsp\n"          // M2
    "mov rcx, qword ptr [rax+0x68]\n"
    "add rcx, 0x1\n"
    "mov qword ptr [rax+0x68], rcx\n"          // vp_calls++
    "mov rcx, qword ptr [rsp+0x10]\n"
    "mov qword ptr [rax+0x78], rcx\n"          // 存档
    "mov edx, 0x04\n"
    "mov dword ptr [r9], edx\n"                // *lpflOldProtect = PAGE_READWRITE
    "mov rcx, 0x4141414141414141\n"
    "mov qword ptr [rsp+0x08], rcx\n"
    "mov qword ptr [rsp+0x10], rcx\n"
    "mov qword ptr [rsp+0x18], rcx\n"
    "mov qword ptr [rsp+0x20], rcx\n"
    "mov rcx, 0x1\n"
    "mov qword ptr [rax+0x58], rcx\n"          // vp_poison
    "mov eax, 0x1\n"
    "ret\n";

// —— 调用方 thunk（回调的直接 caller，与 loader 同形）——
constexpr const char* kThunkAsm =
    "sub rsp, 0x28\n"                          // thunk 自己给回调留 shadow
    "mov rax, 0x%llX\n"                        // SCRATCH
    "mov qword ptr [rax+0x28], rsp\n"          // H（call 前一刻）
    "mov rcx, 0x0\n"
    "mov rdx, 0x1\n"
    "mov r8, 0x0\n"
    "mov rax, 0x%llX\n"                        // CBVA
    "call rax\n"
    "mov r10, rax\n"
    "mov rax, 0x%llX\n"                        // SCRATCH
    "mov qword ptr [rax+0x40], r10\n"          // 回调返回值
    "mov qword ptr [rax+0x30], rsp\n"          // post_rsp
    "mov rdx, 0x1\n"
    "mov qword ptr [rax+0x38], rdx\n"          // returned
    "add rsp, 0x28\n"
    "ret\n";

int probe_main(const Mode& m, const std::vector<u8>& image, u64 base, u8* region) {
    ProtectionContext ctx;
    ctx.image = image;
    ctx.slot<PeImage>(kPeImage) = build_meta(base);

    NewSection d;
    d.name = ".wvmp";
    d.data.assign(16, 0);
    d.characteristics = 0xC0000040u;
    d.requested_rva = kDataRva;
    NewSection c;
    c.name = ".wvmpc";
    c.data.assign(16, 0);
    c.characteristics = 0x60000020u;
    c.requested_rva = kCodeRva;
    auto& secs = ctx.slot<std::vector<NewSection>>(kNewSections);
    secs.push_back(d);
    secs.push_back(c);

    namespace tech = wvmp::passes::anti_debug::tech;
    wvmp::passes::anti_debug::AntiDebugPlan adb;
    adb.techniques = m.drx ? tech::kHardwareBreakpoints : 0;
    adb.init_techniques = adb.techniques;
    if (m.rdtsc) adb.init_techniques |= tech::kTimingRdtsc;
    ctx.slot<wvmp::passes::anti_debug::AntiDebugPlan>(kAntiDebugPlan) = adb;
    // PEB 面（bit0/1）刻意不开：探针进程若正被调试器附加会先撞 FailFast，
    // 那与 CR-04 无关，会把读数搅浑。

    import_protect::ImportPlan imp;
    if (m.imp) {
        imp.active = true;
        imp.iat_base_rva = kFtRva;
        imp.iat_bytes = 16;
        imp.mirror_rva = kMirrorRva;
        imp.slot_count = 2;
        imp.descriptor_count = 1;
        imp.vp_slot_rva = kFtRva;
        imp.page_rva = kTextRva;
        imp.page_bytes = 0x1000;
        imp.oldprot_rva = kOldprotRva;
        ctx.slot<import_protect::ImportPlan>(kImportPlan) = imp;
    }

    TlsHookPass pass;
    pass.run(ctx);

    const auto* plan = ctx.find_slot<tls_hook::TlsPlan>(kTlsPlan);
    const NewSection* ds = nullptr;
    const NewSection* cs = nullptr;
    for (const auto& s : ctx.slot<std::vector<NewSection>>(kNewSections)) {
        if (s.name == ".wvmp") ds = &s;
        if (s.name == ".wvmpc") cs = &s;
    }
    if (plan == nullptr || ds == nullptr || cs == nullptr) return 3;

    std::memcpy(region + kTextRva, image.data() + kTextRaw, 0x800);
    std::memcpy(region + kDataRva, ds->data.data(), ds->data.size());
    std::memcpy(region + kCodeRva, cs->data.data(), cs->data.size());

    const u64 ctx_va = base + kDataRva + kCtxOff;
    const u64 gtc_slot_va = base + kFtRva;
    const u64 cb_va = plan->callback_va;
    const auto cb_off = static_cast<size_t>(plan->callback_rva - kCodeRva);
    std::vector<u8> stub;
    stub.assign(cs->data.begin() + static_cast<std::ptrdiff_t>(cb_off), cs->data.end());

    reportf("mode=%s\n", m.name);
    g_cb = cb_va;
    g_stub_size = stub.size();
    // 桩字节全量（诊断面：按 fault_rip_stub_off 直接定位肇事指令）。
    for (size_t i = 0; i < stub.size(); i += 32) {
        char hex[3 * 32 + 4] = {0};
        int at = 0;
        for (size_t j = i; j < i + 32 && j < stub.size(); ++j)
            at += std::snprintf(hex + at, sizeof(hex) - at, "%02X ", stub[j]);
        reportf("stub[%03zX]=%s\n", i, hex);
    }
    reportf("base=0x%llX\n", ull(base));
    reportf("region_lo=0x%llX\n", ull(base));
    reportf("region_hi=0x%llX\n", ull(base + kRegionBytes));
    reportf("cb_va=0x%llX\n", ull(cb_va));
    reportf("stub_size=%d\n", int(stub.size()));
    reportf("poison=0x%llX\n", ull(kPoison));
    {
        std::vector<u8> pat(8);
        std::memcpy(pat.data(), &ctx_va, 8);
        reportf("ctxva_in_stub=%d\n", bytes_contain(stub, pat) ? 1 : 0);
        std::memcpy(pat.data(), &gtc_slot_va, 8);
        reportf("gtcva_in_stub=%d\n", bytes_contain(stub, pat) ? 1 : 0);
        reportf("ctx_va=0x%llX\n", ull(ctx_va));
        reportf("gtc_slot_va=0x%llX\n", ull(gtc_slot_va));
    }
    reportf("has_sub28=%d\n", find_sub_rsp(stub, 0x28) >= 0 ? 1 : 0);
    reportf("has_sub8=%d\n", find_sub_rsp(stub, 0x08) >= 0 ? 1 : 0);

    u8* sc = static_cast<u8*>(alloc_rw_x(kScratchBytes));
    g_sc = sc;
    char text[4096];
    std::snprintf(text, sizeof(text), kMockGtcAsm, ull(reinterpret_cast<uintptr_t>(sc)),
                  ull(ctx_va), ull(m.drval), ull(m.retval));
    const std::vector<u8> gtc_mock = assemble64(text, "mock_gtc");
    u8* gtc = static_cast<u8*>(alloc_rw_x(gtc_mock.size() + 16));
    std::memcpy(gtc, gtc_mock.data(), gtc_mock.size());
    std::memcpy(region + kFtRva, &gtc, 8);

    if (m.imp) {
        std::snprintf(text, sizeof(text), kMockVpAsm, ull(reinterpret_cast<uintptr_t>(sc)));
        const std::vector<u8> vp_mock = assemble64(text, "mock_vp");
        u8* vp = static_cast<u8*>(alloc_rw_x(vp_mock.size() + 16));
        std::memcpy(vp, vp_mock.data(), vp_mock.size());
        const u64 vp_slot_va = base + kMirrorRva + (imp.vp_slot_rva - imp.iat_base_rva);
        std::memcpy(region + kMirrorRva, &vp, 8);
        std::memcpy(region + kMirrorRva + 8, &gtc, 8);
        reportf("vp_slot_va=0x%llX\n", ull(vp_slot_va));
        reportf("vp_mock=0x%llX\n", ull(reinterpret_cast<uintptr_t>(vp)));
        reportf("orig_slot_before=0x%llX\n", ull(load64(region + kFtRva)));
    }

    std::snprintf(text, sizeof(text), kThunkAsm, ull(reinterpret_cast<uintptr_t>(sc)),
                  ull(cb_va), ull(reinterpret_cast<uintptr_t>(sc)));
    const std::vector<u8> thunk_bytes = assemble64(text, "thunk");
    u8* thunk = static_cast<u8*>(alloc_rw_x(thunk_bytes.size() + 16));
    std::memcpy(thunk, thunk_bytes.data(), thunk_bytes.size());
    reportf("thunk_lo=0x%llX\n", ull(reinterpret_cast<uintptr_t>(thunk)));
    reportf("thunk_hi=0x%llX\n",
            ull(reinterpret_cast<uintptr_t>(thunk) + thunk_bytes.size()));
    reportf("gtc_mock=0x%llX\n", ull(reinterpret_cast<uintptr_t>(gtc)));

    AddVectoredExceptionHandler(1, veh);
    reinterpret_cast<void (*)()>(thunk)();
    RemoveVectoredExceptionHandler(veh);

    const u64 h = scratch_at(sc, kScCallRsp);
    const u64 mm = scratch_at(sc, kScMockRsp);
    reportf("H=0x%llX\n", ull(h));
    reportf("M=0x%llX\n", ull(mm));
    reportf("gap=0x%llX\n", ull(h - mm));
    reportf("h_mod16=%llu\n", ull(h % 16));
    reportf("m_mod16=%llu\n", ull(mm % 16));
    reportf("post_rsp=0x%llX\n", ull(scratch_at(sc, kScPostRsp)));
    reportf("post_eq_h=%llu\n", ull(scratch_at(sc, kScPostRsp) == h ? 1 : 0));
    reportf("returned=%llu\n", ull(scratch_at(sc, kScReturned)));
    reportf("cb_ret=0x%llX\n", ull(scratch_at(sc, kScCbRet)));
    reportf("gtc_calls=%llu\n", ull(scratch_at(sc, kScGtcCalls)));
    reportf("gtc_poison=%llu\n", ull(scratch_at(sc, kScGtcPoison)));
    reportf("save08=0x%llX\n", ull(scratch_at(sc, kScSave08)));
    reportf("save10=0x%llX\n", ull(scratch_at(sc, kScSave10)));
    reportf("save18=0x%llX\n", ull(scratch_at(sc, kScSave18)));
    reportf("save20=0x%llX\n", ull(scratch_at(sc, kScSave20)));
    reportf("vp_calls=%llu\n", ull(scratch_at(sc, kScVpCalls)));
    reportf("vp_poison=%llu\n", ull(scratch_at(sc, kScVpPoison)));
    reportf("vp_m=0x%llX\n", ull(scratch_at(sc, kScVpMockRsp)));
    reportf("vp_save10=0x%llX\n", ull(scratch_at(sc, kScVpSave10)));
    if (m.imp) {
        reportf("orig_slot_after=0x%llX\n", ull(load64(region + kFtRva)));
        reportf("orig_slot1_after=0x%llX\n", ull(load64(region + kFtRva + 8)));
        reportf("oldprot=0x%llX\n", ull(*reinterpret_cast<u32*>(region + kOldprotRva)));
    }
    reportf("completed=1\n");
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: %s <mode> <readings-file>\n", argv[0]);
        return 2;
    }
    const std::string mode = argv[1];
    const Mode* found = nullptr;
    for (const auto& m : kModes) {
        if (mode == m.name) found = &m;
    }
    if (found == nullptr) {
        std::fprintf(stderr, "unknown mode %s\n", mode.c_str());
        return 2;
    }
    g_out = CreateFileA(argv[2], GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (g_out == INVALID_HANDLE_VALUE) return 2;

    int rc = 2;
    try {
        u8* region = static_cast<u8*>(alloc_rw_x(kRegionBytes));
        const u64 base = static_cast<u64>(reinterpret_cast<uintptr_t>(region));
        const std::vector<u8> image = build_image(base);
        rc = probe_main(*found, image, base, region);
    } catch (const std::exception& e) {
        reportf("probe_exception=%s\n", e.what());
        rc = 4;
    }
    reportf("probe_rc=%d\n", rc);
    if (g_out != INVALID_HANDLE_VALUE) CloseHandle(g_out);
    return rc;
}
