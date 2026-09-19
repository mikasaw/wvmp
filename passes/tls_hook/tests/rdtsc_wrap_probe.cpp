// MIT-527 (CR-05)：x64 rdtsc 计时面「注入时间戳」真执行探针（测试夹具，非产品码）。
//
// 形态：跑真实的 TlsHookPass（只开 kTimingRdtsc 位面）产出 .wvmpc 回调桩字节
// → 连同 .wvmp 一起镜像进一块 RWX 内存（VA = 合成 image_base ⇒ plan->callback_va
// 就是加载器会跳的那个地址）→ 把桩里两处 rdtsc 指令字节 `0F 31` 原地换成
// `CC 90`（等长 2 字节 ⇒ 桩内所有偏移/相对跳转不动）→ 由 VEH 在断点现场把
// 本例指定的 EDX:EAX 写进 ContextRecord，当作这一次 rdtsc 的返回值。
//
// 为什么要注入而不是"真等 TSC 回绕"：被测的是**两读数之差怎么组合与比较**，
// 缺陷形态（x64 丢 EDX）只在低 32 位跨进位时才咬人，真机等不到那个时刻。
// 注入只替换时间戳这个不可控输入源；`shl/or/mov/sub/cmp/ja/jmp` 与 FailFast
// 红线全是真实发射码，在真 CPU 上执行。
//
// 判据物理量（逐行 flush 写进 readings，由 test_rdtsc_wrap.cpp 断言）：
//   r11_at_second_sample = open 段真实存进 r11 的第一读数（修前 = 只有低 32 位）
//   delta_at_cmp         = close 段算出的差值，在 `48 3D`（cmp rax,imm32）指令
//                          边界用 TF 单步从 ContextRecord.Rax 读回 ⇒ 是代码算出来
//                          的值，不是夹具侧的纸面算术
//   cmp_imm              = 同一现场从字节里读出的阈值立即数（把 kRdtscThresholdCycles
//                          与发射码钉在一起，常量漂了这里立刻炸）
//   decision             = pass（桩正常返回）/ timeout（撞 FailFast 写零红线）
//
// 进程隔离：timeout 判定走的是 `xor eax,eax; mov [rax],0` 的受控 AV，asm 帧无
// unwind 信息 ⇒ 测试进程内 __try 不可靠，故本探针独立成 exe，gtest 侧只看子
// 进程退出码 + readings。

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "wvmp/passes/tls_hook/tls_hook_pass.hpp"
#include "wvmp/passes/tls_hook/tls_plan.hpp"
#include "wvmp/passes/anti_debug/anti_debug_plan.hpp"
#include "wvmp/passes/pe_loader/pe_image.hpp"
#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"

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

// —— 合成镜像布局（.text：RVA 0x1000 ↔ 文件 0x400；.wvmp RW / .wvmpc RX）——
constexpr size_t kNt = 0x80;
constexpr size_t kOpt = kNt + 24;
constexpr u32 kTextRva = 0x1000;
constexpr u32 kTextRaw = 0x400;
constexpr u32 kDataRva = 0x2000;
constexpr u32 kCodeRva = 0x3000;
constexpr size_t kRegionBytes = 0x6000;

// 与产品侧单一来源常量同值（tls_hook_pass.cpp kRdtscThresholdCycles）。
// 不导出、不引头 ⇒ 由 cmp_imm 读数在运行时对账（见 probe_main 末段）。
constexpr u64 kThreshold = 0x7A120;  // = 500000 周期

// rdtsc 操作码与它的等长断点替身。
constexpr u8 kRdtscOp[2] = {0x0F, 0x31};
constexpr u8 kBpSled[2] = {0xCC, 0x90};

// `cmp rax, imm32` 的指令首两字节 = 计时判定比较的锚点。
constexpr u8 kCmpRaxImm32[2] = {0x48, 0x3D};

constexpr int kMaxTraceSteps = 40;
constexpr u64 kNotReached = 0xDEAD'BEEFull;

// 一次 rdtsc 的返回值 = EDX:EAX 一对 dword。
struct Stamp {
    u32 hi;
    u32 lo;
};
u64 full(const Stamp& s) { return (u64(s.hi) << 32) | s.lo; }

// 六组进位边界（判据 1）。truth 只作回显对照，真断言取真机读数。
struct Case {
    const char* name;
    Stamp t1;
    Stamp t2;
    const char* note;
};
constexpr Case kCases[] = {
    // 对照组：无进位、差值远小于阈值 ⇒ 修前修后判定与差值都相同。
    {"normal_small", {0x0u, 0x00001000u}, {0x0u, 0x00001200u}, "无进位小差值"},
    // 判据 1 点名的回绕例：真实差 0x20，修前算成 0xFFFFFFFF00000020。
    {"wrap_low32", {0x1u, 0xFFFFFFF0u}, {0x2u, 0x00000010u}, "低 32 位回绕（单次进位）"},
    // 低 32 位回绕 + 高位跨 3 次进位：真差 0x300000200 = 必超阈。
    {"multi_carry", {0x5u, 0xFFFFFF00u}, {0x9u, 0x00000100u}, "跨多次进位"},
    // 恰好等于阈值：`ja` 不成立 ⇒ 判定 = 不超时（与 x86 侧同语义）。
    {"eq_threshold", {0x7u, 0x00000000u}, {0x7u, u32(kThreshold)}, "差值 == 阈值"},
    // 阈值 +1：反向钉，防"一律放行"式假修。
    {"threshold_plus_one", {0x7u, 0x00000000u}, {0x7u, u32(kThreshold) + 1u}, "差值 == 阈值+1"},
    // 低 32 位不回绕、高位跨 8 次进位：真差 0x800001000 必超阈，修前算成 0x1000 ⇒ 漏报。
    {"hi_jump_no_low_wrap", {0x1u, 0x00001000u}, {0x9u, 0x00002000u}, "高位大跳（漏报面）"},
};

HANDLE g_out = INVALID_HANDLE_VALUE;
u64 g_cb = 0;
size_t g_stub_size = 0;
u64 g_site[2] = {0, 0};
Stamp g_stamp[2] = {};

// 真机读回的判据量。
int g_sample_hits = 0;
u64 g_r11_at_s2 = kNotReached;
u64 g_rax_at_s2 = kNotReached;
u64 g_rdx_at_s2 = kNotReached;
int g_steps = 0;
int g_anchor_seen = 0;
u64 g_delta_at_cmp = kNotReached;
u64 g_r11_at_cmp = kNotReached;
u64 g_rdx_at_cmp = kNotReached;
u64 g_flags_at_cmp = 0;
u32 g_cmp_imm = 0;

unsigned long long ull(u64 v) { return static_cast<unsigned long long>(v); }

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

void hex_dump(const char* tag, const u8* p, size_t n) {
    for (size_t i = 0; i < n; i += 32) {
        char hex[3 * 32 + 4] = {0};
        int at = 0;
        for (size_t j = i; j < i + 32 && j < n; ++j)
            at += std::snprintf(hex + at, sizeof(hex) - at, "%02X ", p[j]);
        reportf("%s[%03zX]=%s\n", tag, i, hex);
    }
}

bool in_stub_range(u64 addr) {
    return g_cb != 0 && g_stub_size != 0 && addr >= g_cb && addr < g_cb + g_stub_size;
}

// 断点现场把本例时间戳写进 EDX:EAX（rdtsc 的架构语义：写 32 位寄存器 ⇒ 高
// 32 位清零，所以这里必须只给低 32 位有效值，不能直接把 64 位全值塞 RAX）。
void inject_sample(CONTEXT* cr, int which) {
    cr->Rax = u64(g_stamp[which].lo);
    cr->Rdx = u64(g_stamp[which].hi);
    cr->Rip += 1;  // 越过 CC（int3 长 1 字节），后随 90 = nop
    reportf("sample_injected=%d stamp=0x%llX hi=0x%llX lo=0x%llX\n", which + 1,
            ull(full(g_stamp[which])), ull(g_stamp[which].hi), ull(g_stamp[which].lo));
}

LONG WINAPI veh(EXCEPTION_POINTERS* ep) {
    CONTEXT* cr = ep->ContextRecord;
    const DWORD code = ep->ExceptionRecord->ExceptionCode;

    if (code == EXCEPTION_BREAKPOINT) {
        for (int i = 0; i < 2; ++i) {
            if (g_site[i] == 0 || cr->Rip != g_site[i]) continue;
            if (g_sample_hits != i) break;  // 重复命中：交给下面的兜底
            if (i == 1) {
                // open 段跑完后的 r11 = 它真实存下的第一读数（缺陷本体在这里现形）。
                g_r11_at_s2 = cr->R11;
                g_rax_at_s2 = cr->Rax;
                g_rdx_at_s2 = cr->Rdx;
            }
            inject_sample(cr, i);
            ++g_sample_hits;
            if (i == 1) {
                reportf("r11_at_second_sample=0x%llX\n", ull(g_r11_at_s2));
                reportf("rax_at_second_sample=0x%llX\n", ull(g_rax_at_s2));
                reportf("rdx_at_second_sample=0x%llX\n", ull(g_rdx_at_s2));
                // TF：单步到判定比较处，从真机上下文取回代码算出的差值。
                cr->EFlags |= u64(0x100);
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        reportf("unexpected_bp_rip=0x%llX\n", ull(cr->Rip));
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (code == EXCEPTION_SINGLE_STEP) {
        ++g_steps;
        if (!in_stub_range(cr->Rip) || g_steps > kMaxTraceSteps || g_anchor_seen != 0) {
            cr->EFlags &= ~u64(0x100);  // 出窗 / 步数封顶 / 已取到差值 ⇒ 停止单步
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        const u8* p = reinterpret_cast<const u8*>(cr->Rip);
        reportf("step %02d rip_off=0x%llX bytes=%02X %02X %02X rax=0x%llX rdx=0x%llX r11=0x%llX\n",
                g_steps, ull(cr->Rip - g_cb), p[0], p[1], p[2], ull(cr->Rax),
                ull(cr->Rdx), ull(cr->R11));
        if (p[0] == kCmpRaxImm32[0] && p[1] == kCmpRaxImm32[1]) {
            g_anchor_seen = 1;
            g_delta_at_cmp = cr->Rax;
            g_r11_at_cmp = cr->R11;
            g_rdx_at_cmp = cr->Rdx;
            g_flags_at_cmp = cr->EFlags;
            std::memcpy(&g_cmp_imm, p + 2, sizeof(g_cmp_imm));
            // 判定前最后一站：差值/操作数/立即数逐行落盘（timeout 路径进程随后
            // 就死了，读数必须在现场写）。
            reportf("anchor_seen=1\n");
            reportf("delta_at_cmp=0x%llX\n", ull(g_delta_at_cmp));
            reportf("r11_at_cmp=0x%llX\n", ull(g_r11_at_cmp));
            reportf("rdx_at_cmp=0x%llX\n", ull(g_rdx_at_cmp));
            reportf("flags_at_cmp=0x%llX\n", ull(g_flags_at_cmp));
            reportf("cmp_imm=0x%llX\n", ull(g_cmp_imm));
            cr->EFlags &= ~u64(0x100);  // 判定与后续分支照常真跑
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        cr->EFlags |= u64(0x100);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // 其余异常 = 撞了 FailFast 写零红线（或桩内非预期崩溃）：现场取证。
    const ULONG_PTR* info = ep->ExceptionRecord->ExceptionInformation;
    reportf("fault_code=0x%08X\n", static_cast<u32>(ep->ExceptionRecord->ExceptionCode));
    reportf("fault_dir=%llu\n", ull(static_cast<u64>(info[0])));
    reportf("fault_addr=0x%llX\n", ull(static_cast<u64>(info[1])));
    reportf("fault_rip=0x%llX\n", ull(cr->Rip));
    if (in_stub_range(cr->Rip)) {
        reportf("fault_rip_stub_off=0x%llX\n", ull(cr->Rip - g_cb));
        if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
            info[1] == 0 && g_sample_hits == 2 && g_anchor_seen != 0) {
            // 两采样都注入过 + 判定比较已走过 + 写地址 0 = 计时判据判为超阈。
            reportf("decision=timeout\n");
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// 合成 PE32+ 镜像：只要头 + 单 .text。本探针不开 DRx / 回填面 ⇒ 不需要导入表。
std::vector<u8> build_image(u64 base) {
    constexpr size_t kOptSize = 240;
    const size_t table = kOpt + kOptSize;
    std::vector<u8> img(table + 40 + 0x800, 0);
    auto wr = [&](size_t off, u64 v, size_t w) {
        for (size_t i = 0; i < w; ++i) img[off + i] = u8((v >> (8 * i)) & 0xFF);
    };
    img[0] = 'M';
    img[1] = 'Z';
    wr(0x3C, kNt, 4);
    img[kNt] = 'P';
    img[kNt + 1] = 'E';
    wr(kNt + 4, 0x8664, 2);          // Machine
    wr(kNt + 6, 1, 2);               // NumberOfSections
    wr(kNt + 20, kOptSize, 2);       // SizeOfOptionalHeader
    wr(kNt + 22, 0x0022, 2);         // Characteristics
    wr(kOpt, 0x020B, 2);             // Magic = PE32+
    wr(kOpt + 16, 0x1000, 4);        // SectionAlignment
    wr(kOpt + 20, 0x200, 4);         // FileAlignment
    wr(kOpt + 24, base, 8);          // ImageBase
    wr(kOpt + 56, 0x6000, 4);        // SizeOfImage
    wr(kOpt + 60, 0x200, 4);         // SizeOfHeaders
    wr(kOpt + 108, 16, 4);           // NumberOfRvaAndSizes
    std::memcpy(&img[table], ".text", 5);
    wr(table + 8, 0x800, 4);         // VirtualSize
    wr(table + 12, kTextRva, 4);     // VirtualAddress
    wr(table + 16, 0x800, 4);        // SizeOfRawData
    wr(table + 20, kTextRaw, 4);     // PointerToRawData
    wr(table + 36, 0x60000020, 4);   // Characteristics
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

void* alloc_rwx(size_t bytes) {
    void* p = VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT,
                           PAGE_EXECUTE_READWRITE);
    if (p == nullptr) throw std::runtime_error("probe: VirtualAlloc(RWX) failed");
    std::memset(p, 0, bytes);
    return p;
}

// 在桩字节里找 rdtsc 指令。只认精确 2 字节序列；命中数必须恰为 2（open +
// close 各一处），多一处就说明锚点定位不可信，直接失败而不是硬跑。
std::vector<size_t> find_rdtsc_sites(const std::vector<u8>& stub) {
    std::vector<size_t> sites;
    for (size_t i = 0; i + 2 <= stub.size(); ++i)
        if (stub[i] == kRdtscOp[0] && stub[i + 1] == kRdtscOp[1]) sites.push_back(i);
    return sites;
}

int probe_main(const Case& c, u8* region, u64 base) {
    ProtectionContext ctx;
    ctx.image = build_image(base);
    ctx.slot<PeImage>(kPeImage) = build_meta(base);

    NewSection d;
    d.name = ".wvmp";
    d.data.assign(16, 0);
    d.characteristics = 0xC0000040u;
    d.requested_rva = kDataRva;
    NewSection cc;
    cc.name = ".wvmpc";
    cc.data.assign(16, 0);
    cc.characteristics = 0x60000020u;
    cc.requested_rva = kCodeRva;
    auto& secs = ctx.slot<std::vector<NewSection>>(kNewSections);
    secs.push_back(d);
    secs.push_back(cc);

    // 只开计时面：PEB 位（bit0/1）不开（探针被调试器附加时会先撞 FailFast 把
    // 读数搅浑），DRx 位（bit2）不开（不产生 call 站点，rdtsc 窗与 ABI 面解耦）。
    wvmp::passes::anti_debug::AntiDebugPlan adb;
    adb.techniques = wvmp::passes::anti_debug::tech::kTimingRdtsc;
    adb.init_techniques = adb.techniques;
    ctx.slot<wvmp::passes::anti_debug::AntiDebugPlan>(kAntiDebugPlan) = adb;

    TlsHookPass pass;
    pass.run(ctx);

    const auto* plan = ctx.find_slot<tls_hook::TlsPlan>(kTlsPlan);
    const NewSection* ds = nullptr;
    const NewSection* cs = nullptr;
    for (const auto& s : ctx.slot<std::vector<NewSection>>(kNewSections)) {
        if (s.name == ".wvmp") ds = &s;
        if (s.name == ".wvmpc") cs = &s;
    }
    if (plan == nullptr || ds == nullptr || cs == nullptr) {
        reportf("probe_fail=plan_or_sections_missing\n");
        return 3;
    }

    std::memcpy(region + kDataRva, ds->data.data(), ds->data.size());
    std::memcpy(region + kCodeRva, cs->data.data(), cs->data.size());

    const auto cb_off = static_cast<size_t>(plan->callback_rva - kCodeRva);
    std::vector<u8> stub;
    stub.assign(cs->data.begin() + static_cast<std::ptrdiff_t>(cb_off), cs->data.end());

    const std::vector<size_t> sites = find_rdtsc_sites(stub);
    reportf("case=%s\n", c.name);
    reportf("note=%s\n", c.note);
    reportf("t1=0x%llX\n", ull(full(c.t1)));
    reportf("t2=0x%llX\n", ull(full(c.t2)));
    reportf("truth_delta=0x%llX\n", ull(full(c.t2) - full(c.t1)));
    reportf("truth_delta_dec=%llu\n", ull(full(c.t2) - full(c.t1)));
    reportf("threshold=0x%llX\n", ull(kThreshold));
    reportf("cb_va=0x%llX\n", ull(plan->callback_va));
    reportf("stub_size=%d\n", int(stub.size()));
    hex_dump("stub", stub.data(), stub.size());
    if (sites.size() != 2) {
        reportf("probe_fail=rdtsc_sites=%d\n", int(sites.size()));
        return 4;
    }
    reportf("rdtsc_site_off0=0x%llX\n", ull(sites[0]));
    reportf("rdtsc_site_off1=0x%llX\n", ull(sites[1]));
    // 等长替换：0F 31 → CC 90（int3 + nop）。
    for (size_t i = 0; i < 2; ++i) {
        std::memcpy(&stub[sites[i]], kBpSled, 2);
        g_site[i] = plan->callback_va + sites[i];
    }
    g_stamp[0] = c.t1;
    g_stamp[1] = c.t2;
    g_cb = plan->callback_va;
    g_stub_size = stub.size();
    std::memcpy(region + plan->callback_rva, stub.data(), stub.size());
    hex_dump("stub_patched", stub.data(), stub.size());

    AddVectoredExceptionHandler(1, veh);
    reinterpret_cast<void (*)()>(g_cb)();
    RemoveVectoredExceptionHandler(veh);

    reportf("returned=1\n");
    reportf("decision=pass\n");
    reportf("completed=1\n");
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: %s <case> <readings-file>\n", argv[0]);
        return 2;
    }
    const std::string name = argv[1];
    const Case* found = nullptr;
    for (const auto& c : kCases)
        if (name == c.name) found = &c;
    if (found == nullptr) {
        std::fprintf(stderr, "unknown case %s\n", name.c_str());
        return 2;
    }
    g_out = CreateFileA(argv[2], GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (g_out == INVALID_HANDLE_VALUE) return 2;

    int rc = 2;
    try {
        u8* region = static_cast<u8*>(alloc_rwx(kRegionBytes));
        const u64 base = static_cast<u64>(reinterpret_cast<uintptr_t>(region));
        rc = probe_main(*found, region, base);
    } catch (const std::exception& e) {
        reportf("probe_exception=%s\n", e.what());
        rc = 5;
    }
    reportf("sample_hits=%d\n", g_sample_hits);
    reportf("trace_steps=%d\n", g_steps);
    reportf("probe_rc=%d\n", rc);
    if (g_out != INVALID_HANDLE_VALUE) CloseHandle(g_out);
    return rc;
}
