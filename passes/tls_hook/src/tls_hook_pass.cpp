#include "wvmp/passes/tls_hook/tls_hook_pass.hpp"

#include "wvmp/passes/tls_hook/tls_plan.hpp"

#include "wvmp/passes/import_protect/import_plan.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
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

// TLS 回调体装配：
//   - imp == nullptr：v1 占位（清返回值立即返回；x86 stdcall ret 0Ch 自清
//     12B 栈参）。
//   - imp != nullptr（MIT-466）：IAT 回填——原 IAT 页已被 loader 重新只读
//     保护，先 VirtualProtect（经其 IAT 槽调用，此时导入解析已完成）解除
//     写保护 → rep movs 把 .wvmp 镜像整段回填原 .rdata IAT 区 → 按保存值
//     恢复保护 → 占位收尾。绝对立即数 = image_base + RVA（本机非 ASLR
//     约定，与 stub 链一致）。DF=0 为 ABI 既有约定。
std::vector<u8> assemble_callback_stub(bool is_x86,
                                       const import_protect::ImportPlan* imp,
                                       u64 image_base) {
    ks_engine* ks = nullptr;
    if (ks_open(KS_ARCH_X86, is_x86 ? KS_MODE_32 : KS_MODE_64, &ks) != KS_ERR_OK)
        throw std::runtime_error("tls_hook: ks_open failed");
    ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_INTEL);
    char src[640];
    if (imp == nullptr) {
        std::snprintf(src, sizeof(src), "%s",
                      is_x86 ? "xor eax, eax\nret 0Ch" : "xor eax, eax\nret");
    } else {
        const u64 mirror_va = image_base + imp->mirror_rva;
        const u64 orig_va = image_base + imp->iat_base_rva;
        const u64 page_va = image_base + imp->page_rva;
        const u64 oldprot_va = image_base + imp->oldprot_rva;
        // VirtualProtect 调用走「镜像中对应槽」：loader 只解析镜像（dd1 已
        // 重指），原 IAT 槽仍是文件残值（hint RVA），直接调用必跳飞。
        const u64 vp_iat_va =
            image_base + imp->mirror_rva + (imp->vp_slot_rva - imp->iat_base_rva);
        if (is_x86) {
            // x86：绝对内存立即数可直接编码；VirtualProtect = stdcall。
            // esi/edi 为 callee-saved（被 rep movsd 使用），必须保存/恢复，
            // 否则破坏 loader 回调链状态（实测：数组第 2 项不再被调用）。
            std::snprintf(src, sizeof(src),
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
        } else {
            // x64：VirtualProtect(rcx=addr, rdx=size, r8d=new, r9=&old)，
            // 槽地址经 rax 间接调用；恢复时旧保护值经 r10 读出。rsi/rdi 为
            // callee-saved（x64 ABI），回填前后必须保存/恢复。回调自身作为
            // 调用方需提供 32B shadow space（push×2 + sub 0x28 = 0x38：
            // 入口 rsp≡8 mod 16 → 8-0x38 ≡ 0 对齐保持）。
            std::snprintf(src, sizeof(src),
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
        }
    }
    unsigned char* enc = nullptr;
    size_t size = 0, count = 0;
    const int rc = ks_asm(ks, src, 0, &enc, &size, &count);
    std::vector<u8> out;
    if (rc == KS_ERR_OK && enc != nullptr && size > 0)
        out.assign(enc, enc + size);
    const ks_err err = ks_errno(ks);
    if (enc) ks_free(enc);
    ks_close(ks);
    if (out.empty())
        throw std::runtime_error("tls_hook: ks_asm failed errno=" +
                                 std::to_string(int(err)));
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
    // .wvmp 节（stub_link 产出）缺席 = 无可挂靠内容 → 空转（镜像零改动）。
    NewSection* wvmp = nullptr;
    if (auto* sections = ctx.find_slot<std::vector<NewSection>>(kNewSections))
        for (auto& s : *sections)
            if (s.name == ".wvmp") { wvmp = &s; break; }
    if (wvmp == nullptr) {
        ctx.diag.report(Severity::Note, name(),
                        "无 .wvmp 节（stub_link 未产出），跳过 TLS 回调基建");
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

    // —— .wvmp 尾部追加布局：[回调桩 16 对齐][index 槽 8][回调数组 8][TLS 目录 8] ——
    // MIT-466：kImportPlan 在场（import_protect 先行）时回调体携带 IAT
    // 回填循环；槽缺席 = v1 占位体。
    const auto* imp = ctx.find_slot<import_protect::ImportPlan>(kImportPlan);
    const std::vector<u8> stub =
        assemble_callback_stub(is_x86, (imp != nullptr && imp->active) ? imp : nullptr,
                               pe->image_base);
    const u64 cb_off = align_up(wvmp->data.size(), 16);
    const u64 idx_off = align_up(cb_off + stub.size(), 8);
    const OriginalTls orig = read_original_tls(ctx, *pe);
    const u64 array_off = align_up(idx_off + 8, 8);
    const u64 dir_off = align_up(array_off + (2 + orig.callbacks.size()) * ptr_w, 8);

    const u64 cb_rva = sec_rva + cb_off;
    const u64 cb_va = base + cb_rva;
    const u64 idx_va = base + sec_rva + idx_off;
    const u64 array_rva = sec_rva + array_off;
    const u64 array_va = base + array_rva;
    const u64 dir_rva = sec_rva + dir_off;
    const u32 dir_size = plus ? 40u : 24u;

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

    wvmp->data.resize(static_cast<size_t>(cb_off), 0);
    wvmp->data.insert(wvmp->data.end(), stub.begin(), stub.end());
    wvmp->data.resize(static_cast<size_t>(idx_off), 0);
    append_le(wvmp->data, 0, 8);  // index 槽（加载器写 TLS slot index）
    wvmp->data.resize(static_cast<size_t>(array_off), 0);
    wvmp->data.insert(wvmp->data.end(), array_bytes.begin(), array_bytes.end());
    wvmp->data.resize(static_cast<size_t>(dir_off), 0);
    append_le(wvmp->data, dir.start, ptr_w);
    append_le(wvmp->data, dir.end, ptr_w);
    append_le(wvmp->data, dir.index, ptr_w);
    append_le(wvmp->data, dir.callbacks, ptr_w);
    append_le(wvmp->data, dir.zero_fill, 4);
    append_le(wvmp->data, dir.characteristics, 4);

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
