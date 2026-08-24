#include "wvmp/passes/stub_link/stub_link_pass.hpp"

#include "stub_gen.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/diagnostics.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/registry.hpp"
#include "wvmp/passes/pe_loader/pe_image.hpp"
#include "wvmp/passes/virtualize/virtualize_pass.hpp"
#include "wvmp/regvm/runtime/runtime.hpp"
#include "wvmp/vm/backend.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

namespace wvmp::passes {
namespace {

u64 align_up(u64 v, u64 a) { return a == 0 ? v : ((v + a - 1) / a) * a; }

// RWX + 已初始化数据：解释器/字节码/stub 同节共存，v1 不做 W^X 分离。
constexpr u32 kWvmpChars = 0xE000'0040;

} // namespace

std::span<const std::string_view> StubLinkPass::requires_keys() const {
    static constexpr std::string_view kRequires[] = {kVmProgram, kPeImage, kImage};
    return kRequires;
}

std::span<const std::string_view> StubLinkPass::provides_keys() const {
    static constexpr std::string_view kProvides[] = {kNewSections};
    return kProvides;
}

// .wvmp 节内布局（RVA 坐标，全部位置无关）：
//
//   [解释器机器码（16 对齐）]
//   [fn0 blob（8 对齐）][fn0 stub（16 对齐）]
//   [fn1 blob][fn1 stub] ...
//
//   - stub_i 经 .text 入口覆写（E9 rel32，RVA 差）进入：保存现场 → 栈上
//     VmContext（bytecode=blob 指令流、pc=0、scratch=0、v16 GP 预载）→
//     call 解释器入口 → HALT 后回写易失寄存器 → 恢复 → jmp 回 end_rva；
//   - 对外引用仅两类（均为 RVA 相对，随基址平移自洽）：.text→stub 的 E9、
//     stub→.text 的 resume jmp；节内 blob 指针为 rip 相对（回填）。
void StubLinkPass::run(ProtectionContext& ctx) {
    const auto* vfs = ctx.find_slot<std::vector<VirtualizedFunction>>(kVmProgram);
    if (vfs == nullptr || vfs->empty()) {
        ctx.diag.report(Severity::Warning, name(), "无已虚拟化函数，跳过 stub 生成");
        return;
    }
    const PeImage* pe = ctx.find_slot<PeImage>(kPeImage);
    if (pe == nullptr) {
        ctx.diag.report(Severity::Error, name(), "PeImage 模型缺失，无法定位覆写点");
        throw std::runtime_error(std::string(name()) + ": pe image model missing");
    }

    // 共享解释器（寄存器分配随机化走 ctx.rng）。
    const regvm::runtime::RuntimeGenResult rt = regvm::runtime::generate_runtime(ctx.rng);

    // 新节 RVA：既有节虚拟末端之后按 SectionAlignment 对齐。
    u64 sec_align = pe->section_alignment != 0 ? pe->section_alignment : 0x1000;
    u64 max_end = 0x1000;
    for (const auto& s : pe->sections)
        max_end = std::max<u64>(max_end, align_up(u64(s.virtual_addr) + std::max(s.virtual_size, s.raw_size), sec_align));
    const u64 section_rva = align_up(max_end, sec_align);

    // —— 布局与装配 ——
    std::vector<u8> payload;
    payload.reserve(rt.image.code.size() + vfs->size() * 256);
    payload.insert(payload.end(), rt.image.code.begin(), rt.image.code.end());
    payload.resize(static_cast<size_t>(align_up(payload.size(), 16)), 0);
    const u64 rt_entry = section_rva;  // 解释器入口 = 节基址（vm_entry_offset=0）

    struct Patch {
        u64 begin_rva, end_rva, stub_rva;
    };
    std::vector<Patch> patches;

    for (const auto& vf : *vfs) {
        // blob：VmProgram.bytecode 已是 32B 头 + 8xN 流的完整序列化。
        const u64 blob_off = align_up(payload.size(), 8);
        payload.resize(static_cast<size_t>(blob_off), 0);
        payload.insert(payload.end(), vf.program.bytecode.begin(), vf.program.bytecode.end());
        const u64 blob_stream_rva = section_rva + blob_off + 32;  // 跳过 blob 头

        const u64 stub_off = align_up(payload.size(), 16);
        payload.resize(static_cast<size_t>(stub_off), 0);
        const u64 stub_rva = section_rva + stub_off;
        std::vector<u8> stub;
        try {
            // image_base（PE optional header 的 ImageBase）写入 VmContext 的
            // scratch_mem 槽：运行时 Load/Store/Push/Pop 的访存汇编即
            // `[addr + image_base]`. 翻译期算的 RVA（rip-relative 转绝对）
            // + 此基址 = 实际 VA. ASLR 下基址变化不影响 RVA, 槽值不变.
            stub = generate_entry_stub(stub_rva, blob_stream_rva, rt_entry, vf.end_rva,
                                       pe->image_base);
        } catch (const std::exception& e) {
            ctx.diag.report(Severity::Error, name(),
                            "函数 " + vf.name + " stub 生成失败（保持原生）: " + e.what());
            continue;
        }
        payload.insert(payload.end(), stub.begin(), stub.end());
        patches.push_back({vf.begin_rva, vf.end_rva, stub_rva});
    }

    // —— .text 入口覆写（E9 rel32 + INT3 填充区域余量）——
    for (const auto& p : patches) {
        const auto begin_off = pe->rva_to_offset(p.begin_rva);
        const auto end_off = pe->rva_to_offset(p.end_rva);
        if (!begin_off.has_value() || !end_off.has_value()) {
            ctx.diag.report(Severity::Error, name(),
                            "区域 RVA 无法映射到文件偏移（begin=0x" +
                                std::to_string(p.begin_rva) + "），保持原生");
            continue;
        }
        const i64 region_len = static_cast<i64>(*end_off) - static_cast<i64>(*begin_off);
        if (region_len < 5) {
            ctx.diag.report(Severity::Error, name(),
                            "区域长度不足 5 字节，无法写入跳转，保持原生");
            continue;
        }
        const i64 rel = static_cast<i64>(p.stub_rva) -
                        (static_cast<i64>(p.begin_rva) + 5);
        if (rel < -0x8000'0000LL || rel > 0x7FFF'FFFFLL) {
            ctx.diag.report(Severity::Error, name(), "跳转距离超出 rel32，保持原生");
            continue;
        }
        u8* code = ctx.image.data() + *begin_off;
        code[0] = 0xE9;
        const u32 rel_u = static_cast<u32>(rel);
        for (int b = 0; b < 4; ++b)
            code[1 + b] = u8((rel_u >> (8 * b)) & 0xFF);
        for (i64 i = 5; i < region_len; ++i) code[i] = 0xCC;
    }

    // —— 新节请求交给 pe_writer ——
    NewSection req;
    req.name = ".wvmp";
    req.data = std::move(payload);
    req.characteristics = kWvmpChars;
    req.requested_rva = static_cast<u32>(section_rva);
    const size_t payload_size = req.data.size();
    ctx.slot<std::vector<NewSection>>(kNewSections).push_back(std::move(req));

    char rva_buf[24];
    std::snprintf(rva_buf, sizeof(rva_buf), "%llX",
                  static_cast<unsigned long long>(section_rva));
    ctx.diag.report(Severity::Note, name(),
                    "已生成 " + std::to_string(patches.size()) + " 个入口 stub，.wvmp 节 " +
                        std::to_string(payload_size) + " 字节 @ RVA 0x" + rva_buf);
}

WVMP_REGISTER_PASS(StubLinkPass)

} // namespace wvmp::passes
