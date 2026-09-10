#include "wvmp/passes/stub_link/stub_link_pass.hpp"

#include "stub_gen.hpp"

#include "wvmp/common/bytes.hpp"
#include "wvmp/framework/context.hpp"
#include "wvmp/framework/diagnostics.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/protect_levels.hpp"
#include "wvmp/framework/registry.hpp"
#include "wvmp/passes/pe_loader/pe_image.hpp"
#include "wvmp/passes/virtualize/virtualize_pass.hpp"
#include "wvmp/passes/crypt/crypt_plan.hpp"
#include "wvmp/passes/anti_debug/anti_debug_plan.hpp"
#include "wvmp/regvm/isa/blob.hpp"
#include "wvmp/regvm/isa/encoding.hpp"
#include "wvmp/regvm/runtime/runtime.hpp"
#include "wvmp/regvm/runtime/runtime_x86.hpp"
#include "wvmp/vm/backend.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace wvmp::passes {
namespace {

namespace isa = wvmp::regvm::isa;

u64 align_up(u64 v, u64 a) { return a == 0 ? v : ((v + a - 1) / a) * a; }

// RWX + 已初始化数据：解释器/字节码/stub 同节共存，v1 不做 W^X 分离。
// MIT-472 W^X 拆节后两节特征（单一来源）：
//   .wvmp  数据节 RW  = CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE
//   .wvmpc 代码节 RX  = CNT_CODE | MEM_EXECUTE | MEM_READ
constexpr u32 kWvmpDataChars = 0xC000'0040;
constexpr u32 kWvmpCodeChars = 0x6000'0020;

// IMAGE_FILE_MACHINE_I386（x86 32 位目标）。与 pe_loader/marker_scan 同值
// 独立声明（模块边界，pe_image.cpp 解析白名单为单一语义源）。
constexpr u16 kMachineX86 = 0x014C;

// MIT-446 (X4)：x86 stub_link 白名单 gate —— blob 头 → 逐条解码指令流，
// 返回出现在 x86 运行时跳表缺项的 opcode 列表（去重、保序）。空 = 全部可执行。
// 跳表缺项折叠 Halt 是 C2 类静默错（翻译成功、区域覆写后运行即停），在
// 覆写 .text 前拦成 C1 类显式 gate（整函数保持原生）。opcode 集合单一来源
// = asmgen x86_handler_opcodes()（runtime_x86.hpp 契约），禁第二份清单。
std::vector<int> unsupported_x86_ops(const std::vector<u8>& bytecode) {
    std::vector<int> bad;
    wvmp::ByteReader r{bytecode.data(), bytecode.size()};
    const isa::VmBlob blob = isa::read_blob(r);
    const std::span<const int> allowed =
        wvmp::regvm::runtime::x86_handler_opcodes();
    const size_t n = blob.stream.size() / 8;
    for (size_t i = 0; i < n; ++i) {
        u64 word = 0;
        for (int b = 0; b < 8; ++b)
            word |= u64(blob.stream[i * 8 + b]) << (8 * b);
        const int op = int(isa::decode(word).op);
        if (std::find(allowed.begin(), allowed.end(), op) == allowed.end()) {
            if (bad.empty() || bad.back() != op) bad.push_back(op);
        }
    }
    return bad;
}

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

    // 共享解释器（寄存器分配随机化走 ctx.rng）。MIT-446 (X4) B.1：按
    // PeImage.machine 分叉 arch——x86 目标产出 KS_MODE_32 码体
    // （generate_runtime_x86）+ Win32 cdecl stub；x64 路径逐字节不变。
    const bool is_x86 = pe->machine == kMachineX86;
    // MIT-473: crypt 计划 fetch 模式 → 运行时 dispatch 织入逐指令解密
    //（缺省重载 = 无织入，锚点 dump 恒等）。计划槽查找提前于此（生成参数
    // 需要）；algo 校验仍在后续 crypt 计划块。
    const crypt::CryptPlan* plan = ctx.find_slot<crypt::CryptPlan>(kCryptPlan);
    // fetch_mode 先于 algo 校验消费：CryptPass 是 CryptPlan 唯一写者且恒
    // 置 algo=kAlgoXorChain，故 fetch_mode=true 蕴含 blob 已按位置键流加
    // 密——若未来出现第二写者（algo≠xor_chain 却置 fetch_mode），此处会
    // 织入解密而 blob 明文；届时必须先在此加 algo 断言。
    const bool fetch_mode = plan != nullptr && plan->fetch_mode;
    const regvm::runtime::RuntimeGenResult rt =
        is_x86 ? regvm::runtime::generate_runtime_x86(ctx.rng, fetch_mode)
               : regvm::runtime::generate_runtime(ctx.rng, fetch_mode);

    // 新节 RVA（MIT-472 W^X 拆节）：数据节 .wvmp（RW：字节码 blob 等，
    // 解密期/回填期被写）落既有节末端；代码节 .wvmpc（RX：解释器 + stub，
    // 只执行不写）落数据节末端。blob 尺寸可先验（无需生成 stub）→ 先定
    // d 布局再依序生成 stub，无循环依赖。
    u64 sec_align = pe->section_alignment != 0 ? pe->section_alignment : 0x1000;
    u64 max_end = 0x1000;
    for (const auto& s : pe->sections)
        max_end = std::max<u64>(max_end, align_up(u64(s.virtual_addr) + std::max(s.virtual_size, s.raw_size), sec_align));
    const u64 data_section_rva = align_up(max_end, sec_align);

    // —— 布局与装配 ——
    // 前置 pass（import 镜像 / TLS 数据 / 暂存）也只追加数据节；代码追加
    // .wvmpc。
    std::vector<u8> data_payload;
    std::vector<u8> code_payload;
    code_payload.reserve(rt.image.code.size() + vfs->size() * 256);
    data_payload.reserve(vfs->size() * 512);
    code_payload.insert(code_payload.end(), rt.image.code.begin(), rt.image.code.end());
    code_payload.resize(static_cast<size_t>(align_up(code_payload.size(), 16)), 0);

    struct Patch {
        u64 begin_rva, end_rva, stub_rva;
    };
    std::vector<Patch> patches;

    // MIT-458 (crypt-v1)：加密计划（crypt pass 在 Transform 阶段写入；
    // 槽缺席 = 无加密，全部走明文路径，v1 前行为逐字节不变）。algo 不认识
    // 则整单拒绝加密（保守：宁可明文也不发一个解不开的镜像）。
    if (plan != nullptr && plan->algo != crypt::kAlgoXorChain) {
        ctx.diag.report(Severity::Warning, name(),
                        "crypt plan algo '" + plan->algo + "' 不受支持，忽略加密计划");
        plan = nullptr;
    }

    // MIT-463 (anti_debug-v1)：反调试计划（anti_debug pass 写入；槽缺席 =
    // 无检查块，stub 逐字节 v1 前现形）。
    const anti_debug::AntiDebugPlan* adb_plan =
        ctx.find_slot<anti_debug::AntiDebugPlan>(kAntiDebugPlan);
    const auto plan_of = [&](size_t vfs_index) -> const crypt::CryptedFunction* {
        if (plan == nullptr) return nullptr;
        for (const auto& e : plan->functions)
            if (e.vfs_index == vfs_index) return &e;
        return nullptr;
    };

    // MIT-472 (W^X 拆节) 前置尺寸遍历：先跑 x86 白名单 gate（结果缓存）+
    // 合计 blob 尺寸 → 定位数据节/代码节 RVA（blob 尺寸可先验，无需生成
    // stub，无循环依赖）。

    std::vector<char> gated(vfs->size(), 0);
    std::vector<std::vector<int>> gated_ops(vfs->size());
    u64 data_total = 0;
    for (size_t vfs_index = 0; vfs_index < vfs->size(); ++vfs_index) {
        if (is_x86) {
            const std::vector<int> bad =
                unsupported_x86_ops((*vfs)[vfs_index].program.bytecode);
            if (!bad.empty()) {
                gated[vfs_index] = 1;
                gated_ops[vfs_index] = bad;  // MIT-476: 诊断带 opcode 名（票③）
                continue;
            }
        }
        const crypt::CryptedFunction* crypted = plan_of(vfs_index);
        const size_t blob_size = crypted != nullptr
                                     ? crypted->encrypted_blob.size()
                                     : (*vfs)[vfs_index].program.bytecode.size();
        data_total += static_cast<u64>(align_up(blob_size, 8));
    }
    // MIT-476（票①/②）：后续 Emit pass（import_protect 镜像 IAT/oldprot、
    // tls_hook CONTEXT/rdtsc/TLS 面）向 .wvmp 写入——code_rva 此前按纯
    // blobs 尺寸计算，追加全靠节对齐垫片（≤4KB）吸收，超垫片即
    // "not contiguous" 硬失败；全 gate（零 blob）时数据节为空被
    // add_sections 拒绝。预留 8KB 并随节发射（ emit_reserve_take 协议见
    // pe_image.hpp），节最终尺寸恒定 → 连续性恒成立、数据节恒非空。
    //
    // MIT-494j（T32 复验发现）：pe_writer 的 ASLR reloc 扩展（原目录剪
    // 枝重建 + packer 站点块，dd[5] 重指）也走同一预留区，而固定 8KB 只
    // 覆盖 x64 典型面（wvmpTest 3160 B / 1504 条目）；x86 真实世界目标
    // imm32 绝对寻址遍地（wvmpTest 888 KB MSVC /DYNAMICBASE = 28.5 KB /
    // 13472 条目 HIGHLOW），emit_reserve_take fail-closed 打包硬失败。
    // 预留量按原生 reloc 目录尺寸动态加成；判据 = 重建上界（×1.25：垫
    // 补齐 + 块头重建余量）+ 站点余量 4KB（实测站点面 x64 56 站点≈0.4 KB、
    // x86 词流 RVA 化后仅 stub 序言面，4KB ≈ 10 倍实测）未超 8KB 基础预
    // 算时加成为零 → 既有产物（multiseed 池 / x64 wvmpTest）字节零扰动。
    // [pe] aslr=false 或 native 未声明 DYNAMIC_BASE 时 pe_writer 不扩展，
    // 加成同步为零。
    // ⚠️ 判据上界披露（T32 验收 SH2）：×1.25 非最坏界——剪枝重建把每块
    // 条目垫到 4 条目倍数，全 2-条目块目录最坏膨胀 1.33×（S>768B 时
    // 可能低估）；低估后果 = pe_writer emit_reserve_take fail-closed 硬
    // 失败（报错可读，不静默腐化），不产坏镜像。精确上界需遍历目录逐
    // 块算 Σ(8+垫)，留作需要时的增强（T32 口径：启发式 + fail-closed 兜
    // 底已覆盖全部现网目标）。
    u64 aslr_reloc_extra = 0;
    {
        const auto rd_le = [](const u8* p, size_t n) {
            u64 v = 0;
            for (size_t i = 0; i < n; ++i) v |= u64(p[i]) << (8 * i);
            return v;
        };
        const auto* rules = ctx.find_slot<ProtectRules>(kProtectRules);
        const bool aslr_on =
            rules == nullptr || !rules->has_pe_aslr || rules->pe_aslr;
        const size_t opt = pe->nt_headers_offset + 24;
        const size_t dd5 = opt + (pe->is_pe32_plus ? 112u : 96u) + 5 * 8;
        if (aslr_on && opt + 0x48 <= ctx.image.size() && dd5 + 8 <= ctx.image.size()) {
            const u32 reloc_size = static_cast<u32>(rd_le(ctx.image.data() + dd5 + 4, 4));
            const u16 dllchars = static_cast<u16>(rd_le(ctx.image.data() + opt + 0x46, 2));
            if (reloc_size > 0 && (dllchars & 0x0040) != 0) {
                const u64 rebuild_need =
                    u64(reloc_size) + reloc_size / 4 + 64;
                const u64 sites_need = 4096;
                if (rebuild_need + sites_need > kEmitReserveBytes)
                    aslr_reloc_extra = align_up(
                        rebuild_need + sites_need - kEmitReserveBytes, 8);
            }
        }
    }
    const u64 blobs_total = data_total;
    data_total += kEmitReserveBytes + aslr_reloc_extra;
    if (aslr_reloc_extra > 0) {
        // MIT-494j 验收 SH1：加成量落槽——pe_writer 高水位 Note 由此修正
        // 真预留区起点（否则 extra>0 时 used 恒 ≤0 → 预警静默失效）。
        ctx.slot<u64>(kEmitReserveExtra) = aslr_reloc_extra;
        ctx.diag.report(Severity::Note, name(),
                        "ASLR reloc 扩展预算加成 +" +
                            std::to_string(aslr_reloc_extra) +
                            " 字节（原生 reloc 目录超出 8KB 基础预留）");
    }

    const u64 code_rva = align_up(
        data_section_rva + align_up(data_total, sec_align), sec_align);
    const u64 rt_entry = code_rva;  // 解释器入口 = 代码节基址（vm_entry_offset=0）

    // ⚠️ 索引循环：x86 白名单 gate 的提前 continue 也占用一个 vfs 下标，
    // plan 配对（crypted = plan_of(i)）必须与 kVmProgram 下标严格同步。
    // gate 判定复用前置遍历缓存（gated[]）。
    for (size_t vfs_index = 0; vfs_index < vfs->size(); ++vfs_index) {
        const auto& vf = (*vfs)[vfs_index];
        // MIT-446 (X4)：x86 白名单 gate——字节码含 x86 运行时跳表缺项
        // VmOp（SSE 族 32 / Div / Idiv 等"仍纸面"面）的函数整函数保持原生，
        // 阻断 C2 类静默错（翻译成功、区域覆写后运行即 Halt）。x64 路径
        // 不经过本 gate（行为零变化）。
        if (is_x86) {
            if (gated[vfs_index]) {
                std::string ops;
                for (size_t k = 0; k < gated_ops[vfs_index].size() && k < 8; ++k) {
                    if (k != 0) ops += ",";
                    ops += isa::to_string(
                        static_cast<isa::VmOp>(gated_ops[vfs_index][k]));
                }
                if (gated_ops[vfs_index].size() > 8) ops += ",…";
                ctx.diag.report(Severity::Note, name(),
                                "函数 " + vf.name + " 含 x86 运行时未支持的 VmOp（" +
                                    ops + "），跳过虚拟化（保持原生，x86 白名单 gate）");
                continue;
            }
        }
        // blob：VmProgram.bytecode 已是 32B 头 + 8xN 流的完整序列化。
        // MIT-458: 有加密计划时发射密文 blob（32B 明文头 + 密文流 + 8B 尾
        // 旗标），stub 携带 one-shot 解密块；x86 白名单 gate 仍读明文
        // （vf.program.bytecode，加密定长且 gate 在本 pass 内先于发射执行，
        // 密文不进 gate）。MIT-472: blob 落数据节 .wvmp（RW）。
        const crypt::CryptedFunction* crypted = plan_of(vfs_index);
        const u64 blob_off = align_up(data_payload.size(), 8);
        data_payload.resize(static_cast<size_t>(blob_off), 0);
        const std::vector<u8>& blob_bytes =
            crypted ? crypted->encrypted_blob : vf.program.bytecode;
        data_payload.insert(data_payload.end(), blob_bytes.begin(), blob_bytes.end());
        const u64 blob_stream_rva = data_section_rva + blob_off + 32;  // 跳过 blob 头

        const u64 stub_off = align_up(code_payload.size(), 16);
        code_payload.resize(static_cast<size_t>(stub_off), 0);
        const u64 stub_rva = code_rva + stub_off;
        std::vector<u8> stub;
        std::vector<u64> stub_abs_vas;
        try {
            // MIT-458: 加密函数的 stub 携带 one-shot 解密块参数（流/旗标 VA
            // = image_base + RVA，PE32+ imm64 经寄存器中转由 asm 模板处理；
            // key0 立即数嵌入 = 密钥每目标嵌入）。无加密 = nullptr（逐字节
            // v1 前现形）。
            StubCrypt crypt_param{};
            const StubCrypt* crypt_ptr = nullptr;
            // MIT-473: fetch 模式无 one-shot 解密块（dispatch 织入解密）。
            if (crypted != nullptr && !fetch_mode) {
                crypt_param.stream_va = pe->image_base + blob_stream_rva;
                crypt_param.flag_va = crypt_param.stream_va + crypted->stream_bytes;
                crypt_param.key0 = crypted->key0;
                crypt_param.dword_count =
                    static_cast<u32>(crypted->stream_bytes / 4);
                // MIT-464: integrity_crc pass 在管道时 → 解密前 CRC32 校验。
                crypt_param.verify_crc = crypted->has_crc;
                crypt_param.crc32 = crypted->crc32;
                crypt_param.byte_count = static_cast<u32>(crypted->stream_bytes);
                crypt_ptr = &crypt_param;
            }
            StubAntiDebug adb_param{};
            const StubAntiDebug* adb_ptr = nullptr;
            if (adb_plan != nullptr && adb_plan->techniques != 0) {
                adb_param.techniques = adb_plan->techniques;
                adb_ptr = &adb_param;
            }
            // image_base（PE optional header 的 ImageBase）写入 VmContext 的
            // scratch_mem 槽：运行时 Load/Store/Push/Pop 的访存汇编即
            // `[addr + image_base]`. 翻译期算的 RVA（rip-relative 转绝对）
            // + 此基址 = 实际 VA. ASLR 下基址变化不影响 RVA, 槽值不变.
            stub = generate_entry_stub(stub_rva, blob_stream_rva, rt_entry, vf.end_rva,
                                       pe->image_base,
                                       is_x86 ? StubArch::X86 : StubArch::X64,
                                       crypt_ptr, adb_ptr, &stub_abs_vas);
        } catch (const std::exception& e) {
            ctx.diag.report(Severity::Error, name(),
                            "函数 " + vf.name + " stub 生成失败（保持原生）: " + e.what());
            continue;
        }
        code_payload.insert(code_payload.end(), stub.begin(), stub.end());
        // MIT-494：精确站点登记——已知 VA 集在 stub 内的字节精确匹配
        //（零假阳；payload 级泛扫描在 wvmpTest 假阳 2194 处，开发实录）。
        {
            const size_t w = is_x86 ? 4 : 8;
            auto& sites = ctx.slot<std::vector<u32>>(kRelocSites);
            for (const u64 va : stub_abs_vas) {
                u8 pat[8];
                for (size_t i = 0; i < w; ++i)
                    pat[i] = static_cast<u8>((va >> (8 * i)) & 0xFF);
                for (size_t o = 0; o + w <= stub.size(); ++o)
                    if (std::memcmp(stub.data() + o, pat, w) == 0)
                        sites.push_back(static_cast<u32>(stub_rva + o));
            }
        }
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
        // MIT-494c：登记覆写区。落在 [begin_rva, end_rva) 内的 native
        // reloc 条目自本写入起成为孤儿——原指针（如函数头部 `mov rax,
        // imm64`）已被跳板覆写消灭，pe_writer 扩展 reloc 目录时剪枝之
        // （不剪 = loader 把 delta 写进跳板字节 → rel32 毒变野跳，
        // MIT-494a forkface 0x13DE cdb 实证）。
        ctx.slot<std::vector<std::pair<u32, u32>>>(kPatchedRanges)
            .push_back({static_cast<u32>(p.begin_rva),
                        static_cast<u32>(p.end_rva - p.begin_rva)});
    }

    // MIT-476：blob 末端起为 Emit 预留区（预扩零垫）；后续 pass 经
    // kEmitReserveBase 槽内的游标在区内分配（pe_image.hpp 协议注）。

    data_payload.resize(static_cast<size_t>(data_total), 0);
    ctx.slot<u64>(kEmitReserveBase) = blobs_total;

    // —— 新节请求交给 pe_writer（MIT-472 W^X 拆节：两节）——
    // .wvmp（RW，0xC0000040）：字节码 blob 等数据面（解密期被写）。
    // .wvmpc（RX，0x60000020）：解释器 + 入口 stub 代码面（只执行不写）。
    // 先请求 .wvmp（数据）再 .wvmpc（代码），requested_rva 保持连续。
    NewSection data_req;
    data_req.name = ".wvmp";
    data_req.data = std::move(data_payload);
    data_req.characteristics = kWvmpDataChars;
    data_req.requested_rva = static_cast<u32>(data_section_rva);
    const size_t data_size = data_req.data.size();

    NewSection code_req;
    code_req.name = ".wvmpc";
    code_req.data = std::move(code_payload);
    code_req.characteristics = kWvmpCodeChars;
    code_req.requested_rva = static_cast<u32>(code_rva);
    const size_t code_size = code_req.data.size();

    auto& new_sections = ctx.slot<std::vector<NewSection>>(kNewSections);
    new_sections.push_back(std::move(data_req));
    new_sections.push_back(std::move(code_req));

    char rva_buf[48], crva_buf[48];
    std::snprintf(rva_buf, sizeof(rva_buf), "%llX",
                  static_cast<unsigned long long>(data_section_rva));
    std::snprintf(crva_buf, sizeof(crva_buf), "%llX",
                  static_cast<unsigned long long>(code_rva));
    ctx.diag.report(Severity::Note, name(),
                    "已生成 " + std::to_string(patches.size()) + " 个入口 stub，数据节 .wvmp " +
                        std::to_string(data_size) + " 字节 @ RVA 0x" + rva_buf +
                        "，代码节 .wvmpc " + std::to_string(code_size) + " 字节 @ RVA 0x" +
                        crva_buf);
}

WVMP_REGISTER_PASS(StubLinkPass)

} // namespace wvmp::passes
