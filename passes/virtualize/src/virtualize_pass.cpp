#include "wvmp/passes/virtualize/virtualize_pass.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/protect_levels.hpp"
#include "wvmp/framework/registry.hpp"
#include "wvmp/regvm/backend/regvm_backend.hpp"
#include "wvmp/regvm/isa/vm_op.hpp"  // MIT-512 混排 gate VmOp 词域
#include "wvmp/vm/backend.hpp"

#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

namespace wvmp::passes {

namespace isa = wvmp::regvm::isa;  // MIT-512 混排 gate 词域
namespace {

// 引用 regvm 的具名工厂符号，确保其翻译单元（含静态注册）进入链接——
// 否则 MSVC 会丢弃归档中无引用的自注册对象，create_backend 查不到后端。
const auto kRegVmAnchor = &regvm::make_regvm;

std::string hex64(u64 v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llX",
                  static_cast<unsigned long long>(v));
    return buf;
}

} // namespace

std::span<const std::string_view> VirtualizePass::requires_keys() const {
    static constexpr std::string_view kRequires[] = {kLiftedIr};
    return kRequires;
}

std::span<const std::string_view> VirtualizePass::provides_keys() const {
    static constexpr std::string_view kProvides[] = {kVmProgram};
    return kProvides;
}

void VirtualizePass::run(ProtectionContext& ctx) {
    std::unique_ptr<vm::VMBackend> backend = vm::create_backend("regvm");
    if (backend == nullptr) {
        ctx.diag.report(Severity::Error, name(), "regvm 后端未注册（链接配置错误？）");
        throw std::runtime_error(std::string(name()) + ": regvm backend not registered");
    }

    auto& virtualized = ctx.slot<std::vector<VirtualizedFunction>>(kVmProgram);
    virtualized.clear();

    // MIT-457 配置系统 v1：保护档位规则（CLI 写入 kProtectRules；槽缺席 =
    // 直连 API 未装配配置 = 全部缺省档位，与 v1 之前行为一致）。
    const ProtectRules* rules = ctx.find_slot<ProtectRules>(kProtectRules);

    for (size_t fn_index = 0; fn_index < ctx.functions.size(); ++fn_index) {
        const ir::FunctionRegion& fn = ctx.functions[fn_index];
        if (rules != nullptr &&
            rules->level_for(fn.begin_rva, fn_index) == ProtectLevel::None) {
            ctx.diag.report(Severity::Note, name(),
                            "函数 " + fn.name + " 按配置 level=none 保持原生（rva=" +
                                hex64(fn.begin_rva) + "）");
            continue;
        }
        if (fn.blocks.empty()) {
            ctx.diag.report(Severity::Note, name(),
                            "函数 " + fn.name + " 无已 lift 的基本块，跳过虚拟化");
            continue;
        }
        try {
            VirtualizedFunction vf;
            vf.name = fn.name;
            vf.begin_rva = fn.begin_rva;
            vf.end_rva = fn.end_rva;
            vf.program = backend->compile(fn, ctx);

            // C1 保守拦截（MIT-243）：后端经扩展槽回传本次翻译的 skip
            // notes（key 见 regvm_backend.hpp）。任一 note 即放弃该函数的
            // 虚拟化、保持原生执行——否则字节码缺一块而原区域已被 stub_link
            // 覆写，产出静默行为错误的 PE。Note 级而非 throw：保持原生继续
            // 是正常路径，Error 会让 CLI 把整次保护判失败（rc=2）。
            const std::vector<std::string>* notes =
                ctx.find_slot<std::vector<std::string>>(regvm::kLastTranslateNotes);
            if (notes != nullptr && !notes->empty()) {
                for (const std::string& n : *notes)
                    ctx.diag.report(Severity::Note, name(),
                                    "函数 " + fn.name + " 含不可翻译指令，跳过虚拟化" +
                                        "（保持原生）: " + n);
                continue;
            }


            // MIT-518: require_avx 开关（默认 true = 现行为零变化）。
            // false 时含 AVX 词（Vzeroupper 起的连续值域 = vzero + ymm 全族）
            // 的函数整函数 gate——部署非 AVX 机器的安全开关。
            if (rules != nullptr && rules->has_require_avx &&
                !rules->require_avx) {
                bool has_avx = false;
                const auto& bc0 = vf.program.bytecode;
                for (size_t off = 32; off + 8 <= bc0.size(); off += 8) {
                    if (static_cast<int>(bc0[off]) >=
                        static_cast<int>(isa::VmOp::Vzeroupper)) {
                        has_avx = true;
                        break;
                    }
                }
                if (has_avx) {
                    ctx.diag.report(
                        Severity::Note, name(),
                        "函数 " + fn.name +
                            " 含 AVX 词流且 config require_avx=false，跳过虚拟化"
                            "（保持原生，非 AVX 机器部署安全开关）");
                    continue;
                }
            }

            // MIT-512 (档B wave2①): xmm/ymm 混排 gate —— 含 Ymm* 词的函数
            // 不得含 legacy SSE 词（两面低半区各自权威，交错写 = 静默错值；
            // wave2③ 混排契约落地前 fail-closed 整函数原生）。vzeroupper/
            // vzeroall 不在判据内（T63 handler 已做面一致性回写）。
            {
                bool has_ymm = false, has_sse = false;
                const auto& bc = vf.program.bytecode;
                for (size_t off = 32; off + 8 <= bc.size() && !(has_ymm && has_sse);
                     off += 8) {
                    // 值域判据: Ymm* 词族从 YmmMov 起连续追加 (T64+T65+…)
                    if (static_cast<int>(bc[off]) >=
                        static_cast<int>(isa::VmOp::YmmMov)) {
                        has_ymm = true;
                        continue;
                    }
                    switch (static_cast<isa::VmOp>(bc[off])) {
                    case isa::VmOp::Addss: case isa::VmOp::Addps:
                    case isa::VmOp::Addpd: case isa::VmOp::Addsd:
                    case isa::VmOp::Subss: case isa::VmOp::Subps:
                    case isa::VmOp::Subpd: case isa::VmOp::Subsd:
                    case isa::VmOp::Divss: case isa::VmOp::Divps:
                    case isa::VmOp::Divpd: case isa::VmOp::Divsd:
                    case isa::VmOp::Mulss: case isa::VmOp::Mulsd:
                    case isa::VmOp::Mulps: case isa::VmOp::Mulpd:
                    case isa::VmOp::Movss: case isa::VmOp::Movsd:
                    case isa::VmOp::Movaps: case isa::VmOp::Movapd:
                    case isa::VmOp::Movups: case isa::VmOp::Movupd:
                    case isa::VmOp::Xorps: case isa::VmOp::Orps:
                    case isa::VmOp::Andps: case isa::VmOp::Andnps:
                    case isa::VmOp::Ucomiss: case isa::VmOp::Ucomisd:
                    case isa::VmOp::XmmLoad: case isa::VmOp::XmmStore:
                    case isa::VmOp::XmmFromGp: case isa::VmOp::GpFromXmm:
                        has_sse = true;
                        break;
                    default:
                        break;
                    }
                }
                if (has_ymm && has_sse) {
                    ctx.diag.report(
                        Severity::Note, name(),
                        "函数 " + fn.name +
                            " 含 ymm/legacy SSE 混排词流，跳过虚拟化（保持原生，"
                            "档B wave2① 混排契约未落地前的保守 gate）");
                    continue;
                }
            }

            virtualized.push_back(std::move(vf));
        } catch (const std::exception& e) {
            // 单函数失败不拖垮整条管道：记 Error 并跳过该函数（其区域保持原生）。
            ctx.diag.report(Severity::Error, name(),
                            "函数 " + fn.name + " 虚拟化失败（保持原生）: " + e.what());
        }
    }

    if (virtualized.empty())
        ctx.diag.report(Severity::Warning, name(), "没有任何函数被虚拟化");
}

WVMP_REGISTER_PASS(VirtualizePass)

} // namespace wvmp::passes
