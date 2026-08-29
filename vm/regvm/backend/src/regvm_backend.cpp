#include "wvmp/regvm/backend/regvm_backend.hpp"

#include "wvmp/passes/lifter/lift_metadata.hpp"
#include "wvmp/passes/pe_loader/pe_image.hpp"
#include "wvmp/regvm/runtime/runtime.hpp"
#include "wvmp/regvm/translator/translator.hpp"
#include "wvmp/vm/backend_registry.hpp"

#include <cstdio>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace wvmp::regvm {
namespace {

// 在与 ctx.functions 下标平行的 metadata 列表中定位指定函数的 LiftMetadata:
// 先按 begin_rva（区域内唯一）在 ctx.functions 反查下标, 再取平行元素。
// LiftMetadata 本体无 begin_rva 字段（lifter 模块私有结构, 冻结不动）,
// 平行下标是 lifter_pass.cpp 保证的契约（每个函数迭代恰好 push 一个）。
// 返回 nullptr = 找不到对应 metadata（列表缺位 / 平行关系破坏）, 调用方
// 须走保守兜底（放弃该函数虚拟化, 保持原生执行）。MIT-380。
const wvmp::passes::lifter::LiftMetadata* find_metadata_by_begin_rva(
    const ProtectionContext& ctx,
    const std::vector<wvmp::passes::lifter::LiftMetadata>* meta_list,
    u64 begin_rva) {
    if (meta_list == nullptr) return nullptr;
    for (size_t i = 0; i < ctx.functions.size(); ++i) {
        if (ctx.functions[i].begin_rva != begin_rva) continue;
        return i < meta_list->size() ? &(*meta_list)[i] : nullptr;
    }
    return nullptr;
}

class RegVmBackend final : public vm::VMBackend {
public:
    std::string_view name() const override { return "regvm"; }

    void set_codec(vm::BytecodeCodec* codec) override {
        // v1：codec 织入点已预留（dispatch fetch 后），尚未接线；记录并在
        // M3 的 xor_chain codec 任务中启用。先行持有以防调用方意外丢失。
        codec_ = codec;
    }

    vm::VmProgram compile(const ir::FunctionRegion& fn, ProtectionContext& ctx) override {
        // 翻译是纯函数；诊断级 notes 经扩展槽传回调用方（virtualize pass）
        // 转 diag 并做 C1 保守拦截（key 见 regvm_backend.hpp）。契约签名
        // 冻结，无法改返回值——槽是框架预留的跨 pass 通道。
        //
        // MIT-249 follow-up (issue-09): lifter 跳过的字节范围 (LiftMetadata)
        // 不入 IR, 直接在此处检查 → 触发 C1 gate 兜底, 避免 stub_link 按
        // IR 覆写原区域造成静默行为错 (movabs 事故根因)。
        translator::TranslateResult result;
        bool skipped = false;
        if (const auto* meta_list =
                ctx.find_slot<std::vector<wvmp::passes::lifter::LiftMetadata>>(
                    wvmp::passes::lifter::kLiftedMetadata);
            meta_list != nullptr) {
            // LifterPass 写入的 meta_list 与 ctx.functions 按下标平行
            // (lifter_pass.cpp 已保证此顺序)。函数间区分按 begin_rva
            // 匹配——LiftMetadata 是 lifter 模块私有结构无 begin_rva 字段,
            // FunctionRegion 是冻结契约不能加 id 字段, 故经
            // find_metadata_by_begin_rva() 在 ctx.functions 反查下标取平行
            // 元素 (begin_rva 在区域内唯一)。
            // M3+ 多函数并行虚拟化: 按 begin_rva 匹配 metadata, 任一函数有
            // skipped 即只兜底"该函数"（其余函数不受牵连）; 匹配不到对应
            // metadata 时保守兜底, 同样只拦当前函数保持原生执行。
            // MIT-380 修复: v1 的 meta_list->front() 永远读第 0 个函数的
            // metadata, 多函数场景 gate 错位（该拦的不拦 → stub_link 覆写
            // IR 缺字节的区域 → 运行时行为错）。
            const auto* m =
                find_metadata_by_begin_rva(ctx, meta_list, fn.begin_rva);
            if (m == nullptr) {
                result.notes.emplace_back("函数 " + fn.name +
                                          ": 无对应 LiftMetadata, 保守兜底");
                skipped = true;
            } else if (!m->skipped_ranges.empty()) {
                char buf[160];
                std::snprintf(buf, sizeof(buf),
                              "函数 %s: lifter 跳过 %zu 条指令 (rva/size 列表), "
                              "IR 缺字节, 触发 C1 gate",
                              fn.name.c_str(), m->skipped_ranges.size());
                result.notes.emplace_back(buf);
                skipped = true;
            }
        }
        if (!skipped) {
            // MIT-407: 越区跳转 ExitNative 上界接线。上界 = 该函数 .pdata
            // RUNTIME_FUNCTION EndAddress；lifter 检出越区目标回跳本区
            // （LiftMetadata.exit_native_blocked）或 .pdata 缺失时返回
            // nullopt → translator 维持原 C1 gate（行为与修复前逐字节
            // 一致）。v1 在此处禁用接线是 segfault 未修的暂时回退。
            const wvmp::passes::PeImage* pe = ctx.find_slot<wvmp::passes::PeImage>(kPeImage);
            translator::FunctionUpperBoundFn upper_bound_of =
                [pe, &ctx](u64 begin_rva) -> std::optional<u64> {
                if (pe == nullptr || pe->pdata_empty) return std::nullopt;
                if (const auto* meta_list =
                        ctx.find_slot<std::vector<wvmp::passes::lifter::LiftMetadata>>(
                            wvmp::passes::lifter::kLiftedMetadata);
                    meta_list != nullptr) {
                    // 平行下标契约：meta_list 与 ctx.functions 按 begin_rva
                    // 反查（find_metadata_by_begin_rva）。回跳检出 → 整函数
                    // 禁用 ExitNative（gate 本就是函数粒度）。
                    const auto* m =
                        find_metadata_by_begin_rva(ctx, meta_list, begin_rva);
                    if (m != nullptr && m->exit_native_blocked) return std::nullopt;
                }
                return pe->find_function_end_rva(begin_rva);
            };
            // MIT-409 + MIT-413 (G2): 跳转表条目读取。表体 RVA + 下标 +
            // 宽度(4/8) → u64 小端条目（4B 表项零扩展，8B 表项全 8 字节——
            // G2-a 绝对 VA / delta 双语义与 G2-b mem 源表共用此读取面；
            // 步长 = width 而非固定 8，4B 表读取绝不越项）；
            // rva_to_offset 未映射（表越界/落间隙）或越镜像尾 → nullopt →
            // 翻译器保守 gate。表长严禁靠"扫到非法值"推导（D1 锁死），
            // 本函数只按下标读，绝不扫描。
            translator::JumpTableReadFn table_read =
                [pe, &ctx](u64 table_rva, u32 index, u8 width)
                -> std::optional<u64> {
                if (pe == nullptr || (width != 4 && width != 8))
                    return std::nullopt;
                const u64 entry_rva = table_rva + static_cast<u64>(width) * index;
                const auto off = pe->rva_to_offset(entry_rva);
                if (!off || *off + width > ctx.image.size()) return std::nullopt;
                const u8* p = ctx.image.data() + *off;
                if (width == 4)
                    return static_cast<u64>(p[0]) | (static_cast<u64>(p[1]) << 8) |
                           (static_cast<u64>(p[2]) << 16) | (static_cast<u64>(p[3]) << 24);
                return static_cast<u64>(p[0]) | (static_cast<u64>(p[1]) << 8) |
                       (static_cast<u64>(p[2]) << 16) | (static_cast<u64>(p[3]) << 24) |
                       (static_cast<u64>(p[4]) << 32) | (static_cast<u64>(p[5]) << 40) |
                       (static_cast<u64>(p[6]) << 48) | (static_cast<u64>(p[7]) << 56);
            };
            result = translator::translate_function(fn, std::move(upper_bound_of),
                                                    std::move(table_read),
                                                    pe != nullptr ? pe->image_base : 0);
            // MIT-407: exit-native 站点 diag note 不进 gate 通道——virtualize
            // 对 kLastTranslateNotes 的**任一** note 即放弃该函数虚拟化
            // （v1 把站点 note 塞进 notes 的隐患：启用后每个 ExitNative 函数
            // 都会被误 gate）。按前缀过滤，经 ctx.diag 直报（note 级每站点）。
            // MIT-409: jump-table 命中 note 同通道过滤（命中即翻译成功，
            // note 只是 diag 证据，不能触发 gate）。
            // MIT-415: string-op 命中 note 同通道过滤（微程序翻译成功, DF=0
            // 假定是披露不是 gate 原因 — 413 纪律对账: 新 note 类型必须进
            // 过滤白名单, 否则每个含串指令的函数被误 gate, 功能全灭）。
            auto& notes = result.notes;
            for (size_t i = 0; i < notes.size();) {
                if (notes[i].rfind("exit-native @", 0) == 0 ||
                    notes[i].rfind("jump-table @", 0) == 0 ||
                    notes[i].rfind("string-op @", 0) == 0) {
                    ctx.diag.report(Severity::Note, name(), notes[i]);
                    notes.erase(notes.begin() + i);
                } else {
                    ++i;
                }
            }
        }
        ctx.slot<std::vector<std::string>>(kLastTranslateNotes) = std::move(result.notes);
        return std::move(result.program);
    }

    vm::RuntimeImage generate_runtime(const vm::VmProgram& /*prog*/,
                                      ProtectionContext& ctx) override {
        // 解释器机器码与具体程序无关（按 ctx.rng 随机化寄存器分配）。
        return runtime::generate_runtime(ctx.rng).image;
    }

private:
    vm::BytecodeCodec* codec_ = nullptr;
};

[[maybe_unused]] const bool kRegistered = [] {
    vm::register_backend_factory("regvm", &make_regvm);
    return true;
}();

} // namespace

std::unique_ptr<vm::VMBackend> make_regvm() {
    return std::make_unique<RegVmBackend>();
}

} // namespace wvmp::regvm
