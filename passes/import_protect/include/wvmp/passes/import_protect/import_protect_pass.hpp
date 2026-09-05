#pragma once
#include "wvmp/framework/pass.hpp"

namespace wvmp::passes {

// MIT-466：IAT 迁移 + 回填（import_protect v1）。
//
// 前提：stub_link 已产出 .wvmp（本 pass 把镜像 IAT 追加进该节，Emit 阶段、
// stub_link 之后 tls_hook 之前）。
//
// 迁移语义见 import_plan.hpp 头注。要点：
//   - 解析 dd[1] 描述符链，逐描述符以 INT（OriginalFirstThunk）为基准数槽
//     （INT 与 IAT 平行、同长、各自 NULL 终止）；
//   - 全部描述符的 FirstThunk 槽必须落在同一段连续区间 [iat_base, iat_end)
//     （MSVC/链接器标准布局），否则整单放弃迁移；
//   - 镜像追加到 .wvmp（8 对齐），文件态 = 种子派生乱数（掩盖静态分析；
//     加载期被 loader 以真实地址覆写）；
//   - 各描述符 FirstThunk RVA 原地重指镜像切片；INT 原位不动；
//   - 回填由 tls_hook 的 TLS 回调完成（kImportPlan 槽），早于任何用户代码。
//
// 任一异常（dd1 缺失 / 绑定导入 / 槽超上限 / .wvmp 缺席）→ 整单放弃，
// 镜像零改动（保守回退，Note 留痕）。
class ImportProtectPass final : public Pass {
public:
    std::string_view name() const override { return "import_protect"; }
    Phase phase() const override { return Phase::Emit; }
    std::span<const std::string_view> requires_keys() const override;
    std::span<const std::string_view> provides_keys() const override;
    void run(ProtectionContext& ctx) override;
};

} // namespace wvmp::passes
