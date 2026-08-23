#pragma once
#include "wvmp/vm/backend.hpp"

#include <string_view>

namespace wvmp::regvm {

// C1 保守拦截（MIT-243）：translate_function 的诊断 notes 无法经
// VMBackend::compile 的返回值传出（契约签名冻结于 vm/include/wvmp/vm/
// backend.hpp，见 docs/contracts.md §4），改走 ProtectionContext 的类型
// 安全扩展槽。约定：
//   - 每次 compile() **无条件覆写**槽内容 = 本次翻译的 notes（可为空）；
//   - 调用方（virtualize pass）在 compile 返回后立即读取并决策 gate；
//   - 管道单线程，"最近一次 compile"语义无竞态；异常路径不读槽。
inline constexpr std::string_view kLastTranslateNotes = "regvm.last_translate_notes";

// 具名工厂：同时承担“锚点”职责——消费者引用此符号可确保本翻译单元
// （含静态注册代码）不被 MSVC 链接器丢弃。
std::unique_ptr<vm::VMBackend> make_regvm();

} // namespace wvmp::regvm
