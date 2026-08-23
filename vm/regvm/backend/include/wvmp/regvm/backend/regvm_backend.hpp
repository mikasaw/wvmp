#pragma once
#include "wvmp/vm/backend.hpp"

namespace wvmp::regvm {

// 具名工厂：同时承担“锚点”职责——消费者引用此符号可确保本翻译单元
// （含静态注册代码）不被 MSVC 链接器丢弃。
std::unique_ptr<vm::VMBackend> make_regvm();

} // namespace wvmp::regvm
