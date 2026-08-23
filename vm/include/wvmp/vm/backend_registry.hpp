#pragma once
#include "wvmp/vm/backend.hpp"

#include <string_view>

namespace wvmp::vm {

// M2 追加扩展点（不改动已冻结的 backend.hpp 契约）：
// VM 后端以名字注册工厂，create_backend() 查表实例化。未知名字仍返回
// nullptr（保持冻结语义）。
//
// MSVC 注意：注册动作在静态初始化期完成，其所在对象若被链接器丢弃则
// 注册不会发生——后端库应提供一个具名工厂函数（如 make_regvm），消费者
// 引用该符号即可把对象拉进链接（见 virtualize pass 的 anchor 用法）。
using BackendFactory = std::unique_ptr<VMBackend> (*)();

// 重名注册抛 std::runtime_error。
void register_backend_factory(std::string_view name, BackendFactory factory);

} // namespace wvmp::vm
