#pragma once
#include "wvmp/framework/pass.hpp"
#include <string>
#include <vector>
namespace wvmp {
class Pipeline {
public:
    static Pipeline from_names(const std::vector<std::string>& pass_names); // 未知名抛错；按 Phase 排序，阶段内保持给定顺序
    void validate() const;  // requires/provides 检查：依赖的 key 必须来自核心字段(image/functions)或更早 pass 的 provides，否则抛含 pass 名与 key 名的 std::runtime_error
    void run(ProtectionContext& ctx) const;
    const std::vector<Pass*>& stages() const;
private:
    std::vector<Pass*> stages_;
};
}
