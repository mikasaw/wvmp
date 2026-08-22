#pragma once
#include "wvmp/common/rng.hpp"
#include "wvmp/framework/diagnostics.hpp"
#include "wvmp/ir/region.hpp"
#include <any>
#include <filesystem>
#include <map>
#include <string>
#include <string_view>
#include <vector>
namespace wvmp {
class ProtectionContext {
public:
    // —— 核心字段（仅此六个，其余一律走扩展槽）——
    std::filesystem::path input_path, output_path;
    std::vector<u8> image;                     // 被保护文件镜像
    std::vector<ir::FunctionRegion> functions; // 保护区域（marker_scan 产出）
    u64 seed = 0;
    Rng rng;
    Diagnostics diag;

    // —— 类型安全扩展槽（单线程，不加锁）——
    template <class T> T& slot(std::string_view key) {
        auto it = slots_.find(key);
        if (it == slots_.end()) it = slots_.emplace(std::string(key), std::make_any<T>()).first;
        return std::any_cast<T&>(it->second);
    }
    template <class T> const T* find_slot(std::string_view key) const {
        auto it = slots_.find(key); return it == slots_.end() ? nullptr : std::any_cast<T>(&it->second);
    }
    template <class T> T* find_slot(std::string_view key) {
        auto it = slots_.find(key); return it == slots_.end() ? nullptr : std::any_cast<T>(&it->second);
    }
    bool has_slot(std::string_view key) const { return slots_.count(key) != 0; }
    void drop_slot(std::string_view key) {
        auto it = slots_.find(key);          // heterogeneous lookup (<>, C++20)
        if (it != slots_.end()) slots_.erase(it);  // erase(iterator): heterogeneous erase is C++23
    }
private:
    std::map<std::string, std::any, std::less<>> slots_;
};
}
