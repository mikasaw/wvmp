#pragma once
#include "wvmp/framework/pass.hpp"
#include <memory>
#include <vector>
namespace wvmp {
class PassRegistry {
public:
    static PassRegistry& instance();
    void register_pass(std::unique_ptr<Pass> p);      // 重名抛 std::runtime_error
    Pass* find(std::string_view name) const;
    std::vector<std::string_view> names() const;
    void clear();                                     // 测试用
private:
    PassRegistry() = default;
    std::vector<std::unique_ptr<Pass>> passes_;
};
class PassRegistrar { public: explicit PassRegistrar(std::unique_ptr<Pass> p); };
}
#define WVMP_REGISTER_PASS(Type) \
    static ::wvmp::PassRegistrar wvmp_pass_registrar_##Type { std::make_unique<Type>() };
