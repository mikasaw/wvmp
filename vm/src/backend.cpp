#include "wvmp/vm/backend.hpp"
#include "wvmp/vm/backend_registry.hpp"

#include <map>
#include <stdexcept>
#include <string>

namespace wvmp::vm {
namespace {

std::map<std::string, BackendFactory, std::less<>>& factories() {
    static std::map<std::string, BackendFactory, std::less<>> table;
    return table;
}

} // namespace

void register_backend_factory(std::string_view name, BackendFactory factory) {
    if (factory == nullptr)
        throw std::runtime_error("register_backend_factory: null factory");
    auto& table = factories();
    if (table.count(name) != 0)
        throw std::runtime_error("register_backend_factory: duplicate backend name '" +
                                 std::string(name) + "'");
    table.emplace(std::string(name), factory);
}

std::unique_ptr<VMBackend> create_backend(std::string_view name) {
    const auto& table = factories();
    const auto it = table.find(name);
    return it == table.end() ? nullptr : it->second();
}

} // namespace wvmp::vm
