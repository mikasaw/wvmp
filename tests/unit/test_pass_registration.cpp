// 跨模块验证：wvmp_passes_all 里的静态自注册 pass 全部能被 PassRegistry
// 发现（OBJECT 库聚合 + WVMP_REGISTER_PASS + 链接进本可执行文件 的完整链路）。
// 若某个 pass 被 MSVC 链接器丢弃，这里会立刻暴露。

#include "wvmp/framework/registry.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>

namespace {

TEST(PassRegistration, AllPassesDiscoverable) {
    const auto names = wvmp::PassRegistry::instance().names();
    const char* expected[] = {
        "pe_loader", "pe_writer", "marker_scan", "lifter", "mutate",
        "virtualize", "crypt", "anti_debug", "integrity_crc",
        "import_protect", "stub_link", "tls_hook",
    };
    for (const char* e : expected) {
        EXPECT_NE(wvmp::PassRegistry::instance().find(e), nullptr)
            << "pass '" << e << "' not registered (linker dropped its object?)";
    }
    EXPECT_GE(names.size(), static_cast<size_t>(12));
    // 无重名（registry 本身会拒绝重复注册，能走到这里即证明）。
    std::vector<std::string> sorted(names.begin(), names.end());
    std::sort(sorted.begin(), sorted.end());
    EXPECT_EQ(std::adjacent_find(sorted.begin(), sorted.end()), sorted.end());
}

} // namespace
