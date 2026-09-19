// MIT-526 (CR-04)：x64 TLS 回调 ABI 真执行判据（子进程跑 tls_abi_probe）。
//
// 探针把 tls_hook 真实产出的回调桩镜像进 RWX 内存真跳进去，被调侧（模拟
// GetThreadContext / VirtualProtect）按 x64 约定把自己那 4 个 home slot 全写脏。
// 判据全是量出来的物理量（gap = 调用方 call 点 rsp - 被调入口 rsp、出口 rsp ==
// 入口 rsp、崩溃形态的 fault_dir/fault_addr），不是"生成码里有没有 call"。
//
//   gap 0x38 = thunk push 8 + 回调 sub 0x28（32B shadow + 8B 对齐）+ 回调 push 8
//   gap 0x18 = 只 sub 8（CR-04 现场）⇒ 写脏的 [rsp+0x10] 正落在回调返回地址上
//              ⇒ 回调 ret 回飞（fault_dir=8 取指、fault_addr=0x4141…）。

#include <windows.h>

#include <gtest/gtest.h>

#include <cstdlib>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace {

constexpr unsigned long long kGapShadow = 0x38;  // 修后期望
constexpr unsigned long long kGapNoShadow = 0x18;  // CR-04 缺陷形态
constexpr unsigned long long kAv = 0xC0000005ull;
constexpr unsigned long long kPoison = 0x4141414141414141ull;

struct ProbeRun {  // 不叫 Run：advpub.h 里 #define Run
    DWORD exit_code = 0xFFFFFFFF;
    std::string readings;
    std::map<std::string, std::string> kv;

    bool has(const std::string& k) const { return kv.count(k) != 0; }
    unsigned long long num(const std::string& k) const {
        const auto it = kv.find(k);
        if (it == kv.end()) return 0;
        return std::strtoull(it->second.c_str(), nullptr, 0);
    }
    std::string dump() const { return readings; }
};

std::string temp_path_for(const std::string& mode) {
    char dir[MAX_PATH] = {0};
    const DWORD n = GetTempPathA(MAX_PATH, dir);
    std::string out = n > 0 ? dir : ".";
    if (!out.empty() && out.back() != '\\') out += '\\';
    return out + "wvmp_tls_abi_" + mode + ".txt";
}

std::string parseable(const std::string& line) {
    // 只认 key=value；value 允许 0x…/十进制/字符串/点分十进制（异常文本）。
    const auto eq = line.find('=');
    if (eq == std::string::npos) return {};
    return line;
}

std::string probe_path() {
    char buf[MAX_PATH] = {0};
    const DWORD n = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    std::string self(buf, n);
    const auto pos = self.find_last_of("\\/");
    return (pos == std::string::npos ? std::string(".") : self.substr(0, pos + 1)) +
           "wvmp_tls_abi_probe.exe";
}

ProbeRun run_probe(const std::string& mode) {
    ProbeRun r;
    const std::string file = temp_path_for(mode);
    DeleteFileA(file.c_str());
    const std::string cmd = "\"" + probe_path() + "\" " + mode + " \"" + file + "\"";
    std::vector<char> mutable_cmd(cmd.begin(), cmd.end());
    mutable_cmd.push_back('\0');

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessA(nullptr, mutable_cmd.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        r.exit_code = static_cast<DWORD>(0xFFFFFFFFu);
        r.readings = "CreateProcess failed (" + std::to_string(GetLastError()) +
                     ") for probe: " + probe_path();
        return r;
    }
    const DWORD wait = WaitForSingleObject(pi.hProcess, 180000);
    GetExitCodeProcess(pi.hProcess, &r.exit_code);
    if (wait != WAIT_OBJECT_0) {
        TerminateProcess(pi.hProcess, 1);
        r.exit_code = static_cast<DWORD>(0xFFFFFFFEu);
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    std::ifstream f(file, std::ios::binary);
    std::stringstream ss;
    ss << f.rdbuf();
    r.readings = ss.str();
    std::istringstream lines(r.readings);
    std::string line;
    while (std::getline(lines, line)) {
        const std::string p = parseable(line);
        if (p.empty()) continue;
        const auto eq = p.find('=');
        std::string k = p.substr(0, eq);
        std::string v = p.substr(eq + 1);
        while (!v.empty() && (v.back() == '\r' || v.back() == '\n')) v.pop_back();
        if (!k.empty()) r.kv[k] = v;
    }
    DeleteFileA(file.c_str());
    return r;
}

// 正常返回类模式的共同断言。
void expect_clean_return(const ProbeRun& r, unsigned long long expect_calls) {
    EXPECT_EQ(r.exit_code, 0u) << "探针异常退出，readings:\n" << r.dump();
    EXPECT_EQ(r.num("returned"), 1u) << "回调没返回到调用方（返回地址被毁？）\n" << r.dump();
    EXPECT_EQ(r.num("post_eq_h"), 1u) << "出口 RSP != 入口 RSP\n" << r.dump();
    EXPECT_EQ(r.num("cb_ret"), 0u) << r.dump();
    EXPECT_EQ(r.num("gtc_calls"), expect_calls) << r.dump();
    if (expect_calls > 0) {
        EXPECT_EQ(r.num("gtc_poison"), 1u) << "模拟被调没真的写脏 home slot\n" << r.dump();
        EXPECT_EQ(r.num("gap"), kGapShadow) << "shadow space 读数\n" << r.dump();
        EXPECT_NE(r.num("gap"), kGapNoShadow) << "仍是 CR-04 缺陷形态\n" << r.dump();
        EXPECT_EQ(r.num("h_mod16"), 0u) << "call 点 rsp 未 16 对齐\n" << r.dump();
        EXPECT_EQ(r.num("m_mod16"), 8u) << "被调入口 rsp 未 ≡8 mod 16\n" << r.dump();
    }
}

TEST(TlsAbiExec, X64DrxCallSiteLeaves0x28ShadowSpace) {
    const ProbeRun r = run_probe("drx_clean");
    ASSERT_TRUE(r.has("completed")) << "探针未完成，readings:\n" << r.dump();
    expect_clean_return(r, 1);
    // 执行读数的字节面旁证：sub rsp, 0x28 在场、sub rsp, 8 不在场。
    EXPECT_EQ(r.num("has_sub28"), 1u) << r.dump();
    EXPECT_EQ(r.num("has_sub8"), 0u) << "仍有 sub rsp,8 站点\n" << r.dump();
    EXPECT_EQ(r.num("ctxva_in_stub"), 1u) << r.dump();
    EXPECT_EQ(r.num("gtcva_in_stub"), 1u) << r.dump();
}

TEST(TlsAbiExec, X64DrxGtcFailurePathReturnsBalanced) {
    const ProbeRun r = run_probe("drx_gtcfail");  // GTC 返回 0 → je drx_cleanup
    ASSERT_TRUE(r.has("completed")) << r.dump();
    expect_clean_return(r, 1);
}

TEST(TlsAbiExec, X64DrxHitFailsFastWithNullWriteNotStackCorruption) {
    const ProbeRun r = run_probe("drx_hit");  // Dr0 != 0 → drx_fail: mov [0],0
    EXPECT_EQ(r.exit_code, static_cast<DWORD>(kAv)) << r.dump();
    // 崩溃模式没有"跑完之后"的读数 ⇒ 全部取 VEH 现场值。
    EXPECT_EQ(r.num("veh_returned"), 0u) << r.dump();
    EXPECT_EQ(r.num("veh_gtc_calls"), 1u) << r.dump();
    EXPECT_EQ(r.num("veh_gtc_poison"), 1u) << "模拟被调没真的写脏 home slot\n" << r.dump();
    // 这条路径的主判据：FailFast 之前那个 call 站点就得给够 shadow（VEH 现场量）。
    EXPECT_EQ(r.num("veh_gap"), kGapShadow)
        << "drx_fail 路径的 call 站点 shadow 不足\n" << r.dump();
    // 崩溃必须是 FailFast 的写零红线（fault_addr = 0），不是 home slot 写脏后的回飞。
    EXPECT_EQ(r.num("fault_code"), kAv) << r.dump();
    EXPECT_EQ(r.num("fault_addr"), 0u) << "写地址非 0 = 栈被毁而非受控崩溃\n" << r.dump();
    EXPECT_TRUE(r.has("fault_rip_stub_off"))
        << "崩溃点不在生成的桩内 = 回飞到野地址\n" << r.dump();
}

TEST(TlsAbiExec, X64RdtscQuadrantsReturnBalanced) {
    // 四象限：drx 关/开 × rdtsc 关/开（drx 关象限无 call 站点，只验栈平衡与返回）。
    struct Case {
        const char* mode;
        unsigned long long calls;
    };
    const Case cases[] = {{"plain", 0}, {"rdtsc_only", 0}, {"drx_rdtsc", 1}};
    for (const auto& c : cases) {
        const ProbeRun r = run_probe(c.mode);
        SCOPED_TRACE(std::string("mode=") + c.mode);
        ASSERT_TRUE(r.has("completed")) << r.dump();
        expect_clean_return(r, c.calls);
    }
}

TEST(TlsAbiExec, X64BackfillVirtualProtectCallSiteLeavesShadowSpace) {
    const ProbeRun r = run_probe("backfill");
    ASSERT_TRUE(r.has("completed")) << r.dump();
    expect_clean_return(r, 1);
    // 第二个 call 站点（VirtualProtect ×2）同判据：被调写脏 4 槽后回调仍正常返回。
    EXPECT_EQ(r.num("vp_calls"), 2u) << r.dump();
    EXPECT_EQ(r.num("vp_poison"), 1u) << r.dump();
    EXPECT_EQ(r.num("oldprot"), 4u) << "模拟 VP 写回 lpflOldProtect 未生效\n" << r.dump();
    // rep movsq 回填确实执行：原 IAT 槽 = 镜像槽内容。
    EXPECT_EQ(r.num("orig_slot_after"), r.num("vp_mock")) << r.dump();
    EXPECT_EQ(r.num("orig_slot1_after"), r.num("gtc_mock")) << r.dump();
}

TEST(TlsAbiExec, X64PoisonHomeSlotsProvesMockCalleeRealWrite) {
    // 反证自身的反证：home slot 存档值 ≠ 写脏值 ⇒ 写脏真的发生过。
    const ProbeRun r = run_probe("drx_clean");
    ASSERT_TRUE(r.has("completed")) << r.dump();
    EXPECT_NE(r.num("save08"), kPoison) << r.dump();
    EXPECT_NE(r.num("save10"), kPoison) << r.dump();
    EXPECT_NE(r.num("save18"), kPoison) << r.dump();
    EXPECT_NE(r.num("save20"), kPoison) << r.dump();
}

} // namespace
