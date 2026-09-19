// MIT-527 (CR-05)：x64 rdtsc 计时面低 32 位回绕判据（子进程跑 rdtsc_wrap_probe）。
//
// 被测对象是 tls_hook 真实发射的 x64 回调桩字节（夹具只把两处 rdtsc 指令
// `0F 31` 等长换成 `CC 90`，用断点现场注入 EDX:EAX；组合/求差/比较/分支全部
// 原样在真 CPU 上跑）。断言的三个量都是真机读数，不是纸面算术：
//   r11_at_second_sample = open 段真正存进 r11 的第一读数
//   delta_at_cmp         = close 段算出的差值（在 cmp 指令边界从 Rax 读回）
//   decision             = pass（桩返回）/ timeout（撞 FailFast 写零红线）
//
// 修前必 FAIL 的格（基线 `8da17de`，两采样 0x1FFFFFFF0 → 0x200000010）：
//   open 只留低 32 位 ⇒ r11 = 0xFFFFFFF0，close 算出 0xFFFFFFFF00000020 ⇒ 真
//   差 0x20 的正常执行被判超时并 FailFast。修后 r11 = 0x1FFFFFFF0、差 = 0x20。
// `hi_jump_no_low_wrap` 是同一缺陷的反向面：真差 0x800001000（必超阈）修前算成
// 0x1000 ⇒ 漏报。normal_small / eq_threshold / threshold_plus_one 作对照组，
// 保证"一律放行"式假修过不了关。

#include <windows.h>

#include <gtest/gtest.h>

#include <cstdlib>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace {

constexpr unsigned long long kAv = 0xC0000005ull;
constexpr unsigned long long kThreshold = 0x7A120ull;  // = 500000，与产品侧同值

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
    std::string str(const std::string& k) const {
        const auto it = kv.find(k);
        return it == kv.end() ? std::string("<missing>") : it->second;
    }
    std::string dump() const { return readings; }
};

std::string temp_path_for(const std::string& name) {
    char dir[MAX_PATH] = {0};
    const DWORD n = GetTempPathA(MAX_PATH, dir);
    std::string out = n > 0 ? dir : ".";
    if (!out.empty() && out.back() != '\\') out += '\\';
    return out + "wvmp_rdtsc_wrap_" + name + ".txt";
}

std::string probe_path() {
    char buf[MAX_PATH] = {0};
    const DWORD n = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    std::string self(buf, n);
    const auto pos = self.find_last_of("\\/");
    return (pos == std::string::npos ? std::string(".") : self.substr(0, pos + 1)) +
           "wvmp_rdtsc_wrap_probe.exe";
}

ProbeRun run_probe(const std::string& name) {
    ProbeRun r;
    const std::string file = temp_path_for(name);
    DeleteFileA(file.c_str());
    const std::string cmd = "\"" + probe_path() + "\" " + name + " \"" + file + "\"";
    std::vector<char> mutable_cmd(cmd.begin(), cmd.end());
    mutable_cmd.push_back('\0');

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessA(nullptr, mutable_cmd.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
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
        const auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = line.substr(0, eq);
        std::string v = line.substr(eq + 1);
        while (!v.empty() && (v.back() == '\r' || v.back() == '\n')) v.pop_back();
        if (!k.empty()) r.kv[k] = v;
    }
    DeleteFileA(file.c_str());
    return r;
}

// 判据表：真值差与期望判定全部手写在案（不从被测代码的算法回推）。
struct Expect {
    const char* name;
    unsigned long long t1;      // 注入的第一读数（EDX:EAX 组合后的 64 位）
    unsigned long long t2;      // 注入的第二读数
    unsigned long long delta;   // 代码应算出的 64 位差
    const char* decision;       // pass = 不超时 / timeout = 判为超阈
};

constexpr Expect kExpect[] = {
    {"normal_small", 0x1000ull, 0x1200ull, 0x200ull, "pass"},
    {"wrap_low32", 0x1FFFFFFF0ull, 0x200000010ull, 0x20ull, "pass"},
    {"multi_carry", 0x5FFFFFF00ull, 0x900000100ull, 0x300000200ull, "timeout"},
    {"eq_threshold", 0x700000000ull, 0x70007A120ull, 0x7A120ull, "pass"},
    {"threshold_plus_one", 0x700000000ull, 0x70007A121ull, 0x7A121ull, "timeout"},
    {"hi_jump_no_low_wrap", 0x100001000ull, 0x900002000ull, 0x800001000ull, "timeout"},
};

// gtest 的 ASSERT_* 只能在 void 函数里用 ⇒ 判据本体独立成 check_*。
void check_verdict(const Expect& e, const ProbeRun& r) {
    SCOPED_TRACE(std::string("case=") + e.name);
    // 夹具自检：两处 rdtsc 都注入过、单步锚点找到、阈值立即数与常量对得上。
    ASSERT_EQ(r.num("sample_injected"), 2u) << "rdtsc 站点没被真的执行到\n" << r.dump();
    ASSERT_EQ(r.num("anchor_seen"), 1u) << "cmp 锚点未命中，差值读数不可信\n" << r.dump();
    ASSERT_EQ(r.num("cmp_imm"), kThreshold) << "发射码里的阈值与常量不符\n" << r.dump();
    // 真机读数面。
    EXPECT_EQ(r.num("truth_delta"), e.delta) << "夹具侧回显真值差（与判据表对账）\n" << r.dump();
    EXPECT_EQ(r.num("r11_at_second_sample"), e.t1)
        << "open 段存下的第一读数 != 注入的 EDX:EAX 全值 = 高位被丢弃\n" << r.dump();
    EXPECT_EQ(r.num("delta_at_cmp"), e.delta)
        << "close 段算出的差值不等于 64 位真值差\n" << r.dump();
    EXPECT_EQ(r.str("decision"), e.decision)
        << "判定 = " << r.str("decision") << "，期望 " << e.decision << "\n" << r.dump();
    if (std::string(e.decision) == "pass") {
        EXPECT_EQ(r.exit_code, 0u) << r.dump();
        EXPECT_EQ(r.num("returned"), 1u) << r.dump();
    } else {
        EXPECT_EQ(r.exit_code, static_cast<DWORD>(kAv))
            << "超阈判定必须撞 FailFast 写零红线\n" << r.dump();
        EXPECT_EQ(r.num("fault_addr"), 0u)
            << "写地址非 0 = 桩内非预期崩溃，不是受控 FailFast\n" << r.dump();
        EXPECT_TRUE(r.has("fault_rip_stub_off"))
            << "崩溃点不在生成的桩内\n" << r.dump();
    }
}

ProbeRun expect_verdict(const Expect& e) {
    const ProbeRun r = run_probe(e.name);
    check_verdict(e, r);
    return r;
}

TEST(RdtscWrap, X64NormalSmallDeltaPasses) {
    expect_verdict(kExpect[0]);
}

TEST(RdtscWrap, X64Low32WraparoundIsNotTimeout) {
    // CR-05 本体：真差 0x20 的回绕例，修前判成超时。
    const ProbeRun r = expect_verdict(kExpect[1]);
    EXPECT_NE(r.num("delta_at_cmp"), 0xFFFFFFFF00000020ull)
        << "仍是丢 EDX 的截断差\n" << r.dump();
}

TEST(RdtscWrap, X64MultiCarryDeltaIsTimeout) {
    expect_verdict(kExpect[2]);
}

TEST(RdtscWrap, X64DeltaExactlyAtThresholdPasses) {
    expect_verdict(kExpect[3]);
}

TEST(RdtscWrap, X64DeltaOneOverThresholdIsTimeout) {
    expect_verdict(kExpect[4]);
}

TEST(RdtscWrap, X64HighHalfJumpDoesNotHideTimeout) {
    // 同一缺陷的反向面：修前算成 0x1000 ⇒ 真超时被漏掉。
    expect_verdict(kExpect[5]);
}

} // namespace
