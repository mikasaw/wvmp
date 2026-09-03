// testfw.h - minimal self-registering test framework.
//
// Output contract (kept intentionally simple so a packed/unpacked pair can be
// diffed mechanically):
//   [PASS] group.name
//   [FAIL] group.name
//          <indented failure details>
//   [SKIP] group.name
//   SUMMARY passed=N failed=N skipped=N total=M
// Exit code: 0 when failed==0, otherwise 1. A native crash surfaces as a
// non-zero / negative exit code as well - which is itself the test verdict.
#pragma once

#include <string>
#include <vector>
#include <ostream>

namespace fw {

enum class Status { Passed, Failed, Skipped };

class Ctx {
public:
    std::vector<std::string> fails;
    void fail(const std::string& s) { fails.push_back(s); }
};

extern Ctx* g_ctx;   // valid only while a test body runs (single-threaded driver)

void report_failure(const char* file, int line, const std::string& text);

struct TestCase {
    const char* group;
    const char* name;
    void (*fn)();
};

std::vector<TestCase>& tests();
std::vector<const char*>& groups();

class Registrar {
public:
    Registrar(const char* g, const char* n, void (*f)());
    ~Registrar();
private:
    size_t idx_;
};

void mark_skipped();               // test body decides it cannot run here
Status status_of_last();

// Runs everything whose "group.name" contains `filter` (empty = all).
// Returns number of FAILED tests.
int run_all(const std::string& filter, std::ostream& out, bool quiet_details);

bool list_tests(std::ostream& out);

} // namespace fw

#define TEST(group_, name_)                                                    \
    static void wv_test_fn_##group_##_##name_();                               \
    static ::fw::Registrar wv_reg_obj_##group_##_##name_(                      \
        #group_, #name_, &wv_test_fn_##group_##_##name_);                      \
    static void wv_test_fn_##group_##_##name_()

#define FAIL_AT(file, line, text) ::fw::report_failure(file, line, text)

#define CHECK(cond)                                                            \
    do { if (!(cond)) FAIL_AT(__FILE__, __LINE__, "CHECK(" #cond ")"); } while (0)

#define CHECK_MSG(cond, msg)                                                   \
    do { if (!(cond)) FAIL_AT(__FILE__, __LINE__,                              \
            std::string("CHECK(" #cond ") ") + (msg)); } while (0)

#define CHECK_EQ(a, b)                                                         \
    do {                                                                       \
        if (!((a) == (b)))                                                     \
            FAIL_AT(__FILE__, __LINE__,                                        \
                std::string("CHECK_EQ(" #a ", " #b ") : LHS=[") +              \
                ::fw::to_display(a) + "] RHS=[" + ::fw::to_display(b) + "]");  \
    } while (0)

// approximate compare for floating point
#define CHECK_NEAR(a, b, eps)                                                  \
    do {                                                                       \
        double dv_ = (double)(a), rv_ = (double)(b), eps_ = (double)(eps);     \
        if (!(dv_ >= rv_ - eps_ && dv_ <= rv_ + eps_))                         \
            FAIL_AT(__FILE__, __LINE__,                                        \
                std::string("CHECK_NEAR(" #a ", " #b ", " #eps ") : got [") +  \
                ::fw::to_display(dv_) + "] want [" + ::fw::to_display(rv_) +   \
                "] eps [" + ::fw::to_display(eps_) + "]");                     \
    } while (0)

#include <sstream>

namespace fw {
template <class T> std::string to_display(const T& v) {
    std::ostringstream os; os << v; return os.str();
}
inline std::string to_display(unsigned char v) {
    char b[8]; std::snprintf(b, sizeof(b), "%u", (unsigned)v); return b;
}
}
