// testfw.cpp - self-registering test framework implementation.
#include "testfw.h"
#include "common.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>

namespace fw {

// ---------------------------------------------------------------------------
// registry
// ---------------------------------------------------------------------------
static std::vector<TestCase>& reg_tests() {
    static std::vector<TestCase> t;
    return t;
}
std::vector<TestCase>& tests() { return reg_tests(); }

std::vector<const char*>& groups() {
    static std::vector<const char*> g;
    return g;
}

Registrar::Registrar(const char* g, const char* n, void (*f)()) : idx_(0) {
    if (std::find(groups().begin(), groups().end(), g) == groups().end())
        groups().push_back(g);
    auto& v = reg_tests();
    // append after the last test of the same group so per-file ordering holds
    size_t pos = v.size();
    for (size_t i = v.size(); i-- > 0; ) {
        if (std::strcmp(v[i].group, g) == 0) { pos = i + 1; break; }
    }
    idx_ = pos;
    v.insert(v.begin() + pos, TestCase{ g, n, f });
}

Registrar::~Registrar() {}

// ---------------------------------------------------------------------------
// failure reporting / status
// ---------------------------------------------------------------------------
Ctx* g_ctx = nullptr;

static const char* base_name(const char* p) {
    const char* r = p;
    for (; *p; ++p)
        if (*p == '\\' || *p == '/') r = p + 1;
    return r;
}

void report_failure(const char* file, int line, const std::string& text) {
    char buf[1024];
    std::snprintf(buf, sizeof(buf), "%s(%d): %s",
                  base_name(file), line, text.c_str());
    if (g_ctx) g_ctx->fails.push_back(buf);
}

static bool   g_skip_requested = false;
static Status g_last           = Status::Failed;

void   mark_skipped()     { g_skip_requested = true; }
Status status_of_last()   { return g_last; }

// ---------------------------------------------------------------------------
// driver
// ---------------------------------------------------------------------------
int run_all(const std::string& filter, std::ostream& out, bool quiet_details) {
    Ctx ctx;
    int npass = 0, nfail = 0, nskip = 0, shown = 0;

    auto& all = reg_tests();
    for (const TestCase& tc : all) {
        const std::string full = std::string(tc.group) + "." + tc.name;
        if (!filter.empty() && full.find(filter) == std::string::npos)
            continue;
        ++shown;

        ctx = Ctx{};
        g_ctx = &ctx;
        g_skip_requested = false;
        // unbuffered stderr trace: when a packed binary dies mid-suite this
        // names the exact test that killed the process
        std::fprintf(stderr, "[RUN ] %s.%s\n", tc.group, tc.name);
        std::fflush(stderr);
        try {
            tc.fn();
        } catch (const std::exception& e) {
            ctx.fail(std::string("UNEXPECTED EXCEPTION: ") + e.what());
        } catch (...) {
            ctx.fail("UNEXPECTED EXCEPTION (non-standard)");
        }
        g_ctx = nullptr;

        Status st;
        if (g_skip_requested)        { st = Status::Skipped; ++nskip; }
        else if (!ctx.fails.empty()) { st = Status::Failed;   ++nfail; }
        else                         { st = Status::Passed;   ++npass; }
        g_last = st;

        const char* tag =
            st == Status::Passed ? "[PASS]" :
            st == Status::Failed ? "[FAIL]" : "[SKIP]";
        out << tag << ' ' << full << '\n';
        if (!quiet_details || st == Status::Skipped) {
            for (const std::string& f : ctx.fails)
                out << "       " << f << '\n';
            if (st == Status::Skipped)
                out << "       skipped by request\n";
        }
        out.flush();
    }

    out << "SUMMARY passed=" << npass << " failed=" << nfail
        << " skipped=" << nskip << " total=" << shown << '\n';
    out.flush();
    return nfail;
}

bool list_tests(std::ostream& out) {
    for (const TestCase& tc : reg_tests())
        out << tc.group << '.' << tc.name << '\n';
    return !reg_tests().empty();
}

} // namespace fw
