// main.cpp - entry point, CLI parsing, run report.
//
// Usage:
//   test_target.exe                run everything, print results, rc=0 on success
//   test_target.exe --list         enumerate registered tests, exit 0
//   test_target.exe --filter=SUB   run only tests whose "group.name" contains SUB
//   test_target.exe --quiet        hide per-check failure details (single-line verdicts)
//   test_target.exe --log=FILE     additionally mirror all output into FILE
//   test_target.exe --compact      omit environment banner (stable output for diffing)
#include "testfw.h"
#include "common.h"

#include <fstream>
#include <iostream>
#include <sstream>

typedef LONG(WINAPI* PFN_RtlGetVersion)(PRTL_OSVERSIONINFOW);

static std::string os_version_string() {
    HMODULE hNt = ::GetModuleHandleW(L"ntdll.dll");
    if (hNt) {
        PFN_RtlGetVersion pfn =
            (PFN_RtlGetVersion)::GetProcAddress(hNt, "RtlGetVersion");
        if (pfn) {
            RTL_OSVERSIONINFOW vi = {};
            vi.dwOSVersionInfoSize = sizeof(vi);
            if (pfn(&vi) == 0)
                return std::to_string(vi.dwMajorVersion) + "." +
                       std::to_string(vi.dwMinorVersion) + "." +
                       std::to_string(vi.dwBuildNumber);
        }
    }
    return "unknown";
}

struct Options {
    std::string filter;
    std::string log_path;
    bool quiet = false;
    bool compact = false;
    bool list = false;
};

static Options parse_args(int argc, char** argv) {
    Options o;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a.rfind("--filter=", 0) == 0) o.filter = a.substr(9);
        else if (a.rfind("--log=", 0) == 0) o.log_path = a.substr(6);
        else if (a == "--quiet") o.quiet = true;
        else if (a == "--compact") o.compact = true;
        else if (a == "--list") o.list = true;
        // unknown args ignored on purpose
    }
    return o;
}

class TeeBuf : public std::streambuf {
public:
    TeeBuf(std::streambuf* a, std::streambuf* b) : a_(a), b_(b) {}
protected:
    int overflow(int c) override {
        if (c != EOF) { a_->sputc((char)c); b_->sputc((char)c); }
        return c;
    }
    int sync() override { a_->pubsync(); return b_->pubsync(); }
private:
    std::streambuf *a_, *b_;
};

int main(int argc, char** argv) {
    Options opt = parse_args(argc, argv);

    std::ofstream log_file;
    std::ostream* sink_ptr = &std::cout;
    std::ostringstream captured;
    if (!opt.log_path.empty()) {
        log_file.open(opt.log_path.c_str(), std::ios::binary | std::ios::trunc);
        if (log_file.is_open()) {
            static TeeBuf tee(std::cout.rdbuf(), log_file.rdbuf());
            std::cout.flush();
            static std::ostream tee_stream(&tee);
            sink_ptr = &tee_stream;
        }
    }
    std::ostream& out = *sink_ptr;

    if (opt.list) {
        fw::list_tests(out);
        out.flush();
        return 0;
    }

    if (!opt.compact) {
        char exe[MAX_PATH] = {};
        ::GetModuleFileNameA(NULL, exe, MAX_PATH);
        out << "==== WVmp functional target ====\n"
            << "image   : " << exe << "\n"
            << "arch    : " << (sizeof(void*) == 8 ? "x64" : "x86")
            << " (ptr=" << sizeof(void*) << ")\n"
            << "os      : Windows " << os_version_string() << "\n"
            << "built   : " << __DATE__ << ' ' << __TIME__ << "\n"
            << "--------------------------------\n";
    }

    int failures = fw::run_all(opt.filter, out, opt.quiet);

    if (!opt.compact)
        out << "--------------------------------\n";

    out.flush();
    return failures == 0 ? 0 : 1;
}
