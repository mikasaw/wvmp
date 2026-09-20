#include "output_publish.hpp"

#include <atomic>
#include <cstdio>
#include <random>
#include <string>
#include <system_error>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <process.h>
#else
#include <unistd.h>
#endif

namespace wvmp::passes {
namespace {

long current_pid() {
#ifdef _WIN32
    return static_cast<long>(_getpid());
#else
    return static_cast<long>(::getpid());
#endif
}

unsigned long long random_tail() {
    thread_local std::mt19937_64 rng{std::random_device{}()};
    return rng();
}

} // namespace

std::filesystem::path make_temp_output_path(const std::filesystem::path& target) {
    static std::atomic<unsigned long> seq{0};
    std::string name = target.filename().string();
    name += ".wvmp-tmp-";
    name += std::to_string(current_pid());
    name += '-';
    name += std::to_string(seq.fetch_add(1));
    char tail[17];
    std::snprintf(tail, sizeof(tail), "%016llx", random_tail());
    name += '-';
    name += tail;
    return target.parent_path() / std::filesystem::path(name);
}

bool publish_atomic_output(const std::filesystem::path& tmp,
                           const std::filesystem::path& target, std::string& err) {
#ifdef _WIN32
    // 同一目录内 MoveFileExW(REPLACE_EXISTING) 是内核级单次替换：目标要么
    // 整体是旧产物、要么整体是新产物，没有"已经没有了"的窗口。
    const BOOL ok = MoveFileExW(tmp.c_str(), target.c_str(),
                                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    if (ok) return true;
    err = std::error_code(static_cast<int>(::GetLastError()), std::system_category()).message();
    return false;
#else
    // POSIX rename 本身就是原子替换。
    std::error_code ec;
    std::filesystem::rename(tmp, target, ec);
    if (!ec) return true;
    err = ec.message();
    return false;
#endif
}

} // namespace wvmp::passes
