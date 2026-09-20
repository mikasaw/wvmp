#include "output_publish.hpp"

#include <atomic>
#include <cstdio>
#include <random>
#include <string>

#ifdef _WIN32
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

} // namespace wvmp::passes
