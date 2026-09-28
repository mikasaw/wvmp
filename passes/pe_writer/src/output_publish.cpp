#include "output_publish.hpp"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <random>
#include <string>
#include <system_error>
#include <vector>

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

bool verify_written_image(const std::filesystem::path& tmp,
                          const unsigned char* expect_data,
                          std::size_t expect_size,
                          std::string& err) {
    std::ifstream in(tmp, std::ios::binary);
    if (!in) {
        err = "读回打开失败: " + tmp.string();
        return false;
    }
    // 分块读回 + 比对，首个差异字节即报（镜像几 MB 量级，无需整体驻留双份）。
    constexpr std::streamsize kChunk = 1 << 16;
    std::vector<unsigned char> buf(static_cast<std::size_t>(kChunk));
    std::size_t off = 0;
    while (off < expect_size) {
        const std::size_t want = std::min(kChunk, static_cast<std::streamsize>(expect_size - off));
        in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(want));
        if (in.gcount() != static_cast<std::streamsize>(want)) {
            err = "读回短读 @" + std::to_string(off) + " (got " +
                  std::to_string(in.gcount()) + " want " + std::to_string(want) + ")";
            return false;
        }
        if (std::memcmp(buf.data(), expect_data + off, want) != 0) {
            for (std::size_t i = 0; i < want; ++i) {
                if (buf[i] != expect_data[off + i]) {
                    char where[32];
                    std::snprintf(where, sizeof(where), "%zx", off + i);
                    err = std::string("首处差异 @ 0x") + where + " (disk " +
                          std::to_string(buf[i]) + " != image " +
                          std::to_string(expect_data[off + i]) + ")";
                    return false;
                }
            }
        }
        off += want;
    }
    // 末尾还有多余字节 = 也不是这份镜像（长度核已在调用方做过，此处兜底）。
    unsigned char extra = 0;
    if (in.read(reinterpret_cast<char*>(&extra), 1) && in.gcount() == 1) {
        char where[32];
        std::snprintf(where, sizeof(where), "%zx", expect_size);
        err = std::string("读回多出字节 @ 0x") + where;
        return false;
    }
    return true;
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
