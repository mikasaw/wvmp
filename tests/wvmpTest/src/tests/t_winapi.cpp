// t_winapi.cpp - file I/O round trips, memory-mapped files,
// VirtualAlloc/VirtualProtect interplay, dynamic API resolution,
// environment variables, HKCU registry sandboxing.
#include "../testfw.h"
#include "../common.h"

#include <winreg.h>          // excluded by WIN32_LEAN_AND_MEAN

#include <cstdio>
#include <string>
#include <vector>

using namespace wv;

static std::string g_temp_dir;

static bool temp_file_path(std::string& out) {
    if (g_temp_dir.empty()) {
        char buf[MAX_PATH];
        UINT n = ::GetTempPathA(sizeof(buf), buf);
        if (n == 0 || n >= sizeof(buf)) return false;
        g_temp_dir.assign(buf, n);
    }
    static LONG counter = 0;
    LONG seq = InterlockedIncrement(&counter);
    char name[64];
    snprintf(name, sizeof(name), "wvmp_t_%lu_%ld.tmp",
             (unsigned long)::GetCurrentProcessId(), (long)seq);
    out = g_temp_dir + name;
    return true;
}

// ---------------------------------------------------------------------------
TEST(win, file_write_read_append_cleanup) {
    std::string path;
    CHECK(temp_file_path(path));

    enum { MAIN_BYTES = 1u << 16 };              // 64 KB of deterministic noise
    std::vector<u8> blob(MAIN_BYTES);
    for (size_t i = 0; i < blob.size(); ++i) blob[i] = pattern_byte(i);

    HANDLE h = ::CreateFileA(path.c_str(), GENERIC_WRITE, 0, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(h != INVALID_HANDLE_VALUE);
    DWORD written = 0;
    CHECK(::WriteFile(h, blob.data(), (DWORD)blob.size(), &written, NULL));
    CHECK_EQ(written, (DWORD)MAIN_BYTES);
    CHECK(::CloseHandle(h));

    // SHARED reopen so the stdio stream below can coexist
    h = ::CreateFileA(path.c_str(),
                      GENERIC_READ | GENERIC_WRITE,
                      FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(h != INVALID_HANDLE_VALUE);
    std::vector<u8> back(MAIN_BYTES);
    DWORD got = 0;
    CHECK(::ReadFile(h, back.data(), MAIN_BYTES, &got, NULL));
    CHECK_EQ(got, (DWORD)MAIN_BYTES);
    CHECK(memcmp(blob.data(), back.data(), MAIN_BYTES) == 0);

    // append through stdio while our kernel handle stays open
    FILE* f = fopen(path.c_str(), "ab");
    CHECK(f != NULL);                            // needs the shared mode above
    const char tail_msg[] = "wvmp-tail";
    fwrite(tail_msg, 1, sizeof(tail_msg), f);
    fclose(f);

    LARGE_INTEGER sz;
    CHECK(::GetFileSizeEx(h, &sz));
    CHECK_EQ((size_t)sz.QuadPart, MAIN_BYTES + sizeof(tail_msg));

    char tail_back[16] = {};
    DWORD tail_got = 0;
    LONG high = 0;
    ::SetFilePointer(h, (LONG)MAIN_BYTES, &high, FILE_BEGIN);
    CHECK(::ReadFile(h, tail_back, sizeof(tail_back), &tail_got, NULL));
    CHECK(memcmp(tail_back, tail_msg, sizeof(tail_msg)) == 0);
    CHECK(::CloseHandle(h));

    CHECK(::DeleteFileA(path.c_str()));
}

TEST(win, stdio_then_kernel_writer_handoff) {
    std::string path;
    CHECK(temp_file_path(path));
    u8 buf[64];

    // stage 1: stdio creates and fills
    {   FILE* f = fopen(path.c_str(), "wb");
        CHECK(f != NULL);
        for (int i = 0; i < 64; ++i) buf[i] = pattern_byte((size_t)i * 3);
        fwrite(buf, 1, sizeof(buf), f);
        fclose(f);                               // durable before stage 2
    }
    // stage 2: raw kernel handle overwrites the very same 64-byte span
    {   u8 patch[64];
        for (int i = 0; i < 64; ++i) patch[i] = pattern_byte((size_t)i * 3 + 1);
        HANDLE h = ::CreateFileA(path.c_str(), GENERIC_WRITE, 0, NULL,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        CHECK(h != INVALID_HANDLE_VALUE);
        DWORD w = 0;
        CHECK(::WriteFile(h, patch, sizeof(patch), &w, NULL));
        CHECK_EQ(w, (DWORD)sizeof(patch));
        CHECK(::CloseHandle(h));
    }
    // stage 3: a fresh stdio view observes only the latest contents
    {   FILE* f = fopen(path.c_str(), "rb");
        CHECK(f != NULL);
        fread(buf, 1, sizeof(buf), f);
        long post = fgetc(f);
        fclose(f);
        CHECK_EQ(post, EOF);                     // exactly 64 bytes total
        for (int i = 0; i < 64; ++i)
            if (buf[i] != pattern_byte((size_t)i * 3 + 1)) {
                FAIL_AT(__FILE__, __LINE__, "kernel write must win stage 3");
                break;
            }
    }
    ::DeleteFileA(path.c_str());
}

TEST(win, mapped_file_reflection_and_remap) {
    std::string path;
    CHECK(temp_file_path(path));

    enum { MAP_BYTES = 4096 };
    HANDLE h = ::CreateFileA(path.c_str(),
                             GENERIC_READ | GENERIC_WRITE, 0,
                             NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(h != INVALID_HANDLE_VALUE);
    LARGE_INTEGER sz;
    sz.QuadPart = MAP_BYTES;
    CHECK(::SetFilePointerEx(h, sz, NULL, FILE_BEGIN));
    CHECK(::SetEndOfFile(h));

    HANDLE map = ::CreateFileMappingA(h, NULL, PAGE_READWRITE, 0, 0, NULL);
    CHECK(map != NULL);
    u8* view = (u8*)::MapViewOfFile(map, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    CHECK(view != NULL);
    for (int i = 0; i < MAP_BYTES; ++i)
        view[i] = pattern_byte((size_t)i * 5 + 7);
    u32 before = fnv1a32_buf(view, MAP_BYTES);
    view[123] ^= 0x55;
    CHECK(fnv1a32_buf(view, MAP_BYTES) != before);
    CHECK(::UnmapViewOfFile(view));
    CHECK(::CloseHandle(map));

    map = ::CreateFileMappingA(h, NULL, PAGE_READONLY, 0, 0, NULL);
    CHECK(map != NULL);
    const u8* rv = (const u8*)::MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
    CHECK(rv != NULL);
    u8 ref[MAP_BYTES];
    for (int i = 0; i < MAP_BYTES; ++i)
        ref[i] = pattern_byte((size_t)i * 5 + 7);
    ref[123] ^= 0x55;
    CHECK(memcmp(rv, ref, MAP_BYTES) == 0);      // mutation persisted to disk
    CHECK(::UnmapViewOfFile(rv));
    CHECK(::CloseHandle(map));
    CHECK(::CloseHandle(h));

    CHECK(::DeleteFileA(path.c_str()));
}

// SEH-friendly POD zone ------------------------------------------------------
static volatile long g_vp_fault_code = -1;

static void vp_write_probe(u8* p) {
    __try {
        p[10] = 0xAB;                            // page should be READONLY here
    } __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION
                    ? EXCEPTION_EXECUTE_HANDLER
                    : EXCEPTION_CONTINUE_SEARCH) {
        g_vp_fault_code = (long)GetExceptionCode();
    }
}

TEST(win, virtualalloc_protect_cycle) {
    SYSTEM_INFO si;
    ::GetSystemInfo(&si);
    const SIZE_T SPAN = si.dwPageSize * 3;

    u8* mem = (u8*)::VirtualAlloc(NULL, SPAN, MEM_RESERVE | MEM_COMMIT,
                                  PAGE_READWRITE);
    CHECK(mem != NULL);

    u64 sum = 0;
    for (SIZE_T i = 0; i < SPAN; ++i) { mem[i] = (u8)(i ^ 0x3Cu); sum += mem[i]; }
    CHECK(sum != 0);

    DWORD old_protect = 0;
    CHECK(::VirtualProtect(mem, si.dwPageSize, PAGE_READONLY, &old_protect));
    CHECK_EQ(old_protect, (DWORD)PAGE_READWRITE);

    g_vp_fault_code = -1;
    vp_write_probe(mem);                         // contained AV probe
    CHECK_EQ(g_vp_fault_code, (long)EXCEPTION_ACCESS_VIOLATION);

    CHECK(::VirtualProtect(mem, si.dwPageSize, PAGE_READWRITE, &old_protect));
    CHECK_EQ(old_protect, (DWORD)PAGE_READONLY);
    mem[10] = 0x77;                              // writable again
    CHECK_EQ(mem[10], 0x77);

    MEMORY_BASIC_INFORMATION mbi;
    CHECK(::VirtualQuery(mem, &mbi, sizeof(mbi)) == sizeof(mbi));
    CHECK(mbi.State == MEM_COMMIT);
    CHECK(mbi.Protect == PAGE_READWRITE);

    CHECK(::VirtualFree(mem, 0, MEM_RELEASE));
}

TEST(win, dynamic_module_resolution) {
    HMODULE user32 = ::LoadLibraryW(L"user32.dll");
    if (!user32) {
        fw::mark_skipped();
        return;
    }
    // WINAPI (= __stdcall on x86) is REQUIRED here: these exports clean
    // their own stack - a plain cdecl pointer works on x64 but corrupts the
    // stack (and trips /RTC1) on Win32.
    typedef wchar_t* (WINAPI *pfn_charupper)(wchar_t*);
    pfn_charupper up = (pfn_charupper)::GetProcAddress(user32, "CharUpperW");
    CHECK(up != NULL);
    if (up) {
        wchar_t buf[] = L"aBc9-=z";
        wchar_t* res = up(buf);
        CHECK(res == buf);                       // in-place API returns same ptr
        CHECK(wcscmp(buf, L"ABC9-=Z") == 0);     // letters flipped, rest intact
    }
    ::FreeLibrary(user32);

    HMODULE k32 = ::GetModuleHandleW(L"kernel32.dll");
    CHECK(k32 != NULL);
    FARPROC mkf = ::GetProcAddress(k32, "CreateFileW");
    CHECK(mkf != NULL);                          // resolution alone, never called

    HMODULE self = NULL;
    CHECK(::GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                   GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCSTR)&temp_file_path, &self));
    CHECK(self != NULL);
}

TEST(win, environment_variable_roundtrip) {
    CHECK(::SetEnvironmentVariableW(L"WVMP_TEST_ENV", L"value=XyZ_789"));
    wchar_t got[128];
    DWORD n = ::GetEnvironmentVariableW(L"WVMP_TEST_ENV", got, 128);
    CHECK(n > 0 && n < 128);
    CHECK(wcscmp(got, L"value=XyZ_789") == 0);

    // undersized buffers report the space they actually need (incl. NUL)
    wchar_t tiny[4];
    DWORD need = ::GetEnvironmentVariableW(L"WVMP_TEST_ENV", tiny, 4);
    CHECK_MSG(need == n + 1, "required-size contract");

    CHECK(::SetEnvironmentVariableW(L"WVMP_TEST_ENV", NULL));
    n = ::GetEnvironmentVariableW(L"WVMP_TEST_ENV", got, 128);
    CHECK(n == 0);
    CHECK(::GetLastError() == ERROR_ENVVAR_NOT_FOUND);
}

TEST(win, hkcu_registry_typed_values) {
    static const char* BASE = "Software\\WVmpTest";
    HKEY hk = NULL;
    LONG r = ::RegCreateKeyExA(HKEY_CURRENT_USER, BASE, 0, NULL,
                               REG_OPTION_NON_VOLATILE,
                               KEY_SET_VALUE | KEY_QUERY_VALUE,
                               NULL, &hk, NULL);
    if (r != ERROR_SUCCESS) {
        fw::mark_skipped();                      // sandboxed environments etc.
        return;
    }

    static const char msg[] = "hello-wvmp-registry";
    DWORD dval = 123456789u;
    u64 qval = 0x1122334455667788ull;

    CHECK(::RegSetValueExA(hk, "txt", 0, REG_SZ,
                           (const BYTE*)msg, (DWORD)sizeof(msg)) == ERROR_SUCCESS);
    CHECK(::RegSetValueExA(hk, "num32", 0, REG_DWORD,
                           (const BYTE*)&dval, sizeof(dval)) == ERROR_SUCCESS);
    CHECK(::RegSetValueExA(hk, "num64", 0, REG_QWORD,
                           (const BYTE*)&qval, sizeof(qval)) == ERROR_SUCCESS);

    char txt[64];
    DWORD cb = sizeof(txt), type = 0;
    CHECK(::RegQueryValueExA(hk, "txt", NULL, &type, (BYTE*)txt, &cb)
          == ERROR_SUCCESS);
    CHECK(type == REG_SZ && strcmp(txt, msg) == 0);

    DWORD got32 = 0;
    cb = sizeof(got32);
    CHECK(::RegQueryValueExA(hk, "num32", NULL, &type, (BYTE*)&got32, &cb)
          == ERROR_SUCCESS);
    CHECK(type == REG_DWORD);
    CHECK(got32 == dval);

    u64 got64 = 0;
    cb = sizeof(got64);
    CHECK(::RegQueryValueExA(hk, "num64", NULL, &type, (BYTE*)&got64, &cb)
          == ERROR_SUCCESS);
    CHECK(type == REG_QWORD);
    CHECK(got64 == qval);

    ::RegCloseKey(hk);

    LONG del = ::RegDeleteTreeA(HKEY_CURRENT_USER, BASE);
    CHECK(del == ERROR_SUCCESS || del == ERROR_FILE_NOT_FOUND);
}
