#include "stub_gen.hpp"

#include "wvmp/regvm/runtime/runtime.hpp"

#include <keystone/keystone.h>

#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <utility>

namespace wvmp::passes {
namespace {

std::string hex(u64 v) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(v));
    return std::string(buf);
}

// VmContext 常量
constexpr u64 kCtxRegs = 0x10;      // regs[0]
constexpr u64 kCtxRsp = 0x30;       // regs[4]
constexpr u64 kCtxScratch = 0x110;
constexpr u64 kCtxNativeSp = 0x120;
using wvmp::regvm::runtime::kCtxSize;
using wvmp::regvm::runtime::kCtxXmmBase;

constexpr u32 kBlobDispDummy = 0xDEAD'0001;
constexpr u64 kStubPushBytes = wvmp::regvm::runtime::kCalleeSavedIdx.size() * 8;

// MIT-407: ExitNative 退出槽
// Use offset 0x80 (disp8 fits in -128..127 range) — keystone Intel
// parser truncates larger negative displacements (实测 0x10000 → 0x1000).
constexpr u64 kExitSlotHandlerOff = 0x80;
constexpr u64 kExitSlotFinalOff = kCtxSize + 8 * 8 + kExitSlotHandlerOff;

std::string build_stub_asm(u64 rt_entry_rva, u64 resume_rva, u64 image_base) {
    std::string o;
    o += "push rbx\n push rbp\n push rdi\n push rsi\n";
    o += "push r12\n push r13\n push r14\n push r15\n";
    o += "sub rsp, " + hex(kCtxSize) + "\n";
    for (int i = 0; i < 16; ++i) {
        const char* src = nullptr;
        switch (i) {
            case 0: src = "rax"; break;
            case 1: src = "rcx"; break;
            case 2: src = "rdx"; break;
            case 3: src = "rbx"; break;
            case 4: continue;
            case 5: src = "rbp"; break;
            case 6: src = "rsi"; break;
            case 7: src = "rdi"; break;
            default: src = nullptr; break;
        }
        if (i >= 8) {
            o += std::string("mov [rsp + ") + hex(kCtxRegs + u64(i) * 8) + "], r" +
                 std::to_string(i) + "\n";
        } else {
            o += std::string("mov [rsp + ") + hex(kCtxRegs + u64(i) * 8) + "], " + src + "\n";
        }
    }
    o += "lea rax, [rsp + " + hex(kStubPushBytes + kCtxSize) + "]\n";
    o += "mov [rsp + " + hex(kCtxRsp) + "], rax\n";
    o += "mov [rsp + " + hex(kCtxNativeSp) + "], rax\n";
    o += "mov rax, " + hex(image_base) + "\n";
    o += "mov qword ptr [rsp + " + hex(kCtxScratch) + "], rax\n";
    o += "mov qword ptr [rsp + 0x8], 0\n";
    o += "lea rax, [rip + " + hex(kBlobDispDummy) + "]\n";
    o += "mov [rsp], rax\n";
    for (int i = 0; i < 8; ++i) {
        o += std::string("movups [rsp + ") + hex(kCtxXmmBase + u64(i) * 16) +
             "], xmm" + std::to_string(i) + "\n";
    }
    o += "mov rcx, rsp\n";
    o += "call " + hex(rt_entry_rva) + "\n";
    for (const auto& [slot, reg] : {
             std::pair<u64, const char*>{kCtxRegs + 0 * 8, "rax"},
             {kCtxRegs + 1 * 8, "rcx"},
             {kCtxRegs + 2 * 8, "rdx"},
             {kCtxRegs + 8 * 8, "r8"},
             {kCtxRegs + 9 * 8, "r9"},
             {kCtxRegs + 10 * 8, "r10"},
             {kCtxRegs + 11 * 8, "r11"},
         }) {
        o += std::string("mov ") + reg + ", [rsp + " + hex(slot) + "]\n";
    }
    for (int i = 0; i < 8; ++i) {
        o += std::string("movups xmm") + std::to_string(i) + ", [rsp + " +
             hex(kCtxXmmBase + u64(i) * 16) + "]\n";
    }
    o += "add rsp, " + hex(kCtxSize) + "\n";
    o += "pop r15\n pop r14\n pop r13\n pop r12\n";
    o += "pop rsi\n pop rdi\n pop rbp\n pop rbx\n";
    o += "jmp " + hex(resume_rva) + "\n";
    return o;
}

} // namespace

std::vector<u8> generate_entry_stub(u64 stub_rva, u64 blob_stream_rva, u64 rt_entry_rva,
                                    u64 resume_rva, u64 image_base) {
    ks_engine* ks = nullptr;
    if (ks_open(KS_ARCH_X86, KS_MODE_64, &ks) != KS_ERR_OK)
        throw std::runtime_error("stub_link: ks_open failed");
    ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_INTEL);

    const std::string src = build_stub_asm(rt_entry_rva, resume_rva, image_base);
    {
        char* dp = nullptr;
        size_t dp_len = 0;
        if (_dupenv_s(&dp, &dp_len, "WVMP_STUB_DUMP") == 0 && dp && dp_len > 1) {
            FILE* f = nullptr;
            if (fopen_s(&f, dp, "wb") == 0 && f) {
                std::fwrite(src.data(), 1, src.size(), f);
                std::fclose(f);
            }
        }
        std::free(dp);
    }
    unsigned char* enc = nullptr;
    size_t size = 0, count = 0;
    const int rc = ks_asm(ks, src.c_str(), stub_rva, &enc, &size, &count);
    std::vector<u8> code;
    if (rc == 0 && enc) code.assign(enc, enc + size);
    const ks_err err = ks_errno(ks);
    if (enc) ks_free(enc);
    ks_close(ks);
    if (rc != 0)
        throw std::runtime_error("stub_link: ks_asm failed errno=" + std::to_string(int(err)) +
                                 " stmt#" + std::to_string(count));

    const u8 pat[4] = {u8(kBlobDispDummy & 0xFF), u8((kBlobDispDummy >> 8) & 0xFF),
                       u8((kBlobDispDummy >> 16) & 0xFF), u8((kBlobDispDummy >> 24) & 0xFF)};
    size_t found = SIZE_MAX;
    for (size_t i = 0; i + 4 <= code.size(); ++i) {
        if (code[i] == pat[0] && code[i + 1] == pat[1] && code[i + 2] == pat[2] &&
            code[i + 3] == pat[3]) {
            found = i;
            break;
        }
    }
    if (found == SIZE_MAX)
        throw std::runtime_error("stub_link: blob disp placeholder not found in stub code");
    const u64 next_rip = stub_rva + (found - 3) + 7;
    const i64 disp = static_cast<i64>(blob_stream_rva) - static_cast<i64>(next_rip);
    const u32 disp_u = static_cast<u32>(disp);
    for (int b = 0; b < 4; ++b)
        code[found + b] = u8((disp_u >> (8 * b)) & 0xFF);
    return code;
}

} // namespace wvmp::passes
