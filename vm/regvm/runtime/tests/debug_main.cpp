// 手工追踪辅助（不入构建）：固定种子生成，运行最小程序，打印上下文。
#include "wvmp/regvm/runtime/runtime.hpp"

#include "wvmp/common/rng.hpp"
#include "wvmp/regvm/isa/encoding.hpp"
#include "wvmp/regvm/isa/vm_op.hpp"

#include <windows.h>

#include <cstdio>
#include <cstring>
#include <vector>

namespace isa = wvmp::regvm::isa;
namespace rt = wvmp::regvm::runtime;
using wvmp::u8;
using wvmp::u64;

int main() {
    wvmp::Rng rng(0xC0FFEE);
    auto result = rt::generate_runtime(rng);
    printf("code=%zu bytes\n", result.image.code.size());
    {
        FILE* f = nullptr;
        if (fopen_s(&f, "C:/Users/www/AppData/Local/Temp/code.bin", "wb") == 0 && f) {
            std::fwrite(result.image.code.data(), 1, result.image.code.size(), f);
            std::fclose(f);
        }
    }

    void* mem = VirtualAlloc(nullptr, result.image.code.size(), MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);
    std::memcpy(mem, result.image.code.data(), result.image.code.size());

    alignas(16) u8 scratch[0x10000] = {};

    // 程序 1：mov r0,77 ; halt
    {
        std::vector<u8> s;
        isa::append_insn(s, isa::make_insn(isa::VmOp::Mov, isa::OpKind::Reg, 0,
                                           isa::OpKind::Imm, 0, 77, 3));
        isa::append_insn(s, isa::make_insn(isa::VmOp::Halt, isa::OpKind::None, 0,
                                           isa::OpKind::None, 0));
        rt::VmContext ctx;
        ctx.bytecode = s.data();
        ctx.pc = 0;
        ctx.scratch_mem = reinterpret_cast<u64>(scratch);
        reinterpret_cast<void (*)(rt::VmContext*)>(mem)(&ctx);
        printf("P1: pc=%llu r0=%llu ret=%llu\n", (unsigned long long)ctx.pc,
               (unsigned long long)ctx.regs[0], (unsigned long long)ctx.ret_value);
    }

    // 程序 2：两条 mov
    {
        std::vector<u8> s;
        isa::append_insn(s, isa::make_insn(isa::VmOp::Mov, isa::OpKind::Reg, 0,
                                           isa::OpKind::Imm, 0, 77, 3));
        isa::append_insn(s, isa::make_insn(isa::VmOp::Mov, isa::OpKind::Reg, 1,
                                           isa::OpKind::Imm, 0, 33, 3));
        isa::append_insn(s, isa::make_insn(isa::VmOp::Halt, isa::OpKind::None, 0,
                                           isa::OpKind::None, 0));
        rt::VmContext ctx;
        ctx.bytecode = s.data();
        ctx.pc = 0;
        ctx.scratch_mem = reinterpret_cast<u64>(scratch);
        reinterpret_cast<void (*)(rt::VmContext*)>(mem)(&ctx);
        printf("P2: pc=%llu r0=%llu r1=%llu\n", (unsigned long long)ctx.pc,
               (unsigned long long)ctx.regs[0], (unsigned long long)ctx.regs[1]);
    }

    // 程序 3：mov + add reg,reg
    {
        std::vector<u8> s;
        isa::append_insn(s, isa::make_insn(isa::VmOp::Mov, isa::OpKind::Reg, 0,
                                           isa::OpKind::Imm, 0, 77, 3));
        isa::append_insn(s, isa::make_insn(isa::VmOp::Mov, isa::OpKind::Reg, 1,
                                           isa::OpKind::Imm, 0, 33, 3));
        isa::append_insn(s, isa::make_insn(isa::VmOp::Add, isa::OpKind::Reg, 0,
                                           isa::OpKind::Reg, 1, 0, 3));
        isa::append_insn(s, isa::make_insn(isa::VmOp::Halt, isa::OpKind::None, 0,
                                           isa::OpKind::None, 0));
        rt::VmContext ctx;
        ctx.bytecode = s.data();
        ctx.pc = 0;
        ctx.scratch_mem = reinterpret_cast<u64>(scratch);
        reinterpret_cast<void (*)(rt::VmContext*)>(mem)(&ctx);
        printf("P3: pc=%llu r0=%llu r1=%llu (want r0=110)\n", (unsigned long long)ctx.pc,
               (unsigned long long)ctx.regs[0], (unsigned long long)ctx.regs[1]);
    }
    return 0;
}
