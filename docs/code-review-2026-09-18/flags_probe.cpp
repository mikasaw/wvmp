#include "wvmp/regvm/translator/translator.hpp"
#include "wvmp/regvm/isa/encoding.hpp"
#include "wvmp/regvm/runtime/runtime.hpp"
#include <windows.h>
#include <cstring>
#include <iostream>
using namespace wvmp;
namespace isa=regvm::isa;
namespace rt=regvm::runtime;
ir::Insn op(ir::Op o,ir::Reg d,ir::Operand s) {
    ir::Insn i; i.op=o; i.size=ir::Size::S32;
    i.dst=ir::Operand::reg_(d); i.src=s;
    i.updates_flags=(o==ir::Op::Cmp || o==ir::Op::Shl); return i;
}
int main() {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    ir::FunctionRegion fn; fn.name="zero_shift_flags"; fn.arch=ir::Arch::X64;
    fn.begin_rva=0x1000; fn.end_rva=0x1100;
    ir::BasicBlock b; b.addr=fn.begin_rva;
    b.insns={op(ir::Op::Mov,ir::Reg::Rax,ir::Operand::imm_(0)),
             op(ir::Op::Mov,ir::Reg::Rcx,ir::Operand::imm_(0)),
             op(ir::Op::Cmp,ir::Reg::Rax,ir::Operand::imm_(0)),
             op(ir::Op::Shl,ir::Reg::Rdx,ir::Operand::reg_(ir::Reg::Rcx))};
    ir::Insn set; set.op=ir::Op::Setcc; set.size=ir::Size::S8;
    set.cond=ir::Cond::E; set.dst=ir::Operand::reg_(ir::Reg::Rax);
    b.insns.push_back(set); fn.blocks.push_back(b);
    auto translated=regvm::translator::translate_function(fn);
    std::cout << "notes=" << translated.notes.size() << '\n';
    auto& blob=translated.program.bytecode;
    for(size_t o=32;o+8<=blob.size();o+=8) {
        u64 word; std::memcpy(&word,blob.data()+o,8);
        auto ins=isa::decode(word);
        std::cout << isa::to_string(ins.op) << " cond_or_size=" << int(ins.cond_or_size) << '\n';
    }
    Rng rng(12345); auto runtime=rt::generate_runtime(rng);
    auto& code=runtime.image.code;
    void* mem=VirtualAlloc(nullptr,code.size(),MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if(!mem) return 2;
    std::memcpy(mem,code.data(),code.size()); DWORD old;
    if(!VirtualProtect(mem,code.size(),PAGE_EXECUTE_READ,&old)) return 3;
    FlushInstructionCache(GetCurrentProcess(),mem,code.size());
    rt::VmContext ctx; ctx.bytecode=blob.data()+32;
    reinterpret_cast<void(*)(rt::VmContext*)>(static_cast<u8*>(mem)+runtime.image.vm_entry_offset)(&ctx);
    std::cout << "ZERO_SHIFT expected_eax=1 actual_eax=" << ctx.regs[0] << '\n';
    VirtualFree(mem,0,MEM_RELEASE);
}
