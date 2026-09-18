#include "wvmp/passes/pe_loader/pe_image.hpp"
#include "section_builder.hpp"
#include "wvmp/framework/context.hpp"
#include "wvmp/framework/protect_levels.hpp"
#include "wvmp/passes/crypt/crypt_pass.hpp"
#include "wvmp/passes/crypt/crypt_plan.hpp"
#include "wvmp/passes/virtualize/virtualize_pass.hpp"
#include "wvmp/cli/config.hpp"
#include "wvmp/regvm/isa/blob.hpp"
#include "wvmp/regvm/isa/vm_op.hpp"
#include <cstring>
#include <fstream>
#include <iostream>

using namespace wvmp;
using namespace wvmp::passes;
void put(std::vector<u8>& v, size_t o, u64 n, int w=4) {
    for (int i=0; i<w; ++i) v[o+i]=u8(n>>(8*i));
}
std::vector<u8> pe(bool plus) {
    std::vector<u8> v(0x600);
    const size_t nt=0x40, opt=nt+24, os=plus?240:224, sh=opt+os;
    put(v,0,0x5a4d,2); put(v,0x3c,nt); put(v,nt,0x4550);
    put(v,nt+4,plus?0x8664:0x14c,2); put(v,nt+6,1,2);
    put(v,nt+20,os,2); put(v,opt,plus?0x20b:0x10b,2);
    put(v,opt+(plus?24:28),0x400000,plus?8:4);
    put(v,opt+32,0x1000); put(v,opt+36,0x200);
    put(v,opt+56,0x2000); put(v,opt+60,0x400);
    put(v,opt+(plus?108:92),16);
    std::memcpy(v.data()+sh,".text",5);
    put(v,sh+8,0x200); put(v,sh+12,0x1000);
    put(v,sh+16,0x200); put(v,sh+20,0x400); put(v,sh+36,0x60000020);
    return v;
}
NewSection section(const char* name,u32 rva) {
    NewSection s; s.name=name; s.requested_rva=rva;
    s.data.assign(0x100,0xcc); s.characteristics=0x60000020; return s;
}
int main() {
    {
        std::ofstream c("name_rule.toml");
        c << "input='input.exe'\noutput='output.exe'\ndefault_level='none'\n"
             "[[functions]]\nname='target'\nlevel='virtualize'\n";
        c.close();
        auto parsed=cli::parse_config("name_rule.toml");
        std::cout << "NAME_RULE parse_ok=" << parsed.ok
                  << " expected=virtualize actual="
                  << to_string(parsed.value.rules.level_for(0x1000,0)) << '\n';
    }
    {
        ProtectionContext c;
        ir::FunctionRegion a,b,d;
        a.name="A"; a.begin_rva=0x1000;
        b.name="B"; b.begin_rva=0x2000;
        d.name="C"; d.begin_rva=0x3000;
        c.functions={a,b,d}; // A was skipped by virtualize; original indexes B=1, C=2.
        auto& v=c.slot<std::vector<VirtualizedFunction>>(kVmProgram);
        for(auto* f : {&b,&d}) {
            VirtualizedFunction vf; vf.name=f->name; vf.begin_rva=f->begin_rva;
            std::vector<u8> stream(8,0);
            put(stream,0,static_cast<u16>(regvm::isa::VmOp::Halt),2);
            auto blob=regvm::isa::make_blob(ir::Arch::X64,0,std::move(stream));
            ByteWriter writer(vf.program.bytecode);
            regvm::isa::write_blob(writer,blob);
            v.push_back(vf);
        }
        FunctionProtectRule rule; rule.has_index=true; rule.index=1;
        rule.has_crypt=true; rule.crypt=false;
        c.slot<ProtectRules>(kProtectRules).functions.push_back(rule);
        CryptPass{}.run(c);
        std::cout << "CRYPT_INDEX expected_encrypted=C actual_encrypted=";
        for(const auto& f:c.find_slot<crypt::CryptPlan>(kCryptPlan)->functions)
            std::cout << f.name;
        std::cout << '\n';
    }
    for(bool plus:{false,true}) {
        auto v=pe(plus);
        const size_t dd=0x58+(plus?112:96)+3*8;
        put(v,dd,0x1000); put(v,dd+4,12);
        put(v,0x400,0x1100); put(v,0x404,0x1180); put(v,0x408,0x1190);
        const auto m=parse_pe_image(v);
        std::cout << "PDATA " << (plus?"PE32+":"PE32")
                  << " expected=1 actual=" << m.pdata.size()
                  << " empty=" << m.pdata_empty << '\n';
    }
    {
        auto v=pe(true);
        auto p=add_sections(v,{section(".auto",0),section(".fixed",0x3000)},0x1000,0x200);
        std::cout << "SECTIONS auto_then_fixed expected=2000,3000 actual="
                  << std::hex << p[0].rva << ',' << p[1].rva << std::dec << '\n';
    }
    {
        // PE32+ declares no directories. Bytes in the otherwise unused area
        // must not become an active exception directory.
        auto v=pe(true); put(v,0x58+108,0);
        put(v,0x58+112+24,0x1000); put(v,0x58+112+28,12);
        put(v,0x400,0x1100); put(v,0x404,0x1180); put(v,0x408,0x1190);
        std::cout << "DIRECTORY_COUNT zero expected_pdata=0 actual_pdata="
                  << parse_pe_image(v).pdata.size() << '\n';
    }
}
