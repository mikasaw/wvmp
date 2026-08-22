#pragma once
#include "wvmp/common/rng.hpp"
#include "wvmp/framework/context.hpp"
#include "wvmp/ir/region.hpp"
#include <memory>
#include <string_view>
#include <vector>
namespace wvmp::vm {
class BytecodeCodec {
public:
    virtual ~BytecodeCodec() = default;
    virtual std::string_view name() const = 0;
    virtual void encrypt_stream(Rng& rng, std::vector<u8>& bytecode) = 0;
    virtual void emit_decrypt(std::string& interpreter_src) = 0;
};
struct VmProgram { std::vector<u8> bytecode; u64 entry_offset = 0; };
struct RuntimeImage { std::vector<u8> code; u64 vm_entry_offset = 0; };
class VMBackend {
public:
    virtual ~VMBackend() = default;
    virtual std::string_view name() const = 0;
    virtual void set_codec(BytecodeCodec* codec) = 0;
    virtual VmProgram compile(const ir::FunctionRegion& fn, ProtectionContext& ctx) = 0;
    virtual RuntimeImage generate_runtime(const VmProgram& prog, ProtectionContext& ctx) = 0;
};
std::unique_ptr<VMBackend> create_backend(std::string_view name); // 未知名返回 nullptr（实现归 regvm）
}
