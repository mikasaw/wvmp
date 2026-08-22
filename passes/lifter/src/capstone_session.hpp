// capstone 会话封装（lifter 私有，不属于契约）。
//
// 负责 CS_ARCH_X86 + CS_MODE_64/CS_MODE_32 会话的 cs_open/cs_close RAII
// 管理、detail 模式常开，以及基于 cs_disasm_iter 的逐条反汇编迭代接口。
#pragma once

#include "wvmp/common/types.hpp"
#include "wvmp/ir/arch.hpp"

#include <capstone/capstone.h>

namespace wvmp::passes::lifter {

class CapstoneSession {
public:
    // 按 arch 打开 CS_MODE_64 / CS_MODE_32 会话；失败抛 std::runtime_error。
    explicit CapstoneSession(ir::Arch arch);

    // cs_close 释放句柄与 cs_malloc 分配的指令缓冲。
    ~CapstoneSession();

    CapstoneSession(const CapstoneSession&) = delete;
    CapstoneSession& operator=(const CapstoneSession&) = delete;

    CapstoneSession(CapstoneSession&& other) noexcept;
    CapstoneSession& operator=(CapstoneSession&&) noexcept;

    // 反汇编一条指令（cs_disasm_iter 封装）。
    //   code/size/address 均为输入输出：成功时三者被推进到下一条指令；
    //   失败（无效字节）时三者保持不变，由调用方决定如何推进。
    // 返回指向内部 cs_insn 的指针，其内容在下次调用 next() 前有效，
    // 会话存活期间 detail 指针同样有效。
    const cs_insn* next(const u8*& code, size_t& size, u64& address);

    csh raw() const noexcept { return handle_; }
    ir::Arch arch() const noexcept { return arch_; }
    cs_mode mode() const noexcept { return mode_; }

private:
    void close() noexcept;

    csh handle_ = 0;
    cs_insn* insn_ = nullptr;
    ir::Arch arch_ = ir::Arch::X64;
    cs_mode mode_ = CS_MODE_64;
};

} // namespace wvmp::passes::lifter
