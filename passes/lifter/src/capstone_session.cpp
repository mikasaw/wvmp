#include "capstone_session.hpp"

#include <stdexcept>
#include <utility>

namespace wvmp::passes::lifter {

CapstoneSession::CapstoneSession(ir::Arch arch) : arch_(arch) {
    mode_ = (arch == ir::Arch::X86) ? CS_MODE_32 : CS_MODE_64;
    if (cs_open(CS_ARCH_X86, mode_, &handle_) != CS_ERR_OK) {
        throw std::runtime_error("lifter: cs_open failed");
    }
    // 操作数/寄存器细节是指令映射的输入，必须开启。
    if (cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
        cs_close(&handle_);
        throw std::runtime_error("lifter: cs_option(CS_OPT_DETAIL) failed");
    }
    insn_ = cs_malloc(handle_);
    if (insn_ == nullptr) {
        cs_close(&handle_);
        throw std::runtime_error("lifter: cs_malloc failed");
    }
}

CapstoneSession::~CapstoneSession() { close(); }

CapstoneSession::CapstoneSession(CapstoneSession&& other) noexcept
    : handle_(other.handle_), insn_(other.insn_), arch_(other.arch_), mode_(other.mode_) {
    other.handle_ = 0;
    other.insn_ = nullptr;
}

CapstoneSession& CapstoneSession::operator=(CapstoneSession&& other) noexcept {
    if (this != &other) {
        close();
        handle_ = other.handle_;
        insn_ = other.insn_;
        arch_ = other.arch_;
        mode_ = other.mode_;
        other.handle_ = 0;
        other.insn_ = nullptr;
    }
    return *this;
}

void CapstoneSession::close() noexcept {
    // 必须先释放 cs_malloc 的指令缓冲，再关闭句柄（capstone 要求
    // cs_close 之后不得再触碰任何 capstone API/缓冲）。
    if (insn_ != nullptr && handle_ != 0) {
        cs_free(insn_, 1);
    }
    insn_ = nullptr;
    if (handle_ != 0) {
        cs_close(&handle_);
    }
    handle_ = 0;
}

const cs_insn* CapstoneSession::next(const u8*& code, size_t& size, u64& address) {
    if (handle_ == 0 || insn_ == nullptr) {
        return nullptr;
    }
    // 注意：默认未开启 SKIPDATA，遇到无效字节返回 false 且不推进
    // code/size/address（见 capstone cs.c 的失败路径），由调用方处理。
    if (cs_disasm_iter(handle_, &code, &size, &address, insn_)) {
        return insn_;
    }
    return nullptr;
}

} // namespace wvmp::passes::lifter
