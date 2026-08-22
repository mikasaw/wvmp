#include "wvmp/regvm/isa/alias.hpp"

namespace wvmp::regvm::isa {

u64 alias_read(u64 full, ir::Size size) {
    switch (size) {
        case ir::Size::S8:  return full & 0xFF;
        case ir::Size::S16: return full & 0xFFFF;
        case ir::Size::S32: return full & 0xFFFFFFFF;
        case ir::Size::S64: return full;
    }
    return full;  // 不可达：ir::Size 仅四值
}

u64 alias_write(u64 old, u64 val, ir::Size size) {
    switch (size) {
        case ir::Size::S8:
            return (old & ~static_cast<u64>(0xFF)) | (val & 0xFF);
        case ir::Size::S16:
            return (old & ~static_cast<u64>(0xFFFF)) | (val & 0xFFFF);
        case ir::Size::S32:
            return val & 0xFFFFFFFF;  // x86-64：写 32 位寄存器零扩展到 64 位
        case ir::Size::S64:
            return val;
    }
    return val;  // 不可达
}

} // namespace wvmp::regvm::isa
