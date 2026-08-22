#include "wvmp/regvm/isa/encoding.hpp"

#include <stdexcept>
#include <string>

namespace wvmp::regvm::isa {
namespace {

// 位域位置（见 encoding.hpp 位图）。
constexpr u64 kOpMask = (1ull << 14) - 1;
constexpr unsigned kOpShift = 0;
constexpr unsigned kAKindShift = 14;
constexpr unsigned kBKindShift = 16;
constexpr unsigned kCondShift = 18;
constexpr unsigned kRegAShift = 22;
constexpr unsigned kRegBShift = 27;
constexpr unsigned kAuxShift = 32;

[[noreturn]] void reject(std::string_view what, u64 value) {
    throw std::runtime_error("regvm isa: illegal " + std::string(what) +
                             " value " + std::to_string(value));
}
void validate_insn(const VmInsn& insn) {
    // 合法域：opcode ∈ [1, kVmOpMax]（0 为非法哨兵；14 位空间是预留余量，
    // 解码端拒绝未定义的 opcode，blob 版本号负责向前兼容）。
    const u16 op = static_cast<u16>(insn.op);
    if (op == 0 || op > kVmOpMax) reject("opcode", op);
    const auto kind_ok = [](OpKind k) {
        return k == OpKind::None || k == OpKind::Reg || k == OpKind::Imm;
    };
    if (!kind_ok(insn.a_kind)) reject("a_kind", static_cast<u64>(insn.a_kind));
    if (!kind_ok(insn.b_kind)) reject("b_kind", static_cast<u64>(insn.b_kind));
    if (insn.cond_or_size > 15) reject("cond_or_size", insn.cond_or_size);
    if (insn.reg_a >= kRegCount) reject("reg_a", insn.reg_a);
    if (insn.reg_b >= kRegCount) reject("reg_b", insn.reg_b);
}

} // namespace

u64 encode(const VmInsn& insn) {
    validate_insn(insn);
    return (static_cast<u64>(insn.op) << kOpShift) |
           (static_cast<u64>(insn.a_kind) << kAKindShift) |
           (static_cast<u64>(insn.b_kind) << kBKindShift) |
           (static_cast<u64>(insn.cond_or_size) << kCondShift) |
           (static_cast<u64>(insn.reg_a) << kRegAShift) |
           (static_cast<u64>(insn.reg_b) << kRegBShift) |
           (static_cast<u64>(insn.aux) << kAuxShift);
}

VmInsn decode(u64 word) {
    VmInsn insn;
    insn.op = static_cast<VmOp>((word >> kOpShift) & kOpMask);
    const u64 a = (word >> kAKindShift) & 3;
    const u64 b = (word >> kBKindShift) & 3;
    insn.a_kind = static_cast<OpKind>(a);
    insn.b_kind = static_cast<OpKind>(b);
    insn.cond_or_size = static_cast<u8>((word >> kCondShift) & 0xF);
    insn.reg_a = static_cast<u8>((word >> kRegAShift) & 0x1F);
    insn.reg_b = static_cast<u8>((word >> kRegBShift) & 0x1F);
    insn.aux = static_cast<u32>(word >> kAuxShift);
    validate_insn(insn);
    return insn;
}

VmInsn make_insn(VmOp op, OpKind a_kind, u8 reg_a, OpKind b_kind, u8 reg_b,
                 u32 aux, u8 cond_or_size) {
    VmInsn insn;
    insn.op = op;
    insn.a_kind = a_kind;
    insn.b_kind = b_kind;
    insn.reg_a = reg_a;
    insn.reg_b = reg_b;
    insn.aux = aux;
    insn.cond_or_size = cond_or_size;
    return insn;
}

void append_insn(std::vector<u8>& stream, const VmInsn& insn) {
    const u64 word = encode(insn);
    for (int i = 0; i < 8; ++i)
        stream.push_back(static_cast<u8>(word >> (8 * i)));
}

} // namespace wvmp::regvm::isa
