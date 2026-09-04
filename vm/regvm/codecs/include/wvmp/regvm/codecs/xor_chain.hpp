#pragma once
#include "wvmp/common/rng.hpp"
#include "wvmp/common/types.hpp"
#include "wvmp/vm/backend.hpp"

#include <memory>
#include <string_view>

namespace wvmp::regvm::codecs {

// MIT-458 (crypt-v1) xor_chain：blob 级字节码流加密 codec。
//
// 数学（u32 字序 LE，流内链；G = 32 位黄金比例奇常数）：
//   加密（对明文流）: k = state;  c = p ^ k;  state = state * G + c;  写 c
//   解密（对密文流）: k = state;  c = 读出;   state = state * G + c;  写 c ^ k
// 两侧状态的链更新都吃**密文**字（解密方覆写前手里就是密文，递推一致）——
// 加密/解密是同一递推的两面，但同一段内存上**只可执行一次**（再跑一次 =
// 再加密，流即损坏）。stub 侧解密块因此必须 one-shot（8B 尾旗标，见
// crypt_plan.hpp）。
//
// ⚠️ 常数同步纪律：G 与递推序在本文件（C++ 加密侧）与
// passes/stub_link/src/stub_gen.cpp（asm 解密侧模板 build_crypt_asm_*）
// 各有一份——改任一侧必须同步另一侧并复跑 xor_chain 往返单测 +
// crypt E2E（寻 fix：若出现第二处 C++ 消费面，先收编到本文件再改）。
inline constexpr u32 kXorChainMult = 0x9E3779B1;

// blob 帧头宽度（VmBlobHeader 定宽 32B，明文保留——stub_link x86 白名单
// gate 与 read_blob 校验消费头；加密只覆盖 32B 之后的指令流）。
inline constexpr u64 kBlobHeaderBytes = 32;

class XorChainCodec final : public vm::BytecodeCodec {
public:
    std::string_view name() const override { return "xor_chain"; }

    // BytecodeCodec 契约面（M0 冻结）：key0 从 rng 派生（恰好消费一个
    // next()，密钥可复现）。注意：契约不携带"回读密钥"通道——stub 侧需要
    // 同一 key0 的消费方（crypt pass）应走 encrypt_with_key 直连面并自行
    // 记录密钥（MIT-458 D2：不改冻结头）。
    void encrypt_stream(Rng& rng, std::vector<u8>& bytecode) override {
        encrypt_with_key(static_cast<u32>(rng.next()), bytecode);
    }

    // MIT-458: blob 级解密一次性发生在 stub 入口（stub_gen 织入），解释器
    // 取指路径零改动——本面为指令级 codec（C 点后续单）预留，blob 级不消费。
    void emit_decrypt(std::string& interpreter_src) override {
        interpreter_src += "; xor_chain: blob-level decrypt is woven into the entry stub (MIT-458)\n";
    }

    // pass 直连面：外部给定 key0（stub 侧嵌入同一常量，密钥每目标嵌入）。
    // blob = 32B 明文头 + 密文流；长度不变；尾部 <4B 字节保持明文
    // （blob 流恒 8 对齐，本分支为防御面）。
    static void encrypt_with_key(u32 key0, std::vector<u8>& blob);
};

// codec 工厂（未知名返回 nullptr）。与 create_backend 同款约定。
std::unique_ptr<vm::BytecodeCodec> create_codec(std::string_view name);

} // namespace wvmp::regvm::codecs
