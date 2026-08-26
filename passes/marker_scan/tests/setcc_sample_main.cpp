// MIT-336: 端到端正路径样本——区域内含 setcc (REG-REG, 6 variants: setne/sete/
// setb/seta/setl/setg)，验证 setcc 修复后翻译成功、运行时走真 Setcc handler、
// 行为与原生逐字节一致（保护 → 运行 → stdout+退出码比对）。
//
// 设计要点 (沿用 xchg 模式):
//   - MSVC x64 **不支持 inline asm**, setcc 字节由 setcc_sample_asm.asm (MASM)
//     直接 emit, 链接进本 sample. 区域内含 cmp + setcc + movzx 真指令字节。
//   - 区域**只含白名单** ALU: cmp/setcc/movzx, 不含 rip-relative / printf / call
//     （printf 在区域外的 main 中）。
//   - 覆盖 unsigned (setne/sete/setb/seta) + signed (setl/setg) 两个维度, 验证
//     setcc 16 variants 的子集, 跑 byte-exact 比对。

#include "wvmp/sdk/markers.hpp"

#include <cstdint>
#include <cstdio>

extern "C" uint64_t setne_fn(int a, int b);
extern "C" uint64_t sete_fn(int a, int b);
extern "C" uint64_t setb_fn(int a, int b);
extern "C" uint64_t seta_fn(int a, int b);
extern "C" uint64_t setl_fn(int a, int b);
extern "C" uint64_t setg_fn(int a, int b);

int main() {
    // 区域外: 直接调函数 (printf 在区域外)。
    // 测试用例覆盖典型 cond 真/假 两路：
    //   - (1, 2): a != b (setne=1), a == b (sete=0), a <u b (setb=1), a >u b (seta=0),
    //             a <s b (setl=1), a >s b (setg=0)
    //   - (5, 5): a != b (0), a == b (1), a <u b (0), a >u b (0), a <s b (0), a >s b (0)
    //   - (-1, 0): 0xFFFFFFFF >u 0 (seta=1), 0xFFFFFFFF <s 0 (setl=1)
    const uint64_t ne12 = setne_fn(1, 2);   // 1 (1 != 2)
    const uint64_t e12  = sete_fn(1, 2);    // 0 (1 != 2)
    const uint64_t b12  = setb_fn(1, 2);    // 1 (1 <u 2)
    const uint64_t a12  = seta_fn(1, 2);    // 0 (1 !>u 2)
    const uint64_t l12  = setl_fn(1, 2);    // 1 (1 <s 2)
    const uint64_t g12  = setg_fn(1, 2);    // 0 (1 !>s 2)

    const uint64_t ne55 = setne_fn(5, 5);   // 0 (5 == 5)
    const uint64_t e55  = sete_fn(5, 5);    // 1 (5 == 5)
    const uint64_t b55  = setb_fn(5, 5);    // 0 (5 !<u 5)
    const uint64_t a55  = seta_fn(5, 5);    // 0 (5 !>u 5)

    const uint64_t aneg = seta_fn(-1, 0);   // 1 (0xFFFFFFFF >u 0)
    const uint64_t lneg = setl_fn(-1, 0);   // 1 (-1 <s 0)

    std::printf(
        "setcc ne12=%llu e12=%llu b12=%llu a12=%llu l12=%llu g12=%llu "
        "ne55=%llu e55=%llu b55=%llu a55=%llu "
        "aneg=%llu lneg=%llu\n",
        static_cast<unsigned long long>(ne12),
        static_cast<unsigned long long>(e12),
        static_cast<unsigned long long>(b12),
        static_cast<unsigned long long>(a12),
        static_cast<unsigned long long>(l12),
        static_cast<unsigned long long>(g12),
        static_cast<unsigned long long>(ne55),
        static_cast<unsigned long long>(e55),
        static_cast<unsigned long long>(b55),
        static_cast<unsigned long long>(a55),
        static_cast<unsigned long long>(aneg),
        static_cast<unsigned long long>(lneg));
    return 0;
}