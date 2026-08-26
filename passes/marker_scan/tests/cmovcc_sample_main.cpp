// MIT-339: 端到端正路径样本——区域内含 cmovcc (REG-REG, 6 variants: cmove/cmovne/
// cmovb/cmovg/cmovl/cmovge), 验证 cmovcc 修复后翻译成功、运行时走真 Cmovcc handler、
// 行为与原生逐字节一致 (保护 → 运行 → stdout+退出码比对)。
//
// 设计要点 (沿用 setcc 模式):
//   - MSVC x64 **不支持 inline asm**, cmovcc 字节由 cmovcc_sample_asm.asm (MASM)
//     直接 emit, 链接进本 sample. 区域内含 cmp + cmovcc + mov 真指令字节。
//   - 区域**只含白名单** ALU: cmp/cmovcc/mov, 不含 rip-relative / printf / call
//     (printf 在区域外的 main 中)。
//   - 覆盖 unsigned (cmovb/cmova) + signed (cmovl/cmovg/cmovge) + equality
//     (cmove/cmovne) 三个维度, 验证 cmovcc 16 variants 的子集, 跑 byte-exact 比对。
//
// 关键: MSVC /Od 编译 C++ 不会自然 emit cmovcc (老 compiler 走 jcc+mov), 必须用
// MASM (.asm) helper 强制 codegen 真 cmovcc 字节 (pitfall #35)。

#include "wvmp/sdk/markers.hpp"

#include <cstdint>
#include <cstdio>

extern "C" uint64_t cmove_fn(int a, int b, int c, int d);
extern "C" uint64_t cmovne_fn(int a, int b, int c, int d);
extern "C" uint64_t cmovb_fn(int a, int b, int c, int d);
extern "C" uint64_t cmovg_fn(int a, int b, int c, int d);
extern "C" uint64_t cmovl_fn(int a, int b, int c, int d);
extern "C" uint64_t cmovge_fn(int a, int b, int c, int d);

int main() {
    // 区域外: 直接调函数 (printf 在区域外)。
    // 测试用例覆盖典型 cond 真/假 两路:
    //   - (1, 1, 10, 20): cmove=10 (ZF=1, 1==1), cmovne=20, cmovb=20, cmovg=10,
    //     cmovl=20, cmovge=10
    //   - (1, 2, 10, 20): cmove=20 (ZF=0, 1!=2), cmovne=10, cmovb=10 (1<u 2),
    //     cmovg=20, cmovl=10 (1<s 2), cmovge=20
    //   - (5, 5, 10, 20): cmove=10, cmovne=20, cmovb=20, cmovg=20,
    //     cmovl=20, cmovge=10 (5>=5)
    //   - (-1, 0, 10, 20): 0xFFFFFFFF>u 0, cmovb=10, cmovge=10 (-1>=0s 假)
    const uint64_t e_eq  = cmove_fn(1, 1, 10, 20);    // 10 (ZF=1)
    const uint64_t ne_eq = cmovne_fn(1, 1, 10, 20);  // 20 (ZF=1, ne false)
    const uint64_t e_12  = cmove_fn(1, 2, 10, 20);    // 20 (ZF=0)
    const uint64_t ne_12 = cmovne_fn(1, 2, 10, 20);  // 10 (ZF=0, ne true)
    const uint64_t b_12  = cmovb_fn(1, 2, 10, 20);    // 10 (1<u 2)
    const uint64_t g_12  = cmovg_fn(1, 2, 10, 20);    // 20 (1 not >s 2)
    const uint64_t l_12  = cmovl_fn(1, 2, 10, 20);    // 10 (1<s 2)
    const uint64_t ge_12 = cmovge_fn(1, 2, 10, 20);   // 20 (1 not >=s 2)
    const uint64_t ge_55 = cmovge_fn(5, 5, 10, 20);   // 10 (5>=s 5)
    const uint64_t b_neg = cmovb_fn(-1, 0, 10, 20);   // 20 (-1 not <u 0)

    std::printf(
        "cmovcc e_eq=%llu ne_eq=%llu e_12=%llu ne_12=%llu "
        "b_12=%llu g_12=%llu l_12=%llu ge_12=%llu "
        "ge_55=%llu b_neg=%llu\n",
        static_cast<unsigned long long>(e_eq),
        static_cast<unsigned long long>(ne_eq),
        static_cast<unsigned long long>(e_12),
        static_cast<unsigned long long>(ne_12),
        static_cast<unsigned long long>(b_12),
        static_cast<unsigned long long>(g_12),
        static_cast<unsigned long long>(l_12),
        static_cast<unsigned long long>(ge_12),
        static_cast<unsigned long long>(ge_55),
        static_cast<unsigned long long>(b_neg));
    return 0;
}
