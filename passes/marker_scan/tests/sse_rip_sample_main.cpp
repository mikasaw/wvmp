// MIT-408 (C4b): 端到端正路径样本——SSE 指令族 memory 形式 (含 rip-relative
// 全局访问) 真虚拟化。保护 → 运行 → stdout+退出码逐字节比对 (native vs
// virtualized)。
//
// 与 MIT-371~376 五连单 (MASM helper 强制 REG-REG) 的本质差异: 本样本**不
// 用 MASM**——MSVC x64 /Od 对全局浮点/数组 (double g_x; g_x+=1; / arr[i])
// 天然 emit mem 形式 (movsd xmm0,[rip+g_x] / addsd xmm0,[rip+rax*8], 派活单
// §A.1 实测), 这正是本单补回的能力面: 区域内全部是真 mem 形式 SSE 字节。
//
// 区域覆盖 (派活单 §A.3 形式全集):
//   - 读 (src=mem):  movsd/movss xmm,[rip+g] (标量), addsd/subss xmm,[rip+c]
//                    (ALU 源), movaps xmm,[rip+g_ps] (16B 对齐形式),
//                    movups xmm,[rip+g_f4+8] (16B 非对齐), addps xmm,[rip+g]
//   - 写 (dst=mem):  movsd/movss [rip+g], xmm; movaps [rip+g_ps], xmm
//   - 非 rip base+index: movsd xmm,[rcx+rax] / movsd [rcx+rax], xmm
//                    (lea rcx,[rip+g_arr] + imul 下标, 数组访问 MSVC 高频形态)
//   - 栈基址访存:    movaps [rsp+disp], xmm (__m128 赋值临时, /Od 编译器产出)
//   - 比较 (D4):     ucomisd xmm,[rip+c] + jp/jne (g_d == 2.5 判等, MSVC 对
//                    == 用 ucomisd + jp/jne 双条件, 对 > < 用 comisd 不在本单)
//   - D2 对齐证明:   __declspec(align(16)) 对齐数组 + 默认对齐 double 数组
//                    + 非 16B 对齐 float 数组 (movups 16B 非对齐访存) 同
//                    区域处理, 输出一致即证明运行时 movups 非对齐语义无差异
//
// 区域外: printf (call 不受支持, 保持区域外) 与 int 转换 (cvttsd2si 不在本单)。

#include "wvmp/sdk/markers.hpp"

#include <cstdio>
#include <emmintrin.h>

// 全局标量 (double/float): /Od 对 g_x += 1.0 直出 movsd xmm,[rip+g_x] +
// addsd xmm,[rip+c] + movsd [rip+g_x],xmm 三连 mem 形式。
double g_d = 1.5;
float g_f = 2.0f;

// 默认对齐 double 数组 (8B 对齐, 非 16B — D2 非对齐组; 数组下标 base 非
// rip 形态的载体: lea + [rcx+rax] 寻址)。
double g_arr[4] = {1.0, 2.0, 3.0, 4.0};

// 显式 16B 对齐 double 数组 (D2 对齐组)。
__declspec(align(16)) double g_align[4] = {10.0, 20.0, 30.0, 40.0};

// __m128 全局: 编译器保证 16B 对齐并直出 movaps 形式 (含赋值临时
// [rsp+disp] 栈槽); 运行时一律 movups 非对齐语义, 不埋 #GP 雷 (D2)。
__m128 g_ps = {1.0f, 2.0f, 3.0f, 4.0f};
__m128 g_ps2 = {10.0f, 20.0f, 30.0f, 40.0f};

// 非 16B 对齐 float 数组 (4B 对齐): _mm_loadu_ps 直出 movups 16B 非对齐
// 访存 — 证明 XmmLoad 16B 宽度对非对齐地址无差异 (D2)。
float g_f4[8] = {0.5f, 1.5f, 2.5f, 3.5f, 4.5f, 5.5f, 6.5f, 7.5f};

// 额外 double 标量 (subsd/divsd mem 源) 与 __m128d 全局 (movaps + addpd
// mem; 实测 MSVC /Od 对 _mm_add_pd 直出 movaps+addpd+movaps)。
double g_e = 8.0;
__m128d g_pd = {1.5, 2.5};
__m128d g_pd2 = {10.0, 20.0};

int main() {
    int cmp_r = 0;

    WVMP_BEGIN(main);
    // 1) double 标量 += 常量 (movsd read + addsd read + movsd write, 全 rip)
    g_d += 1.0;          // g_d = 1.5 + 1.0 = 2.5
    // 2) float 标量 -= 常量 (movss read + subss read + movss write, 全 rip)
    g_f -= 0.5f;         // g_f = 2.0 - 0.5 = 1.5
    // 3) double 数组下标写 + 读改写 (lea rip + movsd [rcx+rax] read/write)
    g_arr[2] = g_d;      // g_arr[2] = 2.5
    g_arr[1] += g_d;     // g_arr[1] = 2.0 + 2.5 = 4.5
    // 4) 显式 16B 对齐数组 (movsd [rcx+rax] 非 rip 形态)
    g_align[0] += g_d;   // g_align[0] = 10.0 + 2.5 = 12.5
    // 5) __m128 packed 加 (movaps read + addps read + movaps write,
    //    含 movaps [rsp+disp] 栈临时 — 栈基址 mem 形态)
    g_ps = _mm_add_ps(g_ps, g_ps2);   // {11,22,33,44}
    // 6) 非对齐 16B loadu (movups [rip+g_f4+8] 非对齐访存)
    g_ps = _mm_loadu_ps(g_f4 + 2);    // {2.5,3.5,4.5,5.5}
    // 7) ucomisd mem + jp/jne (D4: 全局浮点判等高频形态; g_d == 2.5 成立)
    if (g_d == 2.5) cmp_r = 1;
    // 8) subsd/divsd mem 源 (scalar double 减/除, 同 addsd 折条)
    g_e -= 1.0;          // g_e = 8.0 - 1.0 = 7.0
    g_e /= 2.0;          // g_e = 7.0 / 2.0 = 3.5
    // 9) __m128d packed 加 (movaps read + addpd read + movaps write)
    g_pd = _mm_add_pd(g_pd, g_pd2);   // {11.5, 22.5}
    WVMP_END(main);

    // 期望值: g_d=2.5 g_f=1.5 g_arr=[1,4.5,2.5,4] g_align=[12.5,20,30,40]
    //          g_ps=[2.5,3.5,4.5,5.5] cmp_r=1 g_e=3.5 g_pd=[11.5,22.5]
    std::printf("g_d=%g g_f=%g\n", g_d, static_cast<double>(g_f));
    std::printf("g_arr=[%g,%g,%g,%g]\n", g_arr[0], g_arr[1], g_arr[2], g_arr[3]);
    std::printf("g_align=[%g,%g,%g,%g]\n", g_align[0], g_align[1], g_align[2], g_align[3]);
    std::printf("g_ps=[%g,%g,%g,%g]\n",
                static_cast<double>(g_ps.m128_f32[0]),
                static_cast<double>(g_ps.m128_f32[1]),
                static_cast<double>(g_ps.m128_f32[2]),
                static_cast<double>(g_ps.m128_f32[3]));
    std::printf("cmp_r=%d g_e=%g\n", cmp_r, g_e);
    std::printf("g_pd=[%g,%g]\n", g_pd.m128d_f64[0], g_pd.m128d_f64[1]);
    return 0;
}
