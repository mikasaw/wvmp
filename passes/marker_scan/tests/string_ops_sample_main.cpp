// MIT-415 (G3): 串指令族 rep movs/stos/scas/cmps/lods 微程序展开 E2E 样本。
//
// 覆盖边界 (派活单 §B.4 ①-⑤):
//   ① 逐字节/8B 宽度语义与原生一致 — movsb (32B) / movsq (4×8B) / stosb / lodsb;
//   ② rep 0 次 (rcx=0) 空转 — movsb/stosb/lodsb n=0: 目标不动 + 计数 0 + acc 原值;
//   ③ repnz 早退 (scas/cmps) — repne scasb 命中/未命中/首元素三态 +
//      repe cmpsb 全等/首差异位; 早退索引与剩余 rcx 双可观测
//      (SDM: 早退迭代不推进指针不减计数);
//   ④ 重叠区域 — 原生未定义, 样本禁依赖 (披露, 不测);
//   ⑤ 非对齐 [rsi]/[rdi] — rep movsq dst = buf+1 (8B 非对齐)。
//   flags 通路: 区域内 cmp 置 ZF → rep movsb → sete 读回 — movs 不写 flags
//   的保全证据 (GetFlags/SetFlags 全路径恢复, 非空转)。
//
// 负例: rep nop (pause) 区域 → 三元组白名单外 → C1 gate → 整函数原生,
// 行为 byte-exact 由双跑兜底 (REQUIRE_REAL 只要求 ≥1 真虚拟化函数)。
//
// 验收: multiseed REQUIRE_REAL=1 (≥1 stub + byte-exact); e2e 日志含
// "string-op @ ... DF=0 assumption" 命中 note ×7 (每串指令 1 条) +
// 负例 gate note (pause 未支持)。

#include "wvmp/sdk/markers.hpp"

#include <cstdio>
#include <cstring>

extern "C" unsigned long long wv_str_movsb(void* dst, const void* src, unsigned long long n);
extern "C" unsigned long long wv_str_movsq_unaligned(void* dst, const void* src,
                                                     unsigned long long n);
extern "C" unsigned long long wv_str_stosb(void* dst, unsigned char v, unsigned long long n);
extern "C" unsigned long long wv_str_scasb(const void* buf, unsigned char needle,
                                           unsigned long long n);
extern "C" unsigned long long wv_str_cmpsb(const void* a, const void* b, unsigned long long n);
extern "C" unsigned long long wv_str_lodsb(void* dst, const void* src, unsigned long long n);
extern "C" unsigned long long wv_str_movsb_flags(unsigned long long zf_in, void* dst,
                                                 const void* src, unsigned long long n);
extern "C" unsigned long long wv_str_neg_pause(unsigned long long x);

static int all_byte_eq(const unsigned char* a, const unsigned char* b, size_t n) {
    for (size_t i = 0; i < n; ++i)
        if (a[i] != b[i]) return 0;
    return 1;
}

int main() {
    volatile int ok = 1;
    unsigned char src[32];
    unsigned char dst[40];
    unsigned char ref[40];

    // ① rep movsb 逐字节 + 返回计数 0
    for (int i = 0; i < 32; ++i) src[i] = (unsigned char)(i * 7 + 1);
    std::memset(dst, 0xAA, sizeof(dst));
    unsigned long long c = wv_str_movsb(dst, src, 32);
    std::printf("movsb(32): rc=%llu match=%d\n", c, all_byte_eq(dst, src, 32));
    ok &= (c == 0) && all_byte_eq(dst, src, 32);

    // ② rep movsb rcx=0 空转: 目标不动
    std::memset(dst, 0xBB, sizeof(dst));
    c = wv_str_movsb(dst, src, 0);
    int untouched = 1;
    for (int i = 0; i < 32; ++i) untouched &= (dst[i] == 0xBB);
    std::printf("movsb(0): rc=%llu untouched=%d\n", c, untouched);
    ok &= (c == 0) && untouched;

    // ① 8B + ⑤ 非对齐: rep movsq dst = buf+1 (4 × 8B = 32 字节)
    std::memset(ref, 0xCC, sizeof(ref));
    std::memcpy(ref + 1, src, 32);  // 期望: dst[1..32] = src[0..31], 其余 0xCC
    std::memset(dst, 0xCC, sizeof(dst));
    c = wv_str_movsq_unaligned(dst + 1, src, 4);
    int algn_match = 1;
    for (int i = 0; i < 40; ++i) algn_match &= (dst[i] == ref[i]);
    std::printf("movsq_unaligned(4): rc=%llu match=%d\n", c, algn_match);
    ok &= (c == 0) && algn_match;

    // ③ rep stosb 填充 + ② n=0 空转
    std::memset(dst, 0, sizeof(dst));
    c = wv_str_stosb(dst, 0x5A, 20);
    int filled = 1;
    for (int i = 0; i < 20; ++i) filled &= (dst[i] == 0x5A);
    filled &= (dst[20] == 0);  // 第 21 字节不动 (只填 20)
    std::printf("stosb(20,0x5A): rc=%llu filled=%d\n", c, filled);
    ok &= (c == 0) && filled;
    std::memset(dst, 0x5A, sizeof(dst));
    c = wv_str_stosb(dst, 0x11, 0);
    int st_untouched = (dst[0] == 0x5A);
    std::printf("stosb(0): rc=%llu untouched=%d\n", c, st_untouched);
    ok &= (c == 0) && st_untouched;

    // ③ repne scasb 早退: 命中 → (索引, 剩余 n-idx); 未命中 → (n, 0)。
    // 索引 = rdi-buf: native 实测命中后 RDI 指向匹配元素**之后** (idx = 命中
    // 位 + 1, strlen `lea rax,[rdi-1]` 惯用法), RCX 已含终止迭代的递减。
    for (int i = 0; i < 32; ++i) src[i] = (unsigned char)i;
    unsigned long long r = wv_str_scasb(src, 17, 32);
    std::printf("scasb(hit@17): idx=%llu rem=%llu\n", r >> 32, r & 0xFFFFFFFFull);
    ok &= ((r >> 32) == 18) && ((r & 0xFFFFFFFFull) == 32 - 18);
    r = wv_str_scasb(src, 0x7F, 32);  // 未命中
    std::printf("scasb(miss): idx=%llu rem=%llu\n", r >> 32, r & 0xFFFFFFFFull);
    ok &= ((r >> 32) == 32) && ((r & 0xFFFFFFFFull) == 0);
    r = wv_str_scasb(src, 0, 32);     // 首元素命中 (idx 0+1, 一次迭代即早退)
    std::printf("scasb(hit@0): idx=%llu rem=%llu\n", r >> 32, r & 0xFFFFFFFFull);
    ok &= ((r >> 32) == 1) && ((r & 0xFFFFFFFFull) == 32 - 1);

    // ③ repe cmpsb: 全等 → (n, 0); 首差异位 → (idx, n-idx) (同 past 语义)
    r = wv_str_cmpsb(src, src, 32);
    std::printf("cmpsb(equal): idx=%llu rem=%llu\n", r >> 32, r & 0xFFFFFFFFull);
    ok &= ((r >> 32) == 32) && ((r & 0xFFFFFFFFull) == 0);
    unsigned char diff[32];
    std::memcpy(diff, src, 32);
    diff[7] ^= 0xFF;
    r = wv_str_cmpsb(src, diff, 32);
    std::printf("cmpsb(diff@7): idx=%llu rem=%llu\n", r >> 32, r & 0xFFFFFFFFull);
    ok &= ((r >> 32) == 8) && ((r & 0xFFFFFFFFull) == 32 - 8);

    // ⑥ rep lodsb: 末字节 → dst[0] + rax; n=0 空转 → acc 原值 0x5A, dst 不动
    unsigned char lod_dst = 0;
    c = wv_str_lodsb(&lod_dst, src, 10);
    std::printf("lodsb(10): acc=%02llx dst=%02x\n", c & 0xFF, lod_dst);
    ok &= ((c & 0xFF) == src[9]) && (lod_dst == src[9]);
    lod_dst = 0;
    c = wv_str_lodsb(&lod_dst, src, 0);
    std::printf("lodsb(0): acc=%02llx dst=%02x\n", c & 0xFF, lod_dst);
    // n=0: rep 空转 acc 保留预置 0x5A; rep 之后的 mov [rdi],al 照常执行
    ok &= ((c & 0xFF) == 0x5A) && (lod_dst == 0x5A);

    // flags 通路: zf_in=1 → sete=1; zf_in=0 → sete=0 (rep movsb 保全 flags)
    unsigned long long f = wv_str_movsb_flags(1, dst, src, 8);
    std::printf("movsb_flags(zf=1): sete=%llu\n", f);
    ok &= (f == 1);
    f = wv_str_movsb_flags(0, dst, src, 8);
    std::printf("movsb_flags(zf=0): sete=%llu\n", f);
    ok &= (f == 0);

    // 负例: rep nop (pause) → C1 gate → 原生执行, 行为 byte-exact
    unsigned long long g = wv_str_neg_pause(0x1234);
    std::printf("neg_pause: x=%llu\n", g);
    ok &= (g == 0x1234);

    std::printf("ok=%d\n", ok);
    return ok == 1 ? 0 : 2;
}
