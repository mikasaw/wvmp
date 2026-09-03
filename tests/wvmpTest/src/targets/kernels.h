// targets/kernels.h - 保护工具的"打标靶"层。
//
// 入选标准（每个将来放进来的内核都必须满足）：
//   * 纯计算：无异常、无 SEH、无堆分配、无 TLS、无锁、无系统调用
//   * 单一职责、以单出口为主、参数与返回值全部走值/指针
//   * extern "C" 链接：符号不被 C++ name mangling，保护工具的符号选择/
//     报告面板里稳定可见；__declspec(noinline) 保证它一定真实存在一个
//     函数边界可供圈选。
//
// 标记插入约定：在实现文件对应函数的 **收尾处** 套上你自己的 begin/end
// 标记对即可，本层不引入任何宏，保持源码对任何工具零依赖。
//
// 与验证的关系：每个内核都被 kern.* 组的薄驱动覆盖 —— 驱动只负责
// 种子化造数 -> 调用内核 -> 封闭公式/RFC 向量比对，本身不打标；
// 因此加壳后任何一条 FAIL 都能直接归因到具体某个被保护的内核。
#pragma once

#include <stdint.h>

#if defined(_MSC_VER)
#  define WV_TARGET_NOINLINE __declspec(noinline)
#else
#  define WV_TARGET_NOINLINE __attribute__((noinline))
#endif

#ifdef __cplusplus
extern "C" {
#endif

// ===========================================================================
// [位算术 / 整数语义]
// ===========================================================================

// 64x64->128 高位字（进位传播路径），配低位自校验。
WV_TARGET_NOINLINE uint64_t wv_mul64hi(uint64_t a, uint64_t b);

// 经典 Duff 设备字节复制：批次计数器 n=(count+7)/8 驱动终止，
// 两个指针恰好前进 count 字节。
WV_TARGET_NOINLINE void wv_duff_copy(uint8_t* to, const uint8_t* from,
                                     uint32_t count);

// 有序升序数组二分查找：命中返回下标，未命中返回 -1。
WV_TARGET_NOINLINE int32_t wv_bsearch_i32(const int32_t* a, int32_t n,
                                          int32_t key);

// 原地插入排序（稳定）。
WV_TARGET_NOINLINE void wv_insertion_sort(int32_t* v, int32_t n);

// 受限 Ackermann：深互层递归调用链；m 只允许 0..3 且 m*n 组合保持小值，
// 调用方自负边界责任（本函数有意不做防御）。
WV_TARGET_NOINLINE int32_t wv_ackermann(int32_t m, int32_t n);

// ===========================================================================
// [哈希 / 密码学 —— 块级核心]
// ===========================================================================
// 约定：*_compress 只处理单个 64 字节块并 **原地累加** 状态字；
// 填充与长度编码留在驱动侧，这样黄金向量断言可精确归因压缩函数本身。

WV_TARGET_NOINLINE void wv_md5_compress(uint32_t st[4],
                                        const uint8_t block[64]);

// SHA-256 的 8 个初始字（sqrt 前质数小数部分），供驱动组装消息流。
const uint32_t* wv_sha256_h0(void);
WV_TARGET_NOINLINE void wv_sha256_compress(uint32_t h[8],
                                           const uint8_t block[64]);

// CRC-32（IEEE 反射式）。crc_in 用 0xFFFFFFFF 起、最终取反由调用方完成；
// 分段输入时把上次返回值原样传回即可链接。
WV_TARGET_NOINLINE uint32_t wv_crc32_update(uint32_t crc, const uint8_t* p,
                                            uint32_t n);

// ===========================================================================
// [流密码]
// ===========================================================================
typedef struct {
    uint8_t  S[256];
    uint32_t i, j;
} wv_rc4_state;

// 密钥调度，完成后内部游标 i=j=0。
WV_TARGET_NOINLINE void wv_rc4_ksa(wv_rc4_state* st, const uint8_t* key,
                                   uint32_t klen);
// 就地异或加密/解密（同一实现，XOR 对合）。
WV_TARGET_NOINLINE void wv_rc4_crypt(wv_rc4_state* st, uint8_t* buf,
                                     uint32_t n);

// ===========================================================================
// [XTEA 单块]
// ===========================================================================
WV_TARGET_NOINLINE void wv_xtea_encipher(uint32_t v[2], const uint32_t k[4]);
WV_TARGET_NOINLINE void wv_xtea_decipher(uint32_t v[2], const uint32_t k[4]);

// ===========================================================================
// [Base64]
// ===========================================================================
// 编码：dst 容量需 >= ((n+2)/3)*4 + 1；返回写入字符数（不含终结符）。
WV_TARGET_NOINLINE int32_t wv_b64_encode(const uint8_t* src, uint32_t n,
                                         char* dst);
// 解码：返回产生的字节数；遇非法字符立即放弃并返回 -1。
WV_TARGET_NOINLINE int32_t wv_b64_decode(const char* s, uint32_t len,
                                         uint8_t* dst);

#ifdef __cplusplus
}
#endif
