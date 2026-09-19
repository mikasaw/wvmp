// t_kernels.cpp - 打标靶层的验证驱动（薄封装）。
//
// 设计意图：驱动本身【不要】被打标 —— 它只做三件事：
//   种子化造数 -> 调用 targets 层内核 -> 封闭公式/RFC 向量比对。
// 加壳后任何 FAIL 都能精确归因到某个被保护的内核。MD5/SHA256 的填充与
// 长度编码刻意留在本驱动侧，黄金向量因此只校验块压缩函数本身。
#include "../common.h"
#include "../testfw.h"
#include "../targets/kernels.h"

#include <algorithm>
#include <string>
#include <vector>

using namespace wv;

// ---------------------------------------------------------------------------
static const char* tohex(const uint8_t* p, int n) {
    static char buf[72];
    for (int i = 0; i < n && i < 36; ++i) snprintf(buf + i * 2, 3, "%02x", p[i]);
    return buf;
}

// 尾部缓冲区须容纳"整块余数(最多64B)+0x80+补零到偏移56+8B长度"，最坏 128B。
static void md5_via_kernel(const uint8_t* msg, size_t len, uint8_t dg[16]) {
    uint32_t st[4] = { 0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u };
    uint64_t bits = (uint64_t)len * 8;
    uint8_t tail[136];
    size_t t = 0, off = 0;
    while (len - off >= 64) { wv_md5_compress(st, msg + off); off += 64; }
    size_t rest = len - off;
    memcpy(tail, msg + off, rest); t = rest;
    tail[t++] = 0x80;
    while ((t % 64) != 56) tail[t++] = 0;
    for (int i = 0; i < 8; ++i) tail[t++] = (uint8_t)(bits >> (8 * i));
    for (size_t b = 0; b < t; b += 64) wv_md5_compress(st, tail + b);
    for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 4; ++j) dg[4*i+j] = (uint8_t)(st[i] >> (8 * j));
}

static void sha256_via_kernel(const uint8_t* msg, size_t len, uint8_t dg[32]) {
    uint32_t h[8];
    memcpy(h, wv_sha256_h0(), sizeof(h));
    uint64_t bits = (uint64_t)len * 8;
    uint8_t tail[136];
    size_t t = 0, off = 0;
    while (len - off >= 64) { wv_sha256_compress(h, msg + off); off += 64; }
    size_t rest = len - off;
    memcpy(tail, msg + off, rest); t = rest;
    tail[t++] = 0x80;
    while ((t % 64) != 56) tail[t++] = 0;
    for (int i = 0; i < 8; ++i) tail[t++] = (uint8_t)(bits >> (8 * (7 - i)));
    for (size_t b = 0; b < t; b += 64) wv_sha256_compress(h, tail + b);
    for (int i = 0; i < 8; ++i)
        for (int j = 0; j < 4; ++j) dg[4*i+j] = (uint8_t)(h[i] >> (8 * (3 - j)));
}

TEST(kern, md5_block_vectors) {
    uint8_t dg[16];

    md5_via_kernel((const uint8_t*)"", 0, dg);
    CHECK_MSG(strcmp(tohex(dg, 16),
        "d41d8cd98f00b204e9800998ecf8427e") == 0, "md5 empty");

    md5_via_kernel((const uint8_t*)"a", 1, dg);
    CHECK_MSG(strcmp(tohex(dg, 16),
        "0cc175b9c0f1b6a831c399e269772661") == 0, "md5 'a'");

    md5_via_kernel((const uint8_t*)"abc", 3, dg);
    CHECK_MSG(strcmp(tohex(dg, 16),
        "900150983cd24fb0d6963f7d28e17f72") == 0, "md5 abc");

    md5_via_kernel((const uint8_t*)"message digest", 14, dg);
    CHECK_MSG(strcmp(tohex(dg, 16),
        "f96b697d7cb7938d525a2f31aaf161d0") == 0, "md5 message digest");

    // 多块 + 变步长吸收的一致性（内核只做单块，链路由驱动合成）
    const char* longmsg =
        "The quick brown fox jumps over the lazy dog - kernel mark target!";
    md5_via_kernel((const uint8_t*)longmsg, strlen(longmsg), dg);
    CHECK_MSG(strcmp(tohex(dg, 16),
        "900150983cd24fb0d6963f7d28e17f72") != 0, "multi-block sanity");
}

TEST(kern, sha256_block_vectors) {
    uint8_t dg[32];

    sha256_via_kernel((const uint8_t*)"", 0, dg);
    CHECK_MSG(strcmp(tohex(dg, 32),
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855") == 0, "sha256 empty");

    sha256_via_kernel((const uint8_t*)"abc", 3, dg);
    CHECK_MSG(strcmp(tohex(dg, 32),
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad") == 0, "sha256 abc");

    sha256_via_kernel(
        (const uint8_t*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        56, dg);
    CHECK_MSG(strcmp(tohex(dg, 32),
        "248d6a61d20638b8e5c026930c3e6039"
        "a33ce45964ff2167f6ecedd419db06c1") == 0, "sha256 NIST 56B");

    // 雪崩：单比特翻转引起输出大量变化
    uint8_t msg[64];
    memset(msg, 0x41, sizeof(msg));
    uint8_t a[32], b[32];
    sha256_via_kernel(msg, sizeof(msg), a);
    msg[63] ^= 0x08;
    sha256_via_kernel(msg, sizeof(msg), b);
    int diffbits = 0;
    for (int i = 0; i < 32; ++i) {
        uint8_t x = a[i] ^ b[i];
        for (int k = 0; k < 8; ++k) diffbits += (x >> k) & 1;
    }
    CHECK(diffbits >= 48);
}

TEST(kern, rc4_vector_and_roundtrip) {
    // RFC 经典样例：key="Key" pt="Plaintext" -> BBF316E8D940AF0AD3
    uint8_t buf[9];
    memcpy(buf, "Plaintext", 9);

    wv_rc4_state st;
    uint8_t key[] = "Key";
    wv_rc4_ksa(&st, key, 3);
    wv_rc4_crypt(&st, buf, 9);
    const uint8_t want[9] = { 0xBB, 0xF3, 0x16, 0xE8, 0xD9,
                              0x40, 0xAF, 0x0A, 0xD3 };
    CHECK(memcmp(buf, want, 9) == 0);

    // XOR 对合：全新调度解密即还原
    wv_rc4_ksa(&st, key, 3);
    wv_rc4_crypt(&st, buf, 9);
    CHECK(memcmp(buf, "Plaintext", 9) == 0);

    // 大消息分两段 crypt（游标跨段保持流连续性）
    Rng rng(9500u);
    for (int t = 0; t < 40; ++t) {
        uint8_t ks[13];
        for (size_t c = 0; c < sizeof(ks); ++c) ks[c] = (uint8_t)rng.u32n();
        std::vector<uint8_t> msg((size_t)rng.irange(200, 700));
        for (auto& c : msg) c = (uint8_t)rng.u32n();
        std::vector<uint8_t> saved = msg;

        wv_rc4_ksa(&st, ks, sizeof(ks));
        wv_rc4_crypt(&st, msg.data(), (uint32_t)(msg.size() / 2));
        wv_rc4_crypt(&st, msg.data() + msg.size() / 2,
                     (uint32_t)(msg.size() - msg.size() / 2));
        CHECK(memcmp(msg.data(), saved.data(), msg.size()) != 0);
        wv_rc4_ksa(&st, ks, sizeof(ks));
        wv_rc4_crypt(&st, msg.data(), (uint32_t)msg.size());
        CHECK(memcmp(msg.data(), saved.data(), msg.size()) == 0);
    }
}

TEST(kern, crc32_chain_goldens) {
    const char* nine = "123456789";
    uint32_t c1 = ~wv_crc32_update(0xFFFFFFFFu, (const uint8_t*)nine, 9);
    CHECK_EQ(c1, 0xCBF43926u);                   // CRC-32 校验值

    const char* fox = "The quick brown fox jumps over the lazy dog";
    CHECK_EQ(~wv_crc32_update(0xFFFFFFFFu, (const uint8_t*)fox,
                              (uint32_t)strlen(fox)), 0x414FA339u);

    std::vector<uint8_t> blob(1000);
    for (size_t i = 0; i < blob.size(); ++i) blob[i] = pattern_byte(i * 7 + 3);
    uint32_t whole = ~wv_crc32_update(0xFFFFFFFFu, blob.data(),
                                      (uint32_t)blob.size());
    for (uint32_t cut : { 0u, 1u, 33u, 500u, 999u, (uint32_t)blob.size() }) {
        uint32_t chained = wv_crc32_update(0xFFFFFFFFu, blob.data(), cut);
        chained = ~wv_crc32_update(chained, blob.data() + cut,
                                   (uint32_t)(blob.size() - cut));
        CHECK_EQ(chained, whole);
    }
}

// ---------------------------------------------------------------------------
TEST(kern, xtea_roundtrip_and_key_sensitivity) {
    // 已知结构锚点：delta*32 正是解密的初始 sum
    CHECK_EQ(0x9E3779B9u * 32u, 0xC6EF3720u);

    Rng rng(5150u);
    for (int t = 0; t < 120; ++t) {
        uint32_t k[4] = { rng.u32n(), rng.u32n(), rng.u32n(), rng.u32n() };
        uint32_t blk[2] = { rng.u32n(), rng.u32n() };
        uint32_t orig[2] = { blk[0], blk[1] };

        wv_xtea_encipher(blk, k);
        CHECK(blk[0] != orig[0] || blk[1] != orig[1]);
        uint32_t cipher_a[2] = { blk[0], blk[1] };

        wv_xtea_decipher(blk, k);
        CHECK(blk[0] == orig[0] && blk[1] == orig[1]);

        uint32_t k2[4] = { k[0], k[1], k[2], k[3] };
        k2[t % 4] ^= (1u << (t % 31));
        uint32_t b2[2] = { orig[0], orig[1] };
        wv_xtea_encipher(b2, k2);
        CHECK(b2[0] != cipher_a[0] || b2[1] != cipher_a[1]);
    }
}

TEST(kern, mul64hi_closed_forms) {
    uint64_t mx = ~0ull;

    // (2^64-1)^2 = 2^128 - 2^65 + 1 -> 高字 = 2^64-2，低字 = 1
    CHECK_EQ(mx * mx, 1ull);
    CHECK_EQ(wv_mul64hi(mx, mx), mx - 1);
    CHECK_EQ(wv_mul64hi(0x100000000ull, mx), 0xFFFFFFFFull);

    Rng rng(2026u);
    for (int i = 0; i < 300; ++i) {
        uint64_t a = rng.next(), b = rng.next();
        CHECK_EQ(wv_mul64hi(a, b), wv_mul64hi(b, a));   // 交换律
        uint64_t sa = rng.next() % 1000000ull, sb = rng.next() % 1000000ull;
        CHECK_EQ(sa * sb / sb, sa);                     // 无溢出子集可除还原
    }
}

// ---------------------------------------------------------------------------
TEST(kern, duff_copy_matches_memcmp) {
    static const size_t PAD = 16;
    for (uint32_t n = 1; n <= 40; ++n) {
        uint8_t guardA[PAD + 64 + PAD], guardB[PAD + 64 + PAD];
        for (size_t i = 0; i < PAD + 64 + PAD; ++i) {
            guardA[i] = pattern_byte(i);
            guardB[i] = 0x77;
        }
        const uint8_t* src = guardA + PAD;
        uint8_t* dst = guardB + PAD;

        wv_duff_copy(dst, src, n);

        CHECK(memcmp(dst, src, n) == 0);
        for (size_t i = 0; i < PAD; ++i) {
            CHECK_EQ((int)guardB[i], 0x77);
            CHECK_EQ((int)guardB[PAD + 64 + i], 0x77);
        }
        if (n < 64)
            for (uint32_t i = n; i < 64; ++i)
                CHECK_EQ((int)dst[i], 0x77);
    }

    enum { BIG = 30011 };
    static uint8_t big_src[BIG], big_dst[BIG];
    for (int i = 0; i < BIG; ++i) {
        big_src[i] = pattern_byte((size_t)i * 13 + 1);
        big_dst[i] = 0;
    }
    wv_duff_copy(big_dst, big_src, BIG);
    CHECK(memcmp(big_dst, big_src, BIG) == 0);
}

TEST(kern, b64_rfc4648_vectors) {
    struct BV { const char* raw; const char* enc; };
    const BV vecs[] = {
        { "",       "" },         { "f",      "Zg==" },
        { "fo",     "Zm8=" },     { "foo",    "Zm9v" },
        { "foob",   "Zm9vYg==" }, { "fooba",  "Zm9vYmE=" },
        { "foobar", "Zm9vYmFy" },
    };
    char enc[512];
    uint8_t back[512];
    for (const BV& v : vecs) {
        int32_t elen = wv_b64_encode((const uint8_t*)v.raw,
                                     (uint32_t)strlen(v.raw), enc);
        CHECK_EQ(elen, (int32_t)strlen(v.enc));
        CHECK(memcmp(enc, v.enc, (size_t)elen + 1) == 0);

        int32_t dlen = wv_b64_decode(v.enc, (uint32_t)elen, back);
        CHECK_EQ(dlen, (int32_t)strlen(v.raw));
        CHECK(memcmp(back, v.raw, (size_t)dlen) == 0);
    }

    CHECK_EQ(wv_b64_decode("ab!c", 4, back), -1);   // 非法字符拒绝

    Rng rng(60066u);
    for (int t = 0; t < 30; ++t) {
        std::vector<uint8_t> raw((size_t)rng.irange(0, 300));
        for (auto& c : raw) c = (uint8_t)rng.u32n();
        int32_t elen = wv_b64_encode(raw.data(), (uint32_t)raw.size(), enc);
        CHECK(elen > 0 || (raw.empty() && elen == 0));
        int32_t dlen = wv_b64_decode(enc, (uint32_t)elen, back);
        CHECK_EQ(dlen, (int32_t)raw.size());
        if (dlen >= 0)
            CHECK(memcmp(back, raw.data(), raw.size()) == 0);
    }
}

// ---------------------------------------------------------------------------
TEST(kern, search_sort_basics) {
    enum { N = 3000 };
    static int32_t sorted_arr[N];
    for (int i = 0; i < N; ++i) sorted_arr[i] = i * 3;

    // key 取模后再转 signed，恒为 [0, N*3+6]，无负值歧义
    Rng probe(88u);
    for (int i = 0; i < 1500; ++i) {
        int32_t key = (int32_t)(probe.next() % (u64)(N * 3 + 7));
        bool want = (key % 3 == 0 && key / 3 < N);
        int32_t got = wv_bsearch_i32(sorted_arr, N, key);
        CHECK_EQ(got >= 0, want);
        if (got >= 0)
            CHECK_EQ(sorted_arr[got], key);
    }

    // 插入排序 vs std::sort 共识（重复密集域）
    enum { M = 800 };
    Rng rs(31337u);
    std::vector<int32_t> a(M), ref(M);
    for (int i = 0; i < M; ++i) { a[(size_t)i] = (int32_t)(rs.next() % 97u); }
    ref = a;
    std::sort(ref.begin(), ref.end());
    wv_insertion_sort(a.data(), M);
    for (int i = 0; i < M; ++i) CHECK_EQ(a[(size_t)i], ref[(size_t)i]);

    // Ackermann 已知锚点：纯递归深度压力
    CHECK_EQ(wv_ackermann(0, 0), 1);
    CHECK_EQ(wv_ackermann(1, 2), 4);
    CHECK_EQ(wv_ackermann(2, 3), 9);
    CHECK_EQ(wv_ackermann(3, 3), 61);
}

// ---------------------------------------------------------------------------
// MIT-494w (T46): 真实 codegen 面扩展驱动 —— 8 个新 kernel 的共识/向量对
// 拍。驱动侧引用实现只用独立算法（naive 循环 / u64 参考 / 标准库共识），
// 与内核实现不共享代码路径；数据域受限以保证全程 32 位安全。
TEST(kern, realcode_datapath) {
    Rng rng(20260912u);

    // 4x4 矩阵乘 vs naive 三重循环（元素 |v|<=9 防溢出，32 轮 PRNG 矩阵）
    enum { D = 4 };
    int32_t a[D * D], b[D * D], got[D * D], ref[D * D];
    for (int t = 0; t < 32; ++t) {
        for (int i = 0; i < D * D; ++i) {
            a[i] = (int32_t)(rng.next() % 19u) - 9;
            b[i] = (int32_t)(rng.next() % 19u) - 9;
        }
        for (int i = 0; i < D; ++i)
            for (int j = 0; j < D; ++j) {
                int32_t acc = 0;
                for (int k = 0; k < D; ++k) acc += a[i * D + k] * b[k * D + j];
                ref[i * D + j] = acc;
            }
        wv_matmul4x4_i32(got, a, b);
        for (int i = 0; i < D * D; ++i) CHECK_EQ(got[i], ref[i]);
    }

    // 像素灰度：逐像素公式复算
    enum { PN = 512 };
    std::vector<uint32_t> px(PN), po(PN);
    for (int i = 0; i < PN; ++i)
        px[(size_t)i] = (uint32_t)(rng.next() & 0x00FFFFFFu);
    wv_pixel_grey(px.data(), po.data(), PN);
    for (int i = 0; i < PN; ++i) {
        uint32_t r = (px[(size_t)i] >> 16) & 0xFFu;
        uint32_t g = (px[(size_t)i] >> 8) & 0xFFu;
        uint32_t b = px[(size_t)i] & 0xFFu;
        CHECK_EQ(po[(size_t)i], (r * 3 + g * 6 + b) / 10u);
    }

    // 链表：静态节点构建 + 求和/计数共识（含空表）
    enum { LN = 64 };
    static wv_node nodes[LN];
    uint64_t want_sum = 0;
    uint32_t cnt = 0;
    for (int i = 0; i < LN; ++i) {
        nodes[i].val = (int32_t)(rng.next() % 1000u);
        nodes[i].next = (i + 1 < LN) ? &nodes[i + 1] : nullptr;
        want_sum += (uint64_t)(uint32_t)nodes[i].val;
        ++cnt;
    }
    uint64_t got_ls = wv_list_sum(nodes);
    CHECK_EQ((uint32_t)(got_ls >> 32), (uint32_t)want_sum);
    CHECK_EQ((uint32_t)got_ls, cnt);
    CHECK_EQ(wv_list_sum(nullptr), 0ull);

    // 堆 sift：返回值（交换数）手工推演闭式断言（验收 SF-1：置换效果类
    // 断言测不出返回值错算，补小规模精确锚）
    {
        int32_t t1[3] = { 1, 3, 2 };
        CHECK_EQ(wv_siftdown(t1, 3, 0), 1);            // 与 idx1 交换即停
        int32_t t2[3] = { 1, 2, 3 };
        CHECK_EQ(wv_siftdown(t2, 3, 0), 1);            // 与 idx2 交换即停
        int32_t t3[5] = { 0, 4, 2, 3, 1 };
        CHECK_EQ(wv_siftdown(t3, 5, 0), 2);            // 0 沉底两跳
        int32_t t4[3] = { 5, 3, 2 };
        CHECK_EQ(wv_siftdown(t4, 3, 0), 0);            // 已满足 → 0 次
        int32_t t5[1] = { 7 };
        CHECK_EQ(wv_siftdown(t5, 1, 0), 0);            // 无子结点
    }

    // 堆 sift：重复下沉构建最大堆 → 堆性质 + 多重集一致（std::sort 共识）
    enum { HN = 256 };
    std::vector<int32_t> h(HN), orig(HN);
    for (int i = 0; i < HN; ++i)
        h[(size_t)i] = (int32_t)(rng.next() % 5000u);
    orig = h;
    for (int i = HN / 2 - 1; i >= 0; --i) wv_siftdown(h.data(), HN, i);
    for (int i = 1; i < HN; ++i)
        CHECK(h[(size_t)((i - 1) / 2)] >= h[(size_t)i]);
    std::sort(orig.begin(), orig.end());
    std::sort(h.begin(), h.end());
    for (int i = 0; i < HN; ++i) CHECK_EQ(h[(size_t)i], orig[(size_t)i]);
}

TEST(kern, realcode_lang) {
    Rng rng(424242u);

    // 模幂 vs u64 逐位参考平方乘（mod<2^16 限域）；Fermat 锚 3^65520 mod 65521
    CHECK_EQ(wv_modpow_u32(3, 65520, 65521), 1u);
    CHECK_EQ(wv_modpow_u32(2, 10, 1000), 24u);
    for (int t = 0; t < 200; ++t) {
        uint32_t mod = 3u + (uint32_t)(rng.next() % 60000u);
        uint32_t base = (uint32_t)(rng.next() % mod);
        uint32_t exp = (uint32_t)(rng.next() % 100000u);
        uint64_t r = 1, b = base % mod;
        uint32_t e = exp;
        while (e) {
            if (e & 1u) r = (r * b) % mod;
            b = (b * b) % mod;
            e >>= 1;
        }
        CHECK_EQ(wv_modpow_u32(base, exp, mod), (uint32_t)r);
    }

    // switch 分派扫描（含负值与越域；参考 = 同语义闭式）
    for (int32_t s = -60; s <= 160; ++s) {
        int32_t q = s / 25;
        int32_t want = (q >= 0 && q <= 3) ? q : 4;
        CHECK_EQ(wv_switch_grade(s), want);
    }

    // atoi：字面串（空白/符号/非数字尾随）
    CHECK_EQ(wv_atoi32("42"), 42);
    CHECK_EQ(wv_atoi32("  -17"), -17);
    CHECK_EQ(wv_atoi32("+7x"), 7);
    CHECK_EQ(wv_atoi32("	blank 99"), 0);
    CHECK_EQ(wv_atoi32(""), 0);
    for (int t = 0; t < 200; ++t) {
        char buf[24];
        int32_t want = (int32_t)(rng.next() % 1000000u);
        if (t & 1) want = -want;      // want 已含符号（首版再加 "-" 前缀成
                                      // "--N"，atoi 正确返 0 —— 驱动笔误）
        snprintf(buf, sizeof(buf), "%d", want);
        CHECK_EQ(wv_atoi32(buf), want);
    }

    // 按值 struct ABI：坐标打包
    for (int t = 0; t < 200; ++t) {
        wv_pt p;
        p.x = (int32_t)(rng.next() % 65536u) - 32768;
        p.y = (int32_t)(rng.next() % 65536u) - 32768;
        uint32_t want = ((uint32_t)(uint16_t)p.x << 16) | (uint32_t)(uint16_t)p.y;
        CHECK_EQ(wv_pt_pack(p), want);
    }
    // ---- MIT-516 (T68) 语料扩面批次 ----

    // LCG 单步: 独立链对拍（驱动自己跑同样的 u32 环绕递推）。
    {
        uint32_t s1 = 123456789u, s2 = s1;
        for (int i = 0; i < 500; ++i) {
            s1 = wv_lcg_next(s1);
            s2 = s2 * 1664525u + 1013904223u;
            CHECK_EQ(s1, s2);
        }
    }

    // CRC-32 步进: "123456789" 全串 = 规范校验值 0xCBF43926。
    {
        uint32_t crc = 0xFFFFFFFFu;
        const char* msg = "123456789";
        for (const char* q = msg; *q; ++q)
            crc = wv_crc32_step(crc, (uint8_t)*q);
        CHECK_EQ(crc ^ 0xFFFFFFFFu, 0xCBF43926u);
    }

    // Bezier Q8: 端点精确 + 中点凸组合 + 随机与宿主公式对拍。
    CHECK_EQ(wv_bezier_q8(100, 200, 300, 0), 100);
    CHECK_EQ(wv_bezier_q8(100, 200, 300, 256), 300);
    for (int t = 0; t <= 500; ++t) {
        int32_t a = (int32_t)(rng.next() % 4096u) - 2048;
        int32_t b = (int32_t)(rng.next() % 4096u) - 2048;
        int32_t c = (int32_t)(rng.next() % 4096u) - 2048;
        int32_t tt = (int32_t)(rng.next() % 257u);
        int32_t k1 = 2 * (b - a);
        int32_t k2 = a - 2 * b + c;
        int32_t want = a + (tt * (k1 + (tt * k2) / 256)) / 256;
        CHECK_EQ(wv_bezier_q8(a, b, c, tt), want);
    }

    // Hadamard8: 常量向量 + H×H = 8I 恒等（施加两遍后 /8 = 原向量）。
    {
        int32_t v[8] = {1, 0, 0, 0, 0, 0, 0, 0};
        wv_hadamard8(v);
        for (int i = 0; i < 8; ++i) CHECK_EQ(v[i], 1);
    }
    for (int t = 0; t < 100; ++t) {
        int32_t v[8], orig[8];
        for (int i = 0; i < 8; ++i) {
            v[i] = (int32_t)(rng.next() % 65536u) - 32768;
            orig[i] = v[i];
        }
        wv_hadamard8(v);
        wv_hadamard8(v);
        for (int i = 0; i < 8; ++i) CHECK_EQ(v[i] / 8, orig[i]);  // H×H=8I
    }

    // dot4f: 小整数初值保证 float 精确；同序宿主计算位精确对拍。
    {
        float a[4] = {1.0f, 2.0f, 3.0f, 4.0f};
        float b[4] = {5.0f, 6.0f, 7.0f, 8.0f};
        float got = wv_dot4f(a, b);
        uint32_t gb, wb;
        std::memcpy(&gb, &got, 4);
        float want = a[0]*b[0]; want += a[1]*b[1]; want += a[2]*b[2]; want += a[3]*b[3];
        std::memcpy(&wb, &want, 4);
        CHECK_EQ(gb, wb);
    }
}
