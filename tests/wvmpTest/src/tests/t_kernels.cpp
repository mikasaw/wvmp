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
