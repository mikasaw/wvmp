// t_hashcrypto.cpp - CRC32, Adler-32, FNV-1a, MD5, SHA-256, HMAC-SHA256,
// RC4, XTEA, Base64. Arithmetic/bit-heavy workloads exercising rotation,
// carry propagation, byte-order assembly and dense loops - prime material
// for catching VM translation bugs.
//
// Digest constant tables are DERIVED at startup (sin()/roots of primes) and
// validated against well-known anchor words, so no hand-typed typo tables.
#include "../testfw.h"
#include "../common.h"

#include <cmath>
#include <string>
#include <vector>

using namespace wv;

static u32 rotl32_(u32 x, int c) { return c == 0 ? x : ((x << c) | (x >> (32 - c))); }
static u32 rotr32_(u32 x, int c) { return c == 0 ? x : ((x >> c) | (x << (32 - c))); }

// ===========================================================================
// MD5
// ===========================================================================
static const u32* md5_table() {
    static u32 T[64];
    static bool ok = []() {
        for (int i = 0; i < 64; ++i)
            T[i] = (u32)(std::fabs(std::sin((double)i + 1.0)) * 4294967296.0);
        return T[0] == 0xd76aa478u && T[1] == 0xe8c7b756u &&
               T[63] == 0xeb86d391u;
    }();
    if (!ok) FAIL_AT(__FILE__, __LINE__, "MD5 sine-table anchors failed");
    return T;
}

struct MD5 {
    u32 st[4] = { 0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u };
    u64 nbytes = 0;
    u8 buf[64];
    size_t blen = 0;

    void compress(const u8* p) {
        u32 m[16];
        for (int i = 0; i < 16; ++i)
            m[i] = (u32)p[4*i] | ((u32)p[4*i+1] << 8) |
                   ((u32)p[4*i+2] << 16) | ((u32)p[4*i+3] << 24);
        const u32* T = md5_table();
        static const int S[4][4] = {
            { 7, 12, 17, 22 }, { 5, 9, 14, 20 },
            { 4, 11, 16, 23 }, { 6, 10, 15, 21 },
        };
        u32 A = st[0], B = st[1], C = st[2], D = st[3];
        for (int i = 0; i < 64; ++i) {
            u32 F; int g, s;
            if (i < 16)      { F = (B & C) | (~B & D);  g = i;              s = S[0][i & 3]; }
            else if (i < 32) { F = (D & B) | (~D & C);  g = (5*i + 1) % 16; s = S[1][i & 3]; }
            else if (i < 48) { F = B ^ C ^ D;           g = (3*i + 5) % 16; s = S[2][i & 3]; }
            else             { F = C ^ (B | ~D);        g = (7*i) % 16;     s = S[3][i & 3]; }
            u32 tmp = D;
            D = C;
            C = B;
            B = B + rotl32_(A + F + T[i] + m[g], s);
            A = tmp;
        }
        st[0] += A; st[1] += B; st[2] += C; st[3] += D;
    }
    void absorb(const u8* p, size_t n) {          // does NOT touch nbytes
        while (n) {
            size_t take = 64 - blen;
            if (take > n) take = n;
            memcpy(buf + blen, p, take);
            blen += take; p += take; n -= take;
            if (blen == 64) { compress(buf); blen = 0; }
        }
    }
    void update(const void* d, size_t n) {
        nbytes += n;
        absorb((const u8*)d, n);
    }
    void finish(u8 out[16]) {
        u64 bits = nbytes * 8;
        u8 tail[72];
        size_t t = 0;
        tail[t++] = 0x80;
        while ((blen + t) % 64 != 56) tail[t++] = 0;
        for (int i = 0; i < 8; ++i)               // little-endian length
            tail[t++] = (u8)(bits >> (8 * i));
        absorb(tail, t);                          // t <= 71 always fits buffer
        for (int i = 0; i < 4; ++i)
            for (int j = 0; j < 4; ++j)
                out[4*i+j] = (u8)(st[i] >> (8 * j));
    }
};

static std::string md5_hex(const std::string& s) {
    MD5 h;
    h.update(s.data(), s.size());
    u8 dg[16];
    h.finish(dg);
    std::string o(32, '.');
    for (int i = 0; i < 16; ++i) snprintf(&o[i*2], 3, "%02x", dg[i]);
    return o;
}

// ===========================================================================
// SHA-256
// ===========================================================================
static bool wv_is_prime(u32 n) {
    if (n < 2) return false;
    for (u32 d = 2; d * d <= n; ++d) if (n % d == 0) return false;
    return true;
}

static const u32* sha256_h0() {
    static u32 H[8];
    static bool ok = []() {
        int i = 0;
        for (u32 p = 2; i < 8; ++p)
            if (wv_is_prime(p)) {
                long double r = std::sqrt((long double)p);
                H[i++] = (u32)((r - std::floor(r)) * 4294967296.0L);
            }
        return H[0] == 0x6a09e667u && H[1] == 0xbb67ae85u &&
               H[7] == 0x5be0cd19u;
    }();
    if (!ok) FAIL_AT(__FILE__, __LINE__, "sha256 H0 anchors failed");
    return H;
}

static const u32* sha256_k() {
    static u32 K[64];
    static bool ok = []() {
        int i = 0;
        for (u32 p = 2; i < 64; ++p)
            if (wv_is_prime(p)) {
                long double r = std::pow((long double)p, 1.0L / 3.0L);
                K[i++] = (u32)((r - std::floor(r)) * 4294967296.0L);
            }
        return K[0] == 0x428a2f98u && K[63] == 0xc67178f2u;
    }();
    if (!ok) FAIL_AT(__FILE__, __LINE__, "sha256 K anchors failed");
    return K;
}

struct SHA256 {
    u32 h[8];
    u8 buf[64];
    size_t blen = 0;
    u64 nbytes = 0;

    SHA256() {
        const u32* H0 = sha256_h0();
        for (int i = 0; i < 8; ++i) h[i] = H0[i];
        memset(buf, 0, sizeof(buf));
    }

    void compress(const u8* p) {
        static const u32* K = NULL;
        if (!K) K = sha256_k();
        u32 w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = ((u32)p[4*i] << 24) | ((u32)p[4*i+1] << 16) |
                   ((u32)p[4*i+2] << 8) | (u32)p[4*i+3];
        for (int i = 16; i < 64; ++i) {
            u32 s0 = rotr32_(w[i-15], 7) ^ rotr32_(w[i-15], 18) ^ (w[i-15] >> 3);
            u32 s1 = rotr32_(w[i-2], 17) ^ rotr32_(w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        u32 a=h[0], b=h[1], c=h[2], d=h[3], e=h[4], f=h[5], g=h[6], hh=h[7];
        for (int i = 0; i < 64; ++i) {
            u32 S1 = rotr32_(e, 6) ^ rotr32_(e, 11) ^ rotr32_(e, 25);
            u32 ch = (e & f) ^ (~e & g);
            u32 t1 = hh + S1 + ch + K[i] + w[i];
            u32 S0 = rotr32_(a, 2) ^ rotr32_(a, 13) ^ rotr32_(a, 22);
            u32 mj = (a & b) ^ (a & c) ^ (b & c);
            u32 t2 = S0 + mj;
            hh=g; g=f; f=e; e=d+t1;
            d=c;  c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
        h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    void absorb(const u8* p, size_t n) {
        while (n) {
            size_t take = 64 - blen;
            if (take > n) take = n;
            memcpy(buf + blen, p, take);
            blen += take; p += take; n -= take;
            if (blen == 64) { compress(buf); blen = 0; }
        }
    }
    void update(const void* d, size_t n) {
        nbytes += n;
        absorb((const u8*)d, n);
    }
    void finish(u8 out[32]) {
        u64 bits = nbytes * 8;
        u8 tail[72];
        size_t t = 0;
        tail[t++] = 0x80;
        while ((blen + t) % 64 != 56) tail[t++] = 0;
        for (int i = 0; i < 8; ++i)               // big-endian length
            tail[t++] = (u8)(bits >> (8 * (7 - i)));
        absorb(tail, t);
        for (int i = 0; i < 8; ++i)
            for (int j = 0; j < 4; ++j)
                out[4*i+j] = (u8)(h[i] >> (8 * (3 - j)));
    }
};

static std::string sha256_hex(const std::string& s) {
    SHA256 h;
    h.update(s.data(), s.size());
    u8 dg[32];
    h.finish(dg);
    std::string o(64, '.');
    for (int i = 0; i < 32; ++i) snprintf(&o[i*2], 3, "%02x", dg[i]);
    return o;
}

// ===========================================================================
TEST(hash, md5_goldens) {
    CHECK_MSG(md5_hex("") == "d41d8cd98f00b204e9800998ecf8427e", "md5 empty");
    CHECK_MSG(md5_hex("a") == "0cc175b9c0f1b6a831c399e269772661", "md5 'a'");
    CHECK_MSG(md5_hex("abc") == "900150983cd24fb0d6963f7d28e17f72", "md5 abc");
    CHECK_MSG(md5_hex("message digest") ==
        "f96b697d7cb7938d525a2f31aaf161d0", "md5 message digest");
    CHECK_MSG(md5_hex("abcdefghijklmnopqrstuvwxyz") ==
        "c3fcd3d76192e4007dfb496cca67e13b", "md5 alphabet");
    CHECK_MSG(md5_hex(
        "1234567890123456789012345678901234567890"
        "1234567890123456789012345678901234567890") ==
        "57edf4a22be3c955ac49da2e2107b67a", "md5 digits x8");

    // incremental feed of odd-sized chunks equals one-shot hashing
    const std::string corpus =
        "The quick brown fox jumps over the lazy dog - pack me! 0123456789";
    MD5 inc;
    size_t pos = 0, step = 7;
    while (pos < corpus.size()) {
        size_t take = step < corpus.size() - pos ? step : corpus.size() - pos;
        inc.update(corpus.data() + pos, take);
        pos += take;
        ++step;
    }
    u8 dg[16];
    inc.finish(dg);
    std::string got(32, '.');
    for (int i = 0; i < 16; ++i) snprintf(&got[i*2], 3, "%02x", dg[i]);
    CHECK_MSG(got == md5_hex(corpus), "incremental == one-shot");
}

TEST(hash, sha256_goldens_and_streaming) {
    CHECK_MSG(sha256_hex("") ==
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "sha256 empty");
    CHECK_MSG(sha256_hex("abc") ==
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "sha256 abc");
    CHECK_MSG(sha256_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        "sha256 multi-block NIST vector");
    CHECK_MSG(sha256_hex("The quick brown fox jumps over the lazy dog") ==
        "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        "sha256 fox");

    std::vector<u8> blob(300);
    for (size_t i = 0; i < blob.size(); ++i) blob[i] = pattern_byte(i);
    auto run = [&](size_t chunk) {
        SHA256 h;
        size_t off = 0;
        while (off < blob.size()) {
            size_t take = chunk < blob.size() - off ? chunk : blob.size() - off;
            h.update(blob.data() + off, take);
            off += take;
        }
        u8 dg[32];
        h.finish(dg);
        std::string o(64, '.');
        for (int i = 0; i < 32; ++i) snprintf(&o[i*2], 3, "%02x", dg[i]);
        return o;
    };
    std::string ref = run(blob.size());
    CHECK(ref.size() == 64);
    for (size_t ch : { (size_t)1, (size_t)5, (size_t)31, (size_t)64, (size_t)99 })
        CHECK_MSG(run(ch) == ref, "chunked sha256 stability");

    // avalanche sanity: flipping one input bit changes many output bits
    std::vector<u8> b2 = blob;
    b2[150] ^= 0x40;
    SHA256 ha, hb;
    ha.update(b2.data(), b2.size());
    hb.update(blob.data(), blob.size());
    u8 da[32], db[32];
    ha.finish(da); hb.finish(db);
    int diff_bits = 0;
    for (int i = 0; i < 32; ++i) {
        u8 x = da[i] ^ db[i];
        for (int k = 0; k < 8; ++k) diff_bits += (x >> k) & 1;
    }
    CHECK(diff_bits >= 64);                      // healthy mixing head-room
}

// ===========================================================================
// CRC-32 (IEEE, reflected)
// ===========================================================================
struct CRC32 {
    static const u32* table() {
        static u32 t[256];
        static bool ok = []() {
            for (u32 i = 0; i < 256; ++i) {
                u32 c = i;
                for (int k = 0; k < 8; ++k)
                    c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
                t[i] = c;
            }
            return t[1] == 0x77073096u && t[255] == 0x2D02EF8Du;
        }();
        if (!ok) FAIL_AT(__FILE__, __LINE__, "crc table anchors failed");
        return t;
    }
    // streaming: chain previous returned value back in
    static u32 update(u32 state_crc /*post-invert form*/, const void* p, size_t n) {
        const u32* T = table();
        const u8* b = (const u8*)p;
        while (n--) state_crc = T[(state_crc ^ *b++) & 0xFF] ^ (state_crc >> 8);
        return state_crc;
    }
};

static u32 crc32_buf(const void* p, size_t n) {
    return ~CRC32::update(0xFFFFFFFFu, p, n);
}

TEST(hash, crc32_stream_split) {
    CHECK_MSG(crc32_buf("", 0) == 0u, "crc empty");
    const char* nine = "123456789";
    CHECK_MSG(crc32_buf(nine, 9) == 0xCBF43926u, "crc check-value");
    const char* fox = "The quick brown fox jumps over the lazy dog";
    CHECK_MSG(crc32_buf(fox, strlen(fox)) == 0x414FA339u, "crc fox");

    std::vector<u8> blob(1000);
    for (size_t i = 0; i < blob.size(); ++i) blob[i] = pattern_byte(i * 7 + 3);
    u32 whole = crc32_buf(blob.data(), blob.size());

    // arbitrary cut point must reproduce the same value through chaining
    for (size_t cut : { (size_t)0, (size_t)1, (size_t)33, (size_t)500,
                        (size_t)999, blob.size() }) {
        u32 chained = ~CRC32::update(
            CRC32::update(0xFFFFFFFFu, blob.data(), cut),
            blob.data() + cut, blob.size() - cut);
        CHECK_EQ(chained, whole);
    }
}

TEST(hash, adler32_concat_identity) {
    auto adler = [](const u8* p, size_t n, u32 sa = 1, u32 sb = 0) {
        for (size_t i = 0; i < n; ++i) {
            sa = (sa + p[i]) % 65521u;
            sb = (sb + sa) % 65521u;
        }
        return std::make_pair(sa, sb);
    };
    const char* w = "Wikipedia";
    auto rw = adler((const u8*)w, 9);
    CHECK_MSG((rw.second << 16 | rw.first) == 0x11E60398u, "adler 'Wikipedia'");

    auto re = adler(NULL, 0);
    CHECK(re.first == 1 && re.second == 0);

    // (a,b)-carried concatenation must match whole-buffer processing
    Rng rng(4711u);
    std::vector<u8> blob(400);
    for (auto& x : blob) x = (u8)rng.u32n();
    for (size_t cut : { (size_t)1, (size_t)127, (size_t)399 }) {
        auto first = adler(blob.data(), cut);
        auto both = adler(blob.data() + cut, blob.size() - cut,
                          first.first, first.second);
        auto direct = adler(blob.data(), blob.size());
        CHECK(both.first == direct.first && both.second == direct.second);
    }
}

TEST(hash, fnv_basis_and_vectors) {
    CHECK_EQ(fnv1a32_buf("", 0), 0x811C9DC5u);
    CHECK_EQ(fnv1a32_buf("a", 1), 0xE40C292Cu);

    // order sensitivity: permuted buffers disagree
    std::vector<u8> x{ 1, 2, 3, 4, 5 }, y{ 5, 4, 3, 2, 1 };
    CHECK(fnv1a32_buf(x.data(), x.size()) != fnv1a32_buf(y.data(), y.size()));
    u32 acc = 0;
    for (int i = 0; i < 50; ++i)
        acc ^= fnv1a32_buf(&i, sizeof(i));
    CHECK(acc != 0);
}

// ===========================================================================
// RC4
// ===========================================================================
struct RC4 {
    u8 S[256];
    size_t I = 0, J = 0;

    RC4(const u8* key, size_t klen) {
        for (int i = 0; i < 256; ++i) S[i] = (u8)i;
        size_t j = 0;
        for (int i = 0; i < 256; ++i) {
            j = (j + S[i] + key[i % klen]) % 256;
            std::swap(S[i], S[(size_t)j]);
        }
        I = J = 0;
    }
    void crypt(u8* p, size_t n) {
        for (size_t k = 0; k < n; ++k) {
            I = (I + 1) % 256;
            J = (J + S[I]) % 256;
            std::swap(S[I], S[J]);
            p[k] ^= S[(S[I] + S[J]) % 256];
        }
    }
};

TEST(hash, rc4_vector_and_roundtrip) {
    const char* pt = "Plaintext";
    const char* key = "Key";
    u8 buf[16];
    memcpy(buf, pt, 9);
    RC4 r1((const u8*)key, 3);
    r1.crypt(buf, 9);
    const u8 want[9] = { 0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3 };
    CHECK(memcmp(buf, want, 9) == 0);

    // fresh instance decrypts identically (XOR involution)
    RC4 r2((const u8*)key, 3);
    r2.crypt(buf, 9);
    CHECK(memcmp(buf, pt, 9) == 0);

    // stream determinism across sizes and key domains
    Rng rng(9001u);
    for (int t = 0; t < 60; ++t) {
        u8 ksalt[13];
        for (auto& c : ksalt) c = (u8)rng.u32n();
        std::vector<u8> msg(rng.irange(1, 700));
        for (auto& c : msg) c = (u8)rng.u32n();
        std::vector<u8> saved = msg;

        RC4 ra(ksalt, sizeof(ksalt));
        ra.crypt(msg.data(), msg.size());
        CHECK(memcmp(msg.data(), saved.data(), msg.size()) != 0);
        RC4 rb(ksalt, sizeof(ksalt));
        rb.crypt(msg.data(), msg.size());
        CHECK(memcmp(msg.data(), saved.data(), msg.size()) == 0);
    }
}

// ===========================================================================
// XTEA (32 cycles, reference formulation)
// ===========================================================================
static void xtea_encipher(u32 v[2], const u32 k[4]) {
    u32 v0 = v[0], v1 = v[1], sum = 0;
    const u32 delta = 0x9E3779B9u;
    for (int i = 0; i < 32; ++i) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
    }
    v[0] = v0; v[1] = v1;
}
static void xtea_decipher(u32 v[2], const u32 k[4]) {
    u32 v0 = v[0], v1 = v[1];
    u32 sum = 0xC6EF3720u;                       // delta * 32
    const u32 delta = 0x9E3779B9u;
    for (int i = 0; i < 32; ++i) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
    }
    v[0] = v0; v[1] = v1;
}

TEST(hash, xtea_roundtrip_and_key_sensitivity) {
    CHECK_EQ(0x9E3779B9u * 32u, 0xC6EF3720u);    // delta*32 feeds the decipher

    Rng rng(5150u);
    for (int t = 0; t < 120; ++t) {
        u32 k[4] = { rng.u32n(), rng.u32n(), rng.u32n(), rng.u32n() };
        u32 blk[2] = { rng.u32n(), rng.u32n() };
        u32 orig[2] = { blk[0], blk[1] };

        xtea_encipher(blk, k);
        CHECK(blk[0] != orig[0] || blk[1] != orig[1]);   // data actually moved
        u32 cipher_a[2] = { blk[0], blk[1] };

        xtea_decipher(blk, k);
        CHECK(blk[0] == orig[0] && blk[1] == orig[1]);

        // one flipped key bit yields different ciphertext for this block
        u32 k2[4] = { k[0], k[1], k[2], k[3] };
        k2[t % 4] ^= (1u << (t % 31));
        u32 b2[2] = { orig[0], orig[1] };
        xtea_encipher(b2, k2);
        CHECK(b2[0] != cipher_a[0] || b2[1] != cipher_a[1]);
    }
}

// ===========================================================================
// Base64 (RFC 4648 alphabet)
// ===========================================================================
static const char* B64_ALPHA =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string b64_encode(const u8* p, size_t n) {
    std::string o;
    o.reserve(((n + 2) / 3) * 4);
    size_t i = 0;
    for (; i + 2 < n; i += 3) {
        u32 grp = ((u32)p[i] << 16) | ((u32)p[i+1] << 8) | p[i+2];
        o += B64_ALPHA[(grp >> 18) & 63];
        o += B64_ALPHA[(grp >> 12) & 63];
        o += B64_ALPHA[(grp >> 6) & 63];
        o += B64_ALPHA[grp & 63];
    }
    if (i + 1 == n) {
        u32 grp = (u32)p[i] << 16;
        o += B64_ALPHA[(grp >> 18) & 63];
        o += B64_ALPHA[(grp >> 12) & 63];
        o += "==";
    } else if (i + 2 == n) {
        u32 grp = ((u32)p[i] << 16) | ((u32)p[i+1] << 8);
        o += B64_ALPHA[(grp >> 18) & 63];
        o += B64_ALPHA[(grp >> 12) & 63];
        o += B64_ALPHA[(grp >> 6) & 63];
        o += '=';
    }
    return o;
}

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static bool b64_decode(const std::string& s, std::vector<u8>& out) {
    out.clear();
    u32 acc = 0;
    int bits = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '=') continue;
        int d = b64_val(c);
        if (d < 0) return false;
        acc = (acc << 6) | (u32)d;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((u8)((acc >> bits) & 0xFF));
        }
    }
    return true;
}

TEST(hash, base64_rfc4648_vectors) {
    struct BV { const char* raw; const char* enc; };
    const BV vecs[] = {
        { "",       "" },         { "f",      "Zg==" },
        { "fo",     "Zm8=" },     { "foo",    "Zm9v" },
        { "foob",   "Zm9vYg==" }, { "fooba",  "Zm9vYmE=" },
        { "foobar", "Zm9vYmFy" },
    };
    for (const BV& v : vecs) {
        std::string got = b64_encode((const u8*)v.raw, strlen(v.raw));
        CHECK_MSG(got == v.enc, ("encode '" + std::string(v.raw) + "'").c_str());
        std::vector<u8> back;
        CHECK(b64_decode(v.enc, back));
        CHECK_MSG(back.size() == strlen(v.raw) &&
                  memcmp(back.data(), v.raw, back.size()) == 0,
                  "decode round trip");
    }

    Rng rng(60066u);
    for (int t = 0; t < 40; ++t) {
        std::vector<u8> raw(rng.irange(0, 300));
        for (auto& c : raw) c = (u8)rng.u32n();
        std::string enc = b64_encode(raw.data(), raw.size());
        std::vector<u8> back;
        CHECK(b64_decode(enc, back));
        CHECK(back.size() == raw.size());
        CHECK(memcmp(back.data(), raw.data(), raw.size()) == 0);
    }
    std::vector<u8> junk;
    CHECK_MSG(!b64_decode("ab!c", junk), "invalid character rejected");
}

// ===========================================================================
// HMAC-SHA256
// ===========================================================================
static std::string hmac_sha256_hex(const std::string& key, const std::string& msg) {
    u8 k0[64];
    memset(k0, 0, sizeof(k0));
    if (key.size() > 64) {
        SHA256 kh;
        kh.update(key.data(), key.size());
        u8 kd[32];
        kh.finish(kd);
        memcpy(k0, kd, 32);
    } else {
        memcpy(k0, key.data(), key.size());
    }
    u8 ipad[64], opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5C;
    }
    SHA256 inner;
    inner.update(ipad, 64);
    inner.update(msg.data(), msg.size());
    u8 ih[32];
    inner.finish(ih);
    SHA256 outer;
    outer.update(opad, 64);
    outer.update(ih, 32);
    u8 oh[32];
    outer.finish(oh);
    std::string o(64, '.');
    for (int i = 0; i < 32; ++i) snprintf(&o[i*2], 3, "%02x", oh[i]);
    return o;
}

TEST(hash, hmac_sha256_known_vector) {
    CHECK_MSG(hmac_sha256_hex("key",
              "The quick brown fox jumps over the lazy dog") ==
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
        "hmac canonical fox");
    // long-key branch hashes down first
    CHECK(hmac_sha256_hex(std::string(80, 'z'), "payload").size() == 64);
}

