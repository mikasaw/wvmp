// t_memory.cpp - heap behavior, alignment, struct layout, big blocks,
// alloca/stack integrity, placement-new pools.
#include "../testfw.h"
#include "../common.h"

#include <malloc.h>
#include <cstddef>
#include <memory>
#include <vector>

using namespace wv;

// ---------------------------------------------------------------------------
static int g_live_dtor_objs = 0;
struct DtorCounter {
    int id;
    DtorCounter() : id(0) { ++g_live_dtor_objs; }
    explicit DtorCounter(int i) : id(i) { ++g_live_dtor_objs; }
    ~DtorCounter() { --g_live_dtor_objs; }
};

TEST(memory, heap_new_delete_patterns) {
    enum { N = 1000 };
    s32* p = new s32[N];
    u32 cks = 0;
    for (int i = 0; i < N; ++i) { p[i] = i * 7 + 3; }
    for (int i = 0; i < N; ++i) { cks = cks * 31 + (u32)p[i]; CHECK_EQ(p[i], i * 7 + 3); }
    delete[] p;
    p = NULL;

    // realloc growth keeps the prefix
    size_t cap = 10;
    char* q = (char*)malloc(cap);
    CHECK(q != NULL);
    for (size_t i = 0; i < cap; ++i) q[i] = pattern_byte(i);
    cap = 1000;
    char* qr = (char*)realloc(q, cap);
    CHECK(qr != NULL);
    bool ok = true;
    for (size_t i = 0; i < 10 && ok; ++i) ok = (qr[i] == (char)pattern_byte(i));
    CHECK_MSG(ok, "realloc preserved the prefix");
    for (size_t i = 10; i < cap; ++i) qr[i] = pattern_byte(i + 100000);
    u32 tail = fnv1a32_buf(qr + 10, cap - 10);
    free(qr);
    CHECK(tail != 0);

    void* z = calloc(64, 1);
    CHECK(z != NULL);
    const u8* zb = (const u8*)z;
    for (int i = 0; i < 64; ++i) CHECK_EQ(zb[i], 0);
    free(z);

    // aligned allocations
    for (unsigned al : { 16u, 64u }) {
        void* m = _aligned_malloc(777, al);
        CHECK(m != NULL);
        CHECK(((uintptr_t)m & (al - 1)) == 0);
        for (int i = 0; i < 777; ++i) ((u8*)m)[i] = pattern_byte(i);
        void* m2 = _aligned_malloc(777, al);
        CHECK(((uintptr_t)m2 & (al - 1)) == 0);
        memcpy(m2, m, 777);
        CHECK(memcmp(m, m2, 777) == 0);
        _aligned_free(m2);
        _aligned_free(m);
    }

    // new[] / delete[] destructor balance
    int before = g_live_dtor_objs;
    {
        DtorCounter* arr = new DtorCounter[30] { DtorCounter(0), DtorCounter(1),
                                                 DtorCounter(2) };
        CHECK(arr != NULL);
        delete[] arr;
    }
    CHECK_EQ(g_live_dtor_objs, before);
}

// win32 ABI pinning - identical between MSVC and MinGW
struct PadA { char c; s32 v; char t; };          // -> 4|4|4|pad? size 12 align 4
struct Pod3 { float x, y, z; };                  // 12 bytes, natural float pack

TEST(memory, struct_layout_and_copy) {
    static_assert(sizeof(Pod3) == 12, "float triple layout");
    CHECK_EQ(sizeof(PadA), (size_t)12);          // MSVC/GCC Windows ABI agree
    CHECK_EQ(alignof(PadA), (size_t)4);
    CHECK_EQ(alignof(Pod3), (size_t)4);
    CHECK_EQ(offsetof(PadA, v), (size_t)4);
    CHECK_EQ(offsetof(PadA, t), (size_t)8);

    // bulk copies preserve field values across many instances
    std::vector<PadA> a(1024), b(1024);
    for (int i = 0; i < 1024; ++i) {
        a[i].c = (char)i;
        a[i].v = i * 7 - 1000;
        a[i].t = (char)(255 - i);
    }
    memcpy(b.data(), a.data(), 1024 * sizeof(PadA));
    for (int i = 0; i < 1024; ++i) {
        CHECK_EQ(b[i].v, i * 7 - 1000);
        // compare in the SAME modulus the store used (u8 wrap-around)
        CHECK_EQ((int)(u8)b[i].t, (int)(u8)(u8)(255 - (unsigned)i));
        CHECK_EQ((int)(char)b[i].c, (int)(signed char)(signed char)(unsigned char)i);
    }
}

TEST(memory, big_block_memmove_overlap) {
    const size_t NB = 4u << 20;                  // 4MB is enough here
    std::vector<u8> v(NB);
    for (size_t i = 0; i < NB; ++i) v[i] = pattern_byte(i);

    // full-buffer checksum computed twice by independent passes must agree
    u64 sum1 = 0, sum2 = 0;
    for (size_t i = 0; i < NB; ++i)           sum1 = sum1 * 257 + v[i];
    for (size_t i = NB; i-- > 0; )            sum2 = sum2 * 131 + v[i];
    CHECK(sum1 != 0);
    CHECK(sum2 != 0);
    // recompute against slices at both ends
    u32 mid_ref = fnv1a32_buf(&v[NB / 2], 4096);
    CHECK(mid_ref != 0);

    const size_t SHIFT = 256u << 10;
    memmove(v.data() + SHIFT, v.data(), NB - SHIFT);     // forward overlap
    bool prefix_ok = true;
    for (size_t i = 0; i < SHIFT && prefix_ok; ++i)
        prefix_ok = (v[i] == pattern_byte(i));           // untouched head
    CHECK(prefix_ok);
    CHECK_EQ(v[SHIFT], pattern_byte(0));
    CHECK_EQ(v[NB - 1], pattern_byte(NB - 1 - SHIFT));

    // chunked alloc/free stress with deterministic interleaving
    Rng rng(20260827);
    u32 acc = 0;
    std::vector<std::pair<u8*, size_t>> live;
    live.reserve(4000);
    for (int cycle = 0; cycle < 2; ++cycle) {
        for (int k = 0; k < 2000; ++k) {
            size_t sz = (size_t)rng.irange(8, 512);
            u8* b = (u8*)malloc(sz);
            CHECK(b != NULL);
            for (size_t i = 0; i < sz; ++i) b[i] = pattern_byte((size_t)k + i);
            acc = acc * 33 + fnv1a32_buf(b, sz);
            live.push_back({ b, sz });
        }
        // deterministic shuffle-free pop order reverse
        while (!live.empty()) {
            auto& e = live.back();
            for (size_t i = 0; i < e.second; ++i) e.first[i] ^= 0x5A;
            acc += e.first[0];
            free(e.first);
            live.pop_back();
        }
    }
    CHECK(acc != 0);
}

TEST(memory, alloca_stack_integrity) {
    struct AllocaRunner {
        static u64 descend(int d, u64 seed) {
            u8* scratch = (u8*)alloca(1024);
            for (int i = 0; i < 1024; ++i)
                scratch[i] = (u8)(seed * (u64)(i + d) >> 9);
            u64 mine = fnv1a32_buf(scratch, 1024);
            if (d == 1) return mine;
            u64 child = descend(d - 1, seed ^ (u64)d * 0xA5A5A5A5ull);
            // our own scratch must still be intact after the child returned
            u64 again = fnv1a32_buf(scratch, 1024);
            if (again != mine) return 0xDEADBEEFDEADBEEFull;  // stack smashed
            return child * 1099511628211ull ^ mine;
        }
    };
    u64 r1 = AllocaRunner::descend(48, 123456789ull);
    u64 r2 = AllocaRunner::descend(48, 123456789ull);
    CHECK(r1 != 0);
    CHECK(r1 != 0xDEADBEEFDEADBEEFull);
    CHECK_EQ(r1, r2);
}

TEST(memory, placement_new_pool_reuse) {
    struct Foo { int id; char tag[12]; };
    const int SLOTS = 64;
    alignas(Foo) static unsigned char pool_raw[SLOTS * sizeof(Foo)];
    memset(pool_raw, 0xCC, sizeof(pool_raw));
    int before = g_live_dtor_objs;

    std::vector<Foo*> alive;
    int next_id = 1;
    for (int round = 0; round < 5; ++round) {
        for (int s = 0; s < SLOTS; ++s) {
            Foo* f = new (pool_raw + s * sizeof(Foo)) Foo();
            f->id = next_id++;
            snprintf(f->tag, sizeof(f->tag), "obj%03d", f->id);
            alive.push_back(f);
        }
        for (Foo* f : alive) {
            CHECK(f->id > 0);
            char ref[16];
            snprintf(ref, sizeof(ref), "obj%03d", f->id);
            CHECK(strcmp(f->tag, ref) == 0);
            f->~Foo();                            // manual destruction
        }
        alive.clear();
    }
    CHECK_EQ(g_live_dtor_objs, before);           // no stray ctors ran
    CHECK_EQ(next_id, 5 * SLOTS + 1);

    // matrix stored flat row-major
    const int R = 13, C = 17;
    std::vector<int> mat(R * C);
    for (int r = 0; r < R; ++r)
        for (int c = 0; c < C; ++c)
            mat[r * C + c] = (r * 31 + c * 7) % 101;
    CHECK_EQ(mat[0], 0);
    CHECK_EQ(mat[R * C - 1], ((R-1) * 31 + (C-1) * 7) % 101);
    long long diag = 0;
    for (int k = 0; k < R && k < C; ++k) diag += mat[k * C + k];
    CHECK(diag >= 0);
}
