// t_controlflow.cpp - branches, jump tables, recursion, indirect calls.
#include "../testfw.h"
#include "../common.h"

#include <functional>
#include <vector>

using namespace wv;

typedef s32 (*binop_t)(s32, s32);

static s32 op_add(s32 a, s32 b) { return a + b; }
static s32 op_sub(s32 a, s32 b) { return a - b; }
static s32 op_mul(s32 a, s32 b) { return a * b; }
static s32 op_xor(s32 a, s32 b) { return a ^ b; }

static s32 apply_switch(int sel, s32 a, s32 b) {
    switch (sel) {                              // dense -> likely jump table
        case 0: return a + b;
        case 1: return a - b;
        case 2: return a * b;
        case 3: return a ^ b;
        case 4: return a + 2 * b;
        case 5: return 3 * a - b;
        case 6: return (a & 0xFFFF) | (b << 16);
        case 7: return ~(a ^ b);
        case 8: return (a << 2) - b;
        case 9: return a + (b >> 1);
        default: return -559038737;             // 0xDEADBEEF truncated
    }
}

TEST(flow, switch_dispatch_matches_table) {
    binop_t table[4] = { op_add, op_sub, op_mul, op_xor };
    Rng rng(606);
    for (int i = 0; i < 600; ++i) {
        s32 a = (s32)rng.next(), b = (s32)rng.next();
        int sel = rng.irange(0, 9);
        s32 via_switch = apply_switch(sel, a, b);
        s32 expect;
        switch (sel) {                          // independent recomputation
            case 0: expect = a + b; break;
            case 1: expect = a - b; break;
            case 2: expect = a * b; break;
            case 3: expect = a ^ b; break;
            case 4: expect = a + 2 * b; break;
            case 5: expect = 3 * a - b; break;
            case 6: expect = (a & 0xFFFF) | (b << 16); break;
            case 7: expect = ~(a ^ b); break;
            case 8: expect = (a << 2) - b; break;
            default: expect = a + (b >> 1); break;
        }
        CHECK_EQ(via_switch, expect);
        if (sel < 4) CHECK_EQ(table[sel](a, b), via_switch);
    }
    CHECK_EQ(apply_switch(42, 1, 2), -559038737);   // default arm
    CHECK_EQ(apply_switch(-1, 1, 2), -559038737);
}

TEST(flow, sparse_switch) {
    auto classify = [](int code) -> const char* {
        switch (code) {
            case 0x0004:      return "idle";
            case 0x0100:      return "busy";
            case 0x10000000:  return "critical";
            case 0x7FFFFFFF:  return "edge";
            case -2147483647 - 1: return "min";     // INT_MIN without UB warning
            default:          return "other";
        }
    };
    CHECK_MSG(strcmp(classify(0x0004), "idle") == 0, "dense-low");
    CHECK_MSG(strcmp(classify(0x0100), "busy") == 0, "near-low");
    CHECK_MSG(strcmp(classify(0x10000000), "critical") == 0, "high");
    CHECK_MSG(strcmp(classify(0x7FFFFFFF), "edge") == 0, "max");
    CHECK_MSG(strcmp(classify(INT_MIN), "min") == 0, "min");
    CHECK_MSG(strcmp(classify(12345), "other") == 0, "default");
    CHECK_MSG(strcmp(classify(-(1 << 30)), "other") == 0, "large-gap default A");
    CHECK_MSG(strcmp(classify(1 << 30), "other") == 0, "large-gap default B");
}

// classic Duff's device byte copy - the batch counter n (not the element
// count!) drives termination, so both pointers advance exactly count bytes
static void duff_copy(u8* to, const u8* from, size_t count) {
    size_t batches = (count + 7) / 8;
    switch (count % 8) {
        case 0: do { *to++ = *from++;
        case 7:      *to++ = *from++;
        case 6:      *to++ = *from++;
        case 5:      *to++ = *from++;
        case 4:      *to++ = *from++;
        case 3:      *to++ = *from++;
        case 2:      *to++ = *from++;
        case 1:      *to++ = *from++;
                } while (--batches > 0);
    }
}

TEST(flow, duff_device_matches_memcpy) {
    static const size_t PAD = 16;
    for (size_t n = 1; n <= 40; ++n) {           // sweeps every case label
        u8 guardA[PAD + 64 + PAD], guardB[PAD + 64 + PAD];
        for (size_t i = 0; i < PAD + 64 + PAD; ++i) {
            guardA[i] = pattern_byte(i);         // source carries sentinels too
            guardB[i] = 0x77;                    // dest starts as pure sentinel
        }
        const u8* src = guardA + PAD;
        u8* dst = guardB + PAD;

        duff_copy(dst, src, n);

        CHECK(memcmp(dst, src, n) == 0);         // copied span exact
        for (size_t i = 0; i < PAD; ++i) {       // sentinels intact
            CHECK_EQ((int)guardB[i], 0x77);
            CHECK_EQ((int)guardB[PAD + 64 + i], 0x77);
        }
        if (n < 64)
            for (size_t i = n; i < 64; ++i)
                CHECK_EQ((int)dst[i], 0x77);     // no overrun past requested
    }

    // stress a large odd count against memcmp equivalence
    enum { BIG = 30011 };
    static u8 big_src[BIG], big_dst[BIG];
    for (int i = 0; i < BIG; ++i) {
        big_src[i] = pattern_byte((size_t)i * 13 + 1);
        big_dst[i] = 0;
    }
    duff_copy(big_dst, big_src, BIG);
    CHECK(memcmp(big_dst, big_src, BIG) == 0);
}

static u64 fib_rec(int n, u64 a = 0, u64 b = 1) {           // tail-style recursion
    return n == 0 ? a : fib_rec(n - 1, b, a + b);
}
static u64 fib_iter(int n) {
    u64 a = 0, b = 1;
    while (n-- > 0) { u64 t = a + b; a = b; b = t; }
    return a;
}
static int ack(int m, int n) {                               // bounded inputs only
    if (m == 0) return n + 1;
    if (n == 0) return ack(m - 1, 1);
    return ack(m - 1, ack(m, n - 1));
}
static int mutual_odd(int n);                                // mutual recursion
static int mutual_even(int n) { return n == 0 ? 1 : mutual_odd(n - 1); }
static int mutual_odd(int n)  { return n == 0 ? 0 : mutual_even(n - 1); }

static bool bsearch_rec(const s32* a, int lo, int hi, s32 key, int* out_idx) {
    if (lo > hi) return false;
    int mid = lo + (hi - lo) / 2;
    if (a[mid] == key) { *out_idx = mid; return true; }
    if (a[mid] < key) return bsearch_rec(a, mid + 1, hi, key, out_idx);
    return bsearch_rec(a, lo, mid - 1, key, out_idx);
}
static bool bsearch_iter(const s32* a, int n, s32 key, int* out_idx) {
    int lo = 0, hi = n - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (a[mid] == key) { *out_idx = mid; return true; }
        if (a[mid] < key) lo = mid + 1; else hi = mid - 1;
    }
    return false;
}

TEST(flow, recursion_variants) {
    CHECK_EQ(fib_rec(0), 0ull);
    CHECK_EQ(fib_rec(1), 1ull);
    CHECK_EQ(fib_rec(10), 55ull);
    CHECK_EQ(fib_rec(50), 12586269025ull);
    for (int n = 0; n <= 30; ++n)
        CHECK_EQ(fib_rec(n), fib_iter(n));

    CHECK_EQ(ack(0, 0), 1);
    CHECK_EQ(ack(1, 2), 4);
    CHECK_EQ(ack(2, 3), 9);
    CHECK_EQ(ack(3, 3), 61);                     // heavy nested recursion

    CHECK_EQ(mutual_even(0), 1);
    CHECK_EQ(mutual_even(17), 0);
    CHECK_EQ(mutual_odd(300), 0);                // 300 is even
    for (int n = 0; n <= 200; ++n) {
        CHECK_EQ(mutual_even(n) ^ mutual_odd(n), 1);
        CHECK_EQ(mutual_even(n), ((n % 2) == 0) ? 1 : 0);
    }

    const int N = 4096;
    static s32 arr[N];
    for (int i = 0; i < N; ++i) arr[i] = i * 3;  // strictly increasing
    Rng rng(808);
    for (int i = 0; i < 300; ++i) {
        s32 key = (s32)rng.next() % (N * 3 + 7);
        int ri = -2, ii = -2;
        bool fr = bsearch_rec(arr, 0, N - 1, key, &ri);
        bool fi = bsearch_iter(arr, N, key, &ii);
        CHECK_EQ(fr, fi);
        CHECK_EQ(ri, ii);
        if (fr) CHECK_EQ(arr[ri], key);
        // note: the cast-then-mod above can yield NEGATIVE keys - treat those
        // as absent by contract
        if (key >= 0 && key % 3 == 0 && key / 3 < N) {
            CHECK_MSG(fr, "member key must hit");
            CHECK_EQ(key / 3, ri);
        } else {
            CHECK_MSG(!fr, "absent key must miss");
        }
    }
}

TEST(flow, deep_call_chain) {
    // Plain deep recursion: f(d) = f(d-1) + d*STEP, f(0)=0, checked against
    // the closed-form Gauss sum.
    const int DEPTH = 512, STEP = 3;
    std::function<int(int)> rec = [&](int d) -> int {
        return d == 0 ? 0 : rec(d - 1) + d * STEP;
    };
    long long want = (long long)STEP * DEPTH * (DEPTH + 1) / 2;
    CHECK_EQ(rec(DEPTH), (int)want);

    // Per-frame locals must survive a deep descent. Every frame derives its
    // slot deterministically from its depth alone, so BOTH aggregates have an
    // independent closed-form recomputation - no self-reference tricks.
    struct Agg { u32 down_sum; u32 xor_up; };

    struct Runner {
        static u32 frame_val(int d, u32 seed_base) {
            return (seed_base * (u32)d) ^ 0x9E3779B9u;
        }
        static Agg descend(int d, u32 seed_base) {
            u32 myval = frame_val(d, seed_base);
            Agg agg{ myval, myval };
            if (d > 1) {
                Agg c = descend(d - 1, seed_base);
                agg.down_sum += c.down_sum;
                agg.xor_up = c.xor_up ^ (myval * 3u);   // child already folded
            }
            return agg;
        }
    };
    const u32 SEED = 0xC0FFEEu;
    Agg got = Runner::descend(DEPTH, SEED);

    // Independent recomputation of the exact recurrence:
    //   down_sum folds plain frame values;
    //   xor_up leaves ONLY depth==1 unmultiplied, every ancestor XORs v*3.
    u32 want_sum = 0;
    for (int d = DEPTH; d >= 1; --d) want_sum += Runner::frame_val(d, SEED);

    u32 want_xor = Runner::frame_val(1, SEED);
    for (int d = 2; d <= DEPTH; ++d)
        want_xor ^= Runner::frame_val(d, SEED) * 3u;

    CHECK_EQ(got.down_sum, want_sum);
    CHECK_EQ(got.xor_up, want_xor);

    // repeat runs must be bit-identical through deep stacks
    Agg again = Runner::descend(DEPTH, SEED);
    CHECK_EQ(again.down_sum, got.down_sum);
    CHECK_EQ(again.xor_up, got.xor_up);
}

struct StateMachine {
    enum State { S_START, S_A, S_B, S_ACCEPTED, S_DEAD };
    typedef State (*handler_t)(State, char);
};

static StateMachine::State st_on_char(StateMachine::State s, char c) {
    switch (s) {
        case StateMachine::S_START: return c == 'a' ? StateMachine::S_A : StateMachine::S_DEAD;
        case StateMachine::S_A:     return c == 'b' ? StateMachine::S_B : (c == 'a' ? StateMachine::S_A : StateMachine::S_DEAD);
        case StateMachine::S_B:     return c == 'a' ? StateMachine::S_A : StateMachine::S_DEAD;
        default:                    return StateMachine::S_DEAD;
    }
}

TEST(flow, state_machine_indirect) {
    // Machine language (derived from the transition table):
    // S_START --a--> S_A;  S_A --a--> S_A, --b--> S_B;  S_B --a--> S_A.
    // => accepted iff len>=2, starts with 'a', ends with 'b', and contains
    //    no "bb" substring. That textual predicate is the INDEPENDENT oracle
    //    the machine must agree with everywhere below.
    auto oracle = [](const char* s) -> bool {
        size_t len = strlen(s);
        if (len < 2 || s[0] != 'a' || s[len - 1] != 'b') return false;
        for (size_t i = 1; i < len; ++i)
            if (s[i] == 'b' && s[i - 1] == 'b') return false;
        return true;
    };
    auto run_machine = [](const char* s) -> bool {
        StateMachine::State st = StateMachine::S_START;
        for (; *s; ++s) st = st_on_char(st, *s);
        return st == StateMachine::S_B;
    };

    const char* inputs[] = {
        "", "a", "ab", "aba", "abab", "aab", "aabba", "bab",
        "ba", "aa", "aabb", "aaabbb", "aaa", "aabbab",
    };
    bool any_true = false;
    for (const char* in : inputs) {
        bool m = run_machine(in);
        bool o = oracle(in);
        CHECK_EQ(m ? 1 : 0, o ? 1 : 0);
        any_true |= m;
    }
    CHECK(any_true);                             // corpus covered both verdicts

    // randomized corpus: exhaustive disagreement hunt over structured strings
    Rng rng(1717u);
    char buf[17];
    int hits = 0;
    for (int t = 0; t < 1500; ++t) {
        unsigned len = (unsigned)(rng.next() % 16u);
        for (unsigned i = 0; i < len; ++i)
            buf[i] = (char)('a' + (rng.next() % 2u));
        buf[len] = 0;
        bool m = run_machine(buf);
        hits += m;
        if (m != oracle(buf)) {
            FAIL_AT(__FILE__, __LINE__, "machine/oracle disagreement");
            break;
        }
    }
    CHECK(hits > 25);                            // generator really explores
}

static s32 fold_with_pointers(const std::vector<s32>& v, binop_t op, s32 init) {
    s32 acc = init;
    for (s32 e : v) acc = op(acc, e);
    return acc;
}

TEST(flow, fnptr_pipeline_and_member_ptrs) {
    Rng rng(909);
    std::vector<s32> v(64);
    for (auto& e : v) e = (s32)(rng.next() % 1000) - 500;

    binop_t ops[3] = { op_add, op_sub, op_xor };
    s32 sum_a = fold_with_pointers(v, ops[0], 0);
    s32 manual_sum = 0;
    for (s32 e : v) manual_sum += e;
    CHECK_EQ(sum_a, manual_sum);

    s32 chained = 0;
    chained = op_add(chained, fold_with_pointers(v, ops[2], 0));       // xor of all
    s32 manual_xor = 0;
    for (s32 e : v) manual_xor ^= e;
    CHECK_EQ(chained, manual_xor);

    // lambdas routed through std::function must behave like direct calls
    std::function<s32(const std::vector<s32>&)> maxof = [](const std::vector<s32>& w) {
        s32 m = w.empty() ? 0 : w[0];
        for (s32 e : w) if (e > m) m = e;
        return m;
    };
    s32 manual_max = v[0];
    for (s32 e : v) if (e > manual_max) manual_max = e;
    CHECK_EQ(maxof(v), manual_max);

    // pointer-to-member dispatch
    struct Widget {
        int bias;
        int add(int x) const { return x + bias; }
        int mul(int x) const { return x * bias; }
    };
    Widget w{ 7 };
    int (Widget::*mf)(int) const = &Widget::add;
    CHECK_EQ((w.*mf)(10), 17);
    mf = &Widget::mul;
    CHECK_EQ((w.*mf)(10), 70);

    void (Widget::*setter_seen)(int) = nullptr;  // non-const overload pattern
    (void)setter_seen;
}
