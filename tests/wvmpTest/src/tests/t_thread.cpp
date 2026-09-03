// t_thread.cpp - threads, atomics, condition variables, critical sections,
// events, call_once, TLS (static + dynamic). Every check is ordering- or
// invariant-based - never wall-clock based, so a heavily-slowed VM build
// still passes on correctness.
#include "../testfw.h"
#include "../common.h"

#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
#include <vector>

using namespace wv;

// ---------------------------------------------------------------------------
TEST(thrd, join_and_per_thread_results) {
    const int N = 8;
    const int LO = 2000;
    std::vector<long long> partial((size_t)N, 0);

    std::vector<std::thread> ts;
    for (int t = 0; t < N; ++t)
        ts.emplace_back([t, &partial, LO]() {
            long long acc = 0;
            for (int i = 1; i <= LO; ++i) acc += (long long)i * i;
            partial[(size_t)t] = acc;
        });
    for (auto& th : ts) th.join();

    long long want_each = (long long)LO * (LO + 1) * (2 * LO + 1) / 6;
    long long total = 0;
    for (int t = 0; t < N; ++t) {
        CHECK_EQ(partial[(size_t)t], want_each);
        total += partial[(size_t)t];
    }
    CHECK_EQ(total, want_each * N);
}

TEST(thrd, atomic_fetch_add_exact_total) {
    const int N = 8, M = 5000;
    std::atomic<int> counter{ 0 };
    std::atomic<int> max_seen{ 0 };

    std::vector<std::thread> ts;
    for (int t = 0; t < N; ++t)
        ts.emplace_back([&]() {
            for (int i = 0; i < M; ++i) {
                // fetch_add yields the pre-increment value; track running max
                int prev = counter.fetch_add(1, std::memory_order_relaxed);
                int cur_max = max_seen.load(std::memory_order_relaxed);
                while (prev > cur_max &&
                       !max_seen.compare_exchange_weak(cur_max, prev,
                                                       std::memory_order_relaxed)) {}
            }
        });
    for (auto& th : ts) th.join();

    CHECK_EQ(counter.load(), N * M);             // exact under any interleaving
    CHECK(max_seen.load() >= counter.load() - 1);
    CHECK(max_seen.load() <= N * M - 1);
}

TEST(thrd, atomic_cas_monotonic_max_single_writer) {
    std::atomic<int> slot{ -1000000 };
    Rng rng(424242u);
    int expect_max = -1000000;

    for (int step = 0; step < 600; ++step) {
        int candidate = rng.irange(-50, 50);
        if (candidate > expect_max) expect_max = candidate;

        // lock-free monotonic max: CAS only when it would raise the value;
        // on failure compare_exchange_strong refreshes `cur`, so a stored
        // larger value terminates the loop instead of spinning forever.
        int cur = slot.load();
        while (candidate > cur &&
               !slot.compare_exchange_strong(cur, candidate)) {}
    }
    CHECK_EQ(slot.load(), expect_max);
}

TEST(thrd, producer_consumer_cv_drain) {
    const int P = 4, PER_PRODUCER = 2500;

    struct BQ {
        std::mutex mx;
        std::condition_variable cv_space, cv_items;
        std::deque<int> q;
        size_t cap;
        bool closed = false;
        explicit BQ(size_t c) : cap(c) {}
        void push(int v) {
            std::unique_lock<std::mutex> lk(mx);
            cv_space.wait(lk, [&] { return q.size() < cap; });
            q.push_back(v);
            lk.unlock();
            cv_items.notify_one();
        }
        bool pop(int* out) {
            std::unique_lock<std::mutex> lk(mx);
            cv_items.wait(lk, [&] { return !q.empty() || closed; });
            if (q.empty()) return false;         // closed & drained
            *out = q.front();
            q.pop_front();
            lk.unlock();
            cv_space.notify_one();
            return true;
        }
        void close() {
            std::unique_lock<std::mutex> lk(mx);
            closed = true;
            lk.unlock();
            cv_items.notify_all();
        }
    } bq(16);

    std::mutex stat_mx;
    std::vector<int> per_producer((size_t)P, 0);
    u64 xor_consumed = 0;

    auto producer_fn = [&](int id) {
        for (int i = 0; i < PER_PRODUCER; ++i)
            bq.push(id * 10000000 + i);
    };
    auto consumer_fn = [&]() {
        int v;
        while (bq.pop(&v)) {
            std::lock_guard<std::mutex> g(stat_mx);
            ++per_producer[(size_t)(v / 10000000)];
            xor_consumed ^= (u64)v;
        }
    };

    u64 expect_xor = 0;
    for (int id = 0; id < P; ++id)
        for (int i = 0; i < PER_PRODUCER; ++i)
            expect_xor ^= (u64)(id * 10000000 + i);   // order-free fold

    std::vector<std::thread> pts;
    for (int id = 0; id < P; ++id)
        pts.emplace_back(producer_fn, id);
    std::vector<std::thread> cts;
    for (int k = 0; k < 2; ++k) cts.emplace_back(consumer_fn);
    for (auto& th : pts) th.join();
    bq.close();                                  // consumers drain then exit
    for (auto& th : cts) th.join();

    int total_consumed = 0;
    for (int id = 0; id < P; ++id) {
        CHECK_EQ(per_producer[(size_t)id], PER_PRODUCER);
        total_consumed += per_producer[(size_t)id];
    }
    CHECK_EQ(total_consumed, P * PER_PRODUCER);
    CHECK(xor_consumed == expect_xor);
}

// ---------------------------------------------------------------------------
static CRITICAL_SECTION g_cs;
static volatile long g_cs_locked = 0, g_cs_unlocked = 0;
struct CsGuard {
    CsGuard()  { EnterCriticalSection(&g_cs); InterlockedIncrement(&g_cs_locked); }
    ~CsGuard() { LeaveCriticalSection(&g_cs); InterlockedIncrement(&g_cs_unlocked); }
};
static long g_cs_counter = 0;

TEST(win, critical_section_balance) {
    InitializeCriticalSection(&g_cs);
    g_cs_locked = g_cs_unlocked = 0;
    g_cs_counter = 0;

    const int T = 6, INC = 4000;
    std::vector<std::thread> ts;
    for (int t = 0; t < T; ++t)
        ts.emplace_back([INC]() {
            for (int i = 0; i < INC; ++i) {
                CsGuard g;
                ++g_cs_counter;
            }
        });
    for (auto& th : ts) th.join();

    CHECK_EQ(g_cs_counter, T * INC);
    CHECK_EQ(g_cs_locked, (long)(T * INC));
    CHECK_EQ(g_cs_unlocked, g_cs_locked);
    DeleteCriticalSection(&g_cs);
}

static HANDLE g_ping = NULL, g_pong = NULL;
static std::string g_transcript;
static std::mutex g_tx_mx;

static void transcript_side(char ch, int turns) {
    HANDLE mine = (ch == 'A') ? g_ping : g_pong;
    HANDLE other = (ch == 'A') ? g_pong : g_ping;
    for (int i = 0; i < turns; ++i) {
        WaitForSingleObject(mine, INFINITE);
        { std::lock_guard<std::mutex> g(g_tx_mx); g_transcript += ch; }
        SetEvent(other);
    }
}

TEST(win, event_handshake_transcript) {
    // auto-reset ping-pong forces a scheduler-independent exact interleaving
    g_ping = CreateEvent(NULL, FALSE, TRUE, NULL);   // 'A' starts ready
    g_pong = CreateEvent(NULL, FALSE, FALSE, NULL);
    CHECK(g_ping != NULL && g_pong != NULL);
    g_transcript.clear();

    const int TURNS = 120;
    std::thread ta(transcript_side, 'A', TURNS / 2);
    std::thread tb(transcript_side, 'B', TURNS / 2);
    ta.join();
    tb.join();

    CloseHandle(g_ping);
    CloseHandle(g_pong);
    CHECK((int)g_transcript.size() == TURNS);
    for (int i = 0; i < TURNS; ++i) {
        char want = (i % 2 == 0) ? 'A' : 'B';
        if (g_transcript[(size_t)i] != want) {
            FAIL_AT(__FILE__, __LINE__, "interleave deviated");
            break;
        }
    }
}

namespace once_target {
static std::once_flag flag;
static std::atomic<int> calls{ 0 };
static void touch() { calls.fetch_add(1); }
} // namespace once_target

TEST(thrd, call_once_exactly_once) {
    once_target::calls.store(0);
    std::vector<std::thread> ts;
    for (int t = 0; t < 5; ++t)
        ts.emplace_back([]() {
            std::call_once(once_target::flag, []() { once_target::touch(); });
        });
    for (auto& th : ts) th.join();
    CHECK_EQ(once_target::calls.load(), 1);
}

// ---------------------------------------------------------------------------
static __declspec(thread) int tls_static_slot = 0;
static DWORD tls_indexes[4];

TEST(thrd, tls_isolation_and_dynamic_tls) {
    const int N = 4;
    std::vector<int> collected((size_t)N, -1);

    bool all_ok = true;
    for (int k = 0; k < N; ++k) {
        tls_indexes[k] = TlsAlloc();
        all_ok &= (tls_indexes[k] != TLS_OUT_OF_INDEXES);
    }
    if (!all_ok) {
        for (int k = 0; k < N; ++k)
            if (tls_indexes[k] != TLS_OUT_OF_INDEXES) TlsFree(tls_indexes[k]);
        fw::mark_skipped();
        return;
    }

    tls_static_slot = 7777;                      // main-thread private value

    std::vector<std::thread> ts;
    for (int t = 0; t < N; ++t)
        ts.emplace_back([t, &collected]() {
            // static TLS starts at zero here - main thread's 7777 invisible
            CHECK_EQ(tls_static_slot, 0);
            tls_static_slot = (t + 1) * 3;
            collected[(size_t)t] = tls_static_slot;

            LPVOID pv = TlsGetValue(tls_indexes[t]);
            CHECK(pv == NULL);                   // fresh slot reads empty
            TlsSetValue(tls_indexes[t], (LPVOID)(uintptr_t)(t * 13 + 5));
            pv = TlsGetValue(tls_indexes[t]);
            CHECK_EQ((int)(uintptr_t)pv, t * 13 + 5);
        });
    for (auto& th : ts) th.join();

    for (int t = 0; t < N; ++t)
        CHECK_EQ(collected[(size_t)t], (t + 1) * 3);
    CHECK_EQ(tls_static_slot, 7777);             // untouched by workers

    BOOL freed_all = TRUE;
    for (int k = 0; k < N; ++k)
        freed_all &= TlsFree(tls_indexes[k]);
    CHECK(freed_all);
}
