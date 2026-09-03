// t_stl.cpp - standard containers/algorithms/smart pointers. Only
// semantic properties are asserted - never internal capacity numbers,
// which legitimately differ between MSVC STL and libstdc++.
#include "../testfw.h"
#include "../common.h"

#include <algorithm>
#include <deque>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <numeric>
#include <queue>
#include <set>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace wv;

// ---------------------------------------------------------------------------
TEST(stl, vector_semantics) {
    std::vector<s32> v;
    v.reserve(32);
    CHECK_EQ(v.size(), (size_t)0);
    CHECK(v.empty());
    CHECK(v.capacity() >= (size_t)32);

    long long want_total = 0;
    for (int i = 0; i < 500; ++i) {
        v.push_back(i * 3);
        want_total += (long long)i * 3;
        CHECK_EQ(v.back(), i * 3);
        CHECK_EQ(v.size(), (size_t)(i + 1));
    }
    long long got_total = std::accumulate(v.begin(), v.end(), 0LL);
    CHECK_EQ(got_total, want_total);

    // erase middle third
    size_t before = v.size();
    v.erase(v.begin() + 100, v.begin() + 200);
    CHECK_EQ(v.size(), before - 100);
    CHECK(std::is_sorted(v.begin(), v.end()));

    v.clear();
    CHECK_EQ(v.size(), (size_t)0);
    CHECK(v.begin() == v.end());                 // empty range invariant

    // resize value-initializes the appended region
    std::vector<u8> z;
    z.resize(64);
    for (u8 c : z) CHECK_EQ(c, (u8)0);
    z.resize(100, 0xAB);
    for (size_t i = 64; i < 100; ++i) CHECK_EQ(z[i], 0xAB);
}

TEST(stl, deque_ends_and_indexing) {
    std::deque<s32> d;
    for (int i = 0; i < 200; ++i) {
        if (i % 2 == 0) d.push_back(i);
        else            d.push_front(i);
    }
    // model replay with an ordinary vector kept in matching layout
    std::vector<s32> ref;
    for (int i = 0; i < 200; ++i) {
        if (i % 2 == 0) ref.push_back(i);
        else            ref.insert(ref.begin(), i);
    }
    CHECK_EQ(d.size(), ref.size());
    for (size_t i = 0; i < ref.size(); ++i)
        CHECK_EQ(d[(int)i], ref[i]);
    CHECK_EQ(d.front(), ref.front());
    CHECK_EQ(d.back(), ref.back());

    d.erase(d.begin() + 90);
    ref.erase(ref.begin() + 90);
    CHECK_EQ(d.size(), ref.size());
    for (size_t i = 0; i < ref.size(); ++i)
        CHECK_EQ(d[(int)i], ref[i]);
}

TEST(stl, list_reverse_unique_merge) {
    std::list<int> l;
    std::vector<int> raw{ 5, 3, 8, 3, 1, 9, 5, 5, 2 };
    for (int x : raw) l.push_back(x);

    l.sort();
    std::vector<int> sorted_ref = raw;
    std::sort(sorted_ref.begin(), sorted_ref.end());
    CHECK_EQ(l.size(), sorted_ref.size());
    { size_t i = 0; for (int x : l) CHECK_EQ(x, sorted_ref[i++]); }

    l.unique();
    std::vector<int> uniq_ref;
    std::unique_copy(sorted_ref.begin(), sorted_ref.end(),
                     std::back_inserter(uniq_ref));
    CHECK_EQ(l.size(), uniq_ref.size());
    { size_t i = 0; for (int x : l) CHECK_EQ(x, uniq_ref[i++]); }

    l.reverse();
    CHECK_EQ(l.front(), uniq_ref.back());
    CHECK_EQ(l.back(), uniq_ref.front());

    // splice moves whole chains preserving their order
    std::list<int> other{ 100, 101 };
    auto pos = ++l.begin();
    l.splice(pos, other);
    CHECK(other.empty());
    CHECK_EQ(l.size(), uniq_ref.size() + 2);
}

TEST(stl, assoc_container_ordering) {
    std::map<std::string, int> m{
        { "pear", 3 }, { "apple", 1 }, { "fig", 6 }, { "banana", 2 },
    };
    m["cherry"] = 4;                             // operator[] default-insert then set
    CHECK_EQ(m["avocado"], 0);                   // default inserted too

    std::vector<std::string> keys;
    for (auto& kv : m) keys.push_back(kv.first);
    std::vector<std::string> expect = keys;      // capture then sort to compare
    std::sort(expect.begin(), expect.end());
    CHECK(keys == expect);                       // traversal IS ascending
    CHECK(m.at("fig") == 6);

    std::set<int> s{ 30, 10, 50, 20, 40 };
    s.insert(10);                                // dup ignored
    CHECK_EQ(s.size(), (size_t)5);
    CHECK(*s.begin() == 10 && *s.rbegin() == 50);
    CHECK(s.lower_bound(25) != s.end());
    CHECK_EQ(*s.lower_bound(25), 30);
    CHECK_EQ(*s.upper_bound(35), 40);

    std::multiset<int> ms{ 7, 7, 7, 2, 9 };
    CHECK_EQ(ms.count(7), (size_t)3);
    auto rng = ms.equal_range(7);
    CHECK((size_t)std::distance(rng.first, rng.second) == (size_t)3);
    CHECK(rng.first == ms.lower_bound(7));

    std::multimap<char, int> mm{ {'x',1},{'y',5},{'x',9},{'z',2} };
    auto eqr = mm.equal_range('x');
    int xsum = 0;
    for (auto it = eqr.first; it != eqr.second; ++it) xsum += it->second;
    CHECK_EQ(xsum, 10);
    // all 'x' entries are contiguous in-order
    std::vector<char> order;
    for (auto& kv : mm) order.push_back(kv.first);
    CHECK(order.size() == 4 && order[0] == 'x' && order[1] == 'x');
}

TEST(stl, unordered_map_content_fingerprint) {
    std::unordered_map<int, std::string> um;
    Rng rng(777u);
    std::map<int, std::string> oracle;
    for (int i = 0; i < 400; ++i) {
        int k = rng.irange(0, 300);
        std::string v = "val" + std::to_string(i % 17);
        um[k] = v;
        oracle[k] = v;
    }
    CHECK_EQ(um.size(), oracle.size());

    // contents agree regardless of internal iteration order
    size_t matched = 0;
    u64 key_sum = 0, len_sum = 0;
    for (auto& kv : um) {
        auto it = oracle.find(kv.first);
        if (it != oracle.end() && it->second == kv.second) ++matched;
        key_sum += (u64)kv.first;
        len_sum += kv.second.size();
    }
    CHECK_EQ(matched, oracle.size());

    u64 okey = 0, olen = 0;
    for (auto& kv : oracle) { okey += (u64)kv.first; olen += kv.second.size(); }
    CHECK_EQ(key_sum, okey);
    CHECK_EQ(len_sum, olen);

    um.rehash(1024);                             // buckets grow; content must hold
    for (auto& kv : oracle) {
        auto it = um.find(kv.first);
        CHECK(it != um.end());
        CHECK_EQ(it->second, kv.second);
    }
    um.erase(um.begin(), um.end());
    CHECK(um.empty());
}

TEST(stl, priority_queue_and_heap_ops) {
    std::priority_queue<int> maxq;               // default comparator -> descending
    std::vector<int> feed{ 33, 12, 99, 45, 7, 71, 8, 60 };
    for (int x : feed) maxq.push(x);
    std::vector<int> pops;
    while (!maxq.empty()) { pops.push_back(maxq.top()); maxq.pop(); }
    std::vector<int> want = feed;
    std::sort(want.begin(), want.end(), std::greater<int>());
    CHECK(pops == want);

    std::priority_queue<int, std::vector<int>, std::greater<int>> minq;
    for (int x : feed) minq.push(x);
    std::sort(want.begin(), want.end());
    pops.clear();
    while (!minq.empty()) { pops.push_back(minq.top()); minq.pop(); }
    CHECK(pops == want);
}

TEST(stl, algorithms_contracts) {
    std::vector<int> v(100);
    std::iota(v.begin(), v.end(), 1);
    CHECK_EQ((long long)v.back(), 100LL);

    // rotate left by 37: new[i] == orig[(i + 37) % 100]
    std::rotate(v.begin(), v.begin() + 37, v.end());
    std::vector<int> rot_ref(100);
    for (int i = 0; i < 100; ++i) rot_ref[i] = ((i + 37) % 100) + 1;
    CHECK(v == rot_ref);

    auto is_even = [](int x) { return (x % 2) == 0; };
    // stable_partition: evens keep relative order in front, odds behind
    std::vector<int> probe = v;
    auto split = std::stable_partition(probe.begin(), probe.end(), is_even);
    CHECK(std::all_of(probe.begin(), split, is_even));
    CHECK(std::none_of(split, probe.end(), is_even));
    std::sort(probe.begin(), probe.end());
    std::vector<int> baseline = rot_ref;
    std::sort(baseline.begin(), baseline.end());
    CHECK(probe == baseline);                    // same multiset survived

    auto square = [](long long x) { return x * x; };
    long long sq_sum = std::accumulate(v.begin(), v.end(), 0LL,
                                       [&](long long acc, int x) { return acc + square(x); });
    long long manual_sq = 0;
    for (size_t i = 0; i < baseline.size(); ++i) manual_sq += square(baseline[i]);
    CHECK_EQ(sq_sum, manual_sq);

    std::vector<int> src(50);
    std::generate(src.begin(), src.end(), [n = 0]() mutable { return n += 7; });
    for (int i = 0; i < 50; ++i) CHECK_EQ(src[i], 7 * (i + 1));

    auto sq_sum_probe = std::accumulate(rot_ref.begin(), rot_ref.end(), 0LL,
                                        [&](long long acc, int x) { return acc + square(x); });
    CHECK_EQ(sq_sum, sq_sum_probe);              // either input view must agree

    auto it = std::find_if(rot_ref.begin(), rot_ref.end(),
                           [](int x) { return x > 41 && x % 3 == 0; });
    CHECK(it != rot_ref.end());
    CHECK_EQ(*it, 42);                           // first qualifying rotation slot
}

TEST(stl, smart_pointer_ownership_script) {
    std::vector<const char*> events;

    auto sp1 = std::make_shared<int>(123);
    std::weak_ptr<int> wp = sp1;
    CHECK(sp1.use_count() == 1);
    {
        auto sp2 = sp1;
        CHECK(sp2.use_count() == 2);
        auto locked = wp.lock();
        CHECK(locked.get() == sp1.get());
        CHECK_EQ(*locked, 123);
    }
    CHECK(sp1.use_count() == 1);
    sp1.reset();
    CHECK(wp.expired());                         // object died with last owner
    CHECK_MSG(wp.lock().get() == NULL, "expired weak locks nothing");

    auto up1 = std::make_unique<int>(42);
    int* raw_addr = up1.get();
    auto up2 = std::move(up1);
    CHECK(up1.get() == NULL);                    // moved-from empties out
    CHECK(up2.get() == raw_addr);                // same allocation traveled
    CHECK_EQ(*up2, 42);

    // shared_ptr custom deleter fires exactly once
    static int deletes;
    deletes = 0;
    {
        auto sp3 = std::shared_ptr<int>(new int(7), [](int* p) { delete p; ++deletes; });
        auto sp4 = sp3;
        CHECK(sp4.use_count() == 2);
    }
    CHECK_EQ(deletes, 1);
    (void)events;
}

TEST(stl, tuple_pair_reference_binding) {
    int a = 5, b = 9;
    auto tp = std::tie(a, b);
    std::get<0>(tp) = 55;
    std::get<1>(tp) = 99;
    CHECK_EQ(a, 55);
    CHECK_EQ(b, 99);                             // references hit originals

    std::pair<std::string, int> p1{ "one", 1 }, p2{ "two", 2 };
    auto by_first = p1 < p2;
    CHECK(by_first);
    p2.first = "aaa";
    CHECK(p2 < p1);                              // lexicographic flipped
    CHECK_EQ(std::get<1>(p2), 2);

    auto tup = std::make_tuple(3, 1.5f, std::string("s"));
    CHECK_EQ(std::get<0>(tup), 3);
    CHECK_NEAR(std::get<1>(tup), 1.5, 1e-6);
    CHECK(std::get<2>(tup) == "s");

    std::swap(p1, p2);
    CHECK(p1.first == "aaa");
    CHECK(p2.second == 1);
}
