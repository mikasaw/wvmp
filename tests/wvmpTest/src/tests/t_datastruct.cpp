// t_datastruct.cpp - linked lists, BST, open-addressing hashmap, sorting,
// ring buffer, trie, graph traversal, interval merging.
#include "../testfw.h"
#include "../common.h"

#include <algorithm>
#include <numeric>
#include <vector>

using namespace wv;

// ---------------------------------------------------------------------------
struct NodeU { int v; NodeU* next; };

TEST(ds, singly_linked_list_ops) {
    const int N = 512;
    NodeU* head = NULL;
    NodeU** tail_ptr = &head;
    for (int i = 0; i < N; ++i) {
        NodeU* n = new NodeU{ i, NULL };
        *tail_ptr = n;
        tail_ptr = &n->next;
    }
    size_t cnt = 0;
    long long total = 0;
    for (NodeU* p = head; p; p = p->next) { total += p->v; ++cnt; }
    CHECK_EQ(cnt, (size_t)N);
    CHECK_EQ(total, (long long)N * (N - 1) / 2);

    // reverse in place - three-pointer shuffle
    NodeU* prev = NULL;
    NodeU* cur = head;
    while (cur) {
        NodeU* nx = cur->next;
        cur->next = prev;
        prev = cur;
        cur = nx;
    }
    head = prev;
    int i = N - 1;
    for (NodeU* p = head; p; p = p->next, --i)
        if (p->v != i) { FAIL_AT(__FILE__, __LINE__, "reverse mismatch"); break; }

    // remove even-valued nodes preserving odd order
    NodeU dummy{ -1, head };
    NodeU* it = &dummy;
    size_t removed = 0;
    while (it->next) {
        if ((it->next->v & 1) == 0) {
            NodeU* dead = it->next;
            it->next = dead->next;
            delete dead;
            ++removed;
        } else {
            it = it->next;
        }
    }
    CHECK_EQ(removed, (size_t)(N / 2));
    size_t kept = 0;
    long long odd_sum = 0;
    for (NodeU* p = dummy.next; p; p = p->next) { ++kept; odd_sum += p->v; }
    CHECK_EQ(kept, (size_t)(N / 2));
    CHECK_EQ(odd_sum, (long long)256 * 256);     // 1+3+...+511 = 256^2

    NodeU* q = dummy.next;
    while (q) { NodeU* d = q; q = q->next; delete d; }
}

// ---------------------------------------------------------------------------
struct BSTN { int key; BSTN* l; BSTN* r; };
static BSTN* bst_insert(BSTN* root, int k) {
    if (!root) return new BSTN{ k, NULL, NULL };
    if (k < root->key) root->l = bst_insert(root->l, k);
    else if (k > root->key) root->r = bst_insert(root->r, k);
    return root;
}
static bool bst_find(BSTN* root, int k) {
    while (root) {
        if (root->key == k) return true;
        root = k < root->key ? root->l : root->r;
    }
    return false;
}
static void bst_inorder(BSTN* root, std::vector<int>& out) {
    if (!root) return;
    bst_inorder(root->l, out);
    out.push_back(root->key);
    bst_inorder(root->r, out);
}
static void bst_free(BSTN* root) {
    if (!root) return;
    bst_free(root->l); bst_free(root->r); delete root;
}
static BSTN* bst_erase(BSTN* root, int k, bool* removed) {
    if (!root) return NULL;
    if (k < root->key) { root->l = bst_erase(root->l, k, removed); return root; }
    if (k > root->key) { root->r = bst_erase(root->r, k, removed); return root; }
    *removed = true;
    if (!root->l) { BSTN* r = root->r; delete root; return r; }
    if (!root->r) { BSTN* l = root->l; delete root; return l; }
    BSTN* succ = root->r;
    while (succ->l) succ = succ->l;
    root->key = succ->key;
    bool once = false;
    root->r = bst_erase(root->r, succ->key, &once);
    return root;
}

TEST(ds, binary_search_tree) {
    const int N = 1024;
    Rng rng(70707u);
    std::vector<int> vals(N);
    std::iota(vals.begin(), vals.end(), 100000);
    // manual Fisher-Yates (our Rng is not a std URBG)
    for (size_t i = vals.size(); i > 1; --i)
        std::swap(vals[i - 1], vals[(size_t)rng.irange(0, (int)i - 1)]);

    BSTN* root = NULL;
    for (int v : vals) root = bst_insert(root, v);

    std::vector<int> seq;
    seq.reserve(N);
    bst_inorder(root, seq);
    std::vector<int> sorted = vals;
    std::sort(sorted.begin(), sorted.end());
    CHECK(seq.size() == sorted.size());
    for (size_t i = 0; i < sorted.size() && i < seq.size(); ++i)
        CHECK_EQ(seq[i], sorted[i]);

    static bool has[2048];
    memset(has, 0, sizeof(has));
    for (int v : vals) has[v - 100000] = true;
    Rng probe_rng(88u);
    for (int i = 0; i < 1500; ++i) {
        int off = (int)(probe_rng.next() % 2048u);
        bool want = has[off];
        CHECK_EQ(bst_find(root, 100000 + off), want);
    }

    for (int i = 0; i < 300; ++i) {
        bool gone = false;
        root = bst_erase(root, vals[i], &gone);
        CHECK_MSG(gone, "present key must be removable");
    }
    std::vector<int> after;
    bst_inorder(root, after);
    CHECK(std::is_sorted(after.begin(), after.end()));
    CHECK(after.size() == N - 300);
    for (size_t i = 1; i < after.size(); ++i)
        CHECK(after[i] != after[i - 1]);

    bst_free(root);
}

// open addressing: linear probing, tombstone deletes --------------------------
struct HashMapOA {
    enum : u32 { CAP = 1024 };                   // power of two
    enum SlotState : u8 { EMPTY, USED, DEAD };
    std::vector<u32> keys, vals;
    std::vector<u8> state;

    HashMapOA() : keys(CAP, 0), vals(CAP, 0), state(CAP, EMPTY) {}
    static size_t slot_of(u32 k) { return (size_t)((k * 2654435769u) & (CAP - 1)); }

    void put(u32 k, u32 v) {
        // Full chain scan BEFORE placing: an existing entry for k must be
        // found even when tombstones/empties opened earlier in its probe
        // path - otherwise duplicates ("ghosts") sneak in.
        size_t first_dead = SIZE_MAX, first_empty = SIZE_MAX;
        for (size_t tries = 0; tries < CAP; ++tries) {
            size_t s = (slot_of(k) + tries) & (CAP - 1);
            u8 st = state[s];
            if (st == USED) {
                if (keys[s] == k) { vals[s] = v; return; }   // true update
                continue;
            }
            if (st == DEAD) {
                if (first_dead == SIZE_MAX) first_dead = s;
            } else {
                first_empty = s;                 // EMPTY ends the chain
                break;
            }
        }
        size_t tgt = (first_dead != SIZE_MAX) ? first_dead : first_empty;
        if (tgt != SIZE_MAX) {
            state[tgt] = USED; keys[tgt] = k; vals[tgt] = v;
            return;
        }
        FAIL_AT(__FILE__, __LINE__, "hashmap unexpectedly full");
    }
    long find(u32 k) const {                     // -1 absent, else value
        for (size_t tries = 0; tries < CAP; ++tries) {
            size_t s = (slot_of(k) + tries) & (CAP - 1);
            u8 st = state[s];
            if (st == EMPTY) break;              // hole terminates the chain
            if (st == USED && keys[s] == k) return (long)vals[s];
        }
        return -1;
    }
    void erase(u32 k) {
        for (size_t tries = 0; tries < CAP; ++tries) {
            size_t s = (slot_of(k) + tries) & (CAP - 1);
            if (state[s] == EMPTY) return;
            if (state[s] == USED && keys[s] == k) { state[s] = DEAD; return; }
        }
    }
    size_t live_count() const {
        size_t n = 0;
        for (u8 st : state) n += (st == USED);
        return n;
    }
};

TEST(ds, hashmap_open_addressing) {
    Rng rng(20260827u);
    std::vector<std::pair<u32, u32>> truth;      // parallel ground-truth list
    auto truth_get = [&](u32 k) -> long {
        for (const auto& e : truth) if (e.first == k) return (long)e.second;
        return -1;
    };
    auto truth_set = [&](u32 k, u32 v) {
        for (auto& e : truth) if (e.first == k) { e.second = v; return; }
        truth.push_back({ k, v });
    };
    auto truth_del = [&](u32 k) -> bool {
        for (size_t i = 0; i < truth.size(); ++i)
            if (truth[i].first == k) { truth.erase(truth.begin() + i); return true; }
        return false;
    };

    const u32 KEYSPACE = 1200;
    HashMapOA m;
    for (int step = 0; step < 3000; ++step) {
        int roll = (int)(rng.next() % 100u);
        u32 k = (u32)(rng.next() % KEYSPACE);
        if (roll < 60) {
            u32 v = (u32)(step * 31 + 7);
            m.put(k, v);
            truth_set(k, v);
        } else if (roll < 80) {
            m.erase(k);
            truth_del(k);
        } else {
            long a = m.find(k);
            long b = truth_get(k);
            CHECK_EQ(a, b);                      // map agrees with mirror
        }
    }
    CHECK_EQ(m.live_count(), truth.size());

    // exhaustive agreement over the whole keyspace after the storm
    for (u32 k = 0; k < KEYSPACE; ++k) {
        long a = m.find(k);
        long b = truth_get(k);
        CHECK_EQ(a, b);
    }

    // wipe every key below CAP; survivors live at >=CAP by construction
    for (u32 k = 0; k < HashMapOA::CAP; ++k) {
        m.erase(k);                              // tolerates misses
        truth_del(k);
    }
    size_t residue = 0;
    for (const auto& e : truth)
        if (e.first >= HashMapOA::CAP) ++residue;
    CHECK_EQ(m.live_count(), residue);

    // tombstone reuse: refill half capacity over spread homes
    for (u32 k = 0; k < HashMapOA::CAP / 2; ++k) {
        m.put(k * 4u + 1u, k * 9u);
        truth_set(k * 4u + 1u, k * 9u);
    }
    CHECK_EQ(m.live_count(), truth.size());

    // final authority: exhaustive map-vs-truth agreement over the keyspace
    for (u32 k = 0; k < KEYSPACE; ++k)
        CHECK_EQ(m.find(k), truth_get(k));
}

// ---------------------------------------------------------------------------
TEST(ds, sort_algorithms_consensus) {
    const int N = 4000;
    Rng rng(31337u);
    std::vector<s32> base(N);
    for (auto& e : base) e = (s32)(rng.next() % 97u);    // duplicate-heavy
    std::vector<s32> ref = base;
    std::sort(ref.begin(), ref.end());

    auto eq_ref = [&](const std::vector<s32>& v, const char* who) {
        if (v.size() != ref.size()) { FAIL_AT(__FILE__, __LINE__, who); return; }
        for (size_t i = 0; i < v.size(); ++i)
            if (v[i] != ref[i]) { FAIL_AT(__FILE__, __LINE__, who); return; }
    };

    {   // insertion sort
        std::vector<s32> a = base;
        for (size_t i = 1; i < a.size(); ++i) {
            s32 key = a[i];
            long long j = (long long)i - 1;
            while (j >= 0 && a[(size_t)j] > key) { a[(size_t)j + 1] = a[(size_t)j]; --j; }
            a[(size_t)j + 1] = key;
        }
        eq_ref(a, "insertion");
    }
    {   // merge sort
        std::vector<s32> a = base, tmp(a.size());
        struct MS {
            static void go(s32* v, s32* t, size_t lo, size_t hi) {
                if (hi - lo < 2) return;
                size_t mid = lo + (hi - lo) / 2;
                go(v, t, lo, mid); go(v, t, mid, hi);
                size_t i = lo, j = mid, k = lo;
                while (i < mid && j < hi) t[k++] = (v[i] <= v[j]) ? v[i++] : v[j++];
                while (i < mid) t[k++] = v[i++];
                while (j < hi)  t[k++] = v[j++];
                for (k = lo; k < hi; ++k) v[k] = t[k];
            }
        };
        MS::go(a.data(), tmp.data(), 0, a.size());
        eq_ref(a, "merge");
    }
    {   // heap sort via std heap primitives
        std::vector<s32> a = base;
        std::make_heap(a.begin(), a.end());
        for (size_t n = a.size(); n > 1; --n)
            std::pop_heap(a.begin(), a.begin() + n);
        eq_ref(a, "heap");
    }
    {   // quicksort, middle pivot with Hoare-ish partition
        struct QS {
            static long long part(s32* v, long long lo, long long hi) {
                s32 piv = v[(size_t)((lo + hi) / 2)];
                while (lo <= hi) {
                    while (v[(size_t)lo] < piv) ++lo;
                    while (v[(size_t)hi] > piv) --hi;
                    if (lo <= hi) { std::swap(v[(size_t)lo], v[(size_t)hi]); ++lo; --hi; }
                }
                return lo;
            }
            static void go(s32* v, long long lo, long long hi) {
                if (lo >= hi) return;
                long long p = part(v, lo, hi);
                go(v, lo, p - 1);
                go(v, p, hi);
            }
        };
        std::vector<s32> a = base;
        QS::go(a.data(), 0, (long long)a.size() - 1);
        eq_ref(a, "quick");
    }
    {   // tiny bubble sanity on the first 200 items
        std::vector<s32> a(base.begin(), base.begin() + 200);
        for (size_t pass = 0; pass + 1 < a.size(); ++pass)
            for (size_t i = 0; i + 1 + pass < a.size(); ++i)
                if (a[i] > a[i + 1]) std::swap(a[i], a[i + 1]);
        CHECK(std::is_sorted(a.begin(), a.end()));
    }

    // stable_sort keeps original relative order among equal keys
    struct Tagged { s32 key; int orig; };
    std::vector<Tagged> tg(N);
    for (int i = 0; i < N; ++i) tg[i] = Tagged{ (s32)(rng.next() % 23u), i };
    std::stable_sort(tg.begin(), tg.end(),
                     [](const Tagged& x, const Tagged& y) { return x.key < y.key; });
    for (size_t i = 1; i < tg.size(); ++i) {
        CHECK(tg[i - 1].key <= tg[i].key);
        if (tg[i - 1].key == tg[i].key)
            CHECK_MSG(tg[i - 1].orig < tg[i].orig, "stability preserved");
    }
}

// ---------------------------------------------------------------------------
TEST(ds, ring_buffer_scripted) {
    const int CAP = 8;
    int buf[CAP];
    int head = 0, count = 0;
    std::vector<int> log;

    int next_val = 100;
    auto push = [&]() -> bool {
        if (count == CAP) return false;
        buf[(head + count) % CAP] = next_val++;
        ++count;
        return true;
    };
    auto pop = [&]() -> bool {
        if (count == 0) return false;
        int v = buf[head];
        head = (head + 1) % CAP;
        --count;
        log.push_back(v);
        return true;
    };

    // fill -> drain cycles must yield one globally increasing stream
    for (int lap = 0; lap < 25; ++lap) {
        for (int i = 0; i < CAP; ++i) CHECK(push());
        CHECK_MSG(!push(), "full ring refuses writes");
        CHECK_EQ(count, CAP);
        for (int i = 0; i < CAP; ++i) CHECK(pop());
        CHECK_MSG(!pop(), "empty ring refuses reads");
    }
    CHECK_EQ(log.size(), (size_t)(25 * CAP));
    for (size_t i = 0; i < log.size(); ++i)
        CHECK_EQ(log[i], 100 + (int)i);

    // sliding steady-state: fill to capacity, then pop+push keeps a full
    // window flowing; the drained stream stays globally ordered
    log.clear();
    next_val = 500;
    for (int i = 0; i < CAP; ++i) CHECK(push());          // exactly full
    CHECK_EQ(count, CAP);
    for (int step = 0; step < 200; ++step) {
        int drained_before = (int)log.size();
        CHECK(pop());
        (void)drained_before;
        CHECK(push());
        CHECK_EQ(count, CAP);                    // window never shrinks twice
    }
    while (pop()) {}                             // final drain
    CHECK_EQ(log.size(), (size_t)(CAP + 200));
    for (size_t i = 0; i < log.size(); ++i)
        CHECK_EQ(log[i], 500 + (int)i);
}

// ---------------------------------------------------------------------------
struct TrieNode { TrieNode* ch[26]; bool word_end; };
static TrieNode* trie_new() { return new TrieNode{}; }
static void trie_ins(TrieNode* t, const char* w) {
    TrieNode* p = t;
    for (; *w; ++w) {
        int c = *w - 'a';
        if (!p->ch[c]) p->ch[c] = trie_new();
        p = p->ch[c];
    }
    p->word_end = true;
}
static bool trie_has(TrieNode* t, const char* w) {
    TrieNode* p = t;
    for (; *w; ++w) {
        int c = *w - 'a';
        if (c < 0 || c >= 26) return false;
        p = p->ch[c];
        if (!p) return false;
    }
    return p->word_end;
}
static void trie_collect(TrieNode* t, std::string& cur, std::vector<std::string>& out) {
    if (t->word_end) out.push_back(cur);
    for (int c = 0; c < 26; ++c)
        if (t->ch[c]) {
            cur.push_back((char)('a' + c));
            trie_collect(t->ch[c], cur, out);
            cur.pop_back();
        }
}

TEST(ds, trie_dictionary) {
    TrieNode* root = trie_new();
    const char* dict[] = { "cat", "car", "cart", "do", "dog", "done", "a" };
    for (const char* w : dict) trie_ins(root, w);

    CHECK(trie_has(root, "cat"));
    CHECK(trie_has(root, "car"));
    CHECK(trie_has(root, "cart"));
    CHECK(trie_has(root, "do"));
    CHECK(trie_has(root, "dog"));
    CHECK(trie_has(root, "done"));
    CHECK(trie_has(root, "a"));
    CHECK_MSG(!trie_has(root, "ca"), "prefix alone is not a word");
    CHECK_MSG(!trie_has(root, "don"), "strict prefix missing end mark");
    CHECK_MSG(!trie_has(root, "cats"), "absent extension");

    // prefix walk then subtree dump must reproduce descendants
    auto words_under = [&](const char* pre) {
        std::string cur = pre;
        TrieNode* p = root;
        for (; *pre; ++pre) { p = p->ch[*pre - 'a']; if (!p) break; }
        std::vector<std::string> out;
        if (p) trie_collect(p, cur, out);
        std::sort(out.begin(), out.end());
        return out;
    };
    auto under_ca = words_under("ca");
    CHECK(under_ca.size() == 3 &&
          under_ca[0] == "car" && under_ca[1] == "cart" && under_ca[2] == "cat");
    auto under_do = words_under("do");
    CHECK(under_do.size() == 3 &&
          under_do[0] == "do" && under_do[1] == "dog" && under_do[2] == "done");

    struct Free { static void go(TrieNode* t) {
        for (auto& c : t->ch) if (c) { go(c); delete c; }
    } };
    Free::go(root);
    delete root;
}

// ---------------------------------------------------------------------------
TEST(ds, graph_bfs_dfs_agreement) {
    enum { V = 12 };
    // fixed undirected edges forming one connected component with cycles
    static const int edges[][2] = {
        {0,1},{0,2},{1,3},{2,3},{2,4},{3,5},{4,5},{4,6},
        {5,7},{6,7},{6,8},{7,9},{8,9},{8,10},{9,11},{10,11},{1,11},
    };
    static bool adj[V][V];
    memset(adj, 0, sizeof(adj));
    for (auto& e : edges) { adj[e[0]][e[1]] = adj[e[1]][e[0]] = true; }

    // BFS layers
    int dist[V];
    bool seen[V];
    for (int i = 0; i < V; ++i) { dist[i] = -1; seen[i] = false; }
    dist[0] = 0; seen[0] = true;
    std::vector<int> bfs_order; bfs_order.push_back(0);
    for (size_t qi = 0; qi < bfs_order.size(); ++qi) {
        int u = bfs_order[qi];
        for (int w = 0; w < V; ++w)
            if (adj[u][w] && !seen[w]) { seen[w] = true; dist[w] = dist[u] + 1; bfs_order.push_back(w); }
    }
    for (int i = 0; i < V; ++i)
        CHECK_MSG(seen[i], "graph designed fully connected");

    // symmetry: BFS distance is symmetric (recompute per source)
    for (int src = 0; src < V; ++src) {
        int d2[V]; bool s2[V];
        for (int i = 0; i < V; ++i) { d2[i] = -1; s2[i] = false; }
        d2[src] = 0; s2[src] = true;
        std::vector<int> q; q.push_back(src);
        for (size_t qi = 0; qi < q.size(); ++qi) {
            int u = q[qi];
            for (int w = 0; w < V; ++w)
                if (adj[u][w] && !s2[w]) { s2[w] = true; d2[w] = d2[u] + 1; q.push_back(w); }
        }
        for (int i = 0; i < V; ++i)
            if (src == 0) CHECK_EQ(d2[i], dist[i]);
        CHECK_EQ(d2[0], dist[src]);              // cross-consistency with node 0 run
    }

    // DFS preorder: recursive vs explicit stack must visit identically
    std::vector<int> rec_pre;
    bool vis[V]; memset(vis, 0, sizeof(vis));
    struct DFR { static void go(int u, bool (&a)[V][V], bool (&v)[V], std::vector<int>& out) {
        v[u] = true; out.push_back(u);
        for (int w = 0; w < V; ++w) if (a[u][w] && !v[w]) go(w, a, v, out);
    }};
    DFR::go(0, adj, vis, rec_pre);
    CHECK_EQ(rec_pre.size(), (size_t)V);

    std::vector<int> iter_pre;
    memset(vis, 0, sizeof(vis));
    {
        std::vector<int> st; st.push_back(0);
        while (!st.empty()) {
            int u = st.back(); st.pop_back();
            if (vis[u]) continue;
            vis[u] = true;
            iter_pre.push_back(u);
            for (int w = V - 1; w >= 0; --w)     // reverse to match recursion order
                if (adj[u][w] && !vis[w]) st.push_back(w);
        }
    }
    CHECK_EQ(iter_pre.size(), rec_pre.size());
    for (size_t i = 0; i < rec_pre.size(); ++i)
        CHECK_EQ(iter_pre[i], rec_pre[i]);
}

// ---------------------------------------------------------------------------
TEST(ds, interval_merge_canonical) {
    struct Iv { int a, b; };
    std::vector<Iv> in = {
        { 20, 25 }, { 1, 3 }, { 8, 10 }, { 22, 26 },
        { 9, 12 }, { 2, 5 }, { 15, 15 },
    };
    std::sort(in.begin(), in.end(),
              [](const Iv& x, const Iv& y) { return x.a != y.a ? x.a < y.a : x.b < y.b; });

    std::vector<Iv> merged;
    for (const Iv& iv : in) {
        if (!merged.empty() && iv.a <= merged.back().b)
            merged.back().b = std::max(merged.back().b, iv.b);
        else
            merged.push_back(iv);
    }

    CHECK_EQ(merged.size(), (size_t)4);
    if (merged.size() == 4) {
        CHECK(merged[0].a == 1 &&  merged[0].b == 5);
        CHECK(merged[1].a == 8 &&  merged[1].b == 12);
        CHECK(merged[2].a == 15 && merged[2].b == 15);
        CHECK(merged[3].a == 20 && merged[3].b == 26);
    }

    // disjoint output invariant
    for (size_t i = 1; i < merged.size(); ++i)
        CHECK_MSG(merged[i].a > merged[i - 1].b, "no overlap after merge");
}
