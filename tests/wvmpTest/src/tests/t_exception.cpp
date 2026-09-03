// t_exception.cpp - C++ EH unwinding, Win32 SEH probes, ctor unwinding.
// NOTE: functions that contain __try must be free of C++ objects with
// destructors (MSVC C2712) - results are marshaled through POD globals.
#include "../testfw.h"
#include "../common.h"

#include <new>
#include <stdexcept>
#include <string>
#include <typeinfo>
#include <vector>

using namespace wv;

namespace {

struct ExcBase : std::exception {
    int code;
    explicit ExcBase(int c) : code(c), msg_("base") {}
    const char* what() const noexcept override { return msg_; }
protected:
    const char* msg_;
};
struct ExcMid : ExcBase {
    explicit ExcMid(int c) : ExcBase(c) { msg_ = "mid"; }
};
struct ExcLeaf : ExcMid {
    explicit ExcLeaf(int c) : ExcMid(c) { msg_ = "leaf"; }
};

struct UnwindMark {
    static std::vector<const char*>* sink;
    const char* tag;
    explicit UnwindMark(const char* t) : tag(t) { if (sink) sink->push_back(tag); }
    ~UnwindMark() { if (sink) sink->push_back(tag); }
};
std::vector<const char*>* UnwindMark::sink = NULL;

void deep_throw(int depth, int code) {
    UnwindMark m("frame");
    if (depth == 0) throw ExcLeaf(code);
    deep_throw(depth - 1, code);
}

} // namespace

// ---------------------------------------------------------------------------
TEST(exc, cpp_unwind_marks_and_catch_ref) {
    std::vector<const char*> marks;
    UnwindMark::sink = &marks;
    try {
        UnwindMark outer("outer");
        deep_throw(5, 777);
        FAIL_AT(__FILE__, __LINE__, "unreachable after throw");
    } catch (const ExcMid& e) {                   // leaf IS-A mid
        CHECK(dynamic_cast<const ExcLeaf*>(&e) != NULL);
        CHECK_EQ(e.code, 777);
        CHECK(strcmp(e.what(), "leaf") == 0);
    } catch (...) {
        FAIL_AT(__FILE__, __LINE__, "wrong handler ran");
    }
    UnwindMark::sink = NULL;

    // six deep_throw frames + the outer guard; each appears TWICE (ctor+dtor)
    CHECK_EQ(marks.size(), (size_t)(2 * 6 + 2));
    for (size_t i = 0; i < marks.size() / 2; ++i)
        CHECK(marks[i] == marks[marks.size() - 1 - i]);   // LIFO symmetric
}

struct Guard {                                    // nontrivial member tracking
    static int live;
    int v;
    explicit Guard(int x) : v(x) { ++live; }
    Guard(const Guard& o) : v(o.v) { ++live; }
    ~Guard() { --live; }
};
int Guard::live = 0;

TEST(exc, guard_balance_across_rethrows) {
    int before = Guard::live;
    int observed = 0;
    try {
        Guard a(1);
        try {
            Guard b(2);
            throw ExcBase(9);
        } catch (ExcBase&) {
            Guard c(3);
            observed += c.v;                      // 3 while inner still active
            throw;                                // bare rethrow keeps object
        }
    } catch (const ExcBase& e) {
        observed += e.code * 10;                  // 90 at outermost station
    }
    CHECK_EQ(observed, 93);
    CHECK_EQ(Guard::live, before);
}

TEST(exc, std_exceptions_types_and_payloads) {
    auto expect_type = [&](auto&& thunk, const std::type_info& ti,
                           const char* label) {
        try {
            thunk();
            FAIL_AT(__FILE__, __LINE__, (std::string("no throw: ") + label).c_str());
        } catch (const std::exception& e) {
            CHECK_MSG(typeid(e) == ti, label);    // exact type, slicing-proofed
            (void)e;
        }
    };
    expect_type([] { throw std::bad_alloc(); },        typeid(std::bad_alloc),        "bad_alloc");
    expect_type([] { throw std::bad_cast(); },         typeid(std::bad_cast),         "bad_cast");
    expect_type([] { throw std::invalid_argument("x"); }, typeid(std::invalid_argument), "invalid_argument");
    expect_type([] { throw std::out_of_range("y"); },  typeid(std::out_of_range),     "out_of_range");
    expect_type([] { throw std::runtime_error("z"); }, typeid(std::runtime_error),    "runtime_error");

    try {
        long v = std::stol("-1234567");
        CHECK_EQ((int)v, -1234567);
        int iv = std::stoi("  42 tail ignored");
        CHECK_EQ(iv, 42);
        std::stoi("99999999999");                 // overflows int -> out_of_range
        FAIL_AT(__FILE__, __LINE__, "stoi overflow unnoticed");
    } catch (const std::out_of_range&) {
        CHECK(true);
    } catch (...) {
        FAIL_AT(__FILE__, __LINE__, "wrong overflow flavor");
    }

    struct Aa { virtual ~Aa() {} };
    struct Bb : Aa {};
    struct Cc {};
    Bb bobj;
    Aa& ar = bobj;
    CHECK(&dynamic_cast<Bb&>(ar) == &bobj);       // legal downcast
    bool caught_bad_cast = false;
    try { (void)dynamic_cast<Cc&>(ar); }          // unrelated -> bad_cast
    catch (const std::bad_cast&) { caught_bad_cast = true; }
    CHECK(caught_bad_cast);
    CHECK(dynamic_cast<Cc*>(&ar) == NULL);        // pointer form stays null
}

// ===========================================================================
// SEH zone - only trivially destructible locals in these scopes
// ===========================================================================
static volatile long g_seh_code   = -1;
static volatile long g_seh_ran    = 0;
static volatile int  g_dummy_div  = 0;
static volatile int  g_finally_t1 = 0;
static volatile int  g_finally_t2 = 0;
static volatile long g_veh_hits   = 0;
static void*   g_veh_handle       = NULL;

static LONG CALLBACK veh_counter(PEXCEPTION_POINTERS ep) {
    if (ep && ep->ExceptionRecord &&
        ep->ExceptionRecord->ExceptionCode ==
            (DWORD)EXCEPTION_INT_DIVIDE_BY_ZERO)
        InterlockedIncrement((volatile long*)&g_veh_hits);
    return EXCEPTION_CONTINUE_SEARCH;
}

static void seh_probe_av(void) {
    __try {
        *(volatile int*)(0) = 42;                 // deliberate AV
        g_seh_ran = 0;                            // never reached
    } __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION
                    ? EXCEPTION_EXECUTE_HANDLER
                    : EXCEPTION_CONTINUE_SEARCH) {
        g_seh_code = (long)GetExceptionCode();
        g_seh_ran = 1;
    }
}

static void seh_probe_divzero(void) {
    volatile int zero = 0;
    __try {
        g_dummy_div = 7 / zero;                   // INT_DIVIDE_BY_ZERO
    } __except (GetExceptionCode() == EXCEPTION_INT_DIVIDE_BY_ZERO
                    ? EXCEPTION_EXECUTE_HANDLER
                    : EXCEPTION_CONTINUE_SEARCH) {
        g_seh_code = (long)GetExceptionCode();
        g_seh_ran = 2;
    }
}

static void seh_probe_finally_normal(void) {
    __try {
        g_finally_t1 = 1;
    } __finally {
        g_finally_t2 = 10;
    }
}

static int seh_probe_finally_leave_path(void) {
    __try {
        g_finally_t1 = 2;
        return 43110;                             // finally still intercepts
    } __finally {
        g_finally_t2 = 20;
    }
}

TEST(exc, seh_access_violation_caught) {
    g_seh_ran = 0;
    g_seh_code = -1;
    seh_probe_av();
    CHECK_EQ(g_seh_ran, 1);
    CHECK_EQ(g_seh_code, (long)EXCEPTION_ACCESS_VIOLATION);
}

TEST(exc, seh_integer_divide_by_zero_caught) {
    g_seh_ran = 0;
    g_seh_code = -1;
    seh_probe_divzero();
    CHECK_EQ(g_seh_ran, 2);
    CHECK_EQ(g_seh_code, (long)EXCEPTION_INT_DIVIDE_BY_ZERO);
}

TEST(exc, seh_try_finally_paths) {
    // normal completion path
    g_finally_t1 = 0;
    g_finally_t2 = 0;
    seh_probe_finally_normal();
    CHECK_EQ(g_finally_t1, 1);
    CHECK_EQ(g_finally_t2, 10);

    // early-return path still executes __finally then restores the return value
    g_finally_t1 = 0;
    g_finally_t2 = 0;
    int rv = seh_probe_finally_leave_path();
    CHECK_EQ(rv, 43110);
    CHECK_EQ(g_finally_t1, 2);
    CHECK_EQ(g_finally_t2, 20);
}

TEST(exc, vectored_handler_invocation_count) {
    PVOID h = AddVectoredExceptionHandler(1 /*first*/, &veh_counter);
    if (!h) {
        fw::mark_skipped();
        return;
    }
    g_veh_hits = 0;
    seh_probe_divzero();                          // raises INT_DIVIDE_BY_ZERO
    RemoveVectoredExceptionHandler(h);
    CHECK_EQ(g_veh_hits, 1);
    // after removal, new exceptions must not tick the counter anymore
    long before = g_veh_hits;
    seh_probe_divzero();
    CHECK_EQ(g_veh_hits, before);
}

TEST(exc, constructor_unwinding_partial_build) {
    class ThrowingA {
    public:
        ThrowingA(std::vector<int>& trace) : trace_(trace) { trace.push_back(1); }
        ~ThrowingA() { trace_.push_back(-1); }
    private:
        std::vector<int>& trace_;
    };
    class ThrowingB {
    public:
        ThrowingB(std::vector<int>& trace, int& boom) : trace_(trace) {
            trace.push_back(2);
            if (boom) throw std::runtime_error("mid-ctor");
            boom_used_ = boom;
        }
        ~ThrowingB() { trace_.push_back(-2); }
    private:
        std::vector<int>& trace_;
        int boom_used_ = 0;
    };
    struct Whole {
        ThrowingA a;
        ThrowingB b;
        Whole(std::vector<int>& tr, int& boom)
            try : a(tr), b(tr, boom) {}           // function-try-block on ctors
        catch (...) {
            tr.push_back(99);                     // saw the escaped exception
        }
    };

    std::vector<int> tr;
    int boom = 1;
    try {
        Whole w(tr, boom);
        FAIL_AT(__FILE__, __LINE__, "must not construct");
    } catch (const std::runtime_error&) {
        CHECK(true);
    }
    // fully built 'a' was destroyed during b's failed construction
    CHECK(tr.size() >= 4);
    bool saw_a_destroyed = false, saw_marker = false;
    for (int x : tr) {
        if (x == -1) saw_a_destroyed = true;
        if (x == 99) saw_marker = true;
    }
    CHECK(saw_a_destroyed);
    CHECK(saw_marker);

    // successful path has perfect balance
    tr.clear();
    boom = 0;
    { Whole w2(tr, boom); (void)w2; }
    int ones = 0, minus_ones = 0, twos = 0, minus_twos = 0;
    for (int x : tr) {
        ones += x == 1; minus_ones += x == -1;
        twos  += x == 2; minus_twos += x == -2;
    }
    CHECK(ones == 1 && minus_ones == 1 && twos == 1 && minus_twos == 1);
}
