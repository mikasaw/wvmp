// t_oop.cpp - virtual dispatch, vtable layering, RTTI, CRTP/templates,
// operator overloading, enums. Integer-only numerics keep every assertion
// exact and compiler-independent.
#include "../testfw.h"
#include "../common.h"

#include <map>
#include <memory>
#include <string>
#include <typeindex>
#include <typeinfo>
#include <vector>

using namespace wv;

// ---------------------------------------------------------------------------
namespace shapes {
struct Shape {
    virtual ~Shape() {}
    virtual long long area_mm2() const = 0;
    virtual const char* name() const = 0;
};
struct Square : Shape {
    int a;
    explicit Square(int side) : a(side) {}
    long long area_mm2() const override { return (long long)a * a; }
    const char* name() const override { return "Square"; }
};
struct Rect : Shape {
    int w, h;
    Rect(int w_, int h_) : w(w_), h(h_) {}
    long long area_mm2() const override { return (long long)w * h; }
    const char* name() const override { return "Rect"; }
};
struct RightTri : Shape {
    int leg_a, leg_b;
    RightTri(int a_, int b_) : leg_a(a_), leg_b(b_) {}
    long long area_mm2() const override { return (long long)leg_a * leg_b / 2; }
    const char* name() const override { return "RightTri"; }
};
struct Circle : Shape {                        // pi approximated as 31/10
    int r;
    explicit Circle(int radius) : r(radius) {}
    long long area_mm2() const override { return ((long long)31 * r * r + 5) / 10; }
    const char* name() const override { return "Circle"; }
};
typedef std::unique_ptr<Shape> (*factory_t)(int);
static factory_t pick(const std::string& kind) {
    if (kind == "square")   return [](int v) -> std::unique_ptr<Shape> { return std::unique_ptr<Shape>(new Square(v)); };
    if (kind == "rect")     return [](int v) -> std::unique_ptr<Shape> { return std::unique_ptr<Shape>(new Rect(v, v * 2)); };
    if (kind == "triangle") return [](int v) -> std::unique_ptr<Shape> { return std::unique_ptr<Shape>(new RightTri(v, v + 2)); };
    return [](int v) -> std::unique_ptr<Shape> { return std::unique_ptr<Shape>(new Circle(v)); };
}
} // namespace shapes

TEST(oop, shape_factory_virtual_total) {
    const char* script[] = { "square", "rect", "triangle", "circle" };
    long long total = 0;
    std::vector<const char*> names;
    for (const char* kind : script)
        for (int param : { 2 }) {
            auto sh = shapes::pick(kind)(param);
            total += sh->area_mm2();             // pure virtual through base*
            names.push_back(sh->name());
        }
    // with param v=2 the factories yield, respectively:
    //   Square(2)=4, Rect(2,4)=8, RightTri legs(2,4)/2=4,
    //   Circle(r=v=2): ((31*4)+5)/10 = 12   -> script total 28
    long long want = 4LL                                       // square v*v
                   + 2LL * (long long)(2 * 2)                  // rect v x 2v
                   + ((2LL * 4) / 2)                           // tri legs v,v+2
                   + (((31LL * 2 * 2) + 5) / 10);              // circle r=v
    CHECK_EQ(total, want);
    CHECK_EQ(total, 28LL);
    CHECK(names.size() == 4);
    CHECK(names[0] && !names[0][6]);              // "Square" has 6 chars
}

TEST(oop, shape_registry_dynamic_config) {
    std::map<std::string, shapes::factory_t> reg{
        { "sq", shapes::pick("square") },
        { "rc", shapes::pick("rect") },
    };
    auto sq = reg["sq"](5);
    auto rc = reg["rc"](3);
    CHECK_EQ(sq->area_mm2(), 25LL);              // 5 x 5
    CHECK_EQ(rc->area_mm2(), 18LL);              // rect w=3,h=6
    CHECK(std::string(rc->name()) == "Rect");
}

// ---------------------------------------------------------------------------
namespace layers {
struct Root {
    virtual ~Root() {}
    virtual std::string tag() const { return "R"; }
};
struct Mid : Root {
    std::string tag() const override { return Root::tag() + "M"; }
};
struct Leaf : Mid {
    std::string tag() const override { return Mid::tag() + "L"; }
};
} // namespace layers

namespace layers_fix {
struct Root {
    virtual ~Root() {}
    virtual std::string tag() const { return "R"; }
    std::string tag_direct() const { return tag(); }
};
struct Mid : Root {
    std::string tag() const override { return Root::tag() + "+M"; }
};
struct Leaf : Mid {
    std::string tag() const override { return Mid::tag() + "+L"; }
};
inline std::pair<std::string, std::string> probe(Root& r) {
    return { r.tag(), r.tag_direct() };          // same route either way
}
} // namespace layers_fix

TEST(oop, vtable_static_vs_dynamic_binding) {
    layers_fix::Leaf leaf_obj;

    // through most-derived handle
    auto p_leaf = layers_fix::probe(leaf_obj);
    CHECK(p_leaf.first == "R+M+L");
    CHECK(p_leaf.second == "R+M+L");

    // through middle-typed reference of the same object
    layers_fix::Mid& mid_view = leaf_obj;
    auto p_mid = layers_fix::probe(mid_view);
    CHECK(p_mid.first == "R+M+L");
    CHECK(p_mid.second == "R+M+L");

    // through root-typed pointer
    layers_fix::Root* root_view = &leaf_obj;
    CHECK(root_view->tag() == "R+M+L");

    // unrelated sibling behaves differently - dispatch genuinely virtualized
    layers_fix::Mid plain_mid;
    CHECK(plain_mid.tag() == "R+M");
    layers_fix::Root plain_root;
    CHECK(plain_root.tag() == "R");
}

// ---------------------------------------------------------------------------
TEST(oop, rtti_matrix_and_type_identity) {
    struct PolyBase { virtual ~PolyBase() {} };
    struct D1 : PolyBase { int marker = 11; };
    struct D2 : PolyBase { int other = 22; };
    struct Unrelated {};
    struct NonPoly {};

    D1 d1a, d1b;
    D2 d2;
    PolyBase& pb_d1 = d1a;
    PolyBase& pb_d2 = d2;

    // downcasts succeed and recover the original address exactly
    D1* back = dynamic_cast<D1*>(&pb_d1);
    CHECK(back == &d1a);
    CHECK(back->marker == 11);

    // wrong-side downcast yields null
    CHECK(dynamic_cast<D1*>(&pb_d2) == NULL);
    CHECK(dynamic_cast<D2*>(&pb_d1) == NULL);

    // typeid identity: distinct instances of the SAME type compare equal,
    // different dynamic types through base refs compare unequal
    CHECK(typeid(pb_d1) == typeid(d1b));
    CHECK(typeid(pb_d1) != typeid(pb_d2));

    // typeid on expressions respects STATIC type for non-polymorphic types
    NonPoly np; NonPoly& npr = np;
    CHECK(typeid(np) == typeid(npr));
    CHECK(typeid(np) == typeid(NonPoly));

    // type_index usable as an associative key
    std::map<std::type_index, const char*> names;
    names[std::type_index(typeid(D1))] = "D1";
    names[std::type_index(typeid(D2))] = "D2";
    names[std::type_index(typeid(Unrelated))] = "U";
    CHECK_EQ(names.size(), (size_t)3);
    CHECK(strcmp(names[std::type_index(typeid(D1))], "D1") == 0);
    CHECK(strcmp(names[std::type_index(typeid(pb_d1))], "D1") == 0);
}

// ---------------------------------------------------------------------------
template <class T>
struct Counted {
    static int live;
    static int max_live;
    Counted() { ++live; if (live > max_live) max_live = live; }
    Counted(const Counted&) { ++live; if (live > max_live) max_live = live; }
    Counted& operator=(const Counted&) { return *this; }   // no lifetime change
    ~Counted() { --live; }
};
template <class T> int Counted<T>::live = 0;
template <class T> int Counted<T>::max_live = 0;

struct CtrA : Counted<CtrA> {};                 // CRTP separates counters per type
struct CtrB : Counted<CtrB> {};

TEST(oop, crtp_lifetime_counters) {
    CHECK_EQ(CtrA::live, 0);
    CHECK_EQ(CtrB::live, 0);
    {
        CtrA a1, a2;
        CtrB b1;
        CHECK_EQ(CtrA::live, 2);
        CHECK_EQ(CtrB::live, 1);
        {
            std::vector<CtrA> more(3);
            CHECK_EQ(CtrA::live, 5);
            CtrA copy_of_a1 = a1;
            CHECK_EQ(CtrA::live, 6);
            CHECK(copy_of_a1.live >= 0);         // member mirrors static state
        }
        CHECK_EQ(CtrA::live, 2);
        CHECK_EQ(CtrB::live, 1);
    }
    CHECK_EQ(CtrA::live, 0);
    CHECK_EQ(CtrB::live, 0);
    // high-water marks record the true simultaneity peaks
    CHECK_EQ(CtrA::max_live, 6);
    CHECK_EQ(CtrB::max_live, 1);
}

namespace scaling {
// runtime-polymorphic-like templated functors; avoids FP comparison fuzz by
// restricting doubles to integer-valued magnitudes
struct TagSeq { std::vector<const char*> order; };

TagSeq g_tags;

template <class T>
T scale(const T& v, int k) {
    if constexpr (std::is_same<T, std::string>::value) {
        std::string out;
        out.reserve(v.size() * (size_t)k);
        for (int i = 0; i < k; ++i) out += v;
        return out;
    } else if constexpr (std::is_floating_point<T>::value) {
        double acc = 0;
        for (int i = 0; i < k; ++i) acc += (double)v;
        return (T)acc;
    } else {
        T acc{};
        for (int i = 0; i < k; ++i) acc += v;    // multiplication via additions
        return acc;
    }
}
void note_tag(const char* t) { g_tags.order.push_back(t); }
} // namespace scaling

TEST(oop, template_scale_three_instantiations) {
    using scaling::scale;
    using scaling::note_tag;
    scaling::g_tags.order.clear();

    u32 vi = scale((u32)0x12345678u, 3);
    CHECK_EQ(vi, (u32)0x369D0368u);              // x+x+x == x*3 in the ring

    std::string vs = scale<std::string>("ab", 3);
    CHECK(vs.size() == (size_t)6);
    CHECK(vs[0] == 'a' && vs[1] == 'b' && vs[5] == 'b');
    std::string manual;
    for (int i = 0; i < 3; ++i) manual += "ab";
    CHECK(vs == manual);

    double vd = scale<double>(2.0, 10);
    CHECK_NEAR(vd, 20.0, 1e-9);

    note_tag("int"); note_tag("str"); note_tag("double");
    scaling::g_tags.order.push_back(NULL);
    CHECK(scaling::g_tags.order.size() == 4);
    CHECK(scaling::g_tags.order[0] &&
          strcmp(scaling::g_tags.order[0], "int") == 0);
    CHECK(scaling::g_tags.order[1] &&
          strcmp(scaling::g_tags.order[1], "str") == 0);
}

// ---------------------------------------------------------------------------
struct ComplexInt {
    long re, im;
};
static ComplexInt c_add(ComplexInt a, ComplexInt b) { return { a.re + b.re, a.im + b.im }; }
static ComplexInt c_mul(ComplexInt a, ComplexInt b) {
    return { a.re * b.re - a.im * b.im, a.re * b.im + a.im * b.re };
}
static ComplexInt c_conj(ComplexInt a) { return { a.re, -a.im }; }

TEST(oop, complex_integer_algebra) {
    ComplexInt z{ 1, 2 }, w{ 3, 4 };
    ComplexInt zw = c_mul(z, w);
    CHECK(zw.re == -5 && zw.im == 10);           // classic expansion

    // z * conj(z) == |z|^2 real-only
    ComplexInt zc = c_mul(z, c_conj(z));
    CHECK(zc.im == 0);
    CHECK(zc.re == z.re * z.re + z.im * z.im);

    Rng rng(20262u);
    for (int t = 0; t < 200; ++t) {              // distributivity property
        ComplexInt a{ (long)rng.irange(-9, 9), (long)rng.irange(-9, 9) };
        ComplexInt b{ (long)rng.irange(-9, 9), (long)rng.irange(-9, 9) };
        ComplexInt c{ (long)rng.irange(-9, 9), (long)rng.irange(-9, 9) };

        ComplexInt left  = c_mul(a, c_add(b, c));
        ComplexInt right = c_add(c_mul(a, b), c_mul(a, c));
        CHECK(left.re == right.re && left.im == right.im);
    }
}

struct Wrap64 {
    u64 x;
    Wrap64(u64 v = 0) : x(v) {}
    Wrap64 operator+(Wrap64 o) const { return Wrap64(x + o.x); }
    Wrap64 operator-(Wrap64 o) const { return Wrap64(x - o.x); }
    Wrap64 operator*(Wrap64 o) const { return Wrap64(x * o.x); }
    Wrap64 operator^(Wrap64 o) const { return Wrap64(x ^ o.x); }
};

TEST(oop, operator_stream_mirrors_builtin_u64) {
    Rng rng(555777u);
    u64 builtin = rng.next();
    Wrap64 wrapped(builtin);
    std::vector<u64> snaps_wrapped, snaps_builtin;

    for (int step = 0; step < 400; ++step) {
        u64 opnd = rng.next();
        switch (step % 4) {
            case 0: builtin += opnd;  wrapped = wrapped + Wrap64(opnd); break;
            case 1: builtin ^= opnd;  wrapped = wrapped ^ Wrap64(opnd); break;
            case 2: builtin *= opnd;  wrapped = wrapped * Wrap64(opnd); break;
            default: builtin -= opnd; wrapped = wrapped - Wrap64(opnd); break;
        }
        if (step % 37 == 0) {
            snaps_wrapped.push_back(wrapped.x);
            snaps_builtin.push_back(builtin);
        }
    }
    CHECK(snaps_builtin.size() >= (size_t)10);
    for (size_t i = 0; i < snaps_builtin.size(); ++i)
        CHECK_EQ(snaps_wrapped[i], snaps_builtin[i]);
    CHECK_EQ(wrapped.x, builtin);
}

// ---------------------------------------------------------------------------
enum class Color : u8 { Red = 1, Green = 4, Blue = 9, MaxSentinel = 255 };
enum Bits : u32 { F_A = 1u << 0, F_B = 1u << 2, F_C = 1u << 5 };

TEST(oop, enums_underlying_and_bitflags) {
    CHECK_EQ(sizeof(Color), (size_t)1);
    CHECK_EQ((int)Color::Green, 4);

    // round trips hold for the whole declared palette
    for (Color c : { Color::Red, Color::Green, Color::Blue })
        CHECK(static_cast<Color>(static_cast<u8>(c)) == c);
    CHECK_EQ((u8)Color::MaxSentinel, (u8)255);

    // scripted flag algebra: ((A|B) & ~B) | C ^ A == C | A
    u32 f = (Bits::F_A | Bits::F_B);
    CHECK_EQ(f, 0x5u);                           // bits 0 and 2
    f &= ~(u32)Bits::F_B;
    CHECK_EQ(f, 0x1u);
    f |= (u32)Bits::F_C;
    CHECK_EQ(f, 0x21u);
    f ^= (u32)Bits::F_A;
    CHECK_EQ(f, 0x20u);
    CHECK(!(f & (u32)Bits::F_A));
    CHECK((f & (u32)Bits::F_C));
    CHECK_EQ(f, (u32)Bits::F_C);
}

// helpers referenced above ---------------------------------------------------
namespace unused_trailing {}                     // intentionally empty
