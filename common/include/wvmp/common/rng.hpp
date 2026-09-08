#pragma once
#include "wvmp/common/types.hpp"
#include <random>
#include <algorithm>
namespace wvmp {
class Rng {
public:
    explicit Rng(u64 seed = 0) : engine_(seed) {}
    void reseed(u64 seed) { engine_.seed(seed); }
    u64 next() { return engine_(); }
    u64 uniform(u64 lo, u64 hi) { return std::uniform_int_distribution<u64>(lo, hi)(engine_); }
    template <class It> void shuffle(It b, It e) { std::shuffle(b, e, engine_); }
    // ⚠️ 消费次数与 p 无关（bernoulli_distribution 标准语义 = 先抽
    // canonical 随机数再比阈值，MSVC STL 满足）——"改阈值不改抽取序"
    // 类不变量依赖此点（MIT-489 验收论证），更换 rng 封装实现时需重验。
    bool chance(double p) { return std::bernoulli_distribution(p)(engine_); }
private:
    std::mt19937_64 engine_;
};
}
