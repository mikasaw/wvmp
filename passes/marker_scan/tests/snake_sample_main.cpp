// wvmp_snake_sample: 端到端真实用例样本——贪吃蛇游戏核心逻辑被 WVMP 保护。
//
// 设计要点 (沿用现有 11 个 sample 的规范, 见 rol_sample / adc_sample):
//   - 区域内 (WVMP_BEGIN/END 包裹) 只允许白名单指令 + call gate 整数 ABI:
//     mov / movabs / add / sub / xor / and / or / cmp / test / shl / sar / push / pop / call / ret
//   - 区域外负责 I/O (printf, Sleep, _kbhit, _getch, std::rand) — 这些是
//     C runtime / Win32 API / 不在白名单, 放区域外避免 C1 gate 兜底, 保留
//     区域"完全可虚拟化"特性 (e2e.bat 期望虚拟化后行为与原生一致, 不期望
//     C1 gate 退出)。
//   - 标志原则: 区域内不调 printf / 不读 _kbhit (这两个都涉及 rip-relative
//     全局数据 + libc 间接 call, 触发 C1 gate); 数据通过全局 volatile 数组
//     (region 内外共享) + 简单值传递。
//   - 区域外 + 区域内 数据传输:
//       * input (键盘方向): 区域外 _kbhit/_getch → volatile int g_key
//       * output (蛇身 / 食物 / 分数): 区域外 printf + 区域内存到 volatile 数组
//     这是 VMPilot snake 那种 "VM logic + native I/O" 思路, 但全程 x86 不用 VM。
//
// 行为 (native vs protected stdout 字节比对):
//   stdout 输出最终蛇身长度 + 分数 + 食物坐标 + 死亡状态, 与原生一致。
//   不实际玩游戏 (不需要交互输入), 用 deterministic seed 跑 100 tick 自动结束
//   (撞墙 or 撞自己), 输出最终状态。
//
// 编译 (与现有 sample 一致):
//   /Od /Ob0 /utf-8  +  /INCREMENTAL:NO  →  marker E8 call 形态稳定

#include "wvmp/sdk/markers.hpp"

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <ctime>

// ─── 游戏常量 ──────────────────────────────────────────────────────────
// GW/GH 取 2 的幂 (32): 食物重生路径 `s & (N - 2)` 替代 `s % (N - 1)`,
// MSVC /Od codegen 产出 `and eax, 0x1E` (白名单内), 避免 div 指令触发
// lifter C1 gate 兜底, snake 真虚拟化闭环 (MIT-318)。
static constexpr int GW = 32;      // 网格宽 (2 的幂)
static constexpr int GH = 32;      // 网格高 (2 的幂)
static constexpr int MAX_LEN = 64; // 蛇最大长度

// 方向: 0=up, 1=right, 2=down, 3=left
static constexpr int DIR_DX[4] = {0, 1, 0, -1};
static constexpr int DIR_DY[4] = {-1, 0, 1, 0};

// ─── 区域外全局 (volatile 防常量折叠, 区域内外共享) ────────────────────
static volatile int g_key;             // 区域外 _kbhit/_getch 写入, 区域内读
static volatile int g_score;           // 区域内更新, 区域外 printf
static volatile int g_alive;           // 区域内更新 (0=dead, 1=alive)
static volatile int g_food_x;
static volatile int g_food_y;
static volatile int g_snake_x[MAX_LEN]; // 蛇身 x 数组 (头在 [0])
static volatile int g_snake_y[MAX_LEN];
static volatile int g_snake_len;       // 当前长度

// volatile seed: 区域外 rand_r 用, 区域内读为 next_food 的 PRNG
static volatile unsigned int g_rng_state;

// ─── 区域外 I/O + 初始化 ────────────────────────────────────────────────
static void io_init() {
    std::srand(0xC0FFEEu);
    g_key = 0;
    g_score = 0;
    g_alive = 1;
    g_rng_state = 0xC0FFEEu;

    // 初始蛇身: 中间 3 节, 朝右
    g_snake_len = 3;
    g_snake_x[0] = GW / 2;      g_snake_y[0] = GH / 2;
    g_snake_x[1] = GW / 2 - 1;  g_snake_y[1] = GH / 2;
    g_snake_x[2] = GW / 2 - 2;  g_snake_y[2] = GH / 2;

    // 初始食物: 远离蛇头
    g_food_x = GW / 4;
    g_food_y = GH / 4;
}

// ─── 区域内函数 (核心逻辑, 包 WVMP_BEGIN/END) ──────────────────────────
//
// tick(): 推进一帧
//   - 读 g_key 改方向
//   - 头按方向移动
//   - 撞墙 → g_alive=0
//   - 撞自己 → g_alive=0
//   - 吃到食物 → 蛇长+1, 分数+1, 重生食物
//   - 否则身体跟随 (从尾向头复制)
//   - 更新 g_rng_state (用于 next_food PRNG, 但这里确定性, 实际不用)
//
// 区域内只用白名单 + call gate (call std::rand 时 callgate 整数 ABI)
//   - 不调 printf (printf 在区域内会触发 C1 gate: lea rcx,[rip+str])
//   - 不读 _kbhit/_getch (conio 不在白名单)
//   - 不调 std::rand (rand 在区域内是 call gate 整数 ABI, 但 std::rand 内部
//     用全局 state, 触发 rip-relative; 这里用本地 LCG 模拟, 不调 std::rand)
//
__declspec(noinline) static void tick(int new_dir) {
    WVMP_BEGIN(tick);

    // 局部 LCG PRNG (避免调 std::rand 触发 rip-relative)
    unsigned int s = g_rng_state;
    s = s * 1103515245u + 12345u;
    g_rng_state = s;

    // 1) 读方向: 只在合法 0..3 范围内接受 new_dir
    int dir = new_dir & 0x3;

    // 2) 计算新蛇头
    int head_x = g_snake_x[0];
    int head_y = g_snake_y[0];
    int nx = head_x + DIR_DX[dir];
    int ny = head_y + DIR_DY[dir];

    // 3) 撞墙检测 (边界外)
    int wall = 0;
    if (nx < 0)  wall = 1;
    if (nx >= GW) wall = 1;
    if (ny < 0)  wall = 1;
    if (ny >= GH) wall = 1;
    if (wall != 0) {
        g_alive = 0;
    }

    // 4) 撞自己检测: 新头位置与任一身体节重合 → 死亡
    int len = g_snake_len;
    int self_hit = 0;
    int i = 0;
    while (i < len) {
        int sx = g_snake_x[i];
        int sy = g_snake_y[i];
        int eq_x = (sx == nx) ? 1 : 0;
        int eq_y = (sy == ny) ? 1 : 0;
        if ((eq_x != 0) && (eq_y != 0)) {
            self_hit = 1;
        }
        i = i + 1;
    }
    if (self_hit != 0) {
        g_alive = 0;
    }

    // 5) 吃食物检测
    int food_x = g_food_x;
    int food_y = g_food_y;
    int ate = 0;
    if ((food_x == nx) && (food_y == ny)) {
        ate = 1;
    }

    // 6) 更新蛇身
    //    ate=1: 头插到 [0], 旧身从 [0] 开始依次后移 (长度+1)
    //    ate=0: 头插到 [0], 旧身从 [0] 开始后移 (尾部丢弃, 长度不变)
    int new_len = len + (ate != 0 ? 1 : 0);

    // 先移动: 从尾到头复制 (j = len-1; j >= 0; --j)  逆向避免覆写
    int j = len - 1;
    while (j >= 0) {
        g_snake_x[j + 1] = g_snake_x[j];
        g_snake_y[j + 1] = g_snake_y[j];
        j = j - 1;
    }
    g_snake_x[0] = nx;
    g_snake_y[0] = ny;
    g_snake_len = new_len;

    // 7) ate 时: 分数+1, 重生食物 (用 LCG 找一个不与蛇身重合的位置)
    if (ate != 0) {
        g_score = g_score + 1;
        // 重生食物: 简化用固定算法 (确定性)
        //   food_x = (s & (GW - 2))   ≡ s % 31  (GW=32 时)
        //   food_y = ((s >> 8) & (GH - 2)) ≡ (s >> 8) % 31  (GH=32 时)
        // 用 & (N-2) 替代 % (N-1): MSVC /Od codegen 出 `and eax, 0x1E`,
        // 在 lifter 白名单内, 避开 div 指令。
        int new_fx = (int)(s & (unsigned int)(GW - 2));
        int new_fy = (int)((s >> 8) & (unsigned int)(GH - 2));
        g_food_x = new_fx;
        g_food_y = new_fy;
    }

    WVMP_END(tick);
}

// ─── 区域外 main: deterministic 100-tick 跑, 输出最终状态 ────────────────
int main() {
    io_init();

    // deterministic 方向序列: 1 (right), 1, 2 (down), 1, 1, 2, 1, 1, ...
    // 简化: 全部朝右 (1), 让蛇撞墙或随机撞自己
    static const int kDirSeq[100] = {
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // 10 右
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // 20 右
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // 30 右
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // 40 右
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // 50 右 (此时已撞墙, g_alive=0)
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2,  // 60 下
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2,  // 70 下
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2,  // 80 下
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3,  // 90 左
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3   // 100 左
    };

    int tick_count = 0;
    while (tick_count < 100) {
        if (g_alive == 0) break;
        int d = kDirSeq[tick_count];
        tick(d);
        tick_count = tick_count + 1;
    }

    // 输出最终状态 (E2E 字节比对用)
    // 格式: alive=N len=N score=N food=x,y head=x,y tail=x,y
    std::printf("alive=%d len=%d score=%d food=%d,%d head=%d,%d tail=%d,%d ticks=%d\n",
                (int)g_alive, (int)g_snake_len, (int)g_score,
                (int)g_food_x, (int)g_food_y,
                (int)g_snake_x[0], (int)g_snake_y[0],
                (int)g_snake_x[(int)g_snake_len - 1], (int)g_snake_y[(int)g_snake_len - 1],
                tick_count);
    return 0;
}
