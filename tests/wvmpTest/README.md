# WVmp 功能测试靶标（wvmpTest）

一个**普通的功能性 Windows 程序**，用于检验加壳/虚拟化保护后的行为正确性。
它不包含任何针对保护器的探测逻辑——所有测试断言的都是纯语言/系统语义的
确定性结果：加壳前后运行结果必须完全一致。

- 每个用例独立自校验，输出 `[PASS]/[FAIL]/[SKIP]` 与 `SUMMARY` 行
- 进程退出码：全部通过 `0`；有失败或被加壳器打死均为非 0（崩溃码即结论）
- 覆盖 12 个模块共 **94 个用例**，x64 与 x86 双架构均已验证

## 构建

**Visual Studio 解决方案**（推荐）：打开 `wvmpTest.sln`，提供
Debug/Release × Win32/x64 四套配置，工具集 v145，产物输出至
`build\vs\<平台>\<配置>\test_target.exe`。命令行等价：

```
msbuild wvmpTest.sln -m -p:Configuration=Release -p:Platform=x64
```

**批处理脚本**：

```bat
build.bat        REM x64 -> build\x64\test_target.exe
build.bat x86    REM x86 -> build\x86\test_target.exe
```

脚本内部调用 VS 的 `vcvars64.bat/vcvars32.bat`（路径按你的 VS 安装位置改一处即可）。
也可用 CMake：

```bat
cmake -S . -B build-cmake && cmake --build build-cmake --config Release
```

MinGW 兼容构建（需 `-D_WIN32_WINNT=0x0601`，链接 advapi32）：
`g++ -std=c++17 -O2 src/*.cpp src/tests/*.cpp -ladvapi32 -o test_target.exe`

## 运行

```
test_target.exe                     全量执行
test_target.exe --list              列出全部 group.name
test_target.exe --filter=SUBSTRING  只跑名字含 SUBSTRING 的用例
test_target.exe --compact           隐藏环境横幅（便于 diff）
test_target.exe --log=FILE          输出同步镜像到文件
test_target.exe --quiet             不打印逐条失败明细
```

 stderr 上恒定输出 `[RUN ] group.name` 流水——**加壳版中途被打死时，
最后一条 `[RUN ]` 就是元凶现场**（stdout 有缓冲看不到，stderr 无缓冲）。

## 加壳验证工作流

1. 未加壳基线：
   `test_target.exe --compact > out\base_unpacked.log` （必须 rc==0）
2. 打标记 → 你的保护流程生成 packed.exe；
3. 对比：
   `test_target.exe --compact --log=out\base_packed.log`，
   `fc out\base_unpacked.log out\base_packed.log`
4. 通过标准：两份日志逐字节一致 且 rc 均为 0。差异行直接指出哪个语义被子系统破坏。

或直接使用现成批处理：`run_compare.cmd unpacked.exe packed.exe`

## 模块 → 保护器风险面映射

| 组 | 内容 | 主要考核点 |
|---|---|---|
| math | 整数回绕/截断除法移位旋转/128 位乘高位/SAT/Q16 定点 | VM 指令语义完整度：进位、有符号比较、模运算 |
| flow | switch 跳转表/Duff 设备/深递归互递归二分/函数指针成员指针/std::function/状态机 | 控制流平坦化与间接跳转还原 |
| string | CRT 字符串/format 往返/sscanf/CRLF Locale 锁 C/#UTF-8 API 往返/CSV KV 词法 Levenshtein | CRT 替换兼容性、缓冲区参数传递 |
| memory | new[]/malloc realloc aligned/析构配平/结构布局填充/memmove 重叠/alloca 栈完整性/placement-new 池 | 堆接管兼容、栈帧布局保持 |
| ds | 单链表反转删除/BST 中序删/OpenAddress+墓碑 HashMap/四排序共识/环形队列/Trie/BFS DFS 一致/区间合并 | 复杂内存行走下的指针算术/访存序 |
| hash | CRC32 Adler32 FNV/MD5 SHA256 表驱动轮函数/HMAC/RC4/XTEA/Base64（摘要常数表由启动期推导锚点自校验） | 高强度位运算、循环展开、字节序重组——VM 最易译错的区域 |
| exc | C++ 多层展开 RAII 配平/bare rethrow/std 异常类型谱/dynamic_cast/bad_cast/SEH AV、除零、try-finally 两路径/VEH 计数/构造半途展开 | **异常表与堆栈展开重建——加壳器头号破坏区** |
| stl | vector/deque/list/map set multiset 语义无实现容量依赖/unordered 指纹/pq/算法契约/智能指针脚本/tuple 引用绑定 | STL/CRT 交互、迭代器代码路径 |
| oop | 虚函数工厂注册表/三层 vtable 覆盖链静态 vs 动态绑定/RTTI 矩阵 type_index/CRTP 生命周期计数器/if constexpr 三实例化/int 复数代数/Wrap64 算子流镜像内建/枚举位标志 | **虚表重定位、类型信息保留** |
| thrd/win | join 求和/atomic fetch_add 精确总量/单调 CAS/CV 生产者消费者 drain/CRITICAL_SECTION 收支/auto-reset Event 握手 transcript/call_once/静态 + 动态 TLS | 线程原语共存、TLS 支持、同步对象兼容 |
| winapi | 文件 RW 追加清理共享模式/stdio-kernel 接力/内存映射文件改动持久化/VirtualAlloc→RO 写入探针(受控 AV)→RW 还原→VirtualQuery 动态解析 CharUpperW 实调/环境变量容量契约/HKCU 注册表三种类型读写清除 | IAT 重建、VirtualProtect 类钩子共存 |
| fp_sse | 截断转换矩阵/isnan isinf 符号位/hypot 整数勾股精确相等/SSE2 epi32 add + mullo_epi16 + 解包通道对拍标量/浮点点积整数域 bitexact/x87 控制字往返(x86) | SIMD 通道翻译精度、浮点环境保存恢复 |

## 设计约束（为什么这样写）

- **零时序断言**：线程测试只做次序不变量（transcript、总量守恒、精确 XOR 折叠），
  VM 串行化拖慢几百倍也不影响判定；不加 sleep，杜绝调度抖动假阴性。
- **确定性输入**：唯一 RNG 为 splitmix64，种子逐用例固定；同一二进制重跑结果必相同，
  使"打壳前后 diff"具备字节级可比性。
- **期望值平台无关**：仅断言语义性质（闭合公式、恒等式、交换律、oracle 双实现对拍、
  RFC/NIST 经典向量），不断言 libstdc++/MSVC STL 的实现细节（如 capacity 数值）。
- **自毁灭受控**：故意触发的空指针解引用/整除零都包在自带过滤器的 `__try` 内；
  若这些探针在加壳后反而坠机，恰恰证明展开元数据被破坏——本身就是有效失败信号。
- **可分解排查**：任何时刻可用 `--filter=` 把疑似子系统单独拎出来复跑。

## 给打标者的提示

### targets 层（推荐的第一落点）

`src/targets/kernels.{h,cpp}` 是专门为"函数收尾加标记"准备的一层：
`extern "C"` + `noinline`、纯计算（无 EH/TLS/alloc/锁）、单一职责，
符号在目标文件里稳定可见。当前包含 15 个内核（13 个打标靶 + `sha256_h0`
向量源）：

| 族 | 符号 |
|---|---|
| 位算术 | `wv_mul64hi` `wv_duff_copy` `wv_bsearch_i32` `wv_insertion_sort` `wv_ackermann` |
| 摘要块级 | `wv_md5_compress` `wv_sha256_compress`（填充留在驱动侧）`wv_sha256_h0` `wv_crc32_update` |
| 流密码 | `wv_rc4_ksa` `wv_rc4_crypt` |
| 分组密码 | `wv_xtea_encipher` `wv_xtea_decipher` |
| 编码 | `wv_b64_encode` `wv_b64_decode` |

对应验证在 `kern.*` 组：每个内核都有独立薄驱动 + 黄金向量。
把某个内核加壳后若其驱动 FAIL 而 `hash.*` 等旧实现组仍 PASS，
即可直接归因到该被保护函数。新增内核时遵循 kernels.h 顶部的入选标准。

### 其余模块

`t_exception.cpp` 的 SEH 探针族、`t_oop.cpp` 的虚表链与工厂、线程/API 组
**不建议**圈进 VM 区域 —— 它们考核的正是展开元数据、IAT 与 TLS 这些
保护器必须保真却不宜虚拟化的基础设施。
