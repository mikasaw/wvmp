# WVmp 代码审核记录（2026-09-18）

审核基准：`d382c5463e0eb535286fe5db37adae84a2b8b6be`，开始审核时 Git 工作区无已跟踪文件改动。

本轮记录 **9 项问题：4 项 P1、5 项 P2**。其中 6 项运行了针对性复现，3 项通过源码和接口约定确认。最严重的问题是标志位活跃性优化会改变正常指令序列的计算结果；其次是配置选择器失效或错配，以及 TLS 回调不满足 x64 调用栈约定。

本次仅新增审核文档与复现附件，未修复业务实现。

## 审核范围与验证

- 重点审阅：CLI 配置、流水线、函数档位与加密选择、PE 解析/新增节/写出、TLS 回调、翻译器标志位优化及相关测试。
- 交叉检查：README、`docs/GAPS.md` 与契约说明。已明确记录的指令 gate、blob 首次解密并发限制等不重复计为新问题。
- 使用 `scripts/build.bat` 重新构建成功；重新构建后执行 CTest，**23/23 个测试目标通过，用时 55.58 秒**。这里是 CTest 目标数，不是 GoogleTest 用例总数。
- 首轮使用既有产物、设置 30 秒超时，`regvm_runtime_tests` 超时。重新构建后将超时放宽到 300 秒，该目标用时 55.53 秒通过；不将首轮超时计为代码缺陷。
- 独立 C++ 复现直接调用项目实现；标志位问题进一步执行了项目生成的 x64 VM 运行时机器码。复现程序、脚本及实际输出见 [附件目录](code-review-2026-09-18/)。
- 未逐条验证全部指令语义，未运行完整 native/packed 样本池、32 位运行时全套测试或畸形 PE fuzz。现有测试通过不能覆盖下面的组合与边界情形。

优先级：P1 = 建议下次发布前修复，可导致计算错误、保护配置失效或启动风险；P2 = 特定配置、布局或失败路径下的正确性/可靠性问题。未认定 P0。

## 问题总表

| ID | 优先级 | 问题 | 证据 |
|---|---|---|---|
| CR-01 | P1 | 零次移位前的标志位写入被错误消除 | 翻译器 + 实际 x64 运行时复现 |
| CR-02 | P1 | `name` 选择器的 `level` 静默失效 | 配置解析 + 查询复现 |
| CR-03 | P1 | 加密 `index` 使用过滤后的序号，错配函数 | CryptPass 复现 |
| CR-04 | P1 | x64 TLS 的 GetThreadContext 调用缺少 shadow space | 源码 + Microsoft ABI 文档 |
| CR-05 | P2 | x64 RDTSC 检查在低 32 位回绕时误报 | 发射源码 + 算术反例 |
| CR-06 | P2 | PE32 数据目录读取位置多偏移 4 字节 | 构造 PE32/PE32+ 对照复现 |
| CR-07 | P2 | 异常目录读取忽略目录数量与可选头边界 | `NumberOfRvaAndSizes=0` 复现 |
| CR-08 | P2 | 自动地址与指定地址混用时，新节地址与校验结果不一致 | add_sections 复现 |
| CR-09 | P2 | 输出替换先删除旧文件，失败时无法保留旧产物 | 写出失败路径源码 |

## CR-01：零次移位使标志位优化产生错误结果

**位置**：`vm/regvm/isa/include/wvmp/regvm/isa/encoding.hpp:91-92`、`vm/regvm/translator/src/translator.cpp:4138-4165`。

`Shl/Shr/Sar` 及其 CL 版本被归为无条件覆盖旧 flags 的 `kWrite`。活跃性分析遇到该类指令将 `live_in` 置零，因而可能把它之前的 `cmp/test` 标记为 flags-dead。但有效移位次数为零时，移位保留原 flags，后续条件读取仍依赖前一条指令。

复现对应的原生序列：

```asm
mov eax, 0
mov ecx, 0
cmp eax, 0
shl edx, cl
sete al
```

期望 `eax=1`。项目翻译器无跳过提示（`notes=0`），却将 `cmp` 编成 `cond_or_size=6`（S32=2 加 flags-dead 位=4）；执行生成的 VM 运行时得到 **`eax=0`**。

**影响**：正常受支持指令组合发生静默行为变化。CL 的有效计数为零，包括经位宽掩码归零的计数，均需考虑。已实测的是 x64 S32 的 `ShlCl`；其他同类指令共用的分析问题尚未逐项运行验证。

**建议**：将可能不写 flags 的移位建模为条件定义，保留输入 flags 的活跃性；立即数形式可在计算有效计数后细化。加入经过真实翻译器和运行时的 `cmp → shift(0) → setcc/jcc` 回归，覆盖零、掩码归零及非零计数。

## CR-02：函数名规则无法控制保护档位

**位置**：`framework/include/wvmp/framework/protect_levels.hpp:86-96`；调用方 `passes/virtualize/src/virtualize_pass.cpp:60-61`、`passes/mutate/src/mutate_pass.cpp:242-243`。解析入口为 `cli/src/config.cpp:242-257`。

解析器接受 `name` 选择器和 `level` 字段，但 `level_for(begin_rva, index)` 只检查 index/rva，没有接收或匹配函数名。`crypt_for` 支持 name，不能弥补 level 查询的缺失。

```toml
input = 'input.exe'
output = 'output.exe'
default_level = 'none'
[[functions]]
name = 'target'
level = 'virtualize'
```

**实测**：`parse_ok=1`，对应档位查询预期 `virtualize`、实际 `none`。反向配置（默认 virtualize，按名字排除）同样无法生效。

**影响**：用户指定保护的函数仍保持原生，或明确排除的函数继续进入变异/虚拟化，配置合法且没有针对性的失败提示。

**建议**：统一三个选择器的匹配逻辑，向档位查询传入真实名字，并明确多种选择器同时命中时的优先级。补充按名字开启与关闭保护的集成测试。

## CR-03：加密规则的 index 与区域清单不一致

**位置**：`passes/crypt/src/crypt_pass.cpp:77-85`；原始下标契约为 `framework/include/wvmp/framework/protect_levels.hpp:33-34`。

`index` 定义为 `ctx.functions` 扫描序号。VirtualizePass 会跳过 `level=none`、空基本块或不支持的区域，生成压缩后的 `kVmProgram` 列表。CryptPass 却把该列表下标 `i` 传给 `crypt_for`。

**复现**：原始区域 `[A, B, C]`，A 被跳过，虚拟化列表为 `[B, C]`。配置 `index=1, crypt=false` 应豁免 B、加密 C。实际加密 B、豁免 C，附件输出为 `expected_encrypted=C actual_encrypted=B`。复现手工构造过滤后的列表，运行真实 CryptPass；不执行这些 VM 程序。

**影响**：一个区域的 gate 或保护级别变化会改变其他区域的加密选择，可能把原本要求加密的函数留下明文。

**建议**：保留原始函数索引，或通过稳定标识回查 `ctx.functions`；plan 的 `vfs_index` 仍可保留其现有用途，但不能拿来解释配置中的 index。补充“前置区域被过滤”的选择器回归。

## CR-04：x64 TLS 回调调用 GetThreadContext 时只预留 8 字节

**位置**：`passes/tls_hook/src/tls_hook_pass.cpp:341-365`，DRx 检查分支。

发射序列使用 `sub rsp, 8`、`call qword ptr [rax]`、`add rsp, 8`，只处理了对齐，没有为被调用函数预留 32 字节 shadow space。该检查位于后面的 IAT 回填序列之前，不能使用后者稍后才分配的栈空间。

设回调入口 RSP 为 S：减 8 后再执行 call，被调函数入口 RSP 为 S−16；它合法使用的第二个参数 home slot `[rsp+16]` 就是 S，即 TLS 回调自己的返回地址。被调实现若将 RDX 写回该位置，会破坏回调返回地址。

**影响**：启用 DRx 的 x64 产物存在启动时栈损坏风险，是否实际出现取决于 API 实现是否使用相应 home slot；本轮没有宣称已在当前系统 API 上触发崩溃。调用约定要求由调用方为四个寄存器参数预留空间。[Microsoft x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170)

**建议**：该调用点分配并对称释放 `0x28` 字节（32 字节 shadow space + 8 字节对齐），核对所有分支栈平衡。通过会主动写入 home slots 的模拟被调函数验证，不能只检查生成代码中是否存在 call。

## CR-05：RDTSC 低 32 位回绕导致正常执行被判为超时

**位置**：`passes/tls_hook/src/tls_hook_pass.cpp:199-201`、`:224-228`。

x64 路径第一次 `rdtsc` 后只保存 `rax`，第二次用 `sub rax, r11` 做 64 位差。时间戳高半部 EDX 没有参与计算，低 32 位回绕时，64 位减法会得到极大的无符号数并进入 FailFast。

**反例**：两次完整时间戳为 `0x00000001FFFFFFF0` 和 `0x0000000200000010`，真实差值只有 32。当前代码计算 `0x10 - 0xFFFFFFF0`，64 位结果为 `0xFFFFFFFF00000020`，无符号比较必然大于阈值 500000。

**影响**：开启 rdtsc 后存在依赖启动时机的误终止。这里是对发射指令的确定性算术验证，未依赖等待真实 TSC 回绕来重现。

**建议**：两次采样均正确组合 EDX:EAX 再求差，并以注入时间戳的方式测试高低位进位边界；不要仅通过统计 `rdtsc` 指令出现次数判断正确性。

## CR-06：PE32 异常目录的读取位置偏移错误

**位置**：`passes/pe_loader/src/pe_image.cpp:93-107`。

读完 FileAlignment 后，两种格式的 reader 都位于 OptionalHeader+`0x28`。PE32 分支仍按起点 `0x24` 计算，跳过 `0x3C`，实际落到 `0x64`；正确的 PE32 DataDirectory 起点是 `0x60`，对应跳距为 `0x38`。因此读取 DataDirectory[3] 时把 Size 当成 RVA，并把下一目录的 RVA 当成 Size。

**实测**：同样构造一条 `(begin=0x1100,end=0x1180,unwind=0x1190)` 的异常表，PE32+ 读取 1 条，PE32 读取 0 条并设置 `pdata_empty=true`。

**影响边界**：这是构造输入下确认的解析错误。常规 MSVC x86 文件通常没有 x64 格式的 RUNTIME_FUNCTION 表，因此不能据此声称所有 PE32 文件运行异常；但解析器当前确实无架构过滤地执行此读取，非零目录内容会被错读。

**建议**：按 `opt_start + data_directory_offset` 绝对定位，避免依赖前面读取过程的隐含偏移；同时明确哪些架构允许按 12 字节 RUNTIME_FUNCTION 解释该目录。保留双格式非零目录测试。

## CR-07：不检查目录数量和可选头长度就读取 .pdata

**位置**：`passes/pe_loader/src/pe_image.cpp:59-63`、`:97-107`、`:139-141`。

异常目录读取只检查文件总长度，没有检查 `NumberOfRvaAndSizes > 3`，也没有确认该目录完全位于 `SizeOfOptionalHeader` 声明的区间。文件剩余字节足够不等于目录存在。

**实测**：PE32+ 声明 `NumberOfRvaAndSizes=0`，在未启用的目录槽放入一组可映射值，解析器仍生成 1 条 pdata。预期应视作无异常目录。可选头被缩短时，同一读法还可能跨入节表；该变体本轮仅静态检查，未单独运行。

**影响**：无效或非目录数据可能被作为函数边界，进一步影响 `find_function_end_rva`/ExitNative 的边界判断；此外还会在确认映射有效前根据目录 Size 预分配内存。

**建议**：先校验可选头内目录计数字段、数量与目录区间，再读取；对所引用范围和条目数量完成限制后再分配/解析。补充 0/3/4 个目录、短可选头及目录尺寸异常的用例。

## CR-08：新节混合寻址时校验与落位使用不同起点

**位置**：`passes/pe_writer/src/section_builder.cpp:99-127`、`:130-136`。

校验阶段遇到指定 RVA 请求会推进 `max_va_end`；落位阶段却用这个已包含后续请求的最大值初始化自动请求的 `next_rva`，而不是使用原有镜像末端。这使校验通过的布局在实际写入时发生变化。

**实测**：原节对齐末端 `0x2000`，追加两个大小为 `0x100` 的节：第一个自动分配，第二个指定 `0x3000`。校验预期布局为 `[0x2000,0x3000]`，实际返回并写入 **`[0x4000,0x3000]`**。

**影响**：产生节 RVA 逆序及未预期的虚拟地址空洞，违背本函数对连续落位的校验契约。本轮确认的是字节布局错误，未将该构造镜像作为真实程序加载。当前 stub_link 的固定地址路径不等于所有扩展调用都受影响。

**建议**：先计算最终 placement 列表并校验该列表，再按同一结果写入；或让校验与落位共用独立顺序游标。覆盖 auto→fixed、fixed→auto、多次混排，以及末端连续性。

## CR-09：输出替换不是原子操作，旧文件删除后失败会丢失产物

**位置**：`passes/pe_writer/src/pe_writer_pass.cpp:508-526`。

虽然注释承诺临时文件加 rename 原子替换，实际流程却先 `remove(ctx.output_path)`，再 rename。旧文件删除后若进程中止，或 rename 因竞争/权限变化等失败，旧产物已经丢失；失败分支还删除临时文件，无法保留新产物供恢复。固定的 `.wvmp-tmp` 文件名也会使同目标并发写入共享同一临时文件。

**影响**：覆盖既有输出时破坏失败保留旧版本的保证。该项为失败路径审核，未执行删除用户产物或故障注入实验。

**建议**：使用同目录的唯一临时文件，并通过 Windows 的原子替换机制完成发布；失败时保留旧目标。以专用测试目录验证替换失败、已有目标和同目标并发写入的行为。

## 复跑与后续处理

从项目根目录执行（与项目构建相同，需要 VS 18 Insiders；复现链接默认 Debug 产物）：

```powershell
.\scripts\build.bat
& 'C:\Program Files\Microsoft Visual Studio\18\Insiders\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\ctest.exe' --test-dir build --output-on-failure --timeout 300 -j 2
.\docs\code-review-2026-09-18\reproduce.ps1
```

复现程序仅在 `build/code_review_20260918/` 中生成临时配置和二进制。输出是问题观测值，程序正常退出不代表问题已经修复；应比较 `expected` 与 `actual`。[本次结果](code-review-2026-09-18/results.txt)保留了审核时的实际输出。完整构建与 CTest 日志保留在本机 `build/code_review_20260918/`，未加入版本控制。

建议先修复 CR-01 并跑翻译器到运行时的组合回归，再修复 CR-02/03/04；其余按 PE 输入正确性、输出可靠性和可选检查边界依次处理。修复后应将附件中的最小案例转成正式断言测试，并补充真实 PE native/packed 对照。本报告不把局部审核及 23 个测试目标通过解释为完整发布认证。
