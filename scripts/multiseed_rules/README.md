# multiseed 规则挂点（MIT-522 B0-3）

`scripts/multiseed_e2e.sh` 的每样本规则侧车（sidecar）目录。作用：把 `[[functions]]`
选择器路径纳入**断言式**复跑门禁——不再只靠 `REQUIRE_REAL` 那句 `≥1 个入口 stub`。

## 文件命名（槽位 = 样本 × 变体）

| 文件 | 作用 |
|---|---|
| `<样本名>__<变体名>.rules.toml` | 规则片段，拼进该槽位的 `$cfg`（见下"拼接位置"） |
| `<样本名>__<变体名>.expect.txt` | 该槽位的**跑前预测**（`#` 注释行 + `k=v` 断言行） |
| `<样本名>__<变体名>.passes.txt` | 可选，逐行列 pass 名，**整体替换**该槽位的 6 pass 缺省管道 |

`<样本名>` = 样本文件名去掉 `.exe`。无 `__变体名` 的槽位 = 老样本，保持现口径（`≥1`）。
变体在 `multiseed_e2e.sh` 的 `rule_variants=( "路径|变体名" )` 数组里显式登记（不是目录扫描
自动发现），这样"总槽数"能只读脚本就算出来。

**fail-closed（R2）**：存在 `.rules.toml` 而缺同名 `.expect.txt` ⇒ 该槽 **FAIL** 并点名缺
哪个文件。规则路径永不退回 `≥1` 恒真口径。

## 拼接位置：`[[passes]]` 块之前，不是文件末尾

架构建议的口径是"生成 `$cfg` 后原样追加"。**实际改为插在 `[[passes]]` 之前**，原因：
`default_level` 是 TOML **顶层键**，写在任何 `[[表头]]` 之后会被解析进上一个表。CLI 自己的
报错文案就是这么写的（`cli/src/config.cpp:202-205`：「若这是顶层键，必须写在任何 [[表头]]
之前」），且 `[[passes]]` 条目走严格 schema（只认 `name`），追加式片段会让变体 1/3/4 的
`default_level = "none"` 直接 `protect rc=2`。片段内容仍是**原样**拼接，只是落点在管道块前。

## Note 计数口径（R5，先锁正则再动手）

产品侧 `Severity::Note` 出口统一是 `[wvmp] [note] <pass>: <message>`
（`cli/src/main.cpp:33-40` 的 `severity_tag`（Note→`note` 在 `:35`）+ `:42` `print_diag_item`，
走 **stderr**；池脚本用 `2>&1` 合并捕获）。四类计数器，逐类一条正则，**互不重叠**：

| expect 键 | 语义 | 正则（`grep -E -c`，逐行） |
|---|---|---|
| `stubs` | 真虚拟化的入口 stub 数 | `\[note\] stub_link: 已生成 ([0-9]+) 个入口 stub` |
| `selector_waive_notes` | 选择器判 `level=none` 保持原生（豁免披露） | `^\[wvmp\] \[note\] virtualize: 函数 .+ 按配置 level=none 保持原生（rva=0x[0-9A-Fa-f]+）$` |
| `selector_arbitration_notes` | 跨选择器撞同一函数的仲裁披露（档位面 + 加密面合计） | `^\[wvmp\] \[note\] (virtualize\|crypt): 函数 .+ 命中 [0-9]+ 条 (level\|crypt) 规则（跨选择器撞同一函数，按声明序后评胜）` |
| `translate_gate_notes` | lifter/backend 放弃虚拟化（C1 类翻译 gate） | `^\[wvmp\] \[note\] virtualize: 函数 .+ 跳过虚拟化` |

可选断言键（缺省 = 不断言）：`selector_waive_targets`（豁免函数名**按扫描序**的逗号列表，
钉"哪几个函数"而不只是"几个"——`index` 锚定失效时数量可能不变而身份漂移）、
`crypt_encrypted` / `crypt_total` / `crypt_exempt`（取自
`^\[wvmp\] \[note\] crypt: 已加密 ([0-9]+)/([0-9]+) 个 VM 程序` 与其 `；豁免 ([0-9]+) 个（crypt=false）`
尾巴；该 Note 缺席而 expect 声明了这三个键 ⇒ FAIL）。

### 为什么不能写成"数含 gate / 含保持原生的行"

三类真实日志实抄（第 1、3 行 = `wvmp_shift0_flags_sample.exe` 的**无规则**基线跑，
第 2 行 = 池内 `wvmp_x87_gate_sample.exe` 的**无规则**基线跑；两条都是改前脚本现采）：

```
[wvmp] [note] stub_link: 已生成 7 个入口 stub，数据节 .wvmp 9016 字节 @ RVA 0xB000，代码节 .wvmpc 36323 字节 @ RVA 0xE000
[wvmp] [note] virtualize: 函数 (marker@0x79a) 含不可翻译指令，跳过虚拟化（保持原生）: 函数 (marker@0x79a): lifter 跳过 11 条指令 (rva/size 列表), IR 缺字节, 触发 C1 gate
[wvmp] [note] marker_scan: begin@0x5b0 未解析到名字物化，回退地址名（P7-names 回退路径）
```

- 第 2 行里 **"保持原生"** 是 C1 翻译 gate 的措辞，不是选择器豁免。按"含保持原生"数 ⇒
  `gate_notes` 与 `waive_notes` 混成一锅，豁免正则也会把 gate 行扫进来。所以豁免口径必须
  带 `按配置 level=none 保持原生（rva=` 全串（源码字面量：
  `passes/virtualize/src/virtualize_pass.cpp:98-101`，串在 `:100`），gate 口径必须带
  `跳过虚拟化`（同文件 `:107`、`:130`、`:154`、`:202` 四条文案共有的前缀）。
- 第 3 行说明**必须限定 pass 名**：`marker_scan` 的 P7 回退 Note、`pe_writer` 的 ASLR Note
  都在同一次输出里，不限定 pass 就会数到别的东西。
- `stub_link` 侧还有**另一类**gate 文案——`stub_link_pass.cpp:319`
  `函数 X ... ），跳过虚拟化（保持原生，x86 白名单 gate）`、`:392` `stub 生成失败（保持原生）`。
  本目录的 `translate_gate_notes` **只数 `virtualize:` 面**（档位/翻译放弃），x86 白名单与
  stub 生成期 gate 属另一语义面，刻意不并入；要守那一面得另立键，不许顺手扩宽现有正则。
- 翻译 gate 口径的"跳过虚拟化"前面是**全角逗号**不是空格（四条文案一律 `…，跳过虚拟化`）：
  首版正则按 `" 跳过虚拟化"`（带空格）写，对无规则 x87 基线跑数出 0、活体正证当场判该口径是
  死码 —— 口径必须拿真产物日志验，只对源码字符串读不算验过。
- 豁免类那行在锁口径时**没有**产物日志可抄（选择器路径此前全池零覆盖，正是本单的存在理由），
  故按源码字面量锁定；首次带规则实跑（v1_name_open，seed=1）补到的实抄：
  `[wvmp] [note] virtualize: 函数 (marker@0x5b0) 按配置 level=none 保持原生（rva=0x11B0）`
  与锁定口径逐字相符（复跑：`bash scripts/multiseed_e2e.sh --protect-log wvmp_shift0_flags_sample__v1_name_open`）。

## 预测先行（R1）

每个 `.expect.txt` 顶部带推导链（依据 = `docs/contracts.md` §6.1 区域清单口径 / §6.3 仲裁序 /
§6.4 冲突处理，**不是**被测变值的实测输出）。预测文件与推导链先于首次带规则实跑提交；
实跑后只核对不回写——实测 ≠ 预测即判缺陷并上报。

基线事实（无规则跑，`区域清单` 属输入面元数据而非被_selection_测的输出）：
`wvmp_shift0_flags_sample.exe` = 7 区 / 无规则基线 7 stub，即 7 区各自都可翻译（零 gate）：

```
[0] (marker@0x5b0) rva=0x11B0   [1] (marker@0x5e2) rva=0x11E2   [2] (marker@0x614) rva=0x1214
[3] (marker@0x646) rva=0x1246   [4] (marker@0x678) rva=0x1278   [5] (marker@0x6aa) rva=0x12AA
[6] (marker@0x6dc) rva=0x12DC
```
