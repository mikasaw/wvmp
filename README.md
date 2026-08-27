# WVmp

WVmp 是一个完全插件化的 PE x86/x64 虚拟机保护壳（参考 VMProtect/VMPilot 的自研实现）。

A fully pluginized PE x86/x64 virtual-machine protector (self-researched,
VMProtect/VMPilot-inspired).

## 构建（Windows / MSVC / Ninja，需 VS 18 Insiders）

    scripts\build.bat

从 Git Bash 调用：

    cmd //c "$(cygpath -w scripts/build.bat)"

首次构建会通过 CMake FetchContent 拉取第三方依赖（googletest / capstone /
keystone / tomlplusplus）到 `.deps/`，keystone 编译较久。

## 测试

    scripts\test.bat

## 现实世界 exe 回归测试集 (MIT-350)

派活单核心目标: 让 protected notepad.exe / 7z.exe / tasklist.exe / cmd.exe /
curl.exe 在 `scripts/real_world_exe/verify_real_world.sh` 下跑通 byte-exact
native == protected, 验证 WVmp 在 16 个自测样本之外的真实 Windows exe 上能
用, 同时推动发现派活单派发**前**未识别的指令集 / pitfall.

### 验证步骤

```
bash scripts/real_world_exe/verify_real_world.sh
```

5 个现实世界 exe 覆盖 GUI + 命令行 + 文件压缩 + shell + HTTP:

| 配置 | 输入 | 测试参数 | 模式 |
|---|---|---|---|
| `notepad.toml`  | `C:/Windows/System32/notepad.exe`     | (默认)             | GUI (timeout + rc) |
| `7z.toml`       | `C:/Program Files/7-Zip/7z.exe`        | `--help`           | stdout byte-exact |
| `tasklist.toml` | `C:/Windows/System32/tasklist.exe`     | `/?`               | stdout byte-exact |
| `cmd.toml`      | `C:/Windows/System32/cmd.exe`          | `/c echo WVMP_REAL_WORLD_OK` | stdout byte-exact |
| `curl.toml`     | `C:/Program Files/Git/mingw64/bin/curl.exe` | `--version`   | stdout byte-exact |

每个 toml 配置沿用 `cli/configs/default.toml` 风格 (`pe_loader → marker_scan →
lifter → virtualize → stub_link → pe_writer`). 输出统一到
`build/real_world_exe/<name>.protected.exe`.

### 派活单限定不支持 (verify_real_world.sh 会作为 pitfall 实证记录, 不算回归)

- SSE / AVX / x87 FPU / lock prefix / rep prefix
- MFC / WTL / Qt GUI 框架 / DirectX / OpenGL
- syscall / sysenter
- DLL imports (派活单限定 EXE)
- PE32 32-bit / Control Flow Guard / CET

### 派活单核心目标解读

- **PASS byte-exact + 真虚拟化 (含 stub 生成标记)**: protected 跑通且 stub_link
  生成至少 1 个 VirtualizedFunction, 派活单核心目标 byte-exact 真虚拟化达成
- **PASS byte-exact but C1 gate fallback**: protected 跑通但 stub_link 走 C1
  gate 兜底 (派活单限定不支持的指令集, protected PE 行为正确但未真虚拟化),
  仍记录为 pass (不阻断回归) + 计入 pitfall data points
- **FAIL stdout/rc mismatch**: protected PE 行为偏离 native, 这是派活单核心
  目标**最希望发现的 pitfall**, 计入 pitfall data points
- **SKIP**: 输入 exe 不存在 (e.g. 7-Zip 未安装), 不算失败

### 沉淀 (从 MIT-300~355 教训)

- 派活单 §A 假设不一定是真根因 (pitfall #33, 实战 MIT-332/335/339/341/345/
  347/349/353/355): 派活单描述错 agent 实际正确的情形下, verifier 必独立确认
  native == protected 一致, 不盲反 agent, 也不盲采派活单描述
- 派活单派发后 agent 跑了 8 步就 completed 模式 (pitfall #38 候选, MIT-339 v1
  实证): 派活单红派送 note 强调 "agent 必跑 ≥ 30 分钟, 不要在 5 分钟内
  completed"
- MASM (.asm) helper / rax 栈守恒 / T1 clobber / kStubWindow 64-NOP 填充等
  pitfall (#35-#39) 在本派活单范围外, 沿用现状
