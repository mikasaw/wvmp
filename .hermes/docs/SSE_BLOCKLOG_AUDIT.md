# SSE/Block backlog 派活单整改清单

> 产出: MIT-390(2026-08-28, WVmpCppDev 执行)。
> 依据: MIT-373 暴露的三类基线认知错误 ——
> ① SSE handler 空转仍可 multiseed byte-exact PASS(Accept 假阳性, Keystone 裸多位立即数十六进制解析);
> ② `multica issue run-messages` AC 项不可执行;
> ③ ctest 基线 15/15 过期(MIT-380 新增 regvm_backend_tests 后实际 16/16)。
> 统一模板: `.hermes/templates/SSE_BLOCK_BACKLOG_DISPATCH.md`(MIT-390 决策 D2: 仅人类参考)。

## 现状核查(2026-08-28 实测)

- `multica issue get` 逐单实测(下表"现状"列均为实测, 非推断)。
- ctest 实际基线: **16/16**(基线含 regvm_backend_tests)。
- multiseed 实际基线: **13 samples × 5 seeds = 65 runs**; MIT-373 时点 40/65 PASS,
  其余为既有 segfault(5 样本 × 5 seeds)。`scripts/multiseed_e2e.sh` SAMPLES 实测 13 项,
  含 `wvmp_sse_add_sample` / `wvmp_sse_sub_sample`。
- **编号勘误**(MIT-390 派单描述写的草案编号与平台实际编号有偏移, 以下按平台实际编号执行):
  - verifier 加固单: 描述写 "MIT-378" → 平台实际为 **MIT-389**("WVmpVerifier 验收门加固 — 抓
    SSE handler 空转", status=todo, **未落地**: `scripts/verifier/` 目录不存在, 实测)。
    平台 MIT-378 是无关的 MyArk UI issue, 勿混淆。
  - Block F 三单: 描述写 "MIT-405 / MIT-406 / MIT-407" → 平台**不存在**(issue get 实测 404)。
    无 rewrite 对象; 建单时应直接用新模板。
- 附带事实: `multica issue run-messages` 子命令当前在 CLI 存在(`multica issue --help` 可见,
  语义为 "List messages for an execution", 按 execution id 查询)。历史 AC 项 404 的教训不变:
  CLI 可用性检查不构成交付验收, 新模板一律禁止写此类 AC 项。

## 整改清单

| Issue | 内容 | 现状 | 判定 | 整改要求 |
|---|---|---|---|---|
| MIT-371 | SSE add addss/addps/addpd | done(但 Accept 时 handler 全部空转, MIT-373 才定位根因) | 已 done 无需动 | 派单文本已过期但不重发; 空转暴露面归 MIT-389 复核清单(PRE_EXPOSURE_LIST)覆盖 |
| MIT-373 | SSE sub subss/subps/subpd | in_review(commit 8ed50b0, imm() 修复本体) | 已 done 无需动(等验收) | — |
| MIT-374 | SSE div divss/divps/divpd | backlog; 32k 字旧模板描述; AC #2 写 ctest 15/15, AC #5 写 "multiseed 70/70 PASS + 全样本真虚拟化" —— 均与实际基线矛盾 | **需 rewrite** | ✅ 本单已 rewrite(description 全量替换, 保留技术范围与冻结契约)。派发前项目主确认 |
| MIT-375 | SSE mov movss/movaps/movapd/movups/movupd | backlog; 同 MIT-374(ctest 15/15 + "75/75 PASS") | **需 rewrite** | ✅ 本单已 rewrite。注意: MIT-390 描述误写 MIT-375 为 "SSE mul (mulss/mulps/mulpd)", 平台实际 MIT-375 是浮点**传送** mov 5 形式, rewrite 以平台为准 |
| MIT-376 | SSE 位运算 xorps/orps/andps + 比较 ucomiss/ucomisd | backlog; 同 MIT-374(ctest 15/15 + "80/80 PASS") | **需 rewrite** | ✅ 本单已 rewrite。注意: MIT-390 描述写 "andps/andpd/xorps/xorpdorps", 平台实际 5 形式为 xorps/orps/andps + ucomiss/ucomisd(不含 andpd/xorpd), rewrite 以平台为准 |
| Block F LOOP | 草案编号 MIT-405 | **平台不存在(404)** | 不存在 | 建单时直接用新模板; 非 SSE 单不涉及 ctx.xmm 读回, 但 imm() 硬约束、ctest 16/16、禁 run-messages AC 同样生效 |
| Block F BSF | 草案编号 MIT-406 | 平台不存在(404) | 不存在 | 同上 |
| Block F BT | 草案编号 MIT-407 | 平台不存在(404) | 不存在 | 同上 |
| MIT-387 | 标题 "MIT-373:" 的 backlog 单 | 疑似 MIT-373 派单副本(描述含 `multica issue run-messages` 历史基线段 + 过期数字) | 仅 patch / 需项目主决策 | MIT-373 本体已 in_review; 建议项目主确认 MIT-387 是否取消归档; 若启用必须先按新模板 rewrite |
| MIT-389 | verifier 加固门(草案编号 MIT-378) | todo; `scripts/verifier/` 尚不存在 | 已 done 无需动(未落地) | 落地后 `static_scan_bare_immediates.ps1` + `dump_handler_xmm_check.py` 纳入 SSE/VMX/AVX 验收引用; 落地前 SSE 派单自带 ctx.xmm 读回断言(模板验收 #5) |

## 已执行动作(MIT-390)

1. 新增统一模板 `.hermes/templates/SSE_BLOCK_BACKLOG_DISPATCH.md`(AC#1)。
2. MIT-374 / MIT-375 / MIT-376 description 全量 rewrite
   (`multica issue update --description-file`, 决策 D1; 更新均带 `--no-start`, 不触发派发)。
3. WVmpCppDev instructions 追加"硬约束 4 条" + MIT-390 模板引用(决策 D2, AC#4)。
4. WVmpVerifier instructions 追加 SSE/VMX/AVX 加固门引用(AC#5, MIT-389 待完成口径),
   并把其内部过期的 "15/15" 套件基线字样对齐为 16/16。

## 未执行 / 遗留(项目主动作)

- Block F(LOOP / BSF / BT)建单: 平台无 MIT-405/406/407, 无 rewrite 对象; 建单时用模板。
- MIT-387 处置(取消归档 or 重写)待项目主确认。
- MIT-389 落地前, SSE/VMX/AVX 验收按模板验收 #5 的替代检查执行; 落地后切换为直接引用脚本。
