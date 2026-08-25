#!/usr/bin/env bash
# MIT-306: 强制 REQUIRE_REAL=1 的 multiseed e2e helper.
# 与 multiseed_e2e.sh 的区别: 除 byte-exact 外还校验 "已生成 N 个入口 stub"
# 标记, 防止 C1 gate 兜底被误判 PASS（C1 gate 函数被跳过仍能输出相同 stdout+rc,
# 仅 byte-exact 比对看不出）。
#
# 用法: scripts/multiseed_e2e_real.sh
# 退出码: 0 全 PASS; 非 0 有失败。

set -u
cd "$(cd "$(dirname "$0")/.." && pwd)"
REQUIRE_REAL=1 bash scripts/multiseed_e2e.sh