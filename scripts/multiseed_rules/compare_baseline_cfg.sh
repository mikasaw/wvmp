#!/usr/bin/env bash
# MIT-522 (B0-3) 判据 2 / R4：零扰动证明（全量脚本化，不靠人工抽样）。
#
# 要证的事：引入规则挂点后，**无规则挂点**的槽位生成的 `$cfg` 与 protect 输出必须逐字节
# 不变——否则"新门禁没碰老路径"这句就成了口头承诺。R4 把验收原判据的"任取 3 枚"改成
# 全量比对。
#
# 做法（两侧对称，避免"只测自己新写的生成器"）：
#   1. 取改前脚本（git show <base>:scripts/multiseed_e2e.sh）与改后脚本各一份副本；
#   2. 给**两份副本打同一枚**取证补丁：跑完 protect 后把 cfg 与 protect 原文 dump 出来，
#      并把 seeds 数组收成 1 枚（cfg 是 (样本, seed) 的纯函数，seed 维度不影响比对）；
#   3. 两侧各跑一遍无规则挂点的全池，逐槽位 cmp。
# 副本放在 scripts/ 下（脚本按自身 dirname 推 repo 根），跑完即删——补丁只存在于临时副本，
# 交付的池脚本里没有 dump 钩子。
#
# 用法: bash scripts/multiseed_rules/compare_baseline_cfg.sh [<base-ref>]
#       <base-ref> 默认 mit-debt-b-shiftmask（本单 diff 锚点）
# 退出码: 0 = 三项差异计数全 0；1 = 有差异或取证面不成立；2 = 前置条件不满足。
set -u

repo="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$repo" || exit 2

BASE="${1:-mit-debt-b-shiftmask}"
BASE_SHA="$(git rev-parse --short "$BASE" 2>/dev/null)" || {
    echo "[zero-perturb] 解析不出 base ref '$BASE'（工作树不是 git 仓？该 ref 不存在？）" >&2
    exit 2
}
[[ -x build/cli/wvmp_cli.exe || -x build/vs/cli/Debug/wvmp_cli.exe ]] || {
    echo "[zero-perturb] 找不到 wvmp_cli.exe，先跑 scripts\\build.bat" >&2
    exit 2
}

tmp="$(mktemp -d)"
cleanup() {
    rm -f scripts/.mit522_probe_base_e2e.sh scripts/.mit522_probe_head_e2e.sh
    rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

# ── 两份副本 + 同一枚取证补丁 ────────────────────────────────────────────────
git show "$BASE:scripts/multiseed_e2e.sh" > scripts/.mit522_probe_base_e2e.sh || exit 2
cp scripts/multiseed_e2e.sh scripts/.mit522_probe_head_e2e.sh

# 补丁：在 protect 调用行之后插一段 dump。锚点两侧必须完全一致（改前/改后同一行文本），
# 锚点找不到 = 直接失败，不允许"补丁没打上但比对照样绿"。
ANCHOR='        out="$("$cli" protect --config "$cfg" 2>&1)" || rc=$?'

cat > "$tmp/dump_snippet.txt" <<'SNIPPET'
        if [[ -n "${MULTISEED_DUMP_DIR:-}" ]]; then
            _tag="$(basename "$sample" .exe)__${variant:-unruled}__s${seed}"
            mkdir -p "$MULTISEED_DUMP_DIR"
            sed -E 's#tmp\.[A-Za-z0-9]{4,}#@TMP@#g' "$cfg" > "$MULTISEED_DUMP_DIR/$_tag.cfg"
            printf '%s\n' "$out" | sed -E 's#tmp\.[A-Za-z0-9]{4,}#@TMP@#g' \
                > "$MULTISEED_DUMP_DIR/$_tag.protect.log"
        fi
SNIPPET

apply_probe() { # $1=file
    local f="$1" n
    n="$(grep -nF "$ANCHOR" "$f" | head -1 | cut -d: -f1)"
    if [[ -z "$n" ]]; then
        echo "[zero-perturb] 取证补丁锚点在 $(basename "$f") 里找不到 —— 比对不成立，拒绝出绿" >&2
        exit 2
    fi
    # 按行号切开重接：锚点里带 `2>&1`，任何"替换文本里出现 &"的做法都会被当成"整段匹配
    # 内容"（实测被展开成 out="…2>        out=…1)" 的碎线），故不做字符串替换，只做行手术。
    {
        sed -n "1,${n}p" "$f"
        cat "$tmp/dump_snippet.txt"
        sed -n "$((n + 1)),\$p" "$f"
    } > "$f.probed" && mv "$f.probed" "$f"
    # seed 收成 1 枚（两侧同一枚 seed，逐槽可比）
    sed -i -E 's/^seeds=\(.*\)$/seeds=(12345)/' "$f"
    grep -q '^seeds=(12345)$' "$f" || {
        echo "[zero-perturb] seed 数组补丁没打上（$(basename "$f")）—— 比对不成立" >&2
        exit 2
    }
    grep -qF 'MULTISEED_DUMP_DIR' "$f" || {
        echo "[zero-perturb] dump 补丁没打上（$(basename "$f")）—— 比对不成立" >&2
        exit 2
    }
    bash -n "$f" || {
        echo "[zero-perturb] 补丁后语法检查失败（$(basename "$f")）" >&2
        exit 2
    }
}
apply_probe scripts/.mit522_probe_base_e2e.sh
apply_probe scripts/.mit522_probe_head_e2e.sh

echo "[zero-perturb] base = $BASE ($BASE_SHA)  head = $(git rev-parse --short HEAD) ($(git branch --show-current))"
echo "[zero-perturb] 两侧同补丁：dump cfg + protect 原文；seeds -> (12345)；REQUIRE_REAL=1"

# ── 两侧各跑一遍 ────────────────────────────────────────────────────────────
run_side() { # $1=脚本 $2=dump 目录 $3=stdout
    REQUIRE_REAL=1 MULTISEED_DUMP_DIR="$2" bash "$1" > "$3" 2>&1
    return $?
}
run_side scripts/.mit522_probe_base_e2e.sh "$tmp/dump_base" "$tmp/base.out"
rc_base=$?
run_side scripts/.mit522_probe_head_e2e.sh "$tmp/dump_head" "$tmp/head.out"
rc_head=$?
echo "[zero-perturb] 改前池读数: $(grep -hE '^\[multiseed\] TOTAL' "$tmp/base.out")  (exit $rc_base)"
echo "[zero-perturb] 改后池读数: $(grep -hE '^\[multiseed\] TOTAL' "$tmp/head.out")  (exit $rc_head)"

nb="$(ls "$tmp/dump_base" 2>/dev/null | grep -c '\.cfg$')"
nh="$(ls "$tmp/dump_head" 2>/dev/null | grep -c '\.cfg$')"
echo "[zero-perturb] dump 槽位数: base=$nb head=$nh（head 应 = base + 规则变体槽数）"
[[ "$nb" -gt 0 ]] || { echo "[zero-perturb] 一个槽位都没 dump 出来 —— 取证面不成立" >&2; exit 1; }

# ── 逐槽比对：只看 base 侧的槽位（= 全部无规则挂点槽位）────────────────────────
cfg_diff=0
key_diff=0
compared=0
missing=0
diff_first=""
for cf in "$tmp/dump_base"/*.cfg; do
    tag="$(basename "$cf" .cfg)"
    compared=$((compared + 1))
    if [[ ! -f "$tmp/dump_head/$tag.cfg" || ! -f "$tmp/dump_head/$tag.protect.log" ]]; then
        missing=$((missing + 1))
        diff_first="$diff_first$tag: 改后侧缺 dump"$'\n'
        continue
    fi
    if ! cmp -s "$cf" "$tmp/dump_head/$tag.cfg"; then
        cfg_diff=$((cfg_diff + 1))
        diff_first="$diff_first$tag: cfg 差异"$'\n'$(diff "$cf" "$tmp/dump_head/$tag.cfg" | head -4)
    fi
    # protect 关键行 = CLI 打的全部 [wvmp] 行（@TMP@ 归一后逐行比）：note / 区域清单 /
    # 管道声明 / 完成行都在这集合里，不限定 pass 名，免得"只比 note"漏掉管道顺序变化。
    if ! cmp -s "$tmp/dump_base/$tag.protect.log" "$tmp/dump_head/$tag.protect.log"; then
        key_diff=$((key_diff + 1))
        diff_first="$diff_first$tag: protect 关键行差异"$'\n'$(diff "$tmp/dump_base/$tag.protect.log" "$tmp/dump_head/$tag.protect.log" | head -4)
    fi
done

echo ""
echo "归一口径: 仅抹掉 harness 自己的 mktemp 目录名（s#tmp\\.[A-Za-z0-9]{4,}#@TMP@#g，两侧同规则）；"
echo "          其余逐行比，不限定 pass 名——note / 区域清单 / 管道声明 / 完成行全在比对集合里。"
echo ""
echo "no-rule slots compared: $compared, cfg diffs: $cfg_diff, protect-line diffs: $key_diff"
[[ "$missing" -gt 0 ]] && echo "改后侧缺 dump 的槽位: $missing"
if [[ -n "$diff_first" ]]; then
    echo "--- 前 30 行差异明细 ---"
    printf '%s\n' "$diff_first" | head -30
fi
if [[ "$cfg_diff" -eq 0 && "$key_diff" -eq 0 && "$missing" -eq 0 ]]; then
    echo "[zero-perturb] RESULT: PASS"
    exit 0
fi
echo "[zero-perturb] RESULT: FAIL"
exit 1
