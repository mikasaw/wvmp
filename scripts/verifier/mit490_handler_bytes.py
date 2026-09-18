#!/usr/bin/env python3
"""
MIT-490 (CR-01) 差分表：flags-dead 位改判前后的**逐 handler 码体字节**对账。

Why this tool exists:
  CR-01 的修复面在翻译期（liveness 判定），不是运行时（asmgen）。运行时
  flags_tail 的标记路由（test T8, 1<<20 / jnz skip）是 MIT-474 既有代码，本
  单零改动。但"零改动"必须是**机器证据**而不是断言：把一次真实 protect 产出
  的 runtime image 按 handler 切片、逐 handler 哈希，base 与 head 对照，才能
  把"码体哪些字节变了"逐处列出并归因。
  ⚠️ packed exe 的 sha 在本单**必然**变化（cond_or_size 位 2 属字节码），那
  不是回归判据，也不是恒等证据——本工具刻意不看 packed sha。

Artifacts (both from ONE protect run of a real sample, same seed):
  --asm <runtime_dump.txt>  WVMP_RUNTIME_DUMP=<win path> 下 wvmp_cli protect
                            落盘的 asm_dump（handler 名 + 偏移 + total）
  --pe  <protected.exe>     同一次 protect 的输出 PE（.wvmp 段起始即
                            runtime image.code，与 dump_handler_xmm_check.py
                            同一口径）

Usage:
  # 1) 采集一侧（base 或 head）
  python scripts\\verifier\\mit490_handler_bytes.py collect \
      --asm runtime_dump.txt --pe protected.exe --out head.csv

  # 2) 两侧对照出表（含逐处字节 delta + 退出码）
  python scripts\\verifier\\mit490_handler_bytes.py diff \
      --base base.csv --head head.csv [--details 8]

Exit codes: 0 = 全部 handler 码体恒等; 1 = 存在差异（diff 模式）; 2 = 工具错误。
"""

from __future__ import annotations

import argparse
import hashlib
import re
import struct
import sys

HANDLER_RE = re.compile(r"; ---- handler (\S+) @ \+?(0x[0-9A-Fa-f]+) ----")


def parse_asm_dump(text: str) -> tuple[int, int, list[tuple[str, int]]]:
    """(total, table_off, [(handler, off)]) —— 与 dump_handler_xmm_check.py 同口径。"""
    total = re.search(r"total=(0x[0-9A-Fa-f]+)", text)
    table = re.search(r"table=\+?(0x[0-9A-Fa-f]+)", text)
    handlers = [(n, int(o, 16)) for n, o in HANDLER_RE.findall(text)]
    if not total or not table or not handlers:
        raise ValueError("dump 缺 total/table/handler 布局行（不是 WVMP_RUNTIME_DUMP 文件？）")
    return int(total.group(1), 16), int(table.group(1), 16), handlers


def extract_code_section(pe_path: str) -> tuple[int, bytes]:
    """runtime image 所在节：优先 .wvmpc（RX 码节，段首即 image.code），
    回退 .wvmp（旧布局）。段首是否 vm_entry 由 caller 的偏移覆盖性间接
    保证（handler 偏移越界即 WARN）。"""
    with open(pe_path, "rb") as f:
        data = f.read()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_sz = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    sec0 = e_lfanew + 24 + opt_sz
    found: dict[str, tuple[int, bytes]] = {}
    for i in range(nsec):
        off = sec0 + i * 40
        name = data[off:off + 8].rstrip(b"\0").decode("ascii", "replace")
        if name in (".wvmpc", ".wvmp"):
            raw_sz, raw_ptr = struct.unpack_from("<II", data, off + 16)
            found[name] = (raw_ptr, data[raw_ptr:raw_ptr + raw_sz])
    for name in (".wvmpc", ".wvmp"):
        if name in found:
            return found[name]
    raise ValueError(f"{pe_path} 里没有 .wvmpc/.wvmp 段（未加壳？）")


def cmd_collect(a: argparse.Namespace) -> int:
    try:
        with open(a.asm, encoding="utf-8", errors="replace") as f:
            total, table, handlers = parse_asm_dump(f.read())
        _, code = extract_code_section(a.pe)
    except (OSError, ValueError) as e:
        print(f"[mit490-diff] 工具错误: {e}", file=sys.stderr)
        return 2
    # handler 区间 = [本 handler 偏移, 下一 handler 偏移)，最后一个到跳表起点。
    by_off = sorted(handlers, key=lambda h: h[1])
    spans = []
    for i, (name, off) in enumerate(by_off):
        end = by_off[i + 1][1] if i + 1 < len(by_off) else table
        spans.append((name, off, end))
    rows = []
    for name, off, end in spans:
        body = code[off:end]
        rows.append((name, off, end - off, hashlib.sha256(body).hexdigest()[:16]))
    with open(a.out, "w", encoding="utf-8", newline="") as f:
        f.write("handler,off,size,sha256_16\n")
        for r in rows:
            f.write(f"{r[0]},0x{r[1]:x},{r[2]},{r[3]}\n")
    print(f"[mit490-diff] collect -> {a.out}: {len(rows)} handlers, "
          f"code={len(code)}B, table=0x{table:x}, total=0x{total:x}")
    if len(code) < total:
        print("[mit490-diff] WARN: 码节短于 image total（切片不完整，别信本表）",
              file=sys.stderr)
    return 0


def cmd_diff(a: argparse.Namespace) -> int:
    def read(p: str) -> dict[str, tuple[int, int, str]]:
        out: dict[str, tuple[int, int, str]] = {}
        with open(p, encoding="utf-8") as f:
            for line in f.read().splitlines()[1:]:
                name, off, size, sha = line.split(",")
                out[name] = (int(off, 16), int(size), sha)
        return out
    try:
        base, head = read(a.base), read(a.head)
    except (OSError, ValueError) as e:
        print(f"[mit490-diff] 工具错误: {e}", file=sys.stderr)
        return 2
    only_b = sorted(set(base) - set(head))
    only_h = sorted(set(head) - set(base))
    same = changed = 0
    print(f"{'handler':<16} {'base off/size':>22} {'head off/size':>22}  verdict")
    for name in sorted(set(base) & set(head)):
        bo, bs, bsha = base[name]
        ho, hs, hsha = head[name]
        ok = (bsha == hsha)
        same += ok
        changed += not ok
        if not ok or a.all:
            print(f"{name:<16} {f'0x{bo:x}/{bs}B':>22} {f'0x{ho:x}/{hs}B':>22}  "
                  + ("IDENTICAL" if ok else f"** CHANGED ** sha {bsha} -> {hsha}"))
    print(f"\n[mit490-diff] 共同 handler {same + changed} 个：码体恒等 {same}，"
          f"有字节差异 {changed}；仅 base {len(only_b)}，仅 head {len(only_h)}")
    if only_b or only_h:
        print(f"  仅 base: {only_b}\n  仅 head: {only_h}")
    if changed and a.details:
        print(f"[mit490-diff] 有 {changed} 处码体差异 —— 逐处归因需结合 "
              f"vm/regvm/runtime/src/asmgen.cpp 的本次改动（本单未改该文件）。")
    return 1 if (changed or only_b or only_h) else 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect", help="按 handler 切片码体并出 CSV")
    c.add_argument("--asm", required=True)
    c.add_argument("--pe", required=True)
    c.add_argument("--out", required=True)
    c.set_defaults(fn=cmd_collect)
    d = sub.add_parser("diff", help="两侧 CSV 对照出差分表")
    d.add_argument("--base", required=True)
    d.add_argument("--head", required=True)
    d.add_argument("--all", action="store_true", help="恒等行也逐行列出")
    d.add_argument("--details", type=int, default=8)
    d.set_defaults(fn=cmd_diff)
    a = p.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
