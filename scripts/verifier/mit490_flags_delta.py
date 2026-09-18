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
  # 1) 采集一侧（base 或 head）：逐 handler 码体切片 + 逐词字节码切片
  python scripts\\verifier\\mit490_flags_delta.py collect \
      --asm runtime_dump.txt --pe protected.exe --out head.csv
  python scripts\\verifier\\mit490_flags_delta.py words \
      --pe protected.exe --out head_words.csv [--repo .]

  # 2) 两侧对照出表（含逐处字节 delta + 退出码）
  python scripts\\verifier\\mit490_flags_delta.py diff \
      --base base.csv --head head.csv [--details 8]
  python scripts\\verifier\\mit490_flags_delta.py words-diff \
      --base base_words.csv --head head_words.csv [--all]

Exit codes: 0 = 全部 handler 码体恒等（diff）/ 无词面差异（words-diff）;
1 = 存在差异; 2 = 工具错误。
"""

from __future__ import annotations

import argparse
import hashlib
import os
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


def find_sections(pe_path: str) -> dict[str, bytes]:
    """{节名: 节原始字节}（只取本工具关心的 .wvmpc / .wvmp）。"""
    with open(pe_path, "rb") as f:
        data = f.read()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_sz = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    sec0 = e_lfanew + 24 + opt_sz
    out: dict[str, bytes] = {}
    for i in range(nsec):
        off = sec0 + i * 40
        name = data[off:off + 8].rstrip(b"\0").decode("ascii", "replace")
        if name in (".wvmpc", ".wvmp"):
            raw_sz, raw_ptr = struct.unpack_from("<II", data, off + 16)
            out[name] = data[raw_ptr:raw_ptr + raw_sz]
    if not out:
        raise ValueError(f"{pe_path} 里没有 .wvmpc/.wvmp 段（未加壳？）")
    return out


def extract_code_section(pe_path: str) -> bytes:
    """runtime image 所在节：优先 .wvmpc（RX 码节，段首即 image.code），
    回退 .wvmp（旧布局）。"""
    secs = find_sections(pe_path)
    for name in (".wvmpc", ".wvmp"):
        if name in secs:
            return secs[name]
    raise ValueError("no code section")


# ---------------------------------------------------------------------------
# 词面：真实 protect 产出的 VM blob 逐词解码。
# v1 codec = 直通（asm_dump 头 "codec: none"），故 .wvmp（RW 数据节）里的
# WVMP blob 就是翻译器落地的原始词流 —— flags-dead 位（词 bit 16 =
# cond_or_size 位 2）的扰动面在这里逐词可读，不必退回合成夹具。
# 位图（encoding.hpp 契约）：opcode 13..0 / a_kind 15..14 / b_kind 17..16 /
# cond 21..18 / reg_a 26..22 / reg_b 31..27 / aux 63..32。
# ---------------------------------------------------------------------------
K_AKIND, K_BKIND, K_COND, K_REGA, K_REGB, K_AUX = 14, 16, 18, 22, 27, 32
BLOB_MAGIC = b"WVMP"
BLOB_HEADER = 32
FLAGS_DEAD_BIT = 0x4


def vm_op_names(repo: str) -> dict[int, str]:
    """解析 vm_op.hpp 的 `enum class VmOp : u16 { Mov = 1, Lea, ... }` →
    {值: 名}。解析而非硬编码：新增 op 不必改本工具。"""
    p = os.path.join(repo, "vm", "regvm", "isa", "include", "wvmp", "regvm",
                     "isa", "vm_op.hpp")
    with open(p, encoding="utf-8", errors="replace") as fh:
        raw_text = fh.read()
    # 先剥注释再定位花括号：本文件注释里带 `{`/`}`（位图说明、示例代码），
    # 带注释扫平衡会一路越过 enum 收尾、把后面 to_string/struct 的
    # `aux = 0` 当枚举初值吞进来（实测把整张表错移成 54 项）。
    clean = re.sub(r"/\*.*?\*/", "", re.sub(r"//[^\n]*", "", raw_text), flags=re.S)
    head = clean.index("enum class VmOp")
    open_i = clean.index("{", head)
    depth, end = 0, None
    for j in range(open_i, len(clean)):
        if clean[j] == "{":
            depth += 1
        elif clean[j] == "}":
            depth -= 1
            if depth == 0:
                end = j
                break
    if end is None:
        raise ValueError(f"{p}: enum class VmOp 花括号不闭合")
    names: dict[int, str] = {}
    nxt = 1
    for raw in clean[open_i + 1:end].split(","):
        line = raw.strip()
        g = re.fullmatch(r"([A-Za-z_]\w*)(?:\s*=\s*(0[xX][0-9A-Fa-f]+|\d+))?", line)
        if not g:
            if line:
                raise ValueError(f"{p}: 枚举体出现无法识别的片断 {line!r}")
            continue
        if g.group(2):
            nxt = int(g.group(2), 0)
        names[nxt] = g.group(1)
        nxt += 1
    if len(names) < 100 or names.get(1) != "Mov":
        raise ValueError(f"{p}: 解析出 {len(names)} 个 VmOp（首项 "
                         f"{names.get(1)!r}），枚举解析走样")
    return names


def iter_blobs(sec: bytes):
    """顺序扫 (blob 序号, insn_count, stream bytes)。"""
    pos, idx = 0, 0
    while True:
        j = sec.find(BLOB_MAGIC, pos)
        if j < 0 or j + BLOB_HEADER > len(sec):
            return
        ver, _arch, _entry, cnt = struct.unpack_from("<HHII", sec, j + 4)
        end = j + BLOB_HEADER + cnt * 8
        if ver != 1 or cnt == 0 or cnt > (1 << 18) or end > len(sec):
            pos = j + 4      # 伪 magic（数据里撞出的 WVMP 字串）→ 前进重扫
            continue
        yield idx, cnt, sec[j + BLOB_HEADER:end]
        idx += 1
        pos = end


def cmd_words(a: argparse.Namespace) -> int:
    try:
        names = vm_op_names(a.repo)
        sec = find_sections(a.pe).get(".wvmp", b"")
    except (OSError, ValueError) as e:
        print(f"[mit490-diff] 工具错误: {e}", file=sys.stderr)
        return 2
    if not sec:
        print("[mit490-diff] 工具错误: 无 .wvmp 数据节（字节码不在里面）",
              file=sys.stderr)
        return 2
    rows = 0
    with open(a.out, "w", encoding="utf-8", newline="") as f:
        f.write("region,word,op,a_kind,reg_a,b_kind,reg_b,aux,cond,dead\n")
        for idx, cnt, stream in iter_blobs(sec):
            for wi in range(cnt):
                w = struct.unpack_from("<Q", stream, wi * 8)[0]
                op = w & 0x3FFF
                cond = (w >> K_COND) & 0xF
                f.write(f"{idx},{wi},{names.get(op, 'op%d' % op)},"
                        f"{(w >> K_AKIND) & 3},{(w >> K_REGA) & 0x1F},"
                        f"{(w >> K_BKIND) & 3},{(w >> K_REGB) & 0x1F},"
                        f"0x{(w >> K_AUX) & 0xFFFFFFFF:x},{cond},"
                        f"{cond & FLAGS_DEAD_BIT}\n")
                rows += 1
    print(f"[mit490-diff] words -> {a.out}: {rows} 词")
    return 0


def cmd_words_diff(a: argparse.Namespace) -> int:
    def read(p: str) -> dict[tuple[int, int], tuple[str, int, str]]:
        out = {}
        with open(p, encoding="utf-8") as f:
            for line in f.read().splitlines()[1:]:
                r = line.split(",")
                out[(int(r[0]), int(r[1]))] = (r[2], int(r[8]), r[7])
        return out
    try:
        base, head = read(a.base), read(a.head)
    except (OSError, ValueError) as e:
        print(f"[mit490-diff] 工具错误: {e}", file=sys.stderr)
        return 2
    keys = sorted(set(base) | set(head))
    same = 0
    changed = []
    for k in keys:
        b, h = base.get(k), head.get(k)
        if b is None or h is None or b != h:
            changed.append((k, b, h))
        else:
            same += 1
    print(f"{'region.word':<14} {'op':<12} {'aux':<10} cond base->head  归因")
    for (reg, wi), b, h in changed[: a.limit]:
        if b is None or h is None:
            print(f"{reg}.{wi:<12} {'-':<12} {'-':<10} 词数/布局本身变了（查 blob 边界）")
            continue
        op, cond_b, aux = b
        cond_h = h[1]
        dead_b, dead_h = cond_b & FLAGS_DEAD_BIT, cond_h & FLAGS_DEAD_BIT
        why = ("flags-dead 标清除：该写经零计数/计数不可知的移位仍对外可见"
               if dead_b and not dead_h else
               "flags-dead 标新增" if dead_h and not dead_b else
               "op/kind/reg/aux 变化（本单不该出现，须归因）")
        print(f"{reg}.{wi:<12} {op:<12} {aux:<10} {cond_b} -> {cond_h}   {why}")
    print(f"\n[mit490-diff] 词面 {len(keys)} 词：恒等 {same}，"
          f"cond_or_size 有 delta {len(changed)}")
    if len(changed) > a.limit:
        print(f"  （仅列前 {a.limit} 处，--limit 放宽）")
    return 1 if (a.strict and changed) else 0


def cmd_collect(a: argparse.Namespace) -> int:
    try:
        with open(a.asm, encoding="utf-8", errors="replace") as f:
            total, table, handlers = parse_asm_dump(f.read())
        code = extract_code_section(a.pe)
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
    w = sub.add_parser("words", help="逐词解码 .wvmp 里的 VM blob → CSV")
    w.add_argument("--pe", required=True)
    w.add_argument("--out", required=True)
    w.add_argument("--repo", default=".", help="仓库根（读 vm_op.hpp 取名）")
    w.set_defaults(fn=cmd_words)
    wd = sub.add_parser("words-diff", help="两侧词面 CSV 对照（扰动面逐处归因）")
    wd.add_argument("--base", required=True)
    wd.add_argument("--head", required=True)
    wd.add_argument("--limit", type=int, default=40)
    wd.add_argument("--strict", action="store_true",
                    help="有 delta 即非 0 退出（本单预期有 delta，默认不 strict）")
    wd.set_defaults(fn=cmd_words_diff)
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
