# WVmp

A self-researched PE virtual-machine protector. Translates marked regions of x86/x64 Windows executables into a custom register-based VM, with stub-link dispatch back into native code.

> **Languages**: **English** | [简体中文](README.zh-CN.md)

![x64 direct](https://img.shields.io/badge/x64_direct-99.26%25-brightgreen)
![x86 direct](https://img.shields.io/badge/x86_direct-95.15%25-green)
![wvmpTest x86](https://img.shields.io/badge/wvmpTest_x86-85.7%25-yellowgreen)
![main](https://img.shields.io/badge/main-0b6c5ba-blue)
![baseline](https://img.shields.io/badge/baseline-330%2F330-brightgreen)

## Targets

| Architecture | Machine | Status |
|---|---|---|
| **x64 (PE32+)** | 0x8664 | **Production ready** |
| **x86 (PE32)** | 0x14C | **Production ready** (WOW64 verified) |

Native client code paths are unchanged. Marked regions (two consecutive 8-byte markers) are translated to a custom register-based VM (97 ops, jump table 128 entries). Output preserves byte-identical behavior under `byte-exact` verification — see [docs/GAPS.md](docs/GAPS.md) for full support matrix.

## Permanent gate boundaries (documented, not bugs)

WVmp documents certain instruction families as **permanently gated** — regions containing them remain native and produce byte-identical output, but are not virtualized:

| Family | Why permanent |
|---|---|
| **x87 FPU (D8-DF)** | MSVC defaults to SSE for floating-point; x87 only appears in legacy or /arch:IA32 builds. Implementing x87 handlers would consume jump-table slots for vanishingly rare real-world usage. (MIT-418 R3, MIT-445 §6 B-route, MIT-455 B-route closed.) |
| **Indirect jmp (`jmp [mem]`/`jmp reg`)** | Static analyzable "table form" represents < 0.001% of all indirect jumps in System32 / SysWorld32. Dominant forms (arbitrary mem/reg) require L-level runtime analysis. (MIT-455 §3.2 closed as maintenance.) |
| **Stack depth at mul64hi-like boundaries** | x86 stack frame save area is finite. Outer-frame dependencies require forward-looking ESP resync; deferred. |
| **SEH (`fs:[...])` / segment overrides** | Requires cooperation with Windows exception dispatcher; out of scope for current research line. |

For the full picture see [docs/GAPS.md](docs/GAPS.md) §X7 closure and §Gate distribution table.

## Build (Windows / MSVC / Ninja, requires VS 18 Insiders)

```bat
scripts\build.bat
```

First run fetches CMake dependencies (googletest, capstone, keystone, tomlplusplus) into `.deps/` — keystone takes a while.

## Test

```bat
scripts\test.bat
```

## End-to-end smoke test (GitHub reproduction)

The smoke test exercises the entire pipeline: build wvmpTest target, run native, pack with WVmp CLI, run packed, diff outputs.

```bat
:: Clone wvmpTest sibling repo first:
git clone https://github.com/YOUR/wvmpTest ..\wvmpTest

:: From WVmp repo root:
tests\wvmpTest\smoke_test.bat
```

The script auto-detects `..\wvmpTest` by default; override with `set WVMPTEST_DIR=path\to\wvmpTest` if placed elsewhere. Expectation:

- both native and packed return code = 0
- diff line count = 0 (the `image   :` path line is excluded — it embeds an absolute path)
- native SUMMARY shows `passed=94`

See [tests/wvmpTest/](tests/wvmpTest/) for the test target source and build script.

## Coverage (X7 rescan, 2026-09-03)

| Metric | Value |
|---|---|
| **x64 mnemonic-level direct coverage** (System32 103 files / 17.6M clean insns) | **99.26%** |
| **x86 mnemonic-level direct coverage** (SysWOW64 100 files + 3rd-party + extras / 27.4M clean insns) | **95.15%** |
| **x64 function-level no-gate** (.pdata function domain, 240,277 functions) | **94.74%** |
| **wvmpTest x86 truly virtualized** (103 kernels, marked regions) | **12/14 = 85.7%** |

The rescan script lives at [`scripts/verifier/mit_x7_rescan.py`](scripts/verifier/mit_x7_rescan.py) with output in [`scripts/verifier/mit_x7_rescan_out/`](scripts/verifier/mit_x7_rescan_out/) (215-row jsonl + summary.json). It runs in ~4 minutes and is fully reproducible:

```bat
python scripts\verifier\mit_x7_rescan.py
```

For deep context on the methodology (three-layer replacement for unavailable strict function-level coverage on x86, dual-channel consistency assertion) see [docs/GAPS.md](docs/GAPS.md) §X7 closure.

## Multica engineering workflow

WVmp development is driven by [multica](https://github.com/multica-ai/multica) — every capability addition since 2026-08-29 has been a dispatched task with project-owner verification.

**24 tasks ACCEPTED, 0 rejected, 0 cancelled across two milestones:**
- **M2.5-G (instruction virtualization phase)** — MIT-419 through MIT-435, baseline 240/240, complete
- **M2.5-X (multi-target platform phase)** — MIT-436 through MIT-455, baseline 330/330, complete

For the full issue roster, discipline notes, and accumulated lessons see [docs/MULTICA_ISSUES.md](docs/MULTICA_ISSUES.md).

**Raw multica artifacts** (155 files, 451 KB) are packaged separately for archive download: `docs/multica-archive.tar.gz`. This file is not under git (kept out of source tree to keep the repo lean). For ongoing users, the multica dashboard is the authoritative source.

## Project status

| Stage | Status |
|---|---|
| M2.5-G instruction virtualization (x64) | Done (2026-08-31) |
| M2.5-X multi-target platform (x86 production) | Done (2026-09-03) |
| X3d SSE-32 refinement | Data ready, not scheduled |
| `push_mem` x86 (1.845% — first non-x87 shape gate) | Data ready, candidate for next dispatch |
| M3 cryptographic protection line (MIT-410) | Parked, awaiting prioritization |

## Roadmap

Three work streams are queued beyond the current M2.5-G + M2.5-X close-out, ordered by readiness (data → decision → execution).

### Stream 1: `push_mem` x86 (next-dispatch candidate)

**Why first**: smallest blast radius, single-shape gate, highest ROI.

- **Target shape**: `push [mem]` — the largest non-x87 shape gate on x86, affecting **1.845%** of all instructions across **92.9%** of files in the corpus. (Measured at X7, 2026-09-03; revised 3.7× higher than the X0 pre-scan estimate.)
- **Form breakdown** (x86-only, X7 data):
  - `push_mem` is the dominant non-x87 shape gate, dwarfing every other gate (sse_residual 2.41%, indirect_jmp 1.79%, system_legacy 1.35%, push_imm 0.049% — all on x64; on x86 the picture is reversed).
  - The `push_mem` family itself needs further shape-class breakdown before dispatch (memory operand forms: `[reg]`, `[reg+disp]`, `[reg+reg*scale+disp]`, segment overrides). This shape-class breakdown is the data-side prerequisite for Stream 1.
- **Open questions** before dispatch:
  - **Coverage**: would implementing `push_mem` move wvmpTest x86 true-virtualization from 12/14 → ? Need to measure per-shape coverage before sizing.
  - **Stub-link dispatch cost**: how many new entries in the 128-slot jump table are consumed? Current free slots: 31 (97/128). `push_mem` is expected to consume ~3 slots if implemented as a single shape (split for memory operand forms may consume more).
  - **x64 spillover**: should the same handler serve the x64 case for symmetry, or are x86 memory operand encodings different enough to require separate handlers? (Decision deferred to dispatch.)
- **Expected effort**: 1 single-architect dispatch (X6-class), 1-2 days. No cross-arch implications.

### Stream 2: X3d SSE-32 refinement

**Why second**: already partially executed in X6 (32 SSE ops covered), refinement is incremental.

- **Status today**: 32 SSE ops live in x86 handler table (X6, MIT-454). The "32" refers to VmOps in the existing enum that have SSE-form encodings; Cvt/Shuf/Unpck/Sqrt have no VmOp in the frozen enum and route through narrow-bar. (Per GAPS.md §Cvt)
- **What refinement would target**:
  - Memory-aligned SSE moves (`movaps` / `movaps` for unaligned forms) — currently folded into single `VmOp::Movups`; unaligned form correctness not separately verified.
  - SSE comparison flags: `ucomiss` / `ucomisd` produce EFLAGS bits; full-flag carry semantics not separately verified.
  - `cvt*` family (integer↔float / float-precision): no VmOp yet; currently narrow-bar routed.
- **Open questions**:
  - Real corpus frequency: how often do unaligned SSE moves vs `cvt*` appear in the X7 corpus? X0 estimated both as ~0.5% combined; X7 data did not separately enumerate these shapes.
  - Flag-precision vs jump-table-cost tradeoff: implementing flags-correct `cvt*` may consume jump-table slots for marginal corpus benefit.
- **Expected effort**: small/medium, depends on X3d-triage sub-task data; likely 2-3 days if dispatched.

### Stream 3: M3 cryptographic protection line (MIT-410)

**Why third (and currently parked)**: this is the next major research line, not a continuation of M2.5-X. Scope and prerequisites are different.

- **Origin**: parked during W14 (2026-08-29, see `.multica/mit419-ruling.md` line 7 — backreference to "MIT-410 (M3 line)"). F1 (cryptographic obfuscation of marker-pair magic) and F2 (key-bundle in stub dispatch) were sketched as the two product features.
- **Prerequisites before resuming**:
  - **F1 design choice**: cryptographic primitive (AES-NI vs custom S-box vs VM-emulated cipher). Each has different threat-model and performance profiles.
  - **Threat model definition**: who is the adversary? Reverse engineers with debugger? Automated taint analysis? Different models drive different cryptographic choices.
  - **F2 key-bundle distribution**: where do keys live? Per-target embed (current approach for marker magic) vs server-fetched (anti-tamper). Affects offline-vs-online runtime model.
- **Why parked now**: the M2.5-X close-out establishes the protection primitive is robust on the *non-cryptographic* axis (custom VM opcodes). The cryptographic layer is a strict upgrade, not a fix — there's no product bug forcing it. Parked for prioritization, not abandoned.
- **Expected effort**: 5-10 days of design + 2-3 dispatch cycles, depending on F1/F2 split.

### Sequencing principle

The three streams are listed in **readiness order**, not priority order:

1. **`push_mem` x86** — execute side already has all the data; only the dispatch decision blocks.
2. **X3d SSE-32 refinement** — incremental refinement on existing X6 work; reuses X6 baselines.
3. **M3 cryptographic protection line** — new research line; needs design decisions before any data-side work.

If the team receives a new external priority (e.g. a customer requests cryptographic protection), the order can flip — but `push_mem` will remain the next-dispatch candidate by default.

### Out of scope (explicitly deferred)

These are intentionally **not** on the roadmap because they're not aligned with current research direction:

- **Cross-platform (Linux/macOS ELF/Mach-O)** — different toolchains, different calling conventions; would require a separate project line.
- **Anti-debug / anti-VM / anti-DBI hardening** — anti-RE features are a different product layer; not pursued here.
- **GUI / IDE plugin** — CLI-only is intentional.
- **x87 implementation (B-route)** — formally closed at MIT-455 (X7 data: 0 x87-bearing functions in x64 .pdata domain). R-SSE-only is permanent.

## Architecture

```
[PE file]
   ↓ pe_loader
[Parsed image] (PE sections, imports, .pdata/.xdata)
   ↓ marker_scan            ← detect two consecutive 8-byte markers
[Marked regions]
   ↓ lifter                 ← capstone decode → IR
[IR]                       ← frozen carrier domain (ir::Op)
   ↓ virtualize             ← IR → VmOp table (kVmOpMax=97)
[VmOp sequence]
   ↓ stub_link              ← generate stub dispatch entry
[Protected PE]
```

The implementation lives in `vm/regvm/{backend,lifter,translator,runtime}/`, with passes registered in `passes/{pe_loader,marker_scan,lifter,virtualize,stub_link,pe_writer}/` and the CLI in `cli/`.

## Repository layout

```
WVmp/
├── cli/                       # WVmp CLI (protect subcommand)
├── passes/                    # pipeline passes (pe_loader, marker_scan, ...)
├── vm/regvm/                  # VM implementation (lifter, translator, runtime, backend)
├── sdk/include/wvmp/          # public SDK headers
├── docs/
│   ├── STATUS.md              # current authoritative stage status
│   ├── GAPS.md                # full support matrix + X7 closure
│   ├── MULTICA_ISSUES.md      # multica task roster (24 tasks)
│   └── multica-archive.tar.gz # raw multica artifacts (not under git)
├── scripts/
│   ├── build.bat              # MSVC + Ninja build
│   ├── test.bat               # ctest
│   ├── multiseed_e2e.sh       # 5-seed x 66 sample regression
│   └── verifier/
│       └── mit_x7_rescan.py   # client-state coverage scanner
├── tests/wvmpTest/            # 103-kernel functional test target
│   ├── src/                   # test kernels source
│   ├── build.bat              # builds test_target.exe
│   ├── kernels.toml           # WVmp CLI config for the test target
│   └── smoke_test.bat         # end-to-end smoke test entry point
└── LICENSE                    # MIT
```

## License

MIT. See [LICENSE](LICENSE).

## Acknowledgments

The capstone, keystone, googletest, and tomlplusplus projects used as CMake FetchContent dependencies are included under their respective licenses.