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
:: tests/wvmpTest/ lives inside this repo (no external clone needed).
:: Build the test target, then run the smoke test:
cd tests\wvmpTest
call build.bat x64
cd ..\..
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
| M3 protection surface (Streams 1-5 below) | Six streams queued, ready to dispatch (see Roadmap) |
| Extended surface (Streams 7-9 below) | Three streams parked, awaiting trigger (see Roadmap) |
| Product surface (Stream 6 below) | One stream, gated on Streams 1-5 (see Roadmap) |

## Roadmap

Nine capability streams are queued beyond the current M2.5-G + M2.5-X close-out. They are **independent products** of WVmp (not "stages" of M2.5-X) — each has its own scope, prerequisites, and dispatch plan. They are listed in **roadmap order** (data-side → product surface), not priority order.

The five protective passes in `passes/` (`anti_debug`, `crypt`, `integrity_crc`, `import_protect`, `mutate`) and the `vm/regvm/codecs/` module are all registered as placeholders today (per `docs/STATUS.md` "M3 plugin pool ⏳ not started"). Streams 1-5 are how those placeholders become real product. Streams 7-9 extend the protection surface to broader scopes (driver / VM-detection / host-OS surface) and are explicitly parked until external triggers.

### Stream 1: bytecode cryptographic obfuscation

Replaces the placeholder in `passes/crypt/src/crypt_pass.cpp` and implements the placeholder codec interface in `vm/regvm/codecs/`.

- **What it does**: encrypts the VM bytecode stream after virtualization, embeds decrypt metadata into the stub, and decodes on entry. The marker-pair magic and the VM program become inseparable from the runtime decoder.
- **Why first**: smallest blast radius (one pass + one codec module), no cross-pass dependencies, validates the codec/roundtrip contract end-to-end.
- **Open design decisions** (must be locked before dispatch):
  - **Cipher primitive** — AES-NI (fast, recognizable signature) / custom S-box (no signature, slower) / VM-emulated (homomorphic to current protection, slowest).
  - **Key bundle** — per-target embed (current marker-magic approach, offline-runtime) / server-fetched (anti-tamper, online-runtime only).
  - **Threat model** — interactive debugger / automated taint / mass-scanner — different models favor different cipher choices.
- **Effort**: 1 single-architect dispatch, 2-3 days.

### Stream 2: instruction-level code mutation

Replaces the placeholder in `passes/mutate/src/mutate_pass.cpp`.

- **What it does**: rewrites the lifted IR before VM bytecode emission — dead-code insertion, equivalent substitutions, bogus control flow — deterministically from `ctx.seed`. Increases reverse-engineering cost without changing semantics.
- **Why second**: low risk (pure IR transformation, no runtime dependency), builds on the existing frozen IR carrier domain.
- **Open questions**:
  - **Strength/cost tradeoff** — mutation density affects both runtime perf and reverse-engineering difficulty; calibrate to a target ratio.
  - **Determinism** — seed-derived reproducibility is a hard requirement (test baseline stability).
- **Effort**: 1 single-architect dispatch, 2-3 days.

### Stream 3: anti-debug / anti-instrumentation hardening

Replaces the placeholder in `passes/anti_debug/src/anti_debug_pass.cpp`.

- **What it does**: emits anti-debug checks (PEB.BeingDebugged, hardware breakpoints, NtQuery variants, timing attacks) and anti-instrumentation guards (ProcessInstrumentationCallback, debug break-in hooks) into the protected image.
- **Why third**: independent from crypto/mutate, but requires **runtime stub surface** that the current stub_link interface doesn't yet provide. Needs a small stub extension before the pass is meaningful.
- **Open questions**:
  - **User-mode only** vs **user-mode + kernel-mode** — kernel hooks require a separate SYS runtime; current scope is user-mode only.
  - **Anti-DBI strategy** — ProcessInstrumentationCallback is a Windows 10+ feature; XP/Vista coverage requires alternate approach.
- **Effort**: 2 sub-dispatches (stub extension + pass implementation), 3-4 days total.

### Stream 4: import protection (IAT hardening)

Replaces the placeholder in `passes/import_protect/src/import_protect_pass.cpp`.

- **What it does**: rewrites the import directory to route API calls through the protection stub. IAT entries are encrypted, resolved lazily on first call, with per-function keys.
- **Why fourth**: complementary to bytecode crypto (Stream 1) — together they prevent static extraction of both VM program and API call surface. Builds on existing `passes/stub_link/` infrastructure.
- **Open questions**:
  - **Lazy vs eager resolution** — eager is simpler but leaks presence-of-imports; lazy requires runtime decoder in stub.
  - **SDK API separation** — SDK functions (loader-time helpers) need a separate code path from user-imported APIs.
- **Effort**: 1 single-architect dispatch, 2-3 days.

### Stream 5: runtime integrity verification

Replaces the placeholder in `passes/integrity_crc/src/integrity_crc_pass.cpp`.

- **What it does**: computes digests over protected sections at build time, embeds verification data, and runs self-check on load (with anti-tamper response).
- **Why fifth**: closes the loop on tamper detection — even if Streams 1-4 are bypassed, the runtime can detect that the protected image has been modified post-build.
- **Open questions**:
  - **Verification granularity** — whole-section vs per-function vs per-VM-region. Per-region is strongest but increases overhead.
  - **Trigger strategy** — load-time-only / periodic / on-sensitive-call. Each has different performance/tamper-resistance tradeoffs.
- **Effort**: 1 single-architect dispatch, 1-2 days.

### Stream 6: standalone GUI

A new top-level deliverable. CLI is currently the only interface (`cli/src/main.cpp`). Stream 6 adds a standalone GUI on top of the CLI subprocess.

- **What it does**: project management (load/save WVmp project files), region selection visualization, pass-by-pass configuration panels, real-time compile log, code preview with marker highlighting.
- **Why sixth**: depends on Streams 1-5 having real options to configure. A GUI without real pass options is just a CLI wrapper with chrome.
- **Scope decisions** (must be locked before dispatch):
  - **GUI framework** — Qt (industry standard, paid license for commercial use) / wxWidgets (permissive, smaller ecosystem) / Dear ImGui + native window (developer-friendly, less polished). License compatibility with WVmp's MIT license must be checked per choice.
  - **OS targets** — Windows-only first, cross-platform deferred (matches current WVmp scope).
  - **Process model** — GUI is a thin layer that spawns `wvmp_cli.exe` as a subprocess and parses its output. No direct in-process linking to passes/.
- **Effort**: design + skeleton 2-3 days, feature-complete 5-7 days. This is a **single large dispatch** (or two — GUI skeleton + feature wiring), not multi-stream.

### Stream 7: Windows kernel-driver protection

A separate code path with its own SYS runtime. Currently WVmp operates strictly on user-mode PE executables.

- **What it does**: protects `.sys` driver binaries — separate VM runtime that runs at IRQL ≥ DISPATCH_LEVEL, hardened against kernel debugger attach (KdDebuggerEnabled / KdTransportMaxPacketSize), and DriverUnload hook transparency.
- **Status today**: parked, not dispatched.
- **Why parked now**:
  - **Independent SYS runtime** is required (existing user-mode runtime relies on user-mode API surface).
  - **Different testing infrastructure** (kernel verifier, WinDbg kernel-mode, driver loading test harness).
  - **Different threat model** (kernel-mode adversaries: kernel patch protection, PatchGuard, signed-driver bypass).
  - **No current customer pull** for kernel-driver protection.
- **Trigger to un-park** (any one):
  - Customer request specifically for a `.sys` driver protection scenario.
  - Internal decision to enter the driver-protection product line (commercial decision).
  - Adjacent research need (e.g. a new technique that only makes sense in kernel mode).
- **Effort**: 5-10 days of design + 2-3 dispatch cycles (independent of Streams 1-5).

### Stream 8: anti-VM / anti-sandbox detection

Detects whether the protected program is running inside an analysis environment (hypervisor, sandbox, DBI framework).

- **What it does**: emits detection routines for analysis environments — CPUID hypervisor-present bit, firmware-table vendor scanning, sandbox API artifacts, timing-based detection variants. Hooks into the existing `passes/anti_debug/` infrastructure but operates on a different axis.
- **Status today**: partially covered (CPUID vendor scan exists in some protection tooling), not yet dispatched as a focused effort.
- **Why not a standalone stream earlier**:
  - **Partial coverage already exists** in adjacent streams (anti-debug checks, integrity verification); promoting to standalone is incremental, not greenfield.
  - **Heuristic maintenance cost**: VM/sandbox detection signatures churn faster than VM hardening (vendors add evasion to their analysis tooling). Requires ongoing maintenance, not a one-shot dispatch.
  - **False-positive risk**: aggressive VM-detection breaks legitimate users (e.g. users running under Hyper-V, WSL2, or anti-virus sandboxing).
- **Trigger to un-park** (any one):
  - Customer request specifically for "defeat mass-scanner pipelines" (Stream 1 threat-model variant).
  - Compelling real-world evasion event (a major analysis vendor successfully bypasses current protection).
  - Internal decision to harden against a specific adversary class.
- **Effort**: 1-2 design sessions + 1-2 dispatches, ongoing maintenance budget.

### Stream 9: virtual file system / virtual registry

Hook-based re-direction of host-OS file and registry I/O — emulated resources live encrypted inside the protected image.

- **What it does**: rewrites Win32 file/registry API calls (`CreateFile`, `RegOpenKeyEx`, etc.) to route through a custom dispatcher. Resources appear to come from a "virtual" location while actually being decrypted on demand from an embedded bundle.
- **Status today**: parked, not dispatched. No placeholder infrastructure exists for this.
- **Why parked now**:
  - **Host-OS surface, not VM-protect surface** — the protection primitive's value is in the IR→VM-bytecode layer; host-OS surface-level protection is a different product layer.
  - **Requires inline API hook framework** — ntdll/kernel32 hook chains, hook-safety verification, WoW64 split. Significant infrastructure cost.
  - **High maintenance burden** — Windows API surface changes between versions; hook locations shift.
- **Trigger to un-park** (any one):
  - Customer request for "encrypted embedded resources" (commercial product feature).
  - Adjacent need from another stream (e.g. Stream 1 key bundle could naturally extend into a virtual-filesystem key).
  - Internal decision to harden host-OS surface (product-line decision).
- **Effort**: 2-3 weeks of design + 3-4 dispatch cycles. **Note**: this is roughly the same magnitude as all of Streams 1-5 combined — non-trivial commitment.

### Sequencing principle

The nine streams are listed in **roadmap order**, not priority order:

**Active surface (Streams 1-5)**: protective passes for user-mode PE executables.

1. **Stream 1 (crypt)** — execute side has the smallest scope; codec stub validates the roundtrip contract.
2. **Stream 2 (mutate)** — IR-level, no runtime dependency, build on Stream 1's codec if roundtrip shapes overlap.
3. **Stream 3 (anti_debug)** — needs stub surface extension, builds on Stream 1+2's emitter.
4. **Stream 4 (import_protect)** — depends on Stream 1 for lazy resolution codec, builds on `passes/stub_link/`.
5. **Stream 5 (integrity_crc)** — last protective layer, closes the tamper-detection loop.

**Product surface (Stream 6)**: standalone GUI consumes Streams 1-5.

6. **Stream 6 (GUI)** — entirely dependent on Streams 1-5 having real options to expose.

**Extended surface (Streams 7-9)**: parked, requires external trigger.

7. **Stream 7 (kernel-driver)** — independent runtime; customer pull required.
8. **Stream 8 (anti-VM/anti-sandbox)** — partial coverage; requires specific adversary decision.
9. **Stream 9 (virtual FS / virtual registry)** — host-OS surface; non-trivial scope, requires product-line decision.

If the team receives a new external priority (e.g. customer needs anti-debug urgently), Streams 1-5 can be reordered; if a customer pulls on Streams 7-9 specifically, those can jump ahead. Each stream's prerequisites should be respected. Streams 1-5 form the **M3 protection surface**; Stream 6 is the **M3 product surface**; Streams 7-9 form the **extended surface** parked pending external trigger.

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