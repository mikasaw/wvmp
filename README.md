# WVmp

A self-researched PE virtual-machine protector. Translates marked regions of x86/x64 Windows executables into a custom register-based VM, with stub-link dispatch back into native code.

> **Languages**: **English** | [简体中文](README.zh-CN.md)

![x64 direct](https://img.shields.io/badge/x64_direct-99.26%25-brightgreen)
![x86 direct](https://img.shields.io/badge/x86_direct-95.15%25-green)
![wvmpTest x86](https://img.shields.io/badge/wvmpTest_x86-85.7%25-yellowgreen)
![baseline](https://img.shields.io/badge/baseline-355%2F355-brightgreen)

## Targets

| Architecture | Machine | Status |
|---|---|---|
| **x64 (PE32+)** | 0x8664 | **Production ready** |
| **x86 (PE32)** | 0x14C | **Production ready** (WOW64 verified) |

Native client code paths are unchanged. Marked regions (two consecutive 8-byte markers) are translated to a custom register-based VM (164 ops, jump table 256 entries). Output preserves byte-identical behavior under `byte-exact` verification — see [docs/GAPS.md](docs/GAPS.md) for full support matrix.

Instruction surface highlights (September 2026): **AVX/VEX.256** — a full ymm data path on x64 (`vmov*` + 18 packed-arithmetic ops, `vzeroupper`/`vzeroall`, on-demand ymm stub sync); **x87 FPU** — virtualized on x86 (L0–L4: load/store, compare, fcmov, transcendentals). Each is architecture-gated on the opposite arch — see Gate boundaries below.

## Gate boundaries (documented, not bugs)

Regions containing gated instructions remain native and produce byte-identical output, but are not virtualized. Gates fall into three classes:

**Architecture gates** (instruction family not meaningful for that arch's codegen):

| Family | Scope | Note |
|---|---|---|
| x87 FPU (D8-DF) | x64 regions | MSVC x64 defaults to SSE; x87 is virtualized on x86 instead (MIT-509/510). |
| ymm / VEX.256 | x86 regions | MSVC x86 has no VEX emission surface (MIT-511). |
| EVEX (0x62 prefix) | both | Not yet lifted. |

**Frequency-gated** (flipping is evidence-driven; tracker MIT-521):

| Family | Trigger to revisit |
|---|---|
| legacy SSE + ymm mixed in one function | Whole function stays native; flip the mixed-protocol support when a real protection sample requires it (MIT-514). |
| `vextractf128`/`vinsertf128` horizontal ops | +2 VmOp bridge; proven present in intrinsic reduction code (MIT-520), enters on the same trigger. |
| VEX-GP BMI2 (`mulx`/`pdep`/`pext`) | Pending the BMI2 minimum-machine product decision; `mulx` CF/ZF non-modification verified on Zen5 (MIT-515). |

**Permanent**:

| Family | Why permanent |
|---|---|
| Indirect jmp (`jmp [mem]`/`jmp reg`) | Statically analyzable "table form" is < 0.001% of all indirect jumps in System32 / SysWOW64; dominant forms require L-level runtime analysis. (MIT-455 §3.2, MIT-494x.) |
| SEH (`fs:[...]`) / segment overrides | Requires cooperation with the Windows exception dispatcher; out of scope for the current research line. |

Historical note: x87 and the mul64hi stack-depth boundary were formerly permanent gates — both have since been resolved (x87 → per-arch virtualization, MIT-509/510; mul64hi → esp-resync lookahead + callee `ret N` scanning, MIT-497/500, x86 22/22 regions virtualized). The current status table lives in [docs/GAPS.md](docs/GAPS.md).

## Configuration (TOML)

Pack-time behavior is configured via TOML: per-function protection levels (`default_level` plus `[[functions]]` rules, MIT-457) and `[avx] require` (default `true`; set `false` to keep AVX-word functions native so packed binaries still run on non-AVX machines, MIT-518).

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

*Snapshot of the 2026-09-03 full rescan. The instruction surface expanded afterwards (x87 on x86, ymm/AVX on x64 — see Gate boundaries), so these runs predate that expansion.*

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

**The same dispatch discipline has run continuously from MIT-419 through MIT-521:**
- **M2.5-G (instruction virtualization phase, x64)** — MIT-419 through MIT-435, baseline 240/240
- **M2.5-X (multi-target platform phase, x86 production)** — MIT-436 through MIT-455, baseline 330/330
- **M3 protection surface (Streams 1–5)** — from MIT-456: all five protective passes shipped v1 plus a hardening wave (config system, TLS-hook init, dr*/RDTSC checks, import ref rewrite)
- **Instruction-surface extension (x87 on x86, ymm/AVX on x64)** — MIT-509 through MIT-521, including two autonomous offline batches (2026-09-14)

[docs/MULTICA_ISSUES.md](docs/MULTICA_ISSUES.md) carries the M2.5-era roster and discipline notes; later waves are documented in [docs/STATUS.md](docs/STATUS.md).

**Raw multica artifacts** (155 files, 451 KB) are packaged separately for archive download: `docs/multica-archive.tar.gz`. This file is not under git (kept out of source tree to keep the repo lean). For ongoing users, the multica dashboard is the authoritative source.

## Project status

| Stage | Status |
|---|---|
| M2.5-G instruction virtualization (x64) | Done (2026-08-31) |
| M2.5-X multi-target platform (x86 production) | Done (2026-09-03) |
| M3 protection surface (Streams 1–5) | **v1 shipped** (2026-09, MIT-456 wave) — see Roadmap |
| Instruction-surface extension (x87 x86 / ymm+AVX x64 / BMI2 memo) | Done (2026-09-14, MIT-509–521) |
| Frequency-gated instruction backlog | Open, sample-driven (mixed SSE+ymm, `vextractf128` bridge, BMI2 contract — MIT-521) |
| Product surface (Stream 6 GUI) | Not started, unblocked by Streams 1–5 |
| Extended surface (Streams 7–9) | Parked pending trigger |

## Roadmap

The nine capability streams were charted after the M2.5-G + M2.5-X close-out as **independent products** of WVmp. **Streams 1–5 shipped v1 in September 2026** (MIT-456 wave): the five protective passes are real, pipeline-wired, and configurable per function. Stream 6 (GUI) and Streams 7–9 remain future work. The currently open backlog is the frequency-gated instruction set listed under Gate boundaries — mixed SSE+ymm protocol, `vextractf128`/`vinsertf128` bridge, and the BMI2 minimum-machine decision — all evidence-driven (MIT-521).

### Stream 1: bytecode cryptographic obfuscation — shipped v1 (MIT-458)

An xor-chain codec encrypts the VM bytecode blob after virtualization; the stub performs one-shot decryption at entry, so the marker magic and the VM program are inseparable from the runtime decoder. Regression-hardened in MIT-462; Stream 5 closes the tamper loop on top of it.

### Stream 2: instruction-level code mutation — shipped v1 (MIT-459)

Seed-deterministic IR-level mutation before bytecode emission. v1 ships Nop insertion; junk-Mov substitution followed under flags-liveness gating (MIT-474, MIT-478/479), keeping mutated streams semantically pinned.

### Stream 3: anti-debug / anti-instrumentation hardening — shipped v1 (MIT-463)

PEB.BeingDebugged + NtGlobalFlag checks with FailFast response (MIT-463), initialized via TLS hook (MIT-465/467); hardware-breakpoint (dr*) and RDTSC timing checks added in MIT-470/471.

### Stream 4: import protection (IAT hardening) — shipped v1 (MIT-466)

Import calls routed through the protection stub, with import reference rewrite (MIT-477).

### Stream 5: runtime integrity verification — shipped v1 (MIT-464)

IEEE CRC32 over each ciphertext stream, stored in a reserved trailer slot; the stub verifies before decryption and FailFasts on mismatch (tamper experiment: one flipped ciphertext byte → deterministic crash, rc=139).

All five passes are wired through the TOML config system (MIT-457): per-function protection levels and pass-specific switches.

### Stream 6: standalone GUI

A new top-level deliverable. CLI is currently the only interface (`cli/src/main.cpp`). Stream 6 adds a standalone GUI on top of the CLI subprocess.

- **What it does**: project management (load/save WVmp project files), region selection visualization, pass-by-pass configuration panels, real-time compile log, code preview with marker highlighting.
- **Why now**: Streams 1–5 shipped real, configurable options (MIT-456+), so a GUI has substance to expose. Without them a GUI is just a CLI wrapper with chrome.
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

### Sequencing

**Current order**:

1. **Frequency-gated instruction backlog** — sample-driven (MIT-521): mixed SSE+ymm protocol flip, `vextractf128`/`vinsertf128` bridge (+2 VmOp), and the BMI2 minimum-machine product decision (technical side unblocked, MIT-515).
2. **Stream 6 (GUI)** — unblocked by the shipped Streams 1–5.
3. **Streams 7–9** — parked on their external triggers, unchanged.

When Streams 1–5 shipped, their internal ordering (crypt → mutate → anti_debug → import_protect → integrity_crc) followed the prerequisite chain; hardening follow-ups then landed per wave. Stream 6 is the **M3 product surface**; Streams 7–9 form the **extended surface** parked pending external trigger.

## Architecture

```
[PE file]
   ↓ pe_loader
[Parsed image] (PE sections, imports, .pdata/.xdata)
   ↓ marker_scan            ← detect two consecutive 8-byte markers
[Marked regions]
   ↓ lifter                 ← capstone decode → IR
[IR]                       ← frozen carrier domain (ir::Op)
   ↓ virtualize             ← IR → VmOp table (kVmOpMax=164)
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
│   ├── MULTICA_ISSUES.md      # multica task roster (M2.5-era; later waves in STATUS.md)
│   └── multica-archive.tar.gz # raw multica artifacts (not under git)
├── scripts/
│   ├── build.bat              # MSVC + Ninja build
│   ├── test.bat               # ctest
│   ├── multiseed_e2e.sh       # 5-seed x 66 sample regression
│   └── verifier/
│       ├── mit_x7_rescan.py       # client-state coverage scanner
│       ├── mit_515_bmi_probe/     # BMI2 (mulx/pdep/pext) hardware probe
│       ├── mit_517_avx_profile/   # AVX/VEX codegen frequency profiler
│       └── dump_handler_xmm_check.py # handler-shape dump gate
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