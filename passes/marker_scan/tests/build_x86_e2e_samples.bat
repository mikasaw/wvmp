@echo off
rem MIT-446 (X4) B.4: build the three x86 E2E first-batch samples (forkface /
rem SSE / callgate) under the vcvarsamd64_x86 cross environment.
rem Usage: build_x86_e2e_samples.bat <output dir>
rem NOTE: batch files must stay ASCII-only (cmd parses them in the OEM
rem codepage; UTF-8 Chinese comments get split into bogus commands).
rem Each sample: ml.exe hand-written region asm (marker stubs, /Od form,
rem MIT-437 recipe) + cl C main + link /MACHINE:X86. A trailing native run
rem (rc=0 sentinel per sample) proves build+run works before the pipeline
rem touches anything (D4: native-green-first discipline, 428 lesson).
setlocal
if "%~1"=="" exit /b 1
rem vswhere is needed by vcvarsamd64_x86.bat (same as build_x86_tests.bat).
set "PATH=C:\Program Files (x86)\Microsoft Visual Studio\Installer;%PATH%"
call "C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvarsamd64_x86.bat" >nul || exit /b 1
pushd "%~1" || exit /b 1

ml /nologo /c /Coff "%~dp0x86_forkface_sample.asm" || goto :fail
cl /nologo /utf-8 /O1 /MD /c "%~dp0x86_forkface_main.c" || goto :fail
link /nologo /SUBSYSTEM:CONSOLE /MACHINE:X86 x86_forkface_main.obj x86_forkface_sample.obj /OUT:"%~1\wvmp_x86_forkface_sample.exe" || goto :fail
.\wvmp_x86_forkface_sample.exe || goto :fail

ml /nologo /c /Coff "%~dp0x86_sse_sample.asm" || goto :fail
cl /nologo /utf-8 /O1 /MD /c "%~dp0x86_sse_main.c" || goto :fail
link /nologo /SUBSYSTEM:CONSOLE /MACHINE:X86 x86_sse_main.obj x86_sse_sample.obj /OUT:"%~1\wvmp_x86_sse_sample.exe" || goto :fail
.\wvmp_x86_sse_sample.exe || goto :fail

ml /nologo /c /Coff "%~dp0x86_callgate_sample.asm" || goto :fail
cl /nologo /utf-8 /O1 /MD /c "%~dp0x86_callgate_main.c" || goto :fail
link /nologo /SUBSYSTEM:CONSOLE /MACHINE:X86 x86_callgate_main.obj x86_callgate_sample.obj /OUT:"%~1\wvmp_x86_callgate_sample.exe" || goto :fail
.\wvmp_x86_callgate_sample.exe || goto :fail

rem ---- MIT-450 (X5) B.1: pool expansion 3 -> 10ish (family matrix) ----

rem (1) deepcall: callgate recursion depth, 32-level native tree in the
rem 0x1000 callee window (x64 406/E1 counterpart, 4B accounting).
ml /nologo /c /Coff "%~dp0x86_deepcall_sample.asm" || goto :fail
cl /nologo /utf-8 /O1 /MD /c "%~dp0x86_deepcall_main.c" || goto :fail
link /nologo /SUBSYSTEM:CONSOLE /MACHINE:X86 x86_deepcall_main.obj x86_deepcall_sample.obj /OUT:"%~1\wvmp_x86_deepcall_sample.exe" || goto :fail
.\wvmp_x86_deepcall_sample.exe || goto :fail

rem (2) jmptbl: 4B jump tables (REG abs / REG delta / MEM abs) + 2 gate
rem negatives (no-defense / out-of-region target), x64 413 counterpart.
ml /nologo /c /Coff "%~dp0x86_jmptbl_sample.asm" || goto :fail
cl /nologo /utf-8 /O1 /MD /c "%~dp0x86_jmptbl_main.c" || goto :fail
link /nologo /SUBSYSTEM:CONSOLE /MACHINE:X86 x86_jmptbl_main.obj x86_jmptbl_sample.obj /OUT:"%~1\wvmp_x86_jmptbl_sample.exe" || goto :fail
.\wvmp_x86_jmptbl_sample.exe || goto :fail

rem (3) strops: dword string family mix (rep movsd aligned+unaligned / stosd /
rem repe cmpsd early-exit / repne scasd / lodsd / plain movsd x2).
ml /nologo /c /Coff "%~dp0x86_strops_sample.asm" || goto :fail
cl /nologo /utf-8 /O1 /MD /c "%~dp0x86_strops_main.c" || goto :fail
link /nologo /SUBSYSTEM:CONSOLE /MACHINE:X86 x86_strops_main.obj x86_strops_sample.obj /OUT:"%~1\wvmp_x86_strops_sample.exe" || goto :fail
.\wvmp_x86_strops_sample.exe || goto :fail

rem (4) bitops: popcnt/tzcnt/lzcnt/bswap/cmpxchg/xadd/bts/btr/btc/xchg
rem REG-REG + a callable mem-dest probe (virtualize or gate, both valid).
ml /nologo /c /Coff "%~dp0x86_bitops_sample.asm" || goto :fail
cl /nologo /utf-8 /O1 /MD /c "%~dp0x86_bitops_main.c" || goto :fail
link /nologo /SUBSYSTEM:CONSOLE /MACHINE:X86 x86_bitops_main.obj x86_bitops_sample.obj /OUT:"%~1\wvmp_x86_bitops_sample.exe" || goto :fail
.\wvmp_x86_bitops_sample.exe || goto :fail

rem (5) looplea: nested loops + complex LEA (base+index*scale+disp) + disp
rem index-scale memory ALU operands.
ml /nologo /c /Coff "%~dp0x86_looplea_sample.asm" || goto :fail
cl /nologo /utf-8 /O1 /MD /c "%~dp0x86_looplea_main.c" || goto :fail
link /nologo /SUBSYSTEM:CONSOLE /MACHINE:X86 x86_looplea_main.obj x86_looplea_sample.obj /OUT:"%~1\wvmp_x86_looplea_sample.exe" || goto :fail
.\wvmp_x86_looplea_sample.exe || goto :fail

rem ---- MIT-450 (X5) B.3: gate E2E negative family (x86 real pipeline) ----

rem (6) x87gate: dedicated R-SSE-only face -- x87-only region (fld/fadd/fmul/
rem fdiv/fstp) gates whole-function native + GP helper (REQUIRE_REAL stub).
ml /nologo /c /Coff "%~dp0x86_x87gate_sample.asm" || goto :fail
cl /nologo /utf-8 /O1 /MD /c "%~dp0x86_x87gate_main.c" || goto :fail
link /nologo /SUBSYSTEM:CONSOLE /MACHINE:X86 x86_x87gate_main.obj x86_x87gate_sample.obj /OUT:"%~1\wvmp_x86_x87gate_sample.exe" || goto :fail
.\wvmp_x86_x87gate_sample.exe || goto :fail

rem (7) sehgate: real MSVC __try/__except function with an in-region fs:[...]
rem TEB read (G1 segment override -> whole-function native gate) + GP helper.
ml /nologo /c /Coff "%~dp0x86_sehgate_sample.asm" || goto :fail
cl /nologo /utf-8 /O1 /MD /c "%~dp0x86_sehgate_main.c" || goto :fail
link /nologo /SUBSYSTEM:CONSOLE /MACHINE:X86 x86_sehgate_main.obj x86_sehgate_sample.obj /OUT:"%~1\wvmp_x86_sehgate_sample.exe" || goto :fail
.\wvmp_x86_sehgate_sample.exe || goto :fail

rem (8) std67gate: std D5 gate (callable, native balance) + 67-prefix gate
rem (address taken, never called) + GP helper.
ml /nologo /c /Coff "%~dp0x86_std67gate_sample.asm" || goto :fail
cl /nologo /utf-8 /O1 /MD /c "%~dp0x86_std67gate_main.c" || goto :fail
link /nologo /SUBSYSTEM:CONSOLE /MACHINE:X86 x86_std67gate_main.obj x86_std67gate_sample.obj /OUT:"%~1\wvmp_x86_std67gate_sample.exe" || goto :fail
.\wvmp_x86_std67gate_sample.exe || goto :fail

popd
exit /b 0
:fail
popd
exit /b 1
