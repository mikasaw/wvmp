# marker_scan 泳道测试：
#  1) wvmp_marker_sample —— 样例用户程序（静态链接 wvmp::sdk），作为
#     集成测试的真实扫描对象；
#  2) wvmp_marker_scan_tests —— scan_core 纯函数单元测试 + 真实 exe 的
#     pass 集成测试。

# —— 样例用户程序（测试夹具，不是交付物，不套 /W4 /WX）——
add_executable(wvmp_marker_sample sample_main.cpp)
target_link_libraries(wvmp_marker_sample PRIVATE wvmp::sdk)
# 固定 O0：/Ob0 关内联展开；MSVC 后写的 /Od 覆盖 Debug/Release 的优化级别，
# 保证 marker 调用保持 E8 call 形态（O2 尾调用 jmp 为 v1 已知 TODO）。
target_compile_options(wvmp_marker_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
# 关闭增量链接：Debug 默认 /INCREMENTAL 会把 call 引到 ILT thunk（E9 跳板），
# E8 目标不再落在桩窗口内，扫描必然失配。
target_link_options(wvmp_marker_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# —— gtest：单元 + 集成 ——
add_executable(wvmp_marker_scan_tests
    test_scan_core.cpp
    test_marker_scan_pass.cpp
)
target_link_libraries(wvmp_marker_scan_tests PRIVATE
    wvmp_pass_marker_scan # OBJECT 库：传播其 PUBLIC include 并链入对象
    wvmp_pass_pe_loader   # marker_scan 的 run() 消费 PeImage（offset_to_rva），对象需直链
    wvmp::framework
    wvmp::ir
    wvmp::common
    wvmp::sdk   # 仅为了 magic 常量同步性断言（含 sdk 契约头）
    wvmp::gtest
    gtest_main
)
target_compile_definitions(wvmp_marker_scan_tests PRIVATE
    WVMP_MARKER_SAMPLE_EXE="$<TARGET_FILE:wvmp_marker_sample>"
)
wvmp_target_warnings(wvmp_marker_scan_tests)

add_test(NAME marker_scan COMMAND wvmp_marker_scan_tests)

# —— X1a (MIT-437): ml.exe 手编 x86 标记样本（真产物 fixture）——
# 32 位交叉构建（ml.exe + /MACHINE:X86），走 build_x86_marker_sample.bat；
# 环境无 vcvarsamd64_x86.bat 时降级跳过（对应 fixture 测试 #ifdef 关闭）。
# 与 scripts/build.bat 同源约定：本机唯一 VS 目录硬编码。
set(WVMP_VS_DIR "C:/Program Files/Microsoft Visual Studio/18/Insiders")
if(WIN32 AND MSVC AND EXISTS "${WVMP_VS_DIR}/VC/Auxiliary/Build/vcvarsamd64_x86.bat")
    set(WVMP_X86_MARKER_EXE "${CMAKE_CURRENT_BINARY_DIR}/x86_marker_sample.exe")
    add_custom_command(
        OUTPUT "${WVMP_X86_MARKER_EXE}"
        COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/build_x86_marker_sample.bat" "${WVMP_X86_MARKER_EXE}"
        DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/x86_marker_sample.asm"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_marker_main.c"
                "${CMAKE_CURRENT_SOURCE_DIR}/build_x86_marker_sample.bat"
        COMMENT "x86 marker 样本交叉构建 (X1a: ml.exe + /MACHINE:X86)"
        VERBATIM)
    add_custom_target(wvmp_x86_marker_sample ALL DEPENDS "${WVMP_X86_MARKER_EXE}")
    add_dependencies(wvmp_marker_scan_tests wvmp_x86_marker_sample)
    target_compile_definitions(wvmp_marker_scan_tests PRIVATE
        WVMP_X86_MARKER_SAMPLE_EXE="${WVMP_X86_MARKER_EXE}"
    )
endif()

# —— X4 (MIT-446): x86 E2E 首批三样本（族级：整数+控制流 / SSE 面 / 混合+
# cdecl callgate 参数窗）——32 位交叉构建（build_x86_e2e_samples.bat，
# ml.exe + /MACHINE:X86，437 配方），产物落 build/x86_samples/（multiseed
# x86_samples 池约定路径）。含 native rc=0 哨兵（D4 native 全绿先，428 教训）。
# 环境无 vcvarsamd64_x86.bat 时降级跳过（池条目按文件缺失计数，不误伤）。
if(WIN32 AND MSVC AND EXISTS "${WVMP_VS_DIR}/VC/Auxiliary/Build/vcvarsamd64_x86.bat")
    set(WVMP_X86_E2E_SAMPLE_DIR "${CMAKE_BINARY_DIR}/x86_samples")
    file(MAKE_DIRECTORY "${WVMP_X86_E2E_SAMPLE_DIR}")
    add_custom_command(
        OUTPUT "${WVMP_X86_E2E_SAMPLE_DIR}/wvmp_x86_callgate_sample.exe"
        COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/build_x86_e2e_samples.bat" "${WVMP_X86_E2E_SAMPLE_DIR}"
        DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/x86_forkface_sample.asm"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_forkface_main.c"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_sse_sample.asm"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_sse_main.c"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_callgate_sample.asm"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_callgate_main.c"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_deepcall_sample.asm"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_deepcall_main.c"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_jmptbl_sample.asm"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_jmptbl_main.c"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_strops_sample.asm"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_strops_main.c"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_bitops_sample.asm"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_bitops_main.c"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_looplea_sample.asm"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_looplea_main.c"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_x87gate_sample.asm"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_x87gate_main.c"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_sehgate_sample.asm"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_sehgate_main.c"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_std67gate_sample.asm"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_std67gate_main.c"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_pushform_sample.asm"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_pushform_main.c"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_guardover_sample.asm"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_guardover_main.c"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_pushimm_sample.asm"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_pushimm_main.c"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_pushmem_sample.asm"
                "${CMAKE_CURRENT_SOURCE_DIR}/x86_pushmem_main.c"
                "${CMAKE_CURRENT_SOURCE_DIR}/build_x86_e2e_samples.bat"
        COMMENT "x86 E2E 首批三样本交叉构建 (X4: ml.exe + /MACHINE:X86 -> build/x86_samples)"
        VERBATIM)
    add_custom_target(wvmp_x86_e2e_samples ALL
        DEPENDS "${WVMP_X86_E2E_SAMPLE_DIR}/wvmp_x86_callgate_sample.exe")
endif()

# M2-4：端到端虚拟化样例（区域仅含白名单指令）。
add_executable(wvmp_virt_sample virtual_sample_main.cpp)
target_link_libraries(wvmp_virt_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_virt_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_virt_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-243：端到端正路径样本——区域内**无 loop、无条件跳转、无 rip-relative**，
# 完全白名单直算，验证 C1 保守拦截未误杀可虚拟化区域。
add_executable(wvmp_whitelist_sample whitelist_sample_main.cpp)
target_link_libraries(wvmp_whitelist_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_whitelist_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_whitelist_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-244：端到端正路径样本——区域内含 sar（白名单内），验证 C2-Sar 修复后
# 翻译成功、运行时走真 Sar handler、行为与原生逐字节一致。
add_executable(wvmp_sar_sample sar_sample_main.cpp)
target_link_libraries(wvmp_sar_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_sar_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_sar_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-245：端到端正路径样本——区域内含 adc（白名单内），验证 C2-Adc 修复后
# CF_in 链路正确传播（add 留下的 carry 必须被 adc 看到）。用 _addcarry_u64
# 强制编译器 emit `add` + `adc` 两条指令, 均落在 marker 区域内。
add_executable(wvmp_adc_sample adc_sample_main.cpp)
target_link_libraries(wvmp_adc_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_adc_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_adc_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-246：端到端正路径样本——区域内含 sbb（白名单内），验证 C2-Sbb 修复后
# CF_in 链路正确传播（sub 留下的 borrow 必须被 sbb 看到）。用 _subborrow_u64
# 强制编译器 emit `sub` + `sbb` 两条指令, 均落在 marker 区域内。
add_executable(wvmp_sbb_sample sbb_sample_main.cpp)
target_link_libraries(wvmp_sbb_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_sbb_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_sbb_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-247：端到端正路径样本——区域内含 rol/ror（白名单内），验证 C2-Rol/Ror
# 修复后翻译成功、运行时走真 Rol/Ror handler、行为与原生逐字节一致。用 MSVC
# _rotl64 / _rotr64 内部函数在 /Od 下强制 codegen 为真 `rol` / `ror` 指令。
add_executable(wvmp_rol_sample rol_sample_main.cpp)
target_link_libraries(wvmp_rol_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_rol_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_rol_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-248：端到端正路径样本——区域内含 rip-relative 真实全局读写 (mov/add/
# mov [rip+g_counter])，验证 C4 修复后翻译期 [rip+disp] 转 RVA、运行时
# + image_base 还原 VA、保护后行为与原生逐字节一致。区域**完整可虚拟化**
# (除上述 ALU/Mov 仅 ret，不触发 C1 gate).
add_executable(wvmp_rip_relative_sample rip_relative_sample_main.cpp)
target_link_libraries(wvmp_rip_relative_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_rip_relative_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_rip_relative_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-248: 简化调试样本——单条 [rip+disp] load, 无 spill 栈操作.
add_executable(wvmp_rip_relative_simple_sample rip_relative_simple_main.cpp)
target_link_libraries(wvmp_rip_relative_simple_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_rip_relative_simple_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_rip_relative_simple_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-249: 端到端正路径样本——标记函数 f1 通过 call gate 调到未标记的
# native helper，验证 CallGate 路径通畅（直接 call → emit CallGate →
# 运行时切 rsp 跑 native → ret → RAX 写回 → 继续 dispatch）。helper 是
# 普通 native 函数（非标记），callee 非 stub → call gate 走 native 主路径。
add_executable(wvmp_call_gate_sample call_gate_sample_main.cpp)
target_link_libraries(wvmp_call_gate_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_call_gate_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_call_gate_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-249: 极简调试样本——不含 rip-relative 全局访存，单独验证 CallGate 路径.
add_executable(wvmp_call_gate_simple_sample call_gate_simple_main.cpp)
target_link_libraries(wvmp_call_gate_simple_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_call_gate_simple_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_call_gate_simple_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-249 follow-up (issue-09): 验证 C1 gate 兜底——marker 区域含 cpuid
# (Unsupported, 0F A2), lifter 跳过累积到 LiftMetadata.skipped_ranges,
# backend 见 note → virtualize 放弃虚拟化 → 整函数保持原生执行。
# stdout 为 vendor_class=0/1/2/3 之一, 与原生完全一致。
add_executable(wvmp_lifter_skip_sample lifter_skip_sample_main.cpp)
target_link_libraries(wvmp_lifter_skip_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_lifter_skip_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_lifter_skip_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-300: 端到端真实用例样本——贪吃蛇游戏核心逻辑被 WVMP 保护,
# 验证 WVmp 当前实现能保护真实业务 PE (含 call gate / 多 seed 健壮性).
# 区域内只用白名单 + call gate 整数 ABI, 不调 printf / rand / Sleep.
add_executable(wvmp_snake_sample snake_sample_main.cpp)
target_link_libraries(wvmp_snake_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_snake_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_snake_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-301: 端到端正路径样本——区域内含 cl 变体 shift (D3 /5: shl/shr/sar/
# rol/ror), 验证 cl 变体 shift 修复后翻译成功、运行时走真 ShlCl/ShrCl/
# SarCl/RolCl/RorCl handler、行为与原生逐字节一致。用 volatile uint8_t
# 计数强制 MSVC /Od 下 _rotl64 / _rotr64 codegen 为 cl 变体（D3 /5）而非
# imm 形式 (C1 /r ib)。
# MIT-349: 区域内增加 popcnt 32-bit + 64-bit REG-REG 形式。MSVC __popcnt 内部函数
# 在 /Od 下 emit `popcnt reg, [rsp+disp]` MEM 形式 (派活单限定不支持 MEM form),
# 故 popcnt 字节由 cl_shift_sample_asm.asm (MASM) 直接 emit, 链接进本 sample.
enable_language(ASM_MASM)
add_executable(wvmp_cl_shift_sample
    cl_shift_sample_main.cpp
    cl_shift_sample_asm.asm
)
target_link_libraries(wvmp_cl_shift_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_cl_shift_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_cl_shift_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-302: 端到端正路径样本——区域内含 imul 3 形式 (3-op imm / 2-op reg /
# 1-op F7/5)，验证 imul/mul 修复后翻译成功、运行时走真 Imul/Mul handler、
# 行为与原生逐字节一致。用 volatile int64_t 计乘数避免 MSVC 常量折叠把
# 乘法挪出 marker 区域，区域不含 rip-relative / printf 调用。
add_executable(wvmp_imul_sample imul_sample_main.cpp)
target_link_libraries(wvmp_imul_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_imul_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_imul_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-333: 端到端正路径样本——区域内含 bswap (32-bit / 64-bit)，验证 bswap
# 修复后翻译成功、运行时走真 Bswap handler、行为与原生逐字节一致。用
# _byteswap_ulong / _byteswap_uint64 强制 MSVC /Od 下 codegen 为真 `bswap eax`
# / `bswap rax` 指令 (非 REX.W → S32, REX.W → S64)，区域不含 rip-relative /
# printf / call。
add_executable(wvmp_bswap_sample bswap_sample_main.cpp)
target_link_libraries(wvmp_bswap_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_bswap_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_bswap_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-334: 端到端正路径样本——区域内含 xchg (REG-REG 32-bit / 64-bit)，
# 验证 xchg 修复后翻译成功、运行时走真 Xchg handler、行为与原生逐字节一致。
# MSVC x64 不支持 inline asm, std::swap 等高 level C++ 全部编译成
# mov+mov+mov, 不出 xchg. 真 xchg 字节由 xchg_helper.asm (MASM) 直接
# emit, 链接进本 sample. 区域不含 rip-relative / printf / call（printf 在
# main 区域外）。
enable_language(ASM_MASM)
add_executable(wvmp_xchg_sample
    xchg_sample_main.cpp
    xchg_helper.asm
)
target_link_libraries(wvmp_xchg_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_xchg_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_xchg_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-336: 端到端正路径样本——区域内含 setcc (REG-REG, 6 variants: setne/sete/
# setb/seta/setl/setg), 验证 setcc 修复后翻译成功、运行时走真 Setcc handler、
# 行为与原生逐字节一致。
# MSVC x64 不支持 inline asm, setcc 字节由 setcc_sample_asm.asm (MASM) 直接
# emit, 链接进本 sample. 区域不含 rip-relative / printf / call（printf 在
# main 区域外）。
add_executable(wvmp_setcc_sample
    setcc_sample_main.cpp
    setcc_sample_asm.asm
)
target_link_libraries(wvmp_setcc_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_setcc_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_setcc_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-339: 端到端正路径样本——区域内含 cmovcc (REG-REG, 6 variants: cmove/cmovne/
# cmovb/cmovg/cmovl/cmovge), 验证 cmovcc 修复后翻译成功、运行时走真 Cmovcc handler、
# 行为与原生逐字节一致。
# MSVC x64 不支持 inline asm, cmovcc 字节由 cmovcc_sample_asm.asm (MASM) 直接
# emit, 链接进本 sample. 区域不含 rip-relative / printf / call（printf 在
# main 区域外）。
add_executable(wvmp_cmovcc_sample
    cmovcc_sample_main.cpp
    cmovcc_sample_asm.asm
)
target_link_libraries(wvmp_cmovcc_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_cmovcc_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_cmovcc_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-341: 端到端正路径样本——区域内含 cmpxchg (REG-REG S32/S64), 验证
# cmpxchg 修复后翻译成功、运行时走真 Cmpxchg handler、行为与原生逐字节一致。
# MSVC x64 不支持 inline asm, cmpxchg 字节由 cmpxchg_sample_asm.asm (MASM)
# 直接 emit, 链接进本 sample. 区域不含 rip-relative / printf / call (printf 在
# main 区域外)。覆盖 equal (S32/S64) + not-equal (S32/S64) 两种 cmpxchg 语义。
add_executable(wvmp_cmpxchg_sample
    cmpxchg_sample_main.cpp
    cmpxchg_sample_asm.asm
)
target_link_libraries(wvmp_cmpxchg_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_cmpxchg_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_cmpxchg_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-371: 端到端正路径样本——区域内含 SSE 浮点加 addss/addps/addpd
# (3 形式 REG-REG only), 验证 SSE 浮点加修复后翻译成功、运行时走真 Addss/
# Addps/Addpd handler、行为与原生逐字节一致。MSVC x64 不支持 inline asm,
# 高 level C++ 在 /Od 下对 _mm_add_ss/_mm_add_ps/_mm_add_pd 内部函数会**融合
# load+add 为 MEM 形式**, 故 SSE 字节由 sse_add_sample_asm.asm (MASM)
# 直接 emit 真 REG-REG addss/addps/addpd 字节（F3 0F 58 / 0F 58 / 66 0F 58,
# mod=11）, 链接进本 sample。区域不含 rip-relative / printf / call
# (printf 在 main 区域外)。
enable_language(ASM_MASM)
add_executable(wvmp_sse_add_sample
    sse_add_sample_main.cpp
    sse_add_sample_asm.asm
)
target_link_libraries(wvmp_sse_add_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_sse_add_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_sse_add_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-373: 端到端正路径样本——区域内含 SSE 浮点减 subss/subps/subpd
# (3 形式 REG-REG only), 验证 SSE 浮点减支持后翻译成功、运行时走真 Subss/
# Subps/Subpd handler、行为与原生逐字节一致。MSVC x64 不支持 inline asm,
# 高 level C++ 在 /Od 下对 _mm_sub_ss/_mm_sub_ps/_mm_sub_pd 内部函数会**融合
# load+sub 为 MEM 形式**, 故 SSE 字节由 sse_sub_sample_asm.asm (MASM)
# 直接 emit 真 REG-REG subss/subps/subpd 字节（F3 0F 5C / 0F 5C / 66 0F 5C,
# mod=11）, 链接进本 sample。区域不含 rip-relative / printf / call
# (printf 在 main 区域外)。
enable_language(ASM_MASM)
add_executable(wvmp_sse_sub_sample
    sse_sub_sample_main.cpp
    sse_sub_sample_asm.asm
)
target_link_libraries(wvmp_sse_sub_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_sse_sub_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_sse_sub_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-389: 影子样本——subss 的 ctx.xmm 运行时读回断言 (WVmpVerifier 验收门 A.2)。
# 与 wvmp_sse_sub_sample 的 sse_subss 同 IR 配对, 额外把 ctx.xmm 槽位经 stub
# 恢复路径的可见出口 (返回值 + 区域后原生 store) 全量打印: 返回值 = HALT 时
# ctx.xmm[dst] 读回; 未触碰槽位必须保持 VM 入口同步值。native vs virtualized
# byte-exact; handler 空转 (写错槽) 时读回 = 入口旧值, 与原生不一致 → FAIL。
# 后续 SSE/VMX/AVX 派活单沿用此模式: 每条新指令 1 个影子样本 1:1 配对。
enable_language(ASM_MASM)
add_executable(wvmp_sse_subss_xmm_readback_sample
    sse_subss_xmm_readback_sample_main.cpp
    sse_subss_xmm_readback_sample_asm.asm
)
target_link_libraries(wvmp_sse_subss_xmm_readback_sample PRIVATE wvmp::sdk)
# COMPILE_LANGUAGE 限定 C/C++: 兄弟样本块直接 $<$<CXX_COMPILER_ID:MSVC>:...>
# 会把 C++ 选项也传给 MASM (A4018 invalid command-line option), 本目标收敛。
target_compile_options(wvmp_sse_subss_xmm_readback_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_sse_subss_xmm_readback_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-374: 端到端正路径样本——区域内含 SSE 浮点除 divss/divps/divpd
# (3 形式 REG-REG only), 验证 SSE 浮点除支持后翻译成功、运行时走真 Divss/
# Divps/Divpd handler、行为与原生逐字节一致。MSVC x64 不支持 inline asm,
# 高 level C++ 在 /Od 下对 _mm_div_ss/_mm_div_ps/_mm_div_pd 内部函数会**融合
# load+div 为 MEM 形式**, 故 SSE 字节由 sse_div_sample_asm.asm (MASM)
# 直接 emit 真 REG-REG divss/divps/divpd 字节（F3 0F 5E / 0F 5E / 66 0F 5E,
# mod=11）, 链接进本 sample。区域不含 rip-relative / printf / call
# (printf 在 main 区域外)。
enable_language(ASM_MASM)
add_executable(wvmp_sse_div_sample
    sse_div_sample_main.cpp
    sse_div_sample_asm.asm
)
target_link_libraries(wvmp_sse_div_sample PRIVATE wvmp::sdk)
# COMPILE_LANGUAGE 限定 C/C++: 避免 C++ 选项传给 MASM (A4018), 同 MIT-389 块。
target_compile_options(wvmp_sse_div_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_sse_div_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-374: 影子样本——divss 的 ctx.xmm 运行时读回断言 (WVmpVerifier 验收门 A.2,
# 沿用 MIT-389 subss 影子样本模式)。与 wvmp_sse_div_sample 的 sse_divss 同 IR
# 配对, 额外把 ctx.xmm 槽位经 stub 恢复路径的可见出口 (返回值 + 区域后原生
# store) 全量打印: 返回值 = HALT 时 ctx.xmm[dst] 读回; 未触碰槽位必须保持 VM
# 入口同步值。native vs virtualized byte-exact; handler 空转 (写错槽) 时读回 =
# 入口旧值, 与原生不一致 → FAIL。
enable_language(ASM_MASM)
add_executable(wvmp_sse_divss_xmm_readback_sample
    sse_divss_xmm_readback_sample_main.cpp
    sse_divss_xmm_readback_sample_asm.asm
)
target_link_libraries(wvmp_sse_divss_xmm_readback_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_sse_divss_xmm_readback_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_sse_divss_xmm_readback_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-375: 端到端主样本——区域内含 SSE 浮点传送 movss/movaps/movapd/movups/movupd
# (5 形式 REG-REG load only), 验证浮点传送支持后翻译成功、运行时走真 Movss/
# Movaps/Movapd/Movups/Movupd handler、行为与原生逐字节一致。MSVC x64 不支持
# inline asm, /Od 下 _mm_move_ss/_mm_load_ps/_mm_load_pd 内部函数会**融合
# load+mov 为 MEM 形式**, 故 SSE 字节由 sse_mov_sample_asm.asm (MASM) 直接 emit
# 真 REG-REG 字节 (F3 0F 10 / 0F 28 / 66 0F 28 / 0F 10 / 66 0F 10, mod=11),
# 链接进本 sample。dst/src 槽刻意分散到 xmm0..xmm7 (非 0 槽才暴露 ctx.xmm 偏移
# 公式错), dst 预置一律 != src (mov 类空转判别)。区域不含 rip-relative / printf /
# call (printf 在 main 区域外)。
enable_language(ASM_MASM)
add_executable(wvmp_sse_mov_sample
    sse_mov_sample_main.cpp
    sse_mov_sample_asm.asm
)
target_link_libraries(wvmp_sse_mov_sample PRIVATE wvmp::sdk)
# COMPILE_LANGUAGE 限定 C/C++: 兄弟样本块直接把 C++ 选项也传给 MASM 会 A4018。
target_compile_options(wvmp_sse_mov_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_sse_mov_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-375: 影子样本——SSE 浮点传送 5 条的 ctx.xmm 运行时读回断言 (验收门 A.2 模式)。
# 与 wvmp_sse_mov_sample 同 IR、独立 exe: 每次调用把 VmContext.xmm[0..7] 全 8 槽
# × 4 lane 的 32-bit 原始位图案打印出来。mov 类指令"handler 空转 → 输出=输入"的
# 假阳性在此不成立: dst 槽预置 != src, 空转/写错槽 → 读回 = 入口旧值 (且 src/其他
# 槽状态与原生不符) → native vs virtualized byte-exact 比对 FAIL。
enable_language(ASM_MASM)
add_executable(wvmp_sse_movss_xmm_readback_sample
    sse_movss_xmm_readback_sample_main.cpp
    sse_movss_xmm_readback_sample_asm.asm
)
target_link_libraries(wvmp_sse_movss_xmm_readback_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_sse_movss_xmm_readback_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_sse_movss_xmm_readback_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-376: 端到端主样本——区域内含 SSE 浮点位运算 xorps/orps/andps + 浮点比较
# ucomiss/ucomisd (5 形式 REG-REG only), 验证 5 条新指令支持后翻译成功、运行时
# 走真 Xorps/Orps/Andps/Ucomiss/Ucomisd handler、行为与原生逐字节一致。MSVC x64
# 不支持 inline asm, /Od 下 intrinsic 会融合 load+op 为 MEM 形式, 故 SSE 字节由
# sse_bwcmp_sample_asm.asm (MASM) 直接 emit 真 REG-REG 字节 (0F 57 / 0F 56 /
# 0F 54 / 0F 2E / 66 0F 2E, mod=11), 链接进本 sample。比较类断言 ucomiss 后
# 紧跟 seta 且 seta/movzx/store 都在 marker 区域内 (Setcc handler 读 Ucomiss
# handler 写的 VM flags 槽, 证明 flags 真参与运行时, 派活单 §C 6)。区域不含
# rip-relative / printf / call (printf 在 main 区域外)。
enable_language(ASM_MASM)
add_executable(wvmp_sse_bwcmp_sample
    sse_bwcmp_sample_main.cpp
    sse_bwcmp_sample_asm.asm
)
target_link_libraries(wvmp_sse_bwcmp_sample PRIVATE wvmp::sdk)
# COMPILE_LANGUAGE 限定 C/C++: 兄弟样本块直接把 C++ 选项也传给 MASM 会 A4018。
target_compile_options(wvmp_sse_bwcmp_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_sse_bwcmp_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-376: 影子样本——ucomiss+seta 组合的 flags readback 断言 (派活单 §D D2.1:
# SSE 类新指令族必须配 1 个 ctx.xmm/flags 读回影子样本 1:1 配对; ucomis* 的
# 正确性在 VM flags 槽而非 xmm 槽)。与 wvmp_sse_bwcmp_sample 的 ucomiss+seta
# 同 IR、独立 exe: 每个探针打印区域内 seta 结果 (Setcc handler 读 Ucomiss
# handler 写的 VM flags 槽, greater/less/equal/unordered 四态覆盖 SDM 真值表
# ZF/CF 全组合) + 8 槽 × 4 lane ctx.xmm 全量读回 (证明 handler 不污染任何
# xmm 槽)。native vs virtualized byte-exact; handler 空转 (pitfall #79) →
# seta 读 dispatch 残留 flags / 槽污染 → 与原生不一致 → FAIL。
enable_language(ASM_MASM)
add_executable(wvmp_sse_bwcmpss_flags_readback_sample
    sse_bwcmpss_flags_readback_sample_main.cpp
    sse_bwcmpss_flags_readback_sample_asm.asm
)
target_link_libraries(wvmp_sse_bwcmpss_flags_readback_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_sse_bwcmpss_flags_readback_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_sse_bwcmpss_flags_readback_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-408 (C4b): 端到端主样本——SSE 指令族 memory 形式 (含 rip-relative 全局
# 访问) 真虚拟化。**纯 C++ /Od, 不用 MASM**: MSVC 对全局浮点/数组天然 emit
# mem 形式 (movsd xmm,[rip+g] / addsd xmm,[rip+c] / movsd [rcx+rax],xmm /
# movaps [rsp+disp],xmm / movups 非对齐), 区域内全部是真 mem 形式 SSE 字节
# (派活单 §A.3 读/写两类 + D4 ucomisd + D2 对齐/非对齐两组)。值打印 %g
# byte-exact; 对齐与非对齐全局输出一致即证明运行时 movups 非对齐语义。
add_executable(wvmp_sse_rip_sample
    sse_rip_sample_main.cpp
)
target_link_libraries(wvmp_sse_rip_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_sse_rip_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_sse_rip_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-408 (C4b): 影子样本——SSE mem 原语 (XmmLoad/XmmStore/ALU-mem GP 双槽
# 折条) 的 ctx.xmm 运行时读回断言 (验收门 #79 纪律: byte-exact 对 SSE 写
# GPR 槽形态不可见)。与 wvmp_sse_rip_sample 同能力面配对、独立 exe: 区域
# 由 MASM 直写 5 条 mem 形式 (movups 读/写 + addps mem 源 + movsd 读/写),
# 区域外把 xmm 槽 128-bit 状态全部打出 (%a / %016llx 逐位可比对): 槽位
# 落点错 (写 GPR 区)、宽度截断 (movss 替 movups)、movsd 清零语义缺失都会
# 与 native run 逐字节不一致 → FAIL。
enable_language(ASM_MASM)
add_executable(wvmp_sse_rip_xmm_readback_sample
    sse_rip_xmm_readback_sample_main.cpp
    sse_rip_xmm_readback_sample_asm.asm
)
target_link_libraries(wvmp_sse_rip_xmm_readback_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_sse_rip_xmm_readback_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_sse_rip_xmm_readback_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-404: 端到端主样本——区域内含整数除法族 cdq/cdqe/cqo + div/idiv
# (REG + MEM + rip 形式除数, 32/64 位), 验证整数除法支持后翻译成功、运行时
# 走真 Cdq/Div/Idiv handler、行为与原生逐字节一致 (商/余/负数组合值正确)。
# MSVC x64 不支持 inline asm, C++ volatile 除法只能产 cdq+idiv MEM 形式 —
# REG 形式 / cdqe / rip 除数由 div_sample_asm.asm (MASM) 直接 emit, 链接进
# 本 sample。主函数末尾 div_zero_crash (C++ volatile, cdq+idiv [rsp+..] MEM)
# 除零 → 真 #DE native 直通 (D2.1) — native 与 packed 同为 0xC0000094 形态
# 崩溃 (AC #5 除零对拍), printf+fflush 之后触发。区域不含 printf / call
# (printf 在 main 区域外)。
enable_language(ASM_MASM)
add_executable(wvmp_div_sample
    div_sample_main.cpp
    div_sample_asm.asm
)
target_link_libraries(wvmp_div_sample PRIVATE wvmp::sdk)
# COMPILE_LANGUAGE 限定 C/C++: C++ 选项传给 MASM 会 A4018, 同 MIT-389 块。
target_compile_options(wvmp_div_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_div_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-404: 影子样本——div/idiv 的 Rax/Rdx 双槽 + flags 运行时读回断言
# (对齐 MIT-376 bwcmpss flags readback 影子模式, 派活单 §B.6 / §C D4.1)。
# 与 wvmp_div_sample 同 IR 族、独立 exe: 每个探针打印 商/余双槽 + setz/setc/
# seto/sets/setp 五 flags 探针 (Setcc handler 读 Div/Idiv handler flags_tail
# 写的 VM flags 槽; flags 按 Intel undefined, 但 VM 与 native 同 CPU 同指令
# → 真值逐位一致)。handler 空转/写错槽 → 与原生不一致 → FAIL。ctx.xmm 无关。
enable_language(ASM_MASM)
add_executable(wvmp_div_flags_readback_sample
    div_flags_readback_sample_main.cpp
    div_flags_readback_sample_asm.asm
)
target_link_libraries(wvmp_div_flags_readback_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_div_flags_readback_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_div_flags_readback_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-406 (MIT-E1): 深 call 递归链样本——callgate callee 专用栈窗口的预算
# 边界覆盖。deep_recurse 16 层 x 0x60B = 0x600B 静态可核算树深 (>=0x400B,
# 派活单 §B.6), 旧 0x1D8 预算下修复前必砸穿 VmContext (反证, 验收 #8),
# 修复后树在 host_rsp 下方 0x1000 窗口内生长。递归本体 MASM 直写 (帧深
# 静态可控, C++ /Od 帧布局不可核算), 标记区域在 deepcall_entry (asm)。
enable_language(ASM_MASM)
add_executable(wvmp_deepcall_sample
    deepcall_sample_main.cpp
    deepcall_sample_asm.asm
)
target_link_libraries(wvmp_deepcall_sample PRIVATE wvmp::sdk)
# COMPILE_LANGUAGE 限定 C/C++: C++ 选项传给 MASM 会 A4018, 同 MIT-389 块。
target_compile_options(wvmp_deepcall_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_deepcall_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-406 (MIT-E1): 组合形态样本——区域内 div/idiv (MIT-404 商余双槽路径)
# 与深 call (0x480B 树深) 共存, 验证窗口切换与除法防护互不干扰 (派活单
# §B.7 / §C D4.1)。递归本体复用 deepcall_sample_asm.asm。
enable_language(ASM_MASM)
add_executable(wvmp_deepcall_div_sample
    deepcall_div_sample_main.cpp
    deepcall_sample_asm.asm
)
target_link_libraries(wvmp_deepcall_div_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_deepcall_div_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_deepcall_div_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-407 (MIT-D2): ExitNative 正样本——越区跳转单向退出两类形态 (END-call
# 等价退出 + 早返回 jcc 退出)。两函数须被虚拟化 (REQUIRE_REAL ≥1 stub) 且
# packed 与 native stdout+rc 逐字节一致。/Od 保持标记结构确定（goto/return
# 的越区目标在 /Od 下同样成型）。
add_executable(wvmp_exitnative_pos_sample
    wvmp_exitnative_pos_sample_main.cpp
)
target_link_libraries(wvmp_exitnative_pos_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_exitnative_pos_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_exitnative_pos_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-407 (MIT-D2): ExitNative 反例样本——回跳形态 (C, walker 检出→gate) +
# 超界形态 (MASM, 跨 .pdata 界 jmp→gate)。两函数都不得虚拟化, gate 后
# packed 与 native 逐字节一致。不进 REQUIRE_REAL multiseed（无 stub 属
# 预期），由 e2e.sh + 保护日志 gate note 双通道验证。
enable_language(ASM_MASM)
add_executable(wvmp_exitnative_neg_sample
    wvmp_exitnative_neg_sample_main.cpp
    wv_exitnative_neg_sample_asm.asm
)
target_link_libraries(wvmp_exitnative_neg_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_exitnative_neg_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_exitnative_neg_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-409 (MIT-A6): 跳转表样本——正/负双形态单 exe。正样本 wv_switch8:
# switch 8 路 + default + 边界 (idx 越界走 default), MSVC 稠密 case 恒产
# 四件套跳转表, 翻译期读表静态展开 (比较链, 零新 VmOp) → 真虚拟化
# (REQUIRE_REAL ≥1 stub)。负样本 wv_opaque_jmp_masm (MASM): 区域含
# `mov rax,[g_fp]; jmp rax` opaque 间接跳转 → 照旧 C1 gate, packed 与
# native 逐字节一致。jump-table 命中证据 = 保护日志 "jump-table @ ..."
# note; 负样本 gate = 保护日志 "间接 jmp 未支持" note。
enable_language(ASM_MASM)
add_executable(wvmp_jmp_table_sample
    jmp_table_sample_main.cpp
    jmp_table_sample_asm.asm
)
target_link_libraries(wvmp_jmp_table_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_jmp_table_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_jmp_table_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-413 (G2): 跳转表残余形态样本——5 正 (REQUIRE_REAL 真虚拟化) + 3 负例
# (gate) 单 exe, MASM 手拼字节形态 (clang/GCC 本机不存在, 派活单 §F.1):
#   ① wv_jt8_abs    REG 源 8B 绝对表 (无 add, 表项=完整 VA, 翻译期减
#                    image_base 还原 RVA)
#   ② wv_jt8_delta  REG 源 8B delta 表 (带 add, 表项=case−表基址, 负值
#                    两补码 8B signed)
#   ③ wv_jt8_djmp   REG 源 delta-from-jmp (GCC .L4 风格: lea 基址=jmp 指令
#                    地址; 基址即跳转点时与 delta-from-base 静态不可分, §F.3)
#   ④ wv_jtm_abs    MEM 源直跳 jmp [rcx+rax*8] (lea 基址, 绝对 VA 表项)
#   ⑤ wv_jtm_movabs MEM 源 + movabs 基址 (disp 常量形态)
#   ⑥ wv_jt_undef   无防御 (无 cmp/ja) → 永久 gate (G2-c 裁决)
#   ⑦ wv_jt_oob     表项指向另一函数入口 → 出区 gate
#   ⑧ wv_jt_data    表项指向数据段全局 → 非指令地址 gate
# 证据: 保护日志 5 条 "jump-table @ ... entries=8 reg-8B-abs/reg-8B-delta/
# mem-8B-abs" 命中 + 3 条 gate note (未检出防御常数 / 不在区域各 ≥1)。
enable_language(ASM_MASM)
add_executable(wvmp_jmp_table8_sample
    jmp_table8_sample_main.cpp
    jmp_table8_sample_asm.asm
)
target_link_libraries(wvmp_jmp_table8_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_jmp_table8_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_jmp_table8_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-411 (G1): SSE 尾扫包主样本——双访存语义 + comiss/comisd + pd 位运算族。
# 区域覆盖 (派活单 §A.2 三挂点, 编译器形态实测定形):
#   - 双访存读改写 triple (movsd+addsd+movsd 全 rip, C++ g_d += 1.0 天然产;
#     "dst=mem" 无 x86 编码, 见 sse_memop_sample_main.cpp 头注释);
#   - MSVC /Od 天然 comiss (g_f < 常量 → movss+movss+comiss reg-reg+jbe);
#   - MSVC 对 _mm_and_pd/_mm_or_pd/_mm_xor_pd 直出 andps/orps/xorps
#     (pd/ps 互换无损的编译器证据);
#   - MASM helper 直写: addsd xmm0,[rsp+40] 栈基址 mem 源 / comiss/comisd
#     rip mem 源 + seta (flags 读回) / 真 66-prefix andpd/orpd/xorpd
#     (REG-REG + rip mem 源) / andnps (MIT-411 负例 gate, MIT-425 (G1b)
#     入面按 §B.4 正例翻转 — 真虚拟化, 行为 byte-exact 不变)。
# REQUIRE_REAL: main 区域 + helper 区域真虚拟化 (stub ≥1); 负例函数 gate
# 由保护日志 Note 验证。
enable_language(ASM_MASM)
add_executable(wvmp_sse_memop_sample
    sse_memop_sample_main.cpp
    sse_memop_sample_asm.asm
)
target_link_libraries(wvmp_sse_memop_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_sse_memop_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_sse_memop_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-411 (G1): 影子样本——comiss/comisd 折叠 + pd 位运算族折叠 + 双访存
# 形态的 ctx.xmm / VM-flags 运行时读回断言 (验收门 #79 纪律, 与主样本同
# IR 配对、独立 exe)。区域由 MASM 直写 7 条探针 (comiss/comisd mem 源 +
# seta flags 读回 / andpd/orpd/xorpd reg+mem / addsd 栈源 / 双访存 triple),
# 区域外 8 槽 × 2×u64 全量位图案打印 + seta 结果: 槽位落点错 (写 GPR 区)、
# 宽度截断、flags 空转 (pitfall #79) 均与 native run 逐字节不一致 → FAIL。
enable_language(ASM_MASM)
add_executable(wvmp_sse_memop_xmm_readback_sample
    sse_memop_xmm_readback_sample_main.cpp
    sse_memop_xmm_readback_sample_asm.asm
)
target_link_libraries(wvmp_sse_memop_xmm_readback_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_sse_memop_xmm_readback_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_sse_memop_xmm_readback_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-415 (G3): 端到端主样本——区域内含 rep/repnz 串指令族 (movsb/movsq 非对齐/
# stosb/scasb/cmpsb/lodsb + flags 通路探针), 验证前缀闸放行 + 翻译器微程序
# 展开 (D2: 零新 VmOp) 后真虚拟化、行为与原生逐字节一致。MSVC x64 不支持
# inline asm, /Od 的 memcpy/memset 走 call 不产 rep 串指令 (派活单 §A.3 先验),
# 故全族字节由 string_ops_sample_asm.asm (MASM) 直接 emit。负例 pause 同
# exe 内照旧 gate (行为 byte-exact 由双跑兜底); lock rep movsb 负例本机
# #UD 不可执行, 仅在 lifter 单测覆盖 (披露于报告)。
enable_language(ASM_MASM)
add_executable(wvmp_string_ops_sample
    string_ops_sample_main.cpp
    string_ops_sample_asm.asm
)
target_link_libraries(wvmp_string_ops_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_string_ops_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_string_ops_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-417 (P0): 端到端正路径样本——区域内调用带 double/float 参数的 native
# callee (3 次 callgate: 4 槽 double + 2 槽 float), 验证 CallGate FP 参数/
# 返回值通路 (xmm0..3 入参 + xmm0 返回) 修复后真虚拟化、行为与原生逐字节
# 一致 (G5r triage §6.1: 修复前 FP 参数断链 → 静默错乱零告警)。返回值参与
# 后续 VM 运算 (addsd/addss), 四个可观察输出各对应一条故障通路。
# REQUIRE_REAL: 主函数 fp_callgate_vm 真虚拟化 (stub ≥1)。
add_executable(wvmp_fp_callgate_sample fp_callgate_sample_main.cpp)
target_link_libraries(wvmp_fp_callgate_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_fp_callgate_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_fp_callgate_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-418 (G5r-R3): x87 永久 gate 回归样本——区域内 x87 五族 (fld/fadd/fstp/
# fcomip/fsin) 各 ≥1 条入标记区, lifter 未支持 → C1 gate 整函数保持原生
# (**零 stub**, byte-identical); 同 exe 1 个纯 GP helper 真虚拟化区
# (REQUIRE_REAL ≥1 stub 满足源, stub 总数 1 = 仅 helper 虚拟化钉死 gate
# 证据)。MSVC x64 不产 x87 (long double=double), x87 字节由
# x87_gate_sample_asm.asm (MASM) 直写——416 §A 裁定 MASM 是唯一可靠构造路。
# (enable_language(ASM_MASM) 已由 MIT-415 样本段启用, 此处不重复。)
add_executable(wvmp_x87_gate_sample
    x87_gate_sample_main.cpp
    x87_gate_sample_asm.asm
)
target_link_libraries(wvmp_x87_gate_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_x87_gate_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_x87_gate_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-419 (G4): lock 前缀原子族端到端主样本——C++ Interlocked* intrinsic
# 真产物 + MASM 直写全谱 (lock xadd 32/64、lock bts/btr imm8、lock btc
# reg 位号、裸 xchg mem、lock cmpxchg rip-relative 目标 + cmpxchg 后 je
# ZF 读回惯用法), 验证 F0 前缀闸白名单放行 + strip-and-execute 后真虚拟
# 化、行为与原生逐字节一致 (D1 原子性边界披露 note)。负例 lock mov/lock
# nop (ml64 A2068 拒汇编, db 直发) 区域 → capstone 拒解码 → C1 gate, 原生
# #UD 禁入可执行路径, gate 证据 = protect 日志 (main 只取地址不调用)。
# REQUIRE_REAL: 主函数 cpp_atomic_region + 7 个 MASM 正例真虚拟化 (stub ≥1)。
# 编译档位 (probe 实证 2026-08-30): /Od 下 MSVC 把 Interlocked intrinsic
# 编成 call 到编译器生成 helper (helper 内含 lock xadd/lock and/or/xor/
# lock cmpxchg 单指令, 反汇编表见报告 §3) — C++ 区域覆盖 callgate→原生
# helper 通路 (lock 指令经 callgate 原生执行, 语义断言照旧); /O1 才直发
# 内联 rip-relative lock 形态, 但 /O1 与 Debug 全局 /RTC1 硬冲突
# (cl D8016, /RTC1- 等全部无效) — 内联形态由 MASM 侧按 helper 字节逐条
# 拼写入区域 VM 化 (helper 即编译器真产物, 字节一致)。
add_executable(wvmp_atomic_ops_sample
    wvmp_atomic_ops_sample_main.cpp
    wvmp_atomic_ops_sample_asm.asm
)
target_link_libraries(wvmp_atomic_ops_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_atomic_ops_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_atomic_ops_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-423 (G4b): lock inc/dec 原子补齐端到端主样本——MASM 直写裸 lock
# inc/dec 全谱 (dword/qword 双宽、rip-relative 目标、dec r8d; jnz 循环计数
# 惯用法、add→CF→lock inc→jc CF 保真探针 — SDM: inc/dec 不写 CF), 本体折条
# 真虚拟化 (D1: 零新 VmOp, Load→Inc/Dec→Store, lock-strip note 披露)。
# C++ 侧 _InterlockedIncrement/Decrement 真产物区域 (#33 实测: cl v145 产
# lock xadd ±1 内联展开, 真产物走 419 Xadd 硬件原子通路, 不产裸 lock inc/
# dec — 派活单 §A.3 先验被实测推翻)。负例: lock not (SDM 合法但无 MSVC
# 产物, D2 裁决 gate — **可调用**, gate 行为保真正证) + lock inc ecx
# (reg-dst 非法编码, db 直发, capstone 拒解码 → gate, 原生 #UD 禁调用)。
# REQUIRE_REAL: 7 个 MASM 正例 + cpp_incdec_region 真虚拟化 (stub ≥1)。
add_executable(wvmp_atomic_incdec_sample
    wvmp_atomic_incdec_sample_main.cpp
    wvmp_atomic_incdec_sample_asm.asm
)
target_link_libraries(wvmp_atomic_incdec_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_atomic_incdec_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_atomic_incdec_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-425 (G1b): SSE 收官包端到端主样本——mul 族 (mulss/mulsd/mulps/mulpd)
# + andnps/andnpd + SSE2 整数位运算族 (pand/por/pxor/pandn)。
# 区域覆盖:
#   - C++ 天然 mul 区域 (/Od 直产 movss/mulsd [rip]+movss/movsd — cl v145
#     实测, mul 族编译器自然产物高频形态);
#   - MASM 直写: 0F 59 系四编码 (REG-REG + rip mem 源) / 0F 55 andnps
#     (_mm_andnot_si128 MSVC 真产物形态) / 66 0F 55 andnpd / 66 0F DF
#     pandn / 66 0F DB/EB/EF pand/por/pxor (REG-REG + rip mem 源);
#   - 负例 paddq (66 0F D4): R2 档② 砍面留 G1c (跳表预算 95 顶格) →
#     C1 gate 整函数保持原生 (可调用, 行为 byte-exact)。
# REQUIRE_REAL: C++ 区域 + MASM 正例区域真虚拟化 (stub ≥1)。
enable_language(ASM_MASM)
add_executable(wvmp_sse_fin_sample
    sse_fin_sample_main.cpp
    sse_fin_sample_asm.asm
)
target_link_libraries(wvmp_sse_fin_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_sse_fin_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_sse_fin_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-425 (G1b): 影子样本——mul 族 + andnps/andnpd/pandn + pand/por/pxor
# 的 ctx.xmm 运行时读回断言 (验收门 #79 纪律, 与主样本同能力面配对、独立
# exe)。区域由 MASM 直写 13 条探针 (单指令区域 + nop 垫), 区域外 8 槽 ×
# 2×u64 全量位图案打印: 槽位公式错 (MIT-371 空转形态 sub 0x24)、写 GPR
# 槽区、宽度截断、标量高位丢失均与 native run 逐字节不一致 → FAIL。
enable_language(ASM_MASM)
add_executable(wvmp_sse_fin_xmm_readback_sample
    sse_fin_xmm_readback_sample_main.cpp
    sse_fin_xmm_readback_sample_asm.asm
)
target_link_libraries(wvmp_sse_fin_xmm_readback_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_sse_fin_xmm_readback_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_sse_fin_xmm_readback_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-426 (G6a): VEX.128 档A 端到端主样本 — 38 id V-pair 三地址折叠进既有
# SSE 通路 (零新 VmOp / 零新 handler)。区域覆盖 (vex128_sample_asm.asm,
# ml64 直收 AVX 助记符; C4 全前缀 db 直写): 标量 FP 三态 (vaddss d==s1 /
# vmulps packed d==s2 交换 / vaddps/vsubps/vmulss/vandnps d 独立 Mov 前置)
# + D4 vmovaps 纯拷贝直折 + 408 mem 通路 (vmovups load / vaddsd mem 源) +
# vpxor 清零惯用法 (425 整数位运算镜像) + vucomiss+seta flags 通路 +
# C4 全前缀 vaddsd (D5)。负例区 (函数级分离, 各自整函数 gate, 可调用,
# 行为 byte-exact): ymm 同 mnemonic (B.4 位宽闸) / FMA (双舍入红线) /
# rorx (VEX-GP, G8) / vzeroupper (档B ABI) / vpaddd (G1c 镜像) / vsubsd
# 非交换 d==s2 (D2 裁决) / vmulsd 标量 d==s2 (高位语义不相容) / vmovsd
# 插入 d≠s1 (§F.4 "假 Mov")。
# REQUIRE_REAL: 正例区域真虚拟化 (stub ≥1)。
enable_language(ASM_MASM)
add_executable(wvmp_vex128_sample
    vex128_sample_main.cpp
    vex128_sample_asm.asm
)
target_link_libraries(wvmp_vex128_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_vex128_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_vex128_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-426 (G6a): 影子样本 — 三态折叠 + D4 拷贝 + mem 通路的 ctx.xmm 运行时
# 读回断言 (#79 纪律, 与主样本同能力面配对、独立 exe)。9 探针 (位图案全 8
# 槽预载 + 区域后 8 槽 × 2×u64 全量落盘): d==s1 直走高位残留 / packed
# d==s2 交换全宽语义 / d 独立 pre-Mov 槽位正确性 (误写无关槽即 FAIL) /
# 标量 vmulss "dst 高位 ← s1 高位" (pre-Mov 位级证据) / 非交换 d 独立 /
# vandnps / D4 拷贝 / vpxor 清零 / vmovups mem load。
enable_language(ASM_MASM)
add_executable(wvmp_vex128_xmm_readback_sample
    vex128_xmm_readback_sample_main.cpp
    vex128_xmm_readback_sample_asm.asm
)
target_link_libraries(wvmp_vex128_xmm_readback_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_vex128_xmm_readback_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_vex128_xmm_readback_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-427 (G1c): movd/movq GP↔xmm 桥主样本 — 桥四形 REG + mem 双向 (既有
# XmmLoad/XmmStore 408 通路) + all-xmm 双形态 (F3 0F 7E 清零 → 新
# VmOp::XmmFromGp / 66 0F D6 保持 → 既有 (Movss,S64)=Movsd)。区域由 MASM
# 直写真字节 (MASM 助记符无法区分 F3/66 双形态, db 直发; /Od intrinsic
# 溢出直产 movdqa/movdqu 砍面 → C++ intrinsic 函数全落负例区)。负例区
# (函数级分区): paddq/psubq (B.2 砍面) / pmovmskb/pcmpeqd (D3 不本单) /
# MMX movq (mm 操作数 D2 永久 gate) / movdqa+movdqu (C++ 真产物 gate)。
add_executable(wvmp_sse_bridge_sample
    sse_bridge_sample_main.cpp
    sse_bridge_sample_asm.asm
)
target_link_libraries(wvmp_sse_bridge_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_sse_bridge_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_sse_bridge_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-427 (G1c): 影子样本 — 桥 handler 的 ctx.xmm 运行时读回断言 (#79
# 纪律, 与主样本同能力面配对、独立 exe)。9 探针 (位图案全 8 槽预载 +
# 区域后 8 槽 × 2×u64 全量落盘 + rax GP 读回): movd 高 96 清零 / movq
# 高 64 清零 / movd r32 零扩展 / F3 vs 66 0F D6 双形态 / mem 装入清零 /
# mem store 截取 (误写无关槽即 FAIL)。
enable_language(ASM_MASM)
add_executable(wvmp_sse_bridge_xmm_readback_sample
    sse_bridge_xmm_readback_sample_main.cpp
    sse_bridge_xmm_readback_sample_asm.asm
)
target_link_libraries(wvmp_sse_bridge_xmm_readback_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_sse_bridge_xmm_readback_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_sse_bridge_xmm_readback_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-428 (G1d): movdqa/movdqu 对齐传送主样本 — 双编码 (6F/7F 反写 db 直发)
# × 三形态 (reg-reg / 栈槽 对齐+非对齐 / rip 对齐 load+store 与非对齐 store)
# + VEX vmovdqa/vmovdqu (rr 双向 + rip store) + /Od intrinsic 翻转正例 3 函数
# (427 #33④ 闭环: movd/movq 桥 + movdqa/movdqu spill 共存形态真虚拟化)。
# 负例区 (函数级分区, 各自整函数 gate 可调用, 行为 byte-exact): EVEX
# vmovdqa32 (id=1026 白名单外) / vpaddd ymm (位宽闸) / punpcklqdq (D4 交织) /
# pmovmskb (D3)。本机 AVX2 + AVX-512F/VL 在位 (cpuid probe 2026-08-31)。
enable_language(ASM_MASM)
add_executable(wvmp_aligned_mov_sample
    aligned_mov_sample_main.cpp
    aligned_mov_sample_asm.asm
)
target_link_libraries(wvmp_aligned_mov_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_aligned_mov_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_aligned_mov_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-428 (G1d): 影子样本 — 既有 Movaps/Movups handler 的 ctx.xmm 运行时
# 读回断言 (#79 纪律, 与主样本同能力面配对、独立 exe)。9 探针 (位图案全 8
# 槽预载 + 区域后 8 槽 × 2×u64 全量落盘): 16B 全宽拷贝 (高位 = 源高位, 与
# 427 桥清零语义对照) / 7F 反写形归一化 / 对齐栈槽 + 非对齐栈槽 (movups
# 宽松语义行为钉) / rip load+store / VEX 双形式。零新 handler → dump 门
# SSE_HANDLERS 集合恒等 = 零新 VmOp 机器证明 (426 §D.7)。
enable_language(ASM_MASM)
add_executable(wvmp_aligned_mov_xmm_readback_sample
    aligned_mov_xmm_readback_sample_main.cpp
    aligned_mov_xmm_readback_sample_asm.asm
)
target_link_libraries(wvmp_aligned_mov_xmm_readback_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_aligned_mov_xmm_readback_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_aligned_mov_xmm_readback_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-433 (MIT-P1): rol/ror flags partial-preserve 主样本 — %TEMP%\p432
# 复现样本转正 (MIT-432 §6.1, 自含 MASM marker 桩形保留, 不链 wvmp::sdk)。
# 5 区全部"前态构造 → rotate → setcc 消费 → 区内 Store 落盘"(427 披露①
# 观察纪律): ror ZF / rol ZF (修复前分叉=1, native=0) / shl ZF 对照
# (按结果写, 双侧一致) / rol SF (前态 1 保留, 修复前=0) / ror PF (前态 0
# 保留, 修复前=1)。修复前 stdout 分叉必 FAIL, 修复后 byte-exact。
enable_language(ASM_MASM)
add_executable(wvmp_flags_rol_sample
    wvmp_flags_rol_sample_main.cpp
    wvmp_flags_rol_sample_asm.asm
)
target_compile_options(wvmp_flags_rol_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_flags_rol_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-434 (G8a): BMI 折条款目主样本 — 16 正例区 (andn/bzhi/rorx/shlx/sarx/
# shrx × {d==s1, d==s2, d 独立, mem src} + flags 消费探针 setcc → 区内 Store
# 落盘; bzhi 边界 idx=N 原值+CF=1 probe 修正面) 真虚拟化 + 1 负例区
# (mulx/pdep/pext/blsr/bextr/blsi/blsmsk) 函数级 gate 可调用 byte-exact。
# 单基本块 (432 §6.3), 自含 MASM marker 桩 (433 同款)。multiseed 47→48。
add_executable(wvmp_bmi_sample
    wvmp_bmi_sample_main.cpp
    wvmp_bmi_sample_asm.asm
)
target_compile_options(wvmp_bmi_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_bmi_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-438 (X1b): ret imm16 清栈语义主样本 — 3 区 x64 ret N 直写真编码
# (MASM 手编, 8/0/88h; 区域末条 = ret N, 本单前跳表无 Ret handler 指向
# Halt) + caller 侧平衡探针/返回值断言 (native 手编)。修复前旧 CLI
# (main f7a865c) 反证: VmOp::Ret → Halt → 死分隔符续跑 → stdout 分叉必
# FAIL; 修复后 byte-exact。自含 MASM marker 桩 (433 同款)。
# multiseed 48→49 (245 runs)。
add_executable(wvmp_retimm_sample
    wvmp_retimm_sample_main.cpp
    wvmp_retimm_sample_asm.asm
)
target_compile_options(wvmp_retimm_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_retimm_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-442 (X2a): 形级 fork 面收口主样本 — x64 可执行形态全链 (B.5 D3 硬项):
# 区1 leave 链 (push rbp/mov rbp,rsp/sub rsp/leave/ret 全在区内, 折条
# [Mov rsp←rbp; Pop rbp] 真虚拟化 + bal=0 平衡哨兵) + 区3 plain 串形
# (movsd×2/lodsd 单发微程序 + cld no-op 放行) + 区4 p66 S16 通路 (66 B8/03/89
# + cwde 两 IR 折条 + cbw 载体微程序) 真虚拟化 (REQUIRE_REAL ≥1 stub);
# 负例区2 call [mem] IAT 形 / 区2b call reg (D4 停手 gate 归 X3) / 区5 std
# (D5 gate) / 区6 67 前缀 (B.4 闸, 禁调用) 函数级 gate 可调用/可取址,
# 行为 byte-exact。multiseed 49→50 (250 runs)。
add_executable(wvmp_forkface_sample
    wvmp_forkface_sample_main.cpp
    wvmp_forkface_sample_asm.asm
)
target_compile_options(wvmp_forkface_sample PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:C,CXX>>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_forkface_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)
