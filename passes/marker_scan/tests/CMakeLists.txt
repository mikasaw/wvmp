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
