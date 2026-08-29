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

# MIT-411 (G1): SSE 尾扫包主样本——双访存语义 + comiss/comisd + pd 位运算族。
# 区域覆盖 (派活单 §A.2 三挂点, 编译器形态实测定形):
#   - 双访存读改写 triple (movsd+addsd+movsd 全 rip, C++ g_d += 1.0 天然产;
#     "dst=mem" 无 x86 编码, 见 sse_memop_sample_main.cpp 头注释);
#   - MSVC /Od 天然 comiss (g_f < 常量 → movss+movss+comiss reg-reg+jbe);
#   - MSVC 对 _mm_and_pd/_mm_or_pd/_mm_xor_pd 直出 andps/orps/xorps
#     (pd/ps 互换无损的编译器证据);
#   - MASM helper 直写: addsd xmm0,[rsp+40] 栈基址 mem 源 / comiss/comisd
#     rip mem 源 + seta (flags 读回) / 真 66-prefix andpd/orpd/xorpd
#     (REG-REG + rip mem 源) / 负例 andnps (0F 55 系留 412+, C1 gate)。
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
