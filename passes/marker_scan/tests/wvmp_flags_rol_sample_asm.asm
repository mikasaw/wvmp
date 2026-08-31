; MIT-433 (MIT-P1): rol/ror flags partial-preserve 端到端主样本 MASM —
; %TEMP%\p432 复现样本转正 (MIT-432 §6.1 项目主独立复现形态, 自含 marker 桩
; 原样保留: magic 直嵌, 不链 wvmp::sdk)。
;
; 分叉面 (SDM Vol.2 ROL/ROR: 只写 CF/OF, ZF/SF/PF unaffected):
;   修复前 ror/rol handler 走 build_shift 全量装配 → zero5 的 xor 把宿主
;   ZF/SF/PF 打成 1/0/1 → setcc5 捕宿主内部状态 → setz/sets/setp 消费分叉
;   (MIT-432 §6.1: native ror 后 setz=0, packed=1)。修复后 flags_tail_partial
;   三位从 ctx 旧值保留 → 与 native byte-exact。
;
; 区结构 (5 区全部真虚拟化, REQUIRE_REAL ≥1 stub):
;   前态构造(or imm, ALU 全量写=正确的三位写入) → rotate(rol/ror/shl) →
;   setcc 消费 → 区内 Store 落盘全局 (427 披露① 观察纪律: 消费值经区内
;   Store 通路读出, 禁区域外读 callee-saved 物理寄存器)。
;   ① ror_z:   or eax,1 (ZF=0)  → ror eax,1 → setz  (native 0 / 修复前 1)
;   ② rol_z:   or eax,1 (ZF=0)  → rol eax,1 → setz  (native 0 / 修复前 1)
;   ③ shl_z:   or eax,1 (ZF=0)  → shl eax,1 → setz  (对照: shl 按结果写
;              ZF, 结果非零 → 双侧一致 0; 全量装配对 SHL 组是正确语义)
;   ④ rol_sf:  or eax,80000000h (SF=1) → rol eax,1 → sets
;              (native 保留 1 / 修复前宿主 SF=0 → 0)
;   ⑤ ror_pf:  or eax,1 (低字节奇校验 → PF=0) → ror eax,1 → setp
;              (native 保留 0 / 修复前宿主 PF=1 → 1)
; 修复前 stdout 分叉必 FAIL (multiseed 反证), 修复后 byte-exact PASS。
;
; MASM 手编纪律 (428 pp 位教训): setcc 目的寄存器用 cl (guest RCX 低字节,
; VM setcc handler 写别名槽, 区内 Store 经别名读 — 全 VM 内闭合);
; marker 桩 magic 与 sdk/include/wvmp/sdk/markers.hpp kBeginMagic/kEndMagic
; 逐字节同步 (自含桩不做编译期断言, 同步性由 marker_scan 定位成败兜底)。

.code
; ---- 自含 marker 桩: magic 8 字节连续 (p432 原形) ----
marker_begin PROC
    mov rax, 31474542504D5657h   ; "WVMPBEG1" (kBeginMagic)
    ret
marker_begin ENDP
marker_end PROC
    mov rax, 31444E45504D5657h   ; "WVMPEND1" (kEndMagic)
    ret
marker_end ENDP

; C 链接全局 (wvmp_flags_rol_sample_main.cpp 定义), 区内 Store 落盘槽
EXTERNDEF g_wv433_ror_z  : BYTE
EXTERNDEF g_wv433_rol_z  : BYTE
EXTERNDEF g_wv433_shl_z  : BYTE
EXTERNDEF g_wv433_rol_sf : BYTE
EXTERNDEF g_wv433_ror_pf : BYTE

_TEXT SEGMENT

; ---- ① wv433_ror_z: 区域 { or eax,1; ror eax,1; setz cl; store } ----
wv433_ror_z PROC
    push rbx
    sub rsp, 20h
    call marker_begin
    or  eax, 1              ; 前态 ZF=0 (marker_begin 留下的 0x504D5657|1)
    ror eax, 1              ; ROR: native 只写 CF/OF, ZF 保留 0
    setz cl                 ; native: 0; 修复前 VM: 宿主 xor 污染 → 1
    mov BYTE PTR g_wv433_ror_z, cl   ; 区内 Store 落盘
    call marker_end
    add rsp, 20h
    pop rbx
    ret
wv433_ror_z ENDP

; ---- ② wv433_rol_z: 区域 { or eax,1; rol eax,1; setz cl; store } ----
wv433_rol_z PROC
    push rbx
    sub rsp, 20h
    call marker_begin
    or  eax, 1              ; 前态 ZF=0
    rol eax, 1              ; ROL: 同面, ZF 保留 0
    setz cl                 ; native: 0; 修复前 VM: 1
    mov BYTE PTR g_wv433_rol_z, cl
    call marker_end
    add rsp, 20h
    pop rbx
    ret
wv433_rol_z ENDP

; ---- ③ wv433_shl_z: 对照区 { or eax,1; shl eax,1; setz cl; store } ----
wv433_shl_z PROC
    push rbx
    sub rsp, 20h
    call marker_begin
    or  eax, 1              ; 前态 ZF=0
    shl eax, 1              ; SHL: 按结果写 ZF — 全量装配是正确语义 (对照)
    setz cl                 ; 结果非零 → 双侧一致 0
    mov BYTE PTR g_wv433_shl_z, cl
    call marker_end
    add rsp, 20h
    pop rbx
    ret
wv433_shl_z ENDP

; ---- ④ wv433_rol_sf: 区域 { or eax,80000000h; rol eax,1; sets cl; store } ----
wv433_rol_sf PROC
    push rbx
    sub rsp, 20h
    call marker_begin
    or  eax, 80000000h      ; 前态 SF=1 (结果 0xD04D5657 负)
    rol eax, 1              ; ROL: SF 保留 1 (非按结果清 0)
    sets cl                 ; native: 1; 修复前 VM: 宿主 SF=0 → 0
    mov BYTE PTR g_wv433_rol_sf, cl
    call marker_end
    add rsp, 20h
    pop rbx
    ret
wv433_rol_sf ENDP

; ---- ⑤ wv433_ror_pf: 区域 { or eax,1; ror eax,1; setp cl; store } ----
wv433_ror_pf PROC
    push rbx
    sub rsp, 20h
    call marker_begin
    or  eax, 1              ; 前态 PF=0 (低字节 0x57 五个 1 = 奇校验)
    ror eax, 1              ; ROR: PF 保留 0
    setp cl                 ; native: 0; 修复前 VM: 宿主 xor 偶校验 → 1
    mov BYTE PTR g_wv433_ror_pf, cl
    call marker_end
    add rsp, 20h
    pop rbx
    ret
wv433_ror_pf ENDP

_TEXT ENDS
END
