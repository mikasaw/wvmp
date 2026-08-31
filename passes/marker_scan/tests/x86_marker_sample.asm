; MIT-437 (X1a): ml.exe 手编 x86 标记样本 —— marker_scan 双段 magic E2E fixture。
;
; 桩形态按 cl v19.51.36256 x86 SDK 探针实测字节复刻（dumpbin /disasm，
; 2026-09-01），两形态各一对，E2E 同时覆盖双段识别的两方向：
;   marker_begin/marker_end   —— /Od 形：B8 <hi4> ; C7 45 F8 <lo4> ; 89 45 FC
;                                （hi→lo，间隔 3B；hi 只经 B8 物化一次）
;   marker_begin_o1/end_o1    —— /O1 /O2 形：C7 45 F8 <lo4> ; C7 45 FC <hi4>
;                                （lo→hi，紧邻，间隔 0）
; magic 一律以立即数操作数物化、永不被执行 —— 412 §6 坑②（naked+_emit 吞
; ret / magic 字节执行毁栈）结构性不适用；注释保 ASCII 安全字符范围内的
; 中英混排（ml 对注释高位字节容忍，坑① /utf-8 仅 cl 侧需要）。
;
; MASM 32 位 (ml.exe) 语法坑（412 §6 / X0 §5.2 沉淀）：imm32 十六进制以数字
; 结尾 h（504D5657h）；ebp 负 disp8 由 ml 自动编码 ModRM 45/disp8（本样本
; 无 SIB/MEM 复杂形，无双验面）；SSE 不用故无需 .XMM。
;
; 区域体 = 纯 nop 哨兵（rgn_one 8 字节 / rgn_two 12 字节）：fixture 测试
; 逐字节断言 [begin_rva, end_rva) == 哨兵，钉死区域边界精确性（RVA/尺寸）。

.586
.model flat, c

.code

; kStubWindow 误归属防御 (MIT-349 pitfall #39 同款): 桩前垫 >64B nop, 把
; 首个锚点推离 .text 起始区. 真产物实测 (无垫时): CRT __scrt 的 `call main`
; (目标 = main 入口 0x1000) 落进 begin 锚点前 64B 窗口, 被误归属为 begin
; 桩调用 → 幻影 begin (412 §8 #4 CRT 误归属类, X1a E2E 实弹复现).
; nop 字节永不被执行 (纯占位), 0x90 不含 E8, 不干扰 call 扫描.
    align 16
    REPEAT 80
    nop
    ENDM

; —— /Od 形桩（hi→lo）——
marker_begin PROC
    push ebp
    mov     ebp, esp
    sub     esp, 10h
    mov     eax, 31474542h                  ; hi "BEG1" — B8 imm32
    mov     dword ptr [ebp-8], 504D5657h    ; lo "WVMP" — C7 imm32
    mov     dword ptr [ebp-4], eax          ; hi 经寄存器落盘（无 imm 物化）
    mov     esp, ebp
    pop     ebp
    ret
marker_begin ENDP

marker_end PROC
    push ebp
    mov     ebp, esp
    sub     esp, 10h
    mov     eax, 31444E45h                  ; hi "END1" — B8 imm32
    mov     dword ptr [ebp-8], 504D5657h    ; lo "WVMP"
    mov     dword ptr [ebp-4], eax
    mov     esp, ebp
    pop     ebp
    ret
marker_end ENDP

; —— /O1 /O2 形桩（lo→hi，紧邻）——
marker_begin_o1 PROC
    push ebp
    mov     ebp, esp
    push    ecx
    push    ecx
    mov     dword ptr [ebp-8], 504D5657h    ; lo "WVMP" — C7 imm32
    mov     dword ptr [ebp-4], 31474542h    ; hi "BEG1" — C7 imm32
    mov     esp, ebp
    pop     ecx
    pop     ecx
    ret
marker_begin_o1 ENDP

marker_end_o1 PROC
    push ebp
    mov     ebp, esp
    push    ecx
    push    ecx
    mov     dword ptr [ebp-8], 504D5657h    ; lo "WVMP"
    mov     dword ptr [ebp-4], 31444E45h    ; hi "END1"
    mov     esp, ebp
    pop     ecx
    pop     ecx
    ret
marker_end_o1 ENDP

; —— 标记区域（/Od 形桩包裹，区域体 = 8×nop 哨兵）——
rgn_one PROC
    call    marker_begin
    nop                                     ; 哨兵 8 字节：区域 [begin 后, end 前)
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    call    marker_end
    ret
rgn_one ENDP

; —— 标记区域（/O1 形桩包裹，区域体 = 12×nop 哨兵）——
rgn_two PROC
    call    marker_begin_o1
    nop                                     ; 哨兵 12 字节
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    call    marker_end_o1
    ret
rgn_two ENDP

END
