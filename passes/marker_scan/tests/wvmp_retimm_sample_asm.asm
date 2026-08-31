; MIT-438 (X1b): ret imm16 清栈语义端到端主样本 MASM — x64 现网同类地雷反证
; (X0 §A.1 升级定性: ret imm16 在 x64 也是合法编码, 手写/第三方汇编产物可现;
;  433 同款 "修复前旧 CLI 双跑 stdout 分叉必 FAIL" 反证纪律, REQUIRE_REAL)。
;
; 样本形态 = x64 `ret N` 真编码直写 (MASM 手编纪律, 423/428 同款; stdcall 被
; 调方清栈仿形 — Win64 无编译器产物, 派活单 §B.2 D4: MASM 直写是唯一确定形):
;
;   区1 wv438_stdret8  : ret 10h (常规档; caller 16 对齐垫并入清栈量, 见下注)
;   区2 wv438_retzero  : ret 0   (D3 边界: ≡ plain ret; cdecl 侧 caller 清栈)
;   区3 wv438_retbig   : ret 90h (大 imm 档: 清栈量越过 imm8 幅度)
;
; ⚠ 清栈量对账 (qword 参数的 x64 仿形特有): Win64 push 恒 8B 且 call 点 rsp
; 须 16 对齐 → 良构 caller 的"参数+对齐垫"总量 ≡ 0 (mod 16), stdcall 被调方
; 清栈量 N 恒 ≡ 0 (mod 16)。imm=8 (N≡8) 只出现于 caller 自身奇数 push 的
; 手写场景, 由 runtime 语义电池 (imm=8 档) + translator 矩阵覆盖; 本样本取
; 良构形 10h/0/90h。
;
; 每区结构 (区域含 ret N 为区域末条 — 本单前跳表无 Ret handler 指向 Halt):
;   caller (native, 手编)                  callee (区域 = marker_begin/end 之间)
;   mov rbx, rsp          ; R0 基准        sub  rsp, 28h        ; 区域外
;   sub  rsp, 0x10/0x90   ; 参数槽         call marker_begin    ; 区域外锚点
;   mov [rsp], 5Ah        ; 栈参数          ; ==== region ====
;   mov  ecx, N                            mov eax, ecx         ; 参数消费
;   call callee                            add eax, K
;   (stdcall: 无清理 / cdecl: add rsp)     mov edx, [rsp+30h]   ; 栈参数消费
;   sub  rbx, rsp         ; 平衡探针        add eax, edx
;   store 全局                             add rsp, 28h         ; 区内释放帧
;                                          ret N                ; ★ 清栈返回
;                                          call marker_end      ; 死分隔符
;                                          add rsp, 28h / ret
;
; 分叉面 (修复前旧 CLI = main f7a865c): VmOp::Ret 无 handler → Halt → stub 从
; 区域尾 (死分隔符) 续跑: rax 被 marker_end 魔数覆写 (返回值断言分叉) + 物理
; rsp 落在 ns (callee 帧), 经 `add rsp,28h; ret` 弹出原返回地址回 caller,
; caller rsp = R0-0x10/0x90 (平衡探针分叉)。修复后 ret N 清栈返回 → 与 native
; 逐字节一致。旧 CLI 分叉必 FAIL (multiseed 逐字节比对捕获), 修复后 byte-exact。
;
; 死分隔符设计 (add rsp,28h; ret): 让旧 CLI 的坏路径确定性返回 (弹到的恰是
; 未被消费的原返回地址), 不落入随继函数字节 — 分叉值可复现、贴两侧可审计;
; native / 修复后 packed 恒不执行 (ret N 已跳出区域)。
;
; 区域指令面: mov/add/[rsp+disp] 载入/add rsp,imm/ret N 全白名单 (add rsp
; 走 Op::Add dst=Rsp S64 通路, S64 槽读写即 v4 — 本单实测面之一); caller 全
; native (平衡探针在 caller 侧, 不属 427 区内 Store 观察纪律域)。

.code
; ---- 自含 marker 桩: magic 8 字节连续 (433 同款, 不链 wvmp::sdk) ----
marker_begin PROC
    mov rax, 31474542504D5657h   ; "WVMPBEG1" (kBeginMagic)
    ret
marker_begin ENDP
marker_end PROC
    mov rax, 31444E45504D5657h   ; "WVMPEND1" (kEndMagic)
    ret
marker_end ENDP

; C 链接全局 (wvmp_retimm_sample_main.cpp 定义): 平衡探针 + 返回值落盘槽
EXTERNDEF g_wv438_bal1 : DWORD
EXTERNDEF g_wv438_ret1 : DWORD
EXTERNDEF g_wv438_bal2 : DWORD
EXTERNDEF g_wv438_ret2 : DWORD
EXTERNDEF g_wv438_bal3 : DWORD
EXTERNDEF g_wv438_ret3 : DWORD

_TEXT SEGMENT

; ---- 区1 callee: 区域 { mov/add/load [rsp+30h]/add rsp/ret 8 } ----
; rcx=N, [栈上 8B]=参数 → eax = N + 7 + 参数; stdcall 仿: ret 8 清栈。
wv438_stdret8 PROC
    sub  rsp, 28h
    call marker_begin
    mov  eax, ecx               ; ==== region ====
    add  eax, 7
    mov  edx, [rsp+30h]         ; 栈参数 ([R0-10h] = v4+30h)
    add  eax, edx
    add  rsp, 28h               ; 区内释放帧 → 返回地址顶栈
    ret  10h                    ; ★ 清栈返回 (参数槽+对齐垫, 良构形)
    call marker_end             ; 死分隔符 (旧 CLI 坏路径续跑点)
    add  rsp, 28h
    ret
wv438_stdret8 ENDP

; ---- 区2 callee: ret 0 (D3 边界 ≡ plain ret); cdecl 仿: caller 清栈 ----
wv438_retzero PROC
    sub  rsp, 28h
    call marker_begin
    mov  eax, ecx               ; ==== region ====
    add  eax, 0Dh
    mov  edx, [rsp+30h]
    add  eax, edx
    add  rsp, 28h
    ret  0                      ; ★ imm=0 边界
    call marker_end
    add  rsp, 28h
    ret
wv438_retzero ENDP

; ---- 区3 callee: ret 88h (大 imm; 清栈量越过 imm8 幅度) ----
wv438_retbig PROC
    sub  rsp, 28h
    call marker_begin
    mov  eax, ecx               ; ==== region ====
    add  eax, 15h
    mov  edx, [rsp+30h]
    add  eax, edx
    add  rsp, 28h
    ret  90h                    ; ★ 大 imm 清栈 (0x10 参数槽 + 0x80 垫)
    call marker_end
    add  rsp, 28h
    ret
wv438_retbig ENDP

; ---- 区1 caller: 2 轮 stdcall 调用链 (链 = 重复调用验证平衡可重复) ----
; 每轮: 各自 sub rsp,10h 分配参数槽 → call → (callee ret 10h 已清, 无需
; caller 清理) → 平衡探针 + 返回值落盘。第 2 轮若不复分配, call 点将落在
; 已被上轮清栈的 rsp 上 (错对齐 + 参数错位 — 本单调试实测过的真陷阱)。
wv438_call_stdret8 PROC
    push rbx
    sub  rsp, 20h
    mov  rbx, rsp               ; R0 (16 对齐)
    sub  rsp, 10h               ; 第 1 轮参数槽
    mov  qword ptr [rsp], 5Ah   ; 栈参数
    mov  ecx, 1
    call wv438_stdret8          ; ret 10h → rsp 回 R0
    sub  rbx, rsp               ; 探针: 0 正确 / 10h 失衡 (旧 CLI)
    mov  DWORD PTR g_wv438_bal1, ebx
    add  rbx, rsp               ; 恢复 R0 (探针不得销毁基准, 第 2 轮复用)
    mov  DWORD PTR g_wv438_ret1, eax
    sub  rsp, 10h               ; 第 2 轮重新分配参数槽
    mov  qword ptr [rsp], 1Dh
    mov  ecx, 2
    call wv438_stdret8
    add  eax, 10h               ; 与第 1 轮区分: 2+7+1Dh+10h = 36h
    sub  rbx, rsp
    mov  DWORD PTR g_wv438_bal1, ebx   ; 覆写 (双轮后平衡仍须 0)
    add  rbx, rsp               ; 恢复 R0
    mov  DWORD PTR g_wv438_ret1, eax
    ; 两轮 0x10 均由 callee ret 10h 清 — epilogue 只还 0x20 帧与 push rbx
    add  rsp, 20h
    pop  rbx
    ret
wv438_call_stdret8 ENDP

; ---- 区2 caller: ret 0 (cdecl 仿) — caller 自清 0x10 ----
wv438_call_retzero PROC
    push rbx
    sub  rsp, 20h
    mov  rbx, rsp
    sub  rsp, 10h
    mov  qword ptr [rsp], 5Bh
    mov  ecx, 3
    call wv438_retzero          ; ret 0 → rsp = R0-10h (参数槽仍在)
    add  rsp, 10h               ; cdecl 侧清栈
    sub  rbx, rsp               ; 探针: 0 (旧 CLI: rax 分叉, 平衡碰巧同)
    mov  DWORD PTR g_wv438_bal2, ebx
    mov  DWORD PTR g_wv438_ret2, eax
    add  rsp, 20h
    pop  rbx
    ret
wv438_call_retzero ENDP

; ---- 区3 caller: ret 88h (stdcall 仿大清栈) ----
wv438_call_retbig PROC
    push rbx
    sub  rsp, 20h
    mov  rbx, rsp
    sub  rsp, 90h               ; 0x10 参数槽 + 0x80 垫 (ret 90h 全量清)
    mov  qword ptr [rsp], 5Ch
    mov  ecx, 4
    call wv438_retbig           ; ret 88h → rsp 回 R0
    sub  rbx, rsp               ; 探针: 0 / 90h (旧 CLI)
    mov  DWORD PTR g_wv438_bal3, ebx
    mov  DWORD PTR g_wv438_ret3, eax
    ; callee ret 90h 已清参数槽+垫 — epilogue 只还 sub rsp,20h 与 push rbx
    add  rsp, 20h
    pop  rbx
    ret
wv438_call_retbig ENDP

_TEXT ENDS
END
