#pragma once
#include "wvmp/common/types.hpp"

namespace wvmp::regvm::isa {

// VM 操作码：与 ir::Op 一一同义（值从 1 起，0 为非法哨兵），外加 VM 专属操作。
// 编码空间上限 14 位（kVmOpLimit）。运行时 dispatch 跳表按 opcode 低 8 位索引
// （asmgen.cpp kTableEntries=128，MIT-374 起；此前 6 位 = 64 项，Subpd=63 恰好
// 占满，Divss=64 起越界静默折叠到 halt）。追加枚举前先看 asmgen.cpp 的
// static_assert(kVmOpMax < kTableEntries) 是否仍成立。
// 编码空间上限 14 位（kVmOpLimit）；MIT-404 起用到低 8 位（kVmOpMax=79，
// Idiv；256 项 (MIT-510 扩容)跳表内，static_assert 见 asmgen.cpp kTableEntries），
// runtime 跳转表掩码/项数与之联动（vm/regvm/runtime/src/asmgen.cpp kTableEntries）。
enum class VmOp : u16 {
    Mov = 1, Lea, Add, Sub, Adc, Sbb, And, Or, Xor, Not, Neg, Inc, Dec,
    Shl, Shr, Sar, Rol, Ror, Cmp, Test, Push, Pop, Jmp, Jcc, Call, Ret,
    Load, Store, Nop,

    // —— VM 专属 ——
    Halt,       // 停机：解释器退出执行循环
    GetFlags,   // 读 v16(flags) 到 reg_a（S64 语义）
    SetFlags,   // 将 reg_a 低 5 位写入 v16(flags)

    // —— M2-8 rip-relative 变种 ——
    // LoadRva/StoreRva 与 Load/Store 形态相同（a=Reg, b=Reg-地址），但
    // 运行时会**额外**加上 VmContext.scratch_mem（=image_base）来还原
    // RVA → VA. 用于翻译期把 [rip+disp] 转 RVA 的场景——RVA 与 image_base
    // 都是 32 位内值, 相加不溢出（PE ImageBase < 0x1'0000'0000 典型 < 0x8000'0000）.
    // Load/Store 不加 scratch_mem: 译码的地址已是绝对 VA（来自 host 寄存器
    // 拷贝 / 算术, 直接落地访存）。
    LoadRva, StoreRva,

    // —— M2-9 call gate ——
    // VM 字节码遇到 call 时由翻译器发出；运行时 handler 把 VM 上下文切到
    // native caller frame（Win64 ABI），调目标 RVA 处的 native 函数，callee
    // ret 后把 RAX 写回 regs[v0] 继续 dispatch。aux = 目标 RVA（u32）；
    // cond_or_size = arg_count（v1 仅支持 0；非零暂按 0 兜底并 diag warn）。
    // a_kind / b_kind / reg_a / reg_b 一律 None（gate 与 VM 操作数无关）。
    CallGate,

    // —— MIT-301 cl 变体 shift ——
    // 计数源自 RCX 低 8 位（cl），而非 aux 立即数。lifter 接住 D3 /5（D3 /r）
    // 后用 Operand::Kind::Reg + Reg::Rcx 表示 src, 翻译器据此发射以下 5 个
    // VmOp（b_kind=OpKind::Reg, reg_b=RCX 槽）。运行时 handler 复用 build_shift
    // 逻辑——读 regs[RCX], 按宽度掩码（8/16 &31, 32/64 &63）, count=0 走 no-op
    // 出口不更新 flags, 其余走 native shift + setcc5 + writeback。ShlCl/ShrCl/
    // SarCl/RolCl/RorCl 与 Shl/Shr/Sar/Rol/Ror 编码一一对应, 调用 build_shift
    // 时仅 native op 不同（"shl"/"shr"/"sar"/"rol"/"ror"）。
    ShlCl, ShrCl, SarCl, RolCl, RorCl,

    // —— MIT-302 有符号/无符号乘法 ——
    // Imul 2-op reg 形式（dst = dst * src, native "imul <sz> reg_a, reg_b"）。
    // b_kind=OpKind::Reg, reg_b=src, aux=0, cond_or_size=size。
    // flags 语义同 native imul（CF/OF 当低半 != 高半时 set, SF/ZF/PF 按结果），
    // setcc5 直读 host CPU flags。
    // 3-op imm 形式（dst = src * imm）由翻译器拆为 mov_scratch + Imul(dst, scratch)
    // 两条：先 mov scratch, imm（VmOp::Mov w/ aux=imm32），再 Imul(dst, scratch)
    // 复用本 handler 的 2-op 路径——避免 native imul 第 3 操作数必须为静态立即数的
    // 硬限制（x86 imul r, r, imm 形式要求 imm 是汇编期常量，运行时不可)。
    Imul,
    // Mul 单操作数（unsigned rdx:rax = rax * src, native "mul <sz> reg_b"）。
    // reg_a 不参与（native mul 无显式 dst）；reg_b=src，隐式 RAX 作被乘数。
    // 运行时 handler 读 regs[Rax]，native mul 后将物理 rax/rdx 写回 regs[Rax]/regs[Rdx]。
    // flags 语义同 native mul（CF/OF 当低半 != 高半时 set）。
    Mul,

    // —— MIT-307 movsxd（32→64 位符号扩展，x64 专用）——
    // Movsxd (Reg-Reg): dst = sign_extend_32(src)，native "movsxd dst, src"。
    // a_kind=Reg, reg_a=dst, b_kind=Reg, reg_b=src, aux=0, cond_or_size=3 (S64)。
    // handler 用 movsxd t_[0], dword ptr [ctx + reg_b*8 + 0x10] 直接 32→64
    // 符号扩展 + 写回 [ctx + reg_a*8 + 0x10]。不更新 flags。
    Movsxd,
    // MovsxdMem (Reg-Mem): dst = sign_extend_32([addr])，addr 在 reg_b VM 槽里。
    // a_kind=Reg, reg_a=dst, b_kind=Reg, reg_b=address 槽（翻译器 emit_address 已
    // 把地址算到 scratch 槽, 本 handler 读该槽作地址）。
    // handler: mov t_[1], [ctx + reg_b*8 + 0x10]（取地址）
    //         movsxd t_[0], dword ptr [t_[1]]（32 位 load + 符号扩展）
    //         mov [ctx + reg_a*8 + 0x10], t_[0]（写回 64 位 dst）
    // 不更新 flags。
    MovsxdMem,
    // —— MIT-315 movzx（8→32/64 位零扩展，x64/x86 都支持）——
    // Movzx (Reg-Reg): dst = zero_extend_8(src)，native "movzx dst, byte ptr [..]"。
    // a_kind=Reg, reg_a=dst, b_kind=Reg, reg_b=src, aux=0, cond_or_size=size。
    // handler 用 byte ptr 读 src VM 槽低 8 位（按 alias_read 自动零扩展到完整
    // 64 位），movzx 到 t_[0] 后写回 dst VM 槽（qword）。不更新 flags。
    Movzx,
    // MovzxMem (Reg-Mem): dst = zero_extend_8([addr])，addr 在 reg_b VM 槽里。
    // a_kind=Reg, reg_a=dst, b_kind=Reg, reg_b=address 槽（翻译器 emit_address 已
    // 把地址算到 scratch 槽, 本 handler 读该槽作地址）。
    // handler: mov t_[1], [ctx + reg_b*8 + 0x10]    (取地址)
    //         movzx t_[0], byte ptr [t_[1]]          (8 位 load + 零扩展)
    //         mov [ctx + reg_a*8 + 0x10], t_[0]      (写回 64 位 dst)
    // 不更新 flags。
    MovzxMem,

    // —— MIT-322 lea rip-relative 配套 ——
    // LoadRva/StoreRva 把 RVA 转 VA 后访存, 但 lea 只需地址本身, 不访存.
    // LeaaRva 与 LoadRva/StoreRva 形态相同 (a=Reg, b=Reg-地址), 运行时
    // **额外**加上 VmContext.scratch_mem (=image_base) 还原 RVA → VA 后直接写回
    // reg_a 槽 (不访存). 用于翻译期把 lea [rip+disp] 转 RVA 的场景——
    // 后续非 rip Load/Store 把该地址当绝对 VA 访存 (M2-8 起 Load/Store 不再加
    // scratch_mem, 见 LoadRva 注释).
    // a_kind=Reg, reg_a=dst (写入 VA), b_kind=Reg, reg_b=RVA 槽, aux=0.
    // handler: mov t_[1], [ctx + reg_b*8 + 0x10]    (读 reg_b 槽 = RVA)
    //         add t_[1], [ctx + 0x110]             (RVA += image_base → VA)
    //         mov [ctx + reg_a*8 + 0x10], t_[1]    (VA 写回 reg_a 槽)
    // cond_or_size = size (lea 不写子寄存器别名, 但保持字节码格式一致).
    // 修复 snake 真虚拟化 byte-exact 闭环: `lea rcx, [rip+0x6dfa]` 翻译期
    // 发 RVA, 运行时 +image_base 让 rcx = VA, 后续 `[rcx + rax*4]` Load 才
    // 能读到正确数组元素.
    LeaRva,

    // —— MIT-333 字节序反转 (bswap reg32 / bswap reg64) ——
    // Bswap (Reg): dst = byte_swap(dst), 单操作数 (dst only, no src).
    // a_kind=Reg, reg_a=dst, b_kind=None, aux=0, cond_or_size=size (S32 或 S64).
    // handler:
    //   - S32 (无 REX.W): mov eax, dword ptr [ctx + reg_a*8 + 0x10]
    //                     bswap eax
    //                     mov qword ptr [ctx + reg_a*8 + 0x10], rax
    //   - S64 (REX.W):   mov rax, qword ptr [ctx + reg_a*8 + 0x10]
    //                     bswap rax
    //                     mov qword ptr [ctx + reg_a*8 + 0x10], rax
    // bswap 不影响 flags. S8/S16 bswap 不存在 (Intel SDM),
    // lifter 仅产 S32/S64; handler S8/S16 块走 no-op (defensive).
    Bswap,

    // —— MIT-334 寄存器/内存交换 (xchg r, r / xchg r, m) ——
    // Xchg (Reg-Reg): dst ↔ src, 2 操作数 (a + b 都是寄存器).
    // a_kind=Reg, reg_a=dst, b_kind=Reg, reg_b=src, aux=0, cond_or_size=size.
    // xchg 是对称操作 (Intel SDM Vol. 2 XCHG: xchg a, b == xchg b, a),
    // 翻译器在 REG-REG 时按 IR.dst / IR.src 直产 VmOp::Xchg (a=dst, b=src);
    // MEM-REG 派活单限定不支持 (lifter 拒 MEM → C1 gate 兜底).
    // handler:
    //   - S32 (无 REX.W): mov eax, dword ptr [ctx + reg_a*8 + 0x10]  (低 32 位)
    //                     mov ebx, dword ptr [ctx + reg_b*8 + 0x10]  (低 32 位)
    //                     xchg eax, ebx                              (swap 低 32 位,
    //                                                              上 32 位 rax/rbx 保留)
    //                     mov dword ptr [ctx + reg_a*8 + 0x10], eax  (写回低 32 位,
    //                                                              上 32 位 slot 保留)
    //                     mov dword ptr [ctx + reg_b*8 + 0x10], ebx  (写回低 32 位)
    //   - S64 (REX.W):   mov t0, qword ptr [ctx + reg_a*8 + 0x10]   (full 64)
    //                     mov t1, qword ptr [ctx + reg_b*8 + 0x10]   (full 64)
    //                     xchg t0, t1                                (swap full 64)
    //                     mov qword ptr [ctx + reg_a*8 + 0x10], t0
    //                     mov qword ptr [ctx + reg_b*8 + 0x10], t1
    // xchg 不影响 flags (CF/OF/SF/ZF/PF 不变); 不更新 flags 槽.
    // 派活单 §D 决策 4: Xchg 必 append-only 在 Bswap=48 之后 = 49 (pitfall #34).
    Xchg,

    // —— MIT-336 条件设置字节 (setcc r/m8, 16 variants) ——
    // Setcc (Reg-Reg / Reg-Mem): dst = (cond(flags) ? 1 : 0), 单操作数 (dst only).
    // 字节结构: 0F 90+cc+rm (3 字节; mod=11 REG, mod=00 MEM).
    // a_kind=Reg reg_a=dst, b_kind=None, aux=0, cond_or_size=ir::Cond 0..15.
    //   - REG-REG (setcc al/bl/cl/.../r8b): dst=Reg 8-bit 子寄存器 (lifter 子寄存器折叠到
    //     全寄存器, handler 读低 8 位/写低 8 位)
    //   - MEM (setcc [m]): dst=Mem, lifter 直接 emit Operand::mem_(...); 翻译器折 SetccMem,
    //     类似 Movsxd/Movzx 的 REG-MEM 拆条模式 (pitfall #22h 启发)
    // setcc 是**条件设置**, 不修改 flags (CF/OF/SF/ZF/PF 不变); 但 reads flags 决定 0/1 结果.
    // updates_flags=false (与 Jcc/setcc 一致——flags 由前置 cmp/test/sub 等产生, 这里只是消费).
    // size 字段作 16-condition (cc) 编码 (与 Jcc 共享 cond_or_size 字段, 4 bits=16 variants).
    // 派活单 §D 决策 4: Setcc 必 append-only 在 Xchg=49 之后 = 50 (pitfall #34).
    Setcc,

    // —— MIT-339 条件移动 (cmovcc r, r/m, 16 variants) ——
    // Cmovcc (Reg-Reg / Reg-Mem): dst = cond(flags) ? src : dst, 2 操作数.
    // 字节结构：[48] (REX.W 可选) | 0F 40+cc | ModR/M (3 字节 REX.W;
    // 3 字节无 REX.W; mod=11 REG-REG, mod=00 MEM).
    // a_kind=Reg reg_a=dst, b_kind=Reg reg_b=src, aux=0, cond_or_size=ir::Cond 0..15.
    //   - REG-REG (cmovcc r64, r64): a=dst 寄存器, b=src 寄存器。
    //   - MEM (cmovcc r64, [m]): lifter 直接 emit Operand::mem_(...); 翻译器折
    //     Load(tmp, [m], size) + Cmovcc(dst, tmp) 两条 (与 movzx MEM 路径同结构)。
    //     严格遵循派活单 §D 改动清单 (仅加 VmOp::Cmovcc, 不加 CmovccMem)。
    // cmovcc **reads** flags (CF/OF/SF/ZF/PF) 决定是否赋值, **不**改 flags
    // (CF/OF/SF/ZF/PF 不变); updates_flags=false (与 Setcc 一致——flags 由前置
    // cmp/test/sub 等产生, 这里只是消费)。
    // size 字段作 16-condition (cc) 编码 (与 Jcc/Setcc 共享 cond_or_size 字段,
    // 4 bits=16 variants); 真实位宽由 IR.size 字段另传 (S32 / S64 由 REX.W 决定)。
    // 派活单 §D 决策 4: Cmovcc 必 append-only 在 Setcc=50 之后 = 51 (pitfall #34)。
    Cmovcc,

    // MIT-341: 比较并交换 (cmpxchg r/m, r, 隐式 rax/al 累加器)。
    //   Cmpxchg (Reg-Reg / Mem-Reg):
    //     if (Rax == dst) { ZF=1; dst = src }
    //     else              { ZF=0; Rax = dst }
    //   字节结构: [48] (REX.W 可选) | 0F B0/B1+rm (mod=11 REG-REG, mod=00 MEM-REG;
    //     mod=01/10 派活单限定不支持)。S8 用 0F B0, S16/S32/S64 用 0F B1。
    //   a_kind=Reg reg_a=dst, b_kind=Reg reg_b=src, aux=0,
    //   cond_or_size=ir::Size (S8/S16/S32/S64, 与 ALU binop 共享 2 bits)。
    //   REG-REG (cmpxchg r64, r64): a=dst, b=src。
    //   MEM (cmpxchg [m], r): lifter 直接 emit Operand::mem_(...) 到 dst;
    //     翻译器折 Load(tmp, [m], size) + Cmpxchg(tmp, r) + Store([m], tmp, size)
    //     三条拆条 (与 setcc MEM 路径同结构, 沿用 pitfall #22h 启发)。
    //     严格遵循派活单 §D 改动清单 (仅加 VmOp::Cmpxchg, 不加 CmpxchgMem)。
    //   隐式 acc: handler 硬编码读 regs[Rax] (= vm_reg_of(Rax) 槽, slot 0),
    //     按 cond_or_size 选 8/16/32/64 位宽度 native `cmpxchg`, 再写回 dst 槽
    //     与 Rax 槽。Rax 槽是 VM 寄存器槽表的固定位置, 无需新增 IR 字段即可定位
    //     (沿用 pitfall #34 additive enum append-only 不破坏 Insn 布局/大小)。
    //   cmpxchg **writes** flags (CF/OF/SF/ZF/PF 全更新, 与 cmp 同语义);
    //     handler 用 native cmpxchg 直读 host CPU flags, setcc5 捕获 — 与
    //     imul/mul/shift 等 ALU 路径共享 zero5 + setcc5 + flags_tail 复用。
    //   派活单 §D 决策 4: Cmpxchg 必 append-only 在 Cmovcc 之后
    //     (pitfall #34 additive enum append-only); 派活单限定不支持 lock prefix
    //     (lock cmpxchg 涉及 atomic 语义, 需独立 issue 调试 VM runtime)。
    Cmpxchg,
    // —— MIT-347 movsx（8/16→32/64 位有符号扩展，x64/x86 都支持）——
    // Movsx (Reg-Reg): dst = sign_extend_8/16(src)，native "movsx dst, src"。
    // a_kind=Reg, reg_a=dst, b_kind=Reg, reg_b=src, aux=src_size (低 2 位:
    // S8=0 / S16=1), cond_or_size=size (S32 / S64)。
    // handler 用 byte ptr / word ptr 读 src VM 槽低 8/16 位（按 alias_read 自动
    // 零扩展到完整 64 位），movsx 到 t_[0] 后写回 dst VM 槽（qword，符号扩展
    // 结果落到高 56/48 位）。不更新 flags。
    Movsx,
    // MovsxMem (Reg-Mem): dst = sign_extend_8/16([addr])，addr 在 reg_b VM 槽里。
    // a_kind=Reg, reg_a=dst, b_kind=Reg, reg_b=address 槽（翻译器 emit_address 已
    // 把地址算到 scratch 槽, 本 handler 读该槽作地址）。
    // handler: mov t_[1], [ctx + reg_b*8 + 0x10]    (取地址)
    //         movsx t_[0], byte/word ptr [t_[1]]    (8/16 位 load + 符号扩展)
    //         mov [ctx + reg_a*8 + 0x10], t_[0]      (写回 64 位 dst)
    // 不更新 flags。
    MovsxMem,
    // —— MIT-349 比特计数 (popcnt r, r/m, SSE4.2) ——
    // Popcnt (Reg-Reg): dst = count_ones(src)，native `popcnt <sz> dst, src`。
    // a_kind=Reg, reg_a=dst, b_kind=Reg, reg_b=src, aux=0, cond_or_size=size
    //   (S32 或 S64 由 REX.W 决定, lifter 已传过来)。
    // 派活单限定不支持 MEM 形式 (沿用 movzx/movsx 限定风格, 完全不支持 MEM
    // 不像 movzx/movsx 沿用 MovzxMem/MovsxMem 单独处理)——lifter 拒 MEM → C1
    // gate 兜底。
    // handler: popcnt <sz> t_[0], t_[1]                  (T0 = popcnt(T1))
    //          mov qword ptr [ctx + reg_a*8 + 0x10], t_[0]  (写回 dst)
    // popcnt 不影响 flags (CF/OF/SF/ZF/PF 不变); updates_flags=false。
    // 派活单 §D 决策 4: Popcnt 必 append-only 在 MovsxMem 之后 (pitfall #34)。
    Popcnt,
    // —— MIT-353 前导零计数 (lzcnt r, r/m, BMI1) ——
    // Lzcount (Reg-Reg): dst = count_leading_zeros(src)，native `lzcnt <sz> dst, src`。
    // a_kind=Reg, reg_a=dst, b_kind=Reg, reg_b=src, aux=0, cond_or_size=size
    //   (S32 或 S64 由 REX.W 决定, lifter 已传过来)。
    // 派活单限定不支持 MEM 形式 (沿用 popcnt 限定风格, 完全不支持 MEM)。
    // handler: lzcnt <sz> t_[0], t_[1]                    (T0 = lzcnt(T1))
    //          mov qword ptr [ctx + reg_a*8 + 0x10], t_[0]  (写回 dst)
    //   **关键 (pitfall #37)**: lzcnt 与 popcnt 不同 — lzcnt 不修改 src
    //   (native lzcnt r, r/m 只写 dst, src 寄存器保留), 但 handler 必须
    //   先 `mov T6, T1` 保存 src (T1) 到 T6, 再 `lzcnt t_[0], t_[1]`
    //   (dst 写到 T0). 这与 popcnt "T1 in-place, 不需 T6 保存" 不同 —
    //   popcnt 的源寄存器被消耗可重用 T1, lzcnt 的源寄存器必须保留.
    // 不影响 flags (CF/OF/SF/ZF/PF 不变); updates_flags=false。
    // 派活单 §D 决策 4: Lzcount 必 append-only 在 Popcnt 之后 (pitfall #34)。
    Lzcount,
    // —— MIT-353 末尾零计数 (tzcnt r, r/m, BMI1) ——
    // Tzcount (Reg-Reg): dst = count_trailing_zeros(src)，native `tzcnt <sz> dst, src`。
    // a_kind=Reg, reg_a=dst, b_kind=Reg, reg_b=src, aux=0, cond_or_size=size
    //   (S32 或 S64 由 REX.W 决定, lifter 已传过来)。
    // 派活单限定不支持 MEM 形式 (沿用 popcnt 限定风格, 完全不支持 MEM)。
    // handler: tzcnt <sz> t_[0], t_[1]                    (T0 = tzcnt(T1))
    //          mov qword ptr [ctx + reg_a*8 + 0x10], t_[0]  (写回 dst)
    //   **关键 (pitfall #37)**: tzcnt 与 popcnt 不同 — tzcnt 不修改 src
    //   (native tzcnt r, r/m 只写 dst, src 寄存器保留), 但 handler 必须
    //   先 `mov T6, T1` 保存 src (T1) 到 T6, 再 `tzcnt t_[0], t_[1]`
    //   (dst 写到 T0). 与 lzcnt 路径一致, 同源 pitfall #37 守恒.
    // 不影响 flags (CF/OF/SF/ZF/PF 不变); updates_flags=false。
    // 派活单 §D 决策 4: Tzcount 必 append-only 在 Lzcount 之后 (pitfall #34)。
    Tzcount,

    // —— MIT-371 SSE 浮点加 (addss / addps / addpd)——
    // Addss (Reg-Reg, scalar single):
    //   xmm1 = xmm1 + xmm2 (low 32-bit float, scalar); upper 96 bits unchanged。
    //   字节结构: F3 0F 58 /r (3 字节 REG-REG, mod=11)。
    //   a_kind=Reg reg_a=dst (xmm1), b_kind=Reg reg_b=src (xmm2),
    //   aux=0, cond_or_size=ir::Size::S32 (scalar single)。
    //   handler: movups xmm0, [ctx + reg_a*8 + 0x10]    (读 dst xmm)
    //            movups xmm1, [ctx + reg_b*8 + 0x10]    (读 src xmm)
    //            addss xmm0, xmm1                       (scalar 单精度浮点加)
    //            movups [ctx + reg_a*8 + 0x10], xmm0    (写回 dst xmm)
    //   不影响 EFLAGS (CF/OF/SF/ZF/PF 不变); updates_flags=false。
    Addss,
    // Addps (Reg-Reg, packed single):
    //   xmm1 = xmm1 + xmm2 (4 个 f32 packed, lane-parallel); 全 128-bit。
    //   字节结构: 0F 58 /r (3 字节 REG-REG, mod=11)。
    //   a_kind=Reg reg_a=dst (xmm1), b_kind=Reg reg_b=src (xmm2),
    //   aux=0, cond_or_size=ir::Size::S64 (packed 128-bit; handler 用
    //   movups 全 128-bit 读写; size 字段沿用 S64 占位表示 "xmm 宽")。
    //   handler: movups xmm0, [ctx + reg_a*8 + 0x10]    (读 dst xmm)
    //            movups xmm1, [ctx + reg_b*8 + 0x10]    (读 src xmm)
    //            addps xmm0, xmm1                       (packed 单精度 4-lane 加)
    //            movups [ctx + reg_a*8 + 0x10], xmm0    (写回 dst xmm)
    //   不影响 EFLAGS; updates_flags=false。
    Addps,
    // Addpd (Reg-Reg, packed double):
    //   xmm1 = xmm1 + xmm2 (2 个 f64 packed, lane-parallel); 全 128-bit。
    //   字节结构: 66 0F 58 /r (3 字节 REG-REG, mod=11, 0x66 prefix 隐式)。
    //   a_kind=Reg reg_a=dst (xmm1), b_kind=Reg reg_b=src (xmm2),
    //   aux=0, cond_or_size=ir::Size::S64 (packed 128-bit; 同 Addps)。
    //   handler: movups xmm0, [ctx + reg_a*8 + 0x10]    (读 dst xmm)
    //            movups xmm1, [ctx + reg_b*8 + 0x10]    (读 src xmm)
    //            addpd xmm0, xmm1                       (packed 双精度 2-lane 加)
    //            movups [ctx + reg_a*8 + 0x10], xmm0    (写回 dst xmm)
    //   不影响 EFLAGS; updates_flags=false。
    //   派活单 §D 决策: Addss/Addps/Addpd 必 append-only 在 Tzcount 之后
    //   (pitfall #34 additive enum append-only)。
    Addpd,

    // —— MIT-373 SSE 浮点减 (subss / subps / subpd)——
    // Subss (Reg-Reg, scalar single):
    //   xmm1 = xmm1 - xmm2 (low 32-bit float, scalar); upper 96 bits unchanged。
    //   字节结构: F3 0F 5C /r (REG-REG, mod=11)。
    //   a_kind=Reg reg_a=dst (xmm1), b_kind=Reg reg_b=src (xmm2),
    //   aux=0, cond_or_size=ir::Size::S32 (scalar single)。
    //   handler: movups xmm0, [ctx + reg_a*8 + 0x10]    (读 dst xmm)
    //            movups xmm1, [ctx + reg_b*8 + 0x10]    (读 src xmm)
    //            subss xmm0, xmm1                       (scalar 单精度浮点减)
    //            movups [ctx + reg_a*8 + 0x10], xmm0    (写回 dst xmm)
    //   不影响 EFLAGS (CF/OF/SF/ZF/PF 不变); updates_flags=false。
    Subss,
    // Subps (Reg-Reg, packed single):
    //   xmm1 = xmm1 - xmm2 (4 个 f32 packed, lane-parallel); 全 128-bit。
    //   字节结构: 0F 5C /r (REG-REG, mod=11)。
    //   a_kind=Reg reg_a=dst (xmm1), b_kind=Reg reg_b=src (xmm2),
    //   aux=0, cond_or_size=ir::Size::S64 (packed 128-bit; handler 用
    //   movups 全 128-bit 读写; size 字段沿用 S64 占位表示 "xmm 宽")。
    //   handler: movups xmm0, [ctx + reg_a*8 + 0x10]    (读 dst xmm)
    //            movups xmm1, [ctx + reg_b*8 + 0x10]    (读 src xmm)
    //            subps xmm0, xmm1                       (packed 单精度 4-lane 减)
    //            movups [ctx + reg_a*8 + 0x10], xmm0    (写回 dst xmm)
    //   不影响 EFLAGS; updates_flags=false。
    Subps,
    // Subpd (Reg-Reg, packed double):
    //   xmm1 = xmm1 - xmm2 (2 个 f64 packed, lane-parallel); 全 128-bit。
    //   字节结构: 66 0F 5C /r (REG-REG, mod=11, 0x66 prefix 隐式)。
    //   a_kind=Reg reg_a=dst (xmm1), b_kind=Reg reg_b=src (xmm2),
    //   aux=0, cond_or_size=ir::Size::S64 (packed 128-bit; 同 Subps)。
    //   handler: movups xmm0, [ctx + reg_a*8 + 0x10]    (读 dst xmm)
    //            movups xmm1, [ctx + reg_b*8 + 0x10]    (读 src xmm)
    //            subpd xmm0, xmm1                       (packed 双精度 2-lane 减)
    //            movups [ctx + reg_a*8 + 0x10], xmm0    (写回 dst xmm)
    //   不影响 EFLAGS; updates_flags=false。
    //   派活单 §D 决策: Subss/Subps/Subpd 必 append-only 在 Addss/Addps/Addpd
    //   之后 (pitfall #34 additive enum append-only)。
    Subpd,

    // —— MIT-374 SSE 浮点除 (divss / divps / divpd)——
    // Divss (Reg-Reg, scalar single):
    //   xmm1 = xmm1 / xmm2 (low 32-bit float, scalar); upper 96 bits unchanged。
    //   字节结构: F3 0F 5E /r (REG-REG, mod=11; capstone 5.0.7 实证 F30F5EC1)。
    //   a_kind=Reg reg_a=dst (xmm1), b_kind=Reg reg_b=src (xmm2),
    //   aux=0, cond_or_size=ir::Size::S32 (scalar single)。
    //   handler: movups xmm0, [ctx + reg_a*8 + 0x10]    (读 dst xmm)
    //            movups xmm1, [ctx + reg_b*8 + 0x10]    (读 src xmm)
    //            divss xmm0, xmm1                       (scalar 单精度浮点除)
    //            movups [ctx + reg_a*8 + 0x10], xmm0    (写回 dst xmm)
    //   不影响 EFLAGS (CF/OF/SF/ZF/PF 不变); updates_flags=false。
    Divss,
    // Divps (Reg-Reg, packed single):
    //   xmm1 = xmm1 / xmm2 (4 个 f32 packed, lane-parallel); 全 128-bit。
    //   字节结构: 0F 5E /r (REG-REG, mod=11; capstone 实证 0F5EC1)。
    //   a_kind=Reg reg_a=dst (xmm1), b_kind=Reg reg_b=src (xmm2),
    //   aux=0, cond_or_size=ir::Size::S64 (packed 128-bit; handler 用
    //   movups 全 128-bit 读写; size 字段沿用 S64 占位表示 "xmm 宽")。
    //   handler: movups xmm0, [ctx + reg_a*8 + 0x10]    (读 dst xmm)
    //            movups xmm1, [ctx + reg_b*8 + 0x10]    (读 src xmm)
    //            divps xmm0, xmm1                       (packed 单精度 4-lane 除)
    //            movups [ctx + reg_a*8 + 0x10], xmm0    (写回 dst xmm)
    //   不影响 EFLAGS; updates_flags=false。
    Divps,
    // Divpd (Reg-Reg, packed double):
    //   xmm1 = xmm1 / xmm2 (2 个 f64 packed, lane-parallel); 全 128-bit。
    //   字节结构: 66 0F 5E /r (REG-REG, mod=11, 0x66 prefix 隐式; 实证 660F5EC1)。
    //   a_kind=Reg reg_a=dst (xmm1), b_kind=Reg reg_b=src (xmm2),
    //   aux=0, cond_or_size=ir::Size::S64 (packed 128-bit; 同 Divps)。
    //   handler: movups xmm0, [ctx + reg_a*8 + 0x10]    (读 dst xmm)
    //            movups xmm1, [ctx + reg_b*8 + 0x10]    (读 src xmm)
    //            divpd xmm0, xmm1                       (packed 双精度 2-lane 除)
    //            movups [ctx + reg_a*8 + 0x10], xmm0    (写回 dst xmm)
    //   不影响 EFLAGS; updates_flags=false。
    //   派活单 §D 决策: Divss/Divps/Divpd 必 append-only 在 Subss/Subps/Subpd
    //   之后 (pitfall #34 additive enum append-only)。
    //   ⚠️ divsd (F2 0F 5E, scalar double) 不在本单范围 (派活单只列 3 形式)。
    Divpd, Movss, Movaps, Movapd, Movups, Movupd,

    // —— MIT-376 SSE 浮点位运算 + 浮点比较 (xorps / orps / andps / ucomiss / ucomisd)——
    // Xorps (Reg-Reg, packed bitwise xor):
    //   xmm1 = xmm1 XOR xmm2 (全 128-bit 按位异或, 不解释浮点值)。
    //   字节结构: 0F 57 /r (REG-REG, mod=11; capstone 实证 0F57C1)。
    //   a_kind=Reg reg_a=dst (xmm1), b_kind=Reg reg_b=src (xmm2),
    //   aux=0, cond_or_size=ir::Size::S64 (128-bit 整体读写)。
    //   handler (沿用 MIT-375 build_xmm_transfer 四步模板, xmm 槽位 @ ctx+0x140):
    //            movups xmm0, [ctx + 0x140 + (reg_a-24)*16]   读 dst
    //            movups xmm1, [ctx + 0x140 + (reg_b-24)*16]   读 src
    //            xorps xmm0, xmm1
    //            movups [ctx + 0x140 + (reg_a-24)*16], xmm0   写回 dst
    //   不影响 EFLAGS; updates_flags=false。
    Xorps,
    // Orps (Reg-Reg, packed bitwise or): 同 Xorps, 字节结构 0F 56 /r (实证 0F56C1)。
    Orps,
    // Andps (Reg-Reg, packed bitwise and): 同 Xorps, 字节结构 0F 54 /r (实证 0F54C1)。
    Andps,
    // Ucomiss (Reg-Reg, scalar single unordered compare):
    //   比较 xmm1[31:0] 与 xmm2[31:0], **只写 EFLAGS ZF/PF/CF, 不改 xmm 操作数**。
    //   字节结构: 0F 2E /r (REG-REG, mod=11; capstone 实证 0F2EC1; F3 0F 2E 不存在)。
    //   a_kind=Reg reg_a=dst (xmm1), b_kind=Reg reg_b=src (xmm2),
    //   aux=0, cond_or_size=ir::Size::S32 (scalar single)。
    //   handler 走 ALU binop 同一条 flags 通路 (zero5 → native ucomiss → setcc5 →
    //   flags_tail), setcc/jcc handler 读同一 flags_ 寄存器 (派活单 §D D1.1 决策,
    //   禁止 decode+advance 空转, pitfall #79)。
    //   Intel SDM UCOMISS 真值表: greater → ZF=CF=0 / less → CF=1 / equal → ZF=1 /
    //   unordered (NaN) → ZF=PF=CF=1; OF/SF/AF 由 native ucomiss 清 0 (SDM:
    //   "The OF, SF, AF flags are set to 0"), flags_tail 按位布局
    //   ZF/CF/OF/SF/PF=bit0..4 装配即得 SDM 语义。
    //   updates_flags=**true**。
    Ucomiss,
    // Ucomisd (Reg-Reg, scalar double unordered compare):
    //   同 Ucomiss, 比较低 64 位 f64; 字节结构 66 0F 2E /r (实证 660F2EC1)。
    //   cond_or_size=ir::Size::S64 (scalar double)。updates_flags=true。
    Ucomisd,

    // —— MIT-404 整数除法族 + 符号扩展 (Cdq / Div / Idiv) ——
    // Cdq (零操作数): 隐式 rax → rdx 符号扩展。cdq=99 (S32) / cqo=48 99 (S64),
    //   cond_or_size=size 区分 (handler 按 size 选 native 指令)。
    //   a_kind/b_kind/reg_a/reg_b/aux 一律空 (隐式操作数不经字节码表达)。
    //   handler: 读 Rax 槽 → 物理 RAX → native cdq/cqo 直通 (真 99 字节,
    //   §D.6 capstone 回读锚点) → 物理 RDX 写回 Rdx 槽 → advance。
    //   不影响 EFLAGS (Intel SDM) — 不调 setcc5 也不走 flags_tail (零 flags
    //   写回, flags_ 原样保留); 仅需生成器期防护 pc_/flags_ 落在物理
    //   rax/rdx (native cdq/cqo 直写)。cwd (66 99, S16) 因 0x66 prefix 在
    //   lifter 入口被拒不可达, handler S16 分支为模板完备的防御路径。
    Cdq,
    // Div (单操作数): 无符号除, 隐式 dividend = rdx:rax (S32: edx:eax)。
    //   a_kind=Reg reg_a=Rdx 槽 tag (对齐 Mul 约定), b_kind=Reg reg_b=除数槽
    //   (REG 直发; MEM 形式由翻译器折 Load + Div, rip 形式除数走 LoadRva),
    //   aux=0, cond_or_size=size (S32/S64; S8 dividend=AX 语义不符 lifter 拒,
    //   S16 需 0x66 prefix 入口已拒)。
    //   handler (对齐 build_mul 双结果槽协议): 除数 → T0 (callee-saved) →
    //   zero5 → 物理 RDX:RAX ← Rdx/Rax 双槽 → native div <sz> T0 直通 →
    //   商 (rax) 写 Rax 槽 + 余 (rdx) 写 Rdx 槽 → setcc5 → flags_tail。
    //   flags 按 Intel undefined — 处置照抄 build_imul (zero5 → native →
    //   setcc5 → flags_tail, 同 CPU 真值与 native 执行一致, D4.1)。
    //   除零/商溢出 = 真 #DE, native 直通崩溃形态与未加壳一致 (D2.1)。
    Div,
    // Idiv (单操作数): 有符号除, 余数截断向零 (Intel 语义, D3.1)。其余与
    //   Div 完全同构 (native idiv, F7 /7); 负被除数经 cqo/cdq 符号扩展进
    //   Rdx 槽后 native idiv 直接处理, 无需额外逻辑。
    Idiv,

    // —— MIT-407 ExitNative（区域外跳转单向退出到 native）——
    // 单向退出：越过区域 END 但落在同一函数 .pdata 边界内的跳转目标时，
    // 翻译期发 ExitNative；运行时复用 stub HALT 写回链（rax/rcx/rdx/r8-r11
    // + xmm0-7 + add rsp/pop）→ 间接 jmp 到 aux 指定的 RVA，**不再回 VM**。
    //   - aux = 目标 RVA（u32 零扩展；handler 加 image_base 后写 EXIT_SLOT）
    //   - 无条件直退: a_kind=Imm（handler 解 t_[3]==2 跳过条件链）。注意
    //     cond_or_size 是 4 位字段（encode 端 validate_insn 拒绝 >15），
    //     不存在 0xFF sentinel——v1 草案的 0xFF 设计启用即抛，已废弃。
    //   - 条件退出: cond_or_size = ir::Cond (0..15) 走条件退出（12/17 站点，
    //     triage §6.7），条件由 dispatch 解出 cond 后复用 build_jcc 的
    //     cond_eval 链；不满足则 advance 继续 VM
    //   - 5/17 站点为 jmp（无条件），a_kind=Imm + cond=0
    // 契约：
    //   - 出口 rsp == entry rsp（与 callgate 同一 native_sp 基准，本语料
    //     14 区域 0 push / 0 rsp 调整实测成立；若未来区域含未配平 push，
    //     现行 HALT 链同样会按 entry rsp 恢复，属既有潜在约束）
    //   - EFLAGS 不回写：15 去重落点实测均先覆写 flags 再读，落点不消费
    //     flags；属本语料实测契约，非普适证明（§2.4 / §F.2 披露）
    //   - 间接 jmp / ret 目标维持 gate（C 双向分段不在本单）
    // 运行时通道 = EXIT_SLOT（native_sp - kExitSlotDepth，runtime.hpp 单一
    // 事实来源）：stub 入口预写 VA(resume_rva)，ExitNative handler 命中时
    // 覆写 VA(aux)；stub HALT 终态 `jmp [rsp - kExitSlotDepth]` 间接跳出。
    // 槽内容必须是绝对 VA（image_base + RVA），禁止裸 RVA（v1 segfault 根因）。
    // 派活单 §D 决策: ExitNative 必 append-only 在 Idiv 之后 (pitfall #34
    // additive enum append-only)；kVmOpMax+1=80 < 128 跳表 (asmgen.cpp
    // static_assert(kVmOpMax < kTableEntries))。
    ExitNative,

    // —— MIT-408 SSE scalar-double (sd) 族: addsd/subsd/divsd/movsd ——
    // 与 ss/ps/pd 三族同构的 REG-REG 形式。IR 编码借用既有 ir::Op +
    // Size::S64 双语义 ((Addss,S64)=addsd, (Subss,S64)=subsd, (Divss,S64)=
    // divsd, (Movss,S64)=movsd)——ir::Op 是冻结契约不可增枚举, (op,size)
    // 组合在旧 lifter 中从不产生 (addss 恒 S32), 无歧义。字节结构:
    //   - movsd xmm1, xmm2   F2 0F 10 /r  (标量 double, **只搬低 64 位,
    //     高 64 位保持不变**——与 movss 同语义, 内存源形式的清零语义由
    //     XmmLoad handler 的 native movsd 直产)
    //   - addsd xmm1, xmm2   F2 0F 58 /r  (scalar double 加, 低 64 位)
    //   - subsd xmm1, xmm2   F2 0F 5C /r  /  divsd xmm1, xmm2  F2 0F 5E /r
    //   cond_or_size=ir::Size::S64 (scalar double 8B 占位, 与 packed S64
    //   tag 由 opcode 区分)。不影响 EFLAGS; updates_flags=false。
    // 派活单 §D 决策: 4 op 必 append-only 在 ExitNative 之后 (pitfall #34)。
    Movsd, Addsd, Subsd, Divsd,

    // —— MIT-408 SSE mem 形式原语: XmmLoad / XmmStore ——
    // xmm 槽 ↔ [VA] 访存 (movss=4B / movsd=8B / movups=16B, 宽度经 aux)。
    // 运行时一律 movups 非对齐语义 (D2: PE 不保证全局 16B 对齐, 用对齐版
    // 指令=埋 #GP 雷; movaps/movapd 的 mem 形式同样走本通路)。
    //   XmmLoad:  a_kind=Reg reg_a=目的槽, b_kind=Reg reg_b=地址槽, aux=宽度。
    //     reg_a >= 24 = ctx.xmm 区 (0x140+(reg-24)*16); reg_a < 24 = GP
    //     scratch 双槽 (0x10+reg*8, 16B 覆盖 vN+vN+1)——ALU src=mem 形式
    //     的临时槽编码 (MIT-408 设计: 不动 VmContext 布局, 借用 v18..v23
    //     两两作 xmm 宽临时, 指令边界后即死)。native 指令的 movss/movsd
    //     **清零语义**由 movss/movsd xmm0,[mem] 直产 (SDM: 内存源清零
    //     高位), movups 全 128-bit。
    //   XmmStore:  a_kind=Reg reg_a=地址槽, b_kind=Reg reg_b=源槽 (同上
    //     双语义), aux=宽度。写 [VA] 前先把槽 128-bit 读进 xmm0 (movups),
    //     再按宽度 movss/movsd/movups [addr], xmm0 落盘 (低宽度截断)。
    //   rip-relative: 翻译器先 emit_address (RVA) + 既有 LeaRva (RVA→VA),
    //     再走本对原语——不加 LoadRva/StoreRva 变体, 复用既有通道。
    //   不影响 EFLAGS; 不调 setcc5 也不走 flags_tail, 直接 advance。
    // 派活单 §D 决策: 2 op 必 append-only 在 Divsd 之后 (pitfall #34);
    // kVmOpMax+1=86 < 128 跳表余量充足。
    XmmLoad, XmmStore,

    // —— MIT-419 (G4): lock 前缀原子族 strip-and-execute ——
    // Xadd (Mem-Reg): [addr] = [addr] + reg_b; reg_b = 旧 [addr] (返回旧值
    //   = InterlockedAdd 真产物, lock xadd [m], r)。**单 VmOp 直执行 native
    //   lock xadd [addr], reg** — 一条指令完成读改写, 硬件原子性保真
    //   (D1 的折条妥协不适用于本指令; xadd 不在 ALU mem-dst 折条面)。
    //   a_kind=Reg reg_a=地址槽 (翻译器 emit_address 产出, 与 Load/Store
    //   同通道), b_kind=Reg reg_b=源寄存器槽, aux=0, cond_or_size=size
    //   (S8/S32/S64; S16 需 66 前缀 lifter 入口已拒, handler S16 块防御
    //   no-op)。flags = add 语义 (CF/OF/SF/ZF/PF 全更新), zero5 → native
    //   lock xadd → setcc5 → flags_tail (与 cmpxchg/ALU 同通路)。
    //   handler 内 [addr] 访存是**真内存** (VM 与宿主同进程地址空间) —
    //   多线程并发下硬件原子性由 lock 前缀保真, 不落 D1 折条边界。
    Xadd,
    // Bts / Btr / Btc (Mem-Reg/Imm): CF = bit[位号] of [addr]; [addr] =
    //   1 / 0 / ^1 (按族)。= InterlockedBitTest* 真产物 (lock bts [m], imm8
    //   高频, D3; reg 位号形式一并支持)。a_kind=Reg reg_a=地址槽,
    //   b_kind=Reg (reg_b=位号寄存器槽, 低 8 位) 或 Imm (aux=imm8 位号),
    //   cond_or_size=size (S32/S64; bts 无字节形式, S8/S16 块防御 no-op)。
    //   flags: 仅 CF 有定义 (SDM: 其余未定义) — setcc5 捕 host CPU 真值,
    //   flags_tail 装配, 与原生执行同 CPU 行为 (undefined 位逐 CPU 一致)。
    Bts, Btr, Btc,

    // —— MIT-425 (G1b): SSE 浮点乘 mul 族 + andnps/andnpd ——
    // Mulss/Mulsd/Mulps/Mulpd (Reg-Reg / Reg-Mem 折条): 与 Addss 族同构,
    //   读 dst 槽 → 读 src 槽 (load_src_slot_into_xmm1 双语义, MIT-408 MEM
    //   源经 GP 双槽) → native mul* → 写回 dst 槽 → advance。
    //   a_kind=Reg reg_a=xmm_dst_slot (24..31), b_kind=Reg reg_b=xmm_src_slot
    //   或 GP 双槽 (18..23), aux=0, cond_or_size=ir::Size 标签 (Mulss=S32
    //   scalar single / Mulsd=S64 scalar double / Mulps,S64=Mulps packed /
    //   Mulpd,S64=Mulpd packed, 与 Addss/Addsd/Addps/Addpd 同约定)。
    //   IR 层 (x86_translate.cpp translate_sse_mul): ir::Op 冻结不可增枚举,
    //   SSE mul 以 (Op::Mul, src2=imm(kSseMulSs..kSseMulPd, 14..17)) 载体
    //   标记编码 — 沿用 G3 串指令 / G4 lock 的 "op 载体 + src2=imm(族)"
    //   先例 (14..18 与既有域 0..4 string / 5..13 lock 分区连续, 零碰撞;
    //   写入点唯一 = translate_sse_mul, GP mul/1-op imul→Mul 从不写 src2)。
    //   不影响 EFLAGS; 不调 setcc5/flags_tail, 直接 advance。
    //   派活单 §D 决策: 4 op 必 append-only 在 Btc 之后 (pitfall #34)。
    Mulss, Mulsd, Mulps, Mulpd,
    // Andnps (Reg-Reg / Reg-Mem 折条): dst = ~dst & src (SDM ANDNPS/PANDN
    //   逐位同语义 — andnpd/pandn 66 前缀变体按 411 ps/pd 互认折叠到本 op,
    //   位运算不解释浮点值)。与 Xorps/Orps/Andps 同一 build_xmm_transfer
    //   四步模板, 中间行 native "andnps"。IR 层: (Op::Andps,
    //   src2=imm(kSseAndn=18)) 载体标记 — Op::Andps 常规构造 (translate_sse_
    //   bitwise) 从不写 src2, 零碰撞。andnps 双折 (Not+And) 不可行: VM 无
    //   128-bit NOT 原语 (GP Not handler 是单 u64 槽语义, 落 xmm 区即错址),
    //   派活单 §B.2 "新 VmOp 你实测选" — 选新 VmOp, 字节码零膨胀。
    //   不影响 EFLAGS; 直接 advance。
    Andnps,

    // —— MIT-427 (G1c): movd/movq GP↔xmm 桥原语 ——
    // 64-bit 整数/SIMD 桥 (int↔SIMD 互转/CRC 哈希/序列化代码高频, 425 §A.3
    // intrinsic 真产物: _mm_cvtsi32_si128 → movd xmm, r32 66 0F 6E 等)。
    //   XmmFromGp (load 方向, 高位清零): dst xmm 槽低 4/8 字节 ← src 槽,
    //     **dst 槽其余字节清零** (SDM: MOVD 清 bits 127:32 / MOVQ+F3 0F 7E 清
    //     bits 127:64)。a_kind=Reg reg_a=xmm_dst_slot (24..31),
    //     b_kind=Reg reg_b=src_slot (GP 0..15 或 xmm 24..31 双语义, 后者仅
    //     width=8 — F3 0F 7E xmm 源形态), aux=宽度 (4|8)。
    //     GP 源读 = handler 内 movd/movq xmm, [GP 槽] mem 形式直产清零语义;
    //     xmm 源读 = movsd xmm0, [xmm 槽低 64] (mem 形式清零高位)。
    //   GpFromXmm (store 方向, 宽度截取): dst GP 槽 ← src xmm 槽低 4/8 字节
    //     (SDM: MOVD/MOVQ r/m, xmm 截取低位)。width=4 时**高 4 字节清零**
    //     (native movd r32 写 32 位寄存器本机零扩展, writeback 同款语义 —
    //     截取+清零两步 store)。a_kind=Reg reg_a=gp_dst_slot (0..15),
    //     b_kind=Reg reg_b=xmm_src_slot (24..31), aux=宽度 (4|8)。
    //   mem 操作数形态不经本对: movd/movq xmm, [mem] 与 [mem]←xmm 由 lifter
    //     直接折既有 (Op::Movss, mem) 载体 → XmmLoad/XmmStore (408 通路,
    //     movss/movsd mem 形式自产清零/截断语义)。
    //   编码判据 (vendored capstone 5.0.6 probe 实测, 2026-08-30): MOVD
    //   INSID=377 / MOVQ INSID=378 / VMOVD 1025 / VMOVQ 1021; 66 族
    //   prefix[2]=0x66, F3 0F 7E 被吸收进 id 后 prefix 全零, MMX 裸 0F
    //   6E/6F/7E/7F 带 mm 操作数 (D2 永久 gate)。宽度 = 非 xmm 操作数
    //   size (4/8)。不影响 EFLAGS; 直接 advance。
    //   派活单 §D 决策: 2 op 必 append-only 在 Andnps 之后 (pitfall #34);
    //   kVmOpMax+1=98 < 128 跳表余量 30。
    XmmFromGp, GpFromXmm,

    // —— MIT-506/507 (T60): x87 L0 族 —— 物理FPU驻留直执行 (架构定案见
    // GAPS MIT-506: guest ST 栈 = 物理 st0-st7, handler 直发真实 x87 指
    // 令; kCtxSize 零触碰; native callee 看到 guest 真实 x87 状态 =
    // native-exact)。x86 专属 (x64 解释器不触 x87 词)。
    //   约定: mem 形 a_kind=Reg reg_a=地址槽 (emit_address 产物), 宽度经
    //   aux (4/8/10 字节); st(i) 形 b_kind=Imm reg_b=栈位 i; fadd/fsub/
    //   fmul/fdiv 矩阵经 aux 低位编 pop/reverse 变体。updates_flags 仅
    //   Fcomi/Fcomip (物理 EFLAGS ZF/PF/CF → ctx flags 捕获链)。
    //   fnop 不设词 (lifter 折 VmOp::Nop); fcom/ftst/fcmov/超越/状态控制
    //   全族 = L1-L2 维持 gate。
    // 派活单 §D 决策: 22 op 必 append-only 在 GpFromXmm 之后 (pitfall
    // #34); kVmOpMax+1=120 < 128 跳表余量 8。
    Fld87Mem,       // fld m32/m64/tbyte [acc] (aux=宽度 4/8/10)
    Fld87St,        // fld st(i) (reg_b = i)
    Fld87Const,     // fld1/fldz (aux = 1/0)
    Fst87Mem,       // fst m32/m64/tbyte [acc] (不弹栈)
    Fstp87Mem,      // fstp m32/m64/tbyte [acc] (弹栈)
    Fst87St,        // fst st(i) (不弹栈)
    Fstp87St,       // fstp st(i) (弹栈)
    Fild87Mem,      // fild m32/m64 [acc] (整数入栈)
    Fist87Mem,      // fist m32/m64 [acc] (不弹栈)
    Fistp87Mem,     // fistp m32/m64 [acc] (弹栈)
    Fadd87,         // fadd/faddp 矩阵 (st(i),st / st,st(i) / m32/m64; aux=pop)
    Fmul87,         // fmul/fmulp 同矩阵
    Fsub87,         // fsub/fsubp/fsubr/fsubrp (aux=reverse+pop 位)
    Fdiv87,         // fdiv/fdivp/fdivr/fdivrp (同上)
    Fchs87,         // fchs (st0 变号)
    Fabs87,         // fabs (st0 绝对值)
    Fsqrt87,        // fsqrt (st0 平方根)
    Fcomi87,        // fcomi st0, st(i) + ZF/PF/CF → ctx flags 捕获
    Fcomip87,       // fcomip 同上 + 弹栈
    Fldcw87,        // fldcw m16 [acc]
    Fnstcw87,       // fnstcw m16 [acc]
    Fnstsw87,       // fnstsw: mem 形 (a_kind=Reg acc 槽) / AX 形 (a_kind=Imm
                    //   a=Rax 槽); aux 对 farith mem 为位图 (bit1=rev /
                    //   bit2=dword / bit3=qword), Fnstsw87 双形均 16

    // ---- MIT-510 (T62): x87 L1-L4 续延 (同物理 FPU 驻留架构 append-only;
    //      kVmOpMax 141 ≥ 128 → kTableEntries 256 扩容为本批前置) ----
    // Fcom87: mem 形 a_kind=Reg(acc)+aux 位图 (bit0=pop/bit1=u/bit2=dword/
    //   bit3=qword); reg 形 a_kind=Imm a=0 b=Imm i + aux bit0/bit1。
    //   助记符四变体 fcom/fcomp/fucom/fucomp 由 (pop,u) 选; 只写 SW 不触
    //   guest EFLAGS。
    Fcom87,
    Fcompp87,       // fcompp (无域, 双弹)
    Ftst87,         // ftst (st0 vs 0.0 → SW)
    Fxam87,         // fxam (st0 分类 → SW C0/C2/C3)
    Fcmov87,        // fcmovcc st, st(i): a=Imm 0 b=Imm i; aux=cc 0..7
                    //   (b/e/be/u/nb/ne/nbe/nu); flag_sem=kRead (读 guest
                    //   EFLAGS, handler 自 ctx+0x98 物化)
    Fxch87,         // fxch st(i) (b=Imm i, Fld87St 词域惯例)
    Ffree87,        // ffree st(i) (b=Imm i; aux bit0=pop → +fstp st(0))
    Fincdecstp87,   // fdecstp/fincstp (aux bit0: 0=dec 1=inc)
    F2xm187,        // f2xm1 (st0 = 2^st0 − 1)
    Fyl2x87,        // fyl2x (st1 × log2(st0), 弹)
    Fyl2xp187,      // fyl2xp1 (st1 × log2(st0+1), 弹)
    Fscale87,       // fscale (st0 ×= 2^⌊st1⌋, 弹 st1)
    Fpatan87,       // fpatan (st1 = atan(st1/st0), 弹)
    Fprem87,        // fprem/fprem1 (aux bit0: 0=prem 1=prem1)
    Fsin87,         // fsin
    Fcos87,         // fcos
    Fsincos87,      // fsincos (压 sin, cos)
    Fptan87,        // fptan (压 1.0)
    Frndint87,      // frndint (按 CW RC 舍入)
    Fxtract87,      // fxtract (st0=指数, 压有效位)
    Fnclex87,       // fnclex (清 SW 异常标志)
    Fninit87,       // fninit (FPU 全复位)

    // ---- MIT-511 (T63): AVX 档B wave1 —— kCtxSize 冻结合同 bump
    //      (0x1C8→0x3C8, ctx.ymm[16] 512B 面) + vzeroupper/vzeroall ABI
    //      词 (x64 host 专用; 无操作数; flag_sem kNone)。VEX.256 算术词
    //      属后续波次。kVmOpMax+1=144 < 256 跳表, 余量 112。 ----
    Vzeroupper,     // vzeroupper (物理发射 + ctx.ymm[0..15] 上位 16B 清零)
    Vzeroall,       // vzeroall (物理发射 + ctx.xmm[8] 与 ctx.ymm[16] 全零;
                    //   注意 VZEROALL 含 EMMS 语义 — x64 区无 x87 词, 空效)

    // ---- MIT-512 (T64): AVX 档B wave2① —— ymm 数据通路 (x64 host 专用;
    //      槽位 v24..31 复用为 ymm0..7, 由 VmOp 域语义消歧; 面访问一律
    //      vmovups 32B —— ctx 栈基址仅 16B 对齐, vmovaps 禁用)。 ----
    YmmMov,         // ymm dst, ymm src — 32B 面到面拷贝 (vmovaps/vmovdqa 折叠)
    YmmLoad,        // ymm dst, [mem] — a=Reg(dst 槽) b=Reg(addr 槽) aux=32
    YmmStore,       // [mem], ymm src — a=Reg(addr 槽) b=Reg(src 槽) aux=32

    // ---- MIT-513 (T65): AVX 档B wave2② —— VEX.256 packed 算术
    //      全谱 (x64 host 专用; 槽位/惯例同 T64; aux bit0 = src
      //     为 mem: b=addr 槽; 否则 b=src ymm 槽)。三地址折叠由
      //      lifter 产出 (d 独立 = extra YmmMov 前置)。----
    YmmAddps,       // vaddps (256-bit packed f32 加)
    YmmAddpd,       // vaddpd (256-bit packed f64 加)
    YmmSubps,       // vsubps (256-bit packed f32 减)
    YmmSubpd,       // vsubpd (256-bit packed f64 减)
    YmmMulps,       // vmulps (256-bit packed f32 乘)
    YmmMulpd,       // vmulpd (256-bit packed f64 乘)
    YmmDivps,       // vdivps (256-bit packed f32 除)
    YmmDivpd,       // vdivpd (256-bit packed f64 除)
    YmmXorps,       // vxorps (256-bit 按位异或)
    YmmXorpd,       // vxorpd (256-bit 按位异或)
    YmmOrps,       // vorps (256-bit 按位或)
    YmmOrpd,       // vorpd (256-bit 按位或)
    YmmAndps,       // vandps (256-bit 按位与)
    YmmAndpd,       // vandpd (256-bit 按位与)
    YmmPxor,       // vpxor (256-bit 整数异或)
    YmmPor,       // vpor (256-bit 整数或)
    YmmPand,       // vpand (256-bit 整数与)
    YmmPandn,       // vpandn (256-bit dst=~dst&src, 非交换)
    };

inline constexpr u16 kVmOpMax = static_cast<u16>(VmOp::YmmPandn);  // MIT-513: 164
inline constexpr u16 kVmOpLimit = 1u << 14;  // 14 位编码空间上限

constexpr const char* to_string(VmOp op) {
    switch (op) {
        case VmOp::Mov: return "mov";   case VmOp::Lea: return "lea";
        case VmOp::Add: return "add";   case VmOp::Sub: return "sub";
        case VmOp::Adc: return "adc";   case VmOp::Sbb: return "sbb";
        case VmOp::And: return "and";   case VmOp::Or: return "or";
        case VmOp::Xor: return "xor";   case VmOp::Not: return "not";
        case VmOp::Neg: return "neg";   case VmOp::Inc: return "inc";
        case VmOp::Dec: return "dec";   case VmOp::Shl: return "shl";
        case VmOp::Shr: return "shr";   case VmOp::Sar: return "sar";
        case VmOp::Rol: return "rol";   case VmOp::Ror: return "ror";
        case VmOp::Cmp: return "cmp";   case VmOp::Test: return "test";
        case VmOp::Push: return "push"; case VmOp::Pop: return "pop";
        case VmOp::Jmp: return "jmp";   case VmOp::Jcc: return "jcc";
        case VmOp::Call: return "call"; case VmOp::Ret: return "ret";
        case VmOp::Load: return "load"; case VmOp::Store: return "store";
        case VmOp::Nop: return "nop";   case VmOp::Halt: return "halt";
        case VmOp::GetFlags: return "getflags";
        case VmOp::SetFlags: return "setflags";
        case VmOp::LoadRva: return "loadrva";
        case VmOp::StoreRva: return "storeriva";
        case VmOp::CallGate: return "callgate";
        case VmOp::ShlCl: return "shlcl";
        case VmOp::ShrCl: return "shrcl";
        case VmOp::SarCl: return "sarcl";
        case VmOp::RolCl: return "rolcl";
        case VmOp::RorCl: return "rorcl";
        case VmOp::Imul: return "imul";
        case VmOp::Mul: return "mul";
        case VmOp::Movsxd: return "movsxd";
        case VmOp::MovsxdMem: return "movsxdmem";
        case VmOp::Movzx: return "movzx";
        case VmOp::MovzxMem: return "movzxmem";
        case VmOp::LeaRva: return "learva";
        case VmOp::Bswap: return "bswap";
        case VmOp::Xchg: return "xchg";
        case VmOp::Setcc: return "setcc";
        case VmOp::Cmovcc: return "cmovcc";
        case VmOp::Cmpxchg: return "cmpxchg";
        case VmOp::Movsx: return "movsx";
        case VmOp::MovsxMem: return "movsxmem";
        case VmOp::Popcnt: return "popcnt";
        case VmOp::Lzcount: return "lzcnt";
        case VmOp::Tzcount: return "tzcnt";
        case VmOp::Addss: return "addss";
        case VmOp::Addps: return "addps";
        case VmOp::Addpd: return "addpd";
        case VmOp::Subss: return "subss";
        case VmOp::Subps: return "subps";
        case VmOp::Subpd: return "subpd";
        case VmOp::Divss: return "divss";
        case VmOp::Divps: return "divps";
        case VmOp::Divpd: return "divpd";
        // MIT-375: SSE 浮点传送 5 op.
        case VmOp::Movss: return "movss";
        case VmOp::Movaps: return "movaps";
        case VmOp::Movapd: return "movapd";
        case VmOp::Movups: return "movups";
        case VmOp::Movupd: return "movupd";
        // MIT-376: SSE 浮点位运算 + 浮点比较 5 op.
        case VmOp::Xorps: return "xorps";
        case VmOp::Orps: return "orps";
        case VmOp::Andps: return "andps";
        case VmOp::Ucomiss: return "ucomiss";
        case VmOp::Ucomisd: return "ucomisd";
        // MIT-404: 整数除法族 + 符号扩展 3 op.
        case VmOp::Cdq: return "cdq";
        case VmOp::Div: return "div";
        case VmOp::Idiv: return "idiv";
        // MIT-407: 区域外跳转单向退出到 native.
        case VmOp::ExitNative: return "exitnative";
        // MIT-408: SSE scalar-double 族 + mem 形式原语.
        case VmOp::Movsd: return "movsd";
        case VmOp::Addsd: return "addsd";
        case VmOp::Subsd: return "subsd";
        case VmOp::Divsd: return "divsd";
        case VmOp::XmmLoad: return "xmmload";
        case VmOp::XmmStore: return "xmmstore";
        // MIT-419: lock 前缀原子族.
        case VmOp::Xadd: return "xadd";
        case VmOp::Bts: return "bts";
        case VmOp::Btr: return "btr";
        case VmOp::Btc: return "btc";
        // MIT-425 (G1b): SSE 浮点乘 mul 族 + andnps.
        case VmOp::Mulss: return "mulss";
        case VmOp::Mulsd: return "mulsd";
        case VmOp::Mulps: return "mulps";
        case VmOp::Mulpd: return "mulpd";
        case VmOp::Andnps: return "andnps";
        // MIT-427 (G1c): movd/movq GP↔xmm 桥原语.
        case VmOp::XmmFromGp: return "xmmfromgp";
        case VmOp::GpFromXmm: return "gpfromxmm";
        // MIT-507 (T60): x87 L0 族 (物理 FPU 驻留直执行).
        case VmOp::Fld87Mem: return "fld87mem";
        case VmOp::Fld87St: return "fld87st";
        case VmOp::Fld87Const: return "fld87const";
        case VmOp::Fst87Mem: return "fst87mem";
        case VmOp::Fstp87Mem: return "fstp87mem";
        case VmOp::Fst87St: return "fst87st";
        case VmOp::Fstp87St: return "fstp87st";
        case VmOp::Fild87Mem: return "fild87mem";
        case VmOp::Fist87Mem: return "fist87mem";
        case VmOp::Fistp87Mem: return "fistp87mem";
        case VmOp::Fadd87: return "fadd87";
        case VmOp::Fmul87: return "fmul87";
        case VmOp::Fsub87: return "fsub87";
        case VmOp::Fdiv87: return "fdiv87";
        case VmOp::Fchs87: return "fchs87";
        case VmOp::Fabs87: return "fabs87";
        case VmOp::Fsqrt87: return "fsqrt87";
        case VmOp::Fcomi87: return "fcomi87";
        case VmOp::Fcomip87: return "fcomip87";
        case VmOp::Fldcw87: return "fldcw87";
        case VmOp::Fnstcw87: return "fnstcw87";
        case VmOp::Fnstsw87: return "fnstsw87";
        case VmOp::Fcom87: return "fcom87";
        case VmOp::Fcompp87: return "fcompp87";
        case VmOp::Ftst87: return "ftst87";
        case VmOp::Fxam87: return "fxam87";
        case VmOp::Fcmov87: return "fcmov87";
        case VmOp::Fxch87: return "fxch87";
        case VmOp::Ffree87: return "ffree87";
        case VmOp::Fincdecstp87: return "fincdecstp87";
        case VmOp::F2xm187: return "f2xm187";
        case VmOp::Fyl2x87: return "fyl2x87";
        case VmOp::Fyl2xp187: return "fyl2xp187";
        case VmOp::Fscale87: return "fscale87";
        case VmOp::Fpatan87: return "fpatan87";
        case VmOp::Fprem87: return "fprem87";
        case VmOp::Fsin87: return "fsin87";
        case VmOp::Fcos87: return "fcos87";
        case VmOp::Fsincos87: return "fsincos87";
        case VmOp::Fptan87: return "fptan87";
        case VmOp::Frndint87: return "frndint87";
        case VmOp::Fxtract87: return "fxtract87";
        case VmOp::Fnclex87: return "fnclex87";
        case VmOp::Fninit87: return "fninit87";
        case VmOp::Vzeroupper: return "vzeroupper";
        case VmOp::Vzeroall: return "vzeroall";
        case VmOp::YmmMov: return "ymmmov";
        case VmOp::YmmLoad: return "ymmload";
        case VmOp::YmmStore: return "ymmstore";
        case VmOp::YmmAddps: return "ymmaddps";
        case VmOp::YmmAddpd: return "ymmaddpd";
        case VmOp::YmmSubps: return "ymmsubps";
        case VmOp::YmmSubpd: return "ymmsubpd";
        case VmOp::YmmMulps: return "ymmmulps";
        case VmOp::YmmMulpd: return "ymmmulpd";
        case VmOp::YmmDivps: return "ymmdivps";
        case VmOp::YmmDivpd: return "ymmdivpd";
        case VmOp::YmmXorps: return "ymmxorps";
        case VmOp::YmmXorpd: return "ymmxorpd";
        case VmOp::YmmOrps: return "ymmorps";
        case VmOp::YmmOrpd: return "ymmorpd";
        case VmOp::YmmAndps: return "ymmandps";
        case VmOp::YmmAndpd: return "ymmandpd";
        case VmOp::YmmPxor: return "ymmpxor";
        case VmOp::YmmPor: return "ymmpor";
        case VmOp::YmmPand: return "ymmpand";
        case VmOp::YmmPandn: return "ymmpandn";
    }
    return "?";
}

} // namespace wvmp::regvm::isa
