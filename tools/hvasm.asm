;
; hvasm.asm - the user-mode side of the control channel.
;
; VMMCALL, not CPUID: CPUID is no longer intercepted, so that it can be timed
; against bare metal and match.  VMMCALL is the other instruction a guest can
; trap on from CPL 3 - it has no privilege requirement - and no compiler
; intrinsic reaches this ABI anyway: the magic travels in RAX, the command in
; RBX, the arguments in RDX and RSI, and up to 48 bytes come back in
; RBX/RDX/RSI/RDI/R8/R9.  MSVC has no inline assembler on x64, so this is the
; only way to say it.
;
; RBX, RSI and RDI are non-volatile in the Windows x64 convention and have to be
; preserved across the call even though the hypervisor overwrites them.
;

.code

;
; VOID AsmHypercall(HV_REGS *Regs)   -- RCX = Regs
;
; struct HV_REGS { UINT64 Rax, Rbx, Rcx, Rdx, Rsi, Rdi, R8, R9; }
;
; PROC FRAME with .pushreg, not a bare PROC: when nothing is loaded the VMMCALL
; below raises #UD, and the caller catches it with __try/__except.  SEH has to
; unwind back out through this frame, and it cannot do that without unwind data
; for the four pushes - the dispatch fails and the process dies instead.
AsmHypercall PROC FRAME
        push    rbx
        .pushreg rbx
        push    rsi
        .pushreg rsi
        push    rdi
        .pushreg rdi
        push    r12
        .pushreg r12
        .endprolog

        mov     r12, rcx                        ; keep the struct pointer

        mov     rax, [r12 + 00h]
        mov     rbx, [r12 + 08h]
        mov     rdx, [r12 + 18h]
        mov     rsi, [r12 + 20h]
        mov     rdi, [r12 + 28h]
        mov     r8,  [r12 + 30h]
        mov     r9,  [r12 + 38h]
        mov     rcx, [r12 + 10h]

        vmmcall

        mov     [r12 + 00h], rax
        mov     [r12 + 08h], rbx
        mov     [r12 + 10h], rcx
        mov     [r12 + 18h], rdx
        mov     [r12 + 20h], rsi
        mov     [r12 + 28h], rdi
        mov     [r12 + 30h], r8
        mov     [r12 + 38h], r9

        pop     r12
        pop     rdi
        pop     rsi
        pop     rbx
        ret
AsmHypercall ENDP

END
