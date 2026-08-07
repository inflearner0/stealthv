;
; hvasm.asm - the user-mode side of the control channel.
;
; CPUID architecturally takes only EAX and ECX, so a compiler intrinsic cannot
; reach this ABI: the command travels in RBX and the arguments in RDX and RSI,
; and up to 48 bytes come back in RBX/RDX/RSI/RDI/R8/R9.  MSVC has no inline
; assembler on x64, so this is the only way to say it.
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
AsmHypercall PROC
        push    rbx
        push    rsi
        push    rdi
        push    r12

        mov     r12, rcx                        ; keep the struct pointer

        mov     rax, [r12 + 00h]
        mov     rbx, [r12 + 08h]
        mov     rdx, [r12 + 18h]
        mov     rsi, [r12 + 20h]
        mov     rdi, [r12 + 28h]
        mov     r8,  [r12 + 30h]
        mov     r9,  [r12 + 38h]
        mov     rcx, [r12 + 10h]                ; ECX is the key; load it last

        cpuid

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
