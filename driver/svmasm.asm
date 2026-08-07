;
; svmasm.asm - the parts of the hypervisor that cannot be expressed in C:
;              the VMRUN loop, the devirtualisation tail, and a hypercall
;              trampoline that re-issues a guest VMMCALL from host context.
;

.code

; --- VMCB offsets (asserted against the C structs in svm.h) --------------
VMCB_TSC_OFFSET equ     050h
VMCB_RFLAGS     equ     570h
VMCB_RIP        equ     578h
VMCB_RSP        equ     5D8h

; --- HOST_STACK_LAYOUT slots, relative to RSP after PUSHAQ (0x80 bytes) ---
L_GUEST_VMCB_PA equ     80h + 00h
L_HOST_VMCB_PA  equ     80h + 08h
L_CPU           equ     80h + 10h
L_GUEST_VMCB_VA equ     80h + 18h
L_TSC_EXIT      equ     80h + 20h
L_TSC_OFFSET    equ     80h + 28h
L_TSC_HIDE      equ     80h + 30h
L_TSC_TOTAL     equ     80h + 38h

; --- CONTEXT (winnt.h) offsets, asserted in svmhv.c -----------------------
CTX_RCX         equ     080h
CTX_RDX         equ     088h
CTX_RBX         equ     090h
CTX_RBP         equ     0A0h
CTX_RSI         equ     0A8h
CTX_RDI         equ     0B0h
CTX_R8          equ     0B8h
CTX_R9          equ     0C0h
CTX_R10         equ     0C8h
CTX_R11         equ     0D0h
CTX_R12         equ     0D8h
CTX_R13         equ     0E0h
CTX_R14         equ     0E8h
CTX_R15         equ     0F0h
CTX_XMM0        equ     1A0h

MSR_EFER_ID     equ     0C0000080h
EFER_SVME_MASK  equ     0FFFFEFFFh              ; ~(1 << 12)

EXTERN SvHandleVmExit : PROC
EXTERN SvTraceExecEntry : PROC

PUSHAQ MACRO
        push    rax
        push    rcx
        push    rdx
        push    rbx
        push    -1                              ; dummy RSP slot
        push    rbp
        push    rsi
        push    rdi
        push    r8
        push    r9
        push    r10
        push    r11
        push    r12
        push    r13
        push    r14
        push    r15
ENDM

POPAQ MACRO
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     r11
        pop     r10
        pop     r9
        pop     r8
        pop     rdi
        pop     rsi
        pop     rbp
        add     rsp, 8                          ; discard dummy RSP slot
        pop     rbx
        pop     rdx
        pop     rcx
        pop     rax
ENDM

;
; VOID AsmLaunchVm(HOST_STACK_LAYOUT *HostRsp, PCONTEXT GuestContext)
;
; RCX = top of the host stack, RDX = the guest context captured by
; RtlCaptureContext.  VMRUN only loads RSP/RIP/RAX/RFLAGS from the VMCB, so the
; remaining GPRs are restored here by hand - otherwise the guest would resume
; with this function's register garbage.
;
AsmLaunchVm PROC
        mov     rsp, rcx                        ; switch to the host stack

        movaps  xmm0, xmmword ptr [rdx + CTX_XMM0 + 000h]
        movaps  xmm1, xmmword ptr [rdx + CTX_XMM0 + 010h]
        movaps  xmm2, xmmword ptr [rdx + CTX_XMM0 + 020h]
        movaps  xmm3, xmmword ptr [rdx + CTX_XMM0 + 030h]
        movaps  xmm4, xmmword ptr [rdx + CTX_XMM0 + 040h]
        movaps  xmm5, xmmword ptr [rdx + CTX_XMM0 + 050h]

        mov     rbx, [rdx + CTX_RBX]
        mov     rbp, [rdx + CTX_RBP]
        mov     rsi, [rdx + CTX_RSI]
        mov     rdi, [rdx + CTX_RDI]
        mov     r8,  [rdx + CTX_R8]
        mov     r9,  [rdx + CTX_R9]
        mov     r10, [rdx + CTX_R10]
        mov     r11, [rdx + CTX_R11]
        mov     r12, [rdx + CTX_R12]
        mov     r13, [rdx + CTX_R13]
        mov     r14, [rdx + CTX_R14]
        mov     r15, [rdx + CTX_R15]
        mov     rcx, [rdx + CTX_RCX]
        mov     rdx, [rdx + CTX_RDX]            ; must come last

VmLoop:
        ; RAX is the implicit operand of VMLOAD/VMRUN/VMSAVE.  The guest's own
        ; RAX travels through the VMCB, so clobbering it here is harmless.
        mov     rax, [rsp]                      ; GuestVmcbPa
        vmload  rax                             ; guest FS/GS/TR/LDTR + MSRs
        vmrun   rax                             ; ---- guest runs ----
        vmsave  rax                             ; #VMEXIT: stash them back

        PUSHAQ

        ; Stamp the arrival time before doing anything else.  RAX and RDX are
        ; safe to clobber here: the guest's copies are on the stack, and the
        ; guest's real RAX travels through the VMCB.
        rdtsc
        shl     rdx, 20h
        or      rax, rdx
        mov     [rsp + L_TSC_EXIT], rax

        mov     rax, [rsp + L_HOST_VMCB_PA]
        vmload  rax                             ; host FS/GS/TR/LDTR + MSRs

        mov     rcx, [rsp + L_CPU]              ; arg1: VIRTUAL_CPU *
        mov     rdx, rsp                        ; arg2: GUEST_CONTEXT *
        sub     rsp, 80h                        ; 20h shadow + 60h xmm save
        lea     r8, [rsp + 20h]                 ; arg3: xmm save area
        movaps  xmmword ptr [rsp + 20h], xmm0
        movaps  xmmword ptr [rsp + 30h], xmm1
        movaps  xmmword ptr [rsp + 40h], xmm2
        movaps  xmmword ptr [rsp + 50h], xmm3
        movaps  xmmword ptr [rsp + 60h], xmm4
        movaps  xmmword ptr [rsp + 70h], xmm5

        call    SvHandleVmExit

        movaps  xmm0, xmmword ptr [rsp + 20h]
        movaps  xmm1, xmmword ptr [rsp + 30h]
        movaps  xmm2, xmmword ptr [rsp + 40h]
        movaps  xmm3, xmmword ptr [rsp + 50h]
        movaps  xmm4, xmmword ptr [rsp + 60h]
        movaps  xmm5, xmmword ptr [rsp + 70h]
        add     rsp, 80h

        test    al, al
        jnz     Devirtualise

        ; Charge the time spent in host mode to the hypervisor rather than to
        ; the guest.  TscTotal is kept either way - it is the only measurement
        ; of what this hypervisor costs - while the VMCB only sees the part we
        ; are hiding, and only for exits the guest could have timed.  Still
        ; before POPAQ, so RAX, RCX and RDX are scratch.
        rdtsc
        shl     rdx, 20h
        or      rax, rdx
        sub     rax, [rsp + L_TSC_EXIT]          ; host residency, cycles
        add     [rsp + L_TSC_TOTAL], rax

        ; What comes off the guest's clock is the calibrated constant, not the
        ; residency: see the comment on TscHide in svmhv.h.
        mov     rdx, [rsp + L_TSC_HIDE]
        test    rdx, rdx
        jz      NoTscHiding                      ; hide nothing this time
        mov     rcx, [rsp + L_TSC_OFFSET]
        sub     rcx, rdx
        mov     [rsp + L_TSC_OFFSET], rcx
        mov     rdx, [rsp + L_GUEST_VMCB_VA]
        mov     [rdx + VMCB_TSC_OFFSET], rcx
NoTscHiding:
        POPAQ
        jmp     VmLoop

;
; Tear-down path.  Leave SVM and jump back into the guest's own instruction
; stream with every register intact, by building a [RFLAGS][RIP] frame on the
; guest stack and finishing with POPFQ + RET.
;
Devirtualise:
        mov     rax, [rsp + L_GUEST_VMCB_PA]
        vmload  rax                             ; guest FS/GS/TR/LDTR back
        stgi                                    ; GIF=1 (SVME still set)

        mov     ecx, MSR_EFER_ID
        rdmsr
        and     eax, EFER_SVME_MASK             ; clear EFER.SVME
        wrmsr

        mov     rax, [rsp + L_GUEST_VMCB_VA]
        mov     rcx, [rax + VMCB_RSP]           ; guest RSP
        mov     rdx, [rax + VMCB_RIP]           ; resume RIP (already advanced)
        mov     r8,  [rax + VMCB_RFLAGS]

        sub     rcx, 8
        mov     [rcx], rdx                      ; RET target
        sub     rcx, 8
        mov     [rcx], r8                       ; POPFQ operand
        mov     [rsp + L_GUEST_VMCB_PA], rcx    ; slot is dead from here on

        POPAQ                                   ; all GPRs = guest values
        mov     rsp, [rsp]                      ; RSP now at layout base
        popfq
        ret                                     ; -> guest RIP
AsmLaunchVm ENDP

;
; UINT64 AsmForwardHypercall(UINT64 Rcx, UINT64 Rdx, UINT64 R8, PVOID XmmSave)
;
; Runs in host context, where VMMCALL is intercepted by the hypervisor above us
; (L0).  XMM0-5 carry the input of Hyper-V "XMM fast" hypercalls and are copied
; back afterwards so the guest observes the outputs.
;
AsmForwardHypercall PROC
        movaps  xmm0, xmmword ptr [r9 + 000h]
        movaps  xmm1, xmmword ptr [r9 + 010h]
        movaps  xmm2, xmmword ptr [r9 + 020h]
        movaps  xmm3, xmmword ptr [r9 + 030h]
        movaps  xmm4, xmmword ptr [r9 + 040h]
        movaps  xmm5, xmmword ptr [r9 + 050h]

        vmmcall

        movaps  xmmword ptr [r9 + 000h], xmm0
        movaps  xmmword ptr [r9 + 010h], xmm1
        movaps  xmmword ptr [r9 + 020h], xmm2
        movaps  xmmword ptr [r9 + 030h], xmm3
        movaps  xmmword ptr [r9 + 040h], xmm4
        movaps  xmmword ptr [r9 + 050h], xmm5
        ret
AsmForwardHypercall ENDP

;
; VOID AsmTraceEntry(VOID)
;
; Reached from a hook stub that has just loaded R11 with the hook id.  Nothing
; else has changed: RSP still points at the traced function's return address and
; its arguments are exactly where its caller left them.
;
; Everything volatile has to be preserved, not just the four integer argument
; registers - the recorder is ordinary C and the compiler will happily use XMM0-5,
; which is where a floating-point argument would be sitting.
;
; The exit is the interesting part.  SvTraceExecEntry returns where to continue,
; and rather than juggle that in a register while restoring RAX, it goes onto the
; stack in the slot RAX was saved in and RET does both jobs at once: RSP ends up
; exactly where the traced function expects it, with its return address on top.
;
AsmTraceEntry PROC
        push    rax
        mov     rax, rsp
        add     rax, 8                          ; RSP as the function was entered
        push    rcx
        push    rdx
        push    r8
        push    r9
        push    r10
        push    r11
        push    rax                             ; 8 pushes -> RSP is 8 mod 16

        ; 0x68, not 0x60: the eight pushes left RSP eight short of a 16-byte
        ; boundary, and movaps on a misaligned address faults.  The spare eight
        ; bytes sit above the six saved registers, at [rsp + 60h].
        sub     rsp, 68h
        movaps  xmmword ptr [rsp + 000h], xmm0
        movaps  xmmword ptr [rsp + 010h], xmm1
        movaps  xmmword ptr [rsp + 020h], xmm2
        movaps  xmmword ptr [rsp + 030h], xmm3
        movaps  xmmword ptr [rsp + 040h], xmm4
        movaps  xmmword ptr [rsp + 050h], xmm5

        mov     rcx, [rsp + 68h + 08h]          ; arg1: hook id (the saved R11)
        lea     rdx, [rsp + 68h]                ; arg2: TRACE_FRAME *
        mov     r8,  [rsp + 68h + 00h]          ; arg3: the original RSP
        sub     rsp, 20h
        call    SvTraceExecEntry
        add     rsp, 20h
        mov     [rsp + 68h + 00h], rax          ; stash where to continue

        movaps  xmm0, xmmword ptr [rsp + 000h]
        movaps  xmm1, xmmword ptr [rsp + 010h]
        movaps  xmm2, xmmword ptr [rsp + 020h]
        movaps  xmm3, xmmword ptr [rsp + 030h]
        movaps  xmm4, xmmword ptr [rsp + 040h]
        movaps  xmm5, xmmword ptr [rsp + 050h]
        add     rsp, 68h

        mov     rax, [rsp]                      ; the continuation
        add     rsp, 8
        pop     r11
        pop     r10
        pop     r9
        pop     r8
        pop     rdx
        pop     rcx
        xchg    rax, [rsp]                      ; RAX restored, target on the stack
        ret                                     ; -> trampoline, RSP as at entry
AsmTraceEntry ENDP

AsmReadGdtr PROC
        sgdt    fword ptr [rcx]
        ret
AsmReadGdtr ENDP

AsmReadIdtr PROC
        sidt    fword ptr [rcx]
        ret
AsmReadIdtr ENDP

END
