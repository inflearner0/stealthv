/*
 * step.c - single-stepping the guest.  See step.h for why this exists at all.
 */

#include "step.h"
#include "svmhv.h"
#include "trace.h"

static volatile LONG64 g_Steps;
static volatile LONG64 g_Exposed;

/*
 * The bytes of the instruction that is about to run.
 *
 * Preferred source is the VMCB's own decode assist: the processor already
 * fetched the instruction to intercept it, and what it hands over has no
 * address space attached to it, so there is nothing to get wrong.  Not every
 * configuration fills it in - under a parent hypervisor especially - so the
 * fallback reads at RIP, under the same rule the trace recorder uses: the page
 * is resident because the processor just fetched from it, but that argument
 * covers RIP's own page and nothing past it.
 */
static BOOLEAN SvStepStackReachable(_In_ const VMCB* Vmcb, _In_ UINT64 Address,
                                    _In_ UINT32 Size);

static UINT32 SvStepInstructionBytes(_In_ const VMCB* Vmcb,
                                     _Out_writes_(Max) UINT8* Bytes,
                                     _In_ UINT32 Max)
{
    const UINT64 rip = Vmcb->StateSave.Rip;
    const UINT64 pageEnd = (rip | (PAGE_SIZE - 1)) + 1;
    UINT32 length;
    UINT32 i;

    if (Vmcb->Control.NumOfBytesFetched != 0)
    {
        length = Vmcb->Control.NumOfBytesFetched;
        if (length > Max)
        {
            length = Max;
        }
        for (i = 0; i < length; i++)
        {
            Bytes[i] = Vmcb->Control.GuestInstructionBytes[i];
        }
        return length;
    }

    /*
     * Same rule as the stack: kernel space is mapped identically in every CR3,
     * and user space only when the guest is in the address space this
     * processor's host state is using.  A user-mode step is the common case
     * here and reading nothing would make it useless, so the check is made
     * rather than the address range assumed.
     */
    if (!SvStepStackReachable(Vmcb, rip, 1))
    {
        return 0;
    }

    length = Max;
    if (pageEnd - rip < length)
    {
        length = (UINT32)(pageEnd - rip);
    }
    for (i = 0; i < length; i++)
    {
        Bytes[i] = ((const UINT8*)rip)[i];
    }
    return length;
}

/*
 * How wide a PUSHF/POPF is, and how long the instruction is.
 *
 * In long mode the operand size is 8 unless the instruction carries a 0x66
 * prefix, in which case it is 2 - there is no 4-byte form.  Worth decoding
 * rather than assuming: the 16-bit form is exactly the sort of thing that shows
 * up in code trying to catch a debugger doing this badly.
 */
static VOID SvStepFlagsOperand(_In_ const UINT8* Bytes, _In_ UINT32 Length,
                               _Out_ UINT32* OperandSize, _Out_ UINT32* InsnLength)
{
    UINT32 i;

    *OperandSize = 8;
    *InsnLength = 1;

    for (i = 0; i < Length; i++)
    {
        const UINT8 byte = Bytes[i];

        if (byte == 0x66)
        {
            *OperandSize = 2;
        }
        else if (byte == 0x67 || byte == 0x2E || byte == 0x36 || byte == 0x3E ||
                 byte == 0x26 || byte == 0x64 || byte == 0x65 || byte == 0xF2 ||
                 byte == 0xF3 || (byte >= 0x40 && byte <= 0x4F))
        {
            /* another prefix; keep going */
        }
        else
        {
            *InsnLength = i + 1;        /* the opcode itself */
            return;
        }
    }
}

/*
 * TRUE if the guest's stack is memory this exit handler may touch.
 *
 * Kernel space is mapped the same in every CR3, so a kernel stack is always
 * reachable.  A user stack is only reachable when the address space the guest
 * was in happens to be the one this processor's host state is using, which is
 * whatever it launched in - so it is checked rather than assumed.  Getting this
 * wrong would not fault cleanly; it would write eight bytes into an unrelated
 * process.
 */
static BOOLEAN SvStepStackReachable(_In_ const VMCB* Vmcb, _In_ UINT64 Address,
                                    _In_ UINT32 Size)
{
    if (Address < 0x1000 || (Address + Size) < Address)
    {
        return FALSE;
    }
    if (Address >= (UINT64)MM_SYSTEM_RANGE_START)
    {
        return TRUE;
    }
    return (Vmcb->StateSave.Cr3 & ~0xFFFULL) == (__readcr3() & ~0xFFFULL);
}

/* Give up on hiding TF for the rest of this window, and say so. */
static VOID SvStepExposeFlags(_Inout_ VIRTUAL_CPU* Cpu)
{
    if (!Cpu->Step.FlagsExposed)
    {
        Cpu->Step.FlagsExposed = TRUE;
        InterlockedIncrement64(&g_Exposed);
    }
    Cpu->GuestVmcb.Control.InterceptVector3 &=
        ~(SVM_INTERCEPT_PUSHF | SVM_INTERCEPT_POPF);
    Cpu->GuestVmcb.Control.VmcbClean = 0;
}

VOID SvStepArm(_Inout_ VIRTUAL_CPU* Cpu, _In_ UINT32 Count, _In_ UINT32 Reason)
{
    VMCB* vmcb = &Cpu->GuestVmcb;

    if (Count == 0)
    {
        return;
    }
    if (Count > SVMHV_STEP_MAX)
    {
        Count = SVMHV_STEP_MAX;
    }

    /*
     * Only save the guest's trap flag if we are not already holding it.  A
     * second arm while a window is open would otherwise save our own TF as
     * though it were the guest's, and the flag would be left set when the run
     * ended - a guest single-stepping itself for the rest of its life.
     */
    if (Cpu->Step.Reason == SVMHV_STEP_NONE)
    {
        Cpu->Step.GuestTf = (vmcb->StateSave.Rflags & SVM_RFLAGS_TF) != 0;
        Cpu->Step.FlagsExposed = FALSE;
    }

    Cpu->Step.Reason = Reason;
    Cpu->Step.Remaining = Count;

    vmcb->StateSave.Rflags |= SVM_RFLAGS_TF;
    vmcb->Control.InterceptException |=
        SVM_INTERCEPT_EXCEPTION(SVM_EXCEPTION_DB_VECTOR);
    if (!Cpu->Step.FlagsExposed)
    {
        vmcb->Control.InterceptVector3 |=
            SVM_INTERCEPT_PUSHF | SVM_INTERCEPT_POPF;
    }
    vmcb->Control.VmcbClean = 0;
}

VOID SvStepDisarm(_Inout_ VIRTUAL_CPU* Cpu)
{
    VMCB* vmcb = &Cpu->GuestVmcb;

    if (Cpu->Step.Reason == SVMHV_STEP_NONE)
    {
        return;
    }

    if (Cpu->Step.GuestTf)
    {
        vmcb->StateSave.Rflags |= SVM_RFLAGS_TF;
    }
    else
    {
        vmcb->StateSave.Rflags &= ~SVM_RFLAGS_TF;
    }

    vmcb->Control.InterceptException &=
        ~SVM_INTERCEPT_EXCEPTION(SVM_EXCEPTION_DB_VECTOR);
    vmcb->Control.InterceptVector3 &=
        ~(SVM_INTERCEPT_PUSHF | SVM_INTERCEPT_POPF);
    vmcb->Control.VmcbClean = 0;

    Cpu->Step.Reason = SVMHV_STEP_NONE;
    Cpu->Step.Remaining = 0;
    Cpu->Step.HookId = 0;
}

BOOLEAN SvStepHandleDebugException(_Inout_ VIRTUAL_CPU* Cpu)
{
    VMCB* vmcb = &Cpu->GuestVmcb;

    if (Cpu->Step.Reason == SVMHV_STEP_NONE)
    {
        return FALSE;                   /* the guest's own, not ours */
    }

    /*
     * A #DB that is not a single step - a hardware breakpoint the guest set
     * for itself - happens to arrive while we are stepping and belongs to the
     * guest.  Only BS is ours.
     */
    if ((vmcb->StateSave.Dr6 & SVM_DR6_BS) == 0)
    {
        return FALSE;
    }

    /* The guest must not find our step in its own debug status register. */
    vmcb->StateSave.Dr6 &= ~SVM_DR6_BS;

    InterlockedIncrement64(&g_Steps);

    if (Cpu->Step.Reason == SVMHV_STEP_TRACE)
    {
        UINT8 bytes[16];
        const UINT32 length = SvStepInstructionBytes(vmcb, bytes, sizeof(bytes));

        SvTraceStep(vmcb->StateSave.Rip, vmcb->StateSave.Rsp,
                    vmcb->StateSave.Rflags, vmcb->StateSave.Cr3,
                    Cpu->Index, bytes, length,
                    Cpu->Step.GuestTf);
    }

    Cpu->Step.Remaining--;
    if (Cpu->Step.Remaining == 0)
    {
        SvStepDisarm(Cpu);
    }

    return TRUE;
}

BOOLEAN SvStepEmulatePushf(_Inout_ VIRTUAL_CPU* Cpu)
{
    VMCB* vmcb = &Cpu->GuestVmcb;
    UINT8 bytes[16];
    const UINT32 fetched = SvStepInstructionBytes(vmcb, bytes, sizeof(bytes));
    UINT32 operandSize;
    UINT32 insnLength;
    UINT64 rsp;
    UINT64 flags;

    SvStepFlagsOperand(bytes, fetched, &operandSize, &insnLength);

    rsp = vmcb->StateSave.Rsp - operandSize;
    if (!SvStepStackReachable(vmcb, rsp, operandSize))
    {
        SvStepExposeFlags(Cpu);
        return FALSE;
    }

    /* What the guest believes RFLAGS is: ours, with its own trap flag. */
    flags = vmcb->StateSave.Rflags;
    if (Cpu->Step.GuestTf)
    {
        flags |= SVM_RFLAGS_TF;
    }
    else
    {
        flags &= ~SVM_RFLAGS_TF;
    }

    RtlCopyMemory((VOID*)rsp, &flags, operandSize);
    vmcb->StateSave.Rsp = rsp;
    vmcb->StateSave.Rip += insnLength;
    return TRUE;
}

BOOLEAN SvStepEmulatePopf(_Inout_ VIRTUAL_CPU* Cpu)
{
    VMCB* vmcb = &Cpu->GuestVmcb;
    UINT8 bytes[16];
    const UINT32 fetched = SvStepInstructionBytes(vmcb, bytes, sizeof(bytes));
    UINT32 operandSize;
    UINT32 insnLength;
    const UINT64 current = vmcb->StateSave.Rflags;
    const UINT32 cpl = vmcb->StateSave.Cpl;
    const UINT32 iopl = (UINT32)((current >> 12) & 3);
    UINT64 wanted = 0;
    UINT64 result;

    SvStepFlagsOperand(bytes, fetched, &operandSize, &insnLength);

    if (!SvStepStackReachable(vmcb, vmcb->StateSave.Rsp, operandSize))
    {
        SvStepExposeFlags(Cpu);
        return FALSE;
    }

    RtlCopyMemory(&wanted, (const VOID*)vmcb->StateSave.Rsp, operandSize);

    /*
     * POPF is not a plain assignment, and emulating it as one would hand a
     * user-mode guest the interrupt flag and its own I/O privilege level.  The
     * architectural rules: IOPL only changes at CPL 0, IF only when CPL is at
     * least as privileged as IOPL, and RF, VM, VIP and VIF are never taken from
     * the stack at all.  A 16-bit POPF only touches the low word.
     */
    if (operandSize == 2)
    {
        result = (current & ~0xFFFFULL) | (wanted & 0xFFFFULL);
    }
    else
    {
        const UINT64 preserved = (1ULL << 16) |  /* RF  */
                                 (1ULL << 17) |  /* VM  */
                                 (1ULL << 19) |  /* VIF */
                                 (1ULL << 20);   /* VIP */
        result = (wanted & ~preserved) | (current & preserved);
    }

    if (cpl > 0)
    {
        result = (result & ~(3ULL << 12)) | ((UINT64)iopl << 12);
        if (cpl > iopl)
        {
            result = (result & ~(1ULL << 9)) | (current & (1ULL << 9));
        }
    }

    /* Bit 1 reads as one; 3, 5 and 15 read as zero. */
    result |= 2ULL;
    result &= ~((1ULL << 3) | (1ULL << 5) | (1ULL << 15));

    /*
     * The guest set the trap flag it thinks it set; ours stays on underneath,
     * and is what goes away when the window closes.
     */
    Cpu->Step.GuestTf = (result & SVM_RFLAGS_TF) != 0;
    result |= SVM_RFLAGS_TF;

    vmcb->StateSave.Rflags = result;
    vmcb->StateSave.Rsp += operandSize;
    vmcb->StateSave.Rip += insnLength;
    return TRUE;
}

VOID SvStepCounters(_Out_ UINT64* Steps, _Out_ UINT64* Exposed)
{
    *Steps = (UINT64)InterlockedCompareExchange64(&g_Steps, 0, 0);
    *Exposed = (UINT64)InterlockedCompareExchange64(&g_Exposed, 0, 0);
}
