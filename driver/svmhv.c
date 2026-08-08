/*
 * svmhv.c - a minimal AMD-V (SVM) hypervisor for Windows x64.
 *
 * It virtualises the *running* OS: every logical processor captures its own
 * state, enters guest mode with VMRUN and continues executing the same code it
 * was already executing, one privilege level further down.
 *
 * The guest runs under nested page tables that map every guest physical page to
 * itself, so memory behaves exactly as it did before the driver loaded - the
 * point of the identity map is not isolation but control over permissions.  A
 * page can be made non-executable in one hierarchy and executable-but-shadowed
 * in another, which is how hook.c installs a code hook that nothing can find by
 * reading memory.
 *
 * The other half of the file is about not being noticed: SVM is erased from
 * CPUID and from the guest's view of EFER, every remaining SVM instruction
 * faults exactly as it would on a machine without SVM, the driver's own pages
 * read as zeroes, and the time spent handling an intercepted instruction is
 * subtracted from the guest's TSC.
 *
 * Tested nested under Hyper-V, which is why VMMCALL is forwarded rather than
 * swallowed: the guest OS is itself a Hyper-V child partition and keeps making
 * hypercalls (VMBus signalling, TLB flush enlightenments) that must still reach
 * the hypervisor above us.
 */

#include "svmhv.h"
#include "config.h"
#include "hook.h"
#include "trace.h"
#include "control.h"
#include "hvcall.h"

#ifndef STATUS_HV_FEATURE_UNAVAILABLE
#define STATUS_HV_FEATURE_UNAVAILABLE ((NTSTATUS)0xC0350011L)
#endif

NTSYSAPI    VOID    NTAPI RtlCaptureContext(PCONTEXT ContextRecord);
NTKERNELAPI VOID    KeGenericCallDpc(PKDEFERRED_ROUTINE Routine, PVOID Context);
NTKERNELAPI VOID    KeSignalCallDpcDone(PVOID SystemArgument1);
NTKERNELAPI LOGICAL KeSignalCallDpcSynchronize(PVOID SystemArgument2);

DRIVER_INITIALIZE DriverEntry;
static DRIVER_UNLOAD     SvDriverUnload;
static KDEFERRED_ROUTINE SvVirtualizeDpc;
static KDEFERRED_ROUTINE SvDevirtualizeDpc;

/* The assembler hard-codes these; make a mismatch a compile error. */
C_ASSERT(FIELD_OFFSET(CONTEXT, Rcx)  == 0x080);
C_ASSERT(FIELD_OFFSET(CONTEXT, Rdx)  == 0x088);
C_ASSERT(FIELD_OFFSET(CONTEXT, Rbx)  == 0x090);
C_ASSERT(FIELD_OFFSET(CONTEXT, Rbp)  == 0x0A0);
C_ASSERT(FIELD_OFFSET(CONTEXT, Rsi)  == 0x0A8);
C_ASSERT(FIELD_OFFSET(CONTEXT, Rdi)  == 0x0B0);
C_ASSERT(FIELD_OFFSET(CONTEXT, R8)   == 0x0B8);
C_ASSERT(FIELD_OFFSET(CONTEXT, R15)  == 0x0F0);
C_ASSERT(FIELD_OFFSET(CONTEXT, Xmm0) == 0x1A0);

/* Hyper-V call codes that ask for a TLB flush we have to repeat for our ASID. */
#define HV_CALL_FLUSH_ADDRESS_SPACE       0x0002
#define HV_CALL_FLUSH_ADDRESS_LIST        0x0003
#define HV_CALL_FLUSH_ADDRESS_SPACE_EX    0x0013
#define HV_CALL_FLUSH_ADDRESS_LIST_EX     0x0014

/* ------------------------------------------------------------- globals */

static VIRTUAL_CPU** g_Cpus;
static ULONG         g_CpuCount;
static PVOID         g_Msrpm;              /* 8 KiB, MSR permission map    */
static UINT64        g_MsrpmPa;
static PVOID         g_Iopm;               /* 12 KiB, zeroed, never used   */
static UINT64        g_IopmPa;
static BOOLEAN       g_NripSupported;
static BOOLEAN       g_ForwardHypercalls;  /* TRUE when running under L0   */
static BOOLEAN       g_1GbPages;
static UINT8         g_TlbControl;

/*
 * Everyone flushes their own ASID when this moves.  Bumped by nested page
 * table edits and by forwarded TLB-flush hypercalls, which the layer above us
 * services without any idea that our ASID exists.
 */
static volatile LONG g_FlushGeneration;

static UINT32 SvOptionBits(VOID)
{
    UINT32 bits = 0;

    if (STEALTHV_NESTED_PAGING) bits |= SVMHV_OPT_NESTED_PAGING;
    if (STEALTHV_HIDE_SVM_CPUID) bits |= SVMHV_OPT_HIDE_SVM_CPUID;
    if (STEALTHV_HIDE_EFER)     bits |= SVMHV_OPT_HIDE_EFER;
    if (STEALTHV_TSC_OFFSET)    bits |= SVMHV_OPT_TSC_OFFSET;
    if (STEALTHV_HIDE_PAGES)    bits |= SVMHV_OPT_HIDE_PAGES;
    if (g_ForwardHypercalls) bits |= SVMHV_OPT_PARENT_HYPERVISOR;
    if (g_1GbPages)        bits |= SVMHV_OPT_1GB_PAGES;

    return bits;
}

/* --------------------------------------------------------- capability */

static BOOLEAN SvIsSvmSupported(VOID)
{
    int regs[4];
    int asidCount;

    __cpuid(regs, 0);
    if (regs[1] != 'htuA' || regs[2] != 'DMAc' || regs[3] != 'itne')
    {
        DbgPrint("svmhv: not an AMD processor\n");
        return FALSE;
    }

    __cpuid(regs, CPUID_EXT_FEATURES);
    if ((regs[2] & CPUID_EXT_FEATURE_SVM) == 0)
    {
        DbgPrint("svmhv: CPUID.8000_0001:ECX.SVM is clear\n");
        return FALSE;
    }
    g_1GbPages = (regs[3] & CPUID_EXT_FEATURE_1GB) != 0;

    if ((__readmsr(MSR_VM_CR) & VM_CR_SVMDIS) != 0)
    {
        DbgPrint("svmhv: SVM is disabled and locked by the BIOS (VM_CR.SVMDIS)\n");
        return FALSE;
    }

    __cpuid(regs, CPUID_SVM_FEATURES);
    if (regs[1] <= SVMHV_GUEST_ASID)
    {
        DbgPrint("svmhv: not enough ASIDs (%d)\n", regs[1]);
        return FALSE;
    }
    asidCount = regs[1];
    g_NripSupported = (regs[3] & CPUID_SVM_NRIP_SAVE) != 0;
    g_TlbControl = (regs[3] & CPUID_SVM_FLUSH_BY_ASID) ? SVM_TLB_CONTROL_FLUSH_ASID
                                                       : SVM_TLB_CONTROL_FLUSH_ALL;

    if (STEALTHV_NESTED_PAGING && (regs[3] & CPUID_SVM_NESTED_PAGING) == 0)
    {
        /* Built expecting nested paging, and this processor has none.  Refusing
           to load is better than running with the hooks and the page hiding
           silently absent. */
        DbgPrint("svmhv: nested paging is not available on this processor\n");
        return FALSE;
    }

    /*
     * The NX bit in a nested page table entry is only honoured when the host
     * has EFER.NXE set.  Windows always does; without it the shadow hierarchy
     * would be executable everywhere and hooks would never fire.
     */
    if (STEALTHV_NESTED_PAGING && (__readmsr(MSR_EFER) & EFER_NXE) == 0)
    {
        /* Without NXE the NX bit in a nested entry is ignored, the shadow
           hierarchy is executable everywhere, and no hook would ever fire. */
        DbgPrint("svmhv: host EFER.NXE is clear; nested paging cannot work\n");
        return FALSE;
    }

    /*
     * Are we ourselves a guest?  If so VMMCALL must be relayed upwards; on bare
     * metal it has to raise #UD instead, which is what the guest would see
     * without a hypervisor.
     */
    __cpuid(regs, CPUID_HV_VENDOR);
    g_ForwardHypercalls = (regs[1] == 'rciM' && regs[2] == 'foso' && regs[3] == 'vH t');

    DbgPrint("svmhv: SVM available (nrip=%d, asids=%d, tlbctl=%d, 1gb=%d, "
             "hyper-v parent=%d)\n",
             g_NripSupported, asidCount, g_TlbControl, g_1GbPages,
             g_ForwardHypercalls);
    DbgPrint("svmhv: options: npt=%lu hide-svm-cpuid=%lu hide-efer=%lu "
             "tsc-offset=%lu hide-pages=%lu debug-device=%lu always-flush=%lu\n",
             STEALTHV_NESTED_PAGING, STEALTHV_HIDE_SVM_CPUID, STEALTHV_HIDE_EFER,
             STEALTHV_TSC_OFFSET, STEALTHV_HIDE_PAGES, STEALTHV_CONTROL_INTERFACE,
             STEALTHV_ALWAYS_FLUSH_TLB);

    return TRUE;
}

/* ------------------------------------------------------------- MSRPM */

static VOID SvSetMsrIntercept(_Inout_ UINT8* Msrpm, _In_ UINT32 Msr)
{
    UINT32 base;
    UINT32 bit;

    if (Msr < 0x2000)
    {
        base = 0x000;
        bit = Msr * 2;
    }
    else if (Msr >= 0xC0000000 && Msr < 0xC0002000)
    {
        base = 0x800;
        bit = (Msr - 0xC0000000) * 2;
    }
    else if (Msr >= 0xC0010000 && Msr < 0xC0012000)
    {
        base = 0x1000;
        bit = (Msr - 0xC0010000) * 2;
    }
    else
    {
        NT_ASSERT(FALSE);
        return;
    }

    Msrpm[base + bit / 8] |= (UINT8)(3u << (bit % 8));  /* read + write */
}

/* ---------------------------------------------------------- segments */

static VMCB_SEGMENT SvBuildSegment(_In_ UINT16 Selector, _In_ UINT64 GdtBase)
{
    VMCB_SEGMENT segment;
    const GDT_ENTRY* entry;

    RtlZeroMemory(&segment, sizeof(segment));
    segment.Selector = Selector;

    /* A null selector stays unusable (attrib.P == 0). */
    if ((Selector & ~3u) == 0)
    {
        return segment;
    }

    entry = (const GDT_ENTRY*)(GdtBase + (Selector & ~7u));

    /* VMCB packs descriptor bits 47:40 into 7:0 and 55:52 into 11:8. */
    segment.Attrib = (UINT16)(entry->Attr0 | ((entry->LimitHighAttr1 & 0xF0) << 4));
    segment.Limit  = __segmentlimit(Selector);
    segment.Base   = (UINT64)entry->BaseLow |
                     ((UINT64)entry->BaseMiddle << 16) |
                     ((UINT64)entry->BaseHigh << 24);
    return segment;
}

/* ------------------------------------------------------- exit helpers */

VOID SvSignalTlbFlush(VOID)
{
    InterlockedIncrement(&g_FlushGeneration);
}

static ULONG_PTR SvForceExitIpi(_In_ ULONG_PTR Argument)
{
    int regs[4];

    /* Any intercepted instruction will do; the #VMEXIT is the whole point. */
    __cpuid(regs, 0);
    return Argument;
}

VOID SvSyncTlbFlush(VOID)
{
    SvSignalTlbFlush();

    /*
     * Raising the generation on its own only promises that each processor will
     * flush the next time it leaves guest mode, which may be a long way off -
     * and the caller of a freshly installed hook is usually the instruction
     * immediately after the install.  Until then the processor keeps using the
     * 1 GiB nested translation it cached before the page was split, which is
     * still marked executable, and the hook simply does not fire.
     *
     * So drive an exit everywhere and wait for it.  KeIpiGenericCall runs the
     * routine on every processor, and the CPUID inside it cannot complete
     * without a #VMEXIT that picks up the new generation.
     */
    if (KeGetCurrentIrql() <= DISPATCH_LEVEL)
    {
        KeIpiGenericCall(SvForceExitIpi, 0);
    }
}

static VOID SvAdvanceRip(_Inout_ VMCB* Vmcb, _In_ UINT32 InstructionLength)
{
    /*
     * NRIP-save gives the exact next instruction; without it we fall back to
     * the fixed encoding length of the only instructions we intercept.
     */
    Vmcb->StateSave.Rip = g_NripSupported ? Vmcb->Control.NRip
                                          : Vmcb->StateSave.Rip + InstructionLength;
}

static VOID SvInjectException(_Inout_ VMCB* Vmcb, _In_ UINT64 Vector,
                              _In_ BOOLEAN WithErrorCode)
{
    Vmcb->Control.EventInj = SVM_EVENTINJ_VALID |
                             SVM_EVENTINJ_TYPE_EXCEPTION |
                             (WithErrorCode ? SVM_EVENTINJ_ERRORCODE : 0) |
                             Vector;
}

static VOID SvInjectUd(_Inout_ VMCB* Vmcb)
{
    SvInjectException(Vmcb, SVM_EXCEPTION_UD, FALSE);
}

/* ------------------------------------------------------------ MSRs */

static VOID SvHandleMsr(_Inout_ VIRTUAL_CPU* Cpu, _Inout_ GUEST_CONTEXT* Context)
{
    VMCB* vmcb = &Cpu->GuestVmcb;
    const UINT32 msr = (UINT32)Context->Rcx;
    const BOOLEAN isWrite = (vmcb->Control.ExitInfo1 != 0);
    UINT64 value;

    if (msr == MSR_EFER)
    {
        if (isWrite)
        {
            /* Keep SVME set behind the guest's back. */
            value = ((UINT64)(UINT32)Context->Rdx << 32) | (UINT32)Context->Rax;
            vmcb->StateSave.Efer = value | EFER_SVME;
        }
        else
        {
            value = vmcb->StateSave.Efer & ~EFER_SVME;
            Context->Rax = (UINT32)value;
            Context->Rdx = (UINT32)(value >> 32);
        }

        SvAdvanceRip(vmcb, 2);
        return;
    }

    /*
     * Everything else is only here because enabling the MSR intercept traps
     * every MSR the MSRPM does not describe, so pass it through untouched.  An
     * MSR that does not exist has to keep raising #GP in the guest rather than
     * killing the host, hence the guard: the alternative is a #GP with GIF
     * clear on the host stack.
     */
    __try
    {
        if (isWrite)
        {
            __writemsr(msr, ((UINT64)(UINT32)Context->Rdx << 32) | (UINT32)Context->Rax);
        }
        else
        {
            value = __readmsr(msr);
            Context->Rax = (UINT32)value;
            Context->Rdx = (UINT32)(value >> 32);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        /* Reflect the fault; RIP stays put so the guest retries into its own
           #GP handler. */
        SvInjectException(vmcb, SVM_EXCEPTION_GP, TRUE);
        return;
    }

    SvAdvanceRip(vmcb, 2);
}

/* ------------------------------------------------------- hypercalls */

static BOOLEAN SvHandleVmmcall(_Inout_ VIRTUAL_CPU* Cpu, _Inout_ GUEST_CONTEXT* Context,
                               _Inout_ PVOID XmmSaveArea)
{
    UINT32 callCode;

    /*
     * Ours?  Checked before anything else, and only on the exact magic, so a
     * VMMCALL from anybody else - a Hyper-V enlightenment, or a probe testing
     * whether the instruction faults - takes the paths below untouched.
     */
    if (STEALTHV_CONTROL_INTERFACE && Context->Rax == SVMHV_HYPERCALL_MAGIC)
    {
        const BOOLEAN unload = (Context->Rbx == SVMHV_HV_UNLOAD) &&
                               (Cpu->GuestVmcb.StateSave.Cpl == 0);

        if (unload)
        {
            /* Kernel mode only - user mode must not be able to unload us. */
            Context->Rax = SVMHV_HV_STATUS_OK;
            SvAdvanceRip(&Cpu->GuestVmcb, 3);
            return TRUE;
        }

        SvHandleControlCall(Context);
        SvAdvanceRip(&Cpu->GuestVmcb, 3);
        return FALSE;
    }

    if (!g_ForwardHypercalls)
    {
        /* Bare metal: VMMCALL is #UD to everyone but the hypervisor. */
        SvInjectUd(&Cpu->GuestVmcb);
        return FALSE;
    }

    callCode = (UINT32)(Context->Rcx & 0xFFFF);

    Cpu->HypercallCount++;
    Context->Rax = AsmForwardHypercall(Context->Rcx, Context->Rdx, Context->R8,
                                       XmmSaveArea);
    SvAdvanceRip(&Cpu->GuestVmcb, 3);

    /*
     * The hypercall was serviced by the layer above us, which flushed the
     * partition's TLB without knowing that our ASID exists.  Repeat the flush
     * locally on every hypercall - which is exactly where the guest asked for
     * one - and for the flush calls that can target another processor, ask
     * everybody else to do the same on their next entry.  Anything else runs
     * with no flush at all, which is what makes intercepting MSRs affordable.
     */
    Cpu->PendingFlush = TRUE;

    switch (callCode)
    {
    case HV_CALL_FLUSH_ADDRESS_SPACE:
    case HV_CALL_FLUSH_ADDRESS_LIST:
    case HV_CALL_FLUSH_ADDRESS_SPACE_EX:
    case HV_CALL_FLUSH_ADDRESS_LIST_EX:
        SvSignalTlbFlush();
        break;
    default:
        break;
    }

    return FALSE;
}

/* ------------------------------------------------ nested page faults */

static VOID SvSwitchNpt(_Inout_ VIRTUAL_CPU* Cpu, _In_ BOOLEAN Shadow)
{
    Cpu->ShadowNptActive = Shadow;
    Cpu->GuestVmcb.Control.NCr3 = Shadow ? g_NptShadow.Pml4Pa : g_NptPrimary.Pml4Pa;

    /* Nested translations are ASID-tagged, so changing NCr3 needs a flush. */
    Cpu->PendingFlush = TRUE;
    Cpu->HookSwitches++;
    Cpu->SpuriousNpf = 0;
}

/*
 * Hooked and watched pages are the only pages whose permissions differ between
 * the two hierarchies, so every nested page fault is one of a handful of things:
 * the guest starting to execute a hooked page, writing to or reading a watched
 * one, leaving such a page again, or using a translation this processor cached
 * before the tables changed underneath it.
 *
 * RIP is never advanced - the faulting instruction is re-executed against the
 * new view, which is what makes this work without decoding it or single-stepping.
 */
static VOID SvHandleNestedPageFault(_Inout_ VIRTUAL_CPU* Cpu)
{
    VMCB* vmcb = &Cpu->GuestVmcb;
    const UINT64 info = vmcb->Control.ExitInfo1;
    const UINT64 gpa  = vmcb->Control.ExitInfo2;
    const UINT64 rip  = vmcb->StateSave.Rip;
    SVM_HOOK_PAGE page;

    Cpu->NpfExits++;

    if (Cpu->ShadowNptActive)
    {
        /*
         * In the shadow hierarchy nothing is executable except the pages we
         * switched here for, and an EXEC hook's copy is read-only.  So a fetch
         * fault means execution has left the page, and a write fault means the
         * guest is writing to code it is currently running - either way the
         * honest view is where it needs to be.
         */
        if ((info & (NPF_EXECUTE | NPF_WRITE)) != 0)
        {
            SvSwitchNpt(Cpu, FALSE);
            return;
        }
        goto unexplained;
    }

    if (SvHookFindPage(gpa, &page))
    {
        switch (page.Kind)
        {
        case SVMHV_HOOK_EXEC:
            /* Only the instruction fetch is trapped; reads and writes are
               served by the primary view and see the original bytes. */
            if ((info & NPF_EXECUTE) != 0)
            {
                SvSwitchNpt(Cpu, TRUE);
                return;
            }
            break;

        case SVMHV_HOOK_WRITE:
            if ((info & NPF_WRITE) != 0)
            {
                SvTraceWatchHit(page.HookId, SVMHV_TRACE_WRITE, rip, gpa, info,
                                Cpu->Index);
                SvHookCountHit(page.HookId);
                SvSwitchNpt(Cpu, TRUE);
                return;
            }
            break;

        case SVMHV_HOOK_ACCESS:
            /* The page is not present at all in the primary view, so this is
               every kind of access, reads included. */
            SvTraceWatchHit(page.HookId, SVMHV_TRACE_ACCESS, rip, gpa, info,
                            Cpu->Index);
            SvHookCountHit(page.HookId);
            SvSwitchNpt(Cpu, TRUE);
            return;

        default:
            break;
        }
    }

    if ((info & NPF_PRESENT) == 0)
    {
        /* Nothing is mapped there, it is not a watchpoint, and we cannot
           allocate a page table with GIF clear.  The identity map covers
           everything the processor can address, so this is a bug. */
        KeBugCheckEx(MANUALLY_INITIATED_CRASH, 0x4E50460ULL, info, gpa,
                     (ULONG_PTR)rip);
    }

unexplained:
    /*
     * Left over: a translation cached before a hook was installed or removed.
     * The mapping is already correct, so flush and retry.  If retrying does not
     * help, the tables really are wrong, and a loop here would hang the machine
     * silently - crash instead.
     */
    if (++Cpu->SpuriousNpf > 16)
    {
        KeBugCheckEx(MANUALLY_INITIATED_CRASH, 0x4E504601ULL, info, gpa,
                     (ULONG_PTR)rip);
    }
    Cpu->PendingFlush = TRUE;
}

/* --------------------------------------------------------- exit path */

/*
 * Returns TRUE to tell AsmLaunchVm to leave SVM and resume the guest natively.
 * Runs with GIF == 0: no interrupts, no NMIs, no page faults we could survive.
 * Keep it short and touch nothing pageable.
 */
BOOLEAN SvHandleVmExit(_In_ VIRTUAL_CPU* Cpu, _Inout_ GUEST_CONTEXT* Context,
                       _Inout_ PVOID XmmSaveArea)
{
    VMCB* vmcb = &Cpu->GuestVmcb;
    BOOLEAN devirtualise = FALSE;

    /* RAX and RSP live in the VMCB rather than on the host stack. */
    Context->Rax = vmcb->StateSave.Rax;
    Context->Rsp = vmcb->StateSave.Rsp;
    Cpu->ExitCount++;

    if (vmcb->Control.ExitCode < RTL_NUMBER_OF(Cpu->ExitCodeCounts))
    {
        Cpu->ExitCodeCounts[vmcb->Control.ExitCode]++;
    }

    switch (vmcb->Control.ExitCode)
    {
    case VMEXIT_MSR:
        /*
         * Nothing is taken off the guest's clock for this, or for anything
         * else.  Timing RDMSR to find a hypervisor is a much rarer trick than
         * timing CPUID, and CPUID is no longer intercepted at all.
         */
        Cpu->MsrExits++;
        SvHandleMsr(Cpu, Context);
        break;

    case VMEXIT_NPF:
        SvHandleNestedPageFault(Cpu);
        break;

    case VMEXIT_VMMCALL:
        devirtualise = SvHandleVmmcall(Cpu, Context, XmmSaveArea);
        break;

    /*
     * Everything SVM adds to the instruction set has to behave the way it does
     * on a processor whose EFER.SVME is clear, which is #UD.  Leaving these
     * unintercepted would be worse than detectable: a guest VMSAVE would
     * happily write host state into a page of its choosing.
     */
    case VMEXIT_VMRUN:
    case VMEXIT_VMLOAD:
    case VMEXIT_VMSAVE:
    case VMEXIT_STGI:
    case VMEXIT_CLGI:
    case VMEXIT_SKINIT:
    case VMEXIT_INVLPGA:
        SvInjectUd(vmcb);
        break;

    case VMEXIT_INVALID:
        /*
         * VMRUN rejected the VMCB, so the guest never started.  Host state has
         * been restored and StateSave.Rip still points at the launch site, so
         * we can unwind straight back into SvVirtualizeProcessor.
         */
        Cpu->LaunchExitCode = vmcb->Control.ExitInfo1;
        Cpu->InvalidExits++;
        Cpu->Virtualized = 0;
        Cpu->LaunchFailed = 1;
        devirtualise = TRUE;
        break;

    default:
        KeBugCheckEx(MANUALLY_INITIATED_CRASH,
                     (ULONG_PTR)vmcb->Control.ExitCode,
                     (ULONG_PTR)vmcb->Control.ExitInfo1,
                     (ULONG_PTR)vmcb->StateSave.Rip,
                     (ULONG_PTR)Cpu);
    }

    vmcb->StateSave.Rax = Context->Rax;

    /*
     * Only CPUID gets its cost hidden.  A detector measures rdtsc-cpuid-rdtsc;
     * a nested page fault or a hypercall cannot be attributed to a particular
     * instruction pair, so paying for those as well would only drag this
     * processor's clock away from the others for no benefit.
     */
    /*
     * Nothing is subtracted from the guest's clock any more, and nothing can be.
     *
     * Hiding the cost of an exit meant writing a per-processor running total
     * into the VMCB that only ever decreased, so each processor's clock walked
     * backwards without bound and away from every other processor's.  Windows
     * needs the TSC invariant and synchronised; it absorbed the skew for a few
     * minutes and then reset the machine, with no bugcheck and no dump.
     *
     * The instruction that made compensation necessary is no longer intercepted,
     * so there is no overhead to hide and TscOffset stays where it started.
     * TscTotal is still accumulated - it is the only measurement of what this
     * hypervisor costs - but it is never charged to the guest.
     */
    Cpu->Layout->TscHide = 0;
    Cpu->TscOverhead = (INT64)Cpu->Layout->TscTotal;
    Cpu->TscHidden   = Cpu->Layout->TscOffset;

    if (Cpu->FlushGeneration != g_FlushGeneration)
    {
        Cpu->FlushGeneration = g_FlushGeneration;
        Cpu->PendingFlush = TRUE;
    }
    vmcb->Control.TlbControl = (STEALTHV_ALWAYS_FLUSH_TLB || Cpu->PendingFlush)
                             ? g_TlbControl : SVM_TLB_CONTROL_NOTHING;
    Cpu->PendingFlush = FALSE;

    /*
     * Re-inject an event the exit interrupted.
     *
     * If a #VMEXIT happens while the processor is *delivering* an interrupt or
     * an exception - reading the IDT, walking a descriptor, pushing the frame -
     * the delivery is abandoned and what was being delivered is recorded in
     * EXITINTINFO.  Nothing redelivers it on its own.  Put it in EVENTINJ and
     * the next VMRUN starts the delivery again from the beginning.
     *
     * Nested paging is what makes this reachable: hidden pages and hooked pages
     * are deliberately not present, so a #NPF taken part-way through delivering
     * a timer interrupt is an ordinary event here, not an exotic one.  Dropping
     * it loses the interrupt silently, and the failure lands arbitrarily far
     * away from the cause - which is exactly the shape of a guest that dies with
     * no bugcheck minutes after load.
     *
     * EXITINTINFO and EVENTINJ share a layout (vector, type, error-code-valid,
     * valid, error code in the top half), so this is a straight copy.  An event
     * the handler has just injected itself wins: that one is about the
     * instruction we are returning to, and it has not been delivered yet.
     */
    if ((vmcb->Control.ExitIntInfo & SVM_EVENTINJ_VALID) != 0 &&
        (vmcb->Control.EventInj & SVM_EVENTINJ_VALID) == 0)
    {
        vmcb->Control.EventInj = vmcb->Control.ExitIntInfo;
        Cpu->EventsReinjected++;
    }

    /* We never claim any part of the VMCB is unchanged. */
    vmcb->Control.VmcbClean = 0;

    return devirtualise;
}

/* --------------------------------------------------------- VMCB setup */

static VOID SvPrepareVmcb(_Inout_ VIRTUAL_CPU* Cpu, _In_ const CONTEXT* Guest)
{
    VMCB* vmcb = &Cpu->GuestVmcb;
    DESCRIPTOR_TABLE_REGISTER gdtr;
    DESCRIPTOR_TABLE_REGISTER idtr;
    const UINT64 guestVmcbPa = (UINT64)MmGetPhysicalAddress(&Cpu->GuestVmcb).QuadPart;
    const UINT64 hostVmcbPa  = (UINT64)MmGetPhysicalAddress(&Cpu->HostVmcb).QuadPart;

    AsmReadGdtr(&gdtr);
    AsmReadIdtr(&idtr);

    __writemsr(MSR_EFER, __readmsr(MSR_EFER) | EFER_SVME);
    __writemsr(MSR_VM_HSAVE_PA,
               (UINT64)MmGetPhysicalAddress(Cpu->HostStateArea).QuadPart);

    /*
     * VMRUN and #VMEXIT do not touch FS, GS, TR, LDTR or the SYSCALL MSRs -
     * that is what VMLOAD/VMSAVE are for.  Snapshot them into both VMCBs now,
     * from the very context that is about to become the guest.
     */
    __svm_vmsave(guestVmcbPa);
    __svm_vmsave(hostVmcbPa);

    /*
     * CPUID is deliberately absent.  On AMD that intercept is one optional bit,
     * and leaving it clear is the difference between rdtsc-cpuid-rdtsc reading
     * ~12000 cycles and reading exactly what the bare processor reads.  It costs
     * the ability to mask the SVM feature bits, which is the one concealment
     * this design gives up; everything the leaves used to carry - the control
     * channel, the signature, the unload doorbell - moved to VMMCALL.
     */
    vmcb->Control.InterceptVector3 = SVM_INTERCEPT_INVLPGA;
    vmcb->Control.InterceptVector4 = SVM_INTERCEPT_VMRUN   |
                                     SVM_INTERCEPT_VMMCALL |
                                     SVM_INTERCEPT_VMLOAD  |
                                     SVM_INTERCEPT_VMSAVE  |
                                     SVM_INTERCEPT_STGI    |
                                     SVM_INTERCEPT_CLGI    |
                                     SVM_INTERCEPT_SKINIT;

    if (STEALTHV_HIDE_EFER)
    {
        vmcb->Control.InterceptVector3 |= SVM_INTERCEPT_MSR;
    }
    vmcb->Control.MsrpmBasePa      = g_MsrpmPa;
    vmcb->Control.IopmBasePa       = g_IopmPa;
    vmcb->Control.GuestAsid        = SVMHV_GUEST_ASID;

    /*
     * The guest's translations are tagged with our ASID, which nothing outside
     * this driver knows about, so flush once on the way in and after that only
     * when the guest asks - see SvHandleVmmcall and SvSignalTlbFlush.
     */
    vmcb->Control.TlbControl = g_TlbControl;
    Cpu->FlushGeneration = g_FlushGeneration;

    if (STEALTHV_NESTED_PAGING)
    {
        vmcb->Control.NpEnable = SVM_NP_ENABLE;
        vmcb->Control.NCr3     = g_NptPrimary.Pml4Pa;
        /* With nested paging on, the VMCB's copy of PAT is the one that
           decides memory types.  Leaving it zero makes every page uncacheable
           and the guest crawls to a halt. */
        vmcb->StateSave.GPat = __readmsr(MSR_PAT);
    }

    vmcb->StateSave.Es = SvBuildSegment((UINT16)Guest->SegEs, gdtr.Base);
    vmcb->StateSave.Cs = SvBuildSegment((UINT16)Guest->SegCs, gdtr.Base);
    vmcb->StateSave.Ss = SvBuildSegment((UINT16)Guest->SegSs, gdtr.Base);
    vmcb->StateSave.Ds = SvBuildSegment((UINT16)Guest->SegDs, gdtr.Base);

    vmcb->StateSave.Gdtr.Base  = gdtr.Base;
    vmcb->StateSave.Gdtr.Limit = gdtr.Limit;
    vmcb->StateSave.Idtr.Base  = idtr.Base;
    vmcb->StateSave.Idtr.Limit = idtr.Limit;

    vmcb->StateSave.Efer = __readmsr(MSR_EFER);
    vmcb->StateSave.Cr0  = __readcr0();
    vmcb->StateSave.Cr2  = __readcr2();
    vmcb->StateSave.Cr3  = __readcr3();
    vmcb->StateSave.Cr4  = __readcr4();
    vmcb->StateSave.Dr6  = __readdr(6);
    vmcb->StateSave.Dr7  = __readdr(7);
    vmcb->StateSave.Cpl  = 0;

    vmcb->StateSave.Rflags = Guest->EFlags;
    vmcb->StateSave.Rsp    = Guest->Rsp;
    vmcb->StateSave.Rip    = Guest->Rip;
    vmcb->StateSave.Rax    = Guest->Rax;

    Cpu->Layout->GuestVmcbPa = guestVmcbPa;
    Cpu->Layout->HostVmcbPa  = hostVmcbPa;
    Cpu->Layout->GuestVmcbVa = vmcb;
    Cpu->Layout->Cpu         = Cpu;
    Cpu->Layout->TscExit     = 0;
    Cpu->Layout->TscOffset   = 0;
    Cpu->Layout->TscHide     = 0;
    Cpu->Layout->TscTotal    = 0;
}

static VOID SvVirtualizeProcessor(_Inout_ VIRTUAL_CPU* Cpu)
{
    PCONTEXT context = &Cpu->ContextRecord;

    RtlCaptureContext(context);

    /*
     * Second arrival: either VMRUN succeeded and this is the guest executing
     * the very next instruction, or the launch was rejected and the exit
     * handler unwound us back here.
     */
    if (Cpu->Virtualized != 0 || Cpu->LaunchFailed != 0)
    {
        return;
    }

    SvPrepareVmcb(Cpu, context);
    Cpu->Virtualized = 1;

    AsmLaunchVm(Cpu->Layout, context);
    __debugbreak();   /* unreachable */
}

static VOID SvVirtualizeDpc(_In_ PKDPC Dpc, _In_opt_ PVOID Context,
                            _In_opt_ PVOID SystemArgument1,
                            _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Context);

    SvVirtualizeProcessor(g_Cpus[KeGetCurrentProcessorIndex()]);

    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}

static VOID SvDevirtualizeDpc(_In_ PKDPC Dpc, _In_opt_ PVOID Context,
                              _In_opt_ PVOID SystemArgument1,
                              _In_opt_ PVOID SystemArgument2)
{
    VIRTUAL_CPU* cpu = g_Cpus[KeGetCurrentProcessorIndex()];

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Context);

    if (cpu->Virtualized != 0)
    {
        /* Traps into the hypervisor, which drops SVM and returns here. */
        if (AsmUnloadCall() == SVMHV_HV_STATUS_OK)
        {
            cpu->Virtualized = 0;
        }
    }

    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}

/* ------------------------------------------------------ alloc / free */

static PVOID SvAllocateContiguous(_In_ SIZE_T Size, _Out_ UINT64* PhysicalAddress)
{
    PHYSICAL_ADDRESS highest;
    PVOID va;

    highest.QuadPart = MAXULONG64;
    va = MmAllocateContiguousMemory(Size, highest);
    if (va == NULL)
    {
        *PhysicalAddress = 0;
        return NULL;
    }

    RtlZeroMemory(va, Size);
    *PhysicalAddress = (UINT64)MmGetPhysicalAddress(va).QuadPart;
    return va;
}

static VOID SvFreeResources(VOID)
{
    ULONG i;

    if (g_Cpus != NULL)
    {
        for (i = 0; i < g_CpuCount; i++)
        {
            if (g_Cpus[i] == NULL)
            {
                continue;
            }
            if (g_Cpus[i]->HostStackBase != NULL)
            {
                MmFreeContiguousMemory(g_Cpus[i]->HostStackBase);
            }
            MmFreeContiguousMemory(g_Cpus[i]);
        }
        ExFreePoolWithTag(g_Cpus, SVMHV_POOL_TAG);
        g_Cpus = NULL;
    }

    if (g_Msrpm != NULL)
    {
        MmFreeContiguousMemory(g_Msrpm);
        g_Msrpm = NULL;
    }
    if (g_Iopm != NULL)
    {
        MmFreeContiguousMemory(g_Iopm);
        g_Iopm = NULL;
    }
}

static NTSTATUS SvAllocateResources(VOID)
{
    ULONG i;

    g_CpuCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    g_Cpus = (VIRTUAL_CPU**)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                            sizeof(VIRTUAL_CPU*) * g_CpuCount,
                                            SVMHV_POOL_TAG);
    if (g_Cpus == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_Msrpm = SvAllocateContiguous(2 * PAGE_SIZE, &g_MsrpmPa);
    g_Iopm  = SvAllocateContiguous(3 * PAGE_SIZE, &g_IopmPa);
    if (g_Msrpm == NULL || g_Iopm == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* The only MSR we care about; everything else runs unintercepted. */
    SvSetMsrIntercept((UINT8*)g_Msrpm, MSR_EFER);

    for (i = 0; i < g_CpuCount; i++)
    {
        VIRTUAL_CPU* cpu;
        UINT8* stack;
        UINT64 ignored;

        cpu = (VIRTUAL_CPU*)SvAllocateContiguous(sizeof(VIRTUAL_CPU), &ignored);
        if (cpu == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        g_Cpus[i] = cpu;

        /*
         * Contiguous rather than pool, purely for the alignment: the host stack
         * is hidden from the guest a page at a time, and a pool allocation
         * would share its first and last page with somebody else's data.
         */
        stack = (UINT8*)SvAllocateContiguous(SVMHV_HOST_STACK_SIZE, &ignored);
        if (stack == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        cpu->HostStackBase = stack;
        cpu->Layout = (HOST_STACK_LAYOUT*)(stack + SVMHV_HOST_STACK_SIZE -
                                           sizeof(HOST_STACK_LAYOUT));
    }

    return STATUS_SUCCESS;
}

/*
 * Erase the hypervisor's own architectural state from the guest's view of
 * physical memory.  Only pages the driver never reads while virtualised can go
 * in here: the VMCBs and the host save area are read by the processor using
 * physical addresses (which the nested tables do not affect), and the host
 * stacks are only ever touched with SVM's host state loaded.
 *
 * Deliberately absent: the nested page tables themselves and the hooks' shadow
 * pages.  Both are edited from guest context, so hiding them would mean the
 * driver writing to the dummy page instead.
 */
static VOID SvHideHypervisorPages(VOID)
{
    ULONG i;
    NTSTATUS status;

    status = SvNptHideRange(g_Msrpm, 2 * PAGE_SIZE);
    if (NT_SUCCESS(status))
    {
        status = SvNptHideRange(g_Iopm, 3 * PAGE_SIZE);
    }

    for (i = 0; NT_SUCCESS(status) && i < g_CpuCount; i++)
    {
        /* Pages 0-2 only: GuestVmcb, HostVmcb, HostStateArea.  Page 3 carries
           the counters the driver reads back from guest context. */
        status = SvNptHideRange(g_Cpus[i], 3 * PAGE_SIZE);
        if (NT_SUCCESS(status))
        {
            status = SvNptHideRange(g_Cpus[i]->HostStackBase,
                                    SVMHV_HOST_STACK_SIZE);
        }
    }

    if (!NT_SUCCESS(status))
    {
        DbgPrint("svmhv: could not hide every page (%08X), %u split pages used\n",
                 status, SvNptSplitPagesUsed());
    }
    else
    {
        DbgPrint("svmhv: hypervisor pages hidden, %u split pages used\n",
                 SvNptSplitPagesUsed());
    }
}

/* ---------------------------------------------------------- self test */

/*
 * A hook target with a prologue of exactly known length: five bytes of
 * "mov eax, 11111111h" plus nine nops make up the fourteen an absolute jump
 * needs, so the trampoline's jump back lands on the ret.  It lives in its own
 * page so the shadow copy contains nothing but this.
 */
static const UINT8 kVictimCode[] =
{
    0xB8, 0x11, 0x11, 0x11, 0x11,                   /* mov eax, 11111111h   */
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,   /* 9 x nop      */
    0xC3                                            /* ret                  */
};

#define SVMHV_VICTIM_PROLOG 14

/*
 * A second victim, this one with arguments, so the trace path can be checked
 * rather than assumed.  Also exactly fourteen bytes before the ret:
 *
 *   mov rax, rcx      48 89 C8     3
 *   add rax, rdx      48 01 D0     3
 *   add rax, r8       4C 01 C0     3
 *   add rax, r9       4C 01 C8     3
 *   nop; nop          90 90        2
 *   ret               C3
 */
static const UINT8 kArgVictimCode[] =
{
    0x48, 0x89, 0xC8,
    0x48, 0x01, 0xD0,
    0x4C, 0x01, 0xC0,
    0x4C, 0x01, 0xC8,
    0x90, 0x90,
    0xC3
};

typedef ULONG (*SVMHV_VICTIM_FN)(VOID);
typedef UINT64 (*SVMHV_ARG_VICTIM_FN)(UINT64, UINT64, UINT64, UINT64);

static PVOID           g_ArgVictimPage;
static PVOID           g_VictimPage;
static SVMHV_VICTIM_FN g_VictimTrampoline;
static volatile LONG   g_DetourHits;
static ULONG           g_TrampolineResult;

static ULONG SvTestDetour(VOID)
{
    InterlockedIncrement(&g_DetourHits);

    if (g_VictimTrampoline == NULL)
    {
        return 0xDEADBEEF;
    }

    /* Calling the trampoline runs the original prologue and jumps back into
       the middle of the function, which is only reachable through the shadow
       view - so a correct answer here exercises both hierarchies. */
    g_TrampolineResult = g_VictimTrampoline();
    return g_TrampolineResult ^ 0x33333333;
}

static volatile LONG g_VictimHookedCount;
static volatile LONG g_VictimMissedCount;

/*
 * Runs the hooked function on every processor at once.  NCr3 lives in the VMCB,
 * so each processor has to fault into the shadow hierarchy, run the detour and
 * fault back out entirely on its own - if any of that bookkeeping were shared
 * between processors, this is where it would come apart.  Runs at IPI_LEVEL,
 * which is why the detour has to stay as lock-free as the exit handler.
 */
static ULONG_PTR SvVictimIpi(_In_ ULONG_PTR Argument)
{
    const SVMHV_VICTIM_FN fn = (SVMHV_VICTIM_FN)(ULONG_PTR)g_VictimPage;

    if (fn() == SVMHV_VICTIM_HOOKED)
    {
        InterlockedIncrement(&g_VictimHookedCount);
    }
    else
    {
        InterlockedIncrement(&g_VictimMissedCount);
    }

    return Argument;
}

/*
 * RDTSC is not a barrier and the optimiser will hoist a CPUID whose result
 * nobody reads clean out of the loop, leaving a "measurement" of two
 * back-to-back RDTSCs.  A volatile leaf keeps the call inside the loop and a
 * volatile sink keeps it from being deleted outright.
 */
static volatile ULONG g_TimingLeaf;     /* stays 0; volatile on purpose      */
static volatile int   g_TimingSink;

static UINT64 SvMeasureCpuid(_In_ BOOLEAN WithCpuid)
{
    const ULONG count = 2000;
    UINT64 start;
    UINT64 elapsed;
    ULONG i;
    int regs[4];
    KIRQL irql;

    irql = KeRaiseIrqlToDpcLevel();

    __cpuid(regs, (int)g_TimingLeaf);
    start = __rdtsc();
    for (i = 0; i < count; i++)
    {
        if (WithCpuid)
        {
            __cpuid(regs, (int)g_TimingLeaf);
            g_TimingSink += regs[0];
        }
        else
        {
            _mm_lfence();
        }
    }
    elapsed = __rdtsc() - start;

    KeLowerIrql(irql);
    return elapsed / count;
}

VOID SvRunSelfTest(_Out_ SVMHV_SELFTEST* Result)
{
    /* Function and data pointers go through an integer: the compiler is right
       that mixing them is nonstandard, and this file does it on purpose. */
    const SVMHV_VICTIM_FN victim = (SVMHV_VICTIM_FN)(ULONG_PTR)g_VictimPage;
    PVOID detour = (PVOID)(ULONG_PTR)SvTestDetour;
    VIRTUAL_CPU* cpu;
    PVOID trampoline = NULL;
    SVMHV_HOOK_REQUEST request;
    int regs[4];

    RtlZeroMemory(Result, sizeof(*Result));
    Result->Options = SvOptionBits();

    /* --- what a guest can see about SVM itself --- */
    Result->EferSeenByGuest = __readmsr(MSR_EFER);
    if ((Result->EferSeenByGuest & EFER_SVME) == 0)
    {
        Result->Passed |= SVMHV_TEST_EFER_HIDDEN;
    }

    __cpuid(regs, CPUID_EXT_FEATURES);
    Result->CpuidSvmBit = (regs[2] & CPUID_EXT_FEATURE_SVM) ? 1 : 0;
    if (Result->CpuidSvmBit == 0)
    {
        Result->Passed |= SVMHV_TEST_SVM_CPUID_HIDDEN;
    }

    __cpuid(regs, CPUID_SVM_FEATURES);
    Result->SvmFeatureLeaf[0] = (UINT32)regs[0];
    Result->SvmFeatureLeaf[1] = (UINT32)regs[1];
    Result->SvmFeatureLeaf[2] = (UINT32)regs[2];
    Result->SvmFeatureLeaf[3] = (UINT32)regs[3];
    if ((regs[0] | regs[1] | regs[2] | regs[3]) == 0)
    {
        Result->Passed |= SVMHV_TEST_SVM_LEAF_HIDDEN;
    }

    Result->CpuidCycles    = SvMeasureCpuid(TRUE);
    Result->BaselineCycles = SvMeasureCpuid(FALSE);

    if (STEALTHV_NESTED_PAGING)
    {
        Result->Passed |= SVMHV_TEST_NPT_ACTIVE;
    }

    /* --- the hook --- */
    if (g_VictimPage == NULL)
    {
        return;
    }

    Result->VictimPlain = victim();
    RtlCopyMemory(Result->OriginalBytes, g_VictimPage, sizeof(Result->OriginalBytes));

    g_DetourHits = 0;
    g_TrampolineResult = 0;

    RtlZeroMemory(&request, sizeof(request));
    request.Target = (UINT64)g_VictimPage;
    request.Detour = (UINT64)detour;
    request.PrologLength = SVMHV_VICTIM_PROLOG;
    request.Action = SVMHV_ACTION_DETOUR;
    request.Kind = SVMHV_HOOK_EXEC;

    if (!NT_SUCCESS(SvHookInstall(&request)))
    {
        return;
    }
    Result->Passed |= SVMHV_TEST_HOOK_INSTALLED;
    trampoline = (PVOID)request.Trampoline;
    g_VictimTrampoline = (SVMHV_VICTIM_FN)(ULONG_PTR)trampoline;

    Result->VictimHooked = victim();

    /*
     * The whole point.  Reading the function while it is hooked has to give
     * back the original instructions, because the primary hierarchy still maps
     * the untouched page for anything that is not an instruction fetch.
     */
    RtlCopyMemory(Result->BytesWhileHooked, g_VictimPage,
                  sizeof(Result->BytesWhileHooked));
    if (RtlCompareMemory(Result->BytesWhileHooked, Result->OriginalBytes,
                         sizeof(Result->OriginalBytes)) ==
        sizeof(Result->OriginalBytes))
    {
        Result->Passed |= SVMHV_TEST_READS_UNCHANGED;
    }

    /* Every processor, simultaneously, while the hook is live. */
    g_VictimHookedCount = 0;
    g_VictimMissedCount = 0;
    KeIpiGenericCall(SvVictimIpi, 0);
    Result->CpusHooked = (UINT32)g_VictimHookedCount;
    Result->CpusMissed = (UINT32)g_VictimMissedCount;
    if (Result->CpusMissed == 0 && Result->CpusHooked == g_CpuCount)
    {
        Result->Passed |= SVMHV_TEST_ALL_CPUS;
    }

    Result->DetourHits       = (UINT32)g_DetourHits;
    Result->TrampolineResult = g_TrampolineResult;
    if (Result->DetourHits != 0)
    {
        Result->Passed |= SVMHV_TEST_DETOUR_RAN;
    }
    if (Result->TrampolineResult == SVMHV_VICTIM_PLAIN &&
        Result->VictimHooked == SVMHV_VICTIM_HOOKED)
    {
        Result->Passed |= SVMHV_TEST_TRAMPOLINE_OK;
    }

    SvHookRemove(g_VictimPage);
    g_VictimTrampoline = NULL;

    Result->VictimUnhooked = victim();
    if (Result->VictimUnhooked == SVMHV_VICTIM_PLAIN)
    {
        Result->Passed |= SVMHV_TEST_UNHOOK_OK;
    }

    cpu = g_Cpus[KeGetCurrentProcessorIndex()];
    Result->NpfExitsOnThisCpu = cpu->NpfExits;

    /*
     * And now the trace path, on the victim that takes arguments.  This checks
     * two things at once: that the recorder saw the right values, and that it
     * handed the call on unmolested - the sum can only come out right if every
     * argument survived AsmTraceEntry and the trampoline ran the original code.
     */
    if (g_ArgVictimPage == NULL)
    {
        return;
    }

    RtlZeroMemory(&request, sizeof(request));
    request.Target = (UINT64)g_ArgVictimPage;
    request.PrologLength = SVMHV_VICTIM_PROLOG;
    request.Action = SVMHV_ACTION_TRACE;
    request.Kind = SVMHV_HOOK_EXEC;

    if (NT_SUCCESS(SvHookInstall(&request)))
    {
        const SVMHV_ARG_VICTIM_FN fn =
            (SVMHV_ARG_VICTIM_FN)(ULONG_PTR)g_ArgVictimPage;

        Result->ArgVictimResult = fn(0x1111111111111111ULL,
                                     0x2222222222222222ULL,
                                     0x3333333333333333ULL,
                                     0x4444444444444444ULL);

        SvTraceLastExec(Result->TracedArguments, &Result->TracedRecords);
        SvHookRemove(g_ArgVictimPage);

        if (Result->ArgVictimResult == SVMHV_ARG_VICTIM_SUM &&
            Result->TracedRecords != 0 &&
            Result->TracedArguments[0] == 0x1111111111111111ULL &&
            Result->TracedArguments[1] == 0x2222222222222222ULL &&
            Result->TracedArguments[2] == 0x3333333333333333ULL &&
            Result->TracedArguments[3] == 0x4444444444444444ULL)
        {
            Result->Passed |= SVMHV_TEST_TRACE_OK;
        }
    }
}

/* ------------------------------------------------ published counters --- */

/*
 * Both of these are republished into g_Snapshot by the control worker, so a
 * client reads one structure instead of walking per-processor state whose layout
 * it would otherwise have to know.
 */
VOID SvFillStats(_Out_ SVMHV_STATS* Stats)
{
    ULONG i;

    RtlZeroMemory(Stats, sizeof(*Stats));

    Stats->CpuCount          = g_CpuCount;
    Stats->Options           = SvOptionBits();
    Stats->ActiveHooks       = SvHookActiveCount();
    Stats->NptSplitPagesUsed = SvNptSplitPagesUsed();
    Stats->NptCoverageBytes  = STEALTHV_NESTED_PAGING ? SvNptCoverage() : 0;
    /* Nothing is measured or hidden now that CPUID runs natively. */
    Stats->NativeCpuidCycles = 0;
    Stats->HiddenPerExit     = 0;
    SvTraceCounters(&Stats->TraceRecords, &Stats->TraceDropped,
                    &Stats->TraceFiltered);

    for (i = 0; i < g_CpuCount; i++)
    {
        const VIRTUAL_CPU* cpu = g_Cpus[i];

        Stats->Exits          += cpu->ExitCount;
        Stats->CpuidExits     += cpu->CpuidExits;
        Stats->MsrExits       += cpu->MsrExits;
        Stats->NpfExits       += cpu->NpfExits;
        Stats->HookSwitches   += cpu->HookSwitches;
        Stats->Hypercalls     += cpu->HypercallCount;
        Stats->OverheadCycles += (UINT64)cpu->TscOverhead;
        Stats->HiddenCycles   += (UINT64)(-cpu->TscHidden);

        if (i < SVMHV_MAX_REPORTED_CPUS)
        {
            Stats->PerCpuExits[i] = cpu->ExitCount;
        }
    }
}

VOID SvFillExitHistogram(_Out_ SVMHV_EXIT_HISTOGRAM* Histogram)
{
    ULONG cpu;
    ULONG i;

    RtlZeroMemory(Histogram, sizeof(*Histogram));
    Histogram->CpuCount = g_CpuCount;

    for (cpu = 0; cpu < g_CpuCount; cpu++)
    {
        const VIRTUAL_CPU* virtualCpu = g_Cpus[cpu];

        for (i = 0; i < SVMHV_EXIT_CODE_SLOTS; i++)
        {
            Histogram->Counts[i] += virtualCpu->ExitCodeCounts[i];
        }
        Histogram->NestedPageFaults += virtualCpu->NpfExits;
        Histogram->Invalid += virtualCpu->InvalidExits;
    }
}


/* --------------------------------------------------------- entry/exit */

static VOID SvDriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    ULONG i;
    UINT64 exits = 0;
    UINT64 cpuids = 0;
    UINT64 msrs = 0;
    UINT64 npf = 0;
    UINT64 switches = 0;
    UINT64 hypercalls = 0;
    INT64 overhead = 0;
    INT64 hidden = 0;

    UNREFERENCED_PARAMETER(DriverObject);

    SvControlStop();

    if (g_Cpus != NULL)
    {
        KeGenericCallDpc(SvDevirtualizeDpc, NULL);

        for (i = 0; i < g_CpuCount; i++)
        {
            exits += g_Cpus[i]->ExitCount;
            cpuids += g_Cpus[i]->CpuidExits;
            msrs += g_Cpus[i]->MsrExits;
            npf += g_Cpus[i]->NpfExits;
            switches += g_Cpus[i]->HookSwitches;
            hypercalls += g_Cpus[i]->HypercallCount;
            overhead += g_Cpus[i]->TscOverhead;
            hidden += g_Cpus[i]->TscHidden;
            if (g_Cpus[i]->Virtualized != 0)
            {
                DbgPrint("svmhv: CPU %lu failed to devirtualise - leaking state\n", i);
                return;   /* never free a VMCB the CPU may still be using */
            }
        }
        DbgPrint("svmhv: devirtualised, %llu exits (cpuid %llu, msr %llu, "
                 "npf %llu, hook switches %llu, hypercall %llu), "
                 "%lld cycles in host mode, %lld hidden from the guest\n",
                 exits, cpuids, msrs, npf, switches, hypercalls,
                 overhead, -hidden);
    }

    /* Only now that no processor is in guest mode can the shadow pages and the
       nested page tables go away. */
    SvHookCleanup();

    if (g_VictimPage != NULL)
    {
        SvHookFreeExecutable(g_VictimPage);
        g_VictimPage = NULL;
    }
    if (g_ArgVictimPage != NULL)
    {
        SvHookFreeExecutable(g_ArgVictimPage);
        g_ArgVictimPage = NULL;
    }
    SvTraceFree();

    SvNptFree();
    SvFreeResources();
    DbgPrint("svmhv: unloaded\n");
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    ULONG i;

    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = SvDriverUnload;

    DbgPrint("svmhv: loading\n");

    if (!SvIsSvmSupported())
    {
        return STATUS_HV_FEATURE_UNAVAILABLE;
    }

    status = SvAllocateResources();
    if (!NT_SUCCESS(status))
    {
        SvFreeResources();
        return status;
    }

    if (STEALTHV_NESTED_PAGING)
    {
        status = SvNptInitialize();
        if (!NT_SUCCESS(status))
        {
            DbgPrint("svmhv: nested page tables unavailable (%08X)\n", status);
            SvNptFree();
            SvFreeResources();
            return status;
        }

        status = SvHookInitialize();
        if (!NT_SUCCESS(status))
        {
            SvNptFree();
            SvFreeResources();
            return status;
        }

        /* The self-test victim: one page of its own, executable, so hooking it
           cannot disturb anything else. */
        g_VictimPage = SvHookAllocateExecutable(PAGE_SIZE);
        if (g_VictimPage != NULL)
        {
            RtlFillMemory(g_VictimPage, PAGE_SIZE, 0xCC);
            RtlCopyMemory(g_VictimPage, kVictimCode, sizeof(kVictimCode));
        }

        g_ArgVictimPage = SvHookAllocateExecutable(PAGE_SIZE);
        if (g_ArgVictimPage != NULL)
        {
            RtlFillMemory(g_ArgVictimPage, PAGE_SIZE, 0xCC);
            RtlCopyMemory(g_ArgVictimPage, kArgVictimCode, sizeof(kArgVictimCode));
        }

        status = SvTraceInitialize();
        if (!NT_SUCCESS(status))
        {
            DbgPrint("svmhv: no trace ring (%08X); hooks can still detour\n",
                     status);
        }

        if (STEALTHV_HIDE_PAGES)
        {
            SvHideHypervisorPages();
        }
    }

    KeGenericCallDpc(SvVirtualizeDpc, NULL);

    for (i = 0; i < g_CpuCount; i++)
    {
        if (g_Cpus[i]->Virtualized == 0)
        {
            DbgPrint("svmhv: CPU %lu failed to enter guest mode (exitinfo1 %llx)\n",
                     i, g_Cpus[i]->LaunchExitCode);
            KeGenericCallDpc(SvDevirtualizeDpc, NULL);
            SvHookCleanup();
            if (g_VictimPage != NULL)
            {
                SvHookFreeExecutable(g_VictimPage);
                g_VictimPage = NULL;
            }
            if (g_ArgVictimPage != NULL)
            {
                SvHookFreeExecutable(g_ArgVictimPage);
                g_ArgVictimPage = NULL;
            }
            SvTraceFree();
            SvNptFree();
            SvFreeResources();
            return STATUS_UNSUCCESSFUL;
        }
    }

    DbgPrint("svmhv: %lu processors are now guests\n", g_CpuCount);

    /*
     * Self-test: ask ourselves who we are, over the VMMCALL channel.  A correct
     * answer proves the whole path - VMRUN, the exit handler, and the return to
     * the guest - is live.  It used to be a CPUID leaf; CPUID is no longer
     * intercepted, which is the point.
     */
    if (STEALTHV_CONTROL_INTERFACE)
    {
        SVMHV_HV_SIGNATURE_RESULT probe;
        char signature[13] = { 0 };

        AsmSignatureCall(&probe);
        RtlCopyMemory(signature + 0, &probe.Rbx, 4);
        RtlCopyMemory(signature + 4, &probe.Rdx, 4);
        RtlCopyMemory(signature + 8, &probe.Rsi, 4);

        DbgPrint("svmhv: self-test -> \"%s\"\n", signature);

        if (strcmp(signature, "SVMHV-SIMPLE") != 0)
        {
            DbgPrint("svmhv: SELF-TEST FAILED - vmmcall was not intercepted\n");
        }
    }

    if (STEALTHV_CONTROL_INTERFACE)
    {
        status = SvControlStart();
        if (!NT_SUCCESS(status))
        {
            DbgPrint("svmhv: could not start the control worker (%08X)\n", status);
        }
    }

    return STATUS_SUCCESS;
}
