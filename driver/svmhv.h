/*
 * svmhv.h - driver-internal types shared between svmhv.c and svmasm.asm.
 */

#pragma once

#include "svm.h"
#include "npt.h"
#include "svmhvctl.h"
#include "trace.h"      /* SVMHV_WATCH_PENDING lives in the VIRTUAL_CPU */
#include "step.h"       /* and so does SVMHV_STEP_STATE                 */

#define SVMHV_POOL_TAG          'vmvS'      /* "Svmv" */
#define SVMHV_HOST_STACK_SIZE   0x6000      /* 24 KiB per CPU              */
#define SVMHV_GUEST_ASID        1

/*
 * Guest GPRs as pushed by the PUSHAQ macro in svmasm.asm.  Lowest address
 * first, i.e. reverse push order.  'Rsp' is a dummy slot pushed only to keep
 * the frame 16-byte aligned; the real guest RSP lives in the VMCB.
 */
typedef struct _GUEST_CONTEXT
{
    UINT64 R15, R14, R13, R12, R11, R10, R9, R8;
    UINT64 Rdi, Rsi, Rbp, Rsp, Rbx, Rdx, Rcx, Rax;
} GUEST_CONTEXT;

C_ASSERT(sizeof(GUEST_CONTEXT) == 0x80);

/*
 * Sits at the very top of the host stack.  svmasm.asm addresses these slots
 * as [rsp + 0x80 + n] after PUSHAQ, so the offsets must not move.
 */
typedef struct _HOST_STACK_LAYOUT
{
    UINT64          GuestVmcbPa;    /* +0x00 - also RAX operand of VMRUN   */
    UINT64          HostVmcbPa;     /* +0x08                               */
    struct _VIRTUAL_CPU* Cpu;       /* +0x10                               */
    VMCB*           GuestVmcbVa;    /* +0x18                               */

    /*
     * TSC accounting, maintained entirely in svmasm.asm.  TscExit is stamped
     * the moment control returns to the host; TscTotal accumulates every cycle
     * spent there, and TscOffset accumulates the part of it that is hidden
     * from the guest, negated, ready to be copied into the VMCB.
     *
     * TscHide is how many cycles to take off the guest's clock for this exit,
     * or zero to leave it alone.  It is a calibrated constant rather than the
     * measured residency, for two reasons.  Running nested, most of what an
     * intercepted instruction costs is spent inside the hypervisor above us
     * emulating the #VMEXIT and the VMRUN, which is time this driver never gets
     * to see, let alone measure.  And hiding the residency in full would make
     * CPUID look faster than the hardware can execute it, which is as much of a
     * tell as making it look slow.  So the driver measures the instruction twice
     * - once before the first VMRUN and once as a guest - and hides exactly the
     * difference of the two minima.
     */
    UINT64          TscExit;        /* +0x20                               */
    INT64           TscOffset;      /* +0x28                               */
    UINT64          TscHide;        /* +0x30                               */
    UINT64          TscTotal;       /* +0x38                               */
} HOST_STACK_LAYOUT;

C_ASSERT(sizeof(HOST_STACK_LAYOUT) == 0x40);
C_ASSERT(FIELD_OFFSET(HOST_STACK_LAYOUT, TscExit)   == 0x20);
C_ASSERT(FIELD_OFFSET(HOST_STACK_LAYOUT, TscOffset) == 0x28);
C_ASSERT(FIELD_OFFSET(HOST_STACK_LAYOUT, TscHide)   == 0x30);
C_ASSERT(FIELD_OFFSET(HOST_STACK_LAYOUT, TscTotal)  == 0x38);

/*
 * Per-CPU state.  Allocated as one physically contiguous, page-aligned block
 * so the three architectural pages below are trivially 4 KiB aligned.
 */
typedef struct DECLSPEC_ALIGN(PAGE_SIZE) _VIRTUAL_CPU
{
    VMCB    GuestVmcb;                      /* page 0                      */
    VMCB    HostVmcb;                       /* page 1                      */
    UINT8   HostStateArea[PAGE_SIZE];       /* page 2 - VM_HSAVE_PA        */

    /*
     * Page 3: bookkeeping, not touched by the CPU.  The three pages above are
     * hidden from the guest through the nested page tables, so nothing here
     * may live in them - this is the only part of the structure the driver
     * itself reads while virtualised.
     */
    ULONG   Index;                  /* our own copy: KeGetCurrentProcessor- */
                                    /* Index() is not worth calling with    */
                                    /* GIF clear when we already know it    */
    volatile LONG Virtualized;
    volatile LONG LaunchFailed;
    UINT64  LaunchExitCode;
    UINT64  ExitCount;
    UINT64  CpuidExits;
    UINT64  MsrExits;
    UINT64  NpfExits;
    UINT64  HookSwitches;
    UINT64  HypercallCount;
    INT64   TscOverhead;            /* mirror of Layout->TscTotal           */
    INT64   TscHidden;              /* mirror of Layout->TscOffset          */
    LONG    FlushGeneration;

    /*
     * Livelock detection for nested page faults that the handler cannot
     * explain.  It has to be *consecutive repetitions of the same fault*, not a
     * running total: an unexplained fault is a normal, survivable event (a
     * translation cached before a hook was installed), and a lifetime counter
     * turns sixteen of those spread over a week of uptime into a bugcheck.
     * A genuine livelock is the same instruction faulting on the same page over
     * and over, which is what these three fields measure.
     */
    UINT64  LastNpfGpa;
    UINT64  LastNpfRip;
    ULONG   SpuriousNpf;

    BOOLEAN PendingFlush;

    /*
     * Which nested hierarchy this processor is using.  ShadowNptActive is kept
     * alongside it because the fault handler asks that question far more often
     * than it asks which of the three, and it reads better where it is used.
     */
    ULONG   NptView;                /* SVMHV_NPT_*                          */
    BOOLEAN ShadowNptActive;

    /*
     * Watch steps that ended somewhere other than their own #DB, because
     * something was delivered to the guest in between.  Harmless and
     * self-correcting - the store faults again - but a large number here means
     * watch records are being duplicated and is worth knowing about.
     */
    UINT64  WatchStepsAbandoned;

    /*
     * A watch record claimed at the fault and held back until the store it
     * trapped has actually run; see SvTraceWatchHit.  One per processor is
     * enough because a processor can only be inside one store at a time, and
     * the exit that completes it is the very next one this processor takes.
     */
    SVMHV_WATCH_PENDING WatchPending;

    /* Whether this processor is single-stepping, and why.  See step.h. */
    SVMHV_STEP_STATE Step;

    /*
     * What the guest last wrote to DEBUGCTL, so a read can be answered with the
     * guest's own value while ours keeps last-branch recording on underneath.
     * See STEALTHV_LBR.
     */
    UINT64  GuestDebugCtl;
    PVOID   HostStackBase;
    HOST_STACK_LAYOUT* Layout;

    /* Which exits this processor actually takes, by exit code.  Codes at or
       above 0x100 - in practice only the nested page fault at 0x400 - are
       counted in NpfExits instead. */
    UINT64  ExitCodeCounts[256];
    UINT64  InvalidExits;

    /* Exits the handler could not deal with, which now take this processor out
       of SVM instead of taking the machine down.  Non-zero here means the
       snapshot's fatal record is worth reading. */
    UINT64  FatalExits;

    /* Interrupts and exceptions this exit interrupted mid-delivery and put back.
       Zero here on a busy guest would mean the re-injection is not working. */
    UINT64  EventsReinjected;

    /* Too big for a DPC stack, and it must survive the VMRUN round trip. */
    DECLSPEC_ALIGN(16) CONTEXT ContextRecord;
} VIRTUAL_CPU;

C_ASSERT(FIELD_OFFSET(VIRTUAL_CPU, HostStateArea) == 2 * PAGE_SIZE);

/* ------------------------------------------------------------ svmasm.asm */

/*
 * Switches to the host stack, restores the captured guest GPRs and enters the
 * VMRUN loop.  Never returns while virtualisation is active.
 */
VOID     AsmLaunchVm(_In_ HOST_STACK_LAYOUT* HostRsp, _In_ PCONTEXT GuestContext);

/* Re-issues a guest VMMCALL in host context so the L0 hypervisor sees it. */
UINT64   AsmForwardHypercall(_In_ UINT64 Rcx, _In_ UINT64 Rdx, _In_ UINT64 R8,
                             _Inout_ PVOID XmmSaveArea);

/* Rings the VMMCALL unload doorbell from CPL 0; returns the hypervisor's status. */
UINT64   AsmUnloadCall(VOID);

/* A hypercall that does nothing but exit.  See SvSyncTlbFlush. */
UINT64   AsmNopCall(VOID);

/* The three registers the signature command answers in. */
typedef struct _SVMHV_HV_SIGNATURE_RESULT
{
    UINT64 Rbx;
    UINT64 Rdx;
    UINT64 Rsi;
} SVMHV_HV_SIGNATURE_RESULT;

VOID     AsmSignatureCall(_Out_ SVMHV_HV_SIGNATURE_RESULT* Out);

VOID     AsmReadGdtr(_Out_ DESCRIPTOR_TABLE_REGISTER* Gdtr);
VOID     AsmReadIdtr(_Out_ DESCRIPTOR_TABLE_REGISTER* Idtr);

/* ------------------------------------------------------------- svmhv.c */

BOOLEAN  SvHandleVmExit(_In_ VIRTUAL_CPU* Cpu, _Inout_ GUEST_CONTEXT* Context,
                        _Inout_ PVOID XmmSaveArea);

/*
 * Ask every processor to flush its ASID on its next entry.  Called after a
 * forwarded TLB-flush hypercall that the layer above us satisfied without
 * knowing about our ASID.  Cheap, and safe to call from the exit handler.
 */
VOID     SvSignalTlbFlush(VOID);

/*
 * The same, but does not return until the flush has actually happened
 * everywhere.  A nested page table edit is not in force on a processor until
 * that processor next leaves guest mode, so anything that changes permissions
 * and then expects the very next instruction to fault - installing a hook, for
 * instance - has to use this.  IRQL <= DISPATCH_LEVEL.
 */
VOID     SvSyncTlbFlush(VOID);

/*
 * TRUE if the page belongs to this driver - its image and therefore all of its
 * globals, its per-processor state, its host stacks, or its nested page tables.
 * A watchpoint on any of it fires from inside the code servicing the
 * watchpoint; see the refusal in SvHookInstall.
 */
BOOLEAN  SvOwnsPage(_In_ PVOID Address);

/*
 * Republished into g_Snapshot by the control worker; see control.c.  Both walk
 * per-processor state whose layout a client should not have to know.
 */
VOID     SvFillStats(_Out_ SVMHV_STATS* Stats);
VOID     SvFillExitHistogram(_Out_ SVMHV_EXIT_HISTOGRAM* Histogram);
VOID     SvRunSelfTest(_Out_ SVMHV_SELFTEST* Result);

/*
 * The last exit the handler could not deal with, and whether one has arrived
 * since the caller last asked.
 *
 * The reporting is split from the recording because of where each half runs.
 * Recording happens in the exit handler with GIF clear, where the only safe
 * thing to do is store a few values; saying so out loud - DbgPrint, and the
 * decision about whether the machine can carry on - belongs to the control
 * worker at PASSIVE_LEVEL.  That split is the entire point: it is what replaced
 * a KeBugCheckEx that could never have produced a dump from where it stood.
 */
VOID     SvFillFatalExit(_Out_ SVMHV_FATAL_EXIT* Fatal);

/* The last SVMHV_FATAL_RING_ENTRIES of them, with the total ever recorded. */
VOID     SvFillFatalRing(_Out_ SVMHV_FATAL_RING* Ring);

/*
 * Trap an MSR or an I/O port and record every access.  PASSIVE_LEVEL: both
 * broadcast an exit so the intercept is in force before they return.
 */
NTSTATUS SvWatchMsr(_In_ UINT32 Msr, _In_ BOOLEAN Enable);
NTSTATUS SvWatchIoPort(_In_ UINT32 Port, _In_ BOOLEAN Enable);
BOOLEAN  SvTakeFatalExitReport(_Out_ SVMHV_FATAL_EXIT* Fatal);

/*
 * Leave guest mode on every processor and enter it again, which is exactly what
 * the power callback does across a suspend.
 *
 * Written to test a path that had never run - a Hyper-V guest does not do S3,
 * so the resume code had only ever been reviewed.  It found something.
 *
 * One cycle works, and works repeatedly: all eight processors come back and the
 * self-test passes on both sides of it.  Seven to nine cycles kill the machine.
 * Two runs, two different bugchecks - 0xEF CRITICAL_PROCESS_DIED on the ninth
 * cycle of a run spaced two seconds apart, 0xB8 ATTEMPTED_SWITCH_FROM_DPC on
 * the seventh of a run spaced thirty seconds apart - which says the damage
 * accumulates per cycle rather than being a matter of going too fast.  Whatever
 * is left behind, one cycle's worth of it is survivable and eight is not.
 *
 * That is not yet root-caused.  It matters less for real suspends, which happen
 * minutes or days apart and would have to accumulate over a very long time, but
 * "resume works" is a claim this cannot support and should not be read as.
 *
 * Deliberately not exposed as an MCP tool: it is a diagnostic that is known to
 * crash the machine if repeated, so reaching it should take a deliberate
 * svmhvctl invocation.
 *
 * Returns how many processors came back virtualised.
 */
ULONG    SvCyclePowerTransition(VOID);
