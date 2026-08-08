/*
 * svmhv.h - driver-internal types shared between svmhv.c and svmasm.asm.
 */

#pragma once

#include "svm.h"
#include "npt.h"
#include "svmhvctl.h"

#define SVMHV_POOL_TAG          'vmvS'      /* "Svmv" */
#define SVMHV_HOST_STACK_SIZE   0x6000      /* 24 KiB per CPU              */
#define SVMHV_GUEST_ASID        1

/*
 * How far behind real time a processor's clock is allowed to fall through TSC
 * compensation, in cycles.  Bounds both the backwards drift and the divergence
 * between processors; see the cap in SvHandleVmExit for why an unbounded total
 * is fatal rather than untidy.
 */
#define SVMHV_MAX_TSC_DRIFT     1000000ULL

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
    ULONG   SpuriousNpf;
    BOOLEAN PendingFlush;
    BOOLEAN ShadowNptActive;
    PVOID   HostStackBase;
    HOST_STACK_LAYOUT* Layout;

    /* Which exits this processor actually takes, by exit code.  Codes at or
       above 0x100 - in practice only the nested page fault at 0x400 - are
       counted in NpfExits instead. */
    UINT64  ExitCodeCounts[256];
    UINT64  InvalidExits;

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
 * Republished into g_Snapshot by the control worker; see control.c.  Both walk
 * per-processor state whose layout a client should not have to know.
 */
VOID     SvFillStats(_Out_ SVMHV_STATS* Stats);
VOID     SvFillExitHistogram(_Out_ SVMHV_EXIT_HISTOGRAM* Histogram);
VOID     SvRunSelfTest(_Out_ SVMHV_SELFTEST* Result);
