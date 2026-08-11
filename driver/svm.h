/*
 * svm.h - AMD SVM (AMD-V) architectural definitions.
 *
 * Offsets follow AMD64 Architecture Programmer's Manual Vol. 2, Appendix B
 * ("Layout of VMCB").  Every field that the driver touches is verified with a
 * C_ASSERT against the architectural offset, so a typo in the padding is a
 * build error rather than a triple fault.
 */

#pragma once

#include <ntddk.h>
#include <intrin.h>

/* ------------------------------------------------------------------ MSRs */

#define MSR_PAT                 0x00000277
#define MSR_EFER                0xC0000080
#define EFER_NXE                (1ULL << 11)
#define EFER_SVME               (1ULL << 12)

#define MSR_VM_CR               0xC0010114
#define VM_CR_SVMDIS            (1ULL << 4)     /* SVM disabled and locked   */

#define MSR_VM_HSAVE_PA         0xC0010117

/* ---------------------------------------------------------------- CPUID */

#define CPUID_EXT_FEATURES      0x80000001      /* ECX[2] = SVM             */
#define CPUID_EXT_FEATURE_SVM   (1u << 2)
#define CPUID_EXT_FEATURE_1GB   (1u << 26)      /* EDX[26] = PDPE1GB        */

#define CPUID_SVM_FEATURES      0x8000000A      /* EBX = #ASIDs, EDX = feat */
#define CPUID_SVM_NESTED_PAGING (1u << 0)
#define CPUID_SVM_LBR_VIRT      (1u << 1)
#define CPUID_SVM_NRIP_SAVE     (1u << 3)
#define CPUID_SVM_FLUSH_BY_ASID (1u << 6)

#define CPUID_ADDRESS_SIZES     0x80000008      /* EAX[7:0] = MAXPHYADDR    */

/* VMCB control area, TLB_CONTROL (offset 0x05C) */
#define SVM_TLB_CONTROL_NOTHING     0
#define SVM_TLB_CONTROL_FLUSH_ALL   1   /* entire TLB, every ASID          */
#define SVM_TLB_CONTROL_FLUSH_ASID  3   /* every entry of this guest's ASID */

#define CPUID_HV_VENDOR         0x40000000      /* hypervisor vendor leaf   */

/*
 * Private CPUID leaves.  0x4FFFFFFF is deliberately far away from the
 * 0x4000_00xx block that Hyper-V owns: this hypervisor runs *nested* under
 * Hyper-V, so the guest still needs to see the real Hyper-V leaves.
 *
 * Both leaves answer only when ECX carries the matching key; with any other
 * ECX they are passed straight through to the hardware, so a guest sweeping
 * CPUID space finds nothing that a bare machine would not also return.
 */
/*
 * The control channel, carried on VMMCALL.
 *
 * CPUID is deliberately *not* intercepted (see config.h): on AMD that intercept
 * is a single optional bit, and leaving it clear is what makes rdtsc-cpuid-rdtsc
 * read exactly what bare metal reads.  VMMCALL replaces it because it is the
 * other instruction a guest can trap on from CPL 3 - unlike VMRUN, VMLOAD,
 * VMSAVE, STGI and CLGI, it has no privilege requirement, precisely so guest
 * applications can talk to a VMM.
 *
 * It is also a quieter channel than CPUID ever was.  Ordinary code never
 * executes VMMCALL, so there is no exit storm and no per-exit overhead to hide;
 * and natively VMMCALL raises #UD, so there is no "native cost" for a detector
 * to time this against.  Without the magic in RAX the instruction behaves
 * exactly as it did before - #UD on bare metal, forwarded to the hypervisor
 * above us when nested - so the channel is invisible to anyone without it.
 *
 * The magic sits in RAX because Hyper-V's hypercall convention uses RCX, RDX
 * and R8 as inputs and RAX only as the return register, so a 64-bit value there
 * cannot be confused with a real hypercall.  The command comes in RBX and
 * arguments in RDX/RSI, and up to 48 bytes come back in RBX/RDX/RSI/RDI/R8/R9.
 *
 * This is the only way in.  There is no device object, no IOCTL and no doorbell
 * a debugger could write.  Which also means there is no ACL: the magic is the
 * whole access check, and it is a constant written out in full a few lines
 * below, in a repository, so it is not a secret from anyone who can read this.
 *
 * Every offset passed to a *hypercall* is bounded against the structure it
 * names, so the channel itself cannot be walked across driver memory.  That is
 * a much smaller claim than it sounds, and it used to be written here as though
 * it were the whole story: the commands the doorbell submits include
 * SVMHV_CMD_READ_MEMORY, SVMHV_CMD_WRITE_PHYSICAL and SVMHV_CMD_HOOK_INSTALL,
 * so anything that can reach this channel owns the machine regardless.  By
 * default that includes ring 3; see STEALTHV_CONTROL_REQUIRE_CPL0 in config.h
 * for why, and for how to close it.
 */
#define SVMHV_HYPERCALL_MAGIC   0x53564D485643414CULL   /* "SVMHVCAL" */

#define SVMHV_HV_PING           0   /* -> rbx = magic, rdx = version        */
#define SVMHV_HV_WRITE_REQUEST  1   /* rdx = offset, rsi = value            */
#define SVMHV_HV_SUBMIT         2   /* rdx = command  -> rbx = sequence     */
#define SVMHV_HV_POLL           3   /* -> rbx = completed, rdx = status     */
#define SVMHV_HV_READ_SNAPSHOT  4   /* rdx = offset, rsi = expected seq     */
#define SVMHV_HV_READ_REQUEST   5   /* rdx = offset -> 48 bytes             */
#define SVMHV_HV_READ_TRACE     6   /* legacy: rdx = index, rsi = offset    */
#define SVMHV_HV_TRACE_STATE    7   /* -> head, records, size, floor, gen   */
#define SVMHV_HV_UNLOAD         8   /* CPL 0 only -> devirtualise           */
#define SVMHV_HV_SIGNATURE      9   /* -> rbx/rdx/rsi = "SVMHV-SIMPLE"      */
#define SVMHV_HV_TRACE_CONSUMED 10  /* rdx = sequence drained up to         */

/*
 * Do nothing, and do it from CPL 0.  The exit is the entire purpose: nested
 * page table edits do not take effect on a processor until it next leaves guest
 * mode, so SvSyncTlbFlush has to be able to make that happen on demand.
 *
 * Answered next to the unload doorbell rather than in the control interface,
 * and for the same reason: a build with STEALTHV_CONTROL_INTERFACE at 0 still
 * installs hooks, and a hook that is not flushed is a hook that does not fire.
 */
#define SVMHV_HV_NOP            11  /* CPL 0 only -> force a #VMEXIT        */
#define SVMHV_HV_READ_TRACE_CURSOR 12 /* rdx = absolute seq, rsi = offset    */

/*
 * Single-step the calling processor for rdx instructions, recording one trace
 * record each.  Answered next to the other VMCB-editing calls rather than in
 * hvcall.c, because arming a step means writing this processor's VMCB and the
 * control worker runs on whichever processor Windows felt like.
 */
#define SVMHV_HV_STEP           13  /* rdx = count, or 0 to report instead  */

/*
 * A user-mode execution hook reporting that its target was called.
 *
 * Its own magic in RAX rather than a command under the ordinary one, because
 * the ordinary ABI puts the command in RBX and RBX is non-volatile: a stub that
 * used it would have to save and restore it around every call, and a stub that
 * forgot would corrupt the caller.  With this, the whole stub touches R11 and
 * RAX - R11 is volatile and is not an argument or part of the varargs
 * convention, and RAX is pushed and popped around the call because AL carries
 * the vector-register count into a varargs function and a hook must not be
 * able to break printf.
 *
 * The hook id is in R11.  Nothing is returned: the handler must leave every
 * other register exactly as it found it, because those are the traced
 * function's arguments.
 */
#define SVMHV_UMHOOK_MAGIC      0x53564D485648554DULL   /* 'SVMHVHUM' */

#define SVMHV_HV_STATUS_OK          0
#define SVMHV_HV_STATUS_BADCOMMAND  1
#define SVMHV_HV_STATUS_BADOFFSET   2
#define SVMHV_HV_STATUS_UNAVAILABLE 3
#define SVMHV_HV_STATUS_RETRY       4   /* record/snapshot changed while read */

/* How many bytes one read command returns. */
#define SVMHV_HV_READ_WINDOW    48

/* ---------------------------------------------------------- exit codes */

#define VMEXIT_INVLPGA          0x07A
#define VMEXIT_CPUID            0x072
#define VMEXIT_MSR              0x07C

/* Exceptions exit at 0x40 + vector.  #DB is what a single step arrives as. */
#define VMEXIT_EXCEPTION_BASE   0x040
#define VMEXIT_EXCEPTION_DB     (VMEXIT_EXCEPTION_BASE + 1)

/*
 * PUSHF and POPF.  Intercepted only while a processor is single-stepping, so
 * that the trap flag we set for our own purposes is not the trap flag the guest
 * reads back.  On Intel there is no equivalent - RFLAGS.TF is simply visible -
 * which is one more thing this design gets for being on AMD.
 */
#define VMEXIT_PUSHF            0x070
#define VMEXIT_POPF             0x071

/* An I/O port the IOPM says to trap.  EXITINFO1 describes the access. */
#define VMEXIT_IOIO             0x07B

#define IOIO_TYPE_IN            (1u << 0)   /* clear means OUT              */
#define IOIO_STRING             (1u << 2)   /* INS/OUTS                     */
#define IOIO_REP                (1u << 3)
#define IOIO_SIZE_8             (1u << 4)
#define IOIO_SIZE_16            (1u << 5)
#define IOIO_SIZE_32            (1u << 6)
#define IOIO_PORT_SHIFT         16
#define VMEXIT_VMRUN            0x080
#define VMEXIT_VMMCALL          0x081
#define VMEXIT_VMLOAD           0x082
#define VMEXIT_VMSAVE           0x083
#define VMEXIT_STGI             0x084
#define VMEXIT_CLGI             0x085
#define VMEXIT_SKINIT           0x086

/*
 * A shutdown condition in the guest - a triple fault.  There is no intercept
 * bit for this one: it always exits, which is the whole point.  A guest that
 * triple-faults under SVM does *not* reset the machine, it hands the state that
 * killed it to the host, and dropping that on the floor is how a guest comes to
 * die leaving no bugcheck, no dump and nothing but a Kernel-Power 41.
 */
#define VMEXIT_SHUTDOWN         0x07F

#define VMEXIT_NPF              0x400
#define VMEXIT_INVALID          (-1LL)

/* EXITINFO1 of a #NPF - the low bits mirror a #PF error code. */
#define NPF_PRESENT             (1ULL << 0)
#define NPF_WRITE               (1ULL << 1)
#define NPF_USER                (1ULL << 2)
#define NPF_RESERVED_BIT        (1ULL << 3)
#define NPF_EXECUTE             (1ULL << 4)

/* --------------------------------------------------- intercept vectors */

/* Control area offset 0x008 - one bit per exception vector. */
#define SVM_INTERCEPT_EXCEPTION(vector)  (1u << (vector))
#define SVM_EXCEPTION_DB_VECTOR 1

/* Control area offset 0x00C */
#define SVM_INTERCEPT_PUSHF     (1u << 16)
#define SVM_INTERCEPT_POPF      (1u << 17)
#define SVM_INTERCEPT_CPUID     (1u << 18)
#define SVM_INTERCEPT_INVLPGA   (1u << 26)
#define SVM_INTERCEPT_IOIO      (1u << 27)
#define SVM_INTERCEPT_MSR       (1u << 28)

/* Control area offset 0x010 */
#define SVM_INTERCEPT_VMRUN     (1u << 0)       /* mandatory                */
#define SVM_INTERCEPT_VMMCALL   (1u << 1)
#define SVM_INTERCEPT_VMLOAD    (1u << 2)
#define SVM_INTERCEPT_VMSAVE    (1u << 3)
#define SVM_INTERCEPT_STGI      (1u << 4)
#define SVM_INTERCEPT_CLGI      (1u << 5)
#define SVM_INTERCEPT_SKINIT    (1u << 6)

/* NP_ENABLE (control area 0x090) */
#define SVM_NP_ENABLE           (1ULL << 0)

/*
 * LBR_VIRTUALIZATION_ENABLE, VMCB control offset 0x0B8 bit 0.
 *
 * With it set, VMRUN and #VMEXIT save and restore DBGCTL and the last-branch
 * registers alongside the rest of the guest state, so BrFrom and BrTo in the
 * state save area describe the last control transfer the *guest* made before
 * the exit.  Without it those fields are not maintained and the host's own
 * branches overwrite the registers before anything can read them.
 */
#define SVM_LBR_VIRTUALIZATION   (1ULL << 0)

/* DEBUGCTL, and the bit in it that turns last-branch recording on. */
#define MSR_DEBUGCTL             0x000001D9
#define DEBUGCTL_LBR             (1ULL << 0)
#define DEBUGCTL_BTF             (1ULL << 1)

/* RFLAGS.TF, and the DR6 bit a single-step #DB sets to say it was one. */
#define SVM_RFLAGS_TF           (1ULL << 8)
#define SVM_DR6_BS              (1ULL << 14)

/* EVENTINJ (control area 0x0A8) */
#define SVM_EVENTINJ_VALID      (1ULL << 31)
#define SVM_EVENTINJ_TYPE_EXCEPTION (3ULL << 8)
#define SVM_EVENTINJ_ERRORCODE  (1ULL << 11)
#define SVM_EXCEPTION_UD        6ULL
#define SVM_EXCEPTION_GP        13ULL

/* ------------------------------------------------- nested page tables */

/*
 * Nested page table entries use the ordinary long-mode page table format.
 * The nested walk is a "user" access, so US must be set on every level or
 * the guest cannot reach the page at all.
 */
#define NPT_PRESENT             (1ULL << 0)
#define NPT_WRITE               (1ULL << 1)
#define NPT_USER                (1ULL << 2)
#define NPT_LARGE               (1ULL << 7)     /* PS: 1 GiB / 2 MiB leaf   */
#define NPT_NO_EXECUTE          (1ULL << 63)
#define NPT_PFN_MASK            0x000FFFFFFFFFF000ULL

#define NPT_TABLE               (NPT_PRESENT | NPT_WRITE | NPT_USER)
#define NPT_LEAF_RWX            (NPT_PRESENT | NPT_WRITE | NPT_USER | NPT_LARGE)

#define NPT_PML4_INDEX(gpa)     (((gpa) >> 39) & 0x1FF)
#define NPT_PDPT_INDEX(gpa)     (((gpa) >> 30) & 0x1FF)
#define NPT_PD_INDEX(gpa)       (((gpa) >> 21) & 0x1FF)
#define NPT_PT_INDEX(gpa)       (((gpa) >> 12) & 0x1FF)

#define NPT_1GB                 0x40000000ULL
#define NPT_2MB                 0x00200000ULL

/* --------------------------------------------------------------- VMCB */

#pragma pack(push, 1)

typedef struct _VMCB_SEGMENT
{
    UINT16 Selector;
    UINT16 Attrib;          /* packed: desc bits 47:40 | 55:52 in 11:8      */
    UINT32 Limit;
    UINT64 Base;
} VMCB_SEGMENT;

C_ASSERT(sizeof(VMCB_SEGMENT) == 16);

typedef struct _VMCB_CONTROL_AREA
{
    UINT16 InterceptCrRead;                 /* 0x000 */
    UINT16 InterceptCrWrite;                /* 0x002 */
    UINT16 InterceptDrRead;                 /* 0x004 */
    UINT16 InterceptDrWrite;                /* 0x006 */
    UINT32 InterceptException;              /* 0x008 */
    UINT32 InterceptVector3;                /* 0x00C */
    UINT32 InterceptVector4;                /* 0x010 */
    UINT32 InterceptVector5;                /* 0x014 */
    UINT8  Reserved1[0x03C - 0x018];
    UINT16 PauseFilterThreshold;            /* 0x03C */
    UINT16 PauseFilterCount;                /* 0x03E */
    UINT64 IopmBasePa;                      /* 0x040 */
    UINT64 MsrpmBasePa;                     /* 0x048 */
    UINT64 TscOffset;                       /* 0x050 */
    UINT32 GuestAsid;                       /* 0x058 */
    UINT8  TlbControl;                      /* 0x05C */
    UINT8  Reserved2[3];
    UINT64 VIntr;                           /* 0x060 */
    UINT64 InterruptShadow;                 /* 0x068 */
    UINT64 ExitCode;                        /* 0x070 */
    UINT64 ExitInfo1;                       /* 0x078 */
    UINT64 ExitInfo2;                       /* 0x080 */
    UINT64 ExitIntInfo;                     /* 0x088 */
    UINT64 NpEnable;                        /* 0x090 */
    UINT64 AvicApicBar;                     /* 0x098 */
    UINT64 GuestPaOfGhcb;                   /* 0x0A0 */
    UINT64 EventInj;                        /* 0x0A8 */
    UINT64 NCr3;                            /* 0x0B0 */
    UINT64 LbrVirtualizationEnable;         /* 0x0B8 */
    UINT64 VmcbClean;                       /* 0x0C0 */
    UINT64 NRip;                            /* 0x0C8 */
    UINT8  NumOfBytesFetched;               /* 0x0D0 */
    UINT8  GuestInstructionBytes[15];       /* 0x0D1 */
    UINT8  Reserved3[0x400 - 0x0E0];
} VMCB_CONTROL_AREA;

C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, InterceptVector4) == 0x010);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, IopmBasePa)       == 0x040);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, TscOffset)        == 0x050);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, GuestAsid)        == 0x058);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, NpEnable)         == 0x090);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, NCr3)             == 0x0B0);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, ExitCode)         == 0x070);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, EventInj)         == 0x0A8);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, VmcbClean)        == 0x0C0);
C_ASSERT(FIELD_OFFSET(VMCB_CONTROL_AREA, NRip)             == 0x0C8);
C_ASSERT(sizeof(VMCB_CONTROL_AREA) == 0x400);

typedef struct _VMCB_STATE_SAVE_AREA
{
    VMCB_SEGMENT Es;                        /* 0x000 */
    VMCB_SEGMENT Cs;                        /* 0x010 */
    VMCB_SEGMENT Ss;                        /* 0x020 */
    VMCB_SEGMENT Ds;                        /* 0x030 */
    VMCB_SEGMENT Fs;                        /* 0x040 */
    VMCB_SEGMENT Gs;                        /* 0x050 */
    VMCB_SEGMENT Gdtr;                      /* 0x060 */
    VMCB_SEGMENT Ldtr;                      /* 0x070 */
    VMCB_SEGMENT Idtr;                      /* 0x080 */
    VMCB_SEGMENT Tr;                        /* 0x090 */
    UINT8  Reserved1[0x0CB - 0x0A0];
    UINT8  Cpl;                             /* 0x0CB */
    UINT32 Reserved2;                       /* 0x0CC */
    UINT64 Efer;                            /* 0x0D0 */
    UINT8  Reserved3[0x148 - 0x0D8];
    UINT64 Cr4;                             /* 0x148 */
    UINT64 Cr3;                             /* 0x150 */
    UINT64 Cr0;                             /* 0x158 */
    UINT64 Dr7;                             /* 0x160 */
    UINT64 Dr6;                             /* 0x168 */
    UINT64 Rflags;                          /* 0x170 */
    UINT64 Rip;                             /* 0x178 */
    UINT8  Reserved4[0x1D8 - 0x180];
    UINT64 Rsp;                             /* 0x1D8 */
    UINT8  Reserved5[0x1F8 - 0x1E0];
    UINT64 Rax;                             /* 0x1F8 */
    UINT64 Star;                            /* 0x200 */
    UINT64 LStar;                           /* 0x208 */
    UINT64 CStar;                           /* 0x210 */
    UINT64 SfMask;                          /* 0x218 */
    UINT64 KernelGsBase;                    /* 0x220 */
    UINT64 SysenterCs;                      /* 0x228 */
    UINT64 SysenterEsp;                     /* 0x230 */
    UINT64 SysenterEip;                     /* 0x238 */
    UINT64 Cr2;                             /* 0x240 */
    UINT8  Reserved6[0x268 - 0x248];
    UINT64 GPat;                            /* 0x268 */
    UINT64 DbgCtl;                          /* 0x270 */
    UINT64 BrFrom;                          /* 0x278 */
    UINT64 BrTo;                            /* 0x280 */
    UINT64 LastExcpFrom;                    /* 0x288 */
    UINT64 LastExcpTo;                      /* 0x290 */
    UINT8  Reserved7[0xC00 - 0x298];
} VMCB_STATE_SAVE_AREA;

C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, Cpl)    == 0x0CB);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, Efer)   == 0x0D0);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, Cr4)    == 0x148);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, Cr0)    == 0x158);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, Rflags) == 0x170);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, Rip)    == 0x178);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, Rsp)    == 0x1D8);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, Rax)    == 0x1F8);
C_ASSERT(FIELD_OFFSET(VMCB_STATE_SAVE_AREA, GPat)   == 0x268);
C_ASSERT(sizeof(VMCB_STATE_SAVE_AREA) == 0xC00);

typedef struct _VMCB
{
    VMCB_CONTROL_AREA    Control;
    VMCB_STATE_SAVE_AREA StateSave;
} VMCB;

C_ASSERT(sizeof(VMCB) == PAGE_SIZE);

/*
 * The assembler needs the same offsets; keep them in lockstep with svmasm.asm
 * (VMCB_TSC_OFFSET / VMCB_RFLAGS / VMCB_RIP / VMCB_RSP).
 */
C_ASSERT(FIELD_OFFSET(VMCB, Control.TscOffset)  == 0x050);
C_ASSERT(FIELD_OFFSET(VMCB, StateSave.Rflags) == 0x570);
C_ASSERT(FIELD_OFFSET(VMCB, StateSave.Rip)    == 0x578);
C_ASSERT(FIELD_OFFSET(VMCB, StateSave.Rsp)    == 0x5D8);

/* --------------------------------------------------- GDT descriptor --- */

typedef struct _GDT_ENTRY
{
    UINT16 LimitLow;
    UINT16 BaseLow;
    UINT8  BaseMiddle;
    UINT8  Attr0;           /* type, S, DPL, P                             */
    UINT8  LimitHighAttr1;  /* limit 19:16, AVL, L, D/B, G                 */
    UINT8  BaseHigh;
} GDT_ENTRY;

C_ASSERT(sizeof(GDT_ENTRY) == 8);

typedef struct _DESCRIPTOR_TABLE_REGISTER
{
    UINT16 Limit;
    UINT64 Base;
} DESCRIPTOR_TABLE_REGISTER;

C_ASSERT(sizeof(DESCRIPTOR_TABLE_REGISTER) == 10);

#pragma pack(pop)
