/*
 * svmhvctl.h - the control interface, and the layouts a client needs in order to
 *              read this driver's state out of its own memory.
 *
 * There is no device object and no IOCTL.  The driver's entire interface is one
 * exported structure, svmhv!g_Control, plus a worker thread that polls it: a
 * client writes a command into it and waits for Completed to catch up with
 * Sequence.  Everything else is just driver memory, and a kernel debugger can
 * read it without asking the driver for anything.
 *
 * That split is deliberate.  Only the operations that have to *run kernel code*
 * go through the doorbell: installing a hook allocates a shadow page, pins the
 * target, builds a trampoline, splits the nested page tables and IPIs every
 * processor.  Reading a counter does not - so the worker republishes the
 * counters into a snapshot on every poll and clients read that.
 *
 * The layouts below are mirrored field-for-field by the struct definitions in
 * mcp\svmhv_mcp.py.  Adding a field means adding it in both places.
 */

#pragma once

/* --------------------------------------------------------------- options */

#define SVMHV_OPT_NESTED_PAGING     0x0001
#define SVMHV_OPT_HIDE_SVM_CPUID    0x0002
#define SVMHV_OPT_HIDE_EFER         0x0004
#define SVMHV_OPT_TSC_OFFSET        0x0008
#define SVMHV_OPT_HIDE_PAGES        0x0010
#define SVMHV_OPT_PARENT_HYPERVISOR 0x0020
#define SVMHV_OPT_1GB_PAGES         0x0040
#define SVMHV_OPT_ALWAYS_FLUSH      0x0080

#define SVMHV_MAX_REPORTED_CPUS     64

typedef struct _SVMHV_STATS
{
    UINT32 CpuCount;
    UINT32 Options;
    UINT32 ActiveHooks;
    UINT32 NptSplitPagesUsed;
    UINT64 NptCoverageBytes;
    UINT64 Exits;
    UINT64 CpuidExits;
    UINT64 MsrExits;
    UINT64 NpfExits;
    UINT64 HookSwitches;
    UINT64 Hypercalls;
    UINT64 OverheadCycles;              /* total host-side residency        */
    UINT64 HiddenCycles;                /* of which subtracted from the TSC */
    UINT64 NativeCpuidCycles;           /* cpuid before virtualising        */
    UINT64 HiddenPerExit;               /* the calibrated compensation      */
    UINT64 TraceRecords;                /* trace events ever produced       */
    UINT64 TraceDropped;                /* lost because the ring lapped     */
    UINT64 TraceFiltered;               /* suppressed by a hook filter      */
    UINT64 PerCpuExits[SVMHV_MAX_REPORTED_CPUS];
} SVMHV_STATS;

/*
 * Every #VMEXIT taken, by exit code, summed over processors.  Codes at or above
 * 0x100 - in practice only the nested page fault at 0x400 - are counted
 * separately.  Reading this is the quickest way to see what a driver running
 * under the hypervisor actually makes it do.
 */
#define SVMHV_EXIT_CODE_SLOTS   256

typedef struct _SVMHV_EXIT_HISTOGRAM
{
    UINT32 CpuCount;
    UINT32 Reserved;
    UINT64 Counts[SVMHV_EXIT_CODE_SLOTS];
    UINT64 NestedPageFaults;
    UINT64 Invalid;
} SVMHV_EXIT_HISTOGRAM;

/* ----------------------------------------------------------------- hooks */

/* What the hook does when it fires. */
#define SVMHV_ACTION_TRACE      0   /* record arguments, then run the original   */
#define SVMHV_ACTION_DETOUR     1   /* jump to a kernel address the caller gives */
#define SVMHV_ACTION_SHELLCODE  2   /* jump to bytes the caller supplies         */

/* What kind of access the hook traps. */
#define SVMHV_HOOK_EXEC         0   /* execution of the target                    */
#define SVMHV_HOOK_WRITE        1   /* writes anywhere in the target's page        */
#define SVMHV_HOOK_ACCESS       2   /* any access at all: read, write or execute   */

/*
 * A filter condition, evaluated in the driver before a trace record is produced.
 * Deliberately not a language: the point is to trace a function that is called
 * ten thousand times a second and keep only the calls that matter, without
 * paying to record the rest.
 *
 * The subject is usually an argument - 0-3 are RCX/RDX/R8/R9 and 4-7 the stack
 * arguments from [RSP+0x28] - but it can also be the calling context, which is
 * what makes "only when this process calls it" and "only when this driver calls
 * it" expressible.  Every condition present must hold.
 */
#define SVMHV_SUBJECT_ARGUMENT  0       /* 0..7 select the argument         */
#define SVMHV_SUBJECT_PID       0x100   /* current process id               */
#define SVMHV_SUBJECT_TID       0x101   /* current thread id                */
#define SVMHV_SUBJECT_RETURN    0x102   /* return address: whose code called */
#define SVMHV_SUBJECT_IRQL      0x103

#define SVMHV_CMP_EQUAL         0
#define SVMHV_CMP_NOT_EQUAL     1
#define SVMHV_CMP_ABOVE         2   /* unsigned */
#define SVMHV_CMP_BELOW         3   /* unsigned */
#define SVMHV_CMP_BITS_SET      4   /* (subject & Mask) == Value           */
#define SVMHV_CMP_IN_RANGE      5   /* Value <= subject < Mask             */

#define SVMHV_MAX_FILTERS       4

typedef struct _SVMHV_FILTER
{
    UINT32 Subject;                     /* argument index, or SVMHV_SUBJECT_* */
    UINT32 Comparison;
    UINT64 Mask;                        /* also the end of an IN_RANGE      */
    UINT64 Value;
} SVMHV_FILTER;

/*
 * Follow a pointer argument and copy what it points at into the trace record.
 * An argument that is "a string" is only a string if you dereference it, and
 * doing that from the recorder is the only place it can be done at all - by the
 * time a client reads the ring, the caller's buffer may be gone.
 *
 * Dereferencing is guarded: it only happens at IRQL <= APC_LEVEL, where a page
 * fault is legal, the address is screened, and the copy runs under SEH.  A
 * capture that cannot be taken safely is reported as zero length rather than
 * risking the machine.
 */
#define SVMHV_CAPTURE_NONE      0
#define SVMHV_CAPTURE_ANSI      1   /* char*                                */
#define SVMHV_CAPTURE_WIDE      2   /* wchar_t*                             */
#define SVMHV_CAPTURE_UNICODE   3   /* UNICODE_STRING*                      */
#define SVMHV_CAPTURE_OBJATTR   4   /* OBJECT_ATTRIBUTES* -> its ObjectName */
#define SVMHV_CAPTURE_BYTES     5   /* raw, Length bytes                    */

#define SVMHV_MAX_CAPTURES      2
#define SVMHV_CAPTURE_MAX       128

typedef struct _SVMHV_CAPTURE
{
    UINT32 Argument;                    /* 0-7, which one holds the pointer */
    UINT32 Type;
    UINT32 Length;                      /* SVMHV_CAPTURE_BYTES only         */
    UINT32 Reserved;
} SVMHV_CAPTURE;

/*
 * Replace an argument before the original function ever sees it.  The recorder
 * already holds the saved register frame that the thunk restores on the way out,
 * so changing a value there is all it takes; stack arguments are written back to
 * the caller's frame, which is the caller's own memory and outlives the call.
 */
#define SVMHV_MAX_SPOOFS        4

typedef struct _SVMHV_SPOOF
{
    UINT32 Argument;                    /* 0-7                              */
    UINT32 Reserved;
    UINT64 Value;
} SVMHV_SPOOF;

#define SVMHV_MAX_SHELLCODE     1024

/* One page per memory transfer; see MemoryData below. */
#define SVMHV_MEMORY_MAX        4096

#define SVMHV_PROCESS_NAME_MAX  16

typedef struct _SVMHV_HOOK_REQUEST
{
    UINT64 Target;                      /* kernel virtual address           */
    UINT64 Detour;                      /* ACTION_DETOUR only               */
    UINT32 PrologLength;                /* EXEC hooks: >= 14, and aligned to */
                                        /* an instruction boundary           */
    UINT32 Action;
    UINT32 Kind;
    UINT32 FilterCount;
    SVMHV_FILTER Filters[SVMHV_MAX_FILTERS];
    UINT32 ShellcodeSize;

    /*
     * Which process Target belongs to.  Zero means kernel space, which is what
     * every kernel hook uses and why this could take over a Reserved field
     * without moving anything.  A user-mode target requires it: the address is
     * meaningless without a context, and translating it against whichever
     * address space the worker thread happened to be in would pin a page
     * belonging to somebody else.
     */
    UINT32 TargetProcessId;

    /* out */
    UINT64 Trampoline;
    UINT64 Gpa;
    UINT32 HookId;
    UINT32 Reserved2;

    /*
     * Only fire for this process, matched against the image name in EPROCESS.
     * Empty means any process.  Case-insensitive, and truncated the same way
     * Windows truncates it - "somethinglong.exe" is only ever 15 characters.
     */
    char   ProcessName[SVMHV_PROCESS_NAME_MAX];

    UINT32 CaptureCount;
    UINT32 SpoofCount;
    SVMHV_CAPTURE Captures[SVMHV_MAX_CAPTURES];
    SVMHV_SPOOF Spoofs[SVMHV_MAX_SPOOFS];

    /*
     * Do not call the original at all: return BlockValue to the caller instead.
     * Implemented without touching the assembler - the hook's continuation
     * becomes a two-instruction stub, "mov rax, imm64; ret", which returns
     * through the caller's own return address.
     */
    UINT32 Block;
    UINT32 Reserved3;
    UINT64 BlockValue;

    UINT8  Shellcode[SVMHV_MAX_SHELLCODE];

    /*
     * Memory access, serviced by the worker thread at PASSIVE_LEVEL.
     *
     * It shares the request block rather than getting a channel of its own, so
     * the existing WRITE_REQUEST and READ_REQUEST windows reach it with no new
     * plumbing - the bounds check in both is against the size of this whole
     * structure.  Appended at the end for the same reason: every offset above
     * is hardcoded by clients that have no compiler to compute them.
     *
     * A page at a time.  That is the natural unit for reading code or a
     * structure, and at 48 bytes per window it is 86 hypercalls - microseconds,
     * and far cheaper than the alternative of a client that cannot read memory
     * at all.
     */
    UINT64 MemoryAddress;               /* virtual, or GPA for READ_PHYSICAL */
    UINT32 MemoryLength;                /* in: wanted, clamped to the buffer */
    UINT32 MemoryProcessId;             /* 0 = whatever context we are in    */
    UINT32 MemoryReturned;              /* out: bytes actually transferred   */
    UINT32 MemoryReserved;
    UINT8  MemoryData[SVMHV_MEMORY_MAX];
} SVMHV_HOOK_REQUEST;

/*
 * Shellcode contract.  The bytes are copied to a page of their own and entered
 * with the target's arguments exactly as its caller left them, so a detour can
 * read RCX/RDX/R8/R9 and the stack directly.  Two ways out:
 *
 *   ret                  - replace the function entirely; RAX is the result.
 *   fall off the end     - the driver appends an absolute jump to the
 *                          trampoline, so execution continues into the real
 *                          function.
 *
 * The trampoline address is also stored as a QWORD at page + 0xFF0 and the hook
 * id at page + 0xFF8, so position-independent code can find them with a
 * RIP-relative load instead of needing to be relocated.
 */
#define SVMHV_SHELLCODE_TRAMPOLINE_SLOT 0xFF0
#define SVMHV_SHELLCODE_HOOKID_SLOT     0xFF8

/*
 * How many hooks can exist at once.  Records are never recycled while the
 * driver is loaded - removal only marks one inactive - so this is also the
 * number of distinct targets one load can ever touch.  Sixty-four was reached
 * quickly once several hooks could share a page and instrumenting a whole
 * syscall table became expressible.
 */
#define SVMHV_MAX_HOOK_RECORDS  256

typedef struct _SVMHV_HOOK_INFO
{
    UINT64 Target;
    UINT64 Gpa;
    UINT64 Detour;
    UINT64 Trampoline;
    UINT64 Hits;
    UINT32 HookId;
    UINT32 Action;
    UINT32 Kind;
    UINT32 PrologLength;
    UINT32 Active;
    UINT32 FilterCount;
} SVMHV_HOOK_INFO;

typedef struct _SVMHV_HOOK_LIST
{
    UINT32 Count;
    UINT32 Reserved;
    SVMHV_HOOK_INFO Hooks[SVMHV_MAX_HOOK_RECORDS];
} SVMHV_HOOK_LIST;

/* ----------------------------------------------------------------- trace */

#define SVMHV_TRACE_EXEC        0
#define SVMHV_TRACE_WRITE       1
#define SVMHV_TRACE_ACCESS      2

typedef struct _SVMHV_TRACE_RECORD
{
    UINT64 Sequence;
    UINT64 Tsc;
    UINT64 Rip;                         /* hooked address, or faulting RIP  */
    UINT64 Rsp;
    UINT64 Arguments[4];                /* RCX, RDX, R8, R9                 */
    UINT64 StackArguments[4];           /* [RSP+0x28] upwards               */
    UINT64 ReturnAddress;
    UINT64 Gpa;                         /* watch hooks                      */
    UINT64 ErrorCode;                   /* the #NPF EXITINFO1, for watches  */
    UINT32 HookId;
    UINT32 Type;
    UINT32 Processor;
    UINT32 ProcessId;                   /* exec hooks only; 0 for watches   */
    UINT32 ThreadId;                    /* exec hooks only; 0 for watches   */
    UINT32 Irql;                        /* exec hooks only                  */
    UINT32 Spoofed;                     /* how many arguments were replaced  */
    char   ProcessName[SVMHV_PROCESS_NAME_MAX];

    /* Whatever the captures managed to dereference; zero length if they could
       not be taken safely. */
    UINT32 CaptureLength[SVMHV_MAX_CAPTURES];
    UINT8  CaptureData[SVMHV_MAX_CAPTURES][SVMHV_CAPTURE_MAX];
} SVMHV_TRACE_RECORD;

/* ------------------------------------------------------------- self test */

#define SVMHV_TEST_HOOK_INSTALLED   0x0001
#define SVMHV_TEST_DETOUR_RAN       0x0002
#define SVMHV_TEST_TRAMPOLINE_OK    0x0004
#define SVMHV_TEST_READS_UNCHANGED  0x0008  /* the important one            */
#define SVMHV_TEST_UNHOOK_OK        0x0010
#define SVMHV_TEST_EFER_HIDDEN      0x0020
#define SVMHV_TEST_SVM_CPUID_HIDDEN 0x0040
#define SVMHV_TEST_SVM_LEAF_HIDDEN  0x0080
#define SVMHV_TEST_NPT_ACTIVE       0x0100
#define SVMHV_TEST_ALL_CPUS         0x0200  /* hooked on every processor    */
#define SVMHV_TEST_TRACE_OK         0x0400  /* trace captured the arguments */

#define SVMHV_VICTIM_PLAIN          0x11111111u
#define SVMHV_VICTIM_HOOKED         0x22222222u

/* a + b + c + d for the argument victim's four known arguments */
#define SVMHV_ARG_VICTIM_SUM        0xAAAAAAAAAAAAAAAAULL

typedef struct _SVMHV_SELFTEST
{
    UINT32 Passed;
    UINT32 Options;
    UINT32 VictimPlain;                 /* expect 0x11111111               */
    UINT32 VictimHooked;                /* expect 0x22222222               */
    UINT32 VictimUnhooked;              /* expect 0x11111111               */
    UINT32 DetourHits;
    UINT32 TrampolineResult;            /* expect 0x11111111               */
    UINT32 CpuidSvmBit;                 /* expect 0 when hiding SVM        */
    UINT32 CpusHooked;                  /* processors that saw the detour   */
    UINT32 CpusMissed;                  /* processors that did not          */
    UINT32 SvmFeatureLeaf[4];           /* expect all zero                 */
    UINT32 TracedRecords;
    UINT32 Reserved;
    UINT64 EferSeenByGuest;             /* bit 12 must be clear            */
    UINT64 CpuidCycles;                 /* as a detector would measure it  */
    UINT64 BaselineCycles;
    UINT64 NpfExitsOnThisCpu;
    UINT64 TracedArguments[4];          /* what the trace hook captured    */
    UINT64 ArgVictimResult;             /* expect SVMHV_ARG_VICTIM_SUM     */
    UINT8  OriginalBytes[16];
    UINT8  BytesWhileHooked[16];        /* must equal OriginalBytes        */
} SVMHV_SELFTEST;

/* --------------------------------------------------------------- snapshot */

/*
 * Republished by the worker thread on every poll, so a client can read every
 * counter the driver keeps with a single memory read and without submitting a
 * command.
 */
typedef struct _SVMHV_SNAPSHOT
{
    UINT64 Tsc;                         /* when this snapshot was taken     */
    UINT64 Refreshes;
    SVMHV_STATS Stats;
    SVMHV_EXIT_HISTOGRAM Histogram;
    SVMHV_HOOK_LIST Hooks;
    SVMHV_SELFTEST SelfTest;
} SVMHV_SNAPSHOT;

/* --------------------------------------------------------------- doorbell */

/*
 * 'SVMHVCTL' - a client checks this before believing anything else, so that a
 * stale symbol file cannot make it write commands into unrelated memory.
 */
#define SVMHV_CONTROL_MAGIC     0x4C544356484D5653ULL
#define SVMHV_CONTROL_VERSION   1

#define SVMHV_CMD_NONE          0
#define SVMHV_CMD_HOOK_INSTALL  1
#define SVMHV_CMD_HOOK_REMOVE   2
#define SVMHV_CMD_SELFTEST      3
#define SVMHV_CMD_TRACE_RESET   4

/*
 * Memory access.  All three read the parameters out of the request block and
 * leave the result in MemoryData/MemoryReturned; see SVMHV_HOOK_REQUEST.
 * Serviced by the worker thread, which runs at PASSIVE_LEVEL and can therefore
 * attach to another process and survive a page fault, neither of which is legal
 * in the exit handler.
 */
#define SVMHV_CMD_READ_MEMORY   5
#define SVMHV_CMD_WRITE_MEMORY  6
#define SVMHV_CMD_READ_PHYSICAL 7

/* Resolve \Driver\<name> to its DRIVER_OBJECT address; see memory.h. */
#define SVMHV_CMD_DRIVER_OBJECT 8

typedef struct _SVMHV_CONTROL
{
    UINT64 Magic;
    UINT32 Version;
    UINT32 Command;

    /*
     * The client fills in Request and Command, then writes Sequence last.  The
     * driver copies Sequence into Completed once Status is meaningful, so a
     * client polls one 64-bit value to know its command is done.
     */
    UINT64 Sequence;
    UINT64 Completed;
    INT32  Status;                      /* NTSTATUS of the last command     */
    UINT32 Polls;                       /* worker wakeups: a liveness check  */

    /*
     * Where everything else lives, so a client only has to resolve one symbol
     * and can then read the rest directly.
     */
    UINT64 SnapshotAddress;
    UINT64 TraceRingAddress;
    UINT64 TraceProducedAddress;        /* volatile LONG64, monotonic        */
    UINT64 TraceRingRecords;            /* power of two                      */
    UINT64 TraceRecordSize;
    UINT64 NptPrimaryPml4;              /* virtual, so a client can walk it  */
    UINT64 NptShadowPml4;
    UINT64 NptCoverage;

    SVMHV_HOOK_REQUEST Request;
} SVMHV_CONTROL;

/*
 * A client reading this out of driver memory has to hardcode these offsets - it
 * has no compiler to compute them - so they are asserted here.  If one of these
 * fires, mcp\svmhv_mcp.py needs the same edit.
 */
C_ASSERT(sizeof(SVMHV_FILTER)          == 24);
C_ASSERT(sizeof(SVMHV_TRACE_RECORD)    == 432);
C_ASSERT(sizeof(SVMHV_STATS)           == 640);
C_ASSERT(sizeof(SVMHV_EXIT_HISTOGRAM)  == 2072);
C_ASSERT(sizeof(SVMHV_HOOK_INFO)       == 64);
C_ASSERT(sizeof(SVMHV_HOOK_LIST)       == 8 + 64 * SVMHV_MAX_HOOK_RECORDS);
C_ASSERT(sizeof(SVMHV_SELFTEST)        == 168);
C_ASSERT(sizeof(SVMHV_HOOK_REQUEST)    == 1320 + 24 + SVMHV_MEMORY_MAX);
C_ASSERT(FIELD_OFFSET(SVMHV_HOOK_REQUEST, MemoryAddress) == 1320);
C_ASSERT(FIELD_OFFSET(SVMHV_HOOK_REQUEST, MemoryData)    == 1344);

C_ASSERT(FIELD_OFFSET(SVMHV_SNAPSHOT, Stats)     == 16);
C_ASSERT(FIELD_OFFSET(SVMHV_SNAPSHOT, Histogram) == 656);
C_ASSERT(FIELD_OFFSET(SVMHV_SNAPSHOT, Hooks)     == 2728);
C_ASSERT(FIELD_OFFSET(SVMHV_SNAPSHOT, SelfTest)  == 2728 + sizeof(SVMHV_HOOK_LIST));
C_ASSERT(sizeof(SVMHV_SNAPSHOT)                  == 2728 + sizeof(SVMHV_HOOK_LIST) + 168);

C_ASSERT(FIELD_OFFSET(SVMHV_CONTROL, Sequence)             == 16);
C_ASSERT(FIELD_OFFSET(SVMHV_CONTROL, Completed)            == 24);
C_ASSERT(FIELD_OFFSET(SVMHV_CONTROL, Status)               == 32);
C_ASSERT(FIELD_OFFSET(SVMHV_CONTROL, SnapshotAddress)      == 40);
C_ASSERT(FIELD_OFFSET(SVMHV_CONTROL, TraceRingAddress)     == 48);
C_ASSERT(FIELD_OFFSET(SVMHV_CONTROL, TraceProducedAddress) == 56);
C_ASSERT(FIELD_OFFSET(SVMHV_CONTROL, Request)              == 104);
C_ASSERT(FIELD_OFFSET(SVMHV_HOOK_REQUEST, Filters)         == 32);
C_ASSERT(FIELD_OFFSET(SVMHV_HOOK_REQUEST, Trampoline)      == 136);
C_ASSERT(FIELD_OFFSET(SVMHV_HOOK_REQUEST, HookId)          == 152);
C_ASSERT(FIELD_OFFSET(SVMHV_HOOK_REQUEST, ProcessName)     == 160);
C_ASSERT(FIELD_OFFSET(SVMHV_HOOK_REQUEST, CaptureCount)    == 176);
C_ASSERT(FIELD_OFFSET(SVMHV_HOOK_REQUEST, Captures)        == 184);
C_ASSERT(FIELD_OFFSET(SVMHV_HOOK_REQUEST, Spoofs)          == 216);
C_ASSERT(FIELD_OFFSET(SVMHV_HOOK_REQUEST, Block)           == 280);
C_ASSERT(FIELD_OFFSET(SVMHV_HOOK_REQUEST, BlockValue)      == 288);
C_ASSERT(FIELD_OFFSET(SVMHV_HOOK_REQUEST, Shellcode)       == 296);
C_ASSERT(FIELD_OFFSET(SVMHV_TRACE_RECORD, ProcessName)     == 148);
C_ASSERT(FIELD_OFFSET(SVMHV_TRACE_RECORD, CaptureLength)   == 164);
C_ASSERT(FIELD_OFFSET(SVMHV_TRACE_RECORD, CaptureData)     == 172);
