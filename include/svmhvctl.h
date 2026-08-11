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
#define SVMHV_OPT_LBR               0x0100

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
#define SVMHV_CAPTURE_IRP       6   /* IRP* -> the request it carries       */

/* The highest type the driver will accept; raise it when adding one, or the
   validator in SvHookInstall rejects the new kind with STATUS_INVALID_PARAMETER
   and the only clue is that nothing was installed. */
#define SVMHV_CAPTURE_LAST      SVMHV_CAPTURE_IRP

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

/* Return addresses kept per trace record; see Frames below. */
#define SVMHV_MAX_FRAMES        8

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

    /*
     * Record candidate return addresses as well.  Opt-in: reading a couple of
     * hundred stack slots on every call is not free, and left unconditional on
     * a function in the file path it was enough to starve the control agent
     * that would have removed the hook.
     *
     * In this spare word rather than at the end of the structure, because a
     * hook submit only pushes the first 1320 bytes across the channel - the
     * memory fields past that are written separately, and a flag placed there
     * is silently never sent.
     */
    UINT32 CaptureStack;

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

    /*
     * Capture the return value as well as the arguments.  Opt-in, because it
     * is the only thing here that rewrites a return address, and a hook that
     * does not ask for it cannot be affected by that machinery at all.
     */
    UINT32 CaptureReturn;
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

/*
 * A traced call coming back.  Arguments[0] is the return value and
 * Arguments[1] the cycles spent inside the call; the entry record for the same
 * call is the nearest preceding EXEC record with the same hook and thread.
 */
#define SVMHV_TRACE_RETURN      3

/*
 * One instruction of a single-stepped run.  Rip is where it is about to
 * execute, Rsp and Cr3 the context, Code the bytes, and Arguments[0] the
 * RFLAGS the guest believes it has - ours with the trap flag put back the way
 * the guest left it, which is the only version of RFLAGS worth recording.
 */
#define SVMHV_TRACE_STEP        4

/*
 * An MSR the caller asked to be told about.  Arguments[0] is the MSR number,
 * Arguments[1] the value read or written, and Arguments[2] is 1 for a write.
 *
 * The MSRPM has been there since the driver could hide EFER; what was missing
 * was any way to ask it for anything.  A driver talking to hardware through
 * model-specific registers - or probing IA32_FEATURE_CONTROL and friends to
 * work out whether it is being watched - is invisible without this.
 */
#define SVMHV_TRACE_MSR         5

/*
 * An I/O port access.  Arguments[0] is the port, Arguments[1] the value for a
 * non-string access, Arguments[2] is 1 for a write (OUT), and Arguments[3] the
 * operand size in bytes.  ErrorCode carries the raw IOIO exit information, so
 * a client can see the string and repeat bits for itself.
 */
#define SVMHV_TRACE_IO          6

/*
 * The first time a guest physical page was executed, or written, during a
 * coverage sweep.  Arguments[0] is the page, Rip is what was running, and
 * ErrorCode the #NPF information.  One record per page for the life of the
 * sweep - the permission is granted after the first fault, so the page never
 * reports again.
 */
#define SVMHV_TRACE_COVER       7

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

    /*
     * Who called, beyond the immediate caller.
     *
     * ReturnAddress above says which instruction the call came from, and that
     * is one frame - enough to name the function but not to say why it was
     * reached.  A driver calling ZwCreateFile through three layers of its own
     * dispatch looks identical to one calling it directly, and telling those
     * apart is most of what a trace is for.
     *
     * Zero-terminated: fewer than SVMHV_MAX_FRAMES means the walk ended, not
     * that the stack did.
     */
    UINT32 FrameCount;
    UINT32 FrameReserved;
    UINT64 Frames[SVMHV_MAX_FRAMES];

    /*
     * Watchpoint detail.
     *
     * A watch hit used to carry RIP, the guest physical address and the #NPF
     * error code, and nothing else.  That names the page and the instruction
     * and stops there: not which address space it came from, not what was
     * stored, not even the bytes of the store.  Answering the only question a
     * watchpoint is ever asked - what wrote this, and what did it write - then
     * cost three more round trips and a guess, and for a user-mode watch the
     * process could not be established at all.
     *
     * All of it is free at the point of the fault.  The handler is holding the
     * VMCB, and the watched page is pinned by the hook's MDL and aliased into
     * system space, so reading it is a read through a locked mapping rather
     * than a guess about what is resident.
     *
     *   Cr3          from the VMCB.  A client resolves it to a process against
     *                DirectoryTableBase; recording the process id here instead
     *                would mean a Ps* call from host context with GIF clear,
     *                which this driver deliberately does not do.
     *   ValueBefore  the qword at the faulting address, read at the fault.
     *   ValueAfter   the same qword once the store has retired, read on the
     *                exit that returns this processor to the primary view.
     *   ValueWidth   how many of those bytes are inside the page; 0 when no
     *                value could be taken (an exec record, or a fault whose
     *                page has no system alias).
     *   Code         the bytes at Rip, so the client can decode the store
     *                without a second round trip.  Clamped to the end of RIP's
     *                page and taken only for a kernel RIP: the page holding the
     *                instruction that just faulted is resident by definition,
     *                but the host's CR3 is not the faulting process's, so a
     *                user-mode RIP is not ours to read from here.
     */
    UINT64 Cr3;
    UINT64 ValueBefore;
    UINT64 ValueAfter;
    UINT32 ValueWidth;
    UINT32 CodeLength;
    UINT8  Code[16];

    /*
     * The last branch the guest took before this record was made, straight out
     * of the processor.  Zero when it was not available.
     *
     * The stack walk above reports candidates, and on obfuscated code it
     * reports very little that is true; these two are a fact.  On a
     * first-execution record from a coverage sweep BranchFrom is the
     * instruction that jumped into a page nobody declared, which is the whole
     * question that record raises.
     *
     * Only records made at an exit carry them.  An exec hook's recorder runs in
     * guest context, several jumps into the thunk, where the last branch is one
     * of ours - so those leave the fields zero rather than record the
     * instrument.
     */
    UINT64 BranchFrom;
    UINT64 BranchTo;

    /*
     * Publication protocol, appended so the original record layout remains
     * readable by v1 consumers.  A recorder first clears CommitSequence,
     * fills every preceding field, then stores Sequence + 1 here with a full
     * barrier.  Readers must verify it before and after copying a record.
     *
     * Generation changes on trace-reset.  Sequence itself never goes
     * backwards, so { Generation, Sequence } is also a durable cursor that
     * distinguishes a reset from a quiet trace.
     */
    UINT64 Generation;
    UINT64 CommitSequence;              /* 0 while being written; seq + 1 valid */
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
#define SVMHV_TEST_RETURN_OK        0x0800  /* and the value it returned    */

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
    UINT64 TracedArguments[4];
    UINT64 TracedReturn;          /* what the trace hook captured    */
    UINT64 ArgVictimResult;             /* expect SVMHV_ARG_VICTIM_SUM     */
    UINT8  OriginalBytes[16];
    UINT8  BytesWhileHooked[16];        /* must equal OriginalBytes        */
} SVMHV_SELFTEST;

/* ------------------------------------------------------------ fatal exits */

/*
 * An exit the handler could not deal with.
 *
 * These used to be KeBugCheckEx calls, which was worse than useless: the exit
 * handler runs with GIF clear, on a private host stack, with every other
 * processor still in guest mode under our ASID, and a bugcheck raised from
 * there cannot be relied upon to produce the dump that would justify it.  What
 * it produces instead is a machine that dies leaving nothing behind - which is
 * exactly the shape of the unexplained resets in CLAUDE.md, and exactly the
 * thing that made them impossible to investigate.
 *
 * So the handler records what it saw here and leaves SVM on that processor
 * instead.  For three of the four reasons below the guest then carries on
 * natively and a client reads this out of the snapshot afterwards; for a guest
 * triple fault nothing can carry on, but the state at the moment of death is at
 * least in memory where a debugger can find it.
 */
#define SVMHV_FATAL_NONE            0
#define SVMHV_FATAL_SHUTDOWN        1   /* guest triple fault, VMEXIT 0x7F   */
#define SVMHV_FATAL_UNKNOWN_EXIT    2   /* an exit code we do not handle     */
#define SVMHV_FATAL_NPF_UNMAPPED    3   /* #NPF where the map covers nothing */
#define SVMHV_FATAL_NPF_LOOP        4   /* same instruction, same page, x16  */

typedef struct _SVMHV_FATAL_EXIT
{
    UINT32 Reason;                      /* SVMHV_FATAL_*                     */
    UINT32 Processor;
    UINT64 Count;                       /* this one's position in the run    */
    UINT64 ExitCode;
    UINT64 ExitInfo1;
    UINT64 ExitInfo2;
    UINT64 ExitIntInfo;                 /* an event interrupted mid-delivery */
    UINT64 Rip;
    UINT64 Rsp;
    UINT64 Cr2;
    UINT64 Cr3;                         /* which address space it was in     */
} SVMHV_FATAL_EXIT;

/*
 * The last few, not just the last one.
 *
 * One slot was enough only for the case where a single processor dies and the
 * machine survives to be asked about it.  It is the wrong shape for what this
 * is actually for: eight processors are inside VMRUN at once, so fatal exits
 * arrive concurrently, and the interesting question - did one processor die and
 * take the others with it, or did three die in a row, and in what order - is
 * exactly the question a single overwritten slot cannot answer.  The reset this
 * record exists to explain is still open, and it had one sample per run.
 *
 * Entries are claimed with an interlocked increment, so concurrent exits land
 * in different slots rather than on top of each other.  Slot (Produced - 1) %
 * SVMHV_FATAL_RING_ENTRIES is the newest; Produced keeps counting past the end,
 * so a client can tell a wrapped ring from a short one and knows how many it
 * never saw.
 */
#define SVMHV_FATAL_RING_ENTRIES    8

typedef struct _SVMHV_FATAL_RING
{
    UINT64 Produced;                    /* total ever recorded               */
    UINT64 Reserved;
    SVMHV_FATAL_EXIT Entries[SVMHV_FATAL_RING_ENTRIES];
} SVMHV_FATAL_RING;

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

    /* Appended last on purpose: every offset above is hardcoded by clients
       that have no compiler to compute it, so nothing may move. */
    SVMHV_FATAL_EXIT Fatal;

    /*
     * The same thing with history.  Fatal above is kept, and kept where it is,
     * because clients hardcode its offset and "the last fatal exit" is still
     * the first question anybody asks; this is what to read when the answer is
     * not "none" and the run is worth reconstructing.
     */
    SVMHV_FATAL_RING FatalRing;

    /*
     * Snapshot seqlock.  The control worker makes it odd before updating the
     * snapshot and publishes an even, non-zero value afterwards.  A reader
     * accepts a snapshot only when this value was the same even number before
     * and after all of its windows were copied.
     */
    UINT64 PublishSequence;
} SVMHV_SNAPSHOT;

/* --------------------------------------------------------------- doorbell */

/*
 * 'SVMHVCTL' - a client checks this before believing anything else, so that a
 * stale symbol file cannot make it write commands into unrelated memory.
 */
#define SVMHV_CONTROL_MAGIC     0x4C544356484D5653ULL
#define SVMHV_CONTROL_VERSION   2

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
#define SVMHV_CMD_WRITE_PHYSICAL 9
#define SVMHV_CMD_TRANSLATE     10
#define SVMHV_CMD_DEVICES       11
#define SVMHV_CMD_SYMLINKS      12
#define SVMHV_CMD_CALLBACK_PROBE 13
#define SVMHV_CMD_POWER_CYCLE   14

/*
 * Trap an MSR, or an I/O port, and record every access.
 *
 * Both take their arguments in the memory fields rather than in a block of
 * their own: MemoryAddress is the MSR number or the port, and MemoryLength is
 * 1 to arm and 0 to disarm.  Reusing them costs nothing and keeps every offset
 * above unchanged, which matters more here than tidiness - clients hardcode
 * them.
 */
#define SVMHV_CMD_WATCH_MSR     15
#define SVMHV_CMD_WATCH_IO      16

/*
 * Arm or disarm a coverage sweep.
 *
 * MemoryAddress is the base guest physical address.  The size and the mode
 * both travel in MemoryData - size at 0, mode at 8 - because MemoryLength is
 * not free: the client's transfer helper reads it as the length of the payload
 * and copies exactly that many bytes, so a command that puts anything else
 * there silently sends one byte of its arguments and no more.
 *
 * On the way back MemoryData holds the size actually armed, which after a
 * partial failure is not the size asked for, and MemoryReturned the number of
 * pages granted so far.
 */
#define SVMHV_CMD_SWEEP         17
#define SVMHV_SWEEP_ARGS        16      /* MemoryLength for the above */

/* How many of each can be armed at once. */
#define SVMHV_MAX_MSR_WATCHES   16
#define SVMHV_MAX_IO_WATCHES    16

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
    UINT64 TraceProducedAddress;        /* volatile LONG64, absolute cursor  */
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
C_ASSERT(sizeof(SVMHV_TRACE_RECORD)    == 432 + 8 + 8 * SVMHV_MAX_FRAMES + 80);
C_ASSERT(sizeof(SVMHV_STATS)           == 640);
C_ASSERT(sizeof(SVMHV_EXIT_HISTOGRAM)  == 2072);
C_ASSERT(sizeof(SVMHV_HOOK_INFO)       == 64);
C_ASSERT(sizeof(SVMHV_HOOK_LIST)       == 8 + 64 * SVMHV_MAX_HOOK_RECORDS);
C_ASSERT(sizeof(SVMHV_SELFTEST)        == 176);
C_ASSERT(sizeof(SVMHV_HOOK_REQUEST)    == 1320 + 24 + SVMHV_MEMORY_MAX);
C_ASSERT(FIELD_OFFSET(SVMHV_HOOK_REQUEST, MemoryAddress) == 1320);
C_ASSERT(FIELD_OFFSET(SVMHV_HOOK_REQUEST, MemoryData)    == 1344);
C_ASSERT(FIELD_OFFSET(SVMHV_HOOK_REQUEST, CaptureStack)  == 156);

C_ASSERT(sizeof(SVMHV_FATAL_EXIT)      == 80);
C_ASSERT(sizeof(SVMHV_FATAL_RING)      == 16 + 80 * SVMHV_FATAL_RING_ENTRIES);

C_ASSERT(FIELD_OFFSET(SVMHV_SNAPSHOT, Stats)     == 16);
C_ASSERT(FIELD_OFFSET(SVMHV_SNAPSHOT, Histogram) == 656);
C_ASSERT(FIELD_OFFSET(SVMHV_SNAPSHOT, Hooks)     == 2728);
C_ASSERT(FIELD_OFFSET(SVMHV_SNAPSHOT, SelfTest)  == 2728 + sizeof(SVMHV_HOOK_LIST));
C_ASSERT(FIELD_OFFSET(SVMHV_SNAPSHOT, Fatal)     == 2728 + sizeof(SVMHV_HOOK_LIST) +
                                                    sizeof(SVMHV_SELFTEST));
C_ASSERT(FIELD_OFFSET(SVMHV_SNAPSHOT, FatalRing) == 2728 + sizeof(SVMHV_HOOK_LIST) +
                                                    sizeof(SVMHV_SELFTEST) +
                                                    sizeof(SVMHV_FATAL_EXIT));
C_ASSERT(sizeof(SVMHV_SNAPSHOT)                  == 2728 + sizeof(SVMHV_HOOK_LIST) +
                                                    sizeof(SVMHV_SELFTEST) +
                                                    sizeof(SVMHV_FATAL_EXIT) +
                                                    sizeof(SVMHV_FATAL_RING) +
                                                    sizeof(UINT64));

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
C_ASSERT(FIELD_OFFSET(SVMHV_TRACE_RECORD, Cr3)             ==
         432 + 8 + 8 * SVMHV_MAX_FRAMES);
C_ASSERT(FIELD_OFFSET(SVMHV_TRACE_RECORD, BranchFrom)      ==
         432 + 8 + 8 * SVMHV_MAX_FRAMES + 48);
C_ASSERT(FIELD_OFFSET(SVMHV_TRACE_RECORD, Generation)      ==
         432 + 8 + 8 * SVMHV_MAX_FRAMES + 64);
C_ASSERT(FIELD_OFFSET(SVMHV_TRACE_RECORD, CommitSequence)  ==
         432 + 8 + 8 * SVMHV_MAX_FRAMES + 64 + sizeof(UINT64));
C_ASSERT(FIELD_OFFSET(SVMHV_SNAPSHOT, PublishSequence)     ==
         2728 + sizeof(SVMHV_HOOK_LIST) + sizeof(SVMHV_SELFTEST) +
         sizeof(SVMHV_FATAL_EXIT) + sizeof(SVMHV_FATAL_RING));
