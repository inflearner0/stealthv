/*
 * trace.c - the trace ring and the generic argument recorder.  See trace.h.
 */

#include "trace.h"
#include "hook.h"
#include "svmhv.h"

/*
 * Exported by ntoskrnl but not declared in any public header.  It returns the
 * fifteen-character image name Windows keeps in EPROCESS, which is what makes
 * "hook this only for notepad.exe" expressible without the caller having to
 * chase PIDs that change on every launch.
 */
NTKERNELAPI UCHAR* PsGetProcessImageFileName(_In_ PEPROCESS Process);

/*
 * The kernel's own stack walker.  Exported and usable from any IRQL, and it
 * reads the .pdata unwind tables rather than assuming frame pointers, which is
 * the only approach that works on optimised x64 code.
 *
 * Writing one by hand was the alternative and it is not close: an unwinder that
 * guesses is an unwinder that eventually reads a bad address inside a recorder
 * running with a hook installed, and the machine is then wedged in the one path
 * that could remove the hook.
 */
/*
 * Candidate return addresses, by reading the stack.
 *
 * Not an unwind, and it does not pretend to be.  Three ways of doing this
 * properly were tried and none of them works from here: the stack walkers the
 * kernel exports start from the caller's frame, which is this recorder and the
 * thunk rather than anything interesting, and a manual RtlVirtualUnwind needs a
 * CONTEXT whose non-volatile registers are the traced function's - and by the
 * time C code is running, its own prologue has saved and reused them.
 *
 * So: read the stack and keep what could be a return address.  A value that
 * points into a module's code is either a return address or a coincidence, and
 * the client can tell which by whether the chain makes sense - it symbolizes
 * every entry, so a stray pointer shows up as an odd name rather than hiding.
 * That is weaker than an unwind and it is reported as candidates rather than
 * as a call stack.
 *
 * Reading is the only risk and it is a small one: this is the current thread's
 * own stack, below the pointer it was entered with, and therefore resident.
 */
static ULONG SvTraceStackCandidates(_In_ UINT64 Rsp,
                                    _Out_writes_(Count) UINT64* Frames,
                                    _In_ ULONG Count)
{
    const ULONG64* stack = (const ULONG64*)Rsp;
    ULONG found = 0;
    ULONG i;

    if (Rsp == 0 || Count == 0)
    {
        return 0;
    }

    __try
    {
        for (i = 0; i < 256 && found < Count; i++)
        {
            const UINT64 value = stack[i];

            /* Kernel code lives above this; anything else is data. */
            if (value >= 0xFFFFF80000000000ULL && value < 0xFFFFFFFFFFFF0000ULL)
            {
                Frames[found++] = value;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        /* Ran off the end of the stack; keep whatever was found. */
    }

    return found;
}

/*
 * Power of two, so the modulo is a mask.  4096 records is about 640 KiB, which
 * buys roughly a second of a moderately busy hook before a client that is
 * draining once a second starts losing the oldest of them.
 */
#define TRACE_RING_RECORDS  4096
#define TRACE_RING_MASK     (TRACE_RING_RECORDS - 1)

static SVMHV_TRACE_RECORD* g_Ring;
static volatile LONG64     g_Produced;      /* monotonic; & MASK gives a slot */

/*
 * How far a client says it has drained.  Nothing in the driver consumes the
 * ring - clients read it directly - so this only moves when one tells us it
 * has, through SVMHV_HV_TRACE_CONSUMED.  Without it the drop counter below
 * compares the producer against zero and calls every record after the first
 * ring-full "dropped", whether or not anybody missed it.
 */
static volatile LONG64     g_Consumed;
static volatile LONG64     g_Dropped;
static volatile LONG64     g_Filtered;
static KSPIN_LOCK          g_DrainLock;

/*
 * A hook whose detour is traced must not be able to trace itself.  One flag per
 * processor is enough: the recorder never blocks, so the only way back into it
 * on the same processor is a hooked function called from inside it.
 */
#define TRACE_MAX_CPUS      256
static volatile LONG g_InRecorder[TRACE_MAX_CPUS];

/* A snapshot of the last exec trace, for the self-test. */
static UINT64        g_LastArguments[4];
static UINT64        g_LastReturn;
static volatile LONG g_LastExecRecords;

VOID SvTraceLastExec(_Out_writes_(4) UINT64* Arguments, _Out_ UINT32* Records)
{
    Arguments[0] = g_LastArguments[0];
    Arguments[1] = g_LastArguments[1];
    Arguments[2] = g_LastArguments[2];
    Arguments[3] = g_LastArguments[3];
    *Records = (UINT32)g_LastExecRecords;
}

NTSTATUS SvTraceInitialize(VOID)
{
    KeInitializeSpinLock(&g_DrainLock);

    g_Ring = (SVMHV_TRACE_RECORD*)ExAllocatePool2(
                POOL_FLAG_NON_PAGED,
                sizeof(SVMHV_TRACE_RECORD) * TRACE_RING_RECORDS,
                SVMHV_POOL_TAG);
    if (g_Ring == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_Produced = 0;
    g_Consumed = 0;
    g_Dropped = 0;
    g_Filtered = 0;
    RtlZeroMemory((PVOID)g_InRecorder, sizeof(g_InRecorder));

    return STATUS_SUCCESS;
}

VOID SvTraceFree(VOID)
{
    if (g_Ring != NULL)
    {
        ExFreePoolWithTag(g_Ring, SVMHV_POOL_TAG);
        g_Ring = NULL;
    }
}

VOID SvTraceCounters(_Out_ UINT64* Produced, _Out_ UINT64* Dropped,
                     _Out_ UINT64* Filtered)
{
    *Produced = (UINT64)g_Produced;
    *Dropped  = (UINT64)g_Dropped;
    *Filtered = (UINT64)g_Filtered;
}

/*
 * Claim a slot.  Lapping the reader is a normal outcome under a hot hook, and
 * the only sane response is to overwrite the oldest record and say so - the
 * alternative, dropping the newest, loses exactly the events the caller has
 * just started looking for.
 */
static SVMHV_TRACE_RECORD* SvTraceClaim(_Out_ UINT64* Sequence)
{
    LONG64 sequence;

    *Sequence = 0;

    if (g_Ring == NULL)
    {
        return NULL;
    }

    sequence = InterlockedIncrement64(&g_Produced) - 1;

    /*
     * This slot is about to be reused.  If the client has not said it read the
     * record that was in it, it never will - the write below is what loses it.
     */
    if (sequence >= g_Consumed + TRACE_RING_RECORDS)
    {
        InterlockedIncrement64(&g_Dropped);
    }

    *Sequence = (UINT64)sequence;
    return &g_Ring[sequence & TRACE_RING_MASK];
}

/* --------------------------------------------------------------- filters */

static BOOLEAN SvTraceFilterPasses(_In_ const SVMHV_FILTER* Filter,
                                   _In_ UINT64 Subject)
{
    /* IN_RANGE needs both bounds, so it cannot also use Mask to pre-mask. */
    const UINT64 value = (Filter->Comparison != SVMHV_CMP_IN_RANGE &&
                          Filter->Mask != 0) ? (Subject & Filter->Mask) : Subject;

    switch (Filter->Comparison)
    {
    case SVMHV_CMP_EQUAL:       return value == Filter->Value;
    case SVMHV_CMP_NOT_EQUAL:   return value != Filter->Value;
    case SVMHV_CMP_ABOVE:       return value > Filter->Value;
    case SVMHV_CMP_BELOW:       return value < Filter->Value;
    case SVMHV_CMP_BITS_SET:    return value == Filter->Value;
    case SVMHV_CMP_IN_RANGE:    return value >= Filter->Value && value < Filter->Mask;
    default:                    return TRUE;
    }
}

/*
 * What a filter is looking at.  Usually an argument, but the calling context is
 * what makes "only when this process calls it" and "only when this driver calls
 * it" possible: the return address says whose code we are standing in.
 */
static UINT64 SvTraceSubject(_In_ const SVMHV_FILTER* Filter,
                             _In_reads_(8) const UINT64* Arguments,
                             _In_ UINT64 ReturnAddress)
{
    switch (Filter->Subject)
    {
    case SVMHV_SUBJECT_PID:    return (UINT64)(ULONG_PTR)PsGetCurrentProcessId();
    case SVMHV_SUBJECT_TID:    return (UINT64)(ULONG_PTR)PsGetCurrentThreadId();
    case SVMHV_SUBJECT_RETURN: return ReturnAddress;
    case SVMHV_SUBJECT_IRQL:   return (UINT64)KeGetCurrentIrql();
    default:
        return (Filter->Subject < 8) ? Arguments[Filter->Subject] : 0;
    }
}

/* ------------------------------------------------------------- captures */

/*
 * Dereferencing an argument is the only way to know what a string argument
 * actually said - by the time a client drains the ring, the caller's buffer may
 * be freed or its process gone.  It is also the most dangerous thing in this
 * file, so it is fenced three ways: only at an IRQL where a page fault is legal,
 * only for an address the memory manager currently admits to, and only under
 * SEH.  A capture that cannot be taken safely comes back empty.
 */
static BOOLEAN SvTraceReadable(_In_ const VOID* Address, _In_ SIZE_T Length)
{
    ULONG_PTR page;
    ULONG_PTR last;

    if (Address == NULL || Length == 0)
    {
        return FALSE;
    }

    /* MmIsAddressValid speaks for one page at a time, so ask about each. */
    page = (ULONG_PTR)Address & ~(ULONG_PTR)(PAGE_SIZE - 1);
    last = ((ULONG_PTR)Address + Length - 1) & ~(ULONG_PTR)(PAGE_SIZE - 1);

    for (; page <= last; page += PAGE_SIZE)
    {
        if (!MmIsAddressValid((PVOID)page))
        {
            return FALSE;
        }
    }

    return TRUE;
}

static ULONG SvTraceCopyIn(_Out_writes_bytes_(Maximum) UINT8* Out,
                           _In_ ULONG Maximum, _In_ const VOID* Source,
                           _In_ ULONG Length)
{
    if (Length > Maximum)
    {
        Length = Maximum;
    }
    if (!SvTraceReadable(Source, Length))
    {
        return 0;
    }

    __try
    {
        RtlCopyMemory(Out, Source, Length);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }

    return Length;
}

static ULONG SvTraceCapture(_In_ const SVMHV_CAPTURE* Capture,
                            _In_ UINT64 Argument,
                            _Out_writes_bytes_(SVMHV_CAPTURE_MAX) UINT8* Out)
{
    RtlZeroMemory(Out, SVMHV_CAPTURE_MAX);

    if (Argument == 0)
    {
        return 0;
    }

    switch (Capture->Type)
    {
    case SVMHV_CAPTURE_ANSI:
    case SVMHV_CAPTURE_WIDE:
    {
        /* No strlen on memory that might vanish mid-scan: copy a bounded
           window and let the client find the terminator. */
        return SvTraceCopyIn(Out, SVMHV_CAPTURE_MAX - 2, (const VOID*)Argument,
                             SVMHV_CAPTURE_MAX - 2);
    }

    case SVMHV_CAPTURE_UNICODE:
    case SVMHV_CAPTURE_OBJATTR:
    {
        UNICODE_STRING descriptor;
        const VOID* source = (const VOID*)Argument;

        if (Capture->Type == SVMHV_CAPTURE_OBJATTR)
        {
            /* OBJECT_ATTRIBUTES.ObjectName is a UNICODE_STRING* at +0x10 on
               x64, which is what almost every Nt* path argument really is. */
            UINT64 objectName = 0;

            if (SvTraceCopyIn((UINT8*)&objectName, sizeof(objectName),
                              (const UINT8*)Argument + 0x10,
                              sizeof(objectName)) != sizeof(objectName) ||
                objectName == 0)
            {
                return 0;
            }
            source = (const VOID*)objectName;
        }

        if (SvTraceCopyIn((UINT8*)&descriptor, sizeof(descriptor), source,
                          sizeof(descriptor)) != sizeof(descriptor))
        {
            return 0;
        }
        if (descriptor.Buffer == NULL || descriptor.Length == 0)
        {
            return 0;
        }
        return SvTraceCopyIn(Out, SVMHV_CAPTURE_MAX - 2, descriptor.Buffer,
                             descriptor.Length);
    }

    case SVMHV_CAPTURE_BYTES:
        return SvTraceCopyIn(Out, SVMHV_CAPTURE_MAX, (const VOID*)Argument,
                             (Capture->Length != 0) ? Capture->Length
                                                    : SVMHV_CAPTURE_MAX);

    default:
        return 0;
    }
}

/* ---------------------------------------------------------- return path */

/*
 * Catching a function's return value means being on the stack when it
 * returns, and there is exactly one way to do that without disturbing what
 * the function sees: replace the return address the caller pushed, and
 * remember the real one somewhere.
 *
 * What is *not* possible is calling the trampoline from a stub and taking
 * the value when it comes back.  That inserts a frame, and a function's fifth
 * and later arguments live at fixed offsets from the stack pointer it was
 * entered with - NtCreateFile has eleven.  Shifting RSP by even eight bytes
 * makes every one of them read the wrong slot.
 *
 * So: per thread, because a thread is what owns a call stack.  Not per
 * processor - a thread can be rescheduled onto another processor between
 * being called and returning, and the entry has to travel with it.
 */
#define TRACE_RETURN_SLOTS      512     /* threads tracked at once           */
#define TRACE_RETURN_DEPTH      16      /* nesting per thread                */

typedef struct _TRACE_RETURN_FRAME
{
    UINT64 ReturnAddress;               /* what the caller actually pushed   */
    UINT64 Rsp;                         /* where it was, for validation      */
    UINT64 HookId;
    UINT64 Tsc;                         /* to report how long the call took  */
} TRACE_RETURN_FRAME;

typedef struct _TRACE_RETURN_SLOT
{
    volatile LONG64 Thread;             /* 0 when free                       */
    volatile LONG   Depth;
    TRACE_RETURN_FRAME Frames[TRACE_RETURN_DEPTH];
} TRACE_RETURN_SLOT;

static TRACE_RETURN_SLOT g_ReturnSlots[TRACE_RETURN_SLOTS];
static volatile LONG64   g_ReturnsLost;

static TRACE_RETURN_SLOT* SvTraceReturnSlot(_In_ BOOLEAN Claim)
{
    const LONG64 thread = (LONG64)(ULONG_PTR)PsGetCurrentThread();
    const ULONG start = (ULONG)(((ULONG_PTR)thread >> 4) % TRACE_RETURN_SLOTS);
    ULONG i;

    /* Linear probing.  A thread keeps its slot for as long as it has frames
       outstanding, so the table only has to hold concurrently-traced calls. */
    for (i = 0; i < 32; i++)
    {
        TRACE_RETURN_SLOT* slot = &g_ReturnSlots[(start + i) % TRACE_RETURN_SLOTS];

        if (slot->Thread == thread)
        {
            return slot;
        }
        if (Claim && slot->Thread == 0 &&
            InterlockedCompareExchange64(&slot->Thread, thread, 0) == 0)
        {
            slot->Depth = 0;
            return slot;
        }
    }

    return NULL;
}

/*
 * Called from AsmTraceEntry's decision point.  Returns TRUE if the caller's
 * return address was replaced, in which case AsmTraceReturn will run when the
 * function finishes.  FALSE means capture was not possible, and the function
 * returns straight to its caller as if nothing had happened - which is the
 * only acceptable way to fail here.
 */
static BOOLEAN SvTracePushReturn(_In_ UINT64 HookId, _In_ UINT64 OriginalRsp)
{
    TRACE_RETURN_SLOT* slot = SvTraceReturnSlot(TRUE);
    LONG depth;

    if (slot == NULL)
    {
        InterlockedIncrement64(&g_ReturnsLost);
        return FALSE;
    }

    depth = slot->Depth;
    if (depth < 0 || depth >= TRACE_RETURN_DEPTH)
    {
        InterlockedIncrement64(&g_ReturnsLost);
        return FALSE;
    }

    slot->Frames[depth].ReturnAddress = *(UINT64*)OriginalRsp;
    slot->Frames[depth].Rsp = OriginalRsp;
    slot->Frames[depth].HookId = HookId;
    slot->Frames[depth].Tsc = __rdtsc();
    slot->Depth = depth + 1;

    *(UINT64*)OriginalRsp = (UINT64)(ULONG_PTR)AsmTraceReturn;
    return TRUE;
}

/*
 * The function has returned.  Rax is its result and Rsp is the stack pointer
 * immediately after the ret popped our address, so the frame we are looking
 * for is the one whose recorded Rsp is eight less than this.
 *
 * The search matters.  A function that never returns normally - one unwound
 * through by an exception, or one that longjmps - leaves its frame behind, and
 * taking the top of the stack blindly would hand the next return the wrong
 * address and put the machine somewhere arbitrary.  Frames above the match are
 * exactly those abandoned calls, so they are discarded.
 */
UINT64 SvTraceReturnEntry(_In_ UINT64 Rax, _In_ UINT64 Rsp)
{
    TRACE_RETURN_SLOT* slot = SvTraceReturnSlot(FALSE);
    const UINT64 wanted = Rsp - sizeof(UINT64);
    LONG depth;

    if (slot == NULL)
    {
        /* Nothing recorded for this thread at all.  There is no address to
           return to and nothing safe to invent. */
        KeBugCheckEx(MANUALLY_INITIATED_CRASH, 0x52455431ULL /* 'RET1' */,
                     Rax, Rsp, 0);
    }

    for (depth = slot->Depth - 1; depth >= 0; depth--)
    {
        TRACE_RETURN_FRAME* frame = &slot->Frames[depth];

        if (frame->Rsp != wanted)
        {
            continue;                   /* an abandoned call; drop it */
        }

        {
            const UINT64 address = frame->ReturnAddress;
            const UINT64 elapsed = __rdtsc() - frame->Tsc;
            UINT64 sequence;
            SVMHV_TRACE_RECORD* record = SvTraceClaim(&sequence);

            slot->Depth = depth;
            if (depth == 0)
            {
                /* Last frame out releases the slot for another thread. */
                InterlockedExchange64(&slot->Thread, 0);
            }

            if (record != NULL)
            {
                RtlZeroMemory(record, sizeof(*record));
                record->Sequence = sequence;
                record->Tsc = __rdtsc();
                record->Type = SVMHV_TRACE_RETURN;
                record->HookId = (UINT32)frame->HookId;
                record->Rip = address;
                record->Rsp = Rsp;
                record->ReturnAddress = address;
                record->Arguments[0] = Rax;         /* the result */
            g_LastReturn = Rax;
                record->Arguments[1] = elapsed;     /* cycles in the call */
                record->Processor = KeGetCurrentProcessorIndex();
                record->ProcessId = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
                record->ThreadId = (UINT32)(ULONG_PTR)PsGetCurrentThreadId();
            }

            return address;
        }
    }

    KeBugCheckEx(MANUALLY_INITIATED_CRASH, 0x52455432ULL /* 'RET2' */,
                 Rax, Rsp, (ULONG_PTR)slot->Depth);
}

VOID SvTraceReturnCounters(_Out_ UINT64* Lost)
{
    *Lost = (UINT64)g_ReturnsLost;
}

VOID SvTraceLastReturn(_Out_ UINT64* Value)
{
    *Value = g_LastReturn;
}

/* ------------------------------------------------------------ exec path */

PVOID SvTraceExecEntry(_In_ UINT64 HookId, _In_ TRACE_FRAME* Frame,
                       _In_ UINT64 OriginalRsp)
{
    SVM_HOOK_TRACE_INFO info;
    UINT64 arguments[8];
    UINT64* stack = (UINT64*)OriginalRsp;
    const UINT64 returnAddress = stack[0];
    const KIRQL irql = KeGetCurrentIrql();
    const char* imageName;
    ULONG processor;
    ULONG i;
    ULONG spoofed = 0;

    /*
     * Hook records are never recycled while the driver is loaded - removal only
     * marks them inactive - so a lookup can only fail if the id in the stub is
     * not one we generated, which means something has corrupted the stub.  There
     * is no safe address to continue to in that case.
     */
    if (!SvHookTraceInfo((UINT32)HookId, &info) || info.Trampoline == NULL)
    {
        KeBugCheckEx(MANUALLY_INITIATED_CRASH, 0x54524143ULL /* 'TRAC' */,
                     HookId, (ULONG_PTR)Frame, OriginalRsp);
    }

    processor = KeGetCurrentProcessorIndex();
    if (processor >= TRACE_MAX_CPUS)
    {
        return info.Trampoline;
    }

    if (InterlockedCompareExchange(&g_InRecorder[processor], 1, 0) != 0)
    {
        return info.Trampoline;     /* a hooked function called by the recorder */
    }

    /*
     * The register arguments, then the stack ones.  [RSP+0x00] is the return
     * address and 0x08..0x20 is the caller's spill area for RCX-R9, so the
     * fifth argument starts at 0x28.
     */
    arguments[0] = Frame->Rcx;
    arguments[1] = Frame->Rdx;
    arguments[2] = Frame->R8;
    arguments[3] = Frame->R9;
    arguments[4] = stack[5];
    arguments[5] = stack[6];
    arguments[6] = stack[7];
    arguments[7] = stack[8];

    /*
     * "Only for this process", matched against the image name Windows keeps in
     * EPROCESS - at most fifteen characters, and the same name Task Manager
     * would show you.
     */
    imageName = (const char*)PsGetProcessImageFileName(PsGetCurrentProcess());
    if (info.ProcessName[0] != 0)
    {
        if (imageName == NULL ||
            _strnicmp(imageName, info.ProcessName,
                      SVMHV_PROCESS_NAME_MAX - 1) != 0)
        {
            InterlockedIncrement64(&g_Filtered);
            InterlockedExchange(&g_InRecorder[processor], 0);
            return info.Trampoline;
        }
    }

    for (i = 0; i < info.FilterCount && i < SVMHV_MAX_FILTERS; i++)
    {
        const SVMHV_FILTER* filter = &info.Filters[i];

        if (!SvTraceFilterPasses(filter,
                                 SvTraceSubject(filter, arguments, returnAddress)))
        {
            InterlockedIncrement64(&g_Filtered);
            InterlockedExchange(&g_InRecorder[processor], 0);
            return info.Trampoline;
        }
    }

    {
        UINT64 sequence;
        SVMHV_TRACE_RECORD* record = SvTraceClaim(&sequence);

        if (record != NULL)
        {
            RtlZeroMemory(record, sizeof(*record));
            record->Sequence = sequence;
            record->Tsc      = __rdtsc();
            record->Rip      = info.Target;
            record->Rsp      = OriginalRsp;
            for (i = 0; i < 4; i++)
            {
                record->Arguments[i] = arguments[i];
                record->StackArguments[i] = arguments[4 + i];
            }
            record->ReturnAddress = returnAddress;

            /*
             * The frames above the immediate caller.  Skipped frames are this
             * recorder and the thunk that reached it, which are ours and say
             * nothing about the call.
             *
             * Only at an IRQL where a page fault is legal.  The unwinder reads
             * .pdata, which is pageable, and taking a fault at DISPATCH_LEVEL
             * inside a hook is not survivable - the same reason the captures
             * above are fenced.
             */
            if (info.CaptureStack && irql <= APC_LEVEL)
            {
                record->FrameCount = SvTraceStackCandidates(
                    OriginalRsp + sizeof(UINT64), record->Frames,
                    SVMHV_MAX_FRAMES);
            }

            record->Gpa       = info.Gpa;
            record->HookId    = (UINT32)HookId;
            record->Type      = SVMHV_TRACE_EXEC;
            record->Processor = processor;
            record->ProcessId = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
            record->ThreadId  = (UINT32)(ULONG_PTR)PsGetCurrentThreadId();
            record->Irql      = (UINT32)irql;
            if (imageName != NULL)
            {
                RtlCopyMemory(record->ProcessName, imageName,
                              SVMHV_PROCESS_NAME_MAX - 1);
            }

            /*
             * Follow pointer arguments, but only where a page fault is legal.
             * Above APC_LEVEL, touching paged memory is fatal, so the capture is
             * simply not taken and comes back empty rather than risking it.
             */
            if (irql <= APC_LEVEL)
            {
                for (i = 0; i < info.CaptureCount && i < SVMHV_MAX_CAPTURES; i++)
                {
                    const SVMHV_CAPTURE* capture = &info.Captures[i];

                    if (capture->Type != SVMHV_CAPTURE_NONE &&
                        capture->Argument < RTL_NUMBER_OF(arguments))
                    {
                        record->CaptureLength[i] = SvTraceCapture(
                            capture, arguments[capture->Argument],
                            record->CaptureData[i]);
                    }
                }
            }
        }

        /*
         * Replace arguments on the way through.  The register ones live in the
         * frame the thunk is about to restore, so writing them here is all it
         * takes; the stack ones belong to the caller's frame, which outlives the
         * call, so they are written back in place.
         */
        for (i = 0; i < info.SpoofCount && i < SVMHV_MAX_SPOOFS; i++)
        {
            const ULONG index = info.Spoofs[i].Argument;
            const UINT64 value = info.Spoofs[i].Value;

            switch (index)
            {
            case 0: Frame->Rcx = value; spoofed++; break;
            case 1: Frame->Rdx = value; spoofed++; break;
            case 2: Frame->R8  = value; spoofed++; break;
            case 3: Frame->R9  = value; spoofed++; break;
            default:
                if (index < 8 &&
                    SvTraceReadable(&stack[index + 1], sizeof(UINT64)))
                {
                    stack[index + 1] = value;
                    spoofed++;
                }
                break;
            }
        }

        if (record != NULL)
        {
            record->Spoofed = spoofed;
        }

        g_LastArguments[0] = arguments[0];
        g_LastArguments[1] = arguments[1];
        g_LastArguments[2] = arguments[2];
        g_LastArguments[3] = arguments[3];
        InterlockedIncrement(&g_LastExecRecords);
    }

    SvHookCountHit((UINT32)HookId);

    /*
     * Arrange to be here again when the function returns.  Done last, after the
     * arguments are recorded and while still inside the recursion guard, so a
     * failure to arrange it changes nothing that has already been observed.
     *
     * Deliberately not done for a blocked call: the original never runs, so
     * there is no return to catch, and the block stub returns through the
     * caller's own address - which we would have just overwritten.
     */
    if (info.CaptureReturn && info.BlockStub == NULL)
    {
        (VOID)SvTracePushReturn(HookId, OriginalRsp);
    }

    InterlockedExchange(&g_InRecorder[processor], 0);

    /*
     * Blocking is just a different continuation: a stub that loads RAX and
     * returns.  The thunk leaves RSP exactly as the function was entered, with
     * the caller's return address on top, so the stub's ret goes straight back
     * to the caller and the original never runs.
     */
    return (info.BlockStub != NULL) ? info.BlockStub : info.Trampoline;
}

/* ----------------------------------------------------------- watch path */

VOID SvTraceWatchHit(_In_ UINT32 HookId, _In_ UINT32 Type, _In_ UINT64 Rip,
                     _In_ UINT64 Gpa, _In_ UINT64 ErrorCode,
                     _In_ UINT32 Processor)
{
    UINT64 sequence;
    SVMHV_TRACE_RECORD* record = SvTraceClaim(&sequence);

    if (record == NULL)
    {
        return;
    }

    RtlZeroMemory(record, sizeof(*record));
    record->Sequence  = sequence;
    record->Tsc       = __rdtsc();
    record->Rip       = Rip;
    record->Gpa       = Gpa;
    record->ErrorCode = ErrorCode;
    record->HookId    = HookId;
    record->Type      = Type;
    record->Processor  = Processor;
}

/* --------------------------------------------------------------- clients */

/*
 * Where the ring is, so a client can read it directly instead of asking the
 * driver to copy it.  The consumer index is the client's own business: the
 * producer counter is monotonic, so a client remembers what it has already seen
 * and works out for itself whether it has been lapped.
 */
VOID SvTraceDescribeRing(_Out_ UINT64* Ring, _Out_ UINT64* Produced,
                         _Out_ UINT64* Records, _Out_ UINT64* RecordSize)
{
    *Ring       = (UINT64)g_Ring;
    *Produced   = (UINT64)&g_Produced;
    *Records    = TRACE_RING_RECORDS;
    *RecordSize = sizeof(SVMHV_TRACE_RECORD);
}

/*
 * A client reporting how far it has drained.  Only ever forwards, and never
 * past what has actually been produced: a client that claimed the future would
 * silence the drop counter permanently, which is the one thing this counter
 * exists to avoid.
 */
VOID SvTraceSetConsumed(_In_ UINT64 Sequence)
{
    LONG64 wanted = (LONG64)Sequence;
    LONG64 current;

    if (wanted > g_Produced)
    {
        wanted = g_Produced;
    }

    do
    {
        current = g_Consumed;
        if (wanted <= current)
        {
            return;
        }
    }
    while (InterlockedCompareExchange64(&g_Consumed, wanted, current) != current);
}

VOID SvTraceReset(VOID)
{
    KIRQL irql;

    KeAcquireSpinLock(&g_DrainLock, &irql);
    g_Produced = 0;
    g_Consumed = 0;
    g_Dropped = 0;
    g_Filtered = 0;
    g_LastExecRecords = 0;
    RtlZeroMemory(g_LastArguments, sizeof(g_LastArguments));
    if (g_Ring != NULL)
    {
        RtlZeroMemory(g_Ring, sizeof(SVMHV_TRACE_RECORD) * TRACE_RING_RECORDS);
    }
    KeReleaseSpinLock(&g_DrainLock, irql);
}
