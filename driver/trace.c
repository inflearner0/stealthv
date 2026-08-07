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
 * Power of two, so the modulo is a mask.  4096 records is about 640 KiB, which
 * buys roughly a second of a moderately busy hook before a client that is
 * draining once a second starts losing the oldest of them.
 */
#define TRACE_RING_RECORDS  4096
#define TRACE_RING_MASK     (TRACE_RING_RECORDS - 1)

static SVMHV_TRACE_RECORD* g_Ring;
static volatile LONG64     g_Produced;      /* monotonic; & MASK gives a slot */
static UINT64              g_Consumed;      /* drained under g_DrainLock      */
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

    if ((UINT64)sequence >= g_Consumed + TRACE_RING_RECORDS)
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
