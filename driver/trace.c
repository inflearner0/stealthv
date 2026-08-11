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
 * The walk is bounded by the stack's real top, and it has to be.  This used to
 * read a fixed 256 qwords upwards and guard them with __try/__except, which is
 * two mistakes rather than one: a shallow stack runs into its guard page well
 * short of 256 slots, and an access to an unmapped *kernel* address is not an
 * exception Windows raises - MiSystemFault decides the reference is invalid and
 * calls KeBugCheckEx, so there is nothing for a handler to catch.  Installed on
 * nt!NtCreateFile that took the guest down in under a minute with
 * 0x50 PAGE_FAULT_IN_NONPAGED_AREA, reading the page immediately above the
 * faulting thread's own RSP.  The __except went with the fix, because keeping
 * it would mean keeping something that looks like protection and is not.
 *
 * IoGetStackLimits rather than KeGetCurrentThread()'s StackLimit/StackBase,
 * because an exec hook fires at whatever IRQL its target runs at: at
 * DISPATCH_LEVEL the live stack is the processor's DPC stack, and the thread's
 * own limits describe a different piece of memory entirely.  IoGetStackLimits
 * knows which one is current and is callable at any IRQL.
 */
#define TRACE_STACK_SLOTS   256     /* cost bound; the limits are the safety */

static ULONG SvTraceStackCandidates(_In_ UINT64 Rsp,
                                    _Out_writes_(Count) UINT64* Frames,
                                    _In_ ULONG Count)
{
    ULONG_PTR low = 0;
    ULONG_PTR high = 0;
    UINT64 at;
    ULONG found = 0;
    ULONG examined;

    if (Rsp == 0 || Count == 0)
    {
        return 0;
    }

    IoGetStackLimits(&low, &high);

    /*
     * If RSP is not inside the stack we were told about, we do not know what we
     * are standing on and must not go looking.  Nothing legitimate does this;
     * it means the frame came from somewhere this walk cannot reason about.
     */
    at = (Rsp + 7) & ~7ULL;
    if (high <= low || at < (UINT64)low || at >= (UINT64)high)
    {
        return 0;
    }

    for (examined = 0;
         examined < TRACE_STACK_SLOTS && found < Count && at + 8 <= (UINT64)high;
         examined++, at += 8)
    {
        const UINT64 value = *(const UINT64*)at;

        /* Kernel code lives above this; anything else is data. */
        if (value >= 0xFFFFF80000000000ULL && value < 0xFFFFFFFFFFFF0000ULL)
        {
            Frames[found++] = value;
        }
    }

    return found;
}

/*
 * Power of two, so the modulo is a mask.  4096 records is a little over 2 MiB,
 * which buys roughly a second of a moderately busy hook before a client that is
 * draining once a second starts losing the oldest of them.
 */
#define TRACE_RING_RECORDS  4096
#define TRACE_RING_MASK     (TRACE_RING_RECORDS - 1)

static SVMHV_TRACE_RECORD* g_Ring;
/*
 * Absolute, never-reused sequence numbers.  Reset deliberately does not put
 * this counter back to zero: an old reader must never mistake a record from a
 * previous trace generation for a newly produced record in the same slot.
 */
static volatile LONG64     g_Produced;

/*
 * An even generation is stable; an odd generation means SvTraceReset is
 * publishing a new cursor floor.  Records carry the even generation observed
 * when they were claimed, and clients reject records from another generation.
 */
static volatile LONG64     g_Generation;
static volatile LONG64     g_ResetFloor;
static volatile LONG64     g_ResetProduced;
static volatile LONG64     g_ResetDropped;
static volatile LONG64     g_ResetFiltered;
/* Claims only hold this tiny gate until g_Produced has advanced. */
static volatile LONG       g_Claiming;

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

static UINT64 SvTraceLoad64(_In_ const volatile LONG64* Value)
{
    return (UINT64)InterlockedCompareExchange64((volatile LONG64*)Value, 0, 0);
}

/* Publish only after every ordinary record field is visible to another CPU. */
static VOID SvTracePublish(_Inout_ SVMHV_TRACE_RECORD* Record,
                           _In_ UINT64 Sequence)
{
    KeMemoryBarrier();
    InterlockedExchange64((volatile LONG64*)&Record->CommitSequence,
                          (LONG64)(Sequence + 1));
}

/*
 * A hook whose detour is traced must not be able to trace itself.
 *
 * This used to be one flag per processor, on the grounds that the recorder
 * never blocks - and that stopped being true the moment it started
 * dereferencing arguments.  SvTraceCapture runs at IRQL <= APC_LEVEL precisely
 * so it *can* take a page fault, and a thread that faults there is descheduled
 * and can come back on a different processor.  It then holds the flag belonging
 * to the processor it started on, and a hooked function called after the move
 * tests the flag of the processor it is on now, which is very likely clear.
 * The one case the guard exists to catch is the one it could miss.
 *
 * Recursion is a property of the call chain, and a call chain belongs to a
 * thread, so the flag belongs to a thread.  Same shape as the return table
 * below: open addressed, fixed size, no allocation.  The whole probe window is
 * always scanned, because a slot is released by writing zero and an early exit
 * on the first empty entry could step over the entry it was looking for.
 */
#define TRACE_RECORDER_SLOTS    256
#define TRACE_RECORDER_PROBE    16
#define TRACE_RECORDER_NONE     TRACE_RECORDER_SLOTS

static volatile LONG64 g_InRecorder[TRACE_RECORDER_SLOTS];

/*
 * TRUE if this thread was not already inside the recorder, in which case Slot
 * has to be handed to SvTraceLeaveRecorder on the way out.  FALSE means either
 * genuine recursion or a full table; both are answered the same way, by not
 * recording, because guessing wrong in the other direction is a recorder that
 * calls itself.
 */
static BOOLEAN SvTraceEnterRecorder(_Out_ ULONG* Slot)
{
    const LONG64 thread = (LONG64)(ULONG_PTR)PsGetCurrentThread();
    const ULONG start = (ULONG)(((ULONG_PTR)thread >> 4) % TRACE_RECORDER_SLOTS);
    ULONG spare = TRACE_RECORDER_NONE;
    ULONG i;

    *Slot = TRACE_RECORDER_NONE;

    for (i = 0; i < TRACE_RECORDER_PROBE; i++)
    {
        const ULONG index = (start + i) % TRACE_RECORDER_SLOTS;
        const LONG64 occupant = g_InRecorder[index];

        if (occupant == thread)
        {
            return FALSE;               /* already inside: this is recursion */
        }
        if (occupant == 0 && spare == TRACE_RECORDER_NONE)
        {
            spare = index;
        }
    }

    if (spare == TRACE_RECORDER_NONE ||
        InterlockedCompareExchange64(&g_InRecorder[spare], thread, 0) != 0)
    {
        return FALSE;
    }

    *Slot = spare;
    return TRUE;
}

static VOID SvTraceLeaveRecorder(_In_ ULONG Slot)
{
    if (Slot < TRACE_RECORDER_SLOTS)
    {
        InterlockedExchange64(&g_InRecorder[Slot], 0);
    }
}

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
    g_Generation = 2;                 /* stable, non-zero seqlock value */
    g_ResetFloor = 0;
    g_ResetProduced = 0;
    g_ResetDropped = 0;
    g_ResetFiltered = 0;
    g_Claiming = 0;
    RtlZeroMemory(g_Ring, sizeof(SVMHV_TRACE_RECORD) * TRACE_RING_RECORDS);
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
    const UINT64 produced = SvTraceLoad64(&g_Produced);
    const UINT64 dropped = SvTraceLoad64(&g_Dropped);
    const UINT64 filtered = SvTraceLoad64(&g_Filtered);
    const UINT64 producedBase = SvTraceLoad64(&g_ResetProduced);
    const UINT64 droppedBase = SvTraceLoad64(&g_ResetDropped);
    const UINT64 filteredBase = SvTraceLoad64(&g_ResetFiltered);

    /* Reset is a logical generation boundary, not a destructive ring clear. */
    *Produced = (produced >= producedBase) ? produced - producedBase : 0;
    *Dropped  = (dropped >= droppedBase) ? dropped - droppedBase : 0;
    *Filtered = (filtered >= filteredBase) ? filtered - filteredBase : 0;
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
    UINT64 generation;
    SVMHV_TRACE_RECORD* record;

    *Sequence = 0;

    if (g_Ring == NULL)
    {
        return NULL;
    }

    /*
     * Reset needs a precise floor: an old-generation claim must either advance
     * g_Produced before the reset sees the gate empty, or not advance it at
     * all.  The gate covers only two atomic reads and one increment, never the
     * record formatting path, so reset does not wait for captures or page
     * faults and hook paths never spin waiting for reset.
     */
    generation = SvTraceLoad64(&g_Generation);
    if ((generation & 1) != 0)
    {
        return NULL;
    }

    InterlockedIncrement(&g_Claiming);
    KeMemoryBarrier();
    if (generation != SvTraceLoad64(&g_Generation) ||
        (generation & 1) != 0)
    {
        InterlockedDecrement(&g_Claiming);
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
    InterlockedDecrement(&g_Claiming);

    *Sequence = (UINT64)sequence;
    record = &g_Ring[sequence & TRACE_RING_MASK];

    /*
     * Invalidate the old incarnation before touching anything it contains.
     * A reader that started before this store will see a different commit
     * sequence afterwards; one that starts after it gets RETRY until the
     * final SvTracePublish below.
     */
    InterlockedExchange64((volatile LONG64*)&record->CommitSequence, 0);
    RtlZeroMemory(record, FIELD_OFFSET(SVMHV_TRACE_RECORD, CommitSequence));
    record->Sequence = (UINT64)sequence;
    record->Generation = generation;
    return record;
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

/*
 * "<label>0x<value>" into a bounded buffer, returning what it wrote.
 *
 * Small enough to keep here rather than share: this runs with GIF clear, out of
 * the exit handler, so it may not call anything that could fault or allocate -
 * which rules out every formatting routine the kernel offers.
 */
static ULONG SvTraceFormatText(_Out_writes_bytes_(Maximum) UINT8* Out,
                               _In_ ULONG Maximum, _In_ const CHAR* Label,
                               _In_ UINT64 Value)
{
    static const CHAR digits[] = "0123456789abcdef";
    CHAR temp[16];
    ULONG used = 0;
    int at = 0;

    while (*Label != '\0' && used + 1 < Maximum)
    {
        Out[used++] = (UINT8)*Label++;
    }
    if (used + 3 >= Maximum)
    {
        return used;
    }
    Out[used++] = '0';
    Out[used++] = 'x';

    if (Value == 0)
    {
        Out[used++] = '0';
        return used;
    }
    while (Value != 0 && at < (int)sizeof(temp))
    {
        temp[at++] = digits[Value & 0xF];
        Value >>= 4;
    }
    while (at > 0 && used + 1 < Maximum)
    {
        Out[used++] = (UINT8)temp[--at];
    }
    return used;
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

    case SVMHV_CAPTURE_IRP:
    {
        /*
         * An IRP, reported as the request it carries.
         *
         * This is the one capture that follows a pointer inside a structure
         * rather than reading one, and it is worth the special case: the
         * control code a driver was actually asked for is two dereferences from
         * the IRP and lives nowhere else.  Reading the dispatcher recovers the
         * codes a driver *can* handle; this is the only way to see which ones
         * anything really sends, and with what buffer sizes.
         *
         * The offsets are the x64 IRP and IO_STACK_LOCATION layout: the current
         * stack location at +0xB8, and inside it the major function at +0x00
         * and the DeviceIoControl parameters from +0x08.
         *
         * Formatted as text rather than as a structure so that it arrives
         * legible with no agreement about layout between here and the client -
         * a capture slot is 128 bytes and this needs about seventy.
         */
        UINT64 stackLocation = 0;
        UINT8 slot[0x38];
        ULONG used = 0;

        if (SvTraceCopyIn((UINT8*)&stackLocation, sizeof(stackLocation),
                          (const UINT8*)Argument + 0xB8,
                          sizeof(stackLocation)) != sizeof(stackLocation) ||
            stackLocation == 0)
        {
            return 0;
        }
        if (SvTraceCopyIn(slot, sizeof(slot), (const VOID*)stackLocation,
                          sizeof(slot)) != sizeof(slot))
        {
            return 0;
        }

        used += SvTraceFormatText(Out + used, SVMHV_CAPTURE_MAX - used,
                                  "major=", slot[0]);

        /*
         * Parameters is a union, and only the device control majors put a
         * control code in it.  A dispatcher that serves every major function -
         * which is the common shape, and the reason this hook is worth
         * installing - therefore produces reads and creates through here too,
         * and printing their parameters as "ioctl=" invents a control code out
         * of a buffer length.  It looked entirely plausible: an IRP_MJ_READ
         * came out as ioctl=0xbbc2d000.
         */
        if (slot[0] == IRP_MJ_DEVICE_CONTROL ||
            slot[0] == IRP_MJ_INTERNAL_DEVICE_CONTROL)
        {
            used += SvTraceFormatText(Out + used, SVMHV_CAPTURE_MAX - used,
                                      " ioctl=", *(const UINT32*)(slot + 0x18));
            used += SvTraceFormatText(Out + used, SVMHV_CAPTURE_MAX - used,
                                      " in=", *(const UINT32*)(slot + 0x10));
            used += SvTraceFormatText(Out + used, SVMHV_CAPTURE_MAX - used,
                                      " out=", *(const UINT32*)(slot + 0x08));
        }

        used += SvTraceFormatText(Out + used, SVMHV_CAPTURE_MAX - used,
                                  " dev=", *(const UINT64*)(slot + 0x28));
        return used;
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

    /*
     * Discard frames belonging to calls that never returned.
     *
     * A traced call that is unwound past - an exception caught above it, a
     * longjmp, a thread killed in the middle of it - never reaches
     * AsmTraceReturn, so its frame stays here forever.  The stack grows
     * downwards, so a recorded RSP *below* the one this call was entered with
     * describes stack that has since been popped and cannot come back: the
     * frame is provably dead.
     *
     * Without this the frames accumulate, depth reaches TRACE_RETURN_DEPTH and
     * the thread silently stops capturing returns for the rest of its life -
     * which is a trap, because the code that hits it most is exactly the code
     * worth tracing.  SvTraceReturnEntry already searches downwards and so
     * never returned to a stale address; it just had no way to reclaim one.
     */
    depth = slot->Depth;
    while (depth > 0 && slot->Frames[depth - 1].Rsp < OriginalRsp)
    {
        depth--;
    }
    slot->Depth = depth;

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
                SvTracePublish(record, sequence);
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
    ULONG recorderSlot;
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

    if (!SvTraceEnterRecorder(&recorderSlot))
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
            SvTraceLeaveRecorder(recorderSlot);
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
            SvTraceLeaveRecorder(recorderSlot);
            return info.Trampoline;
        }
    }

    {
        UINT64 sequence;
        SVMHV_TRACE_RECORD* record = SvTraceClaim(&sequence);

        if (record != NULL)
        {
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
            /* Redundant here, where the process id is already known, and
               recorded anyway so that one field means the same thing on every
               kind of record - a watch has nothing but this. */
            record->Cr3       = __readcr3();
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
            SvTracePublish(record, sequence);
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

    SvTraceLeaveRecorder(recorderSlot);

    /*
     * Blocking is just a different continuation: a stub that loads RAX and
     * returns.  The thunk leaves RSP exactly as the function was entered, with
     * the caller's return address on top, so the stub's ret goes straight back
     * to the caller and the original never runs.
     */
    return (info.BlockStub != NULL) ? info.BlockStub : info.Trampoline;
}

/* ----------------------------------------------------------- watch path */

/*
 * The instruction that faulted, so the client can decode the store without
 * coming back for it.
 *
 * Safe for exactly one reason, and it is worth being precise about it: the
 * processor has just fetched an instruction from this page, so the page is
 * mapped and resident by definition.  That argument covers RIP's own page and
 * nothing else, hence the clamp to the page boundary - the next page has no
 * such guarantee and reading into it is how the stack walk used to bugcheck.
 *
 * Kernel addresses only.  The host's CR3 at an exit is whichever address space
 * this processor launched in, so a user-mode RIP would either read the wrong
 * process's memory or fault; the record says CodeLength 0 and the client
 * disassembles it through the control channel instead, at PASSIVE_LEVEL where
 * attaching to the right process is legal.
 */
static UINT32 SvTraceCodeAt(_In_ UINT64 Rip, _Out_writes_(Max) UINT8* Code,
                            _In_ UINT32 Max)
{
    const UINT64 pageEnd = (Rip | (PAGE_SIZE - 1)) + 1;
    UINT32 length = Max;
    UINT32 i;

    if (Rip < (UINT64)MM_SYSTEM_RANGE_START)
    {
        return 0;
    }
    if (pageEnd - Rip < length)
    {
        length = (UINT32)(pageEnd - Rip);
    }

    for (i = 0; i < length; i++)
    {
        Code[i] = ((const UINT8*)Rip)[i];
    }

    return length;
}

VOID SvTraceWatchHit(_In_ UINT32 HookId, _In_ UINT32 Type, _In_ UINT64 Rip,
                     _In_ UINT64 Gpa, _In_ UINT64 ErrorCode,
                     _In_ UINT32 Processor, _In_ UINT64 Cr3,
                     _In_opt_ const VOID* WatchVa,
                     _Inout_ SVMHV_WATCH_PENDING* Pending)
{
    UINT64 sequence;
    SVMHV_TRACE_RECORD* record;

    /*
     * A record outstanding from a previous hit means the exit that should have
     * completed it never arrived.  Publish it as it stands rather than leaking
     * the slot; ValueWidth already says the second read did not happen.
     */
    if (Pending->Record != NULL)
    {
        SvTracePublish(Pending->Record, Pending->Sequence);
        RtlZeroMemory(Pending, sizeof(*Pending));
    }

    record = SvTraceClaim(&sequence);
    if (record == NULL)
    {
        return;
    }

    record->Tsc       = __rdtsc();
    record->Rip       = Rip;
    record->Gpa       = Gpa;
    record->ErrorCode = ErrorCode;
    record->HookId    = HookId;
    record->Type      = Type;
    record->Processor = Processor;
    record->Cr3       = Cr3;
    record->CodeLength = SvTraceCodeAt(Rip, record->Code, sizeof(record->Code));

    /*
     * The value, if the page has an alias.  The GPA an #NPF reports is the
     * faulting byte address, not just its page, so the offset is where the
     * access actually landed.  A qword of it, clamped so it stays inside the
     * page - the store's real width is unknown without decoding it, and
     * reporting a window the client can diff is more honest than guessing.
     */
    if (WatchVa != NULL)
    {
        const UINT32 offset = (UINT32)(Gpa & (PAGE_SIZE - 1));
        UINT32 width = sizeof(UINT64);

        if (offset + width > PAGE_SIZE)
        {
            width = PAGE_SIZE - offset;
        }

        record->ValueBefore = 0;
        RtlCopyMemory(&record->ValueBefore, (const UINT8*)WatchVa + offset,
                      width);
        record->ValueWidth = width;

        /*
         * Held back rather than published.  The store has not run yet - the
         * guest is about to re-execute it - so publishing now would record a
         * "before" and call it the answer.  The next exit this processor takes
         * is the fault that returns it to the primary view, and by then the
         * store has retired.
         */
        Pending->Record   = record;
        Pending->Sequence = sequence;
        Pending->Address  = (const UINT8*)WatchVa + offset;
        Pending->Width    = width;
        return;
    }

    SvTracePublish(record, sequence);
}

VOID SvTraceStep(_In_ UINT64 Rip, _In_ UINT64 Rsp, _In_ UINT64 Rflags,
                 _In_ UINT64 Cr3, _In_ UINT32 Processor,
                 _In_reads_(CodeLength) const UINT8* Code,
                 _In_ UINT32 CodeLength, _In_ BOOLEAN GuestTf)
{
    UINT64 sequence;
    SVMHV_TRACE_RECORD* record = SvTraceClaim(&sequence);
    UINT64 flags = Rflags;

    if (record == NULL)
    {
        return;
    }

    /* Record the guest's RFLAGS, not ours: our trap flag is an artefact of
       the measurement and recording it would be recording the instrument. */
    if (GuestTf)
    {
        flags |= SVM_RFLAGS_TF;
    }
    else
    {
        flags &= ~SVM_RFLAGS_TF;
    }

    record->Tsc          = __rdtsc();
    record->Rip          = Rip;
    record->Rsp          = Rsp;
    record->Cr3          = Cr3;
    record->Type         = SVMHV_TRACE_STEP;
    record->Processor    = Processor;
    record->Arguments[0] = flags;

    if (CodeLength > sizeof(record->Code))
    {
        CodeLength = sizeof(record->Code);
    }
    RtlCopyMemory(record->Code, Code, CodeLength);
    record->CodeLength = CodeLength;

    SvTracePublish(record, sequence);
}

VOID SvTraceWatchComplete(_Inout_ SVMHV_WATCH_PENDING* Pending)
{
    SVMHV_TRACE_RECORD* record = Pending->Record;

    if (record == NULL)
    {
        return;
    }

    RtlCopyMemory(&record->ValueAfter, Pending->Address, Pending->Width);
    SvTracePublish(record, Pending->Sequence);
    RtlZeroMemory(Pending, sizeof(*Pending));
}

/* --------------------------------------------------------------- clients */

/*
 * Where the ring is, so a client can read it directly instead of asking the
 * driver to copy it.  Produced is an absolute cursor, not the reset-relative
 * trace-record counter shown in stats.  It never goes backwards for the
 * lifetime of this driver instance.
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
 * The durable cursor boundary for a client that wants non-destructive reads.
 * Generation is a tiny seqlock around Floor: readers only accept an even,
 * unchanged generation.  A record has to match both this generation and its
 * own committed absolute sequence before the client prints or advances past it.
 */
VOID SvTraceCursorState(_Out_ UINT64* Head, _Out_ UINT64* Floor,
                        _Out_ UINT64* Generation)
{
    UINT64 generation = 0;
    UINT64 floor = 0;
    UINT64 head = 0;
    ULONG attempt;

    for (attempt = 0; attempt < 8; attempt++)
    {
        const UINT64 before = SvTraceLoad64(&g_Generation);

        if ((before & 1) != 0)
        {
            continue;
        }

        head = SvTraceLoad64(&g_Produced);
        floor = SvTraceLoad64(&g_ResetFloor);
        if (head > TRACE_RING_RECORDS && floor < head - TRACE_RING_RECORDS)
        {
            floor = head - TRACE_RING_RECORDS;
        }
        generation = SvTraceLoad64(&g_Generation);
        if (generation == before && (generation & 1) == 0)
        {
            *Head = head;
            *Floor = floor;
            *Generation = generation;
            return;
        }
    }

    /* A reset is exceptionally short.  Tell the client to retry rather than
       returning a floor from one generation and a head from another. */
    *Head = 0;
    *Floor = 0;
    *Generation = SvTraceLoad64(&g_Generation) | 1;
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
    const LONG64 produced = (LONG64)SvTraceLoad64(&g_Produced);

    if (wanted > produced)
    {
        wanted = produced;
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
    UINT64 head;

    /*
     * Never clear an actively-written ring.  Producers run from arbitrary
     * hooks (and from the #NPF handler), so a spin lock held by the worker
     * never excluded them.  Advancing the absolute cursor floor instead makes
     * reset atomic from the reader's point of view and leaves in-flight writers
     * harmlessly tagged with the generation they started in.
     */
    InterlockedIncrement64(&g_Generation);       /* odd: reset in progress */
    KeMemoryBarrier();

    /* See SvTraceClaim: a claim that could still use the old generation must
       have advanced g_Produced before it drops this gate. */
    while (InterlockedCompareExchange(&g_Claiming, 0, 0) != 0)
    {
        KeStallExecutionProcessor(1);
    }

    head = SvTraceLoad64(&g_Produced);
    InterlockedExchange64(&g_ResetFloor, (LONG64)head);
    InterlockedExchange64(&g_ResetProduced, (LONG64)head);
    InterlockedExchange64(&g_ResetDropped, g_Dropped);
    InterlockedExchange64(&g_ResetFiltered, g_Filtered);
    SvTraceSetConsumed(head);

    InterlockedExchange(&g_LastExecRecords, 0);
    RtlZeroMemory(g_LastArguments, sizeof(g_LastArguments));
    g_LastReturn = 0;

    KeMemoryBarrier();
    InterlockedIncrement64(&g_Generation);       /* even: new generation */
}
