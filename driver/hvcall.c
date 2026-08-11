/*
 * hvcall.c - the CPUID control channel.  See hvcall.h.
 */

#include "hvcall.h"
#include "config.h"
#include "control.h"
#include "trace.h"

/*
 * Copy a bounded window out of driver memory into the guest's registers.
 *
 * Every caller has already established that Source/Size names one of our own
 * structures; this is where the offset the client asked for is checked against
 * it.  Reads are clamped rather than refused at the tail so a client can walk a
 * structure whose length is not a multiple of the window.
 */
static UINT64 SvReadWindow(_Inout_ GUEST_CONTEXT* Context,
                           _In_reads_bytes_(Size) const UINT8* Source,
                           _In_ SIZE_T Size, _In_ UINT64 Offset)
{
    UINT8 window[SVMHV_HV_READ_WINDOW] = { 0 };
    SIZE_T available;

    if (Source == NULL)
    {
        return SVMHV_HV_STATUS_UNAVAILABLE;
    }
    if ((Offset & 7) != 0 || Offset >= Size)
    {
        return SVMHV_HV_STATUS_BADOFFSET;
    }

    available = Size - (SIZE_T)Offset;
    if (available > sizeof(window))
    {
        available = sizeof(window);
    }
    RtlCopyMemory(window, Source + Offset, available);

    Context->Rbx = *(const UINT64*)(window + 0x00);
    Context->Rdx = *(const UINT64*)(window + 0x08);
    Context->Rsi = *(const UINT64*)(window + 0x10);
    Context->Rdi = *(const UINT64*)(window + 0x18);
    Context->R8  = *(const UINT64*)(window + 0x20);
    Context->R9  = *(const UINT64*)(window + 0x28);

    return SVMHV_HV_STATUS_OK;
}

/*
 * A snapshot spans hundreds of 48-byte hypercall windows.  A raw window is
 * still available to v1 clients (ExpectedSequence == 0), while v2 clients pin
 * every window to one even publish sequence and retry a whole snapshot when a
 * refresh overlaps it.
 */
static UINT64 SvReadSnapshotWindow(_Inout_ GUEST_CONTEXT* Context,
                                   _In_ UINT64 Offset,
                                   _In_ UINT64 ExpectedSequence)
{
    UINT64 status;

    /* The client samples this field before and after a protected view.  Read
       it atomically rather than relying on a generic byte copy to preserve the
       seqlock's single-word semantics. */
    if (ExpectedSequence == 0 &&
        Offset == FIELD_OFFSET(SVMHV_SNAPSHOT, PublishSequence))
    {
        Context->Rbx = (UINT64)InterlockedCompareExchange64(
            (volatile LONG64*)&g_Snapshot.PublishSequence, 0, 0);
        Context->Rdx = 0;
        Context->Rsi = 0;
        Context->Rdi = 0;
        Context->R8 = 0;
        Context->R9 = 0;
        return SVMHV_HV_STATUS_OK;
    }

    if (ExpectedSequence != 0)
    {
        const UINT64 before = (UINT64)InterlockedCompareExchange64(
            (volatile LONG64*)&g_Snapshot.PublishSequence, 0, 0);

        if ((ExpectedSequence & 1) != 0 || before != ExpectedSequence)
        {
            return SVMHV_HV_STATUS_RETRY;
        }
    }

    status = SvReadWindow(Context, (const UINT8*)&g_Snapshot,
                          sizeof(g_Snapshot), Offset);
    if (status != SVMHV_HV_STATUS_OK || ExpectedSequence == 0)
    {
        return status;
    }

    KeMemoryBarrier();
    if ((UINT64)InterlockedCompareExchange64(
            (volatile LONG64*)&g_Snapshot.PublishSequence, 0, 0) !=
        ExpectedSequence)
    {
        return SVMHV_HV_STATUS_RETRY;
    }

    return SVMHV_HV_STATUS_OK;
}

/*
 * Copy one window of an absolute trace cursor only if its slot remained the
 * same fully-published record for the entire copy.  The control client retries
 * the record as a unit, so it can never compose one trace event from two slot
 * incarnations.
 */
static UINT64 SvReadTraceCursorWindow(_Inout_ GUEST_CONTEXT* Context,
                                      _In_ UINT64 Sequence,
                                      _In_ UINT64 Offset)
{
    UINT64 ring;
    UINT64 producedAddress;
    UINT64 records;
    UINT64 recordSize;
    UINT64 head;
    UINT64 floor;
    UINT64 generation;
    const SVMHV_TRACE_RECORD* record;
    const UINT64 expected = Sequence + 1;
    UINT64 status;

    SvTraceDescribeRing(&ring, &producedAddress, &records, &recordSize);
    if (ring == 0 || records == 0)
    {
        return SVMHV_HV_STATUS_UNAVAILABLE;
    }
    if ((Offset & 7) != 0 || Offset >= recordSize)
    {
        return SVMHV_HV_STATUS_BADOFFSET;
    }

    SvTraceCursorState(&head, &floor, &generation);
    if ((generation & 1) != 0 || Sequence < floor || Sequence >= head)
    {
        return SVMHV_HV_STATUS_RETRY;
    }

    record = &((const SVMHV_TRACE_RECORD*)ring)[Sequence % records];
    if ((UINT64)InterlockedCompareExchange64(
            (volatile LONG64*)&record->CommitSequence, 0, 0) != expected ||
        record->Sequence != Sequence || record->Generation != generation)
    {
        return SVMHV_HV_STATUS_RETRY;
    }

    status = SvReadWindow(Context, (const UINT8*)record,
                          (SIZE_T)recordSize, Offset);
    if (status != SVMHV_HV_STATUS_OK)
    {
        return status;
    }

    KeMemoryBarrier();
    if ((UINT64)InterlockedCompareExchange64(
            (volatile LONG64*)&record->CommitSequence, 0, 0) != expected ||
        record->Sequence != Sequence || record->Generation != generation)
    {
        return SVMHV_HV_STATUS_RETRY;
    }

    /* A concurrent reset makes an otherwise valid old-generation record stale. */
    SvTraceCursorState(&head, &floor, &generation);
    if ((generation & 1) != 0 || Sequence < floor || Sequence >= head ||
        record->Generation != generation)
    {
        return SVMHV_HV_STATUS_RETRY;
    }

    return SVMHV_HV_STATUS_OK;
}

VOID SvHandleControlCall(_Inout_ GUEST_CONTEXT* Context, _In_ UINT8 Cpl)
{
    const UINT64 command = Context->Rbx;
    const UINT64 argument = Context->Rdx;
    const UINT64 argument2 = Context->Rsi;
    UINT64 status = SVMHV_HV_STATUS_OK;

#if STEALTHV_CONTROL_REQUIRE_CPL0
    /*
     * See STEALTHV_CONTROL_REQUIRE_CPL0 in config.h.  All or nothing: gating
     * only the commands that write would be theatre, because installing a hook
     * takes caller-supplied shellcode and runs it in ring 0.
     */
    if (Cpl != 0)
    {
        Context->Rax = SVMHV_HV_STATUS_BADCOMMAND;
        return;
    }
#else
    UNREFERENCED_PARAMETER(Cpl);
#endif

    switch (command)
    {
    case SVMHV_HV_PING:
        Context->Rbx = SVMHV_CONTROL_MAGIC;
        Context->Rdx = SVMHV_CONTROL_VERSION;
        break;

    case SVMHV_HV_WRITE_REQUEST:
        /*
         * The only writable thing in this channel, and it can only reach the
         * request block - a client cannot use it to poke the rest of the driver,
         * let alone the kernel.
         *
         * The bound is written as a subtraction rather than "argument + 8 >
         * size", which is what it used to say and which wraps: the guest
         * controls all 64 bits of the offset, and 0xFFFFFFFFFFFFFFF8 is
         * eight-aligned, so the addition overflowed to zero, the check passed
         * and the store landed eight bytes *below* the request block.  Size is
         * a compile-time constant far larger than eight, so the subtraction
         * cannot underflow.
         */
        C_ASSERT(sizeof(g_Control.Request) > sizeof(UINT64));
        if ((argument & 7) != 0 ||
            argument > sizeof(g_Control.Request) - sizeof(UINT64))
        {
            status = SVMHV_HV_STATUS_BADOFFSET;
            break;
        }
        *(UINT64*)((UINT8*)&g_Control.Request + argument) = argument2;
        break;

    case SVMHV_HV_SUBMIT:
        /*
         * Ring the doorbell for the worker.  Command first, sequence second, for
         * the same reason a debugger client had to: the sequence is what makes
         * the request visible.
         */
        g_Control.Command = (UINT32)argument;
        Context->Rbx = (UINT64)InterlockedIncrement64(
                                    (volatile LONG64*)&g_Control.Sequence);
        break;

    case SVMHV_HV_SIGNATURE:
        /* What the CPUID signature leaf used to answer, for probes. */
        Context->Rbx = 0x484D5653;      /* "SVMH" */
        Context->Rdx = 0x49532D56;      /* "V-SI" */
        Context->Rsi = 0x454C504D;      /* "MPLE" */
        break;

    case SVMHV_HV_POLL:
        Context->Rbx = g_Control.Completed;
        Context->Rdx = (UINT64)(UINT32)g_Control.Status;
        break;

    case SVMHV_HV_READ_SNAPSHOT:
        status = SvReadSnapshotWindow(Context, argument, argument2);
        break;

    case SVMHV_HV_READ_REQUEST:
        status = SvReadWindow(Context, (const UINT8*)&g_Control.Request,
                              sizeof(g_Control.Request), argument);
        break;

    case SVMHV_HV_READ_TRACE:
    {
        UINT64 ring;
        UINT64 produced;
        UINT64 records;
        UINT64 recordSize;

        SvTraceDescribeRing(&ring, &produced, &records, &recordSize);
        if (ring == 0 || records == 0)
        {
            status = SVMHV_HV_STATUS_UNAVAILABLE;
            break;
        }
        if (argument >= records)
        {
            status = SVMHV_HV_STATUS_BADOFFSET;
            break;
        }
        status = SvReadWindow(Context,
                              (const UINT8*)ring + argument * recordSize,
                              (SIZE_T)recordSize, argument2);
        break;
    }

    case SVMHV_HV_TRACE_CONSUMED:
        /* "I have read everything below this sequence." */
        SvTraceSetConsumed(argument);
        break;

    case SVMHV_HV_TRACE_STATE:
    {
        UINT64 ring;
        UINT64 producedAddress;
        UINT64 records;
        UINT64 recordSize;
        UINT64 head;
        UINT64 floor;
        UINT64 generation;

        SvTraceDescribeRing(&ring, &producedAddress, &records, &recordSize);
        SvTraceCursorState(&head, &floor, &generation);
        Context->Rbx = (ring != 0 && producedAddress != 0) ? head : 0;
        Context->Rdx = records;
        Context->Rsi = recordSize;
        Context->Rdi = floor;
        Context->R8  = generation;
        break;
    }

    case SVMHV_HV_READ_TRACE_CURSOR:
        status = SvReadTraceCursorWindow(Context, argument, argument2);
        break;

    default:
        status = SVMHV_HV_STATUS_BADCOMMAND;
        break;
    }

    Context->Rax = status;
}
