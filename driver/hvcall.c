/*
 * hvcall.c - the CPUID control channel.  See hvcall.h.
 */

#include "hvcall.h"
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

VOID SvHandleControlCall(_Inout_ GUEST_CONTEXT* Context)
{
    const UINT64 command = Context->Rbx;
    const UINT64 argument = Context->Rdx;
    const UINT64 argument2 = Context->Rsi;
    UINT64 status = SVMHV_HV_STATUS_OK;

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
         */
        if ((argument & 7) != 0 ||
            argument + sizeof(UINT64) > sizeof(g_Control.Request))
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
        status = SvReadWindow(Context, (const UINT8*)&g_Snapshot,
                              sizeof(g_Snapshot), argument);
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

    case SVMHV_HV_TRACE_STATE:
    {
        UINT64 ring;
        UINT64 producedAddress;
        UINT64 records;
        UINT64 recordSize;

        SvTraceDescribeRing(&ring, &producedAddress, &records, &recordSize);
        Context->Rbx = (ring != 0 && producedAddress != 0)
                     ? *(const volatile UINT64*)producedAddress : 0;
        Context->Rdx = records;
        Context->Rsi = recordSize;
        break;
    }

    default:
        status = SVMHV_HV_STATUS_BADCOMMAND;
        break;
    }

    Context->Rax = status;
}
