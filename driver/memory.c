/*
 * memory.c - reading and writing guest memory for a client.  See memory.h.
 */

/* Before memory.h, which takes ntddk.h: ntifs.h has to be first of the two. */
#include <ntifs.h>

#include "memory.h"

/*
 * Every copy in this file goes through here, and it is deliberately paranoid:
 * a client can ask for any address at all, and the whole point of the interface
 * is that it does not have to know in advance which ones are real.
 *
 * MmIsAddressValid first, a page at a time, then the copy under SEH.  The check
 * races - the page can go away between the question and the answer - which is
 * exactly why the copy is wrapped as well.  Neither alone is enough: SEH cannot
 * catch a fault at DISPATCH_LEVEL, and the check cannot see a page that is
 * valid but has become read-only.
 *
 * Copies a page at a time and stops at the first page that fails, so a read
 * that runs off the end of a valid region returns the part that existed.  A
 * client asking about a structure near the end of a mapping wants those bytes
 * far more than it wants an error.
 */
static ULONG SvMemoryCopy(_Out_writes_bytes_(Length) UINT8* Destination,
                          _In_ const UINT8* Source, _In_ ULONG Length,
                          _In_ BOOLEAN SourceIsUntrusted)
{
    ULONG done = 0;

    while (done < Length)
    {
        const UINT8* from = Source + done;
        const ULONG_PTR pageEnd = ((ULONG_PTR)from | (PAGE_SIZE - 1)) + 1;
        ULONG chunk = (ULONG)(pageEnd - (ULONG_PTR)from);

        if (chunk > Length - done)
        {
            chunk = Length - done;
        }

        if (SourceIsUntrusted && !MmIsAddressValid((PVOID)from))
        {
            break;
        }

        __try
        {
            RtlCopyMemory(Destination + done, from, chunk);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            break;
        }

        done += chunk;
    }

    return done;
}

/*
 * Run Operation in the address space of ProcessId, or in the current one when
 * ProcessId is zero.  Attaching is what makes a user-mode address in another
 * process mean anything here; the worker thread otherwise sees only the system
 * address space, where every user pointer a trace recorded is nonsense.
 */
typedef ULONG (*SVMHV_MEMORY_OPERATION)(_Inout_ SVMHV_HOOK_REQUEST* Request);

static NTSTATUS SvMemoryInProcess(_Inout_ SVMHV_HOOK_REQUEST* Request,
                                  _In_ SVMHV_MEMORY_OPERATION Operation)
{
    KAPC_STATE apcState;
    PEPROCESS process = NULL;
    NTSTATUS status;

    if (Request->MemoryProcessId != 0)
    {
        status = PsLookupProcessByProcessId(
                    (HANDLE)(ULONG_PTR)Request->MemoryProcessId, &process);
        if (!NT_SUCCESS(status))
        {
            Request->MemoryReturned = 0;
            return status;
        }

        KeStackAttachProcess(process, &apcState);
    }

    Request->MemoryReturned = Operation(Request);

    if (process != NULL)
    {
        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(process);
    }

    /*
     * Nothing readable at all is the one case worth reporting as a failure - a
     * client that asked about a bad address should hear so rather than be told
     * about a successful transfer of no bytes.
     */
    return (Request->MemoryReturned != 0) ? STATUS_SUCCESS
                                          : STATUS_PARTIAL_COPY;
}

static ULONG SvMemoryClampLength(_In_ UINT32 Length)
{
    return (Length == 0 || Length > SVMHV_MEMORY_MAX) ? SVMHV_MEMORY_MAX
                                                      : Length;
}

/* ------------------------------------------------------------------ read */

static ULONG SvMemoryReadOperation(_Inout_ SVMHV_HOOK_REQUEST* Request)
{
    return SvMemoryCopy(Request->MemoryData,
                        (const UINT8*)Request->MemoryAddress,
                        SvMemoryClampLength(Request->MemoryLength),
                        TRUE);
}

NTSTATUS SvMemoryRead(_Inout_ SVMHV_HOOK_REQUEST* Request)
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    if (Request->MemoryAddress == 0)
    {
        Request->MemoryReturned = 0;
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Request->MemoryData, sizeof(Request->MemoryData));
    return SvMemoryInProcess(Request, SvMemoryReadOperation);
}

/* ----------------------------------------------------------------- write */

static ULONG SvMemoryWriteOperation(_Inout_ SVMHV_HOOK_REQUEST* Request)
{
    /*
     * The destination is the untrusted side here, and MmIsAddressValid speaks
     * only for presence - a valid but read-only page passes it and then faults
     * on the store, which is what the SEH inside the copy is for.
     */
    const ULONG length = SvMemoryClampLength(Request->MemoryLength);
    ULONG done = 0;

    while (done < length)
    {
        UINT8* to = (UINT8*)Request->MemoryAddress + done;
        const ULONG_PTR pageEnd = ((ULONG_PTR)to | (PAGE_SIZE - 1)) + 1;
        ULONG chunk = (ULONG)(pageEnd - (ULONG_PTR)to);

        if (chunk > length - done)
        {
            chunk = length - done;
        }
        if (!MmIsAddressValid(to))
        {
            break;
        }

        __try
        {
            RtlCopyMemory(to, Request->MemoryData + done, chunk);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            break;
        }

        done += chunk;
    }

    return done;
}

NTSTATUS SvMemoryWrite(_Inout_ SVMHV_HOOK_REQUEST* Request)
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    if (Request->MemoryAddress == 0)
    {
        Request->MemoryReturned = 0;
        return STATUS_INVALID_PARAMETER;
    }

    return SvMemoryInProcess(Request, SvMemoryWriteOperation);
}

/* -------------------------------------------------------------- physical */

NTSTATUS SvMemoryReadPhysical(_Inout_ SVMHV_HOOK_REQUEST* Request)
{
    PHYSICAL_ADDRESS physical;
    const ULONG length = SvMemoryClampLength(Request->MemoryLength);
    PVOID existing;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    Request->MemoryReturned = 0;
    RtlZeroMemory(Request->MemoryData, sizeof(Request->MemoryData));

    /* One page at a time: the mapping this reaches through is per page, and a
       caller wanting more can simply ask twice. */
    if (((Request->MemoryAddress & (PAGE_SIZE - 1)) + length) > PAGE_SIZE)
    {
        return STATUS_INVALID_PARAMETER;
    }

    physical.QuadPart = (LONGLONG)Request->MemoryAddress;

    /*
     * Use the mapping the kernel already has, rather than making one.
     *
     * This was MmMapIoSpace, which is wrong here and was not a subtle kind of
     * wrong: that function is for device memory, and pointing it at ordinary
     * RAM builds a second mapping of a page the memory manager is already
     * tracking in the PFN database.  Doing that is what MEMORY_MANAGEMENT
     * bugchecks are made of, and the lab guest took one twelve minutes after
     * this code first ran.
     *
     * MmGetVirtualForPhysical asks for the direct-map address the page already
     * has, which creates nothing, needs no cache attribute decision and cannot
     * be unmapped out from under anybody.  The cost is that it only answers for
     * pages that have a virtual mapping at all - which is every page of RAM,
     * and none of the holes.  For reading guest memory that is exactly the set
     * we want, and a hole now says so instead of being invented.
     */
    existing = MmGetVirtualForPhysical(physical);
    if (existing == NULL)
    {
        return STATUS_NOT_FOUND;
    }

    Request->MemoryReturned = SvMemoryCopy(Request->MemoryData,
                                           (const UINT8*)existing, length, TRUE);

    return (Request->MemoryReturned != 0) ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
}
