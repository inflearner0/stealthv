/*
 * snapshot.c - copy-on-write snapshots of a range of guest memory.  See
 * snapshot.h for what this is and, more importantly, what it is not.
 */

#include "snapshot.h"
#include "svmhv.h"
#include "npt.h"
#include "memory.h"
#include "control.h"

#define SNAP_TAG    'nSvS'

/*
 * 64 MiB of range, which is where the write sweep's evidence already is: taking
 * write permission away means faulting on very nearly every page the guest
 * touches, and npt.c measured 64 MiB as comfortable and 256 MiB as fatal.  This
 * costs the same faults plus a 4 KiB copy each, so there is no reason to expect
 * it to behave better and every reason to use the number that was measured.
 */
#define SNAP_MAX_PAGES  (16u * 1024u)

typedef struct _SNAP_PAGE
{
    UINT64        Gpa;
    PVOID         SysVa;            /* system alias, locked for the duration */
    volatile LONG StoreIndex;       /* -1 until the original was copied aside */
} SNAP_PAGE;

static SNAP_PAGE*    g_Pages;
static UINT64        g_PageCount;
static UINT8*        g_Store;
static ULONG         g_StorePages;
static volatile LONG g_StoreNext;
static volatile LONG g_Overflowed;

static PMDL          g_Mdl;
static PVOID         g_MappedVa;

static UINT64        g_Base;
static UINT64        g_Size;
static BOOLEAN       g_ReadOnly;

/*
 * Read by every processor's fault handler, written by the control worker.
 * Armed last on the way up and cleared first on the way down, with a
 * SvSyncTlbFlush between clearing it and freeing anything: that call drives an
 * exit on every processor and waits for it, so once it returns no processor can
 * still be inside an exit handler that read the flag as armed.
 */
static volatile LONG g_Armed;

/*
 * Set while SvSnapshotRestore is copying pages back.
 *
 * The restore's own copies are guest-physical writes to pages this snapshot has
 * write-protected, so without this they fault into SvSnapshotSaveOnWrite, which
 * dutifully saves the *modified* page it was about to overwrite and grants
 * write permission for good.  The first restore then works and every one after
 * it silently does nothing, because the page it was watching is writable and no
 * longer being tracked.  That is exactly what happened the first time this was
 * tested, and it is invisible from the outside: the restore reports success and
 * the memory does not change.
 *
 * With the flag set the handler grants and returns without saving, so the copy
 * completes without consuming a store slot or disturbing the bookkeeping the
 * restore is in the middle of resetting.
 */
static volatile LONG g_Restoring;

/* ------------------------------------------------------------------ sort */

/*
 * Shell sort with Ciura's gaps.  The fault handler binary-searches this array,
 * so it has to be ordered by guest physical address - and an MDL hands back
 * whatever pages the range happens to occupy, in virtual order.  Insertion sort
 * would be 256 million comparisons on a full 16384-page range; this is a dozen
 * lines and finishes in the noise.
 */
static VOID SvSnapshotSort(_Inout_updates_(Count) SNAP_PAGE* Pages,
                           _In_ UINT64 Count)
{
    static const UINT64 gaps[] = { 1750, 701, 301, 132, 57, 23, 10, 4, 1 };
    ULONG g;

    for (g = 0; g < RTL_NUMBER_OF(gaps); g++)
    {
        const UINT64 gap = gaps[g];
        UINT64 i;

        if (gap >= Count)
        {
            continue;
        }

        for (i = gap; i < Count; i++)
        {
            const SNAP_PAGE value = Pages[i];
            UINT64 j = i;

            while (j >= gap && Pages[j - gap].Gpa > value.Gpa)
            {
                Pages[j] = Pages[j - gap];
                j -= gap;
            }
            Pages[j] = value;
        }
    }
}

static SNAP_PAGE* SvSnapshotFind(_In_ UINT64 Gpa)
{
    UINT64 low = 0;
    UINT64 high = g_PageCount;

    while (low < high)
    {
        const UINT64 middle = low + (high - low) / 2;
        const UINT64 gpa = g_Pages[middle].Gpa;

        if (gpa == Gpa)
        {
            return &g_Pages[middle];
        }
        if (gpa < Gpa)
        {
            low = middle + 1;
        }
        else
        {
            high = middle;
        }
    }

    return NULL;
}

/* -------------------------------------------------------------- teardown */

/*
 * Everything except the flag, which the caller has already cleared and flushed.
 * Split out because Take's failure paths need it before anything was armed.
 */
static VOID SvSnapshotTearDown(_In_ BOOLEAN RestorePermission)
{
    if (g_Pages != NULL && RestorePermission)
    {
        UINT64 i;

        for (i = 0; i < g_PageCount; i++)
        {
            UINT64* pte = SvNptSplitTo4Kb(&g_NptPrimary, g_Pages[i].Gpa);

            if (pte != NULL)
            {
                *pte |= NPT_WRITE;
            }
        }
        SvSyncTlbFlush();
    }

    if (g_Mdl != NULL)
    {
        if (g_MappedVa != NULL)
        {
            MmUnmapLockedPages(g_MappedVa, g_Mdl);
            g_MappedVa = NULL;
        }
        MmUnlockPages(g_Mdl);
        IoFreeMdl(g_Mdl);
        g_Mdl = NULL;
    }

    if (g_Store != NULL)
    {
        ExFreePoolWithTag(g_Store, SNAP_TAG);
        g_Store = NULL;
    }
    if (g_Pages != NULL)
    {
        ExFreePoolWithTag(g_Pages, SNAP_TAG);
        g_Pages = NULL;
    }

    g_PageCount = 0;
    g_StorePages = 0;
    g_StoreNext = 0;
    g_Overflowed = 0;
    g_Base = 0;
    g_Size = 0;
    g_ReadOnly = FALSE;
}

VOID SvSnapshotRelease(VOID)
{
    if (g_Armed == 0 && g_Pages == NULL)
    {
        return;
    }

    InterlockedExchange(&g_Armed, 0);

    /*
     * The barrier.  Every processor takes an exit here and is out of the fault
     * handler by the time this returns, so nothing can be holding a pointer
     * into what is about to be freed.
     */
    SvSyncTlbFlush();

    SvSnapshotTearDown(TRUE);
}

/* ------------------------------------------------------------------- arm */

NTSTATUS SvSnapshotTake(_In_ UINT64 Address, _In_ UINT64 Size,
                        _In_ UINT32 ProcessId, _In_ UINT32 StorePages)
{
    SVMHV_ATTACH attach = { 0 };
    NTSTATUS status;
    UINT64 base;
    UINT64 pages;
    UINT64 i;
    PMDL mdl = NULL;
    PVOID mapped = NULL;
    BOOLEAN attached = FALSE;
    BOOLEAN readOnly = FALSE;

    base  = Address & ~(UINT64)(PAGE_SIZE - 1);
    Size  = (Size + (Address - base) + PAGE_SIZE - 1) & ~(UINT64)(PAGE_SIZE - 1);
    pages = Size / PAGE_SIZE;

    if (pages == 0 || pages > SNAP_MAX_PAGES)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (StorePages == 0 || StorePages > pages)
    {
        StorePages = (UINT32)pages;
    }

    SvSnapshotRelease();

    if (ProcessId != 0)
    {
        status = SvMemoryAttachProcess(ProcessId, &attach);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        attached = TRUE;
    }

    mdl = IoAllocateMdl((PVOID)base, (ULONG)Size, FALSE, FALSE, NULL);
    if (mdl == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    /*
     * IoModifyAccess first, and it matters: a user range may be mapped
     * copy-on-write, and locking it for reading would leave the guest's first
     * store breaking the sharing and landing on a *different* physical page
     * from the one this snapshot pinned and protected.  Nothing would fault,
     * nothing would be saved, and the restore would put the original back into
     * a page the process had stopped looking at - a snapshot that silently did
     * nothing, which is the worst of the available failures.
     *
     * But a great many interesting ranges are not writable: any code page, and
     * anything read-only in an image.  Asking for modify access on one of those
     * fails the probe outright, which is how this first refused to snapshot
     * .text at all.  Falling back to a read lock is correct for exactly those
     * pages - a page the guest cannot write cannot break its sharing under us,
     * so the thing the modify lock was protecting against cannot happen.
     */
    __try
    {
        MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
        readOnly = FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        readOnly = TRUE;
    }

    if (readOnly)
    {
        __try
        {
            MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            IoFreeMdl(mdl);
            mdl = NULL;
            status = STATUS_INVALID_ADDRESS;
            goto done;
        }
    }

    mapped = MmGetSystemAddressForMdlSafe(
                 mdl, NormalPagePriority | MdlMappingNoExecute);
    if (mapped == NULL)
    {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        mdl = NULL;
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    status = STATUS_SUCCESS;

done:
    if (attached)
    {
        SvMemoryDetachProcess(&attach);
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    g_Mdl = mdl;
    g_MappedVa = mapped;

    g_Pages = (SNAP_PAGE*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                          (SIZE_T)pages * sizeof(SNAP_PAGE),
                                          SNAP_TAG);
    if (g_Pages == NULL)
    {
        SvSnapshotTearDown(FALSE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_Store = (UINT8*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                      (SIZE_T)StorePages * PAGE_SIZE, SNAP_TAG);
    if (g_Store == NULL)
    {
        SvSnapshotTearDown(FALSE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    g_StorePages = StorePages;
    g_StoreNext = 0;
    g_Overflowed = 0;

    for (i = 0; i < pages; i++)
    {
        PVOID va = (UINT8*)mapped + (SIZE_T)i * PAGE_SIZE;

        /*
         * Our own memory would mean the fault handler faulting on the page it
         * is servicing the fault out of.  Nothing else is refused: there is no
         * way for this to know what else on the machine cares about the range
         * it was handed, which is stated plainly in snapshot.h rather than
         * guessed at here.
         */
        if (SvIsHypervisorMemory(va))
        {
            SvSnapshotTearDown(FALSE);
            return STATUS_ACCESS_DENIED;
        }

        g_Pages[i].Gpa = (UINT64)MmGetPhysicalAddress(va).QuadPart;
        g_Pages[i].SysVa = va;
        g_Pages[i].StoreIndex = -1;
    }

    g_PageCount = pages;
    SvSnapshotSort(g_Pages, g_PageCount);

    /*
     * Split before protecting, and protect before arming, for the reason the
     * sweep does the same: by the time a fault can happen every table the
     * handler could need has to already exist, because it cannot allocate one.
     */
    for (i = 0; i < pages; i++)
    {
        UINT64* pte = SvNptSplitTo4Kb(&g_NptPrimary, g_Pages[i].Gpa);

        if (pte == NULL)
        {
            SvSnapshotTearDown(TRUE);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        *pte &= ~NPT_WRITE;
    }

    g_Base = base;
    g_Size = Size;
    g_ReadOnly = readOnly;
    InterlockedExchange(&g_Armed, 1);

    /* Nothing is protected until every processor has left the translations it
       cached before the split; see SvSyncTlbFlush. */
    SvSyncTlbFlush();
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------ fault side */

BOOLEAN SvSnapshotSaveOnWrite(_In_ UINT64 Gpa, _In_ UINT64 FaultInfo)
{
    const UINT64 page = Gpa & ~(UINT64)(PAGE_SIZE - 1);
    SNAP_PAGE* entry;
    UINT64* pte;
    LONG slot;

    if (g_Armed == 0 || (FaultInfo & NPF_WRITE) == 0)
    {
        return FALSE;
    }

    entry = SvSnapshotFind(page);
    if (entry == NULL)
    {
        return FALSE;
    }

    pte = SvNptSplitTo4Kb(&g_NptPrimary, page);
    if (pte == NULL)
    {
        return FALSE;
    }

    if (g_Restoring != 0)
    {
        /* Almost certainly the restore's own copy; see g_Restoring.  Let it
           through without saving - the page is being overwritten with the
           original anyway, so there is nothing here worth keeping. */
        *pte |= NPT_WRITE;
        return TRUE;
    }

    if ((*pte & NPT_WRITE) != 0)
    {
        /*
         * Another processor granted it between the fault and now.  The fault is
         * explained - the guest has only to re-execute - and saying otherwise
         * is what took every processor out of SVM the first time the sweep ran
         * in both modes; see the same case in SvNptSweepGrant.
         */
        return TRUE;
    }

    if (entry->StoreIndex < 0)
    {
        slot = InterlockedIncrement(&g_StoreNext) - 1;

        if (slot < 0 || (ULONG)slot >= g_StorePages)
        {
            /*
             * Out of store.  The write still has to be granted - a fault
             * nothing can satisfy is a livelock, and this handler has no way to
             * retire the store itself - so the page is let through and the
             * snapshot is marked as no longer describing a state the guest was
             * ever in.  SvSnapshotRestore refuses afterwards rather than
             * putting back a mixture of two runs.
             */
            InterlockedExchange(&g_Overflowed, 1);
        }
        else if (InterlockedCompareExchange(&entry->StoreIndex, slot, -1) == -1)
        {
            RtlCopyMemory(g_Store + (SIZE_T)slot * PAGE_SIZE,
                          entry->SysVa, PAGE_SIZE);
        }
        /*
         * Lost the race for this page: the other processor is copying the same
         * original out of the same page, so the slot we reserved is simply
         * abandoned.  Bounded by the number of processors, and cheaper than a
         * lock in a path that runs with GIF clear.
         */
    }

    *pte |= NPT_WRITE;
    return TRUE;
}

/* --------------------------------------------------------------- restore */

NTSTATUS SvSnapshotRestore(_Out_ UINT64* Restored)
{
    UINT64 i;
    UINT64 count = 0;

    *Restored = 0;

    if (g_Armed == 0 || g_Pages == NULL)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (g_Overflowed != 0)
    {
        return STATUS_BUFFER_OVERFLOW;
    }

    /*
     * Our own copies are writes to protected pages, so tell the fault handler
     * to let them through untracked for the duration; see g_Restoring.
     */
    InterlockedExchange(&g_Restoring, 1);

    for (i = 0; i < g_PageCount; i++)
    {
        const LONG slot = g_Pages[i].StoreIndex;
        UINT64* pte;

        if (slot < 0)
        {
            continue;
        }

        /* Grant it here as well as in the handler.  A processor whose cached
           translation is already writable will not fault at all, and one whose
           is not will fault into the handler and be granted there; both have to
           end up writing the page rather than looping on it. */
        pte = SvNptSplitTo4Kb(&g_NptPrimary, g_Pages[i].Gpa);
        if (pte != NULL)
        {
            *pte |= NPT_WRITE;
        }

        RtlCopyMemory(g_Pages[i].SysVa, g_Store + (SIZE_T)slot * PAGE_SIZE,
                      PAGE_SIZE);
        count++;
    }

    /*
     * Re-arm: protect the whole range again, not just what was dirty.  The
     * clean pages are already protected and rewriting the bit costs nothing,
     * and doing all of them is what makes this identical to the state
     * SvSnapshotTake leaves behind - so a restore can be followed by another
     * run and another restore, indefinitely.
     */
    for (i = 0; i < g_PageCount; i++)
    {
        UINT64* pte = SvNptSplitTo4Kb(&g_NptPrimary, g_Pages[i].Gpa);

        if (pte != NULL)
        {
            *pte &= ~NPT_WRITE;
        }
        InterlockedExchange(&g_Pages[i].StoreIndex, -1);
    }

    /* The store is empty again, so the whole capacity is available next time. */
    InterlockedExchange(&g_StoreNext, 0);

    /*
     * Clear the flag before the flush, not after.  A write that slips through
     * on a stale writable translation during the flush is one page's worth of
     * lost tracking that the next fault corrects; a fault taken while the flag
     * is still set would be granted permanently and never tracked again.
     */
    InterlockedExchange(&g_Restoring, 0);
    SvSyncTlbFlush();

    *Restored = count;
    return STATUS_SUCCESS;
}

VOID SvSnapshotState(_Out_ ULONG* State, _Out_ UINT64* Base, _Out_ UINT64* Size,
                     _Out_ UINT64* Dirty, _Out_ UINT64* Capacity)
{
    const LONG used = InterlockedCompareExchange(&g_StoreNext, 0, 0);

    *State = (g_Armed == 0) ? SVMHV_SNAP_IDLE
           : (g_Overflowed != 0) ? SVMHV_SNAP_OVERFLOWED : SVMHV_SNAP_ARMED;
    if (g_Armed != 0 && g_ReadOnly)
    {
        *State |= SVMHV_SNAP_READ_ONLY;
    }
    *Base = g_Base;
    *Size = g_Size;
    *Dirty = (used < 0) ? 0 : (UINT64)used;
    *Capacity = g_StorePages;
}
