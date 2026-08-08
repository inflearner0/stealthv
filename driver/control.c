/*
 * control.c - the doorbell and its worker thread.  See control.h.
 */

#include "control.h"
#include "svmhv.h"
#include "hook.h"
#include "trace.h"
#include "memory.h"
#include "objects.h"

/*
 * Both are ordinary driver globals on purpose: a client resolves svmhv!g_Control
 * from the symbol file and everything else is reachable from the addresses it
 * publishes.  Aligned so a debugger writing 64-bit fields never straddles a
 * cache line that the worker is reading.
 */
DECLSPEC_ALIGN(64) SVMHV_CONTROL  g_Control;
DECLSPEC_ALIGN(64) SVMHV_SNAPSHOT g_Snapshot;

static PKTHREAD      g_Worker;
static volatile LONG g_Stopping;
static KEVENT        g_StopEvent;

/*
 * 100 ms.  Fast enough that a command feels immediate to somebody typing, slow
 * enough that the wakeups are invisible in the exit counters - and this is a
 * timer wait, so the processor is not being spun.
 */
#define CONTROL_POLL_INTERVAL_MS    100

/*
 * The pages a watchpoint must never be pointed at: this driver's own working
 * memory.  See the refusal in SvHookInstall for why.
 */
BOOLEAN SvIsHypervisorMemory(_In_ PVOID Address)
{
    const UINT8* page = (const UINT8*)PAGE_ALIGN(Address);
    UINT64 ring;
    UINT64 produced;
    UINT64 records;
    UINT64 recordSize;

    /*
     * The image covers g_Control and g_Snapshot along with every other global
     * this driver has - the hook table above all, which the fault handler reads
     * on every nested page fault and which used not to be covered here at all.
     */
    if (SvOwnsPage(Address))
    {
        return TRUE;
    }

    /* The trace ring is pool, so it is not in any of the ranges above. */
    SvTraceDescribeRing(&ring, &produced, &records, &recordSize);
    if (ring != 0)
    {
        const UINT8* base = (const UINT8*)PAGE_ALIGN((PVOID)ring);
        if (page >= base && page < (const UINT8*)ring + records * recordSize)
        {
            return TRUE;
        }
    }

    return FALSE;
}

/*
 * A watchpoint that fires thousands of times a second does not just cost
 * performance, it can starve the guest badly enough that the debugger loses the
 * target - and the debugger is the only way to take the watch off again.  So the
 * worker keeps an eye on the rate and disarms anything running away.
 *
 * The threshold is per poll interval, so it is a rate: a watch on genuinely busy
 * memory trips it within a tenth of a second, while a hook on an ordinary
 * function never comes close.
 */
#define CONTROL_RUNAWAY_HITS_PER_POLL   20000

/*
 * The same idea for execution hooks, which the rule above cannot see.
 *
 * It watches the trace ring, and a hook that detours or runs shellcode
 * produces no records at all - it never reaches the recorder.  So a shellcode
 * hook on a busy function is invisible to it, and busy is easy to hit by
 * accident: hooking anything in the file path means every read the control
 * agent does goes through it, and the agent is what would take the hook off.
 *
 * Nested page faults are the signal that does cover them.  Every entry into a
 * hooked page and every exit is one switch, so this counts what the mechanism
 * actually costs regardless of what the hook then does.  200 000 a second is
 * far past useful and roughly ten times what a hook on a genuinely busy
 * function produces.
 *
 * Learned the hard way: a shellcode hook on a filter-manager path slowed the
 * guest until the agent could no longer answer, which is the same shape as the
 * watch problem this file already guarded against - and the guard did not
 * apply.
 */
#define CONTROL_RUNAWAY_SWITCHES_PER_POLL   20000

static UINT64 g_LastTraceRecords;
static UINT64 g_LastHookSwitches;

static VOID SvControlDisarmRunaways(VOID)
{
    const UINT64 records = g_Snapshot.Stats.TraceRecords;
    const UINT64 switches = g_Snapshot.Stats.HookSwitches;
    const UINT64 recordDelta = records - g_LastTraceRecords;
    const UINT64 switchDelta = switches - g_LastHookSwitches;
    const BOOLEAN watchRunaway = (recordDelta >= CONTROL_RUNAWAY_HITS_PER_POLL);
    const BOOLEAN execRunaway =
        (switchDelta >= CONTROL_RUNAWAY_SWITCHES_PER_POLL);
    ULONG i;

    g_LastTraceRecords = records;
    g_LastHookSwitches = switches;

    if (!watchRunaway && !execRunaway)
    {
        return;
    }

    for (i = 0; i < g_Snapshot.Hooks.Count; i++)
    {
        const SVMHV_HOOK_INFO* hook = &g_Snapshot.Hooks.Hooks[i];

        if (hook->Active == 0)
        {
            continue;
        }

        if (hook->Kind != SVMHV_HOOK_EXEC && watchRunaway)
        {
            DbgPrint("svmhv: disarming runaway %s watch on %llx "
                     "(%llu hits in one interval)\n",
                     (hook->Kind == SVMHV_HOOK_WRITE) ? "write" : "access",
                     hook->Target, recordDelta);
            (VOID)SvHookRemove((PVOID)hook->Target);
        }
        else if (hook->Kind == SVMHV_HOOK_EXEC && execRunaway)
        {
            /*
             * Every armed execution hook goes, not the worst one: there is no
             * per-hook switch count to pick by, and by the time this fires the
             * machine is too slow to be choosy on.
             */
            DbgPrint("svmhv: disarming runaway hook on %llx "
                     "(%llu page switches in one interval)\n",
                     hook->Target, switchDelta);
            (VOID)SvHookRemove((PVOID)hook->Target);
        }
    }
}

/* ------------------------------------------------------------- snapshot */

static VOID SvControlRefresh(VOID)
{
    g_Snapshot.Tsc = __rdtsc();
    g_Snapshot.Refreshes++;

    SvFillStats(&g_Snapshot.Stats);
    SvFillExitHistogram(&g_Snapshot.Histogram);
    SvHookList(&g_Snapshot.Hooks);
}

/* -------------------------------------------------------------- commands */

static NTSTATUS SvControlExecute(_In_ UINT32 Command)
{
    switch (Command)
    {
    case SVMHV_CMD_HOOK_INSTALL:
        return SvHookInstall(&g_Control.Request);

    case SVMHV_CMD_HOOK_REMOVE:
        return SvHookRemove((PVOID)g_Control.Request.Target);

    case SVMHV_CMD_SELFTEST:
        SvRunSelfTest(&g_Snapshot.SelfTest);
        return STATUS_SUCCESS;

    case SVMHV_CMD_TRACE_RESET:
        SvTraceReset();
        return STATUS_SUCCESS;

    /* All three run here rather than in the exit handler: see memory.h. */
    case SVMHV_CMD_READ_MEMORY:
        return SvMemoryRead(&g_Control.Request);

    case SVMHV_CMD_WRITE_MEMORY:
        return SvMemoryWrite(&g_Control.Request);

    case SVMHV_CMD_READ_PHYSICAL:
        return SvMemoryReadPhysical(&g_Control.Request);

    case SVMHV_CMD_DRIVER_OBJECT:
        return SvMemoryDriverObject(&g_Control.Request);

    case SVMHV_CMD_WRITE_PHYSICAL:
        return SvMemoryWritePhysical(&g_Control.Request);

    case SVMHV_CMD_TRANSLATE:
        return SvMemoryTranslate(&g_Control.Request);

    case SVMHV_CMD_DEVICES:
        return SvObjectsDevices(&g_Control.Request);

    case SVMHV_CMD_SYMLINKS:
        return SvObjectsSymbolicLinks(&g_Control.Request);

    default:
        return STATUS_INVALID_DEVICE_REQUEST;
    }
}

static VOID SvControlWorker(_In_ PVOID Context)
{
    LARGE_INTEGER interval;

    UNREFERENCED_PARAMETER(Context);

    /* Negative means relative, in 100 ns units. */
    interval.QuadPart = -(LONGLONG)CONTROL_POLL_INTERVAL_MS * 10 * 1000;

    while (g_Stopping == 0)
    {
        const UINT64 sequence = g_Control.Sequence;

        g_Control.Polls++;
        SvControlRefresh();
        SvControlDisarmRunaways();

        if (sequence != g_Control.Completed)
        {
            const UINT32 command = g_Control.Command;

            /*
             * Status first, Completed last: a client that sees Completed catch
             * up is entitled to assume everything else it might read - Status,
             * and the request's output fields - is already there.
             */
            g_Control.Status = (INT32)SvControlExecute(command);
            SvControlRefresh();

            InterlockedExchange64((volatile LONG64*)&g_Control.Completed,
                                  (LONG64)sequence);

            DbgPrint("svmhv: control command %u -> %08X\n", command,
                     g_Control.Status);
            continue;                   /* do not sleep on a busy client */
        }

        (VOID)KeWaitForSingleObject(&g_StopEvent, Executive, KernelMode, FALSE,
                                    &interval);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

/* ------------------------------------------------------------ lifecycle */

NTSTATUS SvControlStart(VOID)
{
    HANDLE handle = NULL;
    NTSTATUS status;

    RtlZeroMemory(&g_Control, sizeof(g_Control));
    RtlZeroMemory(&g_Snapshot, sizeof(g_Snapshot));

    KeInitializeEvent(&g_StopEvent, NotificationEvent, FALSE);
    g_Stopping = 0;

    g_Control.Version             = SVMHV_CONTROL_VERSION;
    g_Control.SnapshotAddress     = (UINT64)&g_Snapshot;
    SvTraceDescribeRing(&g_Control.TraceRingAddress,
                        &g_Control.TraceProducedAddress,
                        &g_Control.TraceRingRecords,
                        &g_Control.TraceRecordSize);
    g_Control.NptPrimaryPml4      = (UINT64)g_NptPrimary.Pml4;
    g_Control.NptShadowPml4       = (UINT64)g_NptShadow.Pml4;
    g_Control.NptCoverage         = SvNptCoverage();

    /* Published last: until the magic is there, nothing above is to be trusted. */
    g_Control.Magic = SVMHV_CONTROL_MAGIC;

    status = PsCreateSystemThread(&handle, THREAD_ALL_ACCESS, NULL, NULL, NULL,
                                  SvControlWorker, NULL);
    if (!NT_SUCCESS(status))
    {
        g_Control.Magic = 0;
        return status;
    }

    status = ObReferenceObjectByHandle(handle, THREAD_ALL_ACCESS, NULL,
                                       KernelMode, (PVOID*)&g_Worker, NULL);
    ZwClose(handle);

    if (!NT_SUCCESS(status))
    {
        /* The thread is running but unreferenced; stop it the same way. */
        g_Worker = NULL;
        SvControlStop();
        return status;
    }

    DbgPrint("svmhv: control block at %p, snapshot at %p\n",
             &g_Control, &g_Snapshot);
    return STATUS_SUCCESS;
}

VOID SvControlStop(VOID)
{
    g_Control.Magic = 0;

    InterlockedExchange(&g_Stopping, 1);
    KeSetEvent(&g_StopEvent, IO_NO_INCREMENT, FALSE);

    if (g_Worker != NULL)
    {
        (VOID)KeWaitForSingleObject(g_Worker, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(g_Worker);
        g_Worker = NULL;
    }
}
