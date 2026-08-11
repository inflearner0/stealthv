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
 * How often this thread looks at the doorbell, in 100 ns units.
 *
 * The idle interval is the wrong one for a client that is working, and it is
 * wrong by a lot.  A client submits, waits for Completed, submits again - and
 * by then this thread is back in a 100 ms wait, so every command costs about
 * fifty milliseconds of nothing happening.  For somebody typing that is
 * invisible.  For a client instrumenting a driver it is the difference between
 * a tool you drive and one you batch: "hook every Nt* entry point" is a couple
 * of hundred commands, and this hypervisor exists to be driven that way.
 *
 * Measured in the lab at 100 ms idle: 200 commands took 21.5 seconds, of which
 * 21 seconds was this thread asleep.
 *
 * Three cadences, because there are three situations:
 *
 *   burst    A spin, for the few milliseconds right after a command, in case
 *            the client is one process issuing several in a row.  No timer is
 *            fast enough for that - a relative wait is rounded up to the system
 *            clock tick, which is 15.6 ms unless something has raised the
 *            resolution, and raising it globally is both rude and visible.
 *
 *   active   A 1 ms timer for two seconds after the last command.  This is the
 *            one that matters for svmhvctl.exe, which is a *new process* per
 *            command and takes about seven milliseconds to start - far longer
 *            than any affordable spin, and far shorter than the idle interval.
 *
 *   idle     100 ms, the original, once nothing has asked for anything for two
 *            seconds.  Ten wakeups a second, on a timer, as before.
 */
#define CONTROL_IDLE_INTERVAL       (100 * 10 * 1000)   /* 100 ms            */
#define CONTROL_ACTIVE_INTERVAL     (1 * 10 * 1000)     /* 1 ms              */
#define CONTROL_ACTIVE_WINDOW       (2 * 1000 * 10 * 1000) /* 2 s            */
#define CONTROL_BURST_STALL_US      50
#define CONTROL_BURST_STALLS        40

/*
 * The snapshot and the runaway detector stay on the idle cadence whatever the
 * loop above is doing.  Both are far more expensive than looking at a doorbell
 * - a refresh copies the whole hook table - and the detector is a *rate*, so
 * running it every millisecond would shrink its window a hundredfold and no
 * hook on earth would trip a twenty-thousand threshold in one millisecond.
 */
#define CONTROL_REFRESH_INTERVAL    CONTROL_IDLE_INTERVAL

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

    /* The executable memory hook.c hands out - trampolines, stubs, the patched
       shadow copies - comes from its own allocator and is in none of the ranges
       SvOwnsPage knows about.  Watching a trampoline means faulting inside the
       handler that services the fault. */
    if (SvHookOwnsPage(Address))
    {
        return TRUE;
    }

    /* The trace ring is pool, so it is not in any of the ranges above. */
    SvTraceDescribeRing(&ring, &produced, &records, &recordSize);
    if (ring != 0)
    {
        const UINT8* base = (const UINT8*)PAGE_ALIGN((PVOID)ring);
        /* Rounded up, to match the page-aligned base: the ring's last page is
           usually a partial one, and comparing an aligned start against an
           unaligned end let a watch be installed on it. */
        const UINT8* end  = (const UINT8*)PAGE_ALIGN(
                                (PVOID)(ring + records * recordSize +
                                        PAGE_SIZE - 1));

        if (page >= base && page < end)
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

/*
 * The worker is the sole snapshot writer.  The trailing sequence is therefore
 * a compact seqlock: odd says a refresh is in progress, even says every field
 * preceding it belongs to one coherent publication.  Readers use it before and
 * after their 48-byte hypercall windows.
 */
static VOID SvSnapshotBeginUpdate(VOID)
{
    InterlockedIncrement64((volatile LONG64*)&g_Snapshot.PublishSequence);
    KeMemoryBarrier();
}

static VOID SvSnapshotEndUpdate(VOID)
{
    KeMemoryBarrier();
    InterlockedIncrement64((volatile LONG64*)&g_Snapshot.PublishSequence);
}

static VOID SvControlRefresh(VOID)
{
    SvSnapshotBeginUpdate();
    g_Snapshot.Tsc = __rdtsc();
    g_Snapshot.Refreshes++;

    SvFillStats(&g_Snapshot.Stats);
    SvFillExitHistogram(&g_Snapshot.Histogram);
    SvHookList(&g_Snapshot.Hooks);
    SvFillFatalExit(&g_Snapshot.Fatal);
    SvSnapshotEndUpdate();
}

/*
 * Say out loud that an exit could not be handled.
 *
 * This is the other half of SvRecordFatalExit, and the reason it is here rather
 * than there: the recording happens in the exit handler with GIF clear, where
 * DbgPrint is not something to be attempting, and the reporting happens on this
 * thread at PASSIVE_LEVEL where it is ordinary.  Between them they replace a
 * KeBugCheckEx raised from a context that could not have written a dump.
 *
 * The processor named here has left SVM and will not go back on its own.  That
 * is the intended outcome - the machine keeps running and the evidence survives
 * - but it does mean the hypervisor is no longer covering every processor, so
 * it is worth being loud about.
 */
static VOID SvControlReportFatalExit(VOID)
{
    static const char* const reasons[] =
    {
        "none", "guest triple fault (VMEXIT_SHUTDOWN)", "unhandled exit code",
        "#NPF on an unmapped page", "#NPF retry limit"
    };
    SVMHV_FATAL_EXIT fatal;
    const char* reason;

    if (!SvTakeFatalExitReport(&fatal))
    {
        return;
    }

    reason = (fatal.Reason < RTL_NUMBER_OF(reasons)) ? reasons[fatal.Reason]
                                                     : "unknown";

    DbgPrint("svmhv: FATAL EXIT #%llu on cpu %lu: %s\n"
             "svmhv:   exitcode %llx info1 %llx info2 %llx exitintinfo %llx\n"
             "svmhv:   rip %llx rsp %llx cr2 %llx cr3 %llx\n"
             "svmhv:   that processor has left SVM and is running natively\n",
             fatal.Count, fatal.Processor, reason,
             fatal.ExitCode, fatal.ExitInfo1, fatal.ExitInfo2, fatal.ExitIntInfo,
             fatal.Rip, fatal.Rsp, fatal.Cr2, fatal.Cr3);
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
    {
        SVMHV_SELFTEST selfTest;

        SvRunSelfTest(&selfTest);
        SvSnapshotBeginUpdate();
        g_Snapshot.SelfTest = selfTest;
        SvSnapshotEndUpdate();
        return STATUS_SUCCESS;
    }

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

    case SVMHV_CMD_CALLBACK_PROBE:
        return SvObjectsCallbackProbe(&g_Control.Request);

    /*
     * Answers with the number of processors that came back, in the memory
     * return field - a partial result is the interesting one, and it is not
     * something a status code could carry.
     */
    case SVMHV_CMD_POWER_CYCLE:
        g_Control.Request.MemoryReturned = SvCyclePowerTransition();
        return STATUS_SUCCESS;

    default:
        return STATUS_INVALID_DEVICE_REQUEST;
    }
}

static VOID SvControlWorker(_In_ PVOID Context)
{
    LARGE_INTEGER interval;
    ULONG64 lastCommand = 0;
    ULONG64 lastRefresh = 0;
    ULONG burst = 0;

    UNREFERENCED_PARAMETER(Context);

    while (g_Stopping == 0)
    {
        const ULONG64 now = KeQueryInterruptTime();
        const UINT64 sequence = *(volatile UINT64*)&g_Control.Sequence;
        const BOOLEAN active = ((now - lastCommand) < CONTROL_ACTIVE_WINDOW);

        g_Control.Polls++;

        if ((now - lastRefresh) >= CONTROL_REFRESH_INTERVAL)
        {
            lastRefresh = now;
            SvControlRefresh();
            SvControlDisarmRunaways();
        }
        SvControlReportFatalExit();

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

            /* A client that sent one command is very likely about to send
               another; see the cadences above. */
            lastCommand = KeQueryInterruptTime();
            burst = CONTROL_BURST_STALLS;
            continue;                   /* do not sleep on a busy client */
        }

        /*
         * The burst spin.  It looks at the doorbell and nothing else, which is
         * the point - it has to be cheap enough to be worth doing for two
         * milliseconds.
         *
         * Read through a volatile pointer: nothing in this loop is a compiler
         * barrier, so a plain read of the field could be hoisted out and the
         * loop would spin on a stale register forever.
         */
        while (burst != 0 && g_Stopping == 0 &&
               *(volatile UINT64*)&g_Control.Sequence == g_Control.Completed)
        {
            burst--;
            KeStallExecutionProcessor(CONTROL_BURST_STALL_US);
        }
        if (*(volatile UINT64*)&g_Control.Sequence != g_Control.Completed)
        {
            continue;
        }

        /* Negative means relative, in 100 ns units. */
        interval.QuadPart = active ? -(LONGLONG)CONTROL_ACTIVE_INTERVAL
                                   : -(LONGLONG)CONTROL_IDLE_INTERVAL;
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
    g_Snapshot.PublishSequence = 2;       /* initial stable, non-zero state */

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
