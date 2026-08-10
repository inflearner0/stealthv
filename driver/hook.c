/*
 * hook.c - nested-paging hooks and watchpoints.  See hook.h for the design.
 */

#include "hook.h"
#include "trace.h"
#include "svmhv.h"
#include "control.h"    /* SvIsHypervisorMemory: what a watch may not touch */
#include "memory.h"     /* SvMemoryAttachProcess: user-mode targets        */

typedef struct _SVM_HOOK
{
    volatile LONG Active;
    UINT32  Kind;               /* SVMHV_HOOK_*                             */
    UINT32  Action;             /* SVMHV_ACTION_*                           */
    UINT64  Gpa;                /* page-aligned guest physical of the page   */
    PVOID   PageVa;             /* page-aligned virtual of the same page     */
    PVOID   TargetVa;
    PVOID   DetourVa;           /* where the patched page jumps to          */
    PVOID   ShadowVa;           /* patched copy of the whole page (EXEC)     */
    UINT64  ShadowPa;
    PVOID   Trampoline;         /* original prologue + jump back            */
    PVOID   ShellcodePage;      /* ACTION_SHELLCODE                          */
    PMDL    Mdl;                /* keeps the target page resident           */

    /*
     * Non-zero when the target is a user-mode address, and the reason the MDL
     * above has to be treated completely differently.
     *
     * A kernel page never goes away, so pinning it for the life of the driver
     * costs nothing and lets install-and-remove reuse everything.  A user page
     * belongs to a process, and a process cannot exit while somebody holds its
     * pages locked - Windows bugchecks 0x76, PROCESS_HAS_LOCKED_PAGES, naming
     * the count of pages still locked.  That is not theoretical: it is what
     * this driver did the first time a user-mode watch was tested and the
     * target was closed afterwards.
     *
     * So a user hook's MDL is released the moment the hook is removed, and a
     * process-exit notification removes any hook still on a process that is
     * going away.
     */
    UINT32  TargetProcessId;

    /*
     * TRUE if this record owns the page's shared resources - the MDL, the
     * shadow copy and the two page table entry pointers.  Several execution
     * hooks may sit in one page; the first one to arrive owns them and the
     * rest borrow, so only the owner may free them and only the last hook to
     * leave the page may put its mappings back.
     */
    BOOLEAN OwnsPage;
    UINT64* PrimaryPte;
    UINT64* ShadowPte;
    ULONG   PrologLength;
    volatile LONG64 Hits;
    ULONG   FilterCount;
    ULONG   CaptureCount;
    ULONG   SpoofCount;
    SVMHV_FILTER Filters[SVMHV_MAX_FILTERS];
    SVMHV_CAPTURE Captures[SVMHV_MAX_CAPTURES];
    SVMHV_SPOOF Spoofs[SVMHV_MAX_SPOOFS];
    BOOLEAN CaptureReturn;
    BOOLEAN CaptureStack;
    char    ProcessName[SVMHV_PROCESS_NAME_MAX];
    PVOID   BlockStub;          /* mov rax, imm64; ret - when blocking      */
    UINT64  BlockValue;         /* what that stub was built to return       */
    ULONG   TrampolineCapacity; /* bytes reserved, so a re-arm can reuse it */
    UINT8   OriginalProlog[SVMHV_MAX_PROLOG];
} SVM_HOOK;

static SVM_HOOK       g_Hooks[SVMHV_MAX_HOOKS];
static KGUARDED_MUTEX g_HookLock;

/* One page of executable memory, bump-allocated for trampolines and stubs. */
static UINT8* g_TrampolinePage;
static ULONG  g_TrampolineUsed;

/* ---------------------------------------------------------- page index */

/*
 * What the nested page fault handler looks a guest physical address up in.
 *
 * It used to walk all SVMHV_MAX_HOOKS records on every fault, with GIF clear,
 * comparing a page number against 256 entries most of which are empty.  That is
 * affordable for a handful of hooks and is exactly the wrong shape for what this
 * driver is for - instrumenting everything at once - because the cost of the
 * scan is paid by every fault, including all the hooks that did not match.
 *
 * One entry per hooked *page*, sorted, so the handler binary searches it.
 * Several execution hooks can share a page and they necessarily agree about
 * what kind it is, so the first of them stands for all of them; the handler only
 * needs to know that the page traps and why.
 *
 * Two buffers, published by an exchange.  The buffer being replaced is the one
 * the handler stopped reading a generation ago, and a rebuild can only follow
 * the previous one through SvSyncTlbFlush, which does not return until every
 * processor has left guest mode - so nothing can still be inside the old one.
 */
typedef struct _SVM_HOOK_PAGE_ENTRY
{
    UINT64 Gpa;
    UINT32 HookId;
    UINT32 Kind;
} SVM_HOOK_PAGE_ENTRY;

typedef struct _SVM_HOOK_PAGE_INDEX
{
    ULONG Count;
    SVM_HOOK_PAGE_ENTRY Entries[SVMHV_MAX_HOOKS];
} SVM_HOOK_PAGE_INDEX;

static SVM_HOOK_PAGE_INDEX g_PageIndex[2];
static volatile LONG       g_PageIndexActive;

/* Caller holds g_HookLock. */
static VOID SvHookRebuildPageIndex(VOID)
{
    const LONG next = 1 - g_PageIndexActive;
    SVM_HOOK_PAGE_INDEX* index = &g_PageIndex[next];
    ULONG count = 0;
    ULONG i;

    for (i = 0; i < SVMHV_MAX_HOOKS; i++)
    {
        const SVM_HOOK* hook = &g_Hooks[i];
        ULONG at;

        if (hook->Active == 0)
        {
            continue;
        }

        /* Insertion sort by GPA; 256 entries at PASSIVE_LEVEL on an operation
           that already broadcasts an IPI is not worth being clever about. */
        for (at = 0; at < count && index->Entries[at].Gpa < hook->Gpa; at++)
        {
            /* find the slot */
        }
        if (at < count && index->Entries[at].Gpa == hook->Gpa)
        {
            continue;               /* another hook in a page already listed */
        }

        RtlMoveMemory(&index->Entries[at + 1], &index->Entries[at],
                      (count - at) * sizeof(index->Entries[0]));
        index->Entries[at].Gpa    = hook->Gpa;
        index->Entries[at].HookId = i;
        index->Entries[at].Kind   = hook->Kind;
        count++;
    }

    index->Count = count;

    /* Published last, and with an interlocked write so the entries above are
       certainly visible to a handler that sees the new selector. */
    InterlockedExchange(&g_PageIndexActive, next);
}

/* ------------------------------------------------------------ executable */

PVOID SvHookAllocateExecutable(_In_ SIZE_T Size)
{
    PHYSICAL_ADDRESS lowest;
    PHYSICAL_ADDRESS highest;
    PHYSICAL_ADDRESS boundary;

    lowest.QuadPart   = 0;
    highest.QuadPart  = MAXULONG64;
    boundary.QuadPart = 0;

    return MmAllocateContiguousNodeMemory(Size, lowest, highest, boundary,
                                          PAGE_EXECUTE_READWRITE, MM_ANY_NODE_OK);
}

VOID SvHookFreeExecutable(_In_ PVOID Va)
{
    MmFreeContiguousMemory(Va);
}

/* ------------------------------------------------------------ lifecycle */

/*
 * A process going away takes its pages with it, and it cannot go anywhere while
 * we hold one locked.  Unhooking here is not tidiness - it is the difference
 * between the target closing normally and the machine bugchecking 0x76 as it
 * tries to.
 *
 * Runs at PASSIVE_LEVEL in the context of the exiting process, which is exactly
 * where SvHookRemove needs to be.
 */
static VOID SvHookProcessNotify(_In_ HANDLE ParentId, _In_ HANDLE ProcessId,
                                _In_ BOOLEAN Create)
{
    const UINT32 pid = (UINT32)(ULONG_PTR)ProcessId;
    ULONG i;

    UNREFERENCED_PARAMETER(ParentId);

    if (Create)
    {
        return;
    }

    for (i = 0; i < SVMHV_MAX_HOOKS; i++)
    {
        PVOID target;

        /* Read the target before dropping into SvHookRemove, which takes the
           lock this loop deliberately does not hold. */
        if (g_Hooks[i].Active == 0 || g_Hooks[i].TargetProcessId != pid)
        {
            continue;
        }
        target = g_Hooks[i].TargetVa;
        if (target == NULL)
        {
            continue;
        }

        DbgPrint("svmhv: process %lu is exiting with hook %lu still on it; "
                 "removing\n", pid, i);
        (VOID)SvHookRemove(target);
    }
}

/*
 * Whether the notification above is actually registered.
 *
 * Both directions of this matter.  Unregistering one that was never registered
 * asks the kernel to take a callback out of a list it is not in; registering
 * and then failing initialisation leaves a callback pointing into a driver that
 * is about to be unloaded, which is a call into freed code the next time any
 * process on the machine exits.  The second of those is not hypothetical - the
 * early-return below used to do exactly that.
 */
static BOOLEAN g_ProcessNotifyRegistered;

NTSTATUS SvHookInitialize(VOID)
{
    NTSTATUS status;

    KeInitializeGuardedMutex(&g_HookLock);
    RtlZeroMemory(g_Hooks, sizeof(g_Hooks));

    /*
     * Registered unconditionally, because a user-mode hook can be installed at
     * any time and there is no second chance to notice the process leaving.
     */
    status = PsSetCreateProcessNotifyRoutine(SvHookProcessNotify, FALSE);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("svmhv: no process-exit notification (%08X); user-mode hooks "
                 "will not be safe\n", status);
        return status;
    }
    g_ProcessNotifyRegistered = TRUE;

    g_TrampolinePage = (UINT8*)SvHookAllocateExecutable(PAGE_SIZE);
    if (g_TrampolinePage == NULL)
    {
        /* Every failure from here on has to take the callback back out first. */
        (VOID)PsSetCreateProcessNotifyRoutine(SvHookProcessNotify, TRUE);
        g_ProcessNotifyRegistered = FALSE;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* int3 everywhere, so a miscomputed jump target faults instead of
       wandering into whatever was in the page before. */
    RtlFillMemory(g_TrampolinePage, PAGE_SIZE, 0xCC);
    g_TrampolineUsed = 0;

    return STATUS_SUCCESS;
}

/*
 * Called after every processor has left guest mode, so the nested page tables
 * are no longer live and the shadow pages cannot be in use.
 */
VOID SvHookCleanup(VOID)
{
    ULONG i;

    /* Before anything is freed: the callback reaches into g_Hooks.  Only if it
       is actually registered - see g_ProcessNotifyRegistered. */
    if (g_ProcessNotifyRegistered)
    {
        (VOID)PsSetCreateProcessNotifyRoutine(SvHookProcessNotify, TRUE);
        g_ProcessNotifyRegistered = FALSE;
    }

    for (i = 0; i < SVMHV_MAX_HOOKS; i++)
    {
        SVM_HOOK* hook = &g_Hooks[i];

        if (hook->Mdl != NULL && hook->OwnsPage)
        {
            MmUnlockPages(hook->Mdl);
            IoFreeMdl(hook->Mdl);
        }
        hook->Mdl = NULL;
        /* Borrowed shadow pages point at the owner's copy; freeing one from
           every record that shares it would free it several times over. */
        if (hook->ShadowVa != NULL && hook->OwnsPage)
        {
            MmFreeContiguousMemory(hook->ShadowVa);
        }
        hook->ShadowVa = NULL;
        if (hook->ShellcodePage != NULL)
        {
            SvHookFreeExecutable(hook->ShellcodePage);
            hook->ShellcodePage = NULL;
        }
        hook->Active = 0;
    }

    /* Nothing is virtualised by the time this runs, so nobody is reading the
       index - but leaving it describing freed records would be a trap for
       anyone who changes that ordering later. */
    RtlZeroMemory(g_PageIndex, sizeof(g_PageIndex));
    g_PageIndexActive = 0;

    if (g_TrampolinePage != NULL)
    {
        SvHookFreeExecutable(g_TrampolinePage);
        g_TrampolinePage = NULL;
    }
}

/* -------------------------------------------------------------- lookup */

BOOLEAN SvHookFindPage(_In_ UINT64 Gpa, _Out_ SVM_HOOK_PAGE* Page)
{
    const UINT64 page = Gpa & ~(UINT64)(PAGE_SIZE - 1);
    const SVM_HOOK_PAGE_INDEX* index = &g_PageIndex[g_PageIndexActive];
    ULONG low = 0;
    ULONG high = index->Count;

    Page->Found = FALSE;
    Page->HookId = 0;
    Page->Kind = 0;

    while (low < high)
    {
        const ULONG middle = low + (high - low) / 2;
        const SVM_HOOK_PAGE_ENTRY* entry = &index->Entries[middle];

        if (entry->Gpa == page)
        {
            Page->Found  = TRUE;
            Page->HookId = entry->HookId;
            Page->Kind   = entry->Kind;
            return TRUE;
        }
        if (entry->Gpa < page)
        {
            low = middle + 1;
        }
        else
        {
            high = middle;
        }
    }

    return FALSE;
}

/* How many hooks are currently armed in one guest physical page. */
static ULONG SvHookPageActiveCount(_In_ UINT64 Gpa)
{
    ULONG count = 0;
    ULONG i;

    for (i = 0; i < SVMHV_MAX_HOOKS; i++)
    {
        if (g_Hooks[i].Active != 0 && g_Hooks[i].Gpa == Gpa)
        {
            count++;
        }
    }

    return count;
}

/*
 * Executable memory this file owns, which a watchpoint must never be pointed at.
 *
 * SvOwnsPage covers the driver image, the per-processor state and the nested
 * page tables, and missed all of this: the trampolines and stubs, the patched
 * shadow copies, and any shellcode page a caller supplied.  Watching one of
 * them means the fault handler faults on the very code it is running to service
 * the fault - the machine survives it, but only just, and the interface that
 * could take the watch off again is the thing being starved.
 *
 * Deliberately lock-free.  It is a refusal check on a path that may already
 * hold g_HookLock, and a stale answer is no worse than the check not existing;
 * taking the lock here would be a self-deadlock waiting for a caller to find.
 */
BOOLEAN SvHookOwnsPage(_In_ PVOID Address)
{
    const UINT8* page = (const UINT8*)PAGE_ALIGN(Address);
    ULONG i;

    if (g_TrampolinePage != NULL && page == PAGE_ALIGN(g_TrampolinePage))
    {
        return TRUE;
    }

    for (i = 0; i < SVMHV_MAX_HOOKS; i++)
    {
        const SVM_HOOK* hook = &g_Hooks[i];

        if (hook->ShadowVa != NULL && page == PAGE_ALIGN(hook->ShadowVa))
        {
            return TRUE;
        }
        if (hook->ShellcodePage != NULL && page == PAGE_ALIGN(hook->ShellcodePage))
        {
            return TRUE;
        }
    }

    return FALSE;
}

ULONG SvHookActiveCount(VOID)
{
    ULONG count = 0;
    ULONG i;

    for (i = 0; i < SVMHV_MAX_HOOKS; i++)
    {
        if (g_Hooks[i].Active != 0)
        {
            count++;
        }
    }

    return count;
}

BOOLEAN SvHookTraceInfo(_In_ UINT32 HookId, _Out_ SVM_HOOK_TRACE_INFO* Info)
{
    const SVM_HOOK* hook;
    ULONG i;

    RtlZeroMemory(Info, sizeof(*Info));

    if (HookId >= SVMHV_MAX_HOOKS)
    {
        return FALSE;
    }

    hook = &g_Hooks[HookId];
    Info->Trampoline   = hook->Trampoline;
    Info->BlockStub    = hook->BlockStub;
    Info->Target       = (UINT64)hook->TargetVa;
    Info->Gpa          = hook->Gpa;
    Info->FilterCount  = hook->FilterCount;
    Info->CaptureCount = hook->CaptureCount;
    Info->SpoofCount   = hook->SpoofCount;
    Info->CaptureReturn = hook->CaptureReturn;
    Info->CaptureStack  = hook->CaptureStack;
    for (i = 0; i < SVMHV_MAX_FILTERS; i++)
    {
        Info->Filters[i] = hook->Filters[i];
    }
    for (i = 0; i < SVMHV_MAX_CAPTURES; i++)
    {
        Info->Captures[i] = hook->Captures[i];
    }
    for (i = 0; i < SVMHV_MAX_SPOOFS; i++)
    {
        Info->Spoofs[i] = hook->Spoofs[i];
    }
    RtlCopyMemory(Info->ProcessName, hook->ProcessName,
                  sizeof(Info->ProcessName));

    return TRUE;
}

VOID SvHookCountHit(_In_ UINT32 HookId)
{
    if (HookId < SVMHV_MAX_HOOKS)
    {
        InterlockedIncrement64(&g_Hooks[HookId].Hits);
    }
}

VOID SvHookList(_Out_ SVMHV_HOOK_LIST* List)
{
    ULONG i;

    RtlZeroMemory(List, sizeof(*List));

    KeAcquireGuardedMutex(&g_HookLock);

    for (i = 0; i < SVMHV_MAX_HOOKS; i++)
    {
        const SVM_HOOK* hook = &g_Hooks[i];
        SVMHV_HOOK_INFO* out;

        /* Report retired hooks too: their records survive removal, and the
           difference between "never installed" and "installed and taken out
           again" is exactly what somebody reading this wants to see. */
        if (hook->TargetVa == NULL)
        {
            continue;
        }

        out = &List->Hooks[List->Count++];
        out->Target       = (UINT64)hook->TargetVa;
        out->Gpa          = hook->Gpa;
        out->Detour       = (UINT64)hook->DetourVa;
        out->Trampoline   = (UINT64)hook->Trampoline;
        out->Hits         = (UINT64)hook->Hits;
        out->HookId       = i;
        out->Action       = hook->Action;
        out->Kind         = hook->Kind;
        out->PrologLength = hook->PrologLength;
        out->Active       = (UINT32)hook->Active;
        out->FilterCount  = hook->FilterCount;
    }

    KeReleaseGuardedMutex(&g_HookLock);
}

/* --------------------------------------------------------------- patch */

/* jmp qword ptr [rip+0]; dq Target - position independent, clobbers nothing. */
static VOID SvWriteAbsoluteJmp(_Out_writes_bytes_(SVMHV_JMP_LENGTH) UINT8* At,
                               _In_ PVOID Target)
{
    At[0] = 0xFF;
    At[1] = 0x25;
    At[2] = 0x00;
    At[3] = 0x00;
    At[4] = 0x00;
    At[5] = 0x00;
    *(UINT64*)(At + 6) = (UINT64)Target;
}

static PVOID SvHookAllocateStub(_In_ ULONG Size)
{
    UINT8* stub;

    if (g_TrampolinePage == NULL || g_TrampolineUsed + Size > PAGE_SIZE)
    {
        return NULL;
    }

    stub = g_TrampolinePage + g_TrampolineUsed;
    g_TrampolineUsed = (g_TrampolineUsed + Size + 15) & ~15u;
    return stub;
}

static PVOID SvBuildTrampoline(_In_ const UINT8* Prolog, _In_ ULONG PrologLength,
                               _In_ PVOID ReturnTo)
{
    UINT8* tramp = (UINT8*)SvHookAllocateStub(PrologLength + SVMHV_JMP_LENGTH);

    if (tramp == NULL)
    {
        return NULL;
    }

    RtlCopyMemory(tramp, Prolog, PrologLength);
    SvWriteAbsoluteJmp(tramp + PrologLength, ReturnTo);
    return tramp;
}

/*
 * The stub a traced hook jumps to.  R11 is volatile and is not an argument
 * register in any calling convention that matters here, so loading the hook id
 * into it leaves the traced function's parameters untouched - and the jump is
 * RIP-relative through memory, so it clobbers nothing at all.
 */
static PVOID SvBuildTraceStub(_In_ UINT32 HookId)
{
    UINT8* stub = (UINT8*)SvHookAllocateStub(10 + SVMHV_JMP_LENGTH);

    if (stub == NULL)
    {
        return NULL;
    }

    stub[0] = 0x49;                                 /* mov r11, imm64       */
    stub[1] = 0xBB;
    *(UINT64*)(stub + 2) = HookId;
    SvWriteAbsoluteJmp(stub + 10, (PVOID)(ULONG_PTR)AsmTraceEntry);

    return stub;
}

/*
 * Caller-supplied code gets a page of its own.  Falling off the end continues
 * into the real function, and the trampoline and hook id are left at fixed
 * offsets so position-independent code can pick them up with a RIP-relative
 * load instead of having to be relocated.
 */
static PVOID SvBuildShellcode(_In_ const UINT8* Bytes, _In_ ULONG Size,
                              _In_ PVOID Trampoline, _In_ UINT32 HookId)
{
    UINT8* page;

    if (Size == 0 || Size + SVMHV_JMP_LENGTH > SVMHV_SHELLCODE_TRAMPOLINE_SLOT)
    {
        return NULL;
    }

    page = (UINT8*)SvHookAllocateExecutable(PAGE_SIZE);
    if (page == NULL)
    {
        return NULL;
    }

    RtlFillMemory(page, PAGE_SIZE, 0xCC);
    RtlCopyMemory(page, Bytes, Size);
    SvWriteAbsoluteJmp(page + Size, Trampoline);

    *(UINT64*)(page + SVMHV_SHELLCODE_TRAMPOLINE_SLOT) = (UINT64)Trampoline;
    *(UINT64*)(page + SVMHV_SHELLCODE_HOOKID_SLOT) = HookId;

    return page;
}

/* --------------------------------------------------- nested page entries */

/*
 * The two entries that make a hook or a watch what it is.  Everything the
 * mechanism does follows from these four lines.
 *
 * The order inside each case is the whole of the correctness argument, and the
 * page index is now part of it: the shadow view has to be complete, and the
 * page has to be findable by the fault handler, *before* the primary view
 * starts faulting.  Otherwise a fault arrives for a hook the handler cannot
 * find and is treated as unexplained.
 */
static VOID SvHookApplyEntries(_Inout_ SVM_HOOK* Hook)
{
    switch (Hook->Kind)
    {
    case SVMHV_HOOK_EXEC:
        *Hook->ShadowPte  = Hook->ShadowPa | NPT_PRESENT | NPT_USER;
        InterlockedExchange(&Hook->Active, 1);
        SvHookRebuildPageIndex();
        *Hook->PrimaryPte = Hook->Gpa | NPT_PRESENT | NPT_WRITE | NPT_USER |
                            NPT_NO_EXECUTE;
        break;

    case SVMHV_HOOK_WRITE:
        /* Executable and readable, but not writable: a write faults, and
           anything else runs at full speed. */
        *Hook->ShadowPte  = Hook->Gpa | NPT_PRESENT | NPT_WRITE | NPT_USER;
        InterlockedExchange(&Hook->Active, 1);
        SvHookRebuildPageIndex();
        *Hook->PrimaryPte = Hook->Gpa | NPT_PRESENT | NPT_USER;
        break;

    case SVMHV_HOOK_ACCESS:
    default:
        /* Not present at all, so reads fault too - nested paging has no way to
           trap a read on a page it is willing to map. */
        *Hook->ShadowPte  = Hook->Gpa | NPT_PRESENT | NPT_WRITE | NPT_USER;
        InterlockedExchange(&Hook->Active, 1);
        SvHookRebuildPageIndex();
        *Hook->PrimaryPte = 0;
        break;
    }
}

static VOID SvHookRestoreEntries(_Inout_ SVM_HOOK* Hook)
{
    /*
     * Executable again in the primary view first, so no new faults are
     * generated, then put the shadow view back to what it is everywhere else:
     * the original page, not executable.
     *
     * That last part used to be omitted, leaving the page executable in the
     * shadow hierarchy for the rest of the driver's life.  It was survivable -
     * both views map the same bytes once the hook is gone - but it quietly
     * eroded the invariant the whole mechanism rests on, that the *only*
     * executable page in the shadow hierarchy is the one a processor switched
     * there for.  With enough retired hooks, a processor could wander through
     * several of them without ever taking the fault that sends it home.
     *
     * A processor still executing in this page in shadow mode now faults on its
     * next fetch, is sent back to the primary hierarchy, and re-executes
     * against the original page - which is exactly where it should be.
     *
     * The shadow page itself is only freed at unload, when no processor can be
     * using it.
     */
    *Hook->PrimaryPte = Hook->Gpa | NPT_PRESENT | NPT_WRITE | NPT_USER;
    *Hook->ShadowPte  = Hook->Gpa | NPT_PRESENT | NPT_USER | NPT_NO_EXECUTE;
    InterlockedExchange(&Hook->Active, 0);
}


/*
 * mov rax, imm64; ret.  Used as a hook's continuation when the caller asked for
 * the original never to run: the thunk returns to this with RSP exactly as the
 * function was entered, so the ret here goes to the real caller with RAX set.
 * No assembler changes, and no special case in the exit path.
 */
static PVOID SvBuildBlockStub(_In_ UINT64 Value)
{
    UINT8* stub = (UINT8*)SvHookAllocateStub(11);

    if (stub == NULL)
    {
        return NULL;
    }

    stub[0] = 0x48;                                 /* mov rax, imm64       */
    stub[1] = 0xB8;
    *(UINT64*)(stub + 2) = Value;
    stub[10] = 0xC3;                                /* ret                  */
    return stub;
}

static NTSTATUS SvHookApplyPolicy(_Inout_ SVM_HOOK* Hook,
                                  _In_ const SVMHV_HOOK_REQUEST* Request)
{
    ULONG i;

    if (Request->CaptureCount > SVMHV_MAX_CAPTURES ||
        Request->SpoofCount > SVMHV_MAX_SPOOFS)
    {
        return STATUS_INVALID_PARAMETER;
    }

    Hook->FilterCount  = Request->FilterCount;
    Hook->CaptureCount = Request->CaptureCount;
    Hook->SpoofCount   = Request->SpoofCount;
    RtlCopyMemory(Hook->Filters, Request->Filters, sizeof(Hook->Filters));
    RtlCopyMemory(Hook->Captures, Request->Captures, sizeof(Hook->Captures));
    RtlCopyMemory(Hook->Spoofs, Request->Spoofs, sizeof(Hook->Spoofs));
    RtlCopyMemory(Hook->ProcessName, Request->ProcessName,
                  sizeof(Hook->ProcessName));
    Hook->ProcessName[sizeof(Hook->ProcessName) - 1] = 0;

    for (i = 0; i < Hook->CaptureCount; i++)
    {
        if (Hook->Captures[i].Argument >= 8 ||
            Hook->Captures[i].Type > SVMHV_CAPTURE_LAST)
        {
            return STATUS_INVALID_PARAMETER;
        }
    }
    for (i = 0; i < Hook->SpoofCount; i++)
    {
        if (Hook->Spoofs[i].Argument >= 8)
        {
            return STATUS_INVALID_PARAMETER;
        }
    }

    Hook->CaptureReturn = (Request->CaptureReturn != 0);
    Hook->CaptureStack  = (Request->CaptureStack != 0);

    /*
     * Reuse the stub when it already returns the right value.
     *
     * Stubs come out of a one-page bump allocator that never frees, so building
     * a fresh one on every install turned install-and-remove-in-a-loop - which
     * the rest of this file goes out of its way to make free - into something
     * that exhausted the page after a few hundred cycles and then failed every
     * subsequent install with STATUS_INSUFFICIENT_RESOURCES.  A blocked hook
     * toggled on and off is a completely ordinary thing to want.
     */
    if (!Request->Block)
    {
        Hook->BlockStub = NULL;
    }
    else if (Hook->BlockStub == NULL || Hook->BlockValue != Request->BlockValue)
    {
        Hook->BlockStub = SvBuildBlockStub(Request->BlockValue);
        if (Hook->BlockStub == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        Hook->BlockValue = Request->BlockValue;
    }

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------- install */

static NTSTATUS SvHookPrepareDetour(_Inout_ SVM_HOOK* Hook,
                                    _Inout_ SVMHV_HOOK_REQUEST* Request)
{
    switch (Request->Action)
    {
    case SVMHV_ACTION_TRACE:
        Hook->DetourVa = SvBuildTraceStub((UINT32)(Hook - g_Hooks));
        break;

    case SVMHV_ACTION_DETOUR:
        if (Request->Detour < (UINT64)MM_SYSTEM_RANGE_START)
        {
            return STATUS_INVALID_PARAMETER;
        }
        Hook->DetourVa = (PVOID)Request->Detour;
        break;

    case SVMHV_ACTION_SHELLCODE:
        if (Request->ShellcodeSize == 0 ||
            Request->ShellcodeSize > SVMHV_MAX_SHELLCODE)
        {
            return STATUS_INVALID_PARAMETER;
        }
        Hook->ShellcodePage = SvBuildShellcode(Request->Shellcode,
                                               Request->ShellcodeSize,
                                               Hook->Trampoline,
                                               (UINT32)(Hook - g_Hooks));
        Hook->DetourVa = Hook->ShellcodePage;
        break;

    default:
        return STATUS_INVALID_PARAMETER;
    }

    return (Hook->DetourVa != NULL) ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
}

NTSTATUS SvHookInstall(_Inout_ SVMHV_HOOK_REQUEST* Request)
{
    NTSTATUS status = STATUS_SUCCESS;
    SVM_HOOK* hook = NULL;
    PVOID target = (PVOID)Request->Target;
    PVOID pageVa;
    ULONG offset;
    ULONG i;
    UINT64 gpa;
    PVOID shadowVa = NULL;
    PMDL mdl = NULL;
    SVMHV_ATTACH attach = { 0 };
    SVM_HOOK* pageOwner = NULL;
    const BOOLEAN isExec = (Request->Kind == SVMHV_HOOK_EXEC);

    Request->Trampoline = 0;
    Request->Gpa = 0;
    Request->HookId = 0;

    /*
     * A user-mode target is allowed, but only with a process to pin it to.
     *
     * The mechanism never cared: a hook keys on a guest physical page, and a
     * user page is as hookable as a kernel one.  What a user target needs that
     * a kernel one does not is a context - the address means nothing without a
     * process, MmGetPhysicalAddress would translate it against whatever address
     * space the worker thread happens to be in, and the answer would be a page
     * belonging to somebody else entirely.  So attach first, and refuse if the
     * caller did not say to what.
     *
     * Two things follow that a caller has to know, and they are documented
     * rather than defended against.  The hook is on the *physical* page, so a
     * page shared between processes - which is every mapped image - fires for
     * all of them; the process filters exist to narrow the recording, and they
     * are the right tool for it.  And a private page can be copied on write
     * afterwards, at which point the hook is watching the copy nobody is using
     * any more.
     */
    if (Request->Target < (UINT64)MM_SYSTEM_RANGE_START)
    {
        if (Request->TargetProcessId == 0)
        {
            return STATUS_INVALID_PARAMETER;
        }

        /*
         * Watchpoints only, for now, and the reason is worth writing down
         * because it is not a policy decision.
         *
         * A watch executes nothing: the fault handler records the access and
         * switches this processor's view, which works identically whoever owns
         * the page.  An exec hook has to jump somewhere, and everywhere this
         * driver can put a detour - the trace stub, a shellcode page, a
         * trampoline - is kernel memory.  Jumping there from CPL 3 faults, and
         * on any modern processor SMEP would stop it even if the mapping
         * allowed it.  Making exec hooks work in user mode means allocating the
         * detour inside the target process, which is a different piece of work
         * and not one to fake.
         */
        if (Request->Kind == SVMHV_HOOK_EXEC)
        {
            return STATUS_NOT_SUPPORTED;
        }
    }
    if (Request->Kind > SVMHV_HOOK_ACCESS)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (Request->FilterCount > SVMHV_MAX_FILTERS)
    {
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * Refuse to watch our own working memory.
     *
     * This is not tidiness, it is the difference between a mistake and an
     * unrecoverable one.  A write watch fires twice per store - once to reach
     * the shadow view, once to leave it - so watching a page that is written in
     * bulk costs thousands of exits a second.  Watching the control block or the
     * snapshot means the worker's own refresh triggers it, at which point the
     * guest is too busy to answer the debugger, and the interface that could
     * remove the watch is the thing being starved.  Asked for by name: doing
     * exactly this cost a VM.
     */
    if (Request->Kind != SVMHV_HOOK_EXEC && SvIsHypervisorMemory(target))
    {
        return STATUS_ACCESS_DENIED;
    }

    pageVa = PAGE_ALIGN(target);
    offset = (ULONG)((ULONG_PTR)target & (PAGE_SIZE - 1));

    if (isExec)
    {
        if (Request->PrologLength < SVMHV_JMP_LENGTH ||
            Request->PrologLength > SVMHV_MAX_PROLOG)
        {
            return STATUS_INVALID_PARAMETER;
        }
        /* A prologue that straddles two pages would need two shadow pages. */
        if (offset + Request->PrologLength > PAGE_SIZE)
        {
            return STATUS_INVALID_PARAMETER;
        }
    }

    KeAcquireGuardedMutex(&g_HookLock);

    /*
     * Everything from here to the MDL has to run in the target's address space
     * when there is one, because that is what makes the translation below mean
     * anything.  Kernel targets attach to nothing and are unaffected.
     */
    if (Request->TargetProcessId != 0)
    {
        status = SvMemoryAttachProcess(Request->TargetProcessId, &attach);
        if (!NT_SUCCESS(status))
        {
            goto done;
        }
    }

    /*
     * Several hooks may share one guest physical page.
     *
     * They have to share the page's resources, because there is only one of
     * each: two nested page table entries, one shadow copy, one MDL pinning
     * the page.  What they do not share is the patch - each hook writes its own
     * jump at its own offset into the one shadow copy, and the fault handler
     * does not care how many there are, because the page either faults or it
     * does not.
     *
     * This matters more than it sounds.  Kernel functions are packed several to
     * a page, so "instrument every Nt* entry point" was impossible while a page
     * could hold one hook - the second install in any page failed, and which
     * ones collided depended on where the linker happened to put things.
     */
    gpa = (UINT64)MmGetPhysicalAddress(pageVa).QuadPart;
    for (i = 0; i < SVMHV_MAX_HOOKS; i++)
    {
        SVM_HOOK* neighbour = &g_Hooks[i];

        /*
         * Retired records count as occupants.
         *
         * This used to skip anything not armed, which let a *second* record be
         * created for a page a retired one still owns - removal frees nothing,
         * so that record keeps the MDL, the shadow copy and both page table
         * entry pointers.  Two records each believing they own one page hand
         * the fault handler two different descriptions of it, and take two
         * separate MDL locks on the same physical page.  A record whose
         * PrimaryPte is NULL has genuinely let go (a user hook, whose pin
         * cannot outlive it) and is the only kind that may be passed over.
         */
        if (neighbour->Gpa != gpa || neighbour->PrimaryPte == NULL)
        {
            continue;
        }
        if (neighbour->TargetVa == target)
        {
            if (neighbour->Active != 0)
            {
                status = STATUS_ALREADY_REGISTERED;    /* this exact target */
                goto done;
            }
            /* Retired, and about to be re-armed by the loop below, which knows
               how to reuse everything this record is still holding - including
               across a change of kind. */
            continue;
        }

        /*
         * Only execution hooks can share.  A watch traps the whole page, so a
         * watch and a hook in one page would each be describing what the other
         * one's entries should be, and only one of them could win.
         */
        if (!isExec || neighbour->Kind != SVMHV_HOOK_EXEC)
        {
            status = STATUS_ALREADY_REGISTERED;
            goto done;
        }

        /*
         * And only in kernel space.  A user page's pin is released the moment
         * its hook is removed, which a second hook sharing that pin would not
         * survive; kernel pins live until unload, so sharing one is safe.
         */
        if (Request->TargetProcessId != 0 || neighbour->TargetProcessId != 0)
        {
            status = STATUS_ALREADY_REGISTERED;
            goto done;
        }

        pageOwner = neighbour;
        break;
    }

    /*
     * Re-arming a target that was hooked before costs nothing: the shadow page,
     * the MDL pinning the target and the two PTE pointers are all still valid,
     * because removal deliberately frees none of them.  Without this, install
     * and remove in a loop would burn a record, a locked page and a shadow page
     * every time round and stop working after SVMHV_MAX_HOOKS goes.
     */
    for (i = 0; i < SVMHV_MAX_HOOKS; i++)
    {
        SVM_HOOK* previous = &g_Hooks[i];

        if (previous->Active != 0 || previous->PrimaryPte == NULL ||
            previous->TargetVa != target || previous->Gpa != gpa)
        {
            continue;
        }

        /*
         * The kind may differ from last time, and this record still has to be
         * the one that is reused: it owns the page, and the neighbour scan
         * above now refuses to build a second record beside it.  The page table
         * entries are rewritten from scratch by SvHookApplyEntries, so the only
         * thing a change of kind actually needs is a shadow copy, which a watch
         * never had.
         */
        if (Request->Kind == SVMHV_HOOK_EXEC && previous->ShadowVa == NULL)
        {
            PHYSICAL_ADDRESS highest;

            highest.QuadPart = MAXULONG64;
            previous->ShadowVa = MmAllocateContiguousMemory(PAGE_SIZE, highest);
            if (previous->ShadowVa == NULL)
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto done;
            }
            previous->ShadowPa =
                (UINT64)MmGetPhysicalAddress(previous->ShadowVa).QuadPart;
            RtlCopyMemory(previous->ShadowVa, pageVa, PAGE_SIZE);
            previous->OwnsPage = TRUE;
        }
        previous->Kind = Request->Kind;
        if (!isExec)
        {
            previous->PrologLength = 0;
        }

        {
            const UINT32 oldAction = previous->Action;

            previous->Action = isExec ? Request->Action : SVMHV_ACTION_TRACE;
            status = SvHookApplyPolicy(previous, Request);
            if (!NT_SUCCESS(status))
            {
                goto done;
            }

            /*
             * A trace stub only depends on the hook id, so re-arming a traced
             * hook can keep the one it already has.  Shellcode has to be
             * rebuilt because the caller may have supplied different bytes.
             */
            if (isExec && (oldAction != Request->Action ||
                           Request->Action == SVMHV_ACTION_SHELLCODE ||
                           previous->DetourVa == NULL))
            {
                if (previous->ShellcodePage != NULL)
                {
                    SvHookFreeExecutable(previous->ShellcodePage);
                    previous->ShellcodePage = NULL;
                }
                status = SvHookPrepareDetour(previous, Request);
                if (!NT_SUCCESS(status))
                {
                    goto done;
                }
            }
        }

        if (isExec)
        {
            /*
             * Refresh the whole shadow copy only when nothing else is using it.
             * With a neighbour still armed in this page, copying the original
             * over the top would erase its patch and quietly unhook it.
             */
            if (SvHookPageActiveCount(gpa) == 0)
            {
                RtlCopyMemory(previous->ShadowVa, pageVa, PAGE_SIZE);
            }
            RtlCopyMemory(previous->OriginalProlog, target, Request->PrologLength);

            if (previous->PrologLength != Request->PrologLength)
            {
                const ULONG wanted = Request->PrologLength + SVMHV_JMP_LENGTH;

                /*
                 * Rewrite the trampoline in place when the space it already
                 * holds is big enough.  Only a shorter or equal prologue can
                 * do that, and it is the common case; allocating unconditionally
                 * leaked a trampoline out of the one-page stub allocator on
                 * every re-arm that changed the length.
                 */
                if (previous->Trampoline != NULL &&
                    wanted <= previous->TrampolineCapacity)
                {
                    RtlCopyMemory(previous->Trampoline, previous->OriginalProlog,
                                  Request->PrologLength);
                    SvWriteAbsoluteJmp((UINT8*)previous->Trampoline +
                                       Request->PrologLength,
                                       (UINT8*)target + Request->PrologLength);
                }
                else
                {
                    PVOID rebuilt = SvBuildTrampoline(previous->OriginalProlog,
                                                      Request->PrologLength,
                                                      (UINT8*)target + Request->PrologLength);
                    if (rebuilt == NULL)
                    {
                        status = STATUS_INSUFFICIENT_RESOURCES;
                        goto done;
                    }
                    previous->Trampoline = rebuilt;
                    previous->TrampolineCapacity = wanted;
                }
                previous->PrologLength = Request->PrologLength;
            }

            SvWriteAbsoluteJmp((UINT8*)previous->ShadowVa + offset,
                               previous->DetourVa);
            if (Request->PrologLength > SVMHV_JMP_LENGTH)
            {
                RtlFillMemory((UINT8*)previous->ShadowVa + offset + SVMHV_JMP_LENGTH,
                              Request->PrologLength - SVMHV_JMP_LENGTH, 0x90);
            }
        }

        SvHookApplyEntries(previous);
        SvSyncTlbFlush();

        Request->Trampoline = (UINT64)previous->Trampoline;
        Request->Gpa = gpa;
        Request->HookId = i;
        status = STATUS_SUCCESS;
        goto done;
    }

    for (i = 0; i < SVMHV_MAX_HOOKS; i++)
    {
        if (g_Hooks[i].TargetVa == NULL)
        {
            hook = &g_Hooks[i];
            break;
        }
    }
    if (hook == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    if (pageOwner == NULL)
    {
        /*
         * Pin the page.  A hook keyed on a physical address is only meaningful
         * for as long as that physical page stays where it is.
         */
        mdl = IoAllocateMdl(pageVa, PAGE_SIZE, FALSE, FALSE, NULL);
        if (mdl == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto done;
        }

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

        /* Re-read: locking may not move a kernel page, but do not assume it. */
        gpa = (UINT64)MmGetPhysicalAddress(pageVa).QuadPart;

        if (isExec)
        {
            PHYSICAL_ADDRESS highest;
            highest.QuadPart = MAXULONG64;
            shadowVa = MmAllocateContiguousMemory(PAGE_SIZE, highest);
            if (shadowVa == NULL)
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto done;
            }
            RtlCopyMemory(shadowVa, pageVa, PAGE_SIZE);
        }
    }
    else
    {
        /*
         * Joining a page somebody else already owns.  The pin, the shadow copy
         * and the page table entries are all already there and already correct;
         * taking a second MDL on the same page or copying the original over the
         * shadow would undo the neighbour rather than add to it.
         */
        shadowVa = pageOwner->ShadowVa;
    }

    if (isExec)
    {
        RtlCopyMemory(hook->OriginalProlog, target, Request->PrologLength);
    }

    hook->Kind         = Request->Kind;
    hook->Action       = isExec ? Request->Action : SVMHV_ACTION_TRACE;
    hook->Gpa          = gpa;
    hook->PageVa       = pageVa;
    hook->TargetVa     = target;
    hook->ShadowVa     = shadowVa;
    hook->ShadowPa     = (shadowVa != NULL)
                       ? (UINT64)MmGetPhysicalAddress(shadowVa).QuadPart : 0;
    hook->Mdl          = mdl;
    hook->OwnsPage     = (pageOwner == NULL);
    hook->TargetProcessId = Request->TargetProcessId;
    hook->PrologLength = isExec ? Request->PrologLength : 0;
    hook->Hits         = 0;

    status = SvHookApplyPolicy(hook, Request);
    if (!NT_SUCCESS(status))
    {
        goto done;
    }

    if (pageOwner != NULL)
    {
        /* One page, one pair of entries: borrow the owner's rather than
           splitting the tables again and getting the same two pointers. */
        hook->PrimaryPte = pageOwner->PrimaryPte;
        hook->ShadowPte  = pageOwner->ShadowPte;
    }
    else
    {
        hook->PrimaryPte = SvNptSplitTo4Kb(&g_NptPrimary, gpa);
        hook->ShadowPte  = SvNptSplitTo4Kb(&g_NptShadow, gpa);
    }
    if (hook->PrimaryPte == NULL || hook->ShadowPte == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    if (isExec)
    {
        hook->Trampoline = SvBuildTrampoline(hook->OriginalProlog,
                                             Request->PrologLength,
                                             (UINT8*)target + Request->PrologLength);
        if (hook->Trampoline == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto done;
        }
        hook->TrampolineCapacity = Request->PrologLength + SVMHV_JMP_LENGTH;

        status = SvHookPrepareDetour(hook, Request);
        if (!NT_SUCCESS(status))
        {
            goto done;
        }

        /*
         * Patch the copy, not the original.  Anything past the jump up to the
         * end of the prologue becomes a nop so the shadow page stays the same
         * length as the original and a jump landing mid-prologue still runs
         * code rather than falling into the middle of an instruction.
         */
        SvWriteAbsoluteJmp((UINT8*)shadowVa + offset, hook->DetourVa);
        if (Request->PrologLength > SVMHV_JMP_LENGTH)
        {
            RtlFillMemory((UINT8*)shadowVa + offset + SVMHV_JMP_LENGTH,
                          Request->PrologLength - SVMHV_JMP_LENGTH, 0x90);
        }
    }

    /*
     * Order matters.  The shadow view has to be complete, and the hook has to
     * be findable by the exit handler, before the primary view starts faulting -
     * otherwise a fault arrives for a hook that does not exist yet.  That is
     * what SvHookApplyEntries does, in that order.
     */
    SvHookApplyEntries(hook);

    /* Not optional: until every processor has flushed, the page is still
       mapped by whatever large-page translation it has cached. */
    SvSyncTlbFlush();

    Request->Trampoline = (UINT64)hook->Trampoline;
    Request->Gpa = gpa;
    Request->HookId = (UINT32)(hook - g_Hooks);

    mdl = NULL;
    shadowVa = NULL;

    DbgPrint("svmhv: hook %u kind=%u action=%u at %p (gpa %llx) -> %p, "
             "prolog %u, trampoline %p\n",
             Request->HookId, hook->Kind, hook->Action, target, gpa,
             hook->DetourVa, hook->PrologLength, hook->Trampoline);

done:
    /*
     * Before anything else on the way out: the shadow copy, the trampoline and
     * the page table edits above all read the target through the attached
     * address space, and everything after this point must not.
     */
    SvMemoryDetachProcess(&attach);

    if (!NT_SUCCESS(status))
    {
        /* Only if we allocated it.  When joining a page, shadowVa is the
           neighbour's copy and freeing it here would unhook them instead. */
        if (shadowVa != NULL && pageOwner == NULL)
        {
            MmFreeContiguousMemory(shadowVa);
        }
        if (mdl != NULL)
        {
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
        }
        if (hook != NULL)
        {
            if (hook->ShellcodePage != NULL)
            {
                SvHookFreeExecutable(hook->ShellcodePage);
            }
            RtlZeroMemory(hook, sizeof(*hook));
        }
    }

    KeReleaseGuardedMutex(&g_HookLock);
    return status;
}

/* -------------------------------------------------------------- remove */

NTSTATUS SvHookRemove(_In_ PVOID Target)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    ULONG i;

    KeAcquireGuardedMutex(&g_HookLock);

    for (i = 0; i < SVMHV_MAX_HOOKS; i++)
    {
        SVM_HOOK* hook = &g_Hooks[i];

        if (hook->Active == 0 || hook->TargetVa != Target)
        {
            continue;
        }

        /*
         * Take this hook's patch out of the shadow copy first, so that a page
         * still holding other hooks stops detouring this target and keeps
         * detouring theirs.  The original bytes are the ones we saved when the
         * jump went in.
         */
        if (hook->Kind == SVMHV_HOOK_EXEC && hook->ShadowVa != NULL)
        {
            const ULONG offset =
                (ULONG)((ULONG_PTR)hook->TargetVa & (PAGE_SIZE - 1));

            RtlCopyMemory((UINT8*)hook->ShadowVa + offset,
                          hook->OriginalProlog, hook->PrologLength);
        }

        InterlockedExchange(&hook->Active, 0);

        /*
         * Only the last hook out puts the mappings back.  Doing it while a
         * neighbour is still armed would make the page ordinary again and
         * silently stop that hook firing - the page either faults for all of
         * them or none.
         */
        if (SvHookPageActiveCount(hook->Gpa) == 0)
        {
            SvHookRestoreEntries(hook);
        }

        /* After the entries, not before: while the page is still trapping, the
           handler has to be able to find out why. */
        SvHookRebuildPageIndex();
        SvSyncTlbFlush();

        /*
         * A user page's pin cannot outlive the hook.  Everything else about a
         * removed hook is deliberately kept so that re-installing costs
         * nothing, but holding this would stop the target process from ever
         * exiting - it would bugcheck 0x76 on its way out instead.
         *
         * The flush above is what makes this safe to do here: no processor is
         * still using a translation that depended on the page staying put.
         */
        if (hook->TargetProcessId != 0 && hook->Mdl != NULL && hook->OwnsPage)
        {
            MmUnlockPages(hook->Mdl);
            IoFreeMdl(hook->Mdl);
            hook->Mdl = NULL;

            /* The record is reusable only for a target that gets re-pinned, so
               make the install path treat it as a fresh one. */
            hook->PrimaryPte = NULL;
            hook->ShadowPte = NULL;
            hook->TargetVa = NULL;
        }

        DbgPrint("svmhv: hook %u removed at %p after %lld hits\n",
                 i, Target, hook->Hits);
        status = STATUS_SUCCESS;
        break;
    }

    KeReleaseGuardedMutex(&g_HookLock);
    return status;
}
