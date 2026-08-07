/*
 * hook.c - nested-paging hooks and watchpoints.  See hook.h for the design.
 */

#include "hook.h"
#include "trace.h"
#include "svmhv.h"
#include "control.h"    /* SvIsHypervisorMemory: what a watch may not touch */

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
    char    ProcessName[SVMHV_PROCESS_NAME_MAX];
    PVOID   BlockStub;          /* mov rax, imm64; ret - when blocking      */
    UINT8   OriginalProlog[SVMHV_MAX_PROLOG];
} SVM_HOOK;

static SVM_HOOK       g_Hooks[SVMHV_MAX_HOOKS];
static KGUARDED_MUTEX g_HookLock;

/* One page of executable memory, bump-allocated for trampolines and stubs. */
static UINT8* g_TrampolinePage;
static ULONG  g_TrampolineUsed;

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

NTSTATUS SvHookInitialize(VOID)
{
    KeInitializeGuardedMutex(&g_HookLock);
    RtlZeroMemory(g_Hooks, sizeof(g_Hooks));

    g_TrampolinePage = (UINT8*)SvHookAllocateExecutable(PAGE_SIZE);
    if (g_TrampolinePage == NULL)
    {
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

    for (i = 0; i < SVMHV_MAX_HOOKS; i++)
    {
        SVM_HOOK* hook = &g_Hooks[i];

        if (hook->Mdl != NULL)
        {
            MmUnlockPages(hook->Mdl);
            IoFreeMdl(hook->Mdl);
            hook->Mdl = NULL;
        }
        if (hook->ShadowVa != NULL)
        {
            MmFreeContiguousMemory(hook->ShadowVa);
            hook->ShadowVa = NULL;
        }
        if (hook->ShellcodePage != NULL)
        {
            SvHookFreeExecutable(hook->ShellcodePage);
            hook->ShellcodePage = NULL;
        }
        hook->Active = 0;
    }

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
    ULONG i;

    Page->Found = FALSE;
    Page->HookId = 0;
    Page->Kind = 0;

    for (i = 0; i < SVMHV_MAX_HOOKS; i++)
    {
        if (g_Hooks[i].Active != 0 && g_Hooks[i].Gpa == page)
        {
            Page->Found = TRUE;
            Page->HookId = i;
            Page->Kind = g_Hooks[i].Kind;
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
 */
static VOID SvHookApplyEntries(_Inout_ SVM_HOOK* Hook)
{
    switch (Hook->Kind)
    {
    case SVMHV_HOOK_EXEC:
        *Hook->ShadowPte  = Hook->ShadowPa | NPT_PRESENT | NPT_USER;
        InterlockedExchange(&Hook->Active, 1);
        *Hook->PrimaryPte = Hook->Gpa | NPT_PRESENT | NPT_WRITE | NPT_USER |
                            NPT_NO_EXECUTE;
        break;

    case SVMHV_HOOK_WRITE:
        /* Executable and readable, but not writable: a write faults, and
           anything else runs at full speed. */
        *Hook->ShadowPte  = Hook->Gpa | NPT_PRESENT | NPT_WRITE | NPT_USER;
        InterlockedExchange(&Hook->Active, 1);
        *Hook->PrimaryPte = Hook->Gpa | NPT_PRESENT | NPT_USER;
        break;

    case SVMHV_HOOK_ACCESS:
    default:
        /* Not present at all, so reads fault too - nested paging has no way to
           trap a read on a page it is willing to map. */
        *Hook->ShadowPte  = Hook->Gpa | NPT_PRESENT | NPT_WRITE | NPT_USER;
        InterlockedExchange(&Hook->Active, 1);
        *Hook->PrimaryPte = 0;
        break;
    }
}

static VOID SvHookRestoreEntries(_Inout_ SVM_HOOK* Hook)
{
    /*
     * Executable again in the primary view first, so no new faults are
     * generated, then point the shadow view at the original page as well - a
     * processor still running in shadow mode then executes the real bytes and
     * drops back to the primary hierarchy on its next exit.  The shadow page
     * itself is only freed at unload, when no processor can be using it.
     */
    *Hook->PrimaryPte = Hook->Gpa | NPT_PRESENT | NPT_WRITE | NPT_USER;
    *Hook->ShadowPte  = Hook->Gpa | NPT_PRESENT | NPT_USER;
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
            Hook->Captures[i].Type > SVMHV_CAPTURE_BYTES)
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

    Hook->BlockStub = NULL;
    if (Request->Block)
    {
        Hook->BlockStub = SvBuildBlockStub(Request->BlockValue);
        if (Hook->BlockStub == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
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
    const BOOLEAN isExec = (Request->Kind == SVMHV_HOOK_EXEC);

    Request->Trampoline = 0;
    Request->Gpa = 0;
    Request->HookId = 0;

    if (Request->Target < (UINT64)MM_SYSTEM_RANGE_START)
    {
        return STATUS_INVALID_PARAMETER;
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
     * One hook per guest physical page.  Two in the same page would have to
     * share one set of nested page table entries, and the second install would
     * silently redefine the first one's behaviour.
     */
    gpa = (UINT64)MmGetPhysicalAddress(pageVa).QuadPart;
    for (i = 0; i < SVMHV_MAX_HOOKS; i++)
    {
        if (g_Hooks[i].Active != 0 && g_Hooks[i].Gpa == gpa)
        {
            status = STATUS_ALREADY_REGISTERED;
            goto done;
        }
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
            previous->TargetVa != target || previous->Gpa != gpa ||
            previous->Kind != Request->Kind)
        {
            continue;
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
            RtlCopyMemory(previous->ShadowVa, pageVa, PAGE_SIZE);
            RtlCopyMemory(previous->OriginalProlog, target, Request->PrologLength);

            if (previous->PrologLength != Request->PrologLength)
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

    /*
     * Pin the page.  A hook keyed on a physical address is only meaningful for
     * as long as that physical page stays where it is.
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
    hook->PrologLength = isExec ? Request->PrologLength : 0;
    hook->Hits         = 0;

    status = SvHookApplyPolicy(hook, Request);
    if (!NT_SUCCESS(status))
    {
        goto done;
    }

    hook->PrimaryPte = SvNptSplitTo4Kb(&g_NptPrimary, gpa);
    hook->ShadowPte  = SvNptSplitTo4Kb(&g_NptShadow, gpa);
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
    if (!NT_SUCCESS(status))
    {
        if (shadowVa != NULL)
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

        SvHookRestoreEntries(hook);
        SvSyncTlbFlush();

        DbgPrint("svmhv: hook %u removed at %p after %lld hits\n",
                 i, Target, hook->Hits);
        status = STATUS_SUCCESS;
        break;
    }

    KeReleaseGuardedMutex(&g_HookLock);
    return status;
}
