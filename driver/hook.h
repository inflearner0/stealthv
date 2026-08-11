/*
 * hook.h - nested-paging hooks and watchpoints.
 *
 * Three things trap here, all through the same mechanism: a page whose entry in
 * the primary hierarchy is deliberately missing a permission, and whose entry in
 * the shadow hierarchy has it.
 *
 *   EXEC    primary: not executable, maps the original page
 *           shadow:  executable, maps a patched copy
 *
 *   WRITE   primary: not writable, maps the original page
 *           shadow:  writable, maps the original page
 *
 *   ACCESS  primary: not present
 *           shadow:  present, writable, executable
 *
 * In every case the fault is resolved the same way: record what happened, switch
 * this processor to the shadow hierarchy, and re-execute.  The instruction then
 * completes, and because nothing else in the shadow hierarchy is executable, the
 * next instruction fetch outside the page faults straight back to the primary
 * one.  No single-stepping, no trap flag, and no need to decode the instruction
 * that faulted.
 *
 * For an EXEC hook that substitution is the whole point: reads and writes keep
 * seeing the original bytes, because they are served by the primary hierarchy,
 * and NCr3 is per-VMCB so only the processor actually executing inside the page
 * ever sees the patch.
 *
 * Callers of an EXEC hook supply PrologLength: the number of bytes at the start
 * of the target that may be overwritten, rounded up to an instruction boundary,
 * at least 14 for an absolute jump.  There is deliberately no length
 * disassembler here; hooking a function whose prologue you have not decoded is
 * not something this file can make safe.
 */

#pragma once

#include "npt.h"
#include "svmhvctl.h"

#define SVMHV_MAX_HOOKS     SVMHV_MAX_HOOK_RECORDS
#define SVMHV_JMP_LENGTH    14      /* ff 25 00000000 + qword target        */
#define SVMHV_MAX_PROLOG    32

/* What the exit handler needs to know about a page that faulted. */
typedef struct _SVM_HOOK_PAGE
{
    UINT32  HookId;
    UINT32  Kind;                   /* SVMHV_HOOK_*                         */
    BOOLEAN Found;

    /*
     * A system-space alias of the watched page, so the exit handler can read
     * what is in it.  Watches only, and NULL if the alias could not be made.
     *
     * It has to be an alias rather than the target's own address: a user-mode
     * watch's page belongs to another process, and the host's CR3 at the exit
     * is whatever address space this processor launched in.  The page is
     * already pinned by the hook's MDL, so the alias is a mapping of locked
     * pages and is valid at any IRQL, which is what makes it legal to read
     * with GIF clear.
     */
    PVOID   WatchVa;
} SVM_HOOK_PAGE;

/* What the trace recorder needs to know about a hook that just fired. */
typedef struct _SVM_HOOK_TRACE_INFO
{
    PVOID         Trampoline;
    PVOID         BlockStub;        /* "mov rax, imm64; ret", or NULL       */
    UINT64        Target;
    UINT64        Gpa;
    ULONG         FilterCount;
    ULONG         CaptureCount;
    ULONG         SpoofCount;
    SVMHV_FILTER  Filters[SVMHV_MAX_FILTERS];
    SVMHV_CAPTURE Captures[SVMHV_MAX_CAPTURES];
    SVMHV_SPOOF   Spoofs[SVMHV_MAX_SPOOFS];
    BOOLEAN       CaptureReturn;
    BOOLEAN       CaptureStack;
    char          ProcessName[SVMHV_PROCESS_NAME_MAX];
} SVM_HOOK_TRACE_INFO;

NTSTATUS SvHookInitialize(VOID);
VOID     SvHookCleanup(VOID);

/*
 * Install from a fully-specified request.  Fills in Trampoline, Gpa and HookId
 * on success.  PASSIVE_LEVEL.
 */
NTSTATUS SvHookInstall(_Inout_ SVMHV_HOOK_REQUEST* Request);
NTSTATUS SvHookRemove(_In_ PVOID Target);
VOID     SvHookList(_Out_ SVMHV_HOOK_LIST* List);

/* ---------------------------------------------------------- exit handler */

/*
 * Exit-handler side.  Runs with GIF clear: no locks, no allocations, no
 * pageable memory.
 */
BOOLEAN  SvHookFindPage(_In_ UINT64 Gpa, _Out_ SVM_HOOK_PAGE* Page);
ULONG    SvHookActiveCount(VOID);

/* Trace side; runs in guest context at the traced function's IRQL. */
BOOLEAN  SvHookTraceInfo(_In_ UINT32 HookId, _Out_ SVM_HOOK_TRACE_INFO* Info);
VOID     SvHookCountHit(_In_ UINT32 HookId);

/* Executable kernel memory, for trampolines, stubs and shellcode. */
PVOID    SvHookAllocateExecutable(_In_ SIZE_T Size);
VOID     SvHookFreeExecutable(_In_ PVOID Va);

/*
 * TRUE if the page holds this file's executable memory - the trampoline and
 * stub page, a hooked page's patched shadow copy, or a caller's shellcode.
 * Nothing there may be watched; see SvIsHypervisorMemory.
 */
BOOLEAN  SvHookOwnsPage(_In_ PVOID Address);
