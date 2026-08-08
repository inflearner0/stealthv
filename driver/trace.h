/*
 * trace.h - the trace ring, and the generic argument-recording detour.
 *
 * A hook whose action is SVMHV_ACTION_TRACE does not need the caller to write
 * any kernel code.  The driver generates a 24-byte stub per hook that loads the
 * hook id into R11 - volatile, and not an argument register, so the traced
 * function's parameters survive - and jumps to AsmTraceEntry, which preserves
 * every volatile register including XMM0-5, records the call, and then continues
 * into that hook's trampoline as if nothing had happened.
 */

#pragma once

#include "svm.h"
#include "svmhvctl.h"

/*
 * The volatile registers AsmTraceEntry preserves, in the order it pushes them.
 * Lowest address first, i.e. reverse push order.  Trampoline shares the slot
 * that carried the original RSP on the way in, which is dead by then.
 */
typedef struct _TRACE_FRAME
{
    UINT64 Trampoline;          /* +0x00 in, the caller's RSP; out, where to go */
    UINT64 R11;                 /* +0x08 - the hook id on entry                 */
    UINT64 R10;                 /* +0x10 */
    UINT64 R9;                  /* +0x18 */
    UINT64 R8;                  /* +0x20 */
    UINT64 Rdx;                 /* +0x28 */
    UINT64 Rcx;                 /* +0x30 */
    UINT64 Rax;                 /* +0x38 */
} TRACE_FRAME;

C_ASSERT(sizeof(TRACE_FRAME) == 0x40);

NTSTATUS SvTraceInitialize(VOID);
VOID     SvTraceFree(VOID);

/*
 * Called from AsmTraceEntry with the hook id, the saved registers and the RSP
 * the traced function was entered with.  Returns the address to continue at,
 * which is normally the hook's trampoline.  Runs in guest context at whatever
 * IRQL the traced function runs at, so: no locks, no pageable memory.
 */
PVOID    SvTraceExecEntry(_In_ UINT64 HookId, _In_ TRACE_FRAME* Frame,
                          _In_ UINT64 OriginalRsp);

/*
 * Called from the #NPF handler for a watchpoint hit, in host context with GIF
 * clear.  Deliberately records less than the exec path: no Ps* calls, no IRQL
 * query, nothing that touches the kernel's own state.
 */
VOID     SvTraceWatchHit(_In_ UINT32 HookId, _In_ UINT32 Type, _In_ UINT64 Rip,
                         _In_ UINT64 Gpa, _In_ UINT64 ErrorCode,
                         _In_ UINT32 Processor);

/*
 * Where the ring lives, so a client can read it out of driver memory rather than
 * asking for a copy.  The producer counter is monotonic; tracking what has
 * already been seen, and noticing when it has been lapped, is the client's job.
 */
VOID     SvTraceDescribeRing(_Out_ UINT64* Ring, _Out_ UINT64* Produced,
                             _Out_ UINT64* Records, _Out_ UINT64* RecordSize);
VOID     SvTraceReset(VOID);

/*
 * A client publishing how far it has drained the ring.  Nothing else moves the
 * consumer index - clients read the ring directly - so without this the driver
 * cannot tell a record that was overwritten unread from one that was read the
 * instant it appeared, and the drop counter says everything was lost.
 */
VOID     SvTraceSetConsumed(_In_ UINT64 Sequence);

/*
 * Where a traced function returns to when its hook asked for the result.  Not
 * called from C: SvTracePushReturn writes this address over the return address
 * the caller pushed, so the function's own RET lands here.
 */
VOID     AsmTraceReturn(VOID);

/* Called by that stub; returns where the function was really going. */
UINT64   SvTraceReturnEntry(_In_ UINT64 Rax, _In_ UINT64 Rsp);

/* Calls whose result could not be captured, for lack of a slot or depth. */
VOID     SvTraceReturnCounters(_Out_ UINT64* Lost);

/* The most recently captured return value, for the self-test. */
VOID     SvTraceLastReturn(_Out_ UINT64* Value);

/*
 * The arguments of the most recent exec trace, and how many there have been.
 * A drain buffer is far too big to put on a stack, and the self-test only needs
 * to know that the last call was captured correctly.
 */
VOID     SvTraceLastExec(_Out_writes_(4) UINT64* Arguments, _Out_ UINT32* Records);
VOID     SvTraceCounters(_Out_ UINT64* Produced, _Out_ UINT64* Dropped,
                         _Out_ UINT64* Filtered);

/* svmasm.asm */
VOID     AsmTraceEntry(VOID);
