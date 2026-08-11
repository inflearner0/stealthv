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

/*
 * A watch record that has been claimed and filled but not published, because
 * the interesting half of it - what the store actually wrote - does not exist
 * yet.  Lives in the VIRTUAL_CPU: one processor can only be inside one store.
 */
typedef struct _SVMHV_WATCH_PENDING
{
    SVMHV_TRACE_RECORD* Record;
    UINT64              Sequence;
    const VOID*         Address;    /* inside the page alias, where to re-read */
    UINT32              Width;
} SVMHV_WATCH_PENDING;

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
 * query, nothing that touches the kernel's own state.  Cr3 is taken from the
 * VMCB and stands in for the process id the exec path gets from Ps*.
 *
 * WatchVa is a system alias of the faulting page, or NULL.  When it is present
 * the recorder reads the qword at the faulting offset and holds the record
 * back, unpublished, so that SvTraceWatchComplete can fill in what the store
 * left there.  A held record is invisible to readers until it is completed,
 * which the publication protocol already handles - CommitSequence does not
 * match, so the slot is skipped.
 */
VOID     SvTraceWatchHit(_In_ UINT32 HookId, _In_ UINT32 Type, _In_ UINT64 Rip,
                         _In_ UINT64 Gpa, _In_ UINT64 ErrorCode,
                         _In_ UINT32 Processor, _In_ UINT64 Cr3,
                         _In_opt_ const VOID* WatchVa,
                         _Inout_ SVMHV_WATCH_PENDING* Pending);

/*
 * Finish a record SvTraceWatchHit held back, reading the watched qword a second
 * time now that the store has retired, and publish it.  Called from the exit
 * that returns this processor to the primary view - which is the very next exit
 * it takes, because nothing else in the shadow hierarchy is executable - and
 * defensively from anywhere else that could reach an exit with one outstanding.
 * Does nothing when there is nothing pending.
 */
VOID     SvTraceWatchComplete(_Inout_ SVMHV_WATCH_PENDING* Pending);

/*
 * One instruction of a single-stepped run.  Host context, GIF clear, same
 * rules as the watch path: nothing that touches the kernel's own state.
 */
/*
 * Stash the last branch this processor's guest took, read out of the VMCB once
 * per exit.  Every recorder that runs in host context picks it up from here.
 *
 * A stash rather than a parameter on each of them: the value is a property of
 * the exit, not of the record, and threading it through four signatures would
 * mean every future recorder having to remember to carry it.  Written once at
 * the top of the exit handler, read within the same exit, per processor - so
 * there is nothing to synchronise.
 */
VOID     SvTraceSetBranch(_In_ UINT32 Processor, _In_ UINT64 From,
                          _In_ UINT64 To);

VOID     SvTraceStep(_In_ UINT64 Rip, _In_ UINT64 Rsp, _In_ UINT64 Rflags,
                     _In_ UINT64 Cr3, _In_ UINT32 Processor,
                     _In_reads_(CodeLength) const UINT8* Code,
                     _In_ UINT32 CodeLength, _In_ BOOLEAN GuestTf);

/*
 * An MSR or I/O port access that somebody asked to be told about.  One shape
 * for both because they are the same record with different names for the
 * fields: Which is the MSR number or the port, Value what moved, IsWrite the
 * direction, Width the operand size, and Raw whatever the exit information had
 * that the client might want to decode itself.
 */
VOID     SvTraceRegister(_In_ UINT32 Type, _In_ UINT64 Rip, _In_ UINT64 Cr3,
                         _In_ UINT32 Processor, _In_ UINT64 Which,
                         _In_ UINT64 Value, _In_ UINT32 IsWrite,
                         _In_ UINT32 Width, _In_ UINT64 Raw);

/*
 * A user-mode execution hook firing.  Host context with GIF clear, which is
 * what makes this a different function from SvTraceExecEntry rather than a
 * parameter to it: no Ps* calls, so no process id and no image name, and no
 * argument captures, because dereferencing a pointer needs a context where a
 * page fault is legal.  CR3 is what identifies the process instead.
 */
VOID     SvTraceUserExec(_In_ UINT32 HookId, _In_ UINT64 Target,
                         _In_ UINT64 Rsp, _In_ UINT64 Cr3,
                         _In_ UINT32 Processor,
                         _In_reads_(4) const UINT64* Arguments,
                         _In_ UINT64 ReturnAddress);

/*
 * Where the ring lives, so a client can read it out of driver memory rather than
 * asking for a copy.  The producer counter is an absolute, monotonic cursor;
 * tracking what has already been seen, and noticing when it has been lapped,
 * is the client's job.
 */
VOID     SvTraceDescribeRing(_Out_ UINT64* Ring, _Out_ UINT64* Produced,
                             _Out_ UINT64* Records, _Out_ UINT64* RecordSize);

/*
 * A stable cursor generation, the oldest sequence still belonging to it, and
 * the one-past-most-recent claimed sequence.  Generation is odd only while a
 * reset is in progress, in which case a client must retry rather than consume.
 */
VOID     SvTraceCursorState(_Out_ UINT64* Head, _Out_ UINT64* Floor,
                            _Out_ UINT64* Generation);
VOID     SvTraceReset(VOID);

/*
 * An optional acknowledgement that is strictly telemetry: it changes only the
 * driver's overwrite/loss accounting, never the trace contents.  Sequence is
 * the absolute cursor returned by SvTraceCursorState, not a reset-relative
 * count.  Readers do not need to call this in order to retain their cursor.
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
