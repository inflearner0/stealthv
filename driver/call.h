/*
 * call.h - call a function in the guest with arguments of your choosing.
 *
 * Everything else here answers "what does this code do when the machine happens
 * to run it".  This answers "what does it do for this input", which is the
 * question that turns reading a disassembly into an experiment - and it is the
 * one question a hypervisor that only observes can never answer, because the
 * input is whatever the guest felt like passing.
 *
 * It runs on the control worker: a system thread at PASSIVE_LEVEL, in system
 * context, with a full kernel stack and page faults legal.  That is the only
 * context in this driver where calling arbitrary code is even arguable - the
 * exit handler runs with GIF clear on a private stack and could not survive the
 * first thing a real function does.
 *
 * What this cannot protect you from
 * ---------------------------------
 * Calling a function with arguments it was not written for runs that function.
 * There is a __try around it and it buys less than it looks like it does: a
 * reference to an invalid *kernel* address is not an exception Windows raises,
 * it is MiSystemFault deciding the reference is invalid and calling
 * KeBugCheckEx, with nothing for a handler to catch.  The same lesson the trace
 * stack walk learned, in a place where it is inherent rather than fixable.
 *
 * So the guard here is deliberately shallow - kernel address, currently valid,
 * not one of ours - because a deep one would be a promise this cannot keep.  A
 * function called with the wrong arguments takes the machine down, and the
 * thing that makes that survivable is the snapshot next door, not this.
 */

#pragma once

#include "svm.h"
#include "svmhvctl.h"

/*
 * Call Request->MemoryAddress with up to SVMHV_CALL_MAX_ARGS arguments taken
 * from MemoryData, optionally in the address space of MemoryProcessId - which
 * is what makes a kernel function that dereferences a user pointer callable at
 * all.  The return value, the cycles it took and any exception code come back
 * in MemoryData.  PASSIVE_LEVEL only.
 */
NTSTATUS SvCallFunction(_Inout_ SVMHV_HOOK_REQUEST* Request);

/* How many calls have been made, and how many raised something catchable. */
VOID     SvCallCounters(_Out_ UINT64* Calls, _Out_ UINT64* Faulted);
