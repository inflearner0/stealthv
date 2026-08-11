/*
 * usercall.h - call a function in a user-mode process, by borrowing a thread.
 *
 * call.c answers "what does this kernel function return for this input".  This
 * is the same question for a .exe or a .dll, and it cannot be answered the same
 * way: the control worker is a system thread, and user code needs a user thread
 * in the right address space with a user stack under it.  There is no way to
 * manufacture one from here that is less invasive than borrowing an existing
 * one, so that is what this does.
 *
 * How
 * ---
 *   1. Suspend a thread of the target process.
 *   2. Save its user-mode CONTEXT, all of it.
 *   3. Allocate one page in the process and put a two-byte infinite loop in it.
 *      That page is where the call is told to return to, and reaching it is how
 *      the call is known to be finished - the thread parks there spinning
 *      instead of running off into code that was never expecting it.
 *   4. Point RIP at the target with the arguments in RCX/RDX/R8/R9, on a stack
 *      well below where the thread was, with the parking page as the return
 *      address.
 *   5. Resume, and poll the thread's RIP until it reaches the parking page.
 *   6. Read RAX, put the saved context back, resume, free the page.
 *
 * What this costs the target
 * --------------------------
 * The borrowed thread does not run its own work while this is happening, so
 * anything waiting on it waits.  If the called function blocks forever the poll
 * times out, and the thread is put back exactly where it was - it loses the
 * time and nothing else, because the original CONTEXT is restored wholesale.
 * The one case that cannot be undone is the called function having side effects
 * on the process, which is inherent in calling it at all, and is what the
 * snapshot next door is for.
 *
 * The thread is chosen by the caller, and the choice matters.  Borrowing a
 * thread that owns a lock and calling something that wants the same lock
 * deadlocks the process until the timeout.  Prefer a thread that is idle in a
 * wait, which for most processes is most of them.
 *
 * Only the four register arguments are passed.  A fifth would have to go in the
 * caller's stack slots, which means knowing the callee's expectations about
 * alignment and home space better than a generic mechanism can.
 */

#pragma once

#include "svm.h"
#include "svmhvctl.h"

/*
 * Call Request->MemoryAddress in Request->MemoryProcessId.  Arguments, the
 * thread to borrow (0 to take the first one the process has) and the timeout
 * come out of MemoryData; the return value and which thread was used go back
 * into it.  PASSIVE_LEVEL, on the control worker.
 */
NTSTATUS SvUserCall(_Inout_ SVMHV_HOOK_REQUEST* Request);
