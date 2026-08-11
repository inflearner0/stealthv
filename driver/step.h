/*
 * step.h - single-stepping the guest, without the guest being able to tell.
 *
 * AMD has no Monitor Trap Flag.  The only way to give a processor exactly one
 * instruction of progress and get control back is RFLAGS.TF and the #DB it
 * raises, which is a problem for a hypervisor that is trying not to be noticed:
 * TF is architecturally visible, and `pushfq; pop rax; test ah, 1` is two
 * instructions of anti-debug that every packer already contains.
 *
 * SVM answers that, where Intel does not.  PUSHF and POPF each have an
 * intercept bit of their own, so while a processor is stepping, both are
 * trapped and emulated: what the guest pushes is RFLAGS with *its* TF, and what
 * it pops sets the flag it thinks it set while ours stays on underneath.  The
 * two intercepts are armed and disarmed with the step, so a processor that is
 * not stepping pays nothing and looks like it did before.
 *
 * How far that actually goes, measured rather than claimed:
 *
 * Emulating either instruction means touching the guest's stack, and the exit
 * handler can only do that where the address is one it can reach.  Kernel space
 * is mapped the same in every CR3, so a kernel-mode step is fine.  A *user*
 * stack is not: the host CR3 at an exit is whichever address space this
 * processor happened to launch in, so unless that is the process being stepped
 * - it usually is not - the emulation cannot be done, and doing it anyway would
 * write eight bytes into an unrelated process.
 *
 * So it gives up instead, drops both intercepts for the rest of the window, and
 * records that it did.  A user-mode step therefore leaves TF visible to a guest
 * that looks, and SvStepCounters says how often that has happened.  This is
 * reported rather than hidden because a concealment feature that quietly does
 * not work is worse than one that is absent: closing it means switching CR3
 * inside the exit handler, which is a real technique and a much bigger change
 * than this one.
 *
 * Stepping is per-processor, because that is what a VMCB is.  It is also always
 * bounded: a step count is decremented on every #DB and the machinery unarms
 * itself when it reaches zero, so a caller cannot leave a processor trapping
 * forever by forgetting to stop it.
 *
 * Two callers:
 *
 *   SVMHV_STEP_WATCH   one instruction, to let a store that a watchpoint
 *                      trapped actually retire.  See hook.c - this is the
 *                      whole reason the file exists.
 *   SVMHV_STEP_TRACE   a caller-requested run of instructions, recorded into
 *                      the trace ring one record each.
 */

#pragma once

#include "svm.h"
#include "svmhvctl.h"

struct _VIRTUAL_CPU;

/* Why this processor is stepping.  Zero means it is not. */
#define SVMHV_STEP_NONE     0
#define SVMHV_STEP_WATCH    1
#define SVMHV_STEP_TRACE    2

/*
 * One instruction to let a trapped I/O access happen.
 *
 * Same shape as the watchpoint: the IN or OUT did not execute, so the port is
 * unarmed in the IOPM, the instruction is allowed through, and the bit goes
 * back on the #DB.  Emulating the access instead was the alternative and it is
 * a much worse one - INS and OUTS with a REP prefix are a memory copy and a
 * loop, and getting either wrong writes to the wrong place or hangs the device.
 * Letting the processor do it is exact by construction.
 */
#define SVMHV_STEP_IO       4

/*
 * Not stepping any more, but the trap flag we set may still be in flight.
 *
 * An interrupt delivered while a window is open pushes RFLAGS - with our TF in
 * it - onto the interrupt frame and clears TF for the handler.  Ending the
 * window at that point clears a flag that is already clear and drops the #DB
 * intercept, and then the handler's IRET puts TF back from the stack.  The next
 * instruction raises a #DB that nothing is intercepting any more, so the guest
 * receives a single-step exception it never asked for, in whatever code
 * happened to be running.
 *
 * That is not theoretical either: it landed inside the __except of the driver's
 * own memory-write path and turned ten of twenty-four writes through a
 * watchpoint into "wrote 0 bytes" - writes which had in fact happened.
 *
 * So the intercept stays armed with the flag cleared, and the first #DB to
 * arrive is swallowed, TF forced back to the guest's own value, and everything
 * dropped.  One stale exception is all there can ever be.
 */
#define SVMHV_STEP_DRAIN    5

/*
 * The most instructions one arm may ask for.  A bound rather than a policy: a
 * caller that asks for a million gets a processor that spends the next million
 * instructions taking an exit each, and there is no way to interrupt it from
 * outside because the control worker needs that processor to run.
 */
#define SVMHV_STEP_MAX      4096

typedef struct _SVMHV_STEP_STATE
{
    UINT32  Reason;                 /* SVMHV_STEP_*; NONE when idle          */
    UINT32  Remaining;

    /*
     * The guest's own trap flag, saved when we set ours.  Everything the guest
     * is allowed to see about TF is answered from this, and it is what goes
     * back into RFLAGS when the step count runs out.
     */
    BOOLEAN GuestTf;

    /*
     * Set once we have had to let a PUSHF or POPF run natively because its
     * stack was not ours to touch.  The intercepts stay off for the rest of
     * this window - re-arming them would only fail again - and the guest can
     * see TF until it closes.  Reported, never pretended about.
     */
    BOOLEAN FlagsExposed;

    /* SVMHV_STEP_WATCH: the record to finish and the hook that asked. */
    UINT32  HookId;

    /* SVMHV_STEP_IO: the port to put back in the IOPM afterwards. */
    UINT32  Port;
} SVMHV_STEP_STATE;

/*
 * Begin stepping this processor.  Count instructions, at most SVMHV_STEP_MAX.
 * Called from the exit handler with GIF clear; it only edits the VMCB, so
 * there is nothing here that could fault or block.  Arming while already armed
 * replaces the previous run.
 */
VOID SvStepArm(_Inout_ struct _VIRTUAL_CPU* Cpu, _In_ UINT32 Count,
               _In_ UINT32 Reason);

/* Stop stepping and put the guest's own trap flag back. */
VOID SvStepDisarm(_Inout_ struct _VIRTUAL_CPU* Cpu);

/*
 * Stop stepping, but keep the #DB intercept until one more arrives.  For
 * ending a window that did not end at its own #DB, where the trap flag may be
 * sitting on an interrupt frame waiting to come back; see SVMHV_STEP_DRAIN.
 */
VOID SvStepDrain(_Inout_ struct _VIRTUAL_CPU* Cpu);

/*
 * A #DB arrived.  Returns TRUE if it was ours - in which case it has been
 * consumed and must not reach the guest - and FALSE if the guest was
 * single-stepping on its own account and should get its exception back.
 */
BOOLEAN SvStepHandleDebugException(_Inout_ struct _VIRTUAL_CPU* Cpu);

/*
 * PUSHF and POPF, emulated so that TF reads back the way the guest left it.
 * Both return FALSE when the guest's stack could not be reached from host
 * context, which drops the two intercepts for the rest of the window and lets
 * the instruction run for real; see FlagsExposed.
 */
BOOLEAN SvStepEmulatePushf(_Inout_ struct _VIRTUAL_CPU* Cpu);
BOOLEAN SvStepEmulatePopf(_Inout_ struct _VIRTUAL_CPU* Cpu);

/*
 * How many steps have been taken, how many windows ended with the trap flag
 * exposed, and how many #DBs were handed to the guest during a window because
 * they did not look like ours.  The last one should be zero unless something in
 * the guest is using hardware breakpoints.
 */
VOID SvStepCounters(_Out_ UINT64* Steps, _Out_ UINT64* Exposed,
                    _Out_ UINT64* NotOurs, _Out_ UINT64* Drained);
