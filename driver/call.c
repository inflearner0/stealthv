/*
 * call.c - call a function in the guest with arguments of your choosing.
 * See call.h, particularly the part about what the __try does not cover.
 */

#include "call.h"
#include "svmhv.h"
#include "memory.h"
#include "control.h"

static volatile LONG64 g_Calls;
static volatile LONG64 g_Faulted;

/*
 * Always eight arguments, whatever the caller asked for.
 *
 * The Microsoft x64 calling convention is caller-cleaned and the callee reads
 * only the parameters it declares, so passing more than a function takes is
 * harmless - the extra ones sit in registers it ignores and in stack slots it
 * never reads.  That means one function pointer type covers every arity up to
 * eight, with no thunk and no assembly, and the argument count is only used to
 * decide how many of the caller's values to believe.
 */
typedef UINT64 (*SVMHV_CALL_TARGET)(UINT64, UINT64, UINT64, UINT64,
                                    UINT64, UINT64, UINT64, UINT64);

NTSTATUS SvCallFunction(_Inout_ SVMHV_HOOK_REQUEST* Request)
{
    SVMHV_ATTACH attach = { 0 };
    UINT64 arguments[SVMHV_CALL_MAX_ARGS] = { 0 };
    const UINT64 target = Request->MemoryAddress;
    UINT64 result = 0;
    UINT64 started;
    UINT64 elapsed = 0;
    UINT32 count = 0;
    UINT32 steps = 0;
    UINT32 exception = 0;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN attached = FALSE;
    BOOLEAN pinned = FALSE;
    ULONG i;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return STATUS_INVALID_LEVEL;
    }

    RtlCopyMemory(arguments, Request->MemoryData, sizeof(arguments));
    RtlCopyMemory(&count, Request->MemoryData + sizeof(arguments),
                  sizeof(count));
    RtlCopyMemory(&steps, Request->MemoryData + sizeof(arguments) + 4,
                  sizeof(steps));
    if (count > SVMHV_CALL_MAX_ARGS)
    {
        count = SVMHV_CALL_MAX_ARGS;
    }
    if (steps > SVMHV_STEP_MAX)
    {
        steps = SVMHV_STEP_MAX;
    }
    for (i = count; i < SVMHV_CALL_MAX_ARGS; i++)
    {
        arguments[i] = 0;
    }

    /*
     * A shallow guard, on purpose; see call.h.  It catches the mistake that
     * actually happens - a symbol that resolved to nothing, or to a user-mode
     * address by accident - and makes no claim about anything past that.
     */
    if (target < (UINT64)MM_SYSTEM_RANGE_START)
    {
        return STATUS_INVALID_ADDRESS;
    }
    if (!MmIsAddressValid((PVOID)target))
    {
        return STATUS_INVALID_ADDRESS;
    }
    if (SvIsHypervisorMemory((PVOID)target))
    {
        /* Re-entering this driver from its own worker thread is not an
           experiment, it is a deadlock with extra steps. */
        return STATUS_ACCESS_DENIED;
    }

    if (Request->MemoryProcessId != 0)
    {
        status = SvMemoryAttachProcess(Request->MemoryProcessId, &attach);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        attached = TRUE;
    }

    InterlockedIncrement64(&g_Calls);

    /*
     * Pin to one processor before arming, and stay pinned until after the
     * window is closed.
     *
     * A step window belongs to the processor it was armed on: SvStepArm writes
     * the trap flag and the #DB intercept into that processor's VMCB.  This
     * thread is an ordinary PASSIVE_LEVEL worker and the scheduler is free to
     * move it, so without this the arm can land on one processor and the disarm
     * on another - leaving the first one stepping whatever runs on it until the
     * count expires, and disarming a window on the second that was never there.
     * Bounded, because the count still runs out, but it is a burst of exits on
     * an unrelated processor and a trace full of code nobody asked about.
     */
    if (steps != 0)
    {
        KeSetSystemAffinityThreadEx((KAFFINITY)1
                                    << (KeGetCurrentProcessorNumberEx(NULL) & 0x3F));
        pinned = TRUE;

        /*
         * Arm as late as possible.  Everything between here and the call is
         * this function's own epilogue and gets stepped too - unavoidable,
         * since a window is a count of instructions and not a range - but it is
         * a dozen records at the front that a reader skips by looking for the
         * target's address.
         */
        (VOID)AsmStepCall(steps);
    }

    started = __rdtsc();

    __try
    {
        result = ((SVMHV_CALL_TARGET)target)(
            arguments[0], arguments[1], arguments[2], arguments[3],
            arguments[4], arguments[5], arguments[6], arguments[7]);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        exception = (UINT32)GetExceptionCode();
        InterlockedIncrement64(&g_Faulted);
        status = STATUS_UNHANDLED_EXCEPTION;
    }

    elapsed = __rdtsc() - started;

    /*
     * Close the window immediately.  Left to expire it records this function's
     * own epilogue, which is both useless and the majority of a short call's
     * records; see SVMHV_HV_STEP_DISARM.
     */
    if (steps != 0)
    {
        (VOID)AsmStepCall(SVMHV_HV_STEP_DISARM);
    }
    if (pinned)
    {
        KeRevertToUserAffinityThreadEx(0);
    }

    if (attached)
    {
        SvMemoryDetachProcess(&attach);
    }

    RtlZeroMemory(Request->MemoryData, SVMHV_CALL_ARGS);
    RtlCopyMemory(Request->MemoryData,      &result,    sizeof(result));
    RtlCopyMemory(Request->MemoryData + 8,  &elapsed,   sizeof(elapsed));
    RtlCopyMemory(Request->MemoryData + 16, &exception, sizeof(exception));
    Request->MemoryReturned = SVMHV_CALL_ARGS;

    return status;
}

VOID SvCallCounters(_Out_ UINT64* Calls, _Out_ UINT64* Faulted)
{
    *Calls = (UINT64)InterlockedCompareExchange64(&g_Calls, 0, 0);
    *Faulted = (UINT64)InterlockedCompareExchange64(&g_Faulted, 0, 0);
}
