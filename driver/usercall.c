/*
 * usercall.c - call a function in a user-mode process, by borrowing a thread.
 * See usercall.h for the shape of it and for what it costs the target.
 */

#include <ntifs.h>
#include "usercall.h"
#include "svmhv.h"
#include "memory.h"

#define USERCALL_TAG        'cUvS'

/* Two bytes: jmp $.  The thread parks here when the called function returns. */
static const UINT8 kParkCode[] = { 0xEB, 0xFE };

/*
 * Below the borrowed thread's own RSP before the new frame starts.
 *
 * The thread is suspended, so nothing below its stack pointer is live and this
 * gap is not strictly needed - but a suspended thread's RSP is where the kernel
 * transition left it, and leaving room means a debugger looking at the stack
 * afterwards can still see the frame that was interrupted.
 */
#define USERCALL_STACK_GAP  0x200

/* How often to look at the borrowed thread while waiting for it to park. */
#define USERCALL_POLL_MS    10
#define USERCALL_MIN_MS     50
#define USERCALL_MAX_MS     30000

/*
 * Documented nowhere, and split across two categories.
 *
 * PsGetContextThread and PsSetContextThread are in ntoskrnl.lib, so they link
 * like anything else.  The other three are exported by ntoskrnl.exe and are not
 * in the import library at all, so naming them produces an unresolved __imp_
 * symbol - they have to be looked up by name at run time instead.  There is no
 * supported way to do any of this, which is a fair description of the whole
 * exercise.
 */
NTKERNELAPI NTSTATUS PsGetContextThread(_In_ PETHREAD Thread,
                                        _Inout_ PCONTEXT ThreadContext,
                                        _In_ KPROCESSOR_MODE Mode);
NTKERNELAPI NTSTATUS PsSetContextThread(_In_ PETHREAD Thread,
                                        _In_ PCONTEXT ThreadContext,
                                        _In_ KPROCESSOR_MODE Mode);

typedef NTSTATUS (*PS_SUSPEND_THREAD)(PETHREAD, PULONG);
typedef NTSTATUS (*PS_RESUME_THREAD)(PETHREAD, PULONG);
typedef PETHREAD (*PS_NEXT_PROCESS_THREAD)(PEPROCESS, PETHREAD);

static PS_SUSPEND_THREAD      g_PsSuspendThread;
static PS_RESUME_THREAD       g_PsResumeThread;
static PS_NEXT_PROCESS_THREAD g_PsGetNextProcessThread;

/*
 * Resolved once, on the first call, rather than at load.
 *
 * At load would be tidier and is the wrong trade: this is the only part of the
 * driver that looks up kernel routines by name, that lookup is a behaviour
 * somebody could notice, and there is no reason to perform it on a machine
 * where nobody ever asks for a user-mode call.
 */
static BOOLEAN SvUserCallResolve(VOID)
{
    UNICODE_STRING name;

    if (g_PsSuspendThread != NULL)
    {
        return TRUE;
    }

    RtlInitUnicodeString(&name, L"PsSuspendThread");
    g_PsSuspendThread = (PS_SUSPEND_THREAD)MmGetSystemRoutineAddress(&name);

    RtlInitUnicodeString(&name, L"PsResumeThread");
    g_PsResumeThread = (PS_RESUME_THREAD)MmGetSystemRoutineAddress(&name);

    RtlInitUnicodeString(&name, L"PsGetNextProcessThread");
    g_PsGetNextProcessThread =
        (PS_NEXT_PROCESS_THREAD)MmGetSystemRoutineAddress(&name);

    if (g_PsSuspendThread == NULL || g_PsResumeThread == NULL ||
        g_PsGetNextProcessThread == NULL)
    {
        DbgPrint("svmhv: no user-mode calls: suspend=%p resume=%p next=%p\n",
                 g_PsSuspendThread, g_PsResumeThread, g_PsGetNextProcessThread);
        g_PsSuspendThread = NULL;
        return FALSE;
    }
    return TRUE;
}

#define PsSuspendThread          g_PsSuspendThread
#define PsResumeThread           g_PsResumeThread
#define PsGetNextProcessThread   g_PsGetNextProcessThread

static VOID SvUserCallSleep(_In_ ULONG Milliseconds)
{
    LARGE_INTEGER interval;

    interval.QuadPart = -((LONGLONG)Milliseconds * 10 * 1000);
    (VOID)KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

/*
 * A thread of the process to borrow.  With a thread id, that one; without,
 * whichever the process lists first.
 *
 * "Whichever comes first" is a convenience and a trap, and it is documented as
 * both: the first thread is usually the main one, which for a GUI process is
 * the one pumping messages and is exactly the thread whose absence is most
 * visible.  Naming a thread is better whenever the caller can.
 */
static NTSTATUS SvUserCallPickThread(_In_ PEPROCESS Process, _In_ UINT64 ThreadId,
                                     _Out_ PETHREAD* Thread)
{
    *Thread = NULL;

    if (ThreadId != 0)
    {
        PETHREAD thread = NULL;
        NTSTATUS status = PsLookupThreadByThreadId(
                              (HANDLE)(ULONG_PTR)ThreadId, &thread);

        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (PsGetThreadProcess(thread) != Process)
        {
            ObDereferenceObject(thread);
            return STATUS_INVALID_PARAMETER_MIX;
        }
        *Thread = thread;
        return STATUS_SUCCESS;
    }

    *Thread = PsGetNextProcessThread(Process, NULL);
    return (*Thread != NULL) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

NTSTATUS SvUserCall(_Inout_ SVMHV_HOOK_REQUEST* Request)
{
    SVMHV_ATTACH attach = { 0 };
    PEPROCESS process = NULL;
    PETHREAD thread = NULL;
    CONTEXT* saved = NULL;
    CONTEXT* working = NULL;
    PVOID park = NULL;
    SIZE_T parkSize = PAGE_SIZE;
    UINT64 arguments[4] = { 0 };
    UINT64 threadId = 0;
    UINT64 usedThread = 0;
    UINT64 returned = 0;
    UINT64 parkedAt = 0;
    UINT32 count = 0;
    UINT32 timeout = 0;
    UINT32 waited = 0;
    NTSTATUS status;
    BOOLEAN attached = FALSE;
    BOOLEAN suspended = FALSE;
    BOOLEAN contextSaved = FALSE;
    BOOLEAN parked = FALSE;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return STATUS_INVALID_LEVEL;
    }
    if (!SvUserCallResolve())
    {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    RtlCopyMemory(arguments, Request->MemoryData, sizeof(arguments));
    RtlCopyMemory(&count, Request->MemoryData + 32, sizeof(count));
    RtlCopyMemory(&timeout, Request->MemoryData + 36, sizeof(timeout));
    RtlCopyMemory(&threadId, Request->MemoryData + 40, sizeof(threadId));

    if (count > RTL_NUMBER_OF(arguments))
    {
        count = RTL_NUMBER_OF(arguments);
    }
    if (timeout < USERCALL_MIN_MS) { timeout = 5000; }
    if (timeout > USERCALL_MAX_MS) { timeout = USERCALL_MAX_MS; }

    /* A kernel address here would be call.c's job, and doing it this way would
       run kernel code on a user stack with user-mode segment state. */
    if (Request->MemoryAddress == 0 ||
        Request->MemoryAddress >= (UINT64)MM_SYSTEM_RANGE_START)
    {
        return STATUS_INVALID_ADDRESS;
    }
    if (Request->MemoryProcessId == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupProcessByProcessId(
                 (HANDLE)(ULONG_PTR)Request->MemoryProcessId, &process);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = SvUserCallPickThread(process, threadId, &thread);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(process);
        return status;
    }
    usedThread = (UINT64)(ULONG_PTR)PsGetThreadId(thread);

    /*
     * CONTEXT has to be 16-byte aligned for the XMM half of it, and it is over
     * a kilobyte, so neither of these belongs on a stack.
     */
    saved = (CONTEXT*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(CONTEXT),
                                      USERCALL_TAG);
    working = (CONTEXT*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(CONTEXT),
                                        USERCALL_TAG);
    if (saved == NULL || working == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    /*
     * Suspend first, then read the context.  The other order reads a context
     * belonging to a thread that is still running, which is a snapshot of
     * nothing in particular.
     */
    status = PsSuspendThread(thread, NULL);
    if (!NT_SUCCESS(status))
    {
        goto done;
    }
    suspended = TRUE;

    saved->ContextFlags = CONTEXT_FULL | CONTEXT_FLOATING_POINT;
    status = PsGetContextThread(thread, saved, UserMode);
    if (!NT_SUCCESS(status))
    {
        goto done;
    }
    contextSaved = TRUE;

    if (saved->Rsp == 0)
    {
        /* No user-mode frame: a system thread, or one that has never been out
           to user mode.  Nothing here would mean anything. */
        status = STATUS_INVALID_THREAD;
        goto done;
    }

    status = SvMemoryAttachProcess(Request->MemoryProcessId, &attach);
    if (!NT_SUCCESS(status))
    {
        goto done;
    }
    attached = TRUE;

    status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &park, 0, &parkSize,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        park = NULL;
        goto done;
    }

    __try
    {
        RtlCopyMemory(park, kParkCode, sizeof(kParkCode));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = STATUS_ACCESS_VIOLATION;
        goto done;
    }

    parkedAt = (UINT64)park;

    /*
     * The frame.  At the first instruction of a function the Microsoft x64 ABI
     * has RSP+8 sixteen-byte aligned, because CALL pushed eight bytes onto an
     * aligned stack - so align down, then subtract the return address.  The
     * callee's home space for the four register arguments is the 32 bytes above
     * that, which is stack below where the thread was and therefore free.
     */
    *working = *saved;
    working->Rip = Request->MemoryAddress;
    working->Rsp = ((saved->Rsp - USERCALL_STACK_GAP) & ~(UINT64)0xF) - 8;
    working->Rcx = arguments[0];
    working->Rdx = arguments[1];
    working->R8  = arguments[2];
    working->R9  = arguments[3];
    working->ContextFlags = CONTEXT_FULL;

    __try
    {
        *(volatile UINT64*)working->Rsp = parkedAt;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = STATUS_ACCESS_VIOLATION;
        goto done;
    }

    status = PsSetContextThread(thread, working, UserMode);
    if (!NT_SUCCESS(status))
    {
        goto done;
    }

    SvMemoryDetachProcess(&attach);
    attached = FALSE;

    status = PsResumeThread(thread, NULL);
    if (!NT_SUCCESS(status))
    {
        goto done;
    }
    suspended = FALSE;

    /*
     * Wait for it to park.  Reading the context of a running thread is not
     * meaningful, so each poll suspends, looks, and either keeps the suspension
     * (it has arrived) or resumes and waits again.  Heavier than watching a
     * flag in memory and far more robust: it needs nothing of the target and
     * works whatever the called function does to the stack on its way back.
     */
    for (waited = 0; waited < timeout; waited += USERCALL_POLL_MS)
    {
        SvUserCallSleep(USERCALL_POLL_MS);

        if (!NT_SUCCESS(PsSuspendThread(thread, NULL)))
        {
            continue;
        }

        working->ContextFlags = CONTEXT_FULL;
        if (!NT_SUCCESS(PsGetContextThread(thread, working, UserMode)))
        {
            (VOID)PsResumeThread(thread, NULL);
            continue;
        }

        if (working->Rip == parkedAt)
        {
            suspended = TRUE;
            parked = TRUE;
            returned = working->Rax;
            break;
        }

        (VOID)PsResumeThread(thread, NULL);
    }

    if (!parked)
    {
        /*
         * It never came back.  Suspend it wherever it is and put the original
         * context back anyway - a thread left running inside a call that is not
         * going to return is worse than one yanked out of it, because the
         * parking page is about to be freed underneath it.
         */
        status = STATUS_TIMEOUT;
        if (NT_SUCCESS(PsSuspendThread(thread, NULL)))
        {
            suspended = TRUE;
        }
    }
    else
    {
        status = STATUS_SUCCESS;
    }

done:
    /*
     * Put the thread back exactly as it was, whatever happened.  This is the
     * only part of this file that must not be skipped on any path, which is why
     * every failure above jumps here rather than returning.
     */
    if (contextSaved && thread != NULL)
    {
        saved->ContextFlags = CONTEXT_FULL | CONTEXT_FLOATING_POINT;
        (VOID)PsSetContextThread(thread, saved, UserMode);
    }

    if (park != NULL)
    {
        SIZE_T zero = 0;

        if (!attached &&
            NT_SUCCESS(SvMemoryAttachProcess(Request->MemoryProcessId, &attach)))
        {
            attached = TRUE;
        }
        if (attached)
        {
            (VOID)ZwFreeVirtualMemory(ZwCurrentProcess(), &park, &zero,
                                      MEM_RELEASE);
        }
    }
    if (attached)
    {
        SvMemoryDetachProcess(&attach);
    }

    if (suspended && thread != NULL)
    {
        (VOID)PsResumeThread(thread, NULL);
    }

    if (saved != NULL)   { ExFreePoolWithTag(saved, USERCALL_TAG); }
    if (working != NULL) { ExFreePoolWithTag(working, USERCALL_TAG); }
    if (thread != NULL)  { ObDereferenceObject(thread); }
    if (process != NULL) { ObDereferenceObject(process); }

    RtlZeroMemory(Request->MemoryData, SVMHV_USERCALL_ARGS);
    RtlCopyMemory(Request->MemoryData,      &returned,   sizeof(returned));
    RtlCopyMemory(Request->MemoryData + 8,  &usedThread, sizeof(usedThread));
    RtlCopyMemory(Request->MemoryData + 16, &parkedAt,   sizeof(parkedAt));
    Request->MemoryReturned = SVMHV_USERCALL_ARGS;

    return status;
}
