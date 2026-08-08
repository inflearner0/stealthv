/*
 * memory.h - reading and writing guest memory on behalf of a client.
 *
 * The point of doing this here rather than with ReadProcessMemory is what the
 * hypervisor already has: an identity map of every guest physical page, and a
 * worker thread running in system context.  A read can therefore reach another
 * process without opening a handle to it, without attaching anything the target
 * can see, and without the target's own protections being consulted - and a
 * physical read reaches memory that no virtual address currently describes.
 *
 * All three run on the worker thread at PASSIVE_LEVEL.  None of them may be
 * called from the exit handler: attaching to a process, mapping physical
 * memory and surviving a page fault are all illegal with GIF clear.
 */

#pragma once

#include <ntddk.h>
#include "svmhvctl.h"

/*
 * memory.c needs ntifs.h for KAPC_STATE and KeStackAttachProcess, and includes
 * it *before* this header.  It cannot be included here: ntifs.h and ntddk.h
 * redefine each other's types unless ntifs.h comes first, and every other
 * translation unit that reaches this header has already taken ntddk.h.
 */

/*
 * Copy MemoryLength bytes from MemoryAddress into MemoryData, optionally in the
 * address space of MemoryProcessId.  Short reads are a success: MemoryReturned
 * says how much was readable, so a client walking a structure that runs into an
 * unmapped page gets the part that existed rather than nothing.
 */
NTSTATUS SvMemoryRead(_Inout_ SVMHV_HOOK_REQUEST* Request);

/* The same in reverse: MemoryData -> MemoryAddress. */
NTSTATUS SvMemoryWrite(_Inout_ SVMHV_HOOK_REQUEST* Request);

/*
 * Read guest physical memory directly.  No page tables are consulted, so this
 * sees pages that are not mapped anywhere - and it is the only way to observe
 * what the nested page tables are actually presenting.
 */
NTSTATUS SvMemoryReadPhysical(_Inout_ SVMHV_HOOK_REQUEST* Request);

/*
 * Look up \Driver\<name> and hand back the address of its DRIVER_OBJECT.
 *
 * This is the one thing about a driver that a client cannot reach with a read:
 * the object lives in the object namespace, not at any address the image
 * advertises.  With it, everything else follows from reads the client already
 * has - and what follows is the dispatch table, which is the map of every way
 * that driver can be entered.  A .sys usually exports nothing, so for reverse
 * engineering one this is worth more than the symbol table it does not have.
 *
 * MemoryData carries the name in on the way in and the address out.
 */
NTSTATUS SvMemoryDriverObject(_Inout_ SVMHV_HOOK_REQUEST* Request);

/*
 * Attach to a process so that a user-mode address means something.
 *
 * These live here rather than in hook.c only because KAPC_STATE and
 * KeStackAttachProcess come from ntifs.h, which cannot be included alongside
 * the ntddk.h everything else has already taken.  The state is carried in an
 * opaque buffer for the same reason: hook.c must be able to hold one without
 * being able to see the type.  PASSIVE_LEVEL, and every attach needs its
 * detach.
 */
typedef struct _SVMHV_ATTACH
{
    UINT8 Opaque[64];               /* a KAPC_STATE, sized with room to spare */
    PVOID Process;                  /* NULL when nothing was attached         */
} SVMHV_ATTACH;

NTSTATUS SvMemoryAttachProcess(_In_ UINT32 ProcessId, _Out_ SVMHV_ATTACH* Attach);
VOID     SvMemoryDetachProcess(_Inout_ SVMHV_ATTACH* Attach);
