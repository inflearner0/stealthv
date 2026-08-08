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
