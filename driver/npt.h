/*
 * npt.h - nested page tables.
 *
 * Two complete identity-mapping hierarchies are built at load time:
 *
 *   g_NptPrimary   every guest physical page maps to itself, RWX.
 *   g_NptShadow    the same, but nothing is executable.
 *
 * A hooked page is the only page that differs between them: in the primary
 * hierarchy it maps the *original* page and is not executable, in the shadow
 * hierarchy it maps a patched *copy* and is the only executable thing there.
 * The exit handler switches a processor's NCr3 between the two on nested page
 * faults, which is what makes a code hook invisible to anything that only
 * reads memory.  See hook.c.
 */

#pragma once

#include "svm.h"

typedef struct _NPT_HIERARCHY
{
    UINT64* Pml4;
    UINT64  Pml4Pa;
    UINT64  LeafFlags;          /* OR'ed into every identity leaf entry     */
} NPT_HIERARCHY;

extern NPT_HIERARCHY g_NptPrimary;
extern NPT_HIERARCHY g_NptShadow;

NTSTATUS SvNptInitialize(VOID);
VOID     SvNptFree(VOID);

/*
 * Walks Gpa down to 4 KiB granularity, splitting a 1 GiB or 2 MiB leaf on the
 * way if needed, and returns a pointer to the final PTE.  PASSIVE_LEVEL only
 * (it hands out pages from a fixed pool, so it never blocks, but callers
 * always have one).  NULL means the split pool is exhausted.
 */
UINT64*  SvNptSplitTo4Kb(_Inout_ NPT_HIERARCHY* Npt, _In_ UINT64 Gpa);

/*
 * Points every page of the range at a shared zero page in both hierarchies,
 * so a guest reading our VMCBs and host stacks out of physical memory sees
 * nothing.  Only safe for memory the driver itself never touches from guest
 * context.
 */
NTSTATUS SvNptHideRange(_In_ PVOID Va, _In_ SIZE_T Size);

/*
 * Read back the leaf entry that currently describes Gpa, without changing
 * anything.  Level is 1 for a 4 KiB entry, 2 for 2 MiB, 3 for 1 GiB, and 0 if
 * nothing maps it at all.  This is the view that makes a hook legible from
 * outside: the same physical page, described two different ways.
 */
VOID     SvNptQuery(_In_ const NPT_HIERARCHY* Npt, _In_ UINT64 Gpa,
                    _Out_ UINT64* Entry, _Out_ ULONG* Level);

/* Size of the identity map, for the statistics interface. */
UINT64   SvNptCoverage(VOID);
ULONG    SvNptSplitPagesUsed(VOID);
