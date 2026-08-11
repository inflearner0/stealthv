/*
 * npt.h - nested page tables.
 *
 * Three complete identity-mapping hierarchies are built at load time:
 *
 *   g_NptPrimary      every guest physical page maps to itself, RWX.
 *   g_NptShadow       the same, but nothing is executable.
 *   g_NptPermissive   the same as primary, and never restricted by anything.
 *
 * A hooked page is the only page that differs between the first two: in the
 * primary hierarchy it maps the *original* page and is not executable, in the
 * shadow hierarchy it maps a patched *copy* and is the only executable thing
 * there.  The exit handler switches a processor's NCr3 between the two on
 * nested page faults, which is what makes a code hook invisible to anything
 * that only reads memory.  See hook.c.
 *
 * The third exists because that scheme does not work for a *watchpoint*, and
 * used to livelock on one.  An execution hook runs the code that is on the
 * page it trapped, so the shadow hierarchy having that one page executable is
 * enough.  A watchpoint traps a store, and the instruction doing the storing is
 * almost never on the page being stored to - so switching to the shadow
 * hierarchy to permit the write also makes the storing instruction impossible
 * to fetch.  The re-fetch faults, the handler reads that as execution having
 * left the page, sends the processor back to the primary hierarchy, and the
 * store faults again: 168000 nested page faults for one eight-byte write, with
 * the store never retiring.
 *
 * So a watch switches to the permissive hierarchy instead, where both the store
 * and the fetch succeed, and gets control back after exactly one instruction
 * with a single step.  Hidden pages are hidden here too - the whole point of a
 * view with no restrictions is that it has no restrictions *of ours*, not that
 * it undoes the concealment for an instruction at a time.
 */

#pragma once

#include "svm.h"

/* Which of the three a processor is currently using; see VIRTUAL_CPU. */
#define SVMHV_NPT_PRIMARY       0
#define SVMHV_NPT_SHADOW        1
#define SVMHV_NPT_PERMISSIVE    2

typedef struct _NPT_HIERARCHY
{
    UINT64* Pml4;
    UINT64  Pml4Pa;
    UINT64  LeafFlags;          /* OR'ed into every identity leaf entry     */
} NPT_HIERARCHY;

extern NPT_HIERARCHY g_NptPrimary;
extern NPT_HIERARCHY g_NptShadow;
extern NPT_HIERARCHY g_NptPermissive;

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
 * Points every page of the range at a private zero page in every hierarchy, so
 * a guest reading our VMCBs and host stacks out of physical memory sees
 * nothing.  Only safe for memory the driver itself never touches from guest
 * context.  One backing page each rather than one shared between them: see the
 * comment on g_HidePool.
 *
 * "Every hierarchy" includes the permissive one, and that is the whole reason
 * it is built by the same code rather than as a plain identity map: a view a
 * processor enters for one instruction is still a view a guest could read
 * itself through.
 */
NTSTATUS SvNptHideRange(_In_ PVOID Va, _In_ SIZE_T Size);

/* TRUE if the page belongs to the nested page tables, the split pool or the
   backing for a hidden page.  Nothing there may be watched. */
BOOLEAN  SvNptOwnsPage(_In_ PVOID Address);

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
