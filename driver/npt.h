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

/* ------------------------------------------------------------- coverage */

/*
 * Take a permission away from every page in a range and give it back one page
 * at a time, recording the first time each is used.
 *
 * This is the thing a hypervisor can do that a debugger cannot.  A module list
 * describes the code somebody declared; it says nothing about code that was
 * mapped by hand and never written to disk, which is where anything worth
 * reverse-engineering has been hiding for a decade.  Marking every page
 * non-executable and watching which ones fault answers "what code has actually
 * run" from underneath the guest, with no cooperation from it - and everything
 * in the answer that no module claims is, by construction, code nobody wanted
 * found.  Marking every page read-only instead answers the other half: which
 * pages were written to, which is where an unpacker shows itself.
 *
 * Cost is bounded and one-way.  A page faults once, is granted the permission
 * for good, and never faults again, so the total is one exit per distinct page
 * ever touched rather than one per access.
 *
 * The range is split to 4 KiB *before* the sweep is armed, because a nested
 * page fault must never have to allocate a page table - see the fault handler.
 * That is also what bounds the range: splitting costs one table page per 2 MiB,
 * out of a pool allocated for the purpose when the sweep starts.
 */
#define SVMHV_SWEEP_OFF         0
#define SVMHV_SWEEP_EXECUTE     1   /* which pages have run                 */
#define SVMHV_SWEEP_WRITE       2   /* which pages have been written         */

/*
 * Both at once, which is the mode worth having.
 *
 * A page that was written and then executed is a page whose code arrived after
 * the mapping did, and almost nothing legitimate does that: an image is loaded
 * by the section manager and arrives executable.  Code copied into pool memory
 * and jumped to is a manual map, an unpacker, or a JIT - and the first two are
 * what there is no other way to find, because nothing on disk and no module
 * list describes them.
 *
 * Order is the whole signal, so the state of each page is remembered rather
 * than inferred: written-then-executed is the find, executed-then-written is
 * self-modifying code, and either on its own is ordinary.
 */
#define SVMHV_SWEEP_BOTH        3

/* What a page has had done to it, reported with its first-execution record. */
#define SVMHV_PAGE_WRITTEN      0x01
#define SVMHV_PAGE_EXECUTED     0x02
#define SVMHV_PAGE_WRITE_FIRST  0x04    /* the write came before the fetch */

/*
 * Set when this grant is worth a trace record.
 *
 * In the single-permission modes every first touch is the answer, so it is
 * always set.  In SVMHV_SWEEP_BOTH it is set only for the write-then-execute
 * transition, because that is the finding and everything else is noise: a
 * 2 GiB range in both modes produced 28779 first-touch records on an idle
 * guest, and a reader that shows the newest two hundred of those will never
 * show the one page that mattered.  The grants still happen and are still
 * counted; they simply are not narrated.
 */
#define SVMHV_PAGE_REPORT       0x08

NTSTATUS SvNptSweepArm(_In_ UINT64 Base, _In_ UINT64 Size, _In_ ULONG Mode);
VOID     SvNptSweepDisarm(VOID);

/*
 * Exit-handler side.  TRUE if Gpa is inside an armed sweep and still faulting,
 * in which case the permission has been granted and the caller should record
 * the page and re-execute.  No allocation: every table it touches already
 * exists.
 */
BOOLEAN  SvNptSweepGrant(_In_ UINT64 Gpa, _In_ UINT64 FaultInfo,
                         _Out_ UINT32* State);

/* Pages granted so far, and how many the range holds. */
VOID     SvNptSweepState(_Out_ ULONG* Mode, _Out_ UINT64* Base, _Out_ UINT64* Size,
                         _Out_ UINT64* Granted);
