/*
 * npt.c - identity-mapped nested page tables.
 *
 * The whole guest physical address space is mapped eagerly with 1 GiB leaves,
 * which costs one PML4 page plus one PDPT page per 512 GiB - about 2 MiB per
 * hierarchy for a 48-bit machine.  Mapping everything up front means a nested
 * page fault can only ever come from a page we deliberately made faulting, so
 * the fault handler never has to allocate memory with GIF clear.
 *
 * Finer granularity is created on demand by SvNptSplitTo4Kb, from a fixed pool
 * of table pages reserved at load time for the same reason.
 */

#include "npt.h"

NPT_HIERARCHY g_NptPrimary;
NPT_HIERARCHY g_NptShadow;
NPT_HIERARCHY g_NptPermissive;

/*
 * Nested page tables are walked by the processor using physical addresses, so
 * every table has to be turned back into a virtual address to be edited.  All
 * of them come out of a handful of physically contiguous blocks, which makes
 * that translation a subtraction instead of a page-table walk.
 */
#define NPT_MAX_BLOCKS      8

typedef struct _NPT_BLOCK
{
    PVOID   Va;
    UINT64  Pa;
    SIZE_T  Size;
} NPT_BLOCK;

static NPT_BLOCK g_Blocks[NPT_MAX_BLOCKS];
static ULONG     g_BlockCount;

/*
 * Pool of spare table pages for splitting large leaves.
 *
 * Raised from 768 when the permissive hierarchy arrived: hiding a page splits
 * a 1 GiB leaf down to 4 KiB in every hierarchy that describes it, so the cost
 * of the driver's own hidden pages went up by half.  Hooks are unaffected -
 * they only ever split the primary and shadow views - but running out here is
 * a load-time failure with an obscure message, so the headroom is worth more
 * than the megabyte.
 */
#define NPT_SPLIT_POOL_PAGES 1152

static UINT8*        g_SplitPool;
static UINT64        g_SplitPoolPa;
static volatile LONG g_SplitPoolNext;

/*
 * Backing for hidden pages: one private zero page for each page that gets
 * hidden, bump-allocated from a block reserved at load time.
 *
 * One shared page for all of them would be cheaper and was what this did
 * originally, and it was wrong twice over.  A shared page has to be read-only,
 * or a guest can write a pattern into one hidden page and read it back out of
 * another - two supposedly distinct physical pages that mirror each other is a
 * sharper tell than anything their contents would have given away.  And
 * read-only means a guest write to a hidden page faults forever: the handler
 * cannot retire the store without decoding it, the mapping can never satisfy
 * it, and the retry limit turns that into a bugcheck.  A page each is writable,
 * so the store lands somewhere harmless and the guest simply carries on.
 */
static UINT8*        g_HidePool;
static UINT64        g_HidePoolPa;
static ULONG         g_HidePoolPages;
static volatile LONG g_HidePoolNext;

static ULONG   g_Pml4Entries;       /* PML4 slots covered (512 GiB each)    */
static BOOLEAN g_Use1GbPages;

/* ------------------------------------------------------------- plumbing */

static PVOID SvNptAllocBlock(_In_ ULONG Pages, _Out_ UINT64* PhysicalAddress)
{
    PHYSICAL_ADDRESS highest;
    PVOID va;

    *PhysicalAddress = 0;

    if (g_BlockCount >= NPT_MAX_BLOCKS)
    {
        NT_ASSERT(FALSE);
        return NULL;
    }

    highest.QuadPart = MAXULONG64;
    va = MmAllocateContiguousMemory((SIZE_T)Pages * PAGE_SIZE, highest);
    if (va == NULL)
    {
        return NULL;
    }

    RtlZeroMemory(va, (SIZE_T)Pages * PAGE_SIZE);

    g_Blocks[g_BlockCount].Va   = va;
    g_Blocks[g_BlockCount].Pa   = (UINT64)MmGetPhysicalAddress(va).QuadPart;
    g_Blocks[g_BlockCount].Size = (SIZE_T)Pages * PAGE_SIZE;
    *PhysicalAddress = g_Blocks[g_BlockCount].Pa;
    g_BlockCount++;

    return va;
}

/* Physical -> virtual, for table pages only. */
static UINT64* SvNptTableVa(_In_ UINT64 PhysicalAddress)
{
    ULONG i;

    for (i = 0; i < g_BlockCount; i++)
    {
        if (PhysicalAddress >= g_Blocks[i].Pa &&
            PhysicalAddress < g_Blocks[i].Pa + g_Blocks[i].Size)
        {
            return (UINT64*)((UINT8*)g_Blocks[i].Va +
                             (PhysicalAddress - g_Blocks[i].Pa));
        }
    }

    return NULL;
}

static UINT64* SvNptAllocTable(_Out_ UINT64* PhysicalAddress)
{
    LONG index = InterlockedIncrement(&g_SplitPoolNext) - 1;

    if (index < 0 || (ULONG)index >= NPT_SPLIT_POOL_PAGES)
    {
        *PhysicalAddress = 0;
        return NULL;
    }

    *PhysicalAddress = g_SplitPoolPa + (UINT64)index * PAGE_SIZE;
    return (UINT64*)(g_SplitPool + (SIZE_T)index * PAGE_SIZE);
}

/* --------------------------------------------------------------- build */

static NTSTATUS SvNptBuildHierarchy(_Out_ NPT_HIERARCHY* Npt, _In_ UINT64 LeafFlags)
{
    ULONG pages;
    ULONG i;
    ULONG j;
    UINT8* block;
    UINT64 blockPa;

    RtlZeroMemory(Npt, sizeof(*Npt));
    Npt->LeafFlags = LeafFlags;

    /* PML4 + one PDPT per covered 512 GiB (+ one PD per GiB without 1 GiB
       leaves, which is why that path only covers the low 512 GiB). */
    pages = 1 + g_Pml4Entries;
    if (!g_Use1GbPages)
    {
        pages += 512 * g_Pml4Entries;
    }

    block = (UINT8*)SvNptAllocBlock(pages, &blockPa);
    if (block == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Npt->Pml4   = (UINT64*)block;
    Npt->Pml4Pa = blockPa;

    for (i = 0; i < g_Pml4Entries; i++)
    {
        UINT64* pdpt   = (UINT64*)(block + (SIZE_T)(1 + i) * PAGE_SIZE);
        UINT64  pdptPa = blockPa + (UINT64)(1 + i) * PAGE_SIZE;

        Npt->Pml4[i] = pdptPa | NPT_TABLE;

        for (j = 0; j < 512; j++)
        {
            const UINT64 gpa = ((UINT64)i << 39) | ((UINT64)j << 30);

            if (g_Use1GbPages)
            {
                pdpt[j] = gpa | NPT_LEAF_RWX | LeafFlags;
            }
            else
            {
                const ULONG pdIndex = 1 + g_Pml4Entries + i * 512 + j;
                UINT64* pd   = (UINT64*)(block + (SIZE_T)pdIndex * PAGE_SIZE);
                UINT64  pdPa = blockPa + (UINT64)pdIndex * PAGE_SIZE;
                ULONG   k;

                for (k = 0; k < 512; k++)
                {
                    pd[k] = (gpa + (UINT64)k * NPT_2MB) | NPT_LEAF_RWX | LeafFlags;
                }
                pdpt[j] = pdPa | NPT_TABLE;
            }
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS SvNptInitialize(VOID)
{
    NTSTATUS status;
    int regs[4];
    UINT32 physBits;

    __cpuid(regs, CPUID_ADDRESS_SIZES);
    physBits = (UINT32)(regs[0] & 0xFF);

    /*
     * A four-level nested page table can only describe 48 bits of guest
     * physical address, so that is the ceiling regardless of what the CPU
     * reports.  Anything below 32 bits is nonsense; assume the maximum.
     */
    if (physBits < 32 || physBits > 48)
    {
        physBits = 48;
    }

    __cpuid(regs, CPUID_EXT_FEATURES);
    g_Use1GbPages = (regs[3] & CPUID_EXT_FEATURE_1GB) != 0;

    g_Pml4Entries = (physBits <= 39) ? 1 : (ULONG)(1ULL << (physBits - 39));

    if (!g_Use1GbPages)
    {
        /* 2 MiB leaves cost one PD per GiB; cap the map at the low 512 GiB
           rather than allocating a gigabyte of page tables. */
        g_Pml4Entries = 1;
        DbgPrint("svmhv: no 1 GiB pages - identity map limited to 512 GiB\n");
    }

    /*
     * What actually gets hidden is the MSRPM, the IOPM and, per processor, two
     * VMCBs, a host save area and a host stack - nine pages a processor plus
     * five.  Twelve a processor is that with room to spare, and running out is
     * not fatal: SvNptHideRange fails and the caller carries on with the page
     * unhidden and a line in the log.
     */
    g_HidePoolPages = 16 + 12 * KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS);
    g_HidePool = (UINT8*)SvNptAllocBlock(g_HidePoolPages, &g_HidePoolPa);
    if (g_HidePool == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_SplitPool = (UINT8*)SvNptAllocBlock(NPT_SPLIT_POOL_PAGES, &g_SplitPoolPa);
    if (g_SplitPool == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = SvNptBuildHierarchy(&g_NptPrimary, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = SvNptBuildHierarchy(&g_NptShadow, NPT_NO_EXECUTE);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    /*
     * Identical to the primary hierarchy, and deliberately never restricted by
     * a hook or a watch.  A processor enters it for exactly one instruction, to
     * let a store that a watchpoint trapped actually retire; see npt.h for why
     * the shadow hierarchy cannot do that job.
     */
    status = SvNptBuildHierarchy(&g_NptPermissive, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    DbgPrint("svmhv: npt identity map: %u bits phys, %u GiB, 1GiB pages=%d, "
             "ncr3 %llx / shadow %llx / permissive %llx\n",
             physBits, (ULONG)(SvNptCoverage() / (1024 * 1024 * 1024)),
             g_Use1GbPages, g_NptPrimary.Pml4Pa, g_NptShadow.Pml4Pa,
             g_NptPermissive.Pml4Pa);

    return STATUS_SUCCESS;
}

VOID SvNptFree(VOID)
{
    ULONG i;

    for (i = 0; i < g_BlockCount; i++)
    {
        MmFreeContiguousMemory(g_Blocks[i].Va);
    }

    RtlZeroMemory(g_Blocks, sizeof(g_Blocks));
    RtlZeroMemory(&g_NptPrimary, sizeof(g_NptPrimary));
    RtlZeroMemory(&g_NptShadow, sizeof(g_NptShadow));
    RtlZeroMemory(&g_NptPermissive, sizeof(g_NptPermissive));
    g_BlockCount = 0;
    g_SplitPool = NULL;
    g_SplitPoolNext = 0;
    g_HidePool = NULL;
    g_HidePoolPages = 0;
    g_HidePoolNext = 0;
}

UINT64 SvNptCoverage(VOID)
{
    return (UINT64)g_Pml4Entries * 512 * NPT_1GB;
}

ULONG SvNptSplitPagesUsed(VOID)
{
    return (ULONG)g_SplitPoolNext;
}

/*
 * Is this page one of ours?  Every nested page table, the split pool and the
 * hidden pages' backing all come out of g_Blocks, so one loop covers them.  A
 * watchpoint on any of it would fire from inside the fault handler that
 * services the watchpoint.
 */
BOOLEAN SvNptOwnsPage(_In_ PVOID Address)
{
    const UINT8* page = (const UINT8*)PAGE_ALIGN(Address);
    ULONG i;

    for (i = 0; i < g_BlockCount; i++)
    {
        const UINT8* base = (const UINT8*)g_Blocks[i].Va;

        if (page >= base && page < base + g_Blocks[i].Size)
        {
            return TRUE;
        }
    }

    return FALSE;
}

/* --------------------------------------------------------------- split */

UINT64* SvNptSplitTo4Kb(_Inout_ NPT_HIERARCHY* Npt, _In_ UINT64 Gpa)
{
    UINT64* pml4e;
    UINT64* pdpt;
    UINT64* pdpte;
    UINT64* pd;
    UINT64* pde;
    UINT64* pt;

    if (Npt->Pml4 == NULL || Gpa >= SvNptCoverage())
    {
        return NULL;
    }

    pml4e = &Npt->Pml4[NPT_PML4_INDEX(Gpa)];
    pdpt  = SvNptTableVa(*pml4e & NPT_PFN_MASK);
    if (pdpt == NULL)
    {
        return NULL;
    }

    pdpte = &pdpt[NPT_PDPT_INDEX(Gpa)];
    if ((*pdpte & NPT_LARGE) != 0)
    {
        /* 1 GiB leaf -> 512 2 MiB leaves with the same permissions. */
        const UINT64 base  = *pdpte & NPT_PFN_MASK;
        const UINT64 flags = *pdpte & ~NPT_PFN_MASK;
        UINT64 newPa;
        UINT64* newPd = SvNptAllocTable(&newPa);
        ULONG i;

        if (newPd == NULL)
        {
            return NULL;
        }
        for (i = 0; i < 512; i++)
        {
            newPd[i] = (base + (UINT64)i * NPT_2MB) | flags;
        }
        /* Publish only once the new table is fully populated. */
        InterlockedExchange64((volatile LONG64*)pdpte, (LONG64)(newPa | NPT_TABLE));
    }

    pd = SvNptTableVa(*pdpte & NPT_PFN_MASK);
    if (pd == NULL)
    {
        return NULL;
    }

    pde = &pd[NPT_PD_INDEX(Gpa)];
    if ((*pde & NPT_LARGE) != 0)
    {
        const UINT64 base  = *pde & NPT_PFN_MASK;
        const UINT64 flags = (*pde & ~NPT_PFN_MASK) & ~NPT_LARGE;
        UINT64 newPa;
        UINT64* newPt = SvNptAllocTable(&newPa);
        ULONG i;

        if (newPt == NULL)
        {
            return NULL;
        }
        for (i = 0; i < 512; i++)
        {
            newPt[i] = (base + (UINT64)i * PAGE_SIZE) | flags;
        }
        InterlockedExchange64((volatile LONG64*)pde, (LONG64)(newPa | NPT_TABLE));
    }

    pt = SvNptTableVa(*pde & NPT_PFN_MASK);
    if (pt == NULL)
    {
        return NULL;
    }

    return &pt[NPT_PT_INDEX(Gpa)];
}

/* --------------------------------------------------------------- query */

VOID SvNptQuery(_In_ const NPT_HIERARCHY* Npt, _In_ UINT64 Gpa,
                _Out_ UINT64* Entry, _Out_ ULONG* Level)
{
    const UINT64* pdpt;
    const UINT64* pd;
    const UINT64* pt;
    UINT64 entry;

    *Entry = 0;
    *Level = 0;

    if (Npt->Pml4 == NULL || Gpa >= SvNptCoverage())
    {
        return;
    }

    entry = Npt->Pml4[NPT_PML4_INDEX(Gpa)];
    if ((entry & NPT_PRESENT) == 0)
    {
        return;
    }

    pdpt = SvNptTableVa(entry & NPT_PFN_MASK);
    if (pdpt == NULL)
    {
        return;
    }

    entry = pdpt[NPT_PDPT_INDEX(Gpa)];
    if ((entry & NPT_LARGE) != 0 || (entry & NPT_PRESENT) == 0)
    {
        *Entry = entry;
        *Level = 3;                     /* 1 GiB leaf, or nothing at all    */
        return;
    }

    pd = SvNptTableVa(entry & NPT_PFN_MASK);
    if (pd == NULL)
    {
        return;
    }

    entry = pd[NPT_PD_INDEX(Gpa)];
    if ((entry & NPT_LARGE) != 0 || (entry & NPT_PRESENT) == 0)
    {
        *Entry = entry;
        *Level = 2;
        return;
    }

    pt = SvNptTableVa(entry & NPT_PFN_MASK);
    if (pt == NULL)
    {
        return;
    }

    *Entry = pt[NPT_PT_INDEX(Gpa)];
    *Level = 1;
}

/* ---------------------------------------------------------------- hide */

/* A private zero page to point one hidden page at. */
static UINT64 SvNptHideBacking(VOID)
{
    LONG index = InterlockedIncrement(&g_HidePoolNext) - 1;

    if (g_HidePool == NULL || index < 0 || (ULONG)index >= g_HidePoolPages)
    {
        return 0;
    }

    return g_HidePoolPa + (UINT64)index * PAGE_SIZE;
}

NTSTATUS SvNptHideRange(_In_ PVOID Va, _In_ SIZE_T Size)
{
    UINT8* page = (UINT8*)Va;
    UINT8* end  = (UINT8*)Va + Size;

    /*
     * Whole pages only, and the caller has to own all of them.  Rounding a
     * partial range outwards would hide somebody else's data, which is a far
     * more interesting bug than anything this function is for.
     */
    if (((ULONG_PTR)Va & (PAGE_SIZE - 1)) != 0 || (Size & (PAGE_SIZE - 1)) != 0)
    {
        NT_ASSERT(FALSE);
        return STATUS_INVALID_PARAMETER;
    }

    for (; page < end; page += PAGE_SIZE)
    {
        const UINT64 gpa = (UINT64)MmGetPhysicalAddress(page).QuadPart;
        UINT64* primary = SvNptSplitTo4Kb(&g_NptPrimary, gpa);
        UINT64* shadow  = SvNptSplitTo4Kb(&g_NptShadow, gpa);
        UINT64* permissive = SvNptSplitTo4Kb(&g_NptPermissive, gpa);
        const UINT64 backing = SvNptHideBacking();

        if (primary == NULL || shadow == NULL || permissive == NULL ||
            backing == 0)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        /*
         * Writable, and backed by a page of its own - see g_HidePool.  Every
         * access a guest can make to a hidden page now completes against zeroes
         * that belong to nobody else, which is what "there is nothing here"
         * has to look like.
         *
         * Executable in the primary hierarchy for the same reason: a fetch that
         * faults with nothing able to satisfy it is a livelock.  The shadow
         * hierarchy keeps NX, because there the invariant that only a hooked
         * page is executable is what drives the switch back out of it.
         */
        *primary = backing | NPT_PRESENT | NPT_WRITE | NPT_USER;
        *shadow  = backing | NPT_PRESENT | NPT_WRITE | NPT_USER | NPT_NO_EXECUTE;

        /*
         * The permissive view is permissive about *our* restrictions, not about
         * the concealment.  A processor is only in it for one instruction, but
         * one instruction is all a guest needs to read a page it was not
         * supposed to find.
         */
        *permissive = backing | NPT_PRESENT | NPT_WRITE | NPT_USER;
    }

    return STATUS_SUCCESS;
}
