/*
 * snapshot.h - copy-on-write snapshots of a range of guest memory.
 *
 * Everything else in this driver observes.  This is the one thing that lets a
 * client run the same code twice, which is the difference between reading a
 * program and doing an experiment on it: take a snapshot, let the guest run,
 * put the memory back the way it was, and run it again with one input changed.
 *
 * The mechanism is the write sweep with a copy in front of it.  Every page of
 * the range loses write permission in the primary hierarchy; the first store to
 * each one faults, the handler copies the original page aside and grants the
 * write, and the page never faults again.  So the cost is one exit and one 4 KiB
 * copy per page actually modified, and nothing at all for a range that is only
 * read - which is the usual shape, and the reason this is affordable where
 * copying the whole range up front would not be.
 *
 * What it is not
 * --------------
 * This is not a VM snapshot and it cannot be made into one from here.  It
 * restores *memory in one range* and nothing else: not registers, not device
 * state, not the pages outside the range that the same code touched, not
 * anything the kernel wrote down about what happened.  A range that some other
 * processor is actively using will be restored underneath it, which for
 * ordinary kernel data means a bugcheck rather than an experiment.
 *
 * It is therefore for memory the operator knows the shape of - a target's heap,
 * a decrypted buffer, a section of a module's data - driven by somebody who
 * knows what else is looking at it.  SvSnapshotTake refuses this driver's own
 * pages and nothing else, because there is no way for it to know what else on
 * the machine cares about the range it was handed.
 *
 * Overflow is refused rather than approximated.  The store is fixed at arm time
 * because a nested page fault cannot allocate, so a range that dirties more
 * pages than the store holds cannot be fully restored - and a half-restored
 * range is worse than none, since it is a state the program was never in.  When
 * that happens the snapshot is marked overflowed and Restore refuses, which at
 * least fails in a way that can be read.
 */

#pragma once

#include "svm.h"

/* Snapshot state, as reported by SvSnapshotState. */
#define SVMHV_SNAP_IDLE         0
#define SVMHV_SNAP_ARMED        1
#define SVMHV_SNAP_OVERFLOWED   2

/*
 * Take a snapshot of Size bytes at Address, in ProcessId (0 for kernel space).
 *
 * The range is pinned with an MDL and aliased into system space for the
 * lifetime of the snapshot - the fault handler has to be able to read the page
 * with GIF clear, and a system alias of a locked page is the only version of
 * that which is safe.  StorePages is how many distinct pages may be modified
 * before the snapshot overflows; 0 asks for one per page of the range, which
 * can always be restored but costs the range's size in non-paged pool.
 *
 * PASSIVE_LEVEL.  Replaces any existing snapshot.
 */
NTSTATUS SvSnapshotTake(_In_ UINT64 Address, _In_ UINT64 Size,
                        _In_ UINT32 ProcessId, _In_ UINT32 StorePages);

/*
 * Put every modified page back and re-arm, so the same snapshot can be restored
 * again.  Write permission is taken away and flushed *before* anything is
 * copied back, or the guest could dirty a page again while it is being restored
 * and never fault for it.
 *
 * Fails with STATUS_BUFFER_OVERFLOW if the store overflowed, in which case the
 * snapshot no longer describes a state the guest was ever in.
 */
NTSTATUS SvSnapshotRestore(_Out_ UINT64* Restored);

/* Drop the snapshot: give write permission back, unmap and free everything. */
VOID     SvSnapshotRelease(VOID);

/*
 * Exit-handler side.  TRUE if Gpa is a page of the armed snapshot that was
 * still write-protected, in which case the original has been copied aside, the
 * write has been granted and the caller should re-execute.  Allocates nothing.
 */
BOOLEAN  SvSnapshotSaveOnWrite(_In_ UINT64 Gpa, _In_ UINT64 FaultInfo);

VOID     SvSnapshotState(_Out_ ULONG* State, _Out_ UINT64* Base,
                         _Out_ UINT64* Size, _Out_ UINT64* Dirty,
                         _Out_ UINT64* Capacity);
