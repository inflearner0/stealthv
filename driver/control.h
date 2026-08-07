/*
 * control.h - the doorbell, and the worker thread that answers it.
 *
 * This is the driver's entire interface.  No device object, no symbolic link, no
 * dispatch routines, nothing reachable from user mode: a client writes a command
 * into svmhv!g_Control and waits.  A kernel debugger can do that with two `eq`
 * commands, and anything already running in ring 0 can do it with two stores.
 *
 * The worker exists because installing a hook has to happen at PASSIVE_LEVEL -
 * it allocates, pins pages with an MDL and broadcasts an IPI - which is not
 * something a client poking at memory can arrange for itself.  Everything that
 * does *not* need kernel code to run stays out of here: the worker republishes
 * the counters into g_Snapshot each time round, and clients read that.
 */

#pragma once

#include "svm.h"        /* for the fixed-width types svmhvctl.h uses */
#include "svmhvctl.h"

extern SVMHV_CONTROL  g_Control;
extern SVMHV_SNAPSHOT g_Snapshot;

NTSTATUS SvControlStart(VOID);
VOID     SvControlStop(VOID);

/*
 * Whether Address falls in this driver's own working memory.  A watchpoint on
 * any of it would fire on the worker's own refresh, starve the guest, and take
 * away the only means of removing the watch.
 */
BOOLEAN  SvIsHypervisorMemory(_In_ PVOID Address);
