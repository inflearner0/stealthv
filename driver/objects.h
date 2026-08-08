/*
 * objects.h - what a driver looks like from the object namespace.
 *
 * The dispatch table says how a driver can be entered; this says how anything
 * outside the kernel reaches it in the first place.  A DRIVER_OBJECT alone does
 * not answer that: the name a caller opens is on a DEVICE_OBJECT, and the name
 * user mode actually uses is a symbolic link somewhere else again.
 *
 * All of it is done here rather than by reading structures from the client,
 * because the two things worth knowing - an object's name, and where a link
 * points - are not in the objects.  They live in the object header and the
 * directory namespace, at offsets that move between builds.  ObQueryNameString
 * and ZwQuerySymbolicLinkObject are documented and do not.
 *
 * PASSIVE_LEVEL, on the worker thread.  Everything here opens handles and
 * allocates; none of it may be called from the exit handler.
 */

#pragma once

#include <ntddk.h>
#include "svmhvctl.h"

/*
 * Every device a driver owns, as text.
 *
 * The name arrives in MemoryData the same way it does for a driver object, and
 * the answer replaces it: one line per device, and one more per device that has
 * something attached above it.  A filter driver shows up in the attachment
 * chain of the device it filters, which is the only place it shows up at all.
 */
NTSTATUS SvObjectsDevices(_Inout_ SVMHV_HOOK_REQUEST* Request);

/*
 * The symbolic links in \GLOBAL??, with their targets.
 *
 * This is the missing half of a device name.  A user-mode program opens
 * \\.\Foo, which is \GLOBAL??\Foo, which is a link to \Device\Something - and
 * the link is the only record of that mapping.  Given the targets, a client can
 * work backwards from a device to the string an application would have used.
 *
 * There are several hundred of them and the buffer holds about forty, so
 * MemoryProcessId doubles as a start index and the answer ends with the index
 * to ask for next when there are more.
 */
NTSTATUS SvObjectsSymbolicLinks(_Inout_ SVMHV_HOOK_REQUEST* Request);

/*
 * Register a callback of our own, so a client can tell the arrays apart.
 *
 * The notification arrays - PspCreateProcessNotifyRoutine and its neighbours -
 * are static data with no symbol even when private symbols are loaded, so they
 * have to be found by reading the function that writes to them.  That locates
 * arrays; it does not say which is which, and they sit next to each other in
 * .data holding structurally identical entries.  A scan that guesses gets it
 * wrong in a way that reads as correct: the first version of this labelled the
 * thread array "process creation" and listed thread callbacks under it.
 *
 * So instead of guessing: register a known routine for each kind through the
 * documented API, let the client find that exact address, and unregister.  The
 * array containing it is that kind, as a matter of fact rather than inference.
 *
 * MemoryAddress is 1 to arm and 0 to disarm; arming answers with the addresses
 * to look for.  Registry notifications fire on every registry operation in the
 * system, so this is not something to leave armed - the driver disarms it at
 * unload if a client forgets.
 */
NTSTATUS SvObjectsCallbackProbe(_Inout_ SVMHV_HOOK_REQUEST* Request);

/* Unregister anything the probe left behind.  Safe to call unarmed. */
VOID SvObjectsProbeStop(VOID);
