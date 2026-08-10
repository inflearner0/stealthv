/*
 * hvcall.h - the CPUID control channel.
 *
 * The driver has no interface: no device object, no IOCTL, no dispatch routines,
 * nothing named that anything could open.  A client reaches the hypervisor by
 * executing CPUID with a private leaf and a key, and the exit handler answers
 * out of the registers it already has in front of it.
 *
 * Because that handler runs with GIF clear it cannot *do* very much - installing
 * a hook allocates, pins pages and broadcasts an IPI, none of which is legal
 * there.  So a hypercall only ever fills in the request and rings the doorbell;
 * the worker thread in control.c does the work at PASSIVE_LEVEL, exactly as
 * before.  The client polls for completion with another hypercall.
 */

#pragma once

#include "svmhv.h"

/*
 * Handles one control hypercall.  Called from the VMMCALL exit handler with the
 * guest's registers, having already checked the magic.  Runs with GIF clear: no
 * locks, no allocations, nothing pageable.
 *
 * Cpl is the privilege level the VMMCALL was executed at, straight out of the
 * VMCB.  It is only consulted when the driver is built with
 * STEALTHV_CONTROL_REQUIRE_CPL0; by default this channel answers ring 3,
 * because svmhvctl.exe is a user-mode binary.
 */
VOID SvHandleControlCall(_Inout_ GUEST_CONTEXT* Context, _In_ UINT8 Cpl);
