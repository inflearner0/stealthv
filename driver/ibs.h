/*
 * ibs.h - AMD Instruction-Based Sampling, read at exits rather than by
 * interrupt.
 *
 * Every other instrument here costs an exit per event: a hook faults four
 * times, a watchpoint once per store, the coverage sweep once per page.  That
 * is fine for a question you can already aim at an address, and useless for the
 * one that comes first - "what does this code touch at all" - because arming
 * enough watchpoints to answer it is what takes the machine down.
 *
 * IBS answers it from the other end.  The processor tags one micro-op in every
 * N and writes down, in MSRs, what it was: the instruction's address, whether
 * it was a load or a store, and the *linear address it touched*.  No
 * instrumentation, no faults, and a cost that is a property of N rather than of
 * how busy the code is.  For an obfuscated routine whose memory accesses are
 * the only honest thing about it, that is the difference between a day and a
 * minute.
 *
 * Polled, not interrupt-driven
 * ----------------------------
 * IBS normally raises an interrupt through the local APIC's LVT when a sample
 * is ready, which would mean this driver owning an interrupt vector, an LVT
 * entry and an ISR - all of it visible, and all of it new failure surface in a
 * driver that already has one unexplained reset to its name.
 *
 * It does not need any of that here, because this hypervisor is already taking
 * exits constantly - a Hyper-V guest with the EFER intercept on takes about
 * 200 000 a second.  So the sample is collected by looking at IbsOpVal at the
 * top of the exit handler, which costs one RDMSR per exit while armed and
 * nothing at all while it is not.  Samples that ripen and are overwritten
 * between two exits are simply lost, which for a sampling facility is not an
 * error - it lowers the rate, and the rate was arbitrary to begin with.
 *
 * Availability
 * ------------
 * IBS is optional and a hypervisor above us is free not to expose it; writing
 * IBS_OP_CTL where it is unsupported is a #GP in host context with GIF clear,
 * which is not survivable.  So the CPUID gate is the whole safety story and it
 * is checked once at load, not per arm: both CPUID.8000_0001:ECX[10] (IBS
 * present) and CPUID.8000_001B:EAX[2] (op sampling) have to be set before a
 * single one of these MSRs is touched.
 */

#pragma once

#include "svm.h"

/* Probe CPUID and remember whether any of this is legal here.  Load time. */
VOID     SvIbsProbe(VOID);
BOOLEAN  SvIbsAvailable(VOID);

/*
 * Sample one micro-op in every Interval, on every processor.  Interval is
 * rounded to the 16-op granularity the hardware counts in and clamped to what
 * the field can hold.  0 disarms.  PASSIVE_LEVEL.
 */
NTSTATUS SvIbsArm(_In_ UINT32 Interval);

/*
 * Exit-handler side: if a sample has ripened on this processor, record it and
 * re-arm.  One predictable-branch global read when nothing is armed.
 */
VOID     SvIbsPoll(_In_ UINT32 Processor, _In_ UINT64 Cr3);

VOID     SvIbsState(_Out_ UINT32* Interval, _Out_ UINT64* Samples);
