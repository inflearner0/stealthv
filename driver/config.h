/*
 * config.h - what this hypervisor conceals, decided at compile time.
 *
 * There is deliberately no registry key.  A driver that reads its own
 * configuration out of HKLM leaves the configuration sitting in HKLM, where
 * anyone curious about the machine can read the exact list of what is being
 * hidden from them and turn it off - and the read itself is a behaviour worth
 * noticing.  These are constants, folded into the code, and the only way to
 * change them is to rebuild.
 *
 * Everything defaults to the most concealed setting.  Where that costs
 * something the cost is written down here rather than left to be discovered.
 */

#pragma once

/*
 * Nested page tables.  Also the prerequisite for hooks, watchpoints and for
 * hiding the driver's own pages - with this off, the guest can read the VMCBs
 * straight out of physical memory.
 */
#define STEALTHV_NESTED_PAGING      1

/*
 * Erase SVM from CPUID: 8000_0001.ECX.SVM and the whole of 8000_000A.  A guest
 * told there is no SVM behaves the way it would on a machine that has none; a
 * guest that believes it has SVM and then takes a #UD from VMRUN has found us.
 */
#define STEALTHV_HIDE_SVM_CPUID     1

/*
 * Hide EFER.SVME, so a ring-0 RDMSR sees the bit clear.
 *
 * This one is not free, and the price depends on where you are running.  The
 * MSRPM describes only three MSR ranges and everything outside them exits
 * *unconditionally* once the MSR intercept is on.  On bare metal every MSR
 * Windows touches often is inside one of those ranges, so the intercept costs
 * almost nothing.  Under a parent hypervisor it is a different story: Hyper-V's
 * synthetic MSRs live at 0x4000_00xx, outside all three, and an APIC-enlightened
 * guest writes HV_X64_MSR_EOI on every interrupt - about 200 000 exits per
 * second, measured in this lab.
 *
 * It is on anyway, because a bit that says "a hypervisor is installed" is worth
 * more to somebody looking for us than the cycles are to us.  If you are
 * running nested and would rather have the throughput back, set this to 0 and
 * accept that a ring-0 RDMSR can see SVME.
 */
#define STEALTHV_HIDE_EFER          1

/*
 * Subtract the cost of an intercepted CPUID from the guest's TSC, calibrated
 * against the same instruction measured before the first VMRUN.  Without it,
 * rdtsc-cpuid-rdtsc is the whole detection.
 *
 * The compensation is per-processor and cumulative, so a thread executing a lot
 * of CPUID drags that processor's clock behind the others - measured at a
 * worst backwards step of 28 ms over 2400 forced migrations while hvtest
 * hammered CPUID.  Ordinary code never comes close.
 */
#define STEALTHV_TSC_OFFSET         1

/*
 * Point the driver's own pages - VMCBs, host save areas, MSRPM, IOPM, host
 * stacks - at a shared zero page in both nested hierarchies, so a guest reading
 * physical memory finds nothing there.
 */
#define STEALTHV_HIDE_PAGES         1

/*
 * Flush the guest ASID on every entry rather than when the guest asks.
 *
 * Leave this at 0.  It is what the driver did before nested paging, and with
 * nested paging it is ruinous: TLB_CONTROL 3 discards this ASID's *nested*
 * translations too, so under a parent hypervisor every entry forces the layer
 * above to rebuild the structures shadowing our nested page tables.  With it on,
 * even the fifteen-second functional test stops making progress.  It exists to
 * get the old behaviour back for comparison, nothing else.
 */
#define STEALTHV_ALWAYS_FLUSH_TLB   0

/*
 * Answer the control CPUID leaf and run the worker thread that services it.
 *
 * This is the last thing between "instrumentable" and "not there at all", and
 * it is the one setting where maximum concealment and a usable tool actually
 * conflict.  What it costs, honestly:
 *
 *   - a system thread that wakes ten times a second.  It is a timer wait, not a
 *     spin, but it is a thread in this driver that a scan of system threads can
 *     see, and a wakeup pattern somebody could correlate.
 *   - one more CPUID leaf that answers, though only to a caller who already
 *     knows the key; with the wrong ECX it passes straight through to the
 *     hardware like any other reserved leaf.
 *
 * There is still no device object, no symbolic link and no dispatch routine, so
 * nothing here is reachable from user mode without the key.  Set this to 0 and
 * the driver has no interface of any kind: nothing to open, nothing to call, and
 * no thread waking up to look at a doorbell.  svmhvctl.exe and the MCP server
 * stop working, because there is nothing left for them to talk to.
 */
#define STEALTHV_CONTROL_INTERFACE  1
