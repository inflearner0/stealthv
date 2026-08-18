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
 * CPUID is not intercepted, and so its feature bits cannot be masked.
 *
 * On AMD that intercept is a single optional bit, unlike Intel where CPUID
 * exits unconditionally.  Leaving it clear is what makes rdtsc-cpuid-rdtsc read
 * exactly what the bare processor reads - and it removes the reason the TSC
 * ever had to be adjusted, which is what used to reset the machine a few
 * minutes after load.
 *
 * The price is the one concealment this design gives up: the guest sees
 * 8000_0001.ECX.SVM set and 8000_000A populated, while VMRUN still raises #UD.
 * That is a real discrepancy, just a much narrower one - code that times CPUID
 * is everywhere, code that tries to use SVM is rare.  Closing it completely
 * means virtualising SVM for the guest, which is a different project.
 */
#define STEALTHV_HIDE_SVM_CPUID     0

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
 * Gone, and it cannot come back while CPUID runs natively.
 *
 * This used to subtract the cost of an intercepted CPUID from the guest's TSC.
 * The subtraction went into a per-processor running total that only ever
 * decreased, so every processor's clock walked backwards without bound and
 * away from the others; Windows needs the TSC invariant and synchronised, and
 * a few minutes in it stopped tolerating the skew and reset the machine - no
 * bugcheck, no dump, only a Kernel-Power event 41.
 *
 * Capping the drift fixed the resets and destroyed the concealment: the budget
 * was spent in about a hundred exits.  Not intercepting CPUID removes the
 * overhead instead of hiding it, which is the only version of this that is both
 * stable and undetectable.
 */
#define STEALTHV_TSC_OFFSET         0

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
 * Last-branch recording, so a trace record can say where control came from.
 *
 * The stack walk in trace.c reports candidates rather than a call stack, and on
 * obfuscated or virtualised code it reports very little that is true.  The
 * processor knows the answer exactly: with LBR virtualisation on, every exit
 * carries the last branch the guest took, and that is a fact no amount of
 * flattening or junk-frame construction can lie about.  It is what makes a
 * first-execution record from the coverage sweep say *who jumped into* a page
 * nobody declared, which is the question that record exists to raise.
 *
 * It costs one guest-visible bit, and that bit is hidden the same way EFER.SVME
 * is: DEBUGCTL is intercepted and reports the LBR and BTF bits the guest set
 * rather than the one we set underneath.  DEBUGCTL is written rarely - this is
 * nothing like the EFER intercept's cost, which is paid on every synthetic MSR
 * a Hyper-V guest touches.
 *
 * Only exits carry it.  A trace hook's recorder runs in guest context, several
 * jumps deep in the thunk, by which time the last branch is one of ours - so
 * exec-hook records deliberately leave the fields zero rather than record a
 * measurement of the instrument.
 */
#define STEALTHV_LBR                1

/*
 * Intercept CPUID and record every one, with the leaf and where it came from.
 *
 * Off, and it has to default off: not intercepting CPUID is the single most
 * important concealment decision in this driver.  It is what makes
 * rdtsc-cpuid-rdtsc measure exactly what the bare processor measures, because
 * it is the bare processor - 2376 cycles either way, against 12309 for a build
 * that did intercept.  Turning this on gives that up completely and is visible
 * to the first piece of code that times a CPUID, which is most of them.
 *
 * It exists because "which instruction detected the hypervisor" is otherwise
 * unanswerable, and one run with it on answers it.  Arm it, learn the leaf,
 * turn it off - the same standing as STEALTHV_ALWAYS_FLUSH_TLB, which is kept
 * for comparison and is not a setting to run.
 */
#define STEALTHV_WATCH_CPUID        0

/*
 * Answer the control CPUID leaf and run the worker thread that services it.
 *
 * This is the last thing between "instrumentable" and "not there at all", and
 * it is the one setting where maximum concealment and a usable tool actually
 * conflict.  What it costs, honestly:
 *
 *   - a system thread that wakes ten times a second while nothing is happening.
 *     It is a timer wait, not a spin, but it is a thread in this driver that a
 *     scan of system threads can see, and a wakeup pattern somebody could
 *     correlate.  While a client is actually issuing commands it is louder than
 *     that on purpose - a couple of milliseconds of spinning and then a
 *     millisecond timer for two seconds - because a hundred milliseconds of
 *     latency per command is the difference between a tool that can be driven
 *     and one that can only be batched.  That burst is itself a pattern, and it
 *     only appears while somebody is using the interface.
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

/*
 * Answer the control channel only at CPL 0.
 *
 * Off, and that is not an oversight - but it is worth being exact about what
 * the default costs, because svm.h used to describe it as "the magic is the
 * whole access check", which understates it.  The magic is a constant compiled
 * into the driver and written out in full in svm.h, in a repository.  It is not
 * a secret from anybody who can read the source, so with this at 0 the control
 * channel is a ring-0 primitive available to any user-mode process on the
 * machine: SVMHV_CMD_WRITE_PHYSICAL writes anywhere in RAM, and
 * SVMHV_CMD_HOOK_INSTALL takes caller-supplied shellcode and arranges for the
 * kernel to execute it.
 *
 * The default is 0 because svmhvctl.exe and the MCP agent are user-mode
 * binaries and this is a lab tool on an isolated guest, where that is the
 * correct trade.  Set it to 1 and only kernel-mode callers are answered, at
 * which point the tooling needs a ring-0 shim of its own.
 *
 * Gating writes but not hook installation was considered and rejected: a hook
 * install runs arbitrary bytes in ring 0, so a partial gate would protect
 * nothing while reading as though it did.  It is all or nothing.
 *
 * The unload doorbell is not covered by this and never was - it checks CPL 0
 * unconditionally, in every build, because user mode must not be able to
 * unload the hypervisor.
 */
#define STEALTHV_CONTROL_REQUIRE_CPL0   0

/*
 * Build for manual mapping: never touch the DRIVER_OBJECT the entry point was
 * handed.
 *
 * This has to be a build flag rather than a runtime check, and that is the
 * whole reason it exists.  A manual mapper calls the entry point with whatever
 * it likes - NULL, its own allocation base and size, a fabricated object - and
 * a non-NULL pointer that is not a DRIVER_OBJECT is indistinguishable from a
 * real one until the driver writes DriverUnload through it.  So the choice is
 * made at compile time or not at all.
 *
 * With this at 1:
 *
 *   - both parameters are ignored, so any mapper's calling convention works;
 *   - the image extent SvOwnsPage compares against comes from __ImageBase and
 *     the PE headers instead of DriverStart/DriverSize;
 *   - no unload routine is registered, and there is none in the binary - a
 *     manually mapped image is never unloaded by the loader, so the cleanup
 *     path could not run and pretending otherwise would only make it look as
 *     though it could.
 *
 * What this flag cannot do is register the image's .pdata with the kernel, and
 * that is worth knowing before relying on the manual-map build.  Kernel-mode
 * SEH finds unwind information through the loader's inverted function table,
 * which is built when a driver is loaded properly; ntoskrnl exports no
 * RtlAddFunctionTable to do it by hand.  Every __try in here is therefore only
 * as good as the mapper - if it does not insert the image into that table, an
 * exception inside one of them is an unhandled kernel exception rather than a
 * caught one.  The __try in call.c is the one that matters, and CLAUDE.md is
 * already honest about how little it buys even on a properly loaded driver.
 */
#ifndef STEALTHV_MANUAL_MAP
#define STEALTHV_MANUAL_MAP         0
#endif
