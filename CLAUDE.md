# Notes for Claude

Engineering detail for anyone (human or model) changing this code. The README is
the user-facing document and deliberately stays shorter; this is where the
reasoning lives. If the two ever disagree, this file is the one that was written
while the code was being debugged.

## Ground rules learned the hard way

**The guest resets, it does not hang.** Every instrument lies about this.
`Get-VM Uptime` keeps counting straight across a reset, `Heartbeat` reads OK once
the guest is back up, and PowerShell Direct "recovering" is just the machine
having rebooted. The only trustworthy signal is
`(Get-CimInstance Win32_OperatingSystem).LastBootUpTime` compared before and
after. Two separate investigations were lost to this.

**There will never be a crash dump.** The failure mode is a triple fault that
the parent Hyper-V resets. `nt!KiBugCheckData` stays zero, no event 1001 is
logged, no `MEMORY.DMP` is written, and only a Kernel-Power event 41 appears
afterwards. Do not go looking for a dump; read the boot time instead.

**Timing is intermittent: budget ~3 minutes per A/B.** One build survived 19
seconds and then reset. A 20-second pass proves nothing. Bisect by rebuilding
one constant in `driver/config.h` at a time and observing 200 s each.

**Do not judge CPUID interception by the ratio to `lfence`.** Under a parent
hypervisor CPUID already exits to *it*, so ~2376 cycles against a 66-cycle
`lfence` - about 36x - is what this machine looks like with nothing of ours
loaded. Take the verdict from the hypervisor's own `cpuid_exits` counter, which
is what `hvtest` now does.

**`STEALTHV_ALWAYS_FLUSH_TLB` must stay 0.** With nested paging, TLB_CONTROL 3
discards this ASID's nested translations too, and under a parent hypervisor
every entry then forces the layer above to rebuild its shadow structures. The
guest stops making progress. It was once tried *as a fix* for the resets and
made a passing test fail.

## Sleep and resume

`EFER.SVME` and `VM_HSAVE_PA` are architectural processor state and S3 does not
preserve them: every processor would come back out of firmware with SVM disabled
while its VMCB still described a running guest. So the driver registers on
`\Callback\PowerState` and devirtualises every processor on the way out of S0,
then enters guest mode again on the way back in — the same two DPCs load and
unload already use. The nested page tables, the hooks and their shadow pages are
ordinary memory and survive untouched; only the processors have to be retaken.

`SvPrepareVmcb` therefore has to be idempotent, which is why it zeroes the VMCB
before filling it. Running it a second time over a VMCB that has already been
used would otherwise inherit an `EVENTINJ` left valid by the last exit and
deliver it to the guest the moment it starts, out of any context that made
sense.

**This path is now partly tested, and it is not right.** `svmhvctl powercycle`
runs the same two steps the callback does — devirtualise everywhere, then enter
guest mode again — so the path can be exercised without an S3 a Hyper-V guest
will never do.

One cycle works, repeatedly: all eight processors come back, `virtualized=8`,
and the self-test passes 0x0fff on both sides. **Seven to nine cycles kill the
machine.** Two runs, two different bugchecks:

| spacing | died on | bugcheck |
|---|---|---|
| 2 s | cycle 9 | 0xEF `CRITICAL_PROCESS_DIED` (svchost) |
| 30 s | cycle 7 | 0xB8 `ATTEMPTED_SWITCH_FROM_DPC` |

Spacing made it worse rather than better, which is the point: the damage
accumulates per cycle, it is not a matter of cycling too fast. Something is left
behind each time that one cycle's worth of is survivable and eight is not, and
it is not the obvious candidates — the VMCB is zeroed on every `SvPrepareVmcb`,
the ASID is flushed on re-entry (`TlbControl = g_TlbControl` in that function,
not the conditional one the steady-state path uses), and nothing on the path
allocates.

Read the counters through a **write-through log**: the first attempt at this
lost the whole run to the file cache and came back as a block of NULs, which
told me nothing about which step died. `soak.ps1` has the logging helper.

So "resume from sleep works" is not a claim this supports. A real suspend
happens minutes or days apart and would take a very long time to accumulate
eight of anything, but that is an argument for it being slow to show, not for it
being absent.

## Known open items

- Long-duration stability under concurrent load is unverified; `soak.ps1` has
  not been re-run since the CPUID interception was removed.
- **The guest still resets, and it is not the workload.** Three triple faults in
  one afternoon (host events 18560), at intervals of about three hours, three
  minutes and ten minutes after load. The ten-minute one happened with the guest
  *idle*: a scheduled task loaded the driver, slept in thirty-second steps
  logging the boot time, and nothing touched the control channel at all. So the
  soak notes below, which reason about the guest failing to keep up with exit
  load, do not explain this — whatever it is happens with no load to keep up
  with. The reset is silent as always: no bugcheck, no dump, only Kernel-Power
  41 in the guest, and the boot time is the only honest instrument.

  **There is now an instrument for this, and it is the first one.** The exit
  handler used to answer four situations with `KeBugCheckEx`, from a context
  that cannot honour one — `GIF` clear, our own host stack, every other
  processor still inside `VMRUN`. One of those four was the `default:` case, and
  `VMEXIT_SHUTDOWN` (0x7F) went through it: a guest triple fault under SVM does
  *not* reset the machine, it exits to the host with the state that killed it.
  So a triple fault became a bugcheck that could not write a dump, which is
  exactly "no bugcheck, no dump, Kernel-Power 41, host event 18560". Whether
  that is *the* cause is not yet established — but all four now record into
  `SVMHV_FATAL_EXIT` and take that processor out of SVM instead, so `svmhvctl
  status` reports `fatal_count` and the reason afterwards, and with `kd`
  attached a triple fault prints one line naming RIP, RSP, CR2, CR3 and
  EXITINTINFO. Read `fatal_count` before believing any run.
- **`capture_stack` bugchecks the guest, reproducibly.** A trace hook installed
  with it on `nt!NtCreateFile` took the guest down in under a minute with
  `0x50 PAGE_FAULT_IN_NONPAGED_AREA`, reading `ffffc70a123ab000` — the page
  immediately above the faulting thread's own stack pointer, which is the guard
  page. The fault is inside `SvTraceStackCandidates`, which walks 256 qwords up
  from RSP looking for things that could be return addresses and simply runs off
  the top of a shallow stack.

  Its `__try`/`__except` does not help and cannot: an access to an unmapped
  *kernel* address is not an exception Windows raises, it is `MiSystemFault`
  deciding the reference is invalid and calling `KeBugCheckEx`, so there is
  nothing for the handler to catch. The comment claiming the stack is
  "therefore resident" is true only of the part below RSP that has been written.
  Closing it means bounding the walk by the real limits —
  `KeGetCurrentThread()`'s `StackLimit` and `StackBase`, or
  `IoGetStackLimits` — rather than by a count of 256, and the `__except` should
  go with it so it stops looking like protection.

  Unlike the reset, this one leaves evidence: host event **18590** (not 18560),
  a real `Minidump\*.dmp`, and a stack of `KeBugCheckEx` ← `MiSystemFault` ←
  `MmAccessFault` ← `KiPageFault` ← `svmhv+0x69c8`. Exec hooks without
  `capture_stack` ran for forty minutes under the same load with nothing.
- **A hot loop in PowerShell dies while an exec hook is live.** With a
  system-wide trace hook on `nt!NtCreateFile`, `powershell.exe` twice took an
  `AccessViolationException` inside `RuntimeHelpers._CompileMethod`, reached
  through `Interpreter.LoopCompiler.CreateDelegate` — PowerShell promoting a
  loop to compiled code, and the JIT faulting as it does so. The task exits
  `0xC0000005` and no `finally` runs, so a test written that way abandons the
  driver loaded and takes PowerShell Direct with it.

  Whether the hypervisor is at fault is not established; what is established is
  that a lab script must not drive the ring from a `for` loop while a hook is
  installed. `cursortests.ps1` waits for ordinary system activity instead. Worth
  noting the guest itself survived both: `LastBootUpTime` never moved.
- The resume-from-sleep path has never run; see above.
- A processor that comes online *after* load has no per-processor slot and stays
  unvirtualised. It is no longer an out-of-bounds array index, but it is still a
  gap: closing it means `KeRegisterProcessorChangeCallback`.
- The control channel answers at CPL 3. That is deliberate — `svmhvctl.exe` is a
  user-mode binary — but the magic is a constant printed in `svm.h` in this
  repository, so it is a ring-0 primitive for any process on the machine, not
  just for "anything that knows it". `STEALTHV_CONTROL_REQUIRE_CPL0` closes it
  at the cost of the tooling; it is all-or-nothing, because a hook install runs
  caller-supplied shellcode and gating only the writes would protect nothing.
- The SVM feature bits are visible to the guest, by design. Closing that means
  virtualising SVM, which is a separate project.
- A processor that takes a fatal exit stays out of SVM until the next load or
  `svmhvctl powercycle`. That is the intended trade — the machine survives and
  the evidence survives — but it means the hypervisor can be covering fewer
  processors than `virtualized=` claims.

## How it works

**Entering.** `KeGenericCallDpc` runs the setup on every processor. Each one
calls `RtlCaptureContext`, sets `EFER.SVME`, points `VM_HSAVE_PA` at a scratch
page, and fills a VMCB from that captured context. `AsmLaunchVm` then switches
to a private host stack and executes `VMRUN`. The guest resumes at the
instruction after `RtlCaptureContext`, where a flag now says "you are the
guest" and the function simply returns.

`VMRUN` only reloads RSP/RIP/RAX/RFLAGS from the VMCB, so `AsmLaunchVm` restores
the remaining GPRs (and XMM0–5) from the captured `CONTEXT` by hand before
entering the loop — otherwise the guest would wake up holding the launch path's
register garbage.

**Running.** `VMRUN` and `#VMEXIT` deliberately do *not* save FS, GS, TR, LDTR
or the SYSCALL MSRs; that is what `VMLOAD`/`VMSAVE` are for. The loop is
therefore `vmload guest → vmrun → vmsave guest → vmload host` around the C
handler. Exits run with `GIF == 0` — no interrupts, no NMIs — so the handler
stays short, allocates nothing and touches nothing pageable.

**Leaving.** `VMMCALL` with the magic in RAX and command 8, from CPL 0 only, is
the unload doorbell. The tail `VMLOAD`s the guest's segment state back into the
CPU, `STGI`s, clears `EFER.SVME`, builds a `[RFLAGS][RIP]` frame on the guest's
own stack and finishes with `POPFQ; RET` — so every register survives and
execution continues inside `SvDevirtualizeDpc` as if the `VMMCALL` had returned.

## Nested paging

Two complete hierarchies are built at load time, both mapping every guest
physical page to itself:

- **primary** — everything present, writable, executable.
- **shadow** — the same, but nothing is executable.

Everything is mapped eagerly with 1 GiB leaves, which costs one PML4 page plus
one PDPT page per 512 GiB: about 2 MiB per hierarchy to describe the whole
48-bit guest physical address space. Mapping it all up front is what makes the
fault handler safe — a nested page fault can then only ever come from a page the
driver deliberately made faulting, so the handler never has to allocate a page
table with `GIF` clear. Finer granularity is split on demand from a fixed pool
of table pages reserved at load time, for the same reason.

`NP_ENABLE` also means the VMCB's own copy of `PAT` is the one that decides
memory types, so `StateSave.GPat` is loaded from the real `MSR_PAT`. Leave it
zero and every page becomes uncacheable and the guest crawls.

## How an exec hook works

A hooked page is the only page whose mapping differs between the two
hierarchies:

| | primary | shadow |
|---|---|---|
| points at | the original page | a private patched copy |
| execute | faults | allowed |
| write | allowed | faults |
| read | the original bytes | the copy |

The guest starts in the primary hierarchy. Executing a hooked page faults, the
handler switches that processor's `NCr3` to the shadow hierarchy and re-executes
the instruction — which is now the first byte of a 14-byte absolute jump to the
detour. Leaving the page faults again (nothing else is executable in the shadow
hierarchy) and switches back. A hooked call therefore costs four exits: in,
out to the detour, back in through the trampoline, and out again.

Nothing is ever patched in place, so **reading the function returns the original
instructions**. And because `NCr3` lives in the VMCB, only the processor
actually executing inside the hooked page sees the copy at all; every other
processor, and every integrity check running on this one, reads the original.

```c
NTSTATUS SvHookInstall(SVMHV_HOOK_REQUEST* Request);   /* kind, action, filters */
NTSTATUS SvHookRemove(PVOID Target);
```

`PrologLength` is how many bytes at the start of `Target` may be overwritten,
rounded **up to an instruction boundary**, minimum 14. There is deliberately no
length disassembler in here: hooking a function whose prologue you have not
decoded is not something this file can make safe. `Trampoline` comes back
holding those original bytes followed by a jump to `Target + PrologLength`, so a
detour can call the real function.

The target page is pinned with an MDL for the lifetime of the hook — a hook keyed
on a physical address is only meaningful for as long as that physical page stays
where it is. One hook per guest physical page; two hooks in one page would have
to share a shadow copy and the second install would discard the first one's
patch.

Removal frees nothing: it restores the mappings, points the shadow view back at
the original page and marks the record inactive. That is deliberate — a
processor still executing inside the page when the hook goes away has to find
real instructions there, and freeing the shadow page underneath it would be a
use-after-free with a `#VMEXIT` in the middle of it. Re-installing on the same
target then reuses the record, its shadow page, its MDL and its PTE pointers, so
install-and-remove in a loop allocates nothing at all. Everything is released at
unload, once no processor can still be in guest mode.

## Staying unnoticed

**CPUID is not intercepted at all.** That is the single most important
concealment decision here, and it is available because this is AMD: `CPUID`
interception is one optional bit in the VMCB, where on Intel `CPUID` exits
unconditionally and no hypervisor has the choice. Leaving the bit clear means
`rdtsc; cpuid; rdtsc` measures exactly what the bare processor measures, because
it *is* the bare processor. There is no overhead to hide and nothing to
calibrate.

| `rdtsc; cpuid; rdtsc`, minimum of 2000 | cycles |
|---|---|
| before the driver loads | 2376 |
| hypervisor live | 2376 |
| an earlier build that did intercept | 12309 |

The cost is that the SVM feature bits cannot be masked: the guest sees
`8000_0001.ECX.SVM` set and `8000_000A` populated, while `VMRUN` still raises
`#UD`. That is a real discrepancy and it is not pretended otherwise — it is
simply a much narrower one. Code that times `CPUID` is everywhere; code that
tries to *use* SVM is rare. Closing it completely means virtualising SVM for the
guest, which is a different project.

Do not judge this by the ratio to `lfence`. Under a parent hypervisor `CPUID`
already exits to *it*, so ~2376 against a 66-cycle `lfence` — about 36x — is
what the machine looks like with nothing of ours loaded. `hvtest` takes the
verdict from the hypervisor's own exit counter instead, which cannot be argued
with: `cpuid exits taken: 0`.

**The rest of the instruction set.** `VMLOAD`, `VMSAVE`, `STGI`, `CLGI`,
`SKINIT` and `INVLPGA` are intercepted and answered with `#UD`. Leaving them
alone would be worse than detectable: with `EFER.SVME` really set, a guest
`VMSAVE` would happily write host state into a page of its choosing.

**The driver's own memory.** The VMCBs, the host save areas, the MSRPM, the IOPM
and the host stacks are pointed at a shared zero page in both hierarchies. The
processor reaches a VMCB by physical address, and the host stacks are only ever
touched with SVM's host state loaded, so none of it is affected — but a guest
reading physical memory now finds nothing there.

Each hidden page gets a **backing page of its own**, and is mapped writable.
Both halves of that matter, and each was got wrong once.

One *shared* dummy page for all of them is the obvious implementation, and it
leaks: a guest can write a pattern into one hidden page and read it back out of
another, and two supposedly distinct physical pages that mirror each other is a
sharper tell than anything their contents would have given away.

Making that shared page **read-only** fixes the mirror and introduces a
bugcheck. A guest write to a hidden page then faults, the handler cannot retire
the store without decoding it, and no mapping it can install will ever satisfy
the retry — so the instruction faults forever and the loop detector eventually
crashes the machine. A page each, writable, has neither problem: the store lands
on zeroes belonging to nobody else and the guest carries on. It costs one page
per hidden page, about 300 KiB on eight processors.

Not hidden: the nested page tables themselves and the hooks' shadow pages. Both
are edited from guest context, so hiding them would mean the driver writing to
the dummy page instead.

**Time.** Nothing is adjusted, and nothing needs to be. The driver no longer
writes `TSC_OFFSET` at all.

It used to. The compensation went into a per-processor running total that only
ever decreased, so every processor's clock walked backwards without bound and
away from the others. Windows needs the TSC invariant and synchronised across
processors; it absorbed the skew for a few minutes and then reset the machine —
no bugcheck, no dump, only a Kernel-Power event 41 afterwards. Capping the drift
stopped the resets and destroyed the concealment in the same stroke: the budget
was spent in about a hundred exits. Not intercepting `CPUID` removes the
overhead instead of hiding it, which is the only version of this that is both
stable and undetectable.

## Four things that bit, and why the code looks the way it does

**A nested page table edit is not in force until the processor next exits.**
Installing a hook writes the NX bit, raises a flush generation and returns — and
the self-test then called the victim on the very next instruction and watched it
run *unhooked*, with zero nested page faults on all eight processors. The
processor was still using the 1 GiB translation it had cached before the page was
split, which is executable. Bumping a counter only promises a flush at each
processor's next `#VMEXIT`, which may be a long way off. `SvSyncTlbFlush` now
drives an exit everywhere with `KeIpiGenericCall` and waits for it.

The instruction it drives that exit *with* matters, and this regressed once
already. It was `CPUID`, chosen when `CPUID` was intercepted, and it silently
stopped forcing anything the day that intercept was removed for concealment.
Hooks kept working anyway, for a reason that is pure luck: a Hyper-V guest
writes `HV_X64_MSR_EOI` on every interrupt, that MSR is outside all three MSRPM
ranges, and so the IPI carrying the routine provoked the exit by itself. On bare
metal, or with `STEALTHV_HIDE_EFER` at 0, there is no MSR intercept and nothing
would have flushed — a freshly installed hook would simply not fire. It is now
`VMMCALL` with `SVMHV_HV_NOP`, which is intercepted in every configuration and
is answered next to the unload doorbell so it works with the control interface
compiled out. If you ever change what this driver intercepts, check this first.

**The guest's TLB has to be flushed when the guest asks, and only then.** The
guest shares the host's page tables, but its translations are tagged with our
ASID, which nothing outside this driver knows about. `INVLPG` and `MOV CR3` are
native and correct; the gap is that a Hyper-V guest flushes with
`HvCallFlushVirtualAddressList` instead, and forwarded from host context that
hypercall flushes the partition's TLB and leaves our ASID's entries intact.
`nt!MiMapSinglePage` then recycles a system PTE and dereferences it through the
stale translation — a reproducible `IRQL_NOT_LESS_OR_EQUAL` inside
`nt!MiCloneVads`.

The original code therefore flushed on *every* `VMRUN`. That is correct, and
without nested paging it is merely expensive. With nested paging it is ruinous,
and not for the obvious reason: `TLB_CONTROL` 3 discards this ASID's *nested*
translations as well, so running under Hyper-V it forces the layer above us to
rebuild whatever it uses to shadow our nested page tables — on every single
entry. Switching it back on to test a theory made things strictly worse: even
the fifteen-second functional test stopped making progress, where with demand
flushing it passes over and over.

So flushing is now on demand: every forwarded hypercall flushes locally — which
is exactly where the guest asked for one — the four flush call codes also raise a
generation so the other processors flush on their next entry, and nothing else
flushes at all. `STEALTHV_ALWAYS_FLUSH_TLB` restores the old behaviour for
comparison and should be left alone otherwise.

This also happens to be what makes the MSR intercept thinkable, since that
multiplies the number of exits by a hundred.

**Timing a single instruction from C measures the wrong thing.** `RDTSC` is not
a barrier and nothing reads the `CPUID` output, so MSVC hoisted the `CPUID`
clean out of both timing loops — leaving a "measurement" of two back-to-back
`RDTSC`s. That is how an intercepted `CPUID` came to measure 33 cycles, *faster*
than an `LFENCE`, and it looked like a triumph rather than a bug. A `volatile`
leaf keeps the instruction in the loop and a `volatile` sink keeps it from being
deleted.

**Don't break into the kernel debugger during a run.** Halting every CPU for
tens of seconds trips PowerShell Direct's session timeout, and if you hold it
long enough the VMBus channels of the integration services go with it — after
which `Stop-VM` also times out and the VM needs a hard power cycle, even though
the kernel itself is perfectly healthy and idle. This looks exactly like the
hypervisor having starved VMBus. Both `runtests.ps1` and `soak.ps1` therefore
run from a scheduled task and report through a file. Attach the debugger to
catch a bugcheck, and otherwise leave it alone.

## Running under Hyper-V

Inside a Hyper-V VM the guest OS is itself a child partition and issues Hyper-V
hypercalls constantly — VMBus signalling, TLB-flush enlightenments. Those are
`VMMCALL` instructions, and once *we* own SVM they no longer reach Hyper-V:
uninter­cepted they raise `#UD`, intercepted-and-ignored they silently break
VMBus, and either way storage and networking die within seconds.

So `VMMCALL` is intercepted and **relayed**: `AsmForwardHypercall` re-issues it
from host context, where the hypervisor above us still intercepts it, passing
RCX/RDX/R8 and XMM0–5 through in both directions (Hyper-V's "XMM fast"
hypercalls put arguments there). On bare metal — detected via the absence of a
`Microsoft Hv` CPUID signature — the same intercept injects `#UD` instead.

Host-side requirements:

```powershell
Set-VMMemory    -VMName $vm -DynamicMemoryEnabled $false -StartupBytes 6GB
Set-VMProcessor -VMName $vm -ExposeVirtualizationExtensions $true
```


## Soak notes, from before the reset was fixed

Kept because the measurements are real and the guest-side problems still apply; the
conclusions about *why* it stopped were superseded by the TSC finding.

Part of what went wrong is the guest, and it has to be dealt with first or it
hides everything else. Windows Defender scanning the soak's own scratch files,
together with memory compression on a 6 GiB VM, jams an NTFS `ERESOURCE` for
minutes at a time; the debugger prints `Possible deadlock` and `!locks` shows a
System worker thread holding it with an IRP outstanding. That reproduces with
this driver **not loaded**, and `Stop-VM` times out in it too. Exclude the
scratch directory from Defender before attempting a soak — with that done, an
iteration that had been taking many seconds takes 370–570 ms.

With Defender out of the way the remaining behaviour is sharp: the soak gets a
few iterations in, with **zero failures** in everything it did manage
(30 process creations, 9 file round-trips, 3 hypervisor probes and 3 hook
install/remove cycles), and then stops making progress. Three configurations,
each cut short by a power-off and read back from the write-through log:

| configuration | progress before it stopped |
|---|---|
| nested paging on, demand flush (shipped) | 3 iterations in ~3 s, 0 failures |
| nested paging **off**, demand flush | 1 iteration |
| nested paging on, **always** flush | 0 iterations — and the functional test wedges too |

Two things follow. It is not the nested paging or the hooks: it happens with both
switched off, which is what took them off the suspect list. And the ordering is
the wrong way round for a deadlock in new code — the *slower* configuration
wedges *sooner*, which is the signature of the guest being unable to keep up
rather than of a lock cycle. That is plausible on the numbers, since a nested exit
here costs 6 000–19 000 cycles and Windows makes hypercalls continuously while
creating processes, but plausible is not measured, and no bugcheck or dump was
ever produced to settle it.

The third row is also the reason `STEALTHV_ALWAYS_FLUSH_TLB` defaults to 0. That went the
opposite way to the guess: flush-every-entry was the historically safe setting,
so it was tried as a fix, and it made a passing test fail.

One caution about instrumentation: `Get-VM ... Uptime` looked like it was showing
spontaneous VM resets during these runs. It was not trustworthy — it is reported
through the integration services, and those are exactly what gets starved here.
The event log and `KiBugCheckData` are the only evidence worth believing, and
neither shows a crash.

So the honest summary is that the hypervisor has not been observed to crash or
corrupt anything, every functional and concealment check passes repeatedly, and
it has *not* been shown to survive a sustained multi-vCPU load. That is the gap
to close next. The way to close it is to stop inferring the failure from the
outside: give the guest more than 6 GiB so memory compression is not competing,
attach a kernel debugger and leave it attached without ever breaking in, and
watch which processor stops making progress — `!running -it` while the soak is
wedged answers in one command what a day of power-cycling does not.

## Configuration

No registry key: every option is a constant in `driver/config.h`, folded in at
build time. A driver that reads its settings out of `HKLM` leaves them sitting
in `HKLM` for anyone curious about the machine.

| Constant | Default | What it does |
|---|---|---|
| `STEALTHV_NESTED_PAGING` | 1 | nested page tables, and therefore hooks and page hiding |
| `STEALTHV_HIDE_SVM_CPUID` | 0 | impossible without intercepting `CPUID`; see above |
| `STEALTHV_HIDE_EFER` | 1 | intercept `EFER` so `SVME` reads as clear |
| `STEALTHV_TSC_OFFSET` | 0 | removed: `CPUID` is not intercepted, so there is no cost |
| `STEALTHV_HIDE_PAGES` | 1 | the driver's own pages read as zeroes |
| `STEALTHV_ALWAYS_FLUSH_TLB` | 0 | flush the ASID every entry — **leave this off** |
| `STEALTHV_CONTROL_INTERFACE` | 1 | answer the control leaf and run its worker |
| `STEALTHV_CONTROL_REQUIRE_CPL0` | 0 | answer the control channel only in ring 0 |

Everything defaults to the most concealed setting it can. Two of them are worth
understanding before you change anything.

**`STEALTHV_HIDE_EFER` is on, and it is not free.** The MSRPM describes only
three MSR ranges, and anything outside them exits *unconditionally* once the MSR
intercept is set. On bare metal every MSR Windows touches often is inside one of
those ranges, so intercepting costs almost nothing. Under a parent hypervisor it
is a different story: Hyper-V's synthetic MSRs live at `0x4000_00xx`, outside all
three, and an APIC-enlightened guest writes `HV_X64_MSR_EOI` on every interrupt —
about **200 000 exits per second**, measured in this lab.

It is on anyway. A bit that says "a hypervisor is installed" is worth more to
somebody looking for you than the cycles are to you, and this used to default off
under a parent hypervisor precisely because the cost is visible — which meant the
stealthiest configuration was the one nobody was running. If you are nested and
want the throughput back, set it to 0 and accept that a ring-0 `RDMSR` can see
`SVME`. The driver logs a line at load when it is hiding EFER under a parent
hypervisor, so the cost is never a mystery later.

**`STEALTHV_CONTROL_INTERFACE` is the last knob between instrumentable and
absent.** With it at 1 there is still no device object, no symbolic link and no
dispatch routine — nothing reachable from user mode without the key, and the
control leaf passes straight through to the hardware for anyone who does not have
it. What it does cost is a system thread that wakes ten times a second while
idle, which a scan of system threads can see, and a `VMMCALL` that answers the
magic. While a client is issuing commands that thread is deliberately louder —
a two-millisecond spin and then a one-millisecond timer for two seconds — which
took a command from ~108 ms to ~32 ms end to end, most of the remainder being
`svmhvctl.exe` process creation. The burst is a pattern of its own, and it is
only present while somebody is driving the interface.

Set it to 0 and the driver has no interface of any kind: nothing to open, nothing
to call, no thread waking up to look at a doorbell. `svmhvctl.exe` and the MCP
server stop working, because there is nothing left to talk to. That is the
trade — full concealment or a tool you can drive, and you cannot have both.

Two capability checks **refuse to load** rather than quietly downgrading: a
processor without nested paging, and a host with `EFER.NXE` clear. Both used to
disable hooks and carry on, which meant a build that asked for concealment could
end up running with the hooks and the page hiding silently absent.
