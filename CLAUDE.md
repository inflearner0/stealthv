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

## Known open items

- Long-duration stability under concurrent load is unverified; `soak.ps1` has
  not been re-run since the CPUID interception was removed.
- Duplicate hook records can exist for the same GPA when the kind differs: only
  *active* hooks are checked for GPA collision, so a watch and a retired exec
  record can share PTE pointers.
- The SVM feature bits are visible to the guest, by design. Closing that means
  virtualising SVM, which is a separate project.

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

That mapping is **read-only**, and the reason is worth recording. It used to be
writable, and because every hidden page points at the *same* dummy page, a guest
could write a pattern into one hidden page and read it back out of another. Two
supposedly distinct physical pages that mirror each other is a sharper tell than
anything their contents would have given away.

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

