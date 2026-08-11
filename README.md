# stealthv

**A minimal AMD-V (SVM) hypervisor for Windows x64, with nested-paging code
hooks that are invisible to anything reading memory — driven over MCP, so a
model can reverse engineer a driver, an executable or the kernel itself by
asking.**

[![ci](https://github.com/inflearner0/stealthv/actions/workflows/ci.yml/badge.svg)](https://github.com/inflearner0/stealthv/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/inflearner0/stealthv?include_prereleases)](https://github.com/inflearner0/stealthv/releases)
[![license](https://img.shields.io/github/license/inflearner0/stealthv)](LICENSE)

A **blue pill** / **hyperjacking** research tool: a kernel driver that puts the
**already running** Windows kernel into an SVM guest, hooks it through **nested
page tables**, and studies **hypervisor detection** from inside the guest. The
AMD counterpart to the Intel VT-x/EPT projects.

> **A lab instrument.** It hides itself from the guest, installs invisible
> kernel hooks, and runs caller-supplied shellcode in kernel mode on request,
> and it will reset the machine it is running on. Machines you own, isolated
> network, and read `CLAUDE.md` before trusting it with anything.

## Driven over MCP

An [MCP server](mcp/svmhv_agent.py) runs **inside the guest** and exposes the
whole instrument as 60 tools, so what drives it can be a model rather than a
person at a console. Ask what a driver's IOCTL interface is, hook the handler,
watch the arguments arrive, patch one in flight, read the original bytes back to
confirm the page never changed — then snapshot the memory it works on, call it
again with a different argument, and put the memory back.

```
client  --HTTP-->  svmhv_agent.py (guest)  -->  svmhvctl.exe  -->  CPUID
```

Inside the guest on purpose: PowerShell Direct drops its session the moment the
hypervisor loads, so a host-side server puts the fragile part in the wrong
place. Standard library only.

Each tool is `svmhv_` plus the name below:

| | |
|---|---|
| **the hypervisor** | `status` `exit_histogram` `selftest` `service` |
| **hooks** | `hook_trace` `hook_detour` `hook_shellcode` `hook_many` `watch` `watch_range` `unhook` `unhook_all` `hooks` |
| **what they caught** | `trace` `trace_summary` `trace_reset` |
| **memory** | `read` `write` `read_physical` `write_physical` `translate` |
| **code** | `disassemble` `assemble` `xrefs` `explain` `search` `strings` |
| **symbols** | `symbols_auto` `symbols_load` `symbol` `exports` `imports` `pdb_info` `syscalls` |
| **modules and processes** | `modules` `sections` `processes` `process_modules` `verify` |
| **drivers** | `driver` `devices` `symlinks` `ioctl` `ioctls` `watch_ioctls` `callbacks` |
| **experiments** | `snapshot` `call` `reverse` `provenance` |
| **finding code** | `sweep` `coverage` `coverage_diff` `dump` `ibs` |
| **notes** | `note` `revive` |

Symbols download themselves on first use. Disassembly and assembly use capstone
and keystone when installed and a built-in decoder and assembler when not.

## What it does

**Hooks nothing can see.** A hooked page is mapped to the original in one
hierarchy and to a patched copy in the other, executable in exactly one of them.
Reading the function returns the original instructions, and only the processor
executing inside the page sees the copy — every other processor, and every
integrity check running on this one, reads the real bytes. Nothing is patched in
place.

- **trace** — arguments, return value, cycles taken, calling module, and return
  addresses found on the stack (candidates, scanned rather than unwound)
- **detour** — your own function, with a trampoline back to the original
- **shellcode** — assembly at the hook, assembled from Intel syntax
- **watch** — fault on write or on any access, code or data
- **filters** — only this process, only this caller, only when an argument is
  above a value; and **spoof** an argument or **block** the call

**Experiments, not only observation.** A copy-on-write **snapshot** over a range
of memory: every page loses write permission, the first store to each faults and
the original is copied aside, and restore puts them back — so the same code can
be run twice with one input changed. **call** runs a function with arguments you
choose and reports what it returns. A stepped run records all sixteen registers
per instruction, so **reverse** answers "which instruction gave this register
that value" by walking backwards instead of running again. **provenance** watches
a buffer and reports its writers grouped by instruction.

The snapshot restores *memory in one range* and nothing else — not registers,
not devices — and a range another processor is using gets restored underneath
it. `call` runs the target: called with arguments it was not written for it
takes the guest down, and no exception handler can prevent that.

**Finding code nothing declared.** The coverage sweep takes a permission away
from every page in a range and gives it back one fault at a time, so a page
costs one exit ever. In `both` mode it remembers the *order*: a page written and
then executed had its code arrive after its mapping did, which is a manual map,
an unpacker or a JIT and very little else. **coverage_diff** brackets an action
with two windows and reports only what the second reached. **dump** turns one of
those pages into a file with its section table rewritten to the memory layout,
so a disassembler opens it at the right addresses; a payload that erased its own
MZ header is dumped flat rather than refused. **ibs** samples through the
processor's own instruction-based sampling where the hardware exposes it.

**Virtualisation.** Every logical processor taken with `VMRUN` while Windows is
running on it. Nested page tables identity-map the whole 48-bit guest physical
space with 1 GiB leaves, split to 4 KiB on demand. `VMLOAD`/`VMSAVE`,
`STGI`/`CLGI`, `SKINIT` and `INVLPGA` answered with `#UD`. Devirtualises for
sleep and re-enters on resume — one transition at a time; repeated cycles are
known to crash the machine.

**Reading the machine.** Guest virtual and guest physical memory, in the kernel
or inside any process, without opening a handle to it or being visible to it,
plus virtual-to-physical translation.

**Staying unnoticed.** `CPUID` is not intercepted at all, which is an AMD
privilege: `rdtsc; cpuid; rdtsc` measures 2376 cycles with the hypervisor live
and 2376 with it unloaded, because it is the same instruction on the same
processor. `EFER.SVME` reads as clear. The driver's own pages read as zeroes,
each backed by a page of its own so they do not mirror each other. Nothing is
done to the TSC, because nothing needs to be.

**Runs nested.** Under Hyper-V the guest's hypercalls are relayed from host
context, so VMBus, storage and networking keep working with SVM owned by this
driver. On bare metal the same intercept injects `#UD`.

**On a driver specifically.** A `.sys` exports nothing, so: `driver` reads its
dispatch table, `devices` and `symlinks` give the names callers open and the
`\\.\Foo` that maps to them, `ioctls` recovers the control codes by reading the
dispatcher, and `callbacks` lists every driver registered for process, thread or
image notifications — those arrays have no symbol and look identical, so the
driver plants a callback of its own and finds it rather than guessing.

`CLAUDE.md` has the engineering detail, including the four bugs that shaped
the design and the things every instrument lies about.
