# stealthv

**An AMD-V (SVM) hypervisor for Windows x64 that puts the already-running kernel
into a guest, hooks it through nested page tables so nothing reading memory can
see the hooks, and exposes the whole thing as 64 MCP tools — so a model can
reverse engineer a driver, an executable or the kernel by asking.**

[![ci](https://github.com/inflearner0/stealthv/actions/workflows/ci.yml/badge.svg)](https://github.com/inflearner0/stealthv/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/inflearner0/stealthv?include_prereleases)](https://github.com/inflearner0/stealthv/releases)
[![license](https://img.shields.io/github/license/inflearner0/stealthv)](LICENSE)

> **Lab instrument.** It hides from the guest, installs invisible kernel hooks,
> runs caller-supplied shellcode in ring 0 on request, and will reset the
> machine it runs on. Hardware you own, isolated network. Read `CLAUDE.md`
> before trusting it with anything.

## Run it

Needs an AMD host, the WDK, and a Windows VM with test signing on. Build on the
host, copy three files into the guest, register the driver once:

```powershell
.\build.ps1 -Sign
```

Then in the guest, with `bin\svmhv.sys`, `bin\svmhvctl.exe` and
`mcp\svmhv_agent.py` copied to `C:\lab\`:

```powershell
sc.exe create svmhv type= kernel binPath= C:\lab\svmhv.sys
python C:\lab\svmhv_agent.py --host 0.0.0.0 --port 8765
```

Point an MCP client at `http://<guest>:8765/mcp` and call `svmhv_service` with
`action: load`. `GET /health` says whether the agent is up and the hypervisor is
answering.

Under Hyper-V the VM needs, from the host:

```powershell
Set-VMProcessor -VMName $vm -ExposeVirtualizationExtensions $true
Set-VMMemory    -VMName $vm -DynamicMemoryEnabled $false -StartupBytes 6GB
```

The agent runs **inside** the guest on purpose: PowerShell Direct drops its
session the moment the hypervisor loads and does not recover until reboot, so a
host-side server puts the fragile part in the wrong place. Standard library
only — no pip step on a machine with no internet.

### Manual mapping

```powershell
.\build.ps1 -ManualMap -Sign      # bin\svmhv-mm.sys
```

The same driver with `STEALTHV_MANUAL_MAP=1`. Its entry point ignores both
parameters, so it does not care whether your mapper passes a `DRIVER_OBJECT`, a
NULL, or its own base and size; the image extent it needs comes from
`__ImageBase` and the PE headers instead. **Do not manual-map `svmhv.sys`** —
that one writes `DriverUnload` through the pointer it was handed.

Two things to know before relying on it. There is no unload routine in the
manual-map build and nothing could call one, so the way out is a reboot. And
kernel SEH finds unwind information through the loader's function table, which
a manually mapped image is not in unless your mapper puts it there — ntoskrnl
exports nothing to do it from inside — so every `__try` in the driver is worth
only as much as your mapper makes it. `svmhv-mm.sys` has been built and its
entry point disassembled; it has not been mapped and run.

## Tools

Each is `svmhv_` plus the name.

| | |
|---|---|
| **hypervisor** | `status` `exit_histogram` `selftest` `service` `revive` |
| **hooks** | `hook_trace` `hook_detour` `hook_shellcode` `hook_many` `watch` `watch_range` `unhook` `unhook_all` `hooks` |
| **what they caught** | `trace` `trace_summary` `trace_reset` `watch_msr` `watch_io` |
| **experiments** | `snapshot` `call` `usercall` `explore` `diverge` `step` `reverse` `provenance` `struct` |
| **finding undeclared code** | `sweep` `coverage` `coverage_diff` `dump` `ibs` |
| **memory** | `read` `write` `read_physical` `write_physical` `translate` |
| **code** | `disassemble` `assemble` `xrefs` `explain` `search` `strings` |
| **symbols** | `symbols_auto` `symbols_load` `symbol` `exports` `imports` `pdb_info` `syscalls` |
| **modules and processes** | `modules` `sections` `processes` `process_modules` `verify` |
| **drivers** | `driver` `devices` `symlinks` `ioctl` `ioctls` `watch_ioctls` `callbacks` |
| **notes** | `note` |

Symbols download themselves on first use. Disassembly and assembly use capstone
and keystone when installed, a built-in decoder and assembler when not.

## What it does

**Hooks nothing can see.** A hooked page maps to the original in one nested
hierarchy and to a patched copy in the other, executable in exactly one of them.
Reading the function returns the original bytes; only the processor executing
inside the page sees the copy. Nothing is patched in place. Hooks trace
arguments and return values, detour to your own code, run assembled shellcode or
fault on write — filtered by process, caller or argument value, and able to
spoof an argument or block the call.

**Experiments, not just observation.** `snapshot` is copy-on-write over a range,
so the same code runs twice with one input changed. `call` invokes a function
with arguments you pick. Stepped runs record all sixteen registers per
instruction, so `reverse` finds what set a register by walking backwards. On top
of those: `diverge` runs two inputs and reports the one instruction where the
paths part — usually the whole answer for a licence or signature check;
`explore` reports which of many inputs reached new code; `struct` infers a field
layout from the width and direction of accesses to a buffer.

**Finding code nothing declared.** The sweep removes a permission from every
page in a range and gives it back one fault at a time — one exit per page, ever.
In `both` mode it remembers the *order*: written and then executed means the
code arrived after the mapping did, which is a manual map, an unpacker or a JIT
and little else. `dump` turns such a page into a file with its section table
rewritten to the memory layout, so a disassembler opens it at the right
addresses; a payload that erased its own MZ header is dumped flat.

**Staying unnoticed.** `CPUID` is not intercepted at all — an AMD privilege.
`rdtsc; cpuid; rdtsc` measures 2376 cycles loaded and 2376 unloaded, because it
is the same instruction on the same processor. `EFER.SVME` reads as clear. The
driver's pages read as zeroes, each backed by a private page so they do not
mirror each other. The TSC is untouched.

**Runs nested.** Under Hyper-V the guest's hypercalls are relayed from host
context, so VMBus, storage and networking keep working with SVM owned by this
driver. On bare metal the same intercept injects `#UD`.

**On a driver specifically.** A `.sys` exports nothing, so `driver` reads its
dispatch table, `devices` and `symlinks` give the names callers open, `ioctls`
recovers control codes from the dispatcher, and `callbacks` lists everything
registered for process, thread or image notifications — those arrays have no
symbol and look identical, so the driver plants a callback of its own and finds
it rather than guessing.

## Limits worth knowing before you start

- **`snapshot` restores memory in one range and nothing else** — not registers,
  not devices. A range another processor is using gets restored underneath it.
- **`call` runs the target.** Called with arguments it was not written for it
  takes the guest down, and no exception handler can prevent that: an invalid
  kernel pointer is a bugcheck, not an exception.
- **A sweep can wedge the machine.** The control worker is the only thing that
  can disarm one, and the fault storm is what starves it. `both` mode is capped
  at 64 MiB; an exec sweep over 1 GiB has needed a hard reset.
- **`usercall` does not work yet.** It fails cleanly with
  `STATUS_PROCEDURE_NOT_FOUND` on kernels where its thread routines do not
  resolve.
- **`ibs` needs hardware that exposes it.** Hyper-V does not pass it through, so
  it refuses there and has never taken a sample in this lab.
- **The guest still resets occasionally**, idle as well as loaded, with no
  bugcheck and no dump. `LastBootUpTime` is the only honest instrument.
- **The manual-map build has never been mapped.** It compiles, and its entry
  point provably touches neither parameter; that is the whole of what has been
  checked.

`CLAUDE.md` has the engineering detail: the bugs that shaped the design, and
what every instrument here lies about.
