# stealthv

**A minimal AMD-V (SVM) hypervisor for Windows x64, with nested-paging code
hooks that are invisible to anything reading memory — driven over MCP, so a
model can reverse engineer a driver, an executable or the kernel itself by
asking.**

[![ci](https://github.com/inflearner0/stealthv/actions/workflows/ci.yml/badge.svg)](https://github.com/inflearner0/stealthv/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/inflearner0/stealthv?include_prereleases)](https://github.com/inflearner0/stealthv/releases)
[![license](https://img.shields.io/github/license/inflearner0/stealthv)](LICENSE)

A **blue pill** / **hyperjacking** research tool: a kernel driver that puts the
**already running** Windows kernel into an SVM guest, installs **EPT-style
hypervisor hooks** through **nested page tables (NPT)**, and studies **hypervisor
detection** from inside the guest. The AMD counterpart to the Intel VT-x/EPT
projects.

**It is not only a driver.** An [MCP server](mcp/svmhv_agent.py) runs inside the
guest and exposes the whole instrument as 46 tools, so the thing driving it can
be a model rather than a person at a console. Ask it what a driver's IOCTL
interface is, put a hook on the handler, watch the arguments arrive, patch one
in flight, and read the original bytes back to confirm nothing on the page
changed — all of it over JSON-RPC, none of it requiring a debugger.

> **A lab instrument.** This is a type-2 hypervisor that hides itself from the
> guest, installs invisible kernel hooks, and runs caller-supplied shellcode in
> kernel mode on request. It exists to study how a driver behaves under
> virtualisation and how much of a hypervisor a guest can detect. Run it on
> machines you own, on an isolated network, and read the *What is and is not
> tested* section before trusting it with anything.

Every logical processor captures its own state, executes `VMRUN`, and carries on
running the exact instruction it was about to run — one privilege level further
down. The guest runs under nested page tables that map every guest physical page
to itself: the point of an identity map is not isolation but control over
permissions, and a page that is non-executable in one hierarchy and
executable-but-substituted in another is enough to hold a code hook nothing can
find by reading memory.

## What it does

**Virtualisation.** Every logical processor is taken with `VMRUN` while Windows
is running on it. Nested page tables identity-map the whole 48-bit guest
physical space with 1 GiB leaves, split to 4 KiB on demand. `VMLOAD`/`VMSAVE`,
`STGI`/`CLGI`, `SKINIT` and `INVLPGA` are intercepted and answered with `#UD`.
Sleep is handled: the driver devirtualises on the way out of S0 and re-enters on
the way back in.

**Hooks nothing can see.** A hooked page is mapped to the original in one
hierarchy and to a patched copy in the other, executable in exactly one of them.
Reading the function returns the original instructions, and only the processor
executing inside the page sees the copy at all — every other processor, and
every integrity check running on this one, reads the real bytes. Nothing is ever
patched in place.

- **trace** — record every call: arguments, return value, cycles taken, the
  calling module, and return addresses found on the stack above it (candidates,
  scanned rather than unwound, and labelled as such)
- **detour** — call your own function, with a trampoline back to the original
- **shellcode** — run assembly at the hook, assembled from Intel syntax
- **watch** — fault on write or on any access to a page, code or data
- **filters** — only this process, only this caller, only when argument 2 is
  above a value; and **spoof** an argument or **block** the call outright

**Reading the machine.** Guest virtual and guest physical memory, in the kernel
or inside any process, without opening a handle to it or being visible to it —
plus virtual-to-physical translation, so the physical calls have an address to
work from.

**Staying unnoticed.** `CPUID` is not intercepted at all, which is an AMD
privilege: `rdtsc; cpuid; rdtsc` measures 2376 cycles with the hypervisor live
and 2376 with it unloaded, because it is the same instruction on the same
processor. `EFER.SVME` reads as clear. The driver's own pages — VMCBs, host save
areas, MSRPM, IOPM, host stacks — read as zeroes from the guest, each backed by
a page of its own so they do not mirror each other. Nothing is done to the TSC,
because nothing needs to be.

**Runs nested.** Under Hyper-V the guest's own hypercalls are relayed from host
context, so VMBus, storage and networking keep working with SVM owned by this
driver. On bare metal the same intercept injects `#UD`.

## Driven over MCP

`mcp/svmhv_agent.py` is an MCP server that runs **inside the guest** and talks
to the driver through its `CPUID` control channel:

```
client  --HTTP-->  svmhv_agent.py (guest)  -->  svmhvctl.exe  -->  CPUID
```

It is inside the guest on purpose. PowerShell Direct drops its session the
moment the hypervisor loads and does not come back until the guest reboots, so a
host-side server puts the fragile part in exactly the wrong place. Standard
library only — no pip step to fail on a machine with no internet.

```powershell
python svmhv_agent.py --host 0.0.0.0 --port 8765
```

The 46 tools, by what they are for — each is `svmhv_` plus the name below:

| | |
|---|---|
| **the hypervisor** | `status` `exit_histogram` `selftest` `service` |
| **hooks** | `hook_trace` `hook_detour` `hook_shellcode` `hook_many` `watch` `watch_range` `unhook` `unhook_all` `hooks` |
| **what they caught** | `trace` `trace_summary` `trace_reset` |
| **memory** | `read` `write` `read_physical` `write_physical` `translate` |
| **code** | `disassemble` `assemble` `xrefs` `explain` `search` `strings` |
| **symbols** | `symbols_auto` `symbols_load` `symbol` `exports` `imports` `pdb_info` `syscalls` |
| **modules and processes** | `modules` `sections` `processes` `process_modules` `verify` |
| **drivers** | `driver` `devices` `symlinks` `ioctl` `ioctls` `callbacks` |
| **notes** | `note` |

Symbols download themselves from the Microsoft symbol server on first use.
Disassembly and assembly use capstone and keystone when they are installed and
fall back to a built-in decoder and assembler when they are not, so the tools
work on a guest with nothing on it.

Some of what that buys, none of which needs a debugger attached:

- **`driver` + `devices` + `symlinks`** — a `.sys` exports nothing, but it has
  to publish its entry points in a `DRIVER_OBJECT`, its devices carry the names
  callers open, and a symbolic link is the only record of which `\\.\Foo` maps
  to which device. Filter drivers appear in the attachment chain and nowhere
  else.
- **`ioctls`** — the control codes a driver handles, recovered by reading its
  dispatcher, decoded into device type, function, method and access. Nothing on
  the machine publishes that interface.
- **`callbacks`** — every driver registered for process, thread or image
  notifications. The arrays have no symbol and look identical, so the driver
  plants a callback of its own and the client finds it, rather than guessing.
- **`verify`** — compare a loaded module against the file it came from, with
  the loader's own import and retpoline patches classified out.

## Build

```powershell
.\build.ps1 -Sign
```

Produces `bin\svmhv.sys` (test-signed), `bin\svmhvctl.exe`, `bin\hvtest.exe`
and `bin\svmhv-test.cer`.

Needs Visual Studio with the C++ toolset and the WDK. Both are discovered:
`vswhere` finds the toolset, and the newest Windows Kit that actually ships
`km\` headers is used as the WDK. Override with `-VsPath`, `-KitRoot` or
`-SdkVersion` if you have several installed.

Prebuilt, test-signed binaries are attached to each [release](../../releases).
The certificate in the archive is generated by that build and is not a trust
anchor — it exists so Windows will load the driver with testsigning on, nothing
more.

## Run

The target needs `bcdedit /set testsigning on`, the test certificate in `Root`
and `TrustedPublisher`, and — importantly — **no other hypervisor owning SVM**
(`bcdedit /set hypervisorlaunchtype off`, VBS/HVCI disabled).

```powershell
sc.exe create svmhv type= kernel binPath= C:\lab\svmhv.sys
sc.exe start svmhv
.\hvtest.exe
sc.exe stop svmhv
```

Under Hyper-V the VM needs `Set-VMProcessor -ExposeVirtualizationExtensions
$true` and dynamic memory off.

## What is and is not tested

**Verified, repeatedly, on an eight-processor Windows 11 guest:** entering and
leaving on every processor, the self-test's twelve checks, hooks installing and
firing and coming off, argument capture and spoofing, the memory and physical
memory paths, and the concealment measurements quoted above — including
`cpuid exits taken: 0` from the hypervisor's own counter, which is the number
that cannot be argued with.

**Not verified:**

- **The guest still resets.** Triple faults at unpredictable intervals after
  load — three in one afternoon at about three hours, three minutes and ten
  minutes. The ten-minute one happened with the guest *idle*, so it is not the
  exit load. There is never a bugcheck or a dump; the host logs event 18560 and
  `LastBootUpTime` is the only honest instrument in the guest. This is the
  outstanding problem with the project.
- **Long-duration stability under concurrent load.** `soak.ps1` has not been
  re-run since `CPUID` interception was removed.
- **Resume from sleep.** The code is written and reviewed but a Hyper-V guest
  does not do S3, so nothing in this lab can exercise it.
- **Bare metal.** Everything here was measured nested under Hyper-V.

`CLAUDE.md` has the engineering detail, including the four bugs that shaped the
design and the things every instrument lies about.

