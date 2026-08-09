# svmhv MCP server

An MCP server for driving the hypervisor: hook anything, trace its arguments,
run your own code in its place, watch pages for data access, and read the
counters that show what a virtualised driver is actually making the CPU do.

## The server runs in the guest

`svmhv_agent.py` runs **inside the guest** and serves MCP over HTTP. Claude
connects to a URL:

```
Claude  --HTTP-->  svmhv_agent.py (guest)  -->  svmhvctl.exe  -->  CPUID
```

An earlier version ran on the host and reached in over PowerShell Direct per
call. That put the fragile part in exactly the wrong place: PowerShell Direct
drops its session while the hypervisor is loaded and does not recover until the
guest reboots, so the transport failed far more often than anything it carried.
Nothing crosses a VMBus channel now; the only hop is ordinary TCP.

Standard library only, deliberately — MCP over HTTP is JSON-RPC in a POST body,
which `http.server` and `json` handle between them. There is no `pip install`
step to fail on a guest with no internet.

## How it reaches the hypervisor

The driver has **no device object, no IOCTL and no dispatch routines** — nothing
named that anything could open. The only way in is to execute `CPUID` with a
private leaf and a key; the hypervisor answers out of the registers it already
has in front of it. **No kernel debugger is involved.**

CPUID architecturally takes only EAX and ECX, but the hypervisor sees the whole
register file at the exit, so the ABI is as wide as it likes: command in RBX,
arguments in RDX/RSI, and up to 48 bytes back in RBX/RDX/RSI/RDI/R8/R9. That is
why `svmhvctl` needs an assembler stub — no compiler intrinsic can set RBX.

A CPUID exit runs with `GIF` clear, so it cannot allocate, pin pages or send an
IPI. A hypercall therefore only ever fills in the request and rings the doorbell;
the driver's worker thread does the real work at PASSIVE_LEVEL, and the client
polls for completion with another hypercall.

**There is no ACL.** The key in ECX is the entire access check, so any process in
the guest that knows it can install a kernel hook. Every offset a client can pass
is bounded against the structure it names, so the channel is not an arbitrary
kernel read — but it is a privileged channel guarded by a shared secret. That is
a deliberate trade for having no user-mode interface in the guest; the IOCTL it
replaced was at least admin-only.

## Setup

In the guest, copy in `bin\svmhvctl.exe` and `mcp\svmhv_agent.py`, allow the port,
and start it:

```powershell
New-NetFirewallRule -DisplayName "svmhv agent 8765" -Direction Inbound `
    -Action Allow -Protocol TCP -LocalPort 8765 -Profile Any
python C:\lab\svmhv_agent.py --host 0.0.0.0 --port 8765
```

`http://<guest-ip>:8765/health` is a plain GET reporting whether the agent is up
and whether the hypervisor is answering — check that first.

Then register it (already done in `~/.claude.json` on this machine):

```json
{
  "mcpServers": {
    "svmhv": { "type": "http", "url": "http://172.24.139.152:8765/mcp" }
  }
}
```

The guest needs its NIC, so `bcdedit /debug` must be **off** — with kernel
debugging on, the KD adapter claims the network adapter and the guest has no IP
at all. No debugger, no symbols, no credentials, and nothing installed in the
guest beyond a bare Python.

**This listens on a network interface and every tool can install kernel hooks.**
Run it on an isolated switch and treat the port as equivalent to kernel access on
that machine.

## Tools

47 of them. Each is `svmhv_` plus the name below:

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
| **notes** | `note` |

Plus `GET /health` for a quick liveness check.

## The one thing that will bite you

**`prolog_length` must land on an instruction boundary.** It is how many bytes at
the start of the target may be overwritten, minimum 14 for an absolute jump.
There is deliberately no length disassembler in the driver — get this wrong and
you will corrupt the function. The agent decodes the prologue for you and passes
a length that lands on an instruction boundary, so omitting `prolog_length` is
the safe choice; supply one only when you have decoded it yourself.

Symbols do resolve: `nt!NtCreateFile` works as a target, and the PDB is fetched
from the Microsoft symbol server on first use.

## Watchpoints are page-granular and expensive

A write watch fires **twice per store**: once to reach the permissive view, once
to leave it. On a page that is written in bulk that is thousands of exits a
second, which is enough to starve the guest until nothing can reach it any more —
including the channel that would remove the watch.

Two guards exist because this actually happened during development and cost a VM:

- the driver refuses a watch on its own control block, snapshot or trace ring
  (`STATUS_ACCESS_DENIED`);
- the worker disarms any watch producing more than 20000 hits in a 100 ms
  interval, and says so in the debug log.

Neither makes a watch on a hot page a good idea. Watch data you expect to be
touched rarely, and prefer an exec hook with a filter for anything frequent.

## Shellcode contract

Bytes are copied to a page of their own and entered with the target's arguments
exactly as its caller left them, so `RCX/RDX/R8/R9` and the stack are all live.

- `ret` — replace the function entirely; `RAX` is the result.
- fall off the end — the driver appends a jump to the trampoline, so execution
  continues into the real function.

The trampoline address is also at `page + 0xFF0` and the hook id at
`page + 0xFF8`, so position-independent code can load them RIP-relative.

Make a function return 1 without ever running it:

```
svmhv_hook_shellcode("some!Function", "b8 01 00 00 00 c3")   # mov eax,1; ret
```
