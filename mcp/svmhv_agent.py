#!/usr/bin/env python3
"""
svmhv_agent.py - the svmhv MCP server, running *inside* the guest.

This replaces the host-side server that reached in over PowerShell Direct.  That
arrangement had the fragile part in exactly the wrong place: PowerShell Direct
drops its session while the hypervisor is loaded and does not recover until the
guest reboots, so the transport failed far more often than anything it carried.

Here the server sits next to the thing it controls:

    Claude  --HTTP-->  svmhv_agent.py (guest)  -->  svmhvctl.exe  -->  CPUID

Nothing crosses a VMBus channel, and the only hop left is ordinary TCP.

Standard library only, deliberately.  MCP over HTTP is JSON-RPC 2.0 in a POST
body, which `http.server` and `json` handle between them - so this needs nothing
installed in the guest beyond a bare Python, and there is no pip step to fail on
a machine with no internet.

    python svmhv_agent.py --host 0.0.0.0 --port 8765

Then point a client at http://<guest-ip>:8765/mcp .

This listens on a network interface and every tool it exposes can install kernel
hooks, so it is a lab instrument: run it on an isolated switch, and treat the
port as equivalent to kernel access on that machine.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CTL = r"C:\lab\svmhvctl.exe"
PROTOCOL_VERSION = "2024-11-05"

# Subcommand names, hex addresses, lengths, mode words, and the option strings
# built by hook_options - which is why the dot (notepad.exe) and the colon
# (1:objattr) are in here.  These go to subprocess as an argv list, so no shell
# ever sees them; the check is belt and braces against a malformed tool argument
# reaching svmhvctl as something it would misparse.
SAFE_ARGUMENT = re.compile(r"\A[0-9A-Za-z_.:-]+\Z")

_lock = threading.Lock()


class CtlError(RuntimeError):
    pass


def ctl(*arguments: str) -> str:
    """Run svmhvctl locally and return its output."""
    for argument in arguments:
        if not SAFE_ARGUMENT.match(argument):
            raise CtlError(f"refusing to pass {argument!r} to svmhvctl")

    # The helper talks to a single control block; serialise callers so two
    # requests cannot interleave a request write with somebody else's submit.
    with _lock:
        try:
            done = subprocess.run(
                [CTL, *arguments],
                capture_output=True, text=True, timeout=60,
            )
        except FileNotFoundError:
            raise CtlError(f"{CTL} is not there")
        except subprocess.TimeoutExpired:
            raise CtlError("svmhvctl did not finish within 60s")

    text = (done.stdout or "") + (done.stderr or "")
    if "present=0" in text or "is not loaded" in text:
        raise CtlError(
            "the hypervisor did not answer the control leaf: svmhv is not loaded, "
            "or was built with STEALTHV_CONTROL_INTERFACE 0"
        )
    return text


def pairs(text: str) -> dict[str, str]:
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if "=" in line and " " not in line.split("=", 1)[0]:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def records(text: str, prefix: str) -> list[dict[str, str]]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith(prefix + " "):
            continue
        record = {}
        for token in line[len(prefix) + 1:].split():
            if "=" in token:
                key, value = token.split("=", 1)
                record[key] = value
        out.append(record)
    return out


def as_int(values: dict[str, str], key: str, default: int = 0) -> int:
    try:
        return int(values.get(key, ""), 0)
    except ValueError:
        return default


def hexarg(text: str) -> str:
    return text.strip().lower().removeprefix("0x")




# --------------------------------------------------------------- hook options

CAPTURE_TYPES = ("ansi", "wide", "unicode", "objattr", "bytes")


def hook_options(process=None, pid=None, caller_base=None, caller_size=None,
                 filter_expr=None, capture=None, capture2=None,
                 spoof=None, spoof2=None, block=None) -> list[str]:
    """
    Turn the tool parameters into svmhvctl's named options.

    Everything here narrows *when* a hook fires or changes *what* the target
    sees, which is the difference between a hook you can leave on a busy
    function and one that floods the ring.
    """
    options: list[str] = []

    if process:
        # Windows only keeps fifteen characters of it, so match what it kept.
        options += ["--process", process[:15]]
    if pid is not None:
        options += ["--pid", str(int(pid))]
    if caller_base:
        if not caller_size:
            raise CtlError("caller_base needs caller_size: the range is what "
                           "identifies the driver")
        options += ["--caller", hexarg(str(caller_base)), str(int(caller_size, 0)
                    if isinstance(caller_size, str) else int(caller_size))]
    if filter_expr:
        options += ["--filter", filter_expr]

    for descriptor in (capture, capture2):
        if not descriptor:
            continue
        parts = descriptor.split(":")
        if len(parts) < 2 or parts[1].lower() not in CAPTURE_TYPES:
            raise CtlError(
                f"capture must be ARG:TYPE[:LEN] with TYPE in "
                f"{', '.join(CAPTURE_TYPES)} - got {descriptor!r}")
        options += ["--capture", descriptor]

    for descriptor in (spoof, spoof2):
        if not descriptor:
            continue
        if ":" not in descriptor:
            raise CtlError(f"spoof must be ARG:VALUE - got {descriptor!r}")
        options += ["--spoof", descriptor]

    if block is not None:
        options += ["--block", str(block)]

    return options


def decode_capture(hex_text: str) -> str:
    """
    Render a capture as text. The driver copies a bounded window and does not
    know where the string ended, so the terminator is found here.
    """
    try:
        raw = bytes.fromhex(hex_text)
    except ValueError:
        return hex_text

    # UTF-16 if the odd bytes are mostly zero, which is what a wide string in
    # the ASCII range looks like.
    odd = raw[1::2]
    if odd and sum(1 for b in odd if b == 0) > len(odd) * 0.7:
        text = raw.decode("utf-16-le", "replace")
    else:
        text = raw.decode("latin-1", "replace")

    text = text.split("\x00", 1)[0]
    printable = "".join(c if 32 <= ord(c) < 127 or ord(c) > 160 else "." for c in text)
    return printable or "(empty)"


# --------------------------------------------------------------- formatting

OPTION_BITS = [
    (0x0001, "nested-paging"), (0x0002, "hide-svm-cpuid"),
    (0x0004, "hide-efer"), (0x0008, "tsc-offset"), (0x0010, "hide-pages"),
    (0x0020, "parent-hypervisor"), (0x0040, "1gb-pages"),
    (0x0080, "always-flush-tlb"),
]
KIND_NAMES = {0: "exec", 1: "write-watch", 2: "access-watch"}
ACTION_NAMES = {0: "trace", 1: "detour", 2: "shellcode"}
TRACE_TYPES = {0: "exec", 1: "write", 2: "access"}
EXIT_NAMES = {
    0x072: "CPUID", 0x07A: "INVLPGA", 0x07C: "MSR", 0x080: "VMRUN",
    0x081: "VMMCALL", 0x082: "VMLOAD", 0x083: "VMSAVE", 0x084: "STGI",
    0x085: "CLGI", 0x086: "SKINIT", 0x400: "#NPF",
}
SELFTEST_BITS = [
    (0x0001, "hook installed"), (0x0002, "detour ran"),
    (0x0004, "trampoline reached the original"),
    (0x0008, "reads return the original bytes"),
    (0x0010, "unhook restored it"), (0x0020, "EFER.SVME hidden"),
    (0x0040, "SVM hidden from cpuid"), (0x0080, "SVM feature leaf hidden"),
    (0x0100, "nested paging active"), (0x0200, "hooked on every processor"),
    (0x0400, "trace captured the arguments"),
]
STATUS_NAMES = {
    0xC000000D: "STATUS_INVALID_PARAMETER",
    0xC000009A: "STATUS_INSUFFICIENT_RESOURCES",
    0xC0000225: "STATUS_NOT_FOUND",
    0xC0000022: "STATUS_ACCESS_DENIED - refused: that is the driver's own memory, "
                "and a watch on it would starve the guest",
    0xC000010A: "STATUS_INVALID_ADDRESS",
    0x000000B7: "STATUS_ALREADY_REGISTERED - that page already has a hook",
}


def hook_result(text: str, what: str) -> str:
    values = pairs(text)
    status = as_int(values, "status", -1) & 0xFFFFFFFF
    if status != 0:
        return f"{what} failed: {STATUS_NAMES.get(status, hex(status))}"
    return (
        f"{what}\n"
        f"  hook id    : {as_int(values, 'hookid')}\n"
        f"  guest phys : {as_int(values, 'gpa'):#x}\n"
        f"  trampoline : {as_int(values, 'trampoline'):#x}  "
        f"(call this to reach the original)"
    )


# -------------------------------------------------------------------- tools

def tool_status() -> str:
    values = pairs(ctl("status"))
    options = as_int(values, "options")
    exits = as_int(values, "exits")
    overhead = as_int(values, "overhead_cycles")

    lines = [
        f"processors      : {as_int(values, 'cpus')}",
        f"options         : "
        f"{', '.join(n for b, n in OPTION_BITS if options & b) or 'none'} "
        f"({options:#06x})",
        f"npt identity map: {as_int(values, 'npt_coverage') // (1 << 30)} GiB, "
        f"{as_int(values, 'split_pages')} split pages",
        f"active hooks    : {as_int(values, 'active_hooks')}",
        "",
        f"exits           : {exits:,}",
        f"  cpuid         : {as_int(values, 'cpuid_exits'):,}",
        f"  msr           : {as_int(values, 'msr_exits'):,}",
        f"  nested #PF    : {as_int(values, 'npf_exits'):,}",
        f"  hook switches : {as_int(values, 'hook_switches'):,}",
        f"  hypercalls    : {as_int(values, 'hypercalls'):,}",
    ]
    if exits:
        lines.append(f"  avg residency : {overhead // exits:,} cycles")
    lines += [
        "",
        f"cycles in host  : {overhead:,}",
        f"hidden from tsc : {as_int(values, 'hidden_cycles'):,}",
        f"cpuid native    : {as_int(values, 'native_cpuid'):,} cycles, hiding "
        f"{as_int(values, 'hidden_per_exit'):,} per intercepted cpuid",
        "",
        f"trace records   : {as_int(values, 'trace_records'):,} "
        f"({as_int(values, 'trace_dropped'):,} dropped, "
        f"{as_int(values, 'trace_filtered'):,} filtered)",
    ]
    per_cpu = sorted(
        (m for m in (re.fullmatch(r"cpu(\d+)_exits", k) for k in values) if m),
        key=lambda m: int(m.group(1)),
    )
    if per_cpu:
        lines += ["", "exits per processor: " + ", ".join(
            f"{int(m.group(1))}:{int(values[m.group(0)]):,}" for m in per_cpu)]
    return "\n".join(lines)


def tool_exit_histogram() -> str:
    text = ctl("histogram")
    lines = ["exits by code:"]
    for record in records(text, "exit"):
        code = int(record.get("code", "0"), 0)
        lines.append(
            f"  {code:#05x} {EXIT_NAMES.get(code, ''):<9} "
            f"{int(record.get('count', '0'), 0):,}"
        )
    invalid = as_int(pairs(text), "invalid")
    if invalid:
        lines.append(f"  VMEXIT_INVALID  {invalid:,}  <- a VMCB was rejected")
    return "\n".join(lines)


def tool_hooks() -> str:
    rows = records(ctl("hooks"), "hook")
    if not rows:
        return "no hook records"
    lines = [
        f"{'id':>3} {'state':<8} {'kind':<13} {'action':<10} {'target':<18} "
        f"{'gpa':<14} {'hits':>10}  prolog"
    ]
    for row in rows:
        kind = int(row.get("kind", "0"), 0)
        action = int(row.get("action", "0"), 0)
        prolog = int(row.get("prolog", "0"), 0)
        lines.append(
            f"{int(row.get('id', '0')):>3} "
            f"{'active' if int(row.get('active', '0'), 0) else 'retired':<8} "
            f"{KIND_NAMES.get(kind, '?'):<13} {ACTION_NAMES.get(action, '?'):<10} "
            f"{int(row.get('target', '0'), 0):#018x} "
            f"{int(row.get('gpa', '0'), 0):#014x} "
            f"{int(row.get('hits', '0'), 0):>10,}  {prolog or '-'}"
        )
    return "\n".join(lines)


def tool_trace(count: int = 40) -> str:
    if not 1 <= count <= 200:
        return "count must be between 1 and 200"
    text = ctl("trace", str(count))
    header = pairs(text)
    rows = records(text, "trace")
    if not rows:
        return f"no trace records yet ({as_int(header, 'produced')} produced)"

    lines = [f"{as_int(header, 'produced'):,} produced; showing {len(rows)}"]
    for row in rows:
        kind = int(row.get("type", "0"), 0)
        if kind == 0:
            entry = [
                f"[{row.get('seq')}] hook {row.get('hook')} cpu{row.get('cpu')} "
                f"{row.get('proc', '-')} pid {row.get('pid')} "
                f"tid {row.get('tid')} irql {row.get('irql')} rip {row.get('rip')}",
                f"      args {row.get('a0')} {row.get('a1')} {row.get('a2')} "
                f"{row.get('a3')}",
                f"      stack {row.get('s0')} {row.get('s1')} "
                f"ret {row.get('ret')} rsp {row.get('rsp')}",
            ]
            if int(row.get("spoofed", "0"), 0):
                entry.append(f"      {row['spoofed']} argument(s) replaced "
                             f"before the original saw them")
            for index in range(2):
                captured = row.get(f"cap{index}")
                if captured:
                    entry.append(f'      arg capture {index}: '
                                 f'"{decode_capture(captured)}"')
            lines.append("\n".join(entry))
        else:
            error = int(row.get("err", "0"), 0)
            decoded = [n for b, n in ((1, "present"), (2, "write"),
                                      (4, "user"), (16, "fetch")) if error & b]
            lines.append(
                f"[{row.get('seq')}] hook {row.get('hook')} cpu{row.get('cpu')} "
                f"{TRACE_TYPES.get(kind, '?')} gpa {row.get('gpa')} "
                f"from rip {row.get('rip')} "
                f"({'|'.join(decoded) or 'not-present'})"
            )
    return "\n".join(lines)


def tool_trace_reset() -> str:
    status = as_int(pairs(ctl("trace-reset")), "status", -1)
    return "trace ring reset" if status == 0 else f"failed: {status:#010x}"


def tool_hook_trace(target: str, prolog_length: int = 14, **options) -> str:
    extra = hook_options(**options)
    return hook_result(
        ctl("hook-trace", hexarg(target), str(prolog_length), *extra),
        f"tracing {target}" + (f" [{' '.join(extra)}]" if extra else ""))


def tool_hook_detour(target: str, detour: str, prolog_length: int = 14,
                     **options) -> str:
    extra = hook_options(**options)
    return hook_result(
        ctl("hook-detour", hexarg(target), str(prolog_length), hexarg(detour),
            *extra),
        f"detoured {target} -> {detour}")


def tool_hook_shellcode(target: str, shellcode_hex: str,
                        prolog_length: int = 14, **options) -> str:
    cleaned = shellcode_hex.replace(" ", "").replace("0x", "").replace(",", "")
    if not cleaned or len(cleaned) % 2:
        return "shellcode_hex must be an even number of hex digits"
    if len(cleaned) // 2 > 1024:
        return f"shellcode is {len(cleaned) // 2} bytes; the limit is 1024"
    extra = hook_options(**options)
    return hook_result(
        ctl("hook-shellcode", hexarg(target), str(prolog_length), cleaned, *extra),
        f"{len(cleaned) // 2} bytes of shellcode on {target}")


def tool_watch(target: str, mode: str = "write", **options) -> str:
    if mode not in ("write", "access"):
        return "mode must be 'write' or 'access'"
    extra = hook_options(**options)
    return hook_result(ctl("watch", hexarg(target), mode, *extra),
                       f"{mode} watch on the page holding {target}")


def tool_unhook(target: str) -> str:
    status = as_int(pairs(ctl("unhook", hexarg(target))), "status", -1)
    return (f"removed the hook on {target}" if status == 0
            else f"remove failed: {status & 0xFFFFFFFF:#010x}")


def tool_selftest() -> str:
    values = pairs(ctl("selftest"))
    passed = as_int(values, "passed")
    lines = [
        f"victim, no hook   : {as_int(values, 'victim_plain'):#010x}",
        f"victim, hooked    : {as_int(values, 'victim_hooked'):#010x} "
        f"(detour ran {as_int(values, 'detour_hits')}x, trampoline returned "
        f"{as_int(values, 'trampoline_result'):#010x})",
        f"victim, unhooked  : {as_int(values, 'victim_unhooked'):#010x}",
        f"bytes before      : {values.get('original_bytes', '?')}",
        f"bytes while hooked: {values.get('hooked_bytes', '?')}",
        f"all processors    : {as_int(values, 'cpus_hooked')} hooked, "
        f"{as_int(values, 'cpus_missed')} missed",
        "traced arguments  : " + " ".join(
            values.get(f"traced_arg{i}", "?") for i in range(4)),
        f"arg victim result : {values.get('arg_result', '?')} "
        f"(expect 0xaaaaaaaaaaaaaaaa)",
        f"EFER seen by guest: {values.get('efer', '?')}",
        f"cpuid in kernel   : {as_int(values, 'cpuid_cycles'):,} cycles "
        f"(baseline {as_int(values, 'baseline_cycles'):,})",
        "",
    ]
    for bit, name in SELFTEST_BITS:
        lines.append(f"  [{'pass' if passed & bit else 'FAIL'}] {name}")
    failures = sum(1 for bit, _ in SELFTEST_BITS if not passed & bit)
    lines += ["", f"{failures} check(s) failed" if failures else "all checks passed"]
    return "\n".join(lines)


TOOLS = [
    {
        "name": "svmhv_status",
        "description":
            "Whether the hypervisor is live, which concealment options are on, "
            "and every counter it keeps: exits by category, cycles spent in host "
            "mode, how much is hidden from the guest's TSC, trace ring health.",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": lambda a: tool_status(),
    },
    {
        "name": "svmhv_exit_histogram",
        "description":
            "Every #VMEXIT taken, by exit code, summed over processors. The "
            "quickest way to see what a driver under the hypervisor makes it do.",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": lambda a: tool_exit_histogram(),
    },
    {
        "name": "svmhv_hooks",
        "description":
            "Every hook record, including retired ones - removal marks a record "
            "inactive rather than recycling it.",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": lambda a: tool_hooks(),
    },
    {
        "name": "svmhv_trace",
        "description":
            "Read the newest trace records. Exec hooks show captured arguments; "
            "watchpoint hits show the faulting RIP, guest physical address and "
            "decoded #NPF error code.",
        "inputSchema": {
            "type": "object",
            "properties": {"count": {"type": "integer",
                                     "description": "how many, 1-200"}},
        },
        "handler": lambda a: tool_trace(int(a.get("count", 40))),
    },
    {
        "name": "svmhv_trace_reset",
        "description": "Empty the trace ring and zero its counters.",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": lambda a: tool_trace_reset(),
    },
    {
        "name": "svmhv_hook_trace",
        "description":
            "Hook a function and record its arguments on every call, then let the "
            "original run. Captures RCX/RDX/R8/R9, stack arguments, return "
            "address, RSP, processor, PID/TID, image name and IRQL. "
            "Narrow it with process/pid (a specific process) or "
            "caller_base+caller_size (only when a specific driver calls it); "
            "dereference string arguments with capture; replace arguments with "
            "spoof; or refuse the call entirely with block. prolog_length is how many "
            "bytes at the target may be overwritten, rounded UP to an instruction "
            "boundary, minimum 14 - there is no length disassembler in the driver, "
            "so decode the prologue first or you will corrupt the function.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string",
                           "description": "hex kernel address"},
                "prolog_length": {"type": "integer"},
                "process": {"type": "string", "description":
                    "only fire when this image is the current process, e.g. "
                    "'notepad.exe'; Windows keeps 15 characters of the name"},
                "pid": {"type": "integer", "description":
                    "only fire for this process id"},
                "caller_base": {"type": "string", "description":
                    "hex base of a module; with caller_size, fires only when the "
                    "return address is inside it - i.e. only when THAT driver "
                    "calls the target"},
                "caller_size": {"type": "integer", "description":
                    "size of the caller_base range in bytes"},
                "filter_expr": {"type": "string", "description":
                    "raw condition SUBJECT:OP:VALUE[:MASK]; SUBJECT is 0-7 or "
                    "pid/tid/ret/irql, OP is eq|ne|above|below|bits|range"},
                "capture": {"type": "string", "description":
                    "dereference a pointer argument: ARG:TYPE where TYPE is "
                    "ansi, wide, unicode (UNICODE_STRING*), objattr "
                    "(OBJECT_ATTRIBUTES* -> its ObjectName) or bytes:LEN. "
                    "Only taken at IRQL <= APC_LEVEL and under SEH"},
                "capture2": {"type": "string", "description": "a second capture"},
                "spoof": {"type": "string", "description":
                    "replace an argument before the original sees it: ARG:VALUE"},
                "spoof2": {"type": "string", "description": "a second spoof"},
                "block": {"type": "string", "description":
                    "do not call the original at all; return this value to the "
                    "caller instead"},
            },
            "required": ["target"],
        },
        "handler": lambda a: tool_hook_trace(
            a["target"], int(a.get("prolog_length", 14)),
            **{k: a[k] for k in (
                "process", "pid", "caller_base", "caller_size", "filter_expr",
                "capture", "capture2", "spoof", "spoof2", "block") if k in a}),
    },
    {
        "name": "svmhv_hook_detour",
        "description":
            "Hook a function so it jumps to another kernel address you already "
            "have. The returned trampoline runs the original prologue and jumps "
            "back past it, so the detour can call through.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "detour": {"type": "string"},
                "prolog_length": {"type": "integer"},
                "process": {"type": "string", "description":
                    "only fire when this image is the current process, e.g. "
                    "'notepad.exe'; Windows keeps 15 characters of the name"},
                "pid": {"type": "integer", "description":
                    "only fire for this process id"},
                "caller_base": {"type": "string", "description":
                    "hex base of a module; with caller_size, fires only when the "
                    "return address is inside it - i.e. only when THAT driver "
                    "calls the target"},
                "caller_size": {"type": "integer", "description":
                    "size of the caller_base range in bytes"},
                "filter_expr": {"type": "string", "description":
                    "raw condition SUBJECT:OP:VALUE[:MASK]; SUBJECT is 0-7 or "
                    "pid/tid/ret/irql, OP is eq|ne|above|below|bits|range"},
                "capture": {"type": "string", "description":
                    "dereference a pointer argument: ARG:TYPE where TYPE is "
                    "ansi, wide, unicode (UNICODE_STRING*), objattr "
                    "(OBJECT_ATTRIBUTES* -> its ObjectName) or bytes:LEN. "
                    "Only taken at IRQL <= APC_LEVEL and under SEH"},
                "capture2": {"type": "string", "description": "a second capture"},
                "spoof": {"type": "string", "description":
                    "replace an argument before the original sees it: ARG:VALUE"},
                "spoof2": {"type": "string", "description": "a second spoof"},
                "block": {"type": "string", "description":
                    "do not call the original at all; return this value to the "
                    "caller instead"},
            },
            "required": ["target", "detour"],
        },
        "handler": lambda a: tool_hook_detour(
            a["target"], a["detour"], int(a.get("prolog_length", 14)),
            **{k: a[k] for k in (
                "process", "pid", "caller_base", "caller_size", "filter_expr",
                "capture", "capture2", "spoof", "spoof2", "block") if k in a}),
    },
    {
        "name": "svmhv_hook_shellcode",
        "description":
            "Hook a function so it runs raw bytes you supply, entered with the "
            "target's arguments exactly as its caller left them. `ret` replaces "
            "the function (RAX is the result); falling off the end continues into "
            "the real one. The trampoline is at page+0xFF0 and the hook id at "
            "page+0xFF8 for position-independent code. Example: "
            "'b8 01 00 00 00 c3' makes it return 1 without running.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "shellcode_hex": {"type": "string"},
                "prolog_length": {"type": "integer"},
                "process": {"type": "string", "description":
                    "only fire when this image is the current process, e.g. "
                    "'notepad.exe'; Windows keeps 15 characters of the name"},
                "pid": {"type": "integer", "description":
                    "only fire for this process id"},
                "caller_base": {"type": "string", "description":
                    "hex base of a module; with caller_size, fires only when the "
                    "return address is inside it - i.e. only when THAT driver "
                    "calls the target"},
                "caller_size": {"type": "integer", "description":
                    "size of the caller_base range in bytes"},
                "filter_expr": {"type": "string", "description":
                    "raw condition SUBJECT:OP:VALUE[:MASK]; SUBJECT is 0-7 or "
                    "pid/tid/ret/irql, OP is eq|ne|above|below|bits|range"},
                "capture": {"type": "string", "description":
                    "dereference a pointer argument: ARG:TYPE where TYPE is "
                    "ansi, wide, unicode (UNICODE_STRING*), objattr "
                    "(OBJECT_ATTRIBUTES* -> its ObjectName) or bytes:LEN. "
                    "Only taken at IRQL <= APC_LEVEL and under SEH"},
                "capture2": {"type": "string", "description": "a second capture"},
                "spoof": {"type": "string", "description":
                    "replace an argument before the original sees it: ARG:VALUE"},
                "spoof2": {"type": "string", "description": "a second spoof"},
                "block": {"type": "string", "description":
                    "do not call the original at all; return this value to the "
                    "caller instead"},
            },
            "required": ["target", "shellcode_hex"],
        },
        "handler": lambda a: tool_hook_shellcode(
            a["target"], a["shellcode_hex"], int(a.get("prolog_length", 14)),
            **{k: a[k] for k in (
                "process", "pid", "caller_base", "caller_size", "filter_expr",
                "capture", "capture2", "spoof", "spoof2", "block") if k in a}),
    },
    {
        "name": "svmhv_watch",
        "description":
            "Watch a page for data access with no code patching at all - a "
            "permission in the nested page tables does the trapping. mode=write "
            "traps stores; mode=access makes the page not-present so reads trap "
            "too. A write watch fires TWICE per store, so on a page written in "
            "bulk it is thousands of exits a second; the driver refuses watches "
            "on its own memory and auto-disarms runaways, but prefer watching "
            "data you expect to be touched rarely.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "mode": {"type": "string", "enum": ["write", "access"]},
            },
            "required": ["target"],
        },
        "handler": lambda a: tool_watch(a["target"], a.get("mode", "write")),
    },
    {
        "name": "svmhv_unhook",
        "description":
            "Remove a hook or watch. Restores the nested page table entries; the "
            "shadow page is not freed until the driver unloads, because a "
            "processor may still be executing in it.",
        "inputSchema": {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        },
        "handler": lambda a: tool_unhook(a["target"]),
    },
    {
        "name": "svmhv_selftest",
        "description":
            "Run the driver's own end-to-end check: install a hook, call the "
            "victim, confirm the detour and trampoline ran, confirm that READING "
            "the hooked function still returns its original bytes, hit it "
            "concurrently on every processor, unhook, and verify the trace path "
            "captured a known set of arguments.",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": lambda a: tool_selftest(),
    },
]

TOOLS_BY_NAME = {tool["name"]: tool for tool in TOOLS}


# ------------------------------------------------------------------ JSON-RPC

def dispatch(request: dict) -> dict | None:
    """One JSON-RPC request in, one response out (None for notifications)."""
    method = request.get("method")
    request_id = request.get("id")

    def ok(result):
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    def fail(code, message):
        return {"jsonrpc": "2.0", "id": request_id,
                "error": {"code": code, "message": message}}

    if method == "initialize":
        return ok({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "svmhv", "version": "1.0.0"},
        })

    if method in ("notifications/initialized", "initialized"):
        return None

    if method == "ping":
        return ok({})

    if method == "tools/list":
        return ok({"tools": [
            {k: v for k, v in tool.items() if k != "handler"} for tool in TOOLS
        ]})

    if method == "tools/call":
        parameters = request.get("params") or {}
        name = parameters.get("name")
        arguments = parameters.get("arguments") or {}
        tool = TOOLS_BY_NAME.get(name)
        if tool is None:
            return fail(-32602, f"no such tool: {name}")
        try:
            text = tool["handler"](arguments)
            is_error = False
        except CtlError as exc:
            text, is_error = str(exc), True
        except Exception as exc:                      # noqa: BLE001
            text, is_error = f"{type(exc).__name__}: {exc}", True
        return ok({"content": [{"type": "text", "text": text}],
                   "isError": is_error})

    if request_id is None:
        return None
    return fail(-32601, f"method not found: {method}")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "svmhv-agent"

    def log_message(self, fmt, *args):
        sys.stderr.write(f"{self.address_string()} {fmt % args}\n")

    def _send(self, code: int, body: bytes, content_type: str):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        """A plain browser check, so it is obvious whether the agent is up."""
        if self.path.rstrip("/") in ("", "/health"):
            try:
                present = "present=1" in ctl("present")
            except CtlError as exc:
                present, detail = False, str(exc)
            else:
                detail = "hypervisor is answering"
            body = json.dumps({"agent": "up", "hypervisor": present,
                               "detail": detail}, indent=2).encode()
            self._send(200, body, "application/json")
        else:
            self._send(404, b"not found\n", "text/plain")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""

        try:
            payload = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self._send(400, json.dumps({
                "jsonrpc": "2.0", "id": None,
                "error": {"code": -32700, "message": "parse error"},
            }).encode(), "application/json")
            return

        if isinstance(payload, list):
            responses = [r for r in (dispatch(item) for item in payload) if r]
            body = json.dumps(responses).encode() if responses else b""
        else:
            response = dispatch(payload)
            body = json.dumps(response).encode() if response else b""

        if body:
            self._send(200, body, "application/json")
        else:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()


def main() -> None:
    global CTL

    parser = argparse.ArgumentParser(description="svmhv MCP agent (in-guest)")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--ctl", default=CTL)
    options = parser.parse_args()

    CTL = options.ctl

    server = ThreadingHTTPServer((options.host, options.port), Handler)
    print(f"svmhv MCP agent on http://{options.host}:{options.port}/mcp",
          flush=True)
    try:
        print("hypervisor: " + ("answering" if "present=1" in ctl("present")
                                else "not answering"), flush=True)
    except CtlError as exc:
        print(f"hypervisor: {exc}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
