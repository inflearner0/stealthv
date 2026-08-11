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
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CTL = r"C:\lab\svmhvctl.exe"
PROTOCOL_VERSION = "2024-11-05"
# Every interface, and no authentication, on purpose.  This is a lab
# instrument that a model on another machine has to be able to reach without a
# credential dance; the isolated switch is the boundary, not the bind address.
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8765

# The agent is deliberately dependency-free, but it is still a network parser
# in front of a kernel control surface.  Keep one request bounded even when a
# client has connected successfully but is otherwise malformed or buggy.  These
# are limits on a single malformed request, not a gate on who may call.
MAX_REQUEST_BODY_BYTES = 1 << 20             # 1 MiB is ample for MCP tools.
MAX_BATCH_REQUESTS = 32
REQUEST_READ_TIMEOUT_SECONDS = 15

# Public PDBs can be large, but an unbounded response or cache file is not a
# reasonable trade for a symbol name.  The parser below keeps the same limit.
MAX_PDB_BYTES = 512 << 20
PDB_DOWNLOAD_TIMEOUT_SECONDS = 60
PDB_PROVENANCE_SUFFIX = ".provenance.json"

# Subcommand names, hex addresses, lengths, mode words, and the option strings
# built by hook_options - which is why the dot (notepad.exe) and the colon
# (1:objattr) are in here.  The equals sign is for the keyword arguments the
# call and usercall subcommands take (pid=, steps=, tid=, timeout=), and its
# absence was a latent bug: every one of those was rejected here before it ever
# reached svmhvctl.  These go to subprocess as an argv list, so no shell ever
# sees them; the check is belt and braces against a malformed tool argument
# reaching svmhvctl as something it would misparse.
SAFE_ARGUMENT = re.compile(r"\A[0-9A-Za-z_.:=-]+\Z")

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
        except OSError as error:
            raise CtlError(f"could not run {CTL}: {error}")

    text = (done.stdout or "") + (done.stderr or "")
    # Ordered by how useful the message is.  "Not loaded" is the overwhelmingly
    # common failure and it exits non-zero, so testing the exit code first would
    # replace the one diagnosis that says what to do with a number.
    if "present=0" in text or "is not loaded" in text:
        raise CtlError(
            "the hypervisor did not answer the control leaf: svmhv is not loaded, "
            "or was built with STEALTHV_CONTROL_INTERFACE 0"
        )
    if done.returncode:
        detail = text.strip()
        raise CtlError(
            f"svmhvctl exited with {done.returncode}"
            + (f": {detail}" if detail else ""))
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

CAPTURE_TYPES = ("ansi", "wide", "unicode", "objattr", "bytes", "irp")


def hook_options(process=None, pid=None, caller_base=None, caller_size=None,
                 filter_expr=None, capture=None, capture2=None,
                 spoof=None, spoof2=None, block=None, in_process=None,
                 capture_return=None, capture_stack=None) -> list[str]:
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
    if capture_return:
        options += ["--capture-return"]
    if capture_stack:
        options += ["--capture-stack"]
    if in_process is not None:
        # Which address space the *target* is in, as opposed to --pid, which
        # narrows what gets recorded once the hook is already placed.
        options += ["--in-process", str(int(in_process))]

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
    (0x0080, "always-flush-tlb"), (0x0100, "lbr"),
]
KIND_NAMES = {0: "exec", 1: "write-watch", 2: "access-watch"}
ACTION_NAMES = {0: "trace", 1: "detour", 2: "shellcode"}
TRACE_TYPES = {0: "exec", 1: "write", 2: "access", 3: "return", 4: "step",
               5: "msr", 6: "io", 7: "coverage"}

# The model-specific registers worth naming on sight. Not a complete list and
# not meant to be: these are the ones that turn up when something is looking
# for a hypervisor, or is talking to the local APIC, and seeing the name rather
# than the number is the difference between reading a trace and decoding one.
MSR_NAMES = {
    0x0000001B: "IA32_APIC_BASE",
    0x0000003A: "IA32_FEATURE_CONTROL",
    0x000000C0000080: "EFER",
    0xC0000080: "EFER",
    0xC0000081: "STAR",
    0xC0000082: "LSTAR",
    0xC0000083: "CSTAR",
    0xC0000084: "SFMASK",
    0xC0000100: "FS_BASE",
    0xC0000101: "GS_BASE",
    0xC0000102: "KERNEL_GS_BASE",
    0xC0000103: "TSC_AUX",
    0xC0010114: "VM_CR",
    0xC0010117: "VM_HSAVE_PA",
    0x00000277: "IA32_PAT",
    0x000001D9: "IA32_DEBUGCTL",
    0x00000010: "IA32_TIME_STAMP_COUNTER",
    0x000000E7: "IA32_MPERF",
    0x000000E8: "IA32_APERF",
}


def branch_line(row):
    """Where control came from, as the processor recorded it.

    Worth more than the stack candidates on anything obfuscated: a flattened
    or virtualised function can build whatever frames it likes, and cannot
    touch what the branch predictor wrote down.
    """
    frm = int(row.get("brfrom", "0"), 0)
    to = int(row.get("brto", "0"), 0)
    if not frm and not to:
        return None
    return f"      last branch {symbolize(frm)} -> {symbolize(to)}"


def msr_name(number: int) -> str:
    name = MSR_NAMES.get(number)
    if name:
        return f"{number:#x} ({name})"
    if 0x40000000 <= number <= 0x400000FF:
        # Hyper-V's synthetic range. The EOI register in particular is written
        # on every interrupt, which is where this driver's exit rate comes from.
        return f"{number:#x} (Hyper-V synthetic)"
    return f"{number:#x}"
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
    (0x0800, "trace captured the return value"),
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
    text = ctl("status")
    values = pairs(text)
    options = as_int(values, "options")
    exits = as_int(values, "exits")
    overhead = as_int(values, "overhead_cycles")

    lines = []

    # First, and unprompted. A processor that took a fatal exit left SVM and is
    # running unvirtualised, so every other number below is describing fewer
    # processors than it claims - and nothing else here would ever say so.
    fatal_count = as_int(values, "fatal_count")
    if fatal_count:
        lines += [
            f"!! {fatal_count} FATAL EXIT(S). That many processors have left "
            f"SVM and are running unvirtualised; the counters below cover the "
            f"rest. Reload the driver to bring them back.",
            "",
        ]
        for row in records(text, "fatalN"):
            lines.append(
                f"  #{row.get('seq')} cpu{row.get('cpu')} "
                f"{row.get('reason')} exit {row.get('exitcode')} "
                f"rip {symbolize(int(row.get('rip', '0'), 0))}")
            lines.append(
                f"       info1 {row.get('info1')} info2 {row.get('info2')} "
                f"exitintinfo {row.get('exitintinfo')} "
                f"cr2 {row.get('cr2')} cr3 {row.get('cr3')}")
        produced = as_int(values, "fatal_produced")
        kept = as_int(values, "fatal_ring")
        if produced > kept:
            lines.append(f"  ({produced - kept} older one(s) have been "
                         f"overwritten; the ring keeps {kept})")
        lines.append("")

    lines += [
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
        # Where the hook goes when it fires. For a shellcode hook that is the
        # page holding your own bytes, which is the only way to find it again -
        # to read what it wrote, or to check what is actually there.
        detour = int(row.get("detour", "0"), 0)
        if detour:
            lines.append(f"{'':>3} {'':<8} -> {ACTION_NAMES.get(action, '?')} "
                         f"at {detour:#018x}")

    lines.append("")
    lines.append("hits counts trace and watch firings; a shellcode hook does "
                 "not go through the recorder, so it stays at zero.")
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
            frames = row.get("frames")
            if frames:
                # The immediate caller is already on the line above; these are
                # the frames beyond it, which is what says why the call
                # happened rather than merely where from.
                # Only what lands in a module.  The driver keeps anything
                # that looks like a kernel address, which includes stack
                # pointers; a value that names no module is not a return
                # address and only makes the chain harder to read.
                named = []
                for frame in frames.split(","):
                    try:
                        address = int(frame, 0)
                    except ValueError:
                        continue
                    if module_for(address) is not None:
                        named.append(symbolize(address))
                if named:
                    entry.append("      stack (candidates read off the stack, "
                                 "not unwound - later entries may be stale):")
                    entry += [f"        {name}" for name in named[:8]]
            if int(row.get("spoofed", "0"), 0):
                entry.append(f"      {row['spoofed']} argument(s) replaced "
                             f"before the original saw them")
            for index in range(2):
                captured = row.get(f"cap{index}")
                if captured:
                    entry.append(f'      arg capture {index}: '
                                 f'"{decode_capture(captured)}"')
            lines.append("\n".join(entry))
        elif kind == 3:
            # A return record: the value is in the first argument slot and the
            # cycles the call took in the second. Rendering it as a watch would
            # show a guest physical address that means nothing here.
            cycles = int(row.get("a1", "0"), 0)
            lines.append(
                f"[{row.get('seq')}] hook {row.get('hook')} cpu{row.get('cpu')} "
                f"RETURNED {row.get('a0')} after {cycles:,} cycles, "
                f"to {symbolize(int(row.get('ret', '0'), 0))}")
        elif kind == 7:
            raw = int(row.get("err", "0"), 0)
            entry = [
                f"[{row.get('seq')}] cpu{row.get('cpu')} coverage: gpa "
                f"{int(row.get('a0', '0'), 0):#014x} first "
                f"{'executed' if raw & 16 else 'written'} from "
                f"{symbolize(int(row.get('rip', '0'), 0))}"]
            branch = branch_line(row)
            if branch:
                entry.append(branch)
            lines.append("\n".join(entry))
        elif kind == 5:
            written = int(row.get("a2", "0"), 0)
            lines.append(
                f"[{row.get('seq')}] cpu{row.get('cpu')} "
                f"{'wrmsr' if written else 'rdmsr'} "
                f"{msr_name(int(row.get('a0', '0'), 0))} "
                f"= {int(row.get('a1', '0'), 0):#x}  "
                f"from {symbolize(int(row.get('rip', '0'), 0))}")
        elif kind == 6:
            written = int(row.get("a2", "0"), 0)
            width = int(row.get("a3", "1"), 0)
            raw = int(row.get("err", "0"), 0)
            flags = [n for b, n in ((4, "string"), (8, "rep")) if raw & b]
            # An IN has no value yet when it is trapped - the instruction has
            # not run - so say nothing rather than print the accumulator.
            value = (f" = {int(row.get('a1', '0'), 0):#x}" if written else "")
            lines.append(
                f"[{row.get('seq')}] cpu{row.get('cpu')} "
                f"{'out' if written else 'in'}{width * 8} "
                f"port {int(row.get('a0', '0'), 0):#06x}{value}"
                + (f" [{'|'.join(flags)}]" if flags else "") +
                f"  from {symbolize(int(row.get('rip', '0'), 0))}")
        elif kind == 4:
            # A single step. There is no hook and no faulting address: the
            # whole record is "this instruction was about to run".
            code = row.get("code", "")
            text = ""
            if code:
                try:
                    _, text, _ = disassemble_one(bytes.fromhex(code), 0,
                                                 int(row.get("rip", "0"), 0))
                except (ValueError, IndexError):
                    text = f"({code})"
            lines.append(
                f"[{row.get('seq')}] cpu{row.get('cpu')} step "
                f"{symbolize(int(row.get('rip', '0'), 0))} "
                f"rflags {int(row.get('a0', '0'), 0):#08x}  {text}")
        else:
            error = int(row.get("err", "0"), 0)
            decoded = [n for b, n in ((1, "present"), (2, "write"),
                                      (4, "user"), (16, "fetch")) if error & b]
            entry = [
                f"[{row.get('seq')}] hook {row.get('hook')} cpu{row.get('cpu')} "
                f"{TRACE_TYPES.get(kind, '?')} gpa {row.get('gpa')} "
                f"from rip {symbolize(int(row.get('rip', '0'), 0))} "
                f"({'|'.join(decoded) or 'not-present'})"
            ]

            # What the location held before and after. The driver reads a fixed
            # window rather than decoding the store's width, so say which bytes
            # actually moved instead of pretending to know the operand size.
            width = int(row.get("width", "0"), 0)
            if width:
                before = int(row.get("before", "0"), 0)
                after = int(row.get("after", "0"), 0)
                if before == after:
                    entry.append(f"      value unchanged: "
                                 f"0x{before:0{width * 2}x}")
                else:
                    changed = [i for i in range(width)
                               if (before >> (i * 8)) & 0xFF !=
                                  (after >> (i * 8)) & 0xFF]
                    span = (f"byte {changed[0]}" if len(changed) == 1
                            else f"bytes {changed[0]}-{changed[-1]}")
                    entry.append(f"      0x{before:0{width * 2}x} -> "
                                 f"0x{after:0{width * 2}x}  ({span} of "
                                 f"{width} at +0x{int(row.get('gpa', '0'), 0) & 0xFFF:x})")

            # The instruction that did it, decoded here rather than costing the
            # caller another round trip for the one thing it always wants next.
            code = row.get("code")
            if code:
                try:
                    raw = bytes.fromhex(code)
                    _, text, _ = disassemble_one(raw, 0,
                                                 int(row.get("rip", "0"), 0))
                    entry.append(f"      {text}")
                except (ValueError, IndexError):
                    entry.append(f"      code {code}")

            # Not resolved to a process name here: that would mean attaching to
            # every process in turn to read its CR3, which is one hypercall
            # each and far too slow to do while rendering a trace. Printed raw
            # because the useful comparison is between records - the same CR3
            # twice is the same address space, which is what separates "one
            # thing is doing this" from "everything is".
            cr3 = row.get("cr3")
            if cr3:
                entry.append(f"      cr3 {cr3}")
            branch = branch_line(row)
            if branch:
                entry.append(branch)
            lines.append("\n".join(entry))
    return "\n".join(lines)


def tool_trace_summary(count: int = 200) -> str:
    """What the ring says, collapsed instead of transcribed.

    A hot hook produces thousands of near-identical records, and rendering them
    one by one buries the answer in the evidence - a model reading 200 full
    records has spent most of its attention before reaching the interesting
    one. The questions a summary actually answers are which processes hit this,
    who called it, and which argument values are distinct; the samples are there
    to drill into afterwards with svmhv_trace.
    """
    count = max(1, min(int(count), 200))
    text = ctl("trace", str(count))
    header = pairs(text)
    rows = records(text, "trace")
    produced = as_int(header, "produced")
    if not rows:
        return f"no trace records yet ({produced:,} produced)"

    by_hook: dict[str, list[dict]] = {}
    for row in rows:
        by_hook.setdefault(row.get("hook", "?"), []).append(row)

    lines = [f"{produced:,} records produced; summarising the newest {len(rows)}",
             ""]

    for hook_id, group in sorted(by_hook.items()):
        kinds = {int(r.get("type", "0"), 0) for r in group}
        kind = ("exec" if kinds == {0} else
                "watch" if 0 not in kinds else "mixed")
        lines.append(f"hook {hook_id}  ({kind})  {len(group)} record(s)")

        def tally(key, render=lambda v: v):
            counts: dict[str, int] = {}
            for row in group:
                value = row.get(key)
                if value is not None:
                    counts[render(value)] = counts.get(render(value), 0) + 1
            return sorted(counts.items(), key=lambda kv: -kv[1])

        processes_seen = tally("proc")
        if processes_seen:
            lines.append("  processes : " + ", ".join(
                f"{name} x{n}" for name, n in processes_seen[:6]))

        callers = tally("ret", lambda v: symbolize(int(v, 0)) if v else "?")
        if callers:
            lines.append("  callers   : " + ", ".join(
                f"{name} x{n}" for name, n in callers[:5]))

        # One representative stack. Which path reached the function is usually
        # the same for every call in a burst, so showing it once beats
        # repeating it sixty times.
        with_stack = [r for r in group if r.get("frames")]
        if with_stack:
            named = []
            for frame in with_stack[-1]["frames"].split(","):
                try:
                    address = int(frame, 0)
                except ValueError:
                    continue
                if module_for(address) is not None:
                    named.append(symbolize(address))
            if named:
                lines.append("  stack     : (candidates, not unwound)")
                lines += [f"      {name}" for name in named[:6]]

        cpus = tally("cpu")
        if cpus:
            lines.append("  processors: " + ", ".join(
                f"cpu{c} x{n}" for c, n in cpus[:8]))

        for index in range(4):
            values = tally(f"a{index}")
            if not values or len(values) > len(group) * 0.9:
                # All distinct means it is a pointer or a handle; saying "many
                # distinct" is more honest than listing them.
                if values:
                    lines.append(f"  arg{index}      : {len(values)} distinct value(s)")
                continue
            lines.append(f"  arg{index}      : " + ", ".join(
                f"{v} x{n}" for v, n in values[:4]))

        captures = [decode_capture(r[f"cap{i}"])
                    for r in group for i in range(2) if r.get(f"cap{i}")]
        if captures:
            unique = sorted(set(captures))
            lines.append(f"  captured  : {len(unique)} distinct; " +
                         ", ".join(f'"{c}"' for c in unique[:5]))

        newest = group[-1]
        lines.append(f"  newest    : seq {newest.get('seq')} "
                     f"{newest.get('proc', '-')} args {newest.get('a0')} "
                     f"{newest.get('a1')} {newest.get('a2')} {newest.get('a3')}")
        lines.append("")

    lines.append("Use svmhv_trace for the full records behind any of this.")
    return "\n".join(lines)


def tool_trace_reset() -> str:
    status = as_int(pairs(ctl("trace-reset")), "status", -1)
    return "trace ring reset" if status == 0 else f"failed: {status:#010x}"


def tool_sweep(mode: str = "exec", base: str = "0", size: str = "0") -> str:
    """Arm or disarm a coverage sweep over guest physical memory."""
    mode = mode.lower()
    if mode not in ("exec", "write", "both", "off"):
        return "mode must be exec, write, both or off"
    if mode == "off":
        result = pairs(ctl("sweep", "off"))
        status = as_int(result, "status", 0)
        return ("sweep disarmed; every page has its permission back"
                if not status else f"failed: {status & 0xFFFFFFFF:#010x}")

    result = pairs(ctl("sweep", mode, hexarg(base), hexarg(size)))
    status = as_int(result, "status", 0)
    if status:
        code = status & 0xFFFFFFFF
        why = ""
        if code == 0xC000000D:
            why = (" - the range needs one table page per 2 MiB and one "
                   "arming covers at most 8 GiB; do it in pieces")
        elif code == 0xC0000023:
            why = (" - the table pool was sized by the first sweep of this "
                   "load and this range needs more. Reload the driver and arm "
                   "the largest range first.")
        elif code == 0xC000009A:
            why = (" - no contiguous block that size. Ask for less, or reload "
                   "the driver when the guest is less fragmented.")
        elif code == 0xC0000206:
            why = (" - both-mode is capped at 64 MiB, and the cap is where the "
                   "evidence is: 2 GiB took every processor out of SVM and 256 "
                   "MiB powered the guest off. Taking write permission away "
                   "means faulting on nearly every page the guest touches, and "
                   "the storm starves the worker that would disarm it. Sweep a "
                   "range you have a reason to suspect.")
        return f"failed: {code:#010x}{why}"

    armed = as_int(result, "sweep_size")
    what = {"exec": "executed", "write": "written",
            "both": "written or executed"}[mode]
    lines = [f"sweeping {mode} over {armed / (1 << 20):,.0f} MiB from "
             f"{int(hexarg(base), 16):#x}",
             f"Every page in the range now faults once, the first time it is "
             f"{what}, and never again. Read the result with svmhv_coverage."]

    # An exec sweep is the cheap one and it is not free.  1 GiB has worked and
    # has also, on a guest that was already busy, produced a fault storm that
    # starved the control worker for minutes - and the control worker is the
    # only thing that can disarm a sweep, so there is no way back except a hard
    # reset of the machine.  The driver's own limit is about table pages, not
    # about this, so the warning lives here.
    if mode == "exec" and armed > (256 << 20):
        lines += [
            "",
            f"That is {armed / (1 << 20):,.0f} MiB, which is past where this "
            f"has been comfortable. An exec sweep faults once per page ever, "
            f"but over a range this size the storm can starve the control "
            f"worker - and that worker is the only thing that can disarm the "
            f"sweep, so the machine has to be reset to get out of it. Sweep a "
            f"range you have a reason to suspect.",
        ]
    if mode == "both":
        lines += [
            "",
            "This is the mode that finds manually mapped code. A page written "
            "and THEN executed had its code arrive after its mapping did, "
            "which an image loaded by the section manager never does - so "
            "what comes back marked that way is a manual map, an unpacker or "
            "a JIT, and very little else.",
        ]
    return "\n".join(lines)


def tool_coverage(limit: int = 400, unknown_only: bool = True) -> str:
    """What the sweep found, with the pages no module accounts for first.

    The whole point is the last column. A page that falls inside a loaded
    module is code somebody declared; a page that falls in none is either a
    manual map, a JIT, or a page of data that happened to be jumped to - and
    those three are exactly what is worth looking at next.
    """
    text = ctl("trace", str(min(limit, 200)))
    produced = as_int(pairs(text), "produced")
    rows = [row for row in records(text, "trace")
            if int(row.get("type", "0"), 0) == 7]
    if not rows:
        return ("no coverage records. Either nothing has run in the range "
                "yet, or the sweep is not armed - svmhv_sweep arms it.")

    # Three buckets, not two. The module list this agent can see is the KERNEL
    # module list, so testing a user-mode RIP against it says "unknown" for
    # every thread in every process - which would bury the one answer the tool
    # exists to give under all of ordinary user-mode execution.
    # Written-then-executed comes out on its own and first. Everything else
    # here is "code ran", which is ordinary; this is "code arrived, and then
    # ran", which almost nothing legitimate does.
    known, unknown, user, wx = [], [], [], []
    for row in rows:
        gpa = int(row.get("a0", "0"), 0)
        rip = int(row.get("rip", "0"), 0)
        cr3 = int(row.get("cr3", "0"), 0)
        state = int(row.get("a1", "0"), 0)
        if state & 0x04:                    # SVMHV_PAGE_WRITE_FIRST
            wx.append((gpa, rip, cr3))
            continue
        if rip < 0xFFFF800000000000:
            user.append((gpa, rip, cr3))
        elif module_for(rip) is not None:
            known.append((gpa, rip, cr3))
        else:
            unknown.append((gpa, rip, cr3))

    lines = [f"{len(rows)} page(s) in the most recent records: {len(wx)} "
             f"WRITTEN THEN EXECUTED, {len(unknown)} run from kernel "
             f"addresses no loaded module accounts for, {len(known)} from "
             f"inside a known module, {len(user)} from user mode"]

    if wx:
        lines += ["", "WRITTEN THEN EXECUTED - code that arrived after its "
                      "mapping did. This is what a manual map looks like:"]
        for gpa, rip, cr3 in wx[:limit]:
            lines.append(f"  gpa {gpa:#014x}  first executed from "
                         f"{symbolize(rip)}  cr3 {cr3:#x}")
        lines.append("  Dump one with svmhv_read_physical at that gpa. The "
                     "page was written before it ran, so whatever wrote it is "
                     "the loader worth finding next.")
    if produced > len(rows):
        # A sweep over a live range produces thousands of these, and this reads
        # only the newest slice of the ring. Say so rather than let a sample
        # read as a total.
        lines.append(f"This is a SAMPLE: {produced:,} records have been "
                     f"produced in all and only the newest are read here. "
                     f"Narrow the swept range, or reset the ring before "
                     f"arming, to see a whole run.")
    lines.append("")

    if unknown:
        lines.append("KERNEL pages no module claims - the interesting ones:")
        for gpa, rip, cr3 in unknown[:limit]:
            lines.append(f"  gpa {gpa:#014x}  first run from rip {rip:#018x}"
                         f"  cr3 {cr3:#x}")
        lines.append("")
        lines.append("Read one with svmhv_read_physical, or svmhv_disassemble "
                     "at the RIP if it is still mapped. A kernel address in no "
                     "module is either a manual map or a pool allocation "
                     "somebody jumped to.")

    if user:
        # Grouping by CR3 is the only attribution available from here: the
        # recorder runs with GIF clear and does not call Ps* to name a process.
        spaces = {}
        for gpa, rip, cr3 in user:
            spaces.setdefault(cr3, 0)
            spaces[cr3] += 1
        lines.append("")
        lines.append(f"user-mode pages, by address space ({len(spaces)} "
                     f"distinct CR3s):")
        for cr3, count in sorted(spaces.items(), key=lambda kv: -kv[1])[:16]:
            lines.append(f"  cr3 {cr3:#014x}  {count} page(s)")
        lines.append("  Not attributed to a process: that would need a Ps* "
                     "call from the exit handler, which this driver does not "
                     "do. Two records with the same CR3 are the same process.")

    if known and not unknown_only:
        lines.append("")
        lines.append("pages inside a loaded module:")
        for gpa, rip, _ in known[:limit]:
            lines.append(f"  gpa {gpa:#014x}  {symbolize(rip)}")
    elif known:
        lines.append("")
        lines.append(f"({len(known)} pages inside loaded modules not shown; "
                     f"pass unknown_only=false for those)")
    return "\n".join(lines)


def tool_watch_msr(msr: str, enabled: bool = True) -> str:
    """Trap a model-specific register and record every access."""
    number = hexarg(msr)
    result = pairs(ctl("watchmsr", number, "on" if enabled else "off"))
    status = as_int(result, "status", 0)
    if status:
        return f"failed: {status & 0xFFFFFFFF:#010x}"
    if not enabled:
        return f"no longer watching msr {msr_name(int(number, 16))}"
    return (f"watching msr {msr_name(int(number, 16))}\n"
            f"Reads and writes both. The MSR intercept is on for the whole "
            f"machine either way when EFER is being hidden, so this costs a "
            f"scan of the watch list per MSR exit and nothing else.")


def tool_watch_io(port: str, enabled: bool = True) -> str:
    """Trap an I/O port and record every IN or OUT."""
    number = hexarg(port)
    result = pairs(ctl("watchio", number, "on" if enabled else "off"))
    status = as_int(result, "status", 0)
    if status:
        return f"failed: {status & 0xFFFFFFFF:#010x}"
    if not enabled:
        return f"no longer watching port {int(number, 16):#06x}"
    return (f"watching port {int(number, 16):#06x}\n"
            f"The instruction is not emulated - the port is unarmed for one "
            f"single step and the bit goes back afterwards - so INS and OUTS "
            f"with a repeat prefix behave exactly as they would unwatched. An "
            f"IN is recorded without a value, because when it is trapped it "
            f"has not read anything yet.")


def tool_step(count: int = 16) -> str:
    """Single-step the processor that issues the request.

    Deliberately not "step this address": the trap flag lives in a VMCB, so a
    step is armed on a processor, not on a target, and it begins at the
    instruction after the hypercall that armed it. What gets recorded is
    svmhvctl's own code — which is the point of having it, because every
    instruction in it is known and the run can therefore be checked rather
    than merely observed.
    """
    if not 1 <= count <= 4096:
        return "count must be between 1 and 4096"

    result = pairs(ctl("step", str(count)))
    text = ctl("trace", str(min(count + 8, 200)))
    rows = [row for row in records(text, "trace")
            if int(row.get("type", "0"), 0) == 4]

    lines = [f"armed {count} step(s); {len(rows)} step record(s) came back "
             f"({as_int(pairs(text), 'produced'):,} produced in all)"]

    # The reading that matters is the one taken while the window was open. A
    # read afterwards proves nothing: the flag has been put back by then, so a
    # build that hid nothing would look exactly the same.
    during = as_int(result, "tf_during", -1)
    after = as_int(result, "tf_after", -1)
    exposed = as_int(result, "exposed_windows", 0)

    if during == 0 and count < 64:
        # The read is a good forty instructions past the hypercall, so a short
        # run has already disarmed itself by the time it happens and a clear
        # flag says nothing either way. Do not let it read as a pass.
        lines.append(f"trap flag read back clear, but {count} steps end before "
                     f"the read is reached - this says nothing about whether "
                     f"it was hidden. Ask for 200 or more.")
    elif during == 0:
        lines.append("trap flag as the guest read it mid-run: clear - PUSHF "
                     "is being intercepted and answered")
    elif during > 0:
        lines.append("trap flag as the guest read it mid-run: SET - the guest "
                     "can see it is being stepped")
    if after > 0:
        lines.append("trap flag after the run: STILL SET. The window should "
                     "have disarmed itself - that is a bug, not a concealment "
                     "weakness.")
    not_ours = as_int(result, "db_not_ours", 0)
    abandoned = as_int(result, "watch_steps_abandoned", 0)
    if not_ours:
        lines.append(f"{not_ours} debug exception(s) were handed to the guest "
                     f"during a step window. Unless something in the guest is "
                     f"using hardware breakpoints, that is our own #DB being "
                     f"injected into code that never asked for it.")
    drained = as_int(result, "db_drained", 0)
    if abandoned:
        lines.append(f"{abandoned} watch step(s) on this processor ended "
                     f"somewhere other than their own #DB - expected under "
                     f"interrupt load; it costs a duplicate watch record and "
                     f"another attempt at the store")
    if drained:
        lines.append(f"{drained} stale debug exception(s) were swallowed after "
                     f"a window ended early. These are the trap flag coming "
                     f"back off an interrupt frame; swallowing them is what "
                     f"keeps the guest from seeing a single-step it never set.")
    if exposed:
        lines.append(f"{exposed} window(s) have given up hiding the flag "
                     f"because the guest's stack was in an address space the "
                     f"exit handler could not reach. That is the expected "
                     f"answer for a user-mode step: the host's CR3 at an exit "
                     f"is whichever process the processor launched in.")
    lines.append("")

    # The ring is not per-run, so a short request can be outnumbered by records
    # left over from a previous one. Show the ends rather than everything.
    shown = rows[-count:] if count <= len(rows) else rows
    head, tail = shown[:20], shown[-20:] if len(shown) > 40 else []

    def render(row):
        code = row.get("code", "")
        text = ""
        if code:
            try:
                _, text, _ = disassemble_one(bytes.fromhex(code), 0,
                                             int(row.get("rip", "0"), 0))
            except (ValueError, IndexError):
                text = f"({code})"
        return (f"  {int(row.get('rip', '0'), 0):#018x}  "
                f"rflags {int(row.get('a0', '0'), 0):#08x}  {text}")

    lines += [render(row) for row in head]
    if tail:
        lines.append(f"  ... {len(shown) - 40} more ...")
        lines += [render(row) for row in tail]

    if not rows:
        lines.append("  (none - if the driver is loaded and this is empty, "
                     "the #DB intercept is not reaching the handler)")
    elif not any(row.get("code") for row in shown):
        lines.append("")
        lines.append("No instruction bytes: the same address-space problem. "
                     "The handler will read them from a kernel RIP, or from "
                     "anywhere when the processor supports decode assists, "
                     "and otherwise records the address alone.")
    return "\n".join(lines)


def hook_target(target: str, prolog: int | None,
                in_process: int = 0) -> tuple[str, str, str]:
    """Resolve a target and settle on a prologue length.

    Both halves exist because both are things a caller gets wrong. The target
    may now be 'nt!NtCreateFile' instead of an address nobody can verify by
    eye, and the length - the parameter the driver's own documentation warns
    will corrupt the function - is decoded from the bytes rather than defaulted
    to 14 and hoped for. An explicit length is still honoured; a caller who has
    disassembled the function themselves outranks this.
    """
    address = resolve(target, in_process)
    note = ""

    if prolog is None:
        try:
            computed = safe_prolog_length(read_bytes(address, 64, in_process))
        except (CtlError, DecodeError) as error:
            raise CtlError(
                f"could not work out a safe prologue for {target}: {error}. "
                "Pass prolog_length explicitly if you have decoded it yourself."
            )
        note = f", prologue {computed} bytes (decoded)"
        prolog = computed

    return f"{address:x}", str(prolog), note


def tool_hook_trace(target: str, prolog_length: int | None = None,
                    **options) -> str:
    target_pid = int(options.get("in_process") or 0)
    address, prolog, note = hook_target(target, prolog_length, target_pid)
    extra = hook_options(**options)
    return hook_result(
        ctl("hook-trace", address, prolog, *extra),
        f"tracing {target}{note}" + (f" [{' '.join(extra)}]" if extra else ""))


def tool_hook_detour(target: str, detour: str, prolog_length: int | None = None,
                     **options) -> str:
    target_pid = int(options.get("in_process") or 0)
    address, prolog, note = hook_target(target, prolog_length, target_pid)
    extra = hook_options(**options)
    return hook_result(
        ctl("hook-detour", address, prolog, f"{resolve(detour, target_pid):x}", *extra),
        f"detoured {target} -> {detour}{note}")


def tool_assemble(source: str, base: str = "0") -> str:
    """Assemble and show what would actually run, without installing anything."""
    try:
        code, listing = assemble_checked(source, _parse_number(base))
    except AsmError as error:
        return f"assembly failed: {error}"
    return "\n".join([
        f"{len(code)} bytes  ({engines()})", "", listing, "",
        f"hex: {code.hex()}",
        "",
        "That listing is the disassembler reading back what the assembler "
        "produced, not a repeat of your input - if they disagreed this would "
        "have failed instead.",
    ])


def tool_hook_shellcode(target: str, shellcode_hex: str = "", asm: str = "",
                        prolog_length: int | None = None, **options) -> str:
    listing = ""
    if asm:
        if shellcode_hex:
            return "give either asm or shellcode_hex, not both"
        try:
            code, listing = assemble_checked(asm, 0)
        except AsmError as error:
            return f"assembly failed: {error}"
        cleaned = code.hex()
    else:
        cleaned = shellcode_hex.replace(" ", "").replace("0x", "").replace(",", "")
    if not cleaned or len(cleaned) % 2:
        return "give asm, or shellcode_hex as an even number of hex digits"
    if len(cleaned) // 2 > 1024:
        return f"shellcode is {len(cleaned) // 2} bytes; the limit is 1024"
    target_pid = int(options.get("in_process") or 0)
    address, prolog, note = hook_target(target, prolog_length, target_pid)
    extra = hook_options(**options)
    outcome = hook_result(
        ctl("hook-shellcode", address, prolog, cleaned, *extra),
        f"{len(cleaned) // 2} bytes of shellcode on {target}{note}")

    # Show what was installed, not what was asked for.  These bytes run in
    # kernel mode with nothing catching a fault, so the listing is the last
    # chance to notice that they are not what was meant.
    return outcome + (f"\n\nwhat will run:\n{listing}" if listing else "")


def tool_watch(target: str, mode: str = "write", **options) -> str:
    if mode not in ("write", "access"):
        return "mode must be 'write' or 'access'"
    extra = hook_options(**options)
    target_pid = int(options.get("in_process") or 0)
    return hook_result(ctl("watch", f"{resolve(target, target_pid):x}", mode, *extra),
                       f"{mode} watch on the page holding {target}")


def tool_hook_many(module: str, contains: str, limit: int = 24,
                   **options) -> str:
    """Instrument every export whose name matches, in one call.

    This is what several hooks per page bought. Before that, the second
    install into any page failed, and kernel functions are packed several to a
    page - so "trace every Nt* entry point" did not fail cleanly, it failed on
    an arbitrary subset determined by where the linker put things.

    Each target still gets its prologue decoded separately, and one that cannot
    be decoded is skipped and named rather than hooked with a guessed length.
    """
    limit = max(1, min(int(limit), 64))
    target_pid = int(options.get("in_process") or 0)
    resolved = process_module_by_name(target_pid, module) if target_pid \
        else module_by_name(module)
    if resolved is None:
        return (f"no module called {module!r} in pid {target_pid}" if target_pid
                else f"no loaded module called {module!r}")

    wanted = contains.lower()
    targets = [(a, n) for a, n in exports(resolved["base"], target_pid)
               if wanted in n.lower()]
    if not targets:
        return f"{resolved['name']} exports nothing matching {contains!r}"

    extra = hook_options(**options)
    installed, skipped = [], []
    for address, name in targets[:limit]:
        try:
            prolog = safe_prolog_length(read_bytes(address, 64, target_pid))
        except (CtlError, DecodeError) as error:
            skipped.append(f"{name}: {error}")
            continue
        text = ctl("hook-trace", f"{address:x}", str(prolog), *extra)
        values = pairs(text)
        if as_int(values, "status", -1) & 0xFFFFFFFF:
            skipped.append(f"{name}: "
                           f"{STATUS_NAMES.get(as_int(values, 'status') & 0xFFFFFFFF, 'failed')}")
        else:
            installed.append(f"{name} (id {as_int(values, 'hookid')}, "
                             f"prologue {prolog})")

    lines = [f"{len(installed)} of {min(len(targets), limit)} hooked"]
    if len(targets) > limit:
        lines[0] += f"; {len(targets) - limit} more matched but the limit is {limit}"
    lines += [""] + [f"  {entry}" for entry in installed]
    if skipped:
        lines += ["", f"{len(skipped)} skipped:"] + [f"  {s}" for s in skipped]
    lines += ["", "svmhv_trace_summary is the way to read what these produce; "
              "svmhv_unhook_all takes them all off again."]
    return "\n".join(lines)


def tool_watch_range(target: str, size: int, mode: str = "write",
                     **options) -> str:
    """Watch every page a range touches.

    A watch traps a page, but a structure or a buffer worth watching is a
    range, and asking somebody to work out which pages that covers is asking
    them to get it wrong at the edges. This installs one watch per page and
    reports them as a group.
    """
    if mode not in ("write", "access"):
        return "mode must be 'write' or 'access'"
    size = max(1, min(int(size), 64 * 4096))

    target_pid = int(options.get("in_process") or 0)
    start = resolve(target, target_pid)
    first = start & ~0xFFF
    last = (start + size - 1) & ~0xFFF
    pages = list(range(first, last + 0x1000, 0x1000))

    extra = hook_options(**options)
    installed, failed = [], []
    for page in pages:
        values = pairs(ctl("watch", f"{page:x}", mode, *extra))
        if as_int(values, "status", -1) & 0xFFFFFFFF:
            failed.append(f"{page:#x}: "
                          f"{STATUS_NAMES.get(as_int(values, 'status') & 0xFFFFFFFF, 'failed')}")
        else:
            installed.append(page)

    lines = [f"{mode} watch over {size} byte(s) at {target} "
             f"= {len(pages)} page(s), {len(installed)} armed"]
    for page in installed:
        lines.append(f"  {page:#018x}")
    if failed:
        lines += ["", "failed:"] + [f"  {f}" for f in failed]
    lines += ["", "A watch fires twice per store and traps the WHOLE page, so "
              "these will also report accesses to whatever else shares them."]
    return "\n".join(lines)


def tool_unhook_all() -> str:
    """Take everything off, in one call.

    The panic button. An agent exploring will eventually arm something that
    floods the ring or slows the machine badly enough that issuing removals one
    at a time is painful, and that is exactly when it needs to be one call.
    """
    removed, failed = 0, []
    for hook in records(ctl("hooks"), "hook"):
        if hook.get("active") != "1":
            continue
        target = hook.get("target", "0")
        status = as_int(pairs(ctl("unhook", hexarg(target))), "status", -1)
        if status == 0:
            removed += 1
        else:
            failed.append(f"{target}: {status & 0xFFFFFFFF:#010x}")

    if removed == 0 and not failed:
        return "nothing was armed"
    lines = [f"removed {removed} hook(s)"]
    if failed:
        lines += ["", "failed:"] + [f"  {f}" for f in failed]
    return "\n".join(lines)


def tool_unhook(target: str, pid: int = 0) -> str:
    # Symbols everywhere a target is accepted, or the tool that installed a hook
    # by name cannot remove it by the same name.
    status = as_int(pairs(ctl("unhook", f"{resolve(target, pid):x}")), "status", -1)
    return (f"removed the hook on {target}" if status == 0
            else f"remove failed: {status & 0xFFFFFFFF:#010x}")


# ------------------------------------------------- x86-64 instruction lengths

# Instructions whose length depends only on the opcode, for the one-byte map.
# The value is (has_modrm, immediate_bytes); an immediate of -1 means it follows
# the operand size, which is 4 unless a 0x66 prefix made it 2.
_ONE_BYTE = {}


def _fill_one_byte():
    for base in (0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38):
        for offset in range(6):
            # add/or/adc/sbb/and/sub/xor/cmp: 4 modrm forms then AL/eAX,imm
            _ONE_BYTE[base + offset] = (offset < 4, 0 if offset < 4
                                        else (1 if offset == 4 else -1))
    for opcode in range(0x50, 0x60):            # push/pop r64
        _ONE_BYTE[opcode] = (False, 0)
    for opcode in range(0x70, 0x80):            # jcc rel8
        _ONE_BYTE[opcode] = (False, 1)
    for opcode in range(0xB0, 0xB8):            # mov r8, imm8
        _ONE_BYTE[opcode] = (False, 1)
    for opcode in range(0xB8, 0xC0):            # mov r32/64, imm32/imm64
        _ONE_BYTE[opcode] = (False, -1)
    _ONE_BYTE.update({
        0x63: (True, 0),                        # movsxd
        0x68: (False, -1), 0x6A: (False, 1),    # push imm
        0x69: (True, -1),  0x6B: (True, 1),     # imul
        0x80: (True, 1),   0x81: (True, -1), 0x83: (True, 1),
        0x84: (True, 0),   0x85: (True, 0),
        0x86: (True, 0),   0x87: (True, 0),
        0x88: (True, 0),   0x89: (True, 0), 0x8A: (True, 0), 0x8B: (True, 0),
        0x8D: (True, 0),                        # lea
        0x8F: (True, 0),                        # pop r/m
        0x90: (False, 0),                       # nop
        0x98: (False, 0),  0x99: (False, 0),
        0x9C: (False, 0),  0x9D: (False, 0),    # pushfq/popfq
        0xC0: (True, 1),   0xC1: (True, 1),     # shifts by imm8
        0xC2: (False, 2),  0xC3: (False, 0),    # ret
        0xC6: (True, 1),   0xC7: (True, -1),    # mov r/m, imm
        0xC9: (False, 0),                       # leave
        0xCC: (False, 0),
        0xD0: (True, 0),   0xD1: (True, 0), 0xD2: (True, 0), 0xD3: (True, 0),
        0xE8: (False, 4),  0xE9: (False, 4),    # call/jmp rel32
        0xEB: (False, 1),                       # jmp rel8
        0xF6: (True, 1),   0xF7: (True, -1),    # test/not/neg/mul/div
        0xF8: (False, 0),  0xF9: (False, 0),
        0xFE: (True, 0),   0xFF: (True, 0),     # inc/dec/call/jmp/push
    })


_fill_one_byte()

# Two-byte opcodes (0F xx) that appear in real prologues and thunks.
_TWO_BYTE = {
    0x05: (False, 0),                           # syscall
    0x0B: (False, 0),                           # ud2
    0x10: (True, 0), 0x11: (True, 0),           # movups/movsd
    0x1E: (True, 0),                            # endbr64
    0x1F: (True, 0),                            # multi-byte nop
    0x28: (True, 0), 0x29: (True, 0),           # movaps
    0x6E: (True, 0), 0x7E: (True, 0),           # movd/movq
    0x6F: (True, 0), 0x7F: (True, 0),
    0xA2: (False, 0),                           # cpuid
    0xB6: (True, 0), 0xB7: (True, 0),           # movzx
    0xBE: (True, 0), 0xBF: (True, 0),           # movsx
    0xAF: (True, 0),                            # imul
    0xD6: (True, 0),
}
for _op in range(0x80, 0x90):                   # jcc rel32
    _TWO_BYTE[_op] = (False, 4)
for _op in range(0x90, 0xA0):                   # setcc
    _TWO_BYTE[_op] = (True, 0)
for _op in range(0x40, 0x50):                   # cmovcc
    _TWO_BYTE[_op] = (True, 0)


class DecodeError(ValueError):
    pass


def instruction_length(code: bytes, at: int = 0) -> int:
    """Length of the instruction at `at`.

    This is what decides a hook's prologue, so it is the one place where being
    wrong corrupts a function.  Capstone answers it when present.
    """
    if _CS is not None:
        for insn in _CS.disasm(code[at:at + 16], 0, count=1):
            return insn.size
        raise DecodeError(f"capstone cannot decode {code[at:at + 8].hex()}")
    return _instruction_length_builtin(code, at)


def _instruction_length_builtin(code: bytes, at: int = 0) -> int:
    """Length of the x86-64 instruction at `at`.

    A length decoder, not a disassembler: it answers "where does the next
    instruction start", which is the only question that has to be right to
    place a hook. It covers the ordinary integer and SSE encodings a compiler
    emits for a function prologue and raises on anything it does not recognise,
    which is the safe direction to be wrong in - refusing to hook is a nuisance,
    guessing a boundary corrupts the function.
    """
    i = at
    operand = 4
    rex_w = False

    while i < len(code):                        # prefixes
        byte = code[i]
        if byte in (0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65):
            i += 1
        elif byte == 0x66:
            operand = 2
            i += 1
        elif byte == 0x67:
            i += 1
        else:
            break

    if i < len(code) and 0x40 <= code[i] <= 0x4F:   # REX
        rex_w = bool(code[i] & 0x08)
        i += 1

    if i >= len(code):
        raise DecodeError("ran off the end in the prefixes")

    opcode = code[i]
    i += 1
    if opcode == 0x0F:
        if i >= len(code):
            raise DecodeError("truncated two-byte opcode")
        entry = _TWO_BYTE.get(code[i])
        if entry is None:
            raise DecodeError(f"unknown opcode 0f {code[i]:02x}")
        i += 1
    else:
        entry = _ONE_BYTE.get(opcode)
        if entry is None:
            raise DecodeError(f"unknown opcode {opcode:02x}")

    has_modrm, immediate = entry
    if rex_w:
        operand = 8 if opcode in range(0xB8, 0xC0) else 4

    if has_modrm:
        if i >= len(code):
            raise DecodeError("truncated modrm")
        modrm = code[i]
        i += 1
        mod = modrm >> 6
        rm = modrm & 7

        if mod != 3 and rm == 4:                # SIB
            if i >= len(code):
                raise DecodeError("truncated sib")
            sib = code[i]
            i += 1
            if mod == 0 and (sib & 7) == 5:
                i += 4                          # disp32, no base
        if mod == 1:
            i += 1
        elif mod == 2:
            i += 4
        elif mod == 0 and rm == 5:
            i += 4                              # RIP-relative

        # Group 1/3 opcodes where /digit selects a form with no immediate.
        if opcode in (0xF6, 0xF7) and ((modrm >> 3) & 7) not in (0, 1):
            immediate = 0

    if immediate == -1:
        immediate = operand
    i += immediate

    if i > len(code):
        raise DecodeError("instruction runs past the bytes provided")
    return i - at


def safe_prolog_length(code: bytes, minimum: int = 14) -> int:
    """Smallest instruction boundary at or after `minimum` bytes.

    This is the number the driver wants and the one a human most often gets
    wrong: overwriting 14 bytes that end in the middle of an instruction leaves
    the tail of it as the first thing the trampoline executes.
    """
    total = 0
    while total < minimum:
        total += instruction_length(code, total)
    return total


# ------------------------------------------------------------- disassembly

REG64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
REG32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
         "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"]
REG8 = ["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"]

ARITH = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"]
SHIFT = ["rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar"]
CONDITION = ["o", "no", "b", "ae", "e", "ne", "be", "a",
             "s", "ns", "p", "np", "l", "ge", "le", "g"]
GROUP3 = ["test", "test", "not", "neg", "mul", "imul", "div", "idiv"]
GROUP5 = ["inc", "dec", "call", "callf", "jmp", "jmpf", "push", "?"]


def _register(index: int, size: int) -> str:
    if size == 8:
        return REG64[index]
    if size == 4:
        return REG32[index]
    if size == 1:
        return REG8[index]
    return REG64[index]


def _signed(value: int, width: int) -> int:
    top = 1 << (width * 8 - 1)
    return value - (top << 1) if value & top else value


def _hex(value: int) -> str:
    return f"-0x{-value:x}" if value < 0 else f"0x{value:x}"


def _immediate(raw: int, width: int, operand_size: int) -> int:
    """An immediate, signed only where the processor sign-extends it.

    An imm8 is sign-extended to the operand size and reads correctly as a small
    negative number; an imm32 against a 64-bit operand is too. An imm32 against
    a 32-bit register is neither - it is the bit pattern, and rendering it
    signed is actively misleading: a vendor IOCTL with its top bit set, which
    is most of them, comes out as 'cmp eax, -0x63bfdbf8' and matches nothing
    anybody would search for.
    """
    if width == 1 or operand_size == 8:
        return _signed(raw, width)
    return raw


class _Operand:
    """One decoded ModRM, rendered lazily so RIP-relative can use the address."""

    def __init__(self, text, rip_target=None):
        self.text = text
        self.rip_target = rip_target


def _decode_modrm(code, i, size, rex_b, rex_x, rex_r):
    """Returns (operand, reg_index, next_offset)."""
    modrm = code[i]
    i += 1
    mod, reg, rm = modrm >> 6, ((modrm >> 3) & 7) | (rex_r << 3), modrm & 7

    if mod == 3:
        return _Operand(_register(rm | (rex_b << 3), size)), reg, i

    base = None
    index_text = ""
    if rm == 4:                                     # SIB
        sib = code[i]
        i += 1
        scale, index, sib_base = sib >> 6, ((sib >> 3) & 7) | (rex_x << 3), sib & 7
        if index != 4:
            index_text = f"+{REG64[index]}*{1 << scale}"
        if mod == 0 and sib_base == 5:
            displacement = _signed(int.from_bytes(code[i:i + 4], "little"), 4)
            i += 4
            return _Operand(f"[{_hex(displacement)}{index_text}]"), reg, i
        base = REG64[sib_base | (rex_b << 3)]
    elif mod == 0 and rm == 5:                      # RIP-relative
        displacement = _signed(int.from_bytes(code[i:i + 4], "little"), 4)
        i += 4
        return _Operand("[rip%+#x]" % displacement, rip_target=displacement), reg, i
    else:
        base = REG64[rm | (rex_b << 3)]

    displacement = 0
    if mod == 1:
        displacement = _signed(code[i], 1)
        i += 1
    elif mod == 2:
        displacement = _signed(int.from_bytes(code[i:i + 4], "little"), 4)
        i += 4

    inside = base + index_text
    if displacement:
        inside += ("+" if displacement > 0 else "-") + f"0x{abs(displacement):x}"
    return _Operand(f"[{inside}]"), reg, i


def disassemble_one(code: bytes, at: int, address: int) -> tuple[int, str, int | None]:
    """One instruction: (length, text, branch target).

    Capstone when available, the built-in decoder otherwise.  The branch target
    is what makes a listing useful - the caller resolves it to a symbol - so it
    is extracted from the decoded operands rather than by parsing the text.
    """
    if _CS is not None:
        return _disassemble_capstone(code, at, address)
    return _disassemble_builtin(code, at, address)


def _disassemble_capstone(code: bytes, at: int, address: int):
    for insn in _CS.disasm(code[at:at + 16], address, count=1):
        text = f"{insn.mnemonic} {insn.op_str}".strip()
        target = None

        try:
            groups = insn.groups
            is_branch = (_capstone.CS_GRP_JUMP in groups or
                         _capstone.CS_GRP_CALL in groups)
            for operand in insn.operands:
                if is_branch and operand.type == _capstone.x86.X86_OP_IMM:
                    # Capstone resolves a relative branch to its destination,
                    # but hands it back signed. Every kernel address is above
                    # 2^63, so it arrives negative - and a negative address
                    # matches no module, which silently drops the symbol from
                    # the listing rather than failing.
                    target = operand.imm & 0xFFFFFFFFFFFFFFFF
                elif (operand.type == _capstone.x86.X86_OP_MEM and
                      operand.mem.base == _capstone.x86.X86_REG_RIP):
                    # Render RIP-relative against the real address: "[rip +
                    # 0xff0]" is only actionable once it is an address.
                    absolute = insn.address + insn.size + operand.mem.disp
                    text = re.sub(r"\[rip \+ 0x[0-9a-f]+\]", f"[{absolute:#x}]",
                                  text)
                    text = re.sub(r"\[rip - 0x[0-9a-f]+\]", f"[{absolute:#x}]",
                                  text)
        except (AttributeError, _capstone.CsError):
            pass                                    # detail unavailable

        return insn.size, text, target

    raise DecodeError(f"capstone cannot decode {code[at:at + 8].hex()}")


def _disassemble_builtin(code: bytes, at: int, address: int) -> tuple[int, str, int | None]:
    """Decode one instruction.

    Returns (length, text, branch_target). Not a complete disassembler - it
    covers the integer subset a compiler emits, and anything it does not
    recognise comes back as 'db' rather than a guess, because a wrong mnemonic
    is worse than an honest gap. The branch target is what makes it useful for
    reverse engineering: it is resolved to a symbol by the caller, so a listing
    shows which functions this one calls.
    """
    length = instruction_length(code, at)
    raw = code[at:at + length]
    i = at
    size = 4
    rex_b = rex_x = rex_r = 0
    segment = ""

    while i < len(code):
        byte = code[i]
        if byte == 0x66:
            size = 2
            i += 1
        elif byte in (0x64, 0x65):
            # fs:/gs: is never noise on x64 - gs is where the KPCR lives, so
            # "gs:[0x188]" is the current thread and "[0x188]" is nonsense.
            segment = "fs:" if byte == 0x64 else "gs:"
            i += 1
        elif byte in (0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x67):
            i += 1
        else:
            break

    if 0x40 <= code[i] <= 0x4F:
        rex = code[i]
        rex_b, rex_x, rex_r = rex & 1, (rex >> 1) & 1, (rex >> 2) & 1
        if rex & 8:
            size = 8
        i += 1

    opcode = code[i]
    i += 1
    text = None
    target = None

    def modrm(operand_size=None):
        return _decode_modrm(code, i, operand_size or size, rex_b, rex_x, rex_r)

    if opcode == 0x0F:
        second = code[i]
        i += 1
        if 0x80 <= second <= 0x8F:
            delta = _signed(int.from_bytes(code[i:i + 4], "little"), 4)
            target = address + length + delta
            text = f"j{CONDITION[second - 0x80]} {target:#x}"
        elif 0x90 <= second <= 0x9F:
            operand, _, i = modrm(1)
            text = f"set{CONDITION[second - 0x90]} {operand.text}"
        elif 0x40 <= second <= 0x4F:
            operand, reg, i = modrm()
            text = f"cmov{CONDITION[second - 0x40]} {_register(reg, size)}, {operand.text}"
        elif second in (0xB6, 0xB7, 0xBE, 0xBF):
            operand, reg, i = modrm(1 if second in (0xB6, 0xBE) else 2)
            name = "movzx" if second in (0xB6, 0xB7) else "movsx"
            text = f"{name} {_register(reg, size)}, {operand.text}"
        elif second == 0xAF:
            operand, reg, i = modrm()
            text = f"imul {_register(reg, size)}, {operand.text}"
        elif second == 0x1E:
            text = "endbr64"
        elif second == 0x1F:
            operand, _, i = modrm()
            text = f"nop {operand.text}"
        elif second == 0x05:
            text = "syscall"
        elif second == 0x0B:
            text = "ud2"
        elif second == 0xA2:
            text = "cpuid"
    elif opcode < 0x40 and (opcode & 7) < 6 and (opcode >> 3) < 8:
        name = ARITH[opcode >> 3]
        low = opcode & 7
        if low in (0, 1, 2, 3):
            operand_size = 1 if low in (0, 2) else size
            operand, reg, i = modrm(operand_size)
            register = _register(reg, operand_size)
            text = (f"{name} {operand.text}, {register}" if low in (0, 1)
                    else f"{name} {register}, {operand.text}")
        else:
            width = 1 if low == 4 else min(size, 4)
            value = _immediate(int.from_bytes(code[i:i + width], "little"),
                               width, size)
            i += width
            text = f"{name} {_register(0, 1 if low == 4 else size)}, {_hex(value)}"
    elif 0x50 <= opcode <= 0x57:
        text = f"push {REG64[(opcode - 0x50) | (rex_b << 3)]}"
    elif 0x58 <= opcode <= 0x5F:
        text = f"pop {REG64[(opcode - 0x58) | (rex_b << 3)]}"
    elif 0x70 <= opcode <= 0x7F:
        delta = _signed(code[i], 1)
        target = address + length + delta
        text = f"j{CONDITION[opcode - 0x70]} {target:#x}"
    elif opcode in (0x80, 0x81, 0x83):
        operand_size = 1 if opcode == 0x80 else size
        operand, reg, i = modrm(operand_size)
        width = 1 if opcode in (0x80, 0x83) else min(size, 4)
        value = _immediate(int.from_bytes(code[i:i + width], "little"), width,
                           operand_size)
        i += width
        text = f"{ARITH[reg & 7]} {operand.text}, {_hex(value)}"
    elif opcode in (0x84, 0x85):
        operand_size = 1 if opcode == 0x84 else size
        operand, reg, i = modrm(operand_size)
        text = f"test {operand.text}, {_register(reg, operand_size)}"
    elif opcode in (0x88, 0x89, 0x8A, 0x8B):
        operand_size = 1 if opcode in (0x88, 0x8A) else size
        operand, reg, i = modrm(operand_size)
        register = _register(reg, operand_size)
        text = (f"mov {operand.text}, {register}" if opcode in (0x88, 0x89)
                else f"mov {register}, {operand.text}")
    elif opcode == 0x8D:
        operand, reg, i = modrm()
        text = f"lea {_register(reg, size)}, {operand.text}"
    elif opcode == 0x90:
        text = "nop"
    elif 0xB8 <= opcode <= 0xBF:
        width = 8 if size == 8 else 4
        value = int.from_bytes(code[i:i + width], "little")
        i += width
        text = f"mov {_register((opcode - 0xB8) | (rex_b << 3), size)}, {value:#x}"
    elif 0xB0 <= opcode <= 0xB7:
        text = f"mov {REG8[(opcode - 0xB0) | (rex_b << 3)]}, {code[i]:#x}"
        i += 1
    elif opcode in (0xC0, 0xC1, 0xD0, 0xD1, 0xD3):
        operand, reg, i = modrm()
        if opcode in (0xC0, 0xC1):
            text = f"{SHIFT[reg & 7]} {operand.text}, {code[i]:#x}"
            i += 1
        elif opcode == 0xD3:
            text = f"{SHIFT[reg & 7]} {operand.text}, cl"
        else:
            text = f"{SHIFT[reg & 7]} {operand.text}, 1"
    elif opcode == 0xC3:
        text = "ret"
    elif opcode == 0xC9:
        text = "leave"
    elif opcode == 0xCC:
        text = "int3"
    elif opcode in (0xC6, 0xC7):
        operand_size = 1 if opcode == 0xC6 else size
        operand, _, i = modrm(operand_size)
        width = 1 if opcode == 0xC6 else min(size, 4)
        value = int.from_bytes(code[i:i + width], "little")
        i += width
        text = f"mov {operand.text}, {value:#x}"
    elif opcode in (0xE8, 0xE9):
        delta = _signed(int.from_bytes(code[i:i + 4], "little"), 4)
        target = address + length + delta
        text = f"{'call' if opcode == 0xE8 else 'jmp'} {target:#x}"
    elif opcode == 0xEB:
        delta = _signed(code[i], 1)
        target = address + length + delta
        text = f"jmp {target:#x}"
    elif opcode in (0xF6, 0xF7):
        operand_size = 1 if opcode == 0xF6 else size
        operand, reg, i = modrm(operand_size)
        name = GROUP3[reg & 7]
        if (reg & 7) in (0, 1):
            width = 1 if opcode == 0xF6 else min(size, 4)
            value = int.from_bytes(code[i:i + width], "little")
            i += width
            text = f"{name} {operand.text}, {value:#x}"
        else:
            text = f"{name} {operand.text}"
    elif opcode == 0xFF:
        operand, reg, i = modrm()
        text = f"{GROUP5[reg & 7]} {operand.text}"
        if operand.rip_target is not None:
            target = address + length + operand.rip_target
    elif opcode == 0x63:
        operand, reg, i = modrm(4)
        text = f"movsxd {_register(reg, 8)}, {operand.text}"
    elif opcode in (0x68, 0x6A):
        width = 1 if opcode == 0x6A else 4
        value = _signed(int.from_bytes(code[i:i + width], "little"), width)
        i += width
        text = f"push {_hex(value)}"

    if text is not None and segment and "[" in text:
        text = text[:text.index("[")] + segment + text[text.index("["):]

    if text is None:
        text = "db " + " ".join(f"{b:02x}" for b in raw)
    elif "[rip" in text:
        # Render RIP-relative against the real address, which is the only form
        # a reader can do anything with.
        for operand_text in (text,):
            pass
        delta = None
        marker = text.index("[rip")
        end = text.index("]", marker)
        inside = text[marker + 4:end]
        try:
            delta = int(inside, 16) if inside.startswith(("0x", "-0x")) else int(inside, 0)
        except ValueError:
            delta = None
        if delta is not None:
            absolute = address + length + delta
            text = text[:marker] + f"[{absolute:#x}]" + text[end + 1:]
            if target is None:
                target = None      # a data reference, not a branch

    return length, text, target


# ------------------------------------------------------- assembly engines

"""
Keystone assembles and Capstone disassembles when they are installed; the
hand-written pair below takes over when they are not.

Both are used, rather than one, and the pairing is the point.  The check that
matters here is that bytes about to run in kernel mode are disassembled back
and shown before they are installed - and that check is only worth something
when the two sides are independent.  Assembling and disassembling with code
written by the same author from the same reading of the encoding tables lets a
shared misconception pass unnoticed: both sides get ModRM wrong the same way
and agree.  Keystone against Capstone are separate implementations, so a
disagreement is real information.

The fallback stays because the agent is otherwise stdlib-only and a guest with
no pip should still be able to write a simple stub.  It is a smaller language -
no RIP-relative, no indirect call, no scaled index - and it says so.
"""

# Set SVMHV_NO_ENGINES=1 to ignore both and use the fallback.  CI runs the
# tests each way for exactly this reason: the fallback is what a guest with no
# pip gets, and it is only tested if something deliberately selects it.
_NO_ENGINES = os.environ.get("SVMHV_NO_ENGINES") == "1"

try:
    if _NO_ENGINES:
        raise ImportError("disabled by SVMHV_NO_ENGINES")
    import keystone as _keystone
    _KS = _keystone.Ks(_keystone.KS_ARCH_X86, _keystone.KS_MODE_64)
except Exception:                                   # not installed, or broken
    _keystone = None
    _KS = None

try:
    if _NO_ENGINES:
        raise ImportError("disabled by SVMHV_NO_ENGINES")
    import capstone as _capstone
    _CS = _capstone.Cs(_capstone.CS_ARCH_X86, _capstone.CS_MODE_64)
    _CS.detail = True
except Exception:
    _capstone = None
    _CS = None


def engines() -> str:
    return (f"assembler: {'keystone' if _KS else 'built-in subset'}, "
            f"disassembler: {'capstone' if _CS else 'built-in subset'}")


# --------------------------------------------------------------- assembly

class AsmError(ValueError):
    pass


_ARITH_OPCODES = {"add": 0, "or": 1, "adc": 2, "sbb": 3,
                  "and": 4, "sub": 5, "xor": 6, "cmp": 7}
_SIZE_NAMES = {"byte": 1, "word": 2, "dword": 4, "qword": 8}


def _register_number(name: str) -> tuple[int, int]:
    """(number, size in bytes) for a register name."""
    name = name.lower()
    for table, size in ((REG64, 8), (REG32, 4), (REG8, 1)):
        if name in table:
            return table.index(name), size
    raise AsmError(f"unknown register {name!r}")


class _PendingLabels(dict):
    """Labels during the first pass, when forward ones are not placed yet.

    Every branch is encoded as a rel32 whatever the distance, so an
    instruction's size never depends on where its target turns out to be -
    which lets pass one answer zero for a label it has not seen and still
    measure every instruction correctly.
    """

    def __contains__(self, key):
        return dict.__contains__(self, key) or key.replace("_", "").isalnum()

    def __missing__(self, key):
        return 0


def _parse_number(text: str, labels: dict[str, int] | None = None) -> int:
    text = text.strip()
    if labels is not None and text in labels:
        return labels[text]
    negative = text.startswith("-")
    if negative:
        text = text[1:]
    try:
        value = int(text, 16) if text.lower().startswith("0x") else int(text, 0)
    except ValueError:
        raise AsmError(f"{text!r} is not a number")
    return -value if negative else value


class _Memory:
    def __init__(self, base, displacement, size):
        self.base = base                    # register number
        self.displacement = displacement
        self.size = size                    # operand size in bytes, or None


def _parse_operand(text: str):
    """A register, an immediate, or [base+displacement]."""
    text = text.strip()
    size = None

    for name, width in _SIZE_NAMES.items():
        if text.lower().startswith(name):
            size = width
            text = text[len(name):].strip()
            if text.lower().startswith("ptr"):
                text = text[3:].strip()
            break

    if text.startswith("["):
        if not text.endswith("]"):
            raise AsmError(f"unclosed memory operand in {text!r}")
        inside = text[1:-1].strip()
        displacement = 0
        for separator in ("+", "-"):
            index = inside.find(separator, 1)
            if index > 0:
                displacement = _parse_number(inside[index:].replace("+", ""))
                if separator == "-":
                    displacement = -abs(_parse_number(inside[index + 1:]))
                inside = inside[:index].strip()
                break
        if "*" in inside:
            raise AsmError("scaled index operands are not supported")
        base, _ = _register_number(inside)
        return _Memory(base, displacement, size)

    try:
        number, width = _register_number(text)
        return ("reg", number, width)
    except AsmError:
        pass
    return ("imm", text)


def _rex(w, reg, rm_base, force=False):
    value = 0x40 | (0x08 if w else 0) | ((reg >> 3) << 2) | (rm_base >> 3)
    return bytes([value]) if (value != 0x40 or force) else b""


def _modrm_memory(reg: int, memory: _Memory) -> bytes:
    base = memory.base & 7
    displacement = memory.displacement

    # rbp/r13 as a base with mod=00 means RIP-relative, so it always needs a
    # displacement byte; rsp/r12 as a base always needs a SIB to express it.
    if displacement == 0 and base != 5:
        mod = 0
        tail = b""
    elif -128 <= displacement <= 127:
        mod = 1
        tail = bytes([displacement & 0xFF])
    else:
        mod = 2
        tail = (displacement & 0xFFFFFFFF).to_bytes(4, "little")

    out = bytes([(mod << 6) | ((reg & 7) << 3) | base])
    if base == 4:
        out += b"\x24"                      # SIB: base=rsp, no index
    return out + tail


def assemble_line(text: str, address: int, labels: dict[str, int]) -> bytes:
    """One instruction. Intel syntax, the subset a hook stub needs."""
    text = text.split(";")[0].strip()
    if not text:
        return b""

    parts = text.split(None, 1)
    mnemonic = parts[0].lower()
    operands = [o.strip() for o in parts[1].split(",")] if len(parts) > 1 else []

    if mnemonic in ("ret", "retn"):
        return b"\xC3"
    if mnemonic == "nop":
        return b"\x90"
    if mnemonic in ("int3", "brk"):
        return b"\xCC"
    if mnemonic == "leave":
        return b"\xC9"

    if mnemonic in ("push", "pop") and len(operands) == 1:
        number, size = _register_number(operands[0])
        if size != 8:
            raise AsmError(f"{mnemonic} takes a 64-bit register")
        prefix = b"\x41" if number >= 8 else b""
        return prefix + bytes([(0x50 if mnemonic == "push" else 0x58)
                               + (number & 7)])

    if mnemonic in ("jmp", "call") and len(operands) == 1:
        target = _parse_number(operands[0], labels)
        delta = target - (address + 5)
        return bytes([0xE9 if mnemonic == "jmp" else 0xE8]) + \
            (delta & 0xFFFFFFFF).to_bytes(4, "little")

    if mnemonic.startswith("j") and mnemonic[1:] in CONDITION and len(operands) == 1:
        target = _parse_number(operands[0], labels)
        delta = target - (address + 6)
        return bytes([0x0F, 0x80 + CONDITION.index(mnemonic[1:])]) + \
            (delta & 0xFFFFFFFF).to_bytes(4, "little")

    if len(operands) != 2:
        raise AsmError(f"{mnemonic!r} with {len(operands)} operand(s) is not "
                       "supported")

    left = _parse_operand(operands[0])
    right = _parse_operand(operands[1])

    # mov reg, imm - the only place a 64-bit immediate is encodable.
    if mnemonic == "mov" and isinstance(left, tuple) and left[0] == "reg" \
            and isinstance(right, tuple) and right[0] == "imm":
        number, size = left[1], left[2]
        value = _parse_number(right[1], labels)
        if size == 8:
            # Shellcode has a 1024-byte budget and small constants are most of
            # what a stub loads, so take the shorter encodings where they are
            # exactly equivalent. Writing a 32-bit register zero-extends into
            # the full 64, which covers every value that fits unsigned - and
            # 0xC0000022, the status code most likely to be loaded here, is one
            # of them. A negative value needs the sign-extended form instead.
            if 0 <= value <= 0xFFFFFFFF:
                return _rex(False, 0, number) + bytes([0xB8 + (number & 7)]) + \
                    value.to_bytes(4, "little")
            if -0x80000000 <= value < 0:
                return _rex(True, 0, number) + \
                    bytes([0xC7, 0xC0 | (number & 7)]) + \
                    (value & 0xFFFFFFFF).to_bytes(4, "little")
            return _rex(True, 0, number) + bytes([0xB8 + (number & 7)]) + \
                (value & (2 ** 64 - 1)).to_bytes(8, "little")
        if size == 4:
            return _rex(False, 0, number) + bytes([0xB8 + (number & 7)]) + \
                (value & 0xFFFFFFFF).to_bytes(4, "little")
        raise AsmError("mov to an 8-bit register with an immediate is not "
                       "supported")

    if mnemonic in ("mov", "lea") or mnemonic in _ARITH_OPCODES or \
            mnemonic == "test":
        # reg, reg
        if isinstance(left, tuple) and left[0] == "reg" and \
                isinstance(right, tuple) and right[0] == "reg":
            if mnemonic == "lea":
                raise AsmError("lea needs a memory operand")
            size = left[2]
            opcode = {"mov": 0x89, "test": 0x85}.get(
                mnemonic, (_ARITH_OPCODES.get(mnemonic, 0) << 3) | 0x01)
            if size == 1:
                opcode -= 1
            return _rex(size == 8, right[1], left[1]) + \
                bytes([opcode, 0xC0 | ((right[1] & 7) << 3) | (left[1] & 7)])

        # reg, [mem]  and  lea reg, [mem]
        if isinstance(left, tuple) and left[0] == "reg" and \
                isinstance(right, _Memory):
            size = left[2]
            opcode = {"mov": 0x8B, "lea": 0x8D}.get(
                mnemonic, (_ARITH_OPCODES.get(mnemonic, 0) << 3) | 0x03)
            return _rex(size == 8, left[1], right.base) + bytes([opcode]) + \
                _modrm_memory(left[1], right)

        # [mem], reg
        if isinstance(left, _Memory) and isinstance(right, tuple) and \
                right[0] == "reg":
            size = right[2]
            opcode = {"mov": 0x89}.get(
                mnemonic, (_ARITH_OPCODES.get(mnemonic, 0) << 3) | 0x01)
            if size == 1:
                opcode -= 1
            return _rex(size == 8, right[1], left.base) + bytes([opcode]) + \
                _modrm_memory(right[1], left)

        # reg, imm  /  [mem], imm
        if isinstance(right, tuple) and right[0] == "imm":
            value = _parse_number(right[1], labels)
            if mnemonic == "mov":
                if isinstance(left, _Memory):
                    size = left.size or 8
                    return _rex(size == 8, 0, left.base) + bytes([0xC7]) + \
                        _modrm_memory(0, left) + \
                        (value & 0xFFFFFFFF).to_bytes(4, "little")
                raise AsmError("unreachable: handled above")

            digit = _ARITH_OPCODES.get(mnemonic)
            if digit is None:
                raise AsmError(f"{mnemonic} with an immediate is not supported")
            short = -128 <= value <= 127
            if isinstance(left, _Memory):
                size = left.size or 8
                return _rex(size == 8, 0, left.base) + \
                    bytes([0x83 if short else 0x81]) + \
                    _modrm_memory(digit, left) + \
                    (bytes([value & 0xFF]) if short
                     else (value & 0xFFFFFFFF).to_bytes(4, "little"))
            size = left[2]
            return _rex(size == 8, 0, left[1]) + \
                bytes([0x83 if short else 0x81,
                       0xC0 | (digit << 3) | (left[1] & 7)]) + \
                (bytes([value & 0xFF]) if short
                 else (value & 0xFFFFFFFF).to_bytes(4, "little"))

    raise AsmError(f"{text!r} is not in the supported subset")


def assemble(source: str, base_address: int = 0) -> bytes:
    """Assemble Intel-syntax source.

    Keystone when available - it knows the whole instruction set, including the
    RIP-relative loads the shellcode contract is designed around and the
    indirect calls a stub needs to reach the trampoline. The built-in below
    covers a much smaller language and is only reached when keystone is not
    installed.
    """
    if _KS is not None:
        try:
            encoded, _ = _KS.asm(source, addr=base_address)
        except Exception as error:
            raise AsmError(f"keystone: {error}")
        code = bytes(encoded) if encoded else b""
    else:
        code = _assemble_builtin(source, base_address)

    # The same answer whichever engine ran.  Keystone raises on empty input and
    # the fallback quietly returns nothing, and a caller that asked for code and
    # got none should hear about it either way - not have an empty shellcode
    # installed on a function.
    if not code:
        raise AsmError("that assembled to no instructions at all")
    return code


def _assemble_builtin(source: str, base_address: int = 0) -> bytes:
    """The fallback assembler: Intel syntax, labels resolved in a second pass."""
    lines = []
    # ';' introduces a comment, which assemble_line strips - it is not a
    # separator, or "mov rax, 1 ; set the result" becomes two instructions.
    for raw in source.splitlines():
        piece = raw.strip()
        if piece:
            lines.append(piece)

    # Pass one: sizes, to place the labels.
    labels: dict[str, int] = {}
    address = base_address
    pending = []
    for line in lines:
        if line.endswith(":") and " " not in line[:-1]:
            labels[line[:-1]] = address
            continue
        pending.append((address, line))
        address += len(assemble_line(line, address, _PendingLabels()))

    # Pass two: the real thing, now that every label has an address.
    out = bytearray()
    for at, line in pending:
        encoded = assemble_line(line, base_address + len(out), labels)
        out += encoded
    return bytes(out)


def assemble_checked(source: str, base_address: int = 0) -> tuple[bytes, str]:
    """Assemble, then read the result back with the disassembler.

    The round trip is the point.  These bytes are about to run in kernel mode
    on a real thread with no exception handling around them, so the thing worth
    having is not a promise that the assembler is right but a listing of what
    will actually execute, produced by a separate decoder that has been read
    against real ntoskrnl.  If the two disagree the code is refused - an
    encoding neither of them agrees on is not one to find out about in ring 0.
    """
    code = assemble(source, base_address)
    if not code:
        raise AsmError("nothing to assemble")

    lines = []
    offset = 0
    while offset < len(code):
        try:
            length, text, _ = disassemble_one(code, offset, base_address + offset)
        except DecodeError as error:
            raise AsmError(
                f"assembled to bytes the disassembler cannot read back at "
                f"offset {offset}: {error}. "
                f"bytes so far: {code[offset:offset + 8].hex()}")
        lines.append(f"  {base_address + offset:#06x}  "
                     f"{code[offset:offset + length].hex():<24} {text}")
        offset += length

    return code, "\n".join(lines)


def instruction_offsets(code: bytes, limit: int = 32) -> list[int]:
    offsets = []
    at = 0
    while at < len(code) and len(offsets) < limit:
        offsets.append(at)
        try:
            at += instruction_length(code, at)
        except DecodeError:
            break
    return offsets


# ------------------------------------------------------------------- memory


def dump_bytes(text: str) -> bytes:
    """Recover the raw bytes from svmhvctl's hex dump.

    The dump is laid out for a human - address, sixteen hex pairs, an ASCII
    column - and a model reading it back needs the bytes, not the picture. Both
    are worth returning: the picture is what makes a structure legible, the
    bytes are what a follow-up question is asked about.
    """
    out = bytearray()
    for line in text.splitlines():
        parts = line.split("  ")
        if len(parts) < 2 or len(parts[0]) != 16:
            continue
        try:
            int(parts[0], 16)
        except ValueError:
            continue
        for token in parts[1].split():
            if len(token) == 2:
                out.append(int(token, 16))
    return bytes(out)


def memory_result(text: str, what: str) -> str:
    values = pairs(text)
    status = as_int(values, "status", -1)
    if status != 0:
        # A short read is reported as a success with fewer bytes; only a
        # transfer of nothing at all comes back as a failure, and the usual
        # reason is that nothing is mapped there.
        return (f"{what} failed: {status & 0xFFFFFFFF:#010x}"
                + (" (nothing readable at that address)"
                   if status & 0xFFFFFFFF == 0x8000000D else ""))
    raw = dump_bytes(text)
    return f"{what}: {len(raw)} bytes\n\n{text.strip()}\n\nhex: {raw.hex()}"


def tool_read(address: str, length: int = 64, pid: int = 0) -> str:
    length = max(1, min(int(length), 4096))
    arguments = ["read", hexarg(address), str(length)]
    if pid:
        arguments.append(str(int(pid)))
    where = f"process {pid}" if pid else "kernel space"
    return memory_result(ctl(*arguments), f"read {length} bytes at {address} in {where}")


def tool_read_physical(gpa: str, length: int = 64) -> str:
    length = max(1, min(int(length), 4096))
    return memory_result(ctl("readphys", hexarg(gpa), str(length)),
                         f"read {length} bytes at guest physical {gpa}")


def tool_write_physical(gpa: str, hex_bytes: str) -> str:
    cleaned = "".join(hex_bytes.split()).removeprefix("0x").lower()
    if not cleaned or len(cleaned) % 2 or any(c not in "0123456789abcdef"
                                              for c in cleaned):
        return "hex_bytes must be an even number of hex digits"
    if len(cleaned) // 2 > 4096:
        return "at most 4096 bytes, and it may not cross a page boundary"

    text = ctl("writephys", hexarg(gpa), cleaned)
    values = pairs(text)
    status = as_int(values, "status", -1)
    if status != 0:
        return f"write failed: {status & 0xFFFFFFFF:#010x}"
    return (f"wrote {as_int(values, 'written')} of {len(cleaned) // 2} bytes "
            f"at guest physical {gpa}")


def tool_translate(address: str, pid: int = 0) -> str:
    arguments = ["translate", hexarg(address)]
    if pid:
        arguments.append(str(int(pid)))
    text = ctl(*arguments)
    values = pairs(text)

    gpa = as_int(values, "gpa", 0)
    if not gpa:
        return f"{address} is not mapped"

    where = f"process {pid}" if pid else "kernel space"
    return (f"{address} in {where} is guest physical {gpa:#x}\n"
            f"page {gpa & ~0xFFF:#x}, offset {gpa & 0xFFF:#x}")


def tool_write(address: str, hex_bytes: str, pid: int = 0) -> str:
    cleaned = "".join(hex_bytes.split()).removeprefix("0x").lower()
    if not cleaned or len(cleaned) % 2 or any(c not in "0123456789abcdef"
                                              for c in cleaned):
        return "hex_bytes must be an even number of hex digits"
    if len(cleaned) // 2 > 4096:
        return "at most 4096 bytes per write"

    arguments = ["write", hexarg(address), cleaned]
    if pid:
        arguments.append(str(int(pid)))
    text = ctl(*arguments)
    values = pairs(text)
    status = as_int(values, "status", -1)
    if status != 0:
        return f"write failed: {status & 0xFFFFFFFF:#010x}"
    return (f"wrote {as_int(values, 'written')} of {len(cleaned) // 2} bytes "
            f"at {address}" + (f" in process {pid}" if pid else ""))


# ------------------------------------------------------- modules and symbols

# How far past an exported symbol an address may be before the name stops
# meaning anything. Functions in ntoskrnl are rarely larger than this, so
# beyond it the nearest export is almost certainly not the one containing the
# address. Private symbols would remove the guesswork; without a PDB this is
# the honest boundary.
SYMBOL_MAX_OFFSET = 0x2000

_modules_cache: list[dict] = []
_exports_cache: dict[object, list[tuple[int, str]]] = {}


def read_bytes(address: int, length: int, pid: int = 0) -> bytes:
    """Raw read, for the parsers below. Raises rather than returning a report."""
    arguments = ["read", f"{address:x}", str(length)]
    if pid:
        arguments.append(str(int(pid)))
    text = ctl(*arguments)
    if as_int(pairs(text), "status", -1) != 0:
        raise CtlError(f"nothing readable at {address:#x}")
    return dump_bytes(text)


def modules(refresh: bool = False) -> list[dict]:
    global _modules_cache
    if _modules_cache and not refresh:
        return _modules_cache

    found = []
    for record in records(ctl("modules"), "module"):
        try:
            found.append({
                "base": int(record["base"], 0),
                "size": int(record["size"], 0),
                "name": record.get("name", "?"),
                "path": record.get("path", ""),
            })
        except (KeyError, ValueError):
            continue
    _modules_cache = found
    return found


_modules_fetched = 0.0


def module_for(address: int, pid: int = 0) -> dict | None:
    """Which loaded module an address belongs to.

    Refreshes once on a miss.  The list is cached because every symbolized
    address consults it, but drivers load and unload while a session is
    running - this one unloads and reloads constantly - and a cache filled
    before that happened reports "not inside any loaded module" for addresses
    that plainly are.  A miss is the only reliable signal that it is stale.
    """
    if pid:
        for module in process_modules(int(pid)):
            if module["base"] <= address < module["base"] + module["size"]:
                return module
        return None

    global _modules_fetched

    for module in modules():
        if module["base"] <= address < module["base"] + module["size"]:
            return module

    if time.time() - _modules_fetched > 5:
        _modules_fetched = time.time()
        for module in modules(refresh=True):
            if module["base"] <= address < module["base"] + module["size"]:
                return module
    return None


def module_by_name(name: str) -> dict | None:
    wanted = name.lower()
    for module in modules():
        if module["name"].lower() == wanted:
            return module
    # "nt" is what everybody calls the kernel, and it is not what it is called.
    if wanted in ("nt", "ntoskrnl", "kernel"):
        for module in modules():
            if module["name"].lower().startswith("ntoskrnl"):
                return module
    return None


def known_symbols(base: int) -> list[tuple[int, str]]:
    """Everything nameable in a module: PDB symbols if loaded, else exports.

    A PDB replaces rather than supplements, because its public symbol table
    already contains the exports - keeping both would report every exported
    function twice, once under each name it happens to have.
    """
    if base in _pdb_symbols:
        return _pdb_symbols[base]

    # Fetch and load once per module, at the moment something first wants a
    # name. Attempted at most once either way: a module with no PDB on the
    # server must not turn every later lookup into another round trip.
    if SYMBOLS_AUTO and base not in _symbol_attempts:
        with _symbol_lock:
            if base not in _symbol_attempts:
                _symbol_attempts.add(base)
                try:
                    path = fetch_pdb(base)
                    _attach_pdb(base, path)
                except Exception as error:       # exports still work below
                    _symbol_failures[base] = str(error)
                else:
                    _symbol_failures.pop(base, None)
        if base in _pdb_symbols:
            return _pdb_symbols[base]

    return exports(base)


def exports(base: int, pid: int = 0) -> list[tuple[int, str]]:
    """Every exported name in the image at `base`, as (address, name).

    Parsed straight out of the mapped image with the memory read primitive, so
    it needs no symbol server, no PDB and no network - which matters because the
    machine being reverse engineered is usually a lab VM with none of the three.
    It only sees exports, not private symbols; for the kernel that is still
    several thousand functions and every Nt* entry point.
    """
    cache_key = (base, int(pid)) if pid else base
    if cache_key in _exports_cache:
        return _exports_cache[cache_key]

    header = read_bytes(base, 0x400, pid)
    if header[:2] != b"MZ":
        raise CtlError(f"no MZ header at {base:#x}")

    pe_offset = int.from_bytes(header[0x3C:0x40], "little")
    if pe_offset + 0x200 > len(header) or header[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise CtlError(f"no PE header at {base:#x}")

    # Optional header: magic 0x20B is PE32+, where the data directory starts at
    # 0x70 from the optional header rather than 0x60.
    optional = pe_offset + 0x18
    magic = int.from_bytes(header[optional:optional + 2], "little")
    directory = optional + (0x70 if magic == 0x20B else 0x60)
    export_rva = int.from_bytes(header[directory:directory + 4], "little")
    export_size = int.from_bytes(header[directory + 4:directory + 8], "little")
    if export_rva == 0 or export_size == 0:
        _exports_cache[cache_key] = []
        return []

    # The export directory and its three arrays are contiguous and usually well
    # under a page; read it in page-sized pieces because that is the transfer
    # unit the driver offers.
    blob = bytearray()
    for offset in range(0, min(export_size, 0x20000), 0x1000):
        blob += read_bytes(base + export_rva + offset,
                           min(0x1000, export_size - offset), pid)

    def dword(at):
        return int.from_bytes(blob[at:at + 4], "little")

    count_names = dword(0x18)
    functions_rva = dword(0x1C)
    names_rva = dword(0x20)
    ordinals_rva = dword(0x24)

    def table(rva, entries, width):
        """Read a table that may fall outside the block already fetched."""
        start = rva - export_rva
        if 0 <= start and start + entries * width <= len(blob):
            return bytes(blob[start:start + entries * width])
        out = bytearray()
        wanted = entries * width
        for offset in range(0, wanted, 0x1000):
            out += read_bytes(base + rva + offset,
                              min(0x1000, wanted - offset), pid)
        return bytes(out)

    names = table(names_rva, count_names, 4)
    ordinals = table(ordinals_rva, count_names, 2)
    functions = table(functions_rva, dword(0x14), 4)

    # Name strings are scattered; fetch the pages they live on once each.
    pages: dict[int, bytes] = {}

    def string_at(rva):
        out = bytearray()
        while len(out) < 256:
            page = (base + rva) & ~0xFFF
            if page not in pages:
                try:
                    pages[page] = read_bytes(page, 0x1000, pid)
                except CtlError:
                    return ""
            chunk = pages[page][(base + rva) & 0xFFF:]
            if b"\0" in chunk:
                return bytes(out + chunk[:chunk.index(b"\0")]).decode(
                    "ascii", "replace")
            out += chunk
            rva += len(chunk)
        return bytes(out).decode("ascii", "replace")

    found = []
    for i in range(count_names):
        name_rva = int.from_bytes(names[i * 4:i * 4 + 4], "little")
        ordinal = int.from_bytes(ordinals[i * 2:i * 2 + 2], "little")
        if (ordinal + 1) * 4 > len(functions):
            continue
        function_rva = int.from_bytes(
            functions[ordinal * 4:ordinal * 4 + 4], "little")
        if function_rva == 0:
            continue
        name = string_at(name_rva)
        if name:
            found.append((base + function_rva, name))

    found.sort()
    _exports_cache[cache_key] = found
    return found


def resolve(name: str, pid: int = 0) -> int:
    """Resolve a kernel or process-local ``module!symbol`` / hex address."""
    text = name.strip()
    if "!" not in text:
        return int(hexarg(text), 16)

    module_name, symbol = text.split("!", 1)
    symbol_pid = int(pid)
    module = process_module_by_name(symbol_pid, module_name) if symbol_pid \
        else module_by_name(module_name)
    if module is None and symbol_pid:
        # A user-mode listing still needs to resolve imports/calls into nt.
        # The target itself may be process-local, but its named callee needn't.
        module = module_by_name(module_name)
        symbol_pid = 0
    if module is None:
        where = f" in pid {pid}" if pid else ""
        raise CtlError(f"no loaded module called {module_name!r}{where}")

    offset = 0
    if "+" in symbol:
        symbol, _, plus = symbol.partition("+")
        offset = int(plus, 0)

    symbols = exports(module["base"], symbol_pid) if symbol_pid \
        else known_symbols(module["base"])
    for address, export in symbols:
        if export.lower() == symbol.lower():
            return address + offset
    raise CtlError(
        f"{module['name']} has no symbol called {symbol!r} "
        + ("(private symbols are loaded, so it is genuinely absent)"
           if not symbol_pid and module["base"] in _pdb_symbols else
           "(only exports are known in this address space)"))


def symbolize(address: int, pid: int = 0) -> str:
    """The inverse: an address as module!symbol+offset, as far as it can."""
    if address == 0:
        return "0"
    module = module_for(address, int(pid)) if pid else module_for(address)
    symbol_pid = int(pid) if module is not None and pid else 0
    # User code calls into the kernel constantly.  When the branch leaves the
    # process module list, retain the kernel name instead of rendering a raw
    # address just because the original read happened in a process context.
    if module is None and pid:
        module = module_for(address)
    if module is None:
        return f"{address:#x}"

    best = None
    try:
        symbols = exports(module["base"], symbol_pid) if symbol_pid \
            else known_symbols(module["base"])
        for export_address, name in symbols:
            if export_address <= address and (best is None
                                              or export_address > best[0]):
                best = (export_address, name)
    except CtlError:
        best = None

    if best is None:
        return f"{module['name']}+{address - module['base']:#x}"

    delta = address - best[0]

    # Only exports are known, so "nearest export" is only the containing
    # function when the address is close to it. Deep inside a module the
    # nearest export is usually thousands of bytes away and belongs to some
    # unrelated function - naming it would be a confident wrong answer, and a
    # caller acting on "ntoskrnl!_setjmpex+0x9138" would be misled about what
    # called what. Past the threshold, say where it is and stop claiming to
    # know what it is.
    if delta > SYMBOL_MAX_OFFSET and (symbol_pid or
                                      module["base"] not in _pdb_symbols):
        return f"{module['name']}+{address - module['base']:#x}"

    return (f"{module['name']}!{best[1]}"
            + (f"+{delta:#x}" if delta else ""))


def tool_modules(filter_text: str = "") -> str:
    wanted = filter_text.lower().strip()
    found = [m for m in modules(refresh=True)
             if not wanted or wanted in m["name"].lower()]
    if not found:
        return f"no loaded module matches {filter_text!r}"
    lines = [f"{len(found)} module(s)", ""]
    for module in sorted(found, key=lambda m: m["base"]):
        lines.append(f"{module['base']:#018x}  {module['size']:>9,}  "
                     f"{module['name']}")
    return "\n".join(lines)


def tool_symbol(name: str, pid: int = 0) -> str:
    address = resolve(name, pid)
    return f"{name} = {address:#x}"


def tool_exports(module_name: str, contains: str = "", pid: int = 0) -> str:
    module = process_module_by_name(pid, module_name) if pid \
        else module_by_name(module_name)
    if module is None:
        return (f"no module called {module_name!r} in pid {pid}" if pid
                else f"no loaded module called {module_name!r}")
    wanted = contains.lower()
    found = [(a, n) for a, n in exports(module["base"], pid)
             if not wanted or wanted in n.lower()]
    if not found:
        return f"{module['name']} exports nothing matching {contains!r}"

    lines = [f"{len(found)} export(s) in {module['name']} "
             f"(base {module['base']:#x})"
             + (f" in pid {pid}" if pid else ""), ""]
    for address, name in found[:400]:
        lines.append(f"{address:#018x}  {name}")
    if len(found) > 400:
        lines.append(f"... and {len(found) - 400} more; narrow it with 'contains'")
    return "\n".join(lines)


# ------------------------------------------------------------------- pdb

def pdb_info(base: int) -> dict:
    """Which PDB a module was built with, out of its debug directory.

    This works with no network and no symbol file present, and it is the part
    you need first: the name, GUID and age together are the only thing that
    identifies the right PDB, and the symbol server path is built from them.
    Matching on name alone gets you a file that will confidently give wrong
    answers for a different build.
    """
    header = read_bytes(base, 0x400)
    if header[:2] != b"MZ":
        raise CtlError(f"no MZ header at {base:#x}")
    pe = int.from_bytes(header[0x3C:0x40], "little")
    optional = pe + 0x18
    magic = int.from_bytes(header[optional:optional + 2], "little")
    directory = optional + (0x70 if magic == 0x20B else 0x60)

    # The debug directory is the seventh data directory, so six entries in.
    rva = int.from_bytes(header[directory + 6 * 8:directory + 6 * 8 + 4], "little")
    size = int.from_bytes(header[directory + 6 * 8 + 4:directory + 6 * 8 + 8],
                          "little")
    if rva == 0 or size == 0:
        raise CtlError("the module has no debug directory")

    entries = read_bytes(base + rva, min(size, 0x200))
    for offset in range(0, len(entries) - 27, 28):
        entry = entries[offset:offset + 28]
        kind = int.from_bytes(entry[12:16], "little")
        if kind != 2:                       # IMAGE_DEBUG_TYPE_CODEVIEW
            continue
        data_size = int.from_bytes(entry[16:20], "little")
        data_rva = int.from_bytes(entry[20:24], "little")
        blob = read_bytes(base + data_rva, min(max(data_size, 24), 512))
        if blob[:4] != b"RSDS":
            continue

        # RSDS: signature, 16-byte GUID, 4-byte age, then a NUL-terminated name.
        guid = blob[4:20]
        age = int.from_bytes(blob[20:24], "little")
        name = blob[24:].split(b"\0", 1)[0].decode("ascii", "replace")
        # The server spells the GUID as a struct, not as bytes in order.
        text = ("%08X%04X%04X%s" % (
            int.from_bytes(guid[0:4], "little"),
            int.from_bytes(guid[4:6], "little"),
            int.from_bytes(guid[6:8], "little"),
            guid[8:16].hex().upper())) + f"{age:X}"
        return {"name": name.replace("\\", "/").split("/")[-1],
                "full": name, "guid": text, "age": age}

    raise CtlError("the debug directory has no CodeView entry")


class PdbError(RuntimeError):
    pass


# ?? followed by one of these is a special member rather than a name.
MANGLED_SPECIAL = {
    "0": "{ctor}", "1": "{dtor}", "2": "operator new", "3": "operator delete",
    "4": "operator=", "5": "operator>>", "6": "operator<<", "7": "operator!",
    "8": "operator==", "9": "operator!=",
    "_E": "{vector dtor}", "_G": "{scalar dtor}",
}


def readable_name(mangled: str) -> str:
    """The qualified name out of an MSVC decorated name.

    Deliberately not a demangler: it recovers Class::method and stops, leaving
    the type signature alone. The signature is most of the complexity and the
    least of the value - what a reader needs is to see
    CClfsBaseFilePersisted::~CClfsBaseFilePersisted rather than
    ??1CClfsBaseFilePersisted@@UEAA@XZ, and the argument types are visible in
    the disassembly anyway.

    Anything it does not confidently understand comes back unchanged, because a
    half-decoded name is worse than a decorated one.
    """
    if not mangled.startswith("?"):
        # A plain C symbol, possibly with the stdcall decoration.
        return mangled.lstrip("_").split("@")[0] if "@" in mangled else mangled

    body = mangled[1:]
    special = ""
    if body.startswith("?"):
        body = body[1:]
        for key in ("_E", "_G", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"):
            if body.startswith(key):
                special = MANGLED_SPECIAL[key]
                body = body[len(key):]
                break
        else:
            return mangled                      # an operator we do not know

    # Name components run up to "@@", innermost first.
    end = body.find("@@")
    if end < 0:
        return mangled
    parts = [p for p in body[:end].split("@") if p]
    if not parts:
        return mangled

    scopes = list(reversed(parts))
    if special == "{ctor}":
        return "::".join(scopes + [scopes[-1]])
    if special in ("{dtor}", "{vector dtor}", "{scalar dtor}"):
        suffix = "~" + scopes[-1]
        if special != "{dtor}":
            suffix += "  " + special
        return "::".join(scopes[:-1] + [scopes[-1]] + [suffix]) \
            if False else "::".join(scopes) + "::" + suffix
    if special:
        return "::".join(scopes) + "::" + special
    return "::".join(scopes)


def _read_limited_pdb(path: str) -> bytes:
    """Read one PDB without letting a corrupt cache file exhaust the guest."""
    try:
        size = os.path.getsize(path)
    except OSError as error:
        raise PdbError(f"could not stat PDB: {error}") from error
    if size > MAX_PDB_BYTES:
        raise PdbError(
            f"PDB is {size:,} bytes; the safety limit is {MAX_PDB_BYTES:,}")

    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_PDB_BYTES + 1)
    except OSError as error:
        raise PdbError(f"could not read PDB: {error}") from error
    if len(data) > MAX_PDB_BYTES:
        # Size can change between stat() and read(), especially in a shared
        # symbol cache.  Refuse the new content rather than parsing a prefix.
        raise PdbError(f"PDB grew beyond the {MAX_PDB_BYTES:,}-byte safety limit")
    return data


def _pdb_streams(data: bytes):
    """Return the MSF block reader and stream layout after bounded checks."""
    if not data.startswith(b"Microsoft C/C++ MSF 7.00"):
        raise PdbError("not an MSF 7.00 file (an old-format PDB, or not a PDB)")
    if len(data) < 0x38:
        raise PdbError("the PDB superblock is too short")

    block_size = int.from_bytes(data[0x20:0x24], "little")
    directory_bytes = int.from_bytes(data[0x2C:0x30], "little")
    block_map = int.from_bytes(data[0x34:0x38], "little")
    if (block_size < 512 or block_size > 0x10000
            or block_size & (block_size - 1)):
        raise PdbError(f"implausible block size {block_size}")
    if not directory_bytes or directory_bytes > MAX_PDB_BYTES:
        raise PdbError(f"implausible directory size {directory_bytes}")

    block_count = len(data) // block_size
    if block_count == 0:
        raise PdbError("the PDB does not contain a complete block")

    def block(index):
        if not 0 <= index < block_count:
            raise PdbError(f"PDB refers to block {index}, outside the file")
        start = index * block_size
        return data[start:start + block_size]

    # This narrow reader intentionally understands the single block-map form
    # used by modern public PDBs.  It is bounded before indexing it, so a bogus
    # directory cannot make the parser allocate or seek arbitrarily.
    directory_blocks_needed = (directory_bytes + block_size - 1) // block_size
    if directory_blocks_needed > block_size // 4:
        raise PdbError("the PDB directory block map is too large")
    map_bytes = block(block_map)
    directory_blocks = [
        int.from_bytes(map_bytes[i * 4:i * 4 + 4], "little")
        for i in range(directory_blocks_needed)]
    directory = b"".join(block(index) for index in directory_blocks)
    directory = directory[:directory_bytes]
    if len(directory) < 4:
        raise PdbError("the PDB stream directory is too short")

    count = int.from_bytes(directory[0:4], "little")
    if count == 0 or count > 0x10000:
        raise PdbError(f"implausible stream count {count}")
    sizes_end = 4 + count * 4
    if sizes_end > len(directory):
        raise PdbError("the PDB stream-size table is truncated")

    sizes = [int.from_bytes(directory[4 + i * 4:8 + i * 4], "little")
             for i in range(count)]
    at = sizes_end
    streams = []
    for size in sizes:
        if size != 0xFFFFFFFF and size > MAX_PDB_BYTES:
            raise PdbError(f"implausible stream size {size}")
        needed = 0 if size == 0xFFFFFFFF else \
            (size + block_size - 1) // block_size
        if at + needed * 4 > len(directory):
            raise PdbError("the PDB stream block list is truncated")
        blocks = [int.from_bytes(directory[at + i * 4:at + i * 4 + 4], "little")
                  for i in range(needed)]
        # Validate now, before a consumer starts allocating a stream from it.
        for index in blocks:
            block(index)
        at += needed * 4
        streams.append((blocks, 0 if size == 0xFFFFFFFF else size))
    return block, streams


def _pdb_stream_bytes(block, stream: tuple[list[int], int]) -> bytes:
    blocks, size = stream
    return b"".join(block(index) for index in blocks)[:size]


def pdb_public_symbols(path: str) -> list[tuple[int, str, int]]:
    """Public symbols from a PDB, as (segment, name, offset).

    A deliberately narrow reader. A PDB is an MSF container holding a dozen
    streams in several formats; all that is wanted here is the public symbol
    table, which is the one that names the functions a module does not export.
    So: the superblock, the stream directory, the DBI header to find the symbol
    stream, and the S_PUB32 records in it. Everything else is skipped rather
    than half-parsed.
    """
    block, streams = _pdb_streams(_read_limited_pdb(path))

    if len(streams) <= 3:
        raise PdbError("no DBI stream")

    dbi = _pdb_stream_bytes(block, streams[3])
    if len(dbi) < 24:
        raise PdbError("the DBI stream is too short to hold a header")

    symbol_stream = int.from_bytes(dbi[20:22], "little")
    if symbol_stream == 0xFFFF or symbol_stream >= len(streams):
        raise PdbError("the DBI header names no symbol stream")

    symbols = _pdb_stream_bytes(block, streams[symbol_stream])

    found = []
    offset = 0
    while offset + 4 <= len(symbols):
        length = int.from_bytes(symbols[offset:offset + 2], "little")
        if length < 2:
            break
        kind = int.from_bytes(symbols[offset + 2:offset + 4], "little")
        record = symbols[offset + 4:offset + 2 + length]

        if kind == 0x110E and len(record) >= 10:        # S_PUB32
            symbol_offset = int.from_bytes(record[4:8], "little")
            segment = int.from_bytes(record[8:10], "little")
            name = record[10:].split(b"\0", 1)[0].decode("ascii", "replace")
            if name and segment:
                found.append((segment, name, symbol_offset))

        offset += 2 + length
        offset = (offset + 3) & ~3                      # records are 4-aligned

    if not found:
        raise PdbError("the symbol stream held no public symbols")
    return found


def pdb_identity(path: str) -> tuple[str, int]:
    """The GUID and age recorded inside a PDB, from stream 1.

    This is what makes an automatic download safe.  The server is content
    addressed by GUID, but nothing stops a cache hit on a file that was put
    there for a different build, and a mismatched PDB does not fail - it names
    functions confidently and wrongly, which is worse than having no names.
    """
    block, streams = _pdb_streams(_read_limited_pdb(path))

    if len(streams) < 2:
        raise PdbError("no PDB info stream")

    info = _pdb_stream_bytes(block, streams[1])
    if len(info) < 28:
        raise PdbError("the PDB info stream is too short")

    # version(4) signature(4) age(4) guid(16)
    age = int.from_bytes(info[8:12], "little")
    guid = info[12:28]
    text = "%08X%04X%04X%s" % (
        int.from_bytes(guid[0:4], "little"),
        int.from_bytes(guid[4:6], "little"),
        int.from_bytes(guid[6:8], "little"),
        guid[8:16].hex().upper())
    return text, age


SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"
SYMBOL_CACHE = r"C:\lab\symbols"
SYMBOLS_AUTO = True                     # fetch on demand unless turned off

_symbol_attempts: set[int] = set()      # modules already tried, to not retry
_symbol_lock = threading.Lock()
_symbol_failures: dict[int, str] = {}


def _pdb_cache_paths(info: dict) -> tuple[str, str, str, str]:
    """Return the validated cache location and server URL for one PDB."""
    name = os.path.basename(info["name"])
    guid = str(info["guid"])
    if (not re.fullmatch(r"[A-Za-z0-9_.-]+\.pdb", name, re.IGNORECASE)
            or not re.fullmatch(r"[0-9A-Fa-f]{33,64}", guid)):
        raise CtlError(f"refusing an implausible PDB identity {name!r}/{guid!r}")
    directory = os.path.join(SYMBOL_CACHE, name, guid)
    path = os.path.join(directory, name)
    url = f"{SYMBOL_SERVER}/{name}/{guid}/{name}"
    return name, directory, path, url


def _pdb_sha256(path: str) -> tuple[str, int]:
    """Hash a PDB while enforcing the same limit as the downloader."""
    digest = hashlib.sha256()
    total = 0
    try:
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(1 << 20)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_PDB_BYTES:
                    raise PdbError(
                        f"PDB exceeds the {MAX_PDB_BYTES:,}-byte safety limit")
                digest.update(chunk)
    except OSError as error:
        raise PdbError(f"could not hash PDB: {error}") from error
    return digest.hexdigest(), total


def _pdb_provenance_path(path: str) -> str:
    return path + PDB_PROVENANCE_SUFFIX


def pdb_provenance(path: str) -> dict | None:
    """Return a verified-download record when the cache has one."""
    try:
        with open(_pdb_provenance_path(path), encoding="utf-8") as handle:
            record = json.load(handle)
    except (OSError, ValueError):
        return None
    return record if isinstance(record, dict) else None


def _write_pdb_provenance(path: str, info: dict, url: str, source: str,
                          pdb_guid: str, pdb_age: int,
                          digest: str, size: int) -> None:
    """Atomically record exactly what was checked before symbols are used."""
    record = {
        "schema": 1,
        "source": source,
        "url": url,
        "fetched_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pdb_name": info["name"],
        "image_guid": str(info["guid"])[:32].upper(),
        "image_age": int(info["age"]),
        "pdb_guid": pdb_guid.upper(),
        "pdb_age": int(pdb_age),
        "sha256": digest,
        "bytes": size,
    }
    provenance = _pdb_provenance_path(path)
    partial = provenance + ".part"
    try:
        with open(partial, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(record, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(partial, provenance)
    except OSError as error:
        try:
            os.remove(partial)
        except OSError:
            pass
        raise PdbError(f"could not write PDB provenance: {error}") from error


def _verify_pdb_identity(path: str, info: dict, url: str) -> tuple[str, int]:
    """Ensure a PDB really belongs to the image that asked for it."""
    guid, age = pdb_identity(path)
    wanted = str(info["guid"])[:32]
    if guid.upper() != wanted.upper():
        raise PdbError(
            f"the file at {url} identifies as GUID {guid}, not {wanted} - "
            "it is for a different build and would name things wrongly")
    return guid, age


def _check_cached_pdb(path: str, info: dict, url: str) -> None:
    """Verify a cache hit too; a stale file is as misleading as a bad download."""
    guid, age = _verify_pdb_identity(path, info, url)
    digest, size = _pdb_sha256(path)
    provenance = pdb_provenance(path)
    if provenance and provenance.get("sha256") not in (None, digest):
        raise PdbError(
            "the cached PDB no longer matches its recorded SHA-256; refusing "
            "to attach symbols from an altered file")
    if provenance is None:
        _write_pdb_provenance(path, info, url, "cache-verified", guid, age,
                              digest, size)


def fetch_pdb(base: int) -> str:
    """Download the PDB a module was built with, into the local cache.

    Only from the Microsoft symbol server, only over the path the module's own
    debug directory names, and only kept if the GUID inside the file matches
    the one asked for.  That last check is the point: the identity is the
    whole reason to download rather than guess by name.
    """
    info = pdb_info(base)
    _, directory, path, url = _pdb_cache_paths(info)
    if os.path.exists(path):
        try:
            _check_cached_pdb(path, info, url)
        except PdbError as error:
            raise CtlError(f"refusing cached PDB {path}: {error}") from error
        return path

    os.makedirs(directory, exist_ok=True)
    request = urllib.request.Request(
        url, headers={"User-Agent": "Microsoft-Symbol-Server/10.0"})

    partial = path + ".part"
    try:
        with urllib.request.urlopen(request, timeout=PDB_DOWNLOAD_TIMEOUT_SECONDS) \
                as response, open(partial, "wb") as out:
            declared = response.headers.get("Content-Length")
            if declared:
                try:
                    expected = int(declared)
                except ValueError as error:
                    raise PdbError("symbol server sent an invalid Content-Length") \
                        from error
                if expected < 0 or expected > MAX_PDB_BYTES:
                    raise PdbError(
                        f"symbol server advertised {expected:,} bytes; the "
                        f"safety limit is {MAX_PDB_BYTES:,}")

            total = 0
            while True:
                chunk = response.read(1 << 20)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_PDB_BYTES:
                    raise PdbError(
                        f"symbol server exceeded the {MAX_PDB_BYTES:,}-byte "
                        "safety limit")
                out.write(chunk)

        guid, age = _verify_pdb_identity(partial, info, url)
        digest, size = _pdb_sha256(partial)
        os.replace(partial, path)
        _write_pdb_provenance(path, info, url, "symbol-server", guid, age,
                              digest, size)
    except (OSError, PdbError, urllib.error.URLError) as error:
        raise CtlError(f"could not fetch usable symbols from {url}: {error}") \
            from error
    finally:
        try:
            os.remove(partial)
        except OSError:
            pass
    return path


_pdb_symbols: dict[int, list[tuple[int, str]]] = {}


def _attach_pdb(base: int, path: str) -> int:
    """Parse a PDB and attach its symbols to the module loaded at `base`."""
    sections = pe_sections(base)
    publics = pdb_public_symbols(path)

    attached = []
    for segment, name, offset in publics:
        if 1 <= segment <= len(sections):
            attached.append((base + sections[segment - 1]["rva"] + offset,
                             readable_name(name)))
    if not attached:
        raise PdbError("no symbol landed in a section this module has")

    attached.sort()
    _pdb_symbols[base] = attached
    _exports_cache.pop(base, None)
    return len(attached)


def load_pdb_symbols(module_name: str, path: str) -> int:
    """Parse a PDB and attach its symbols to a loaded module."""
    resolved = module_by_name(module_name)
    if resolved is None:
        raise CtlError(f"no loaded module called {module_name!r}")

    # A supplied path is not trusted merely because it ends in .pdb.  Public
    # symbols from a different build parse perfectly and are worse than no
    # symbols, because every later address is labelled with confidence.
    _verify_pdb_identity(path, pdb_info(resolved["base"]), path)

    sections = pe_sections(resolved["base"])
    publics = pdb_public_symbols(path)

    # Public symbols are segment:offset; the module's own section table turns
    # those into addresses. Segments are 1-based.
    attached = []
    for segment, name, offset in publics:
        if 1 <= segment <= len(sections):
            attached.append((resolved["base"] + sections[segment - 1]["rva"]
                             + offset, readable_name(name)))

    if not attached:
        raise PdbError("no symbol landed in a section this module has")

    attached.sort()
    _pdb_symbols[resolved["base"]] = attached
    _exports_cache.pop(resolved["base"], None)
    return len(attached)


def tool_pdb_info(module: str) -> str:
    resolved = module_by_name(module)
    if resolved is None:
        return f"no loaded module called {module!r}"
    info = pdb_info(resolved["base"])
    base = resolved["base"]

    if base in _pdb_symbols:
        state = f"symbols: {len(_pdb_symbols[base])} loaded"
    elif base in _symbol_failures:
        # Worth saying out loud. A silent failure looks exactly like a module
        # that has no private symbols, and the two call for different responses.
        state = f"symbols: not loaded - {_symbol_failures[base]}"
    else:
        state = "symbols: not loaded yet"

    cache_line = "  cache: not downloaded"
    try:
        _, _, cache_path, _ = _pdb_cache_paths(info)
        if os.path.exists(cache_path):
            provenance = pdb_provenance(cache_path)
            if provenance:
                cache_line = (f"  cache: {cache_path} (SHA-256 "
                              f"{provenance.get('sha256', '?')}, "
                              f"{provenance.get('source', 'unknown')})")
            else:
                cache_line = f"  cache: {cache_path} (unverified metadata)"
    except CtlError:
        cache_line = "  cache: identity is not safe to turn into a path"

    return "\n".join([
        state,
        "",
        f"{resolved['name']} was built with:",
        f"  pdb  : {info['name']}",
        f"  path : {info['full']}",
        f"  guid : {info['guid']}",
        cache_line,
        "",
        "The symbol server path is built from exactly those three:",
        f"  https://msdl.microsoft.com/download/symbols/"
        f"{info['name']}/{info['guid']}/{info['name']}",
        "",
        "Put the file anywhere the guest can read it and load it with "
        "svmhv_symbols_load. Matching on the name alone gets a PDB for a "
        "different build, which answers confidently and wrongly.",
    ])


def tool_symbols_load(module: str, path: str = "") -> str:
    resolved = module_by_name(module)
    if resolved is None:
        return f"no loaded module called {module!r}"

    if not path:
        # No path given: fetch it, the same way the automatic path does.
        try:
            path = fetch_pdb(resolved["base"])
        except Exception as error:
            return (f"could not fetch symbols for {module}: {error}\n"
                    "svmhv_pdb_info reports the identity if you would rather "
                    "fetch it yourself and pass a path.")

    try:
        count = load_pdb_symbols(module, path)
    except (CtlError, PdbError, OSError) as error:
        return f"could not read {path}: {error}"
    return (f"{count} symbol(s) loaded for {module} from {path}.\n"
            "These now take precedence over exported names everywhere an "
            "address is rendered.")


def tool_symbols_auto(enabled: bool = True) -> str:
    """Turn the automatic fetch on or off for this session."""
    global SYMBOLS_AUTO
    SYMBOLS_AUTO = bool(enabled)
    if not SYMBOLS_AUTO:
        return ("automatic symbol download is off; svmhv_symbols_load still "
                "fetches on demand")
    _symbol_attempts.clear()
    return (f"automatic symbol download is on, from {SYMBOL_SERVER}, cached in "
            f"{SYMBOL_CACHE}. Modules already tried will be retried.")


# --------------------------------------------------------------- findings

FINDINGS_PATH = r"C:\lab\findings.json"


def _findings_read() -> dict:
    try:
        with open(FINDINGS_PATH, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def tool_note(address: str = "", text: str = "", contains: str = "",
              pid: int = 0) -> str:
    """Record what was worked out about an address, or read it back.

    Reverse engineering is mostly accumulated conclusions - this offset is the
    lock, this field is the flags, this branch is the licence check - and none
    of it is recoverable from the binary a second time. Without somewhere to
    put them, every session re-derives the same things from scratch.

    Keyed by symbol rather than address where one is known, because addresses
    move with every reboot and a note pinned to one is worthless tomorrow.

    Each note also records which BUILD it was derived from, taken from the
    module's PDB GUID. A symbol name survives a reboot; it does not survive the
    target shipping an update, and "offset 0x40 is the flags" from the previous
    build is worse than no note at all because it reads as though it were
    checked. A note whose build no longer matches is still shown - it is
    usually still true - but it is shown saying so.
    """
    notes = _findings_read()

    if not text:
        wanted = contains.lower()
        chosen = {k: v for k, v in notes.items()
                  if not wanted or wanted in k.lower()
                  or wanted in str(v).lower()}
        if address:
            key = _note_key(address, pid)
            chosen = {k: v for k, v in notes.items() if k == key}
        if not chosen:
            return "nothing recorded yet" if not (contains or address) else \
                   f"nothing recorded matching {contains or address!r}"
        lines = [f"{len(chosen)} note(s)", ""]
        for key, entries in sorted(chosen.items()):
            lines.append(f"{key}")
            for entry in entries:
                lines.append(f"    {_note_text(key, entry, pid)}")
        return "\n".join(lines)

    if not address:
        return "give an address or symbol to attach the note to"

    key = _note_key(address, pid)
    notes.setdefault(key, []).append({"text": text, "build": _note_build(address, pid)}
                                     if _note_build(address, pid) else text)
    try:
        with open(FINDINGS_PATH, "w", encoding="utf-8") as handle:
            json.dump(notes, handle, indent=1, sort_keys=True)
    except OSError as error:
        return f"could not write {FINDINGS_PATH}: {error}"
    return f"noted against {key}: {text}"


# How many bytes of the code itself identify it, when nothing else does.  Enough
# to be distinctive and short enough to survive the relocations and the one
# patched byte that a payload picks up between one mapping and the next.
NOTE_HASH_BYTES = 64


def _note_key(address: str, pid: int = 0) -> str:
    """A name that survives a reboot, if one can be had."""
    try:
        resolved = resolve(address, pid)
    except CtlError:
        return address

    named = symbolize(resolved, pid)
    if "!" in named or "+" in named:
        return named

    # Nothing declares this address, which is the case that matters most: a
    # manually mapped payload has no module and no symbol, and it lands
    # somewhere different every boot - so a note keyed on the address is worth
    # nothing tomorrow, which is exactly the code worth taking notes about.
    # Key it on the bytes instead, and it follows the code wherever it is next
    # mapped.
    anonymous = _note_content_key(resolved, pid)
    return anonymous if anonymous else f"{resolved:#x}"


def _note_content_key(resolved: int, pid: int = 0) -> str:
    """A key made from the code at an address, for code nothing else names."""
    try:
        code = read_bytes(resolved, NOTE_HASH_BYTES, pid)
    except CtlError:
        return ""
    if len(code) < 16 or not any(code):
        return ""                       # all zeroes identifies nothing
    return "anon:" + hashlib.sha256(code).hexdigest()[:16]


def _note_build(address: str, pid: int = 0) -> str:
    """The PDB identity of the module the address is in, or "" if there is none.

    Best effort throughout: a manually mapped payload has no debug directory,
    a user-mode address may not be reachable, and none of that is a reason to
    refuse to record a conclusion about it.
    """
    try:
        resolved = resolve(address, pid)
        module = module_for(resolved, pid)
        if module is None:
            return ""
        return f"{module['name']}/{pdb_info(module['base'])['guid']}"
    except (CtlError, KeyError, IndexError, ValueError):
        return ""


def _note_text(key: str, entry, pid: int = 0) -> str:
    """One stored note, marked when it came from a build that is not loaded now."""
    if not isinstance(entry, dict):
        return str(entry)                   # written before builds were recorded

    text = entry.get("text", "")
    was = entry.get("build", "")
    if not was:
        return text

    now = _note_build(key, pid)
    if now and now != was:
        return f"{text}   [from {was}; loaded now is {now}]"
    return text


# ------------------------------------------------------- tamper detection

def tool_verify(module: str, limit: int = 24) -> str:
    """Compare a module's code in memory against the file it was loaded from.

    What this finds is somebody else's hooks.  An inline detour, a patched
    prologue, a redirected import - all of them are a difference between the
    bytes running and the bytes on disk, and all of them are invisible to
    anything that only reads memory.

    Relocations are the complication and the reason this reports rather than
    judges: a loaded image has had its absolute addresses fixed up, so a naive
    comparison flags every one of them.  Differences inside a relocation are
    filtered out; what is left is either a patch or a section this cannot
    account for, and both are worth a human deciding about.
    """
    resolved = module_by_name(module)
    if resolved is None:
        return f"no loaded module called {module!r}"

    path = resolved["path"]
    for prefix, replacement in ((r"\SystemRoot", r"C:\Windows"),
                                (r"\??\\", ""), (r"\\??\\", "")):
        if path.startswith(prefix):
            path = replacement + path[len(prefix):]
    try:
        with open(path, "rb") as handle:
            disk = handle.read()
    except OSError as error:
        return (f"cannot read {path}: {error}\n"
                "Without the file there is nothing to compare against.")

    sections = pe_sections(resolved["base"])
    code = [s for s in sections if s["characteristics"] & 0x20000000]
    if not code:
        return f"{resolved['name']} has no executable section"

    # File offsets differ from memory offsets; the section table has both.
    header = read_bytes(resolved["base"], 0x400)
    pe = int.from_bytes(header[0x3C:0x40], "little")
    count = int.from_bytes(header[pe + 6:pe + 8], "little")
    optional_size = int.from_bytes(header[pe + 20:pe + 22], "little")
    table = pe + 24 + optional_size
    raw_offsets = {}
    for i in range(min(count, 32)):
        entry = header[table + i * 40:table + i * 40 + 40]
        name = entry[:8].rstrip(b"\0").decode("ascii", "replace")
        raw_offsets[name] = int.from_bytes(entry[20:24], "little")

    relocated = _relocation_targets(resolved["base"], disk, header, pe,
                                    optional_size)

    differences = []
    scanned = 0
    for section in code:
        raw = raw_offsets.get(section["name"])
        if raw is None:
            continue
        size = min(section["size"], 1 << 20)
        scanned += size
        live = dump_range(resolved["base"] + section["rva"], size)
        for page, blob in sorted(live.items()):
            page_rva = page - resolved["base"]
            for offset, byte in enumerate(blob):
                rva = page_rva + offset
                file_at = raw + (rva - section["rva"])
                if file_at >= len(disk) or disk[file_at] == byte:
                    continue
                if any(r <= rva < r + 8 for r in relocated):
                    continue                    # a fixed-up address, not a patch
                differences.append((resolved["base"] + rva, disk[file_at], byte))
                if len(differences) >= limit * 4:
                    break

    if not differences:
        return (f"{resolved['name']}: {scanned:,} bytes of code match the file "
                f"on disk exactly. Nothing has patched it.")

    # Report runs, not bytes: a hook is a stretch of consecutive differences.
    runs = []
    for address, was, now in differences:
        if runs and address == runs[-1][0] + runs[-1][1]:
            runs[-1][1] += 1
            runs[-1][2].append(now)
            runs[-1][3].append(was)
        else:
            runs.append([address, 1, [now], [was]])

    expected = [r for r in runs if _loader_patch(r[3], r[2])]
    suspect = [r for r in runs if not _loader_patch(r[3], r[2])]

    lines = [f"{resolved['name']}: {scanned:,} bytes of code compared",
             f"  {len(expected)} difference(s) Windows makes itself",
             f"  {len(suspect)} difference(s) it does not", ""]

    if suspect:
        lines.append("unexplained - these are what a hook looks like:")
        for address, length, now, was in suspect[:limit]:
            lines.append(f"  {address:#018x}  {symbolize(address)}")
            lines.append(f"      on disk: {bytes(was).hex()}")
            lines.append(f"      running: {bytes(now).hex()}")
        if len(suspect) > limit:
            lines.append(f"  ... and {len(suspect) - limit} more")
        lines.append("")
    else:
        lines.append("Nothing unexplained: every difference is one the loader "
                     "is known to make.")
        lines.append("")

    if expected:
        lines.append(f"accounted for ({len(expected)}): retpoline and import "
                     "optimisation. Windows rewrites indirect calls through "
                     "the import table into direct ones at load, and patches "
                     "the CFG dispatch stubs, so those bytes never match the "
                     "file and never did.")
    return "\n".join(lines)


def _loader_patch(was: list, now: list) -> bool:
    """Is this difference one Windows makes to every module at load time?

    Two of them account for almost all of it.  Import optimisation rewrites
    "call [__imp_Foo]" - an ff 15 indirect through the import table - into a
    direct e8 call, and pads what is left with nops.  Retpoline and CFG do the
    same to the dispatch stubs, turning an ff e0 or ff 25 into a jmp.

    Both leave the running bytes starting with a direct call or jump where the
    file had an indirect one or padding.  That is a narrow enough shape to
    recognise, and getting it wrong only moves an entry between two lists that
    are both printed.
    """
    was_bytes, now_bytes = bytes(was), bytes(now)

    # Padding either way.  Rewriting an indirect call as a shorter direct one
    # leaves slack, and the loader fills it - zeroes become int3, or the other
    # way about. Nothing hides in a gap between functions.
    padding = set(b"\x00\xcc\x90")
    if set(was_bytes) <= padding and set(now_bytes) <= padding:
        return True

    indirect = (was_bytes[:2] in (b"\xff\x15", b"\xff\x25", b"\xff\xe0",
                                  b"\xff\xd0")
                or was_bytes[:1] in (b"\x48", b"\x4c")      # rex + indirect
                or was_bytes.startswith(b"\x0f\x1f")        # nop padding
                or was_bytes.startswith(b"\xcc"))
    direct = now_bytes[:1] in (b"\xe8", b"\xe9") or \
        now_bytes[:1] in (b"\x48", b"\x4c") or now_bytes.startswith(b"\xcc")
    return indirect and direct


def _relocation_targets(base: int, disk: bytes, header: bytes, pe: int,
                        optional_size: int) -> set[int]:
    """RVAs the loader rewrote, so a diff does not report them as patches."""
    directory = pe + 0x18 + (0x70 if int.from_bytes(
        header[pe + 0x18:pe + 0x1A], "little") == 0x20B else 0x60)
    rva = int.from_bytes(header[directory + 5 * 8:directory + 5 * 8 + 4], "little")
    size = int.from_bytes(header[directory + 5 * 8 + 4:directory + 5 * 8 + 8],
                          "little")
    if rva == 0 or size == 0:
        return set()

    # Find the relocation directory in the file, via the section it lives in.
    count = int.from_bytes(header[pe + 6:pe + 8], "little")
    table = pe + 24 + optional_size
    file_at = None
    for i in range(min(count, 32)):
        entry = header[table + i * 40:table + i * 40 + 40]
        section_rva = int.from_bytes(entry[12:16], "little")
        section_size = int.from_bytes(entry[8:12], "little")
        if section_rva <= rva < section_rva + max(section_size, 1):
            file_at = int.from_bytes(entry[20:24], "little") + (rva - section_rva)
            break
    if file_at is None or file_at + size > len(disk):
        return set()

    targets = set()
    at = file_at
    end = file_at + size
    while at + 8 <= end:
        page_rva = int.from_bytes(disk[at:at + 4], "little")
        block_size = int.from_bytes(disk[at + 4:at + 8], "little")
        if block_size < 8 or at + block_size > end:
            break
        for i in range(8, block_size, 2):
            entry = int.from_bytes(disk[at + i:at + i + 2], "little")
            if (entry >> 12) != 0:              # 0 is padding
                targets.add(page_rva + (entry & 0xFFF))
        at += block_size
    return targets


# ------------------------------------------------------------ system calls

def tool_syscalls(contains: str = "", limit: int = 60) -> str:
    """The system service table, as index -> function.

    A syscall number is how a great deal of code reaches the kernel without
    going near a named import, so being able to say what index 0x55 is on this
    build is often the whole question. The table is an array of 32-bit values;
    each is the offset from the table base, shifted right by four.
    """
    kernel = module_by_name("nt")
    if kernel is None:
        return "the kernel is not in the module list"

    # KiServiceTable is the table itself and KiServiceLimit its length.  The
    # descriptor that points at them - KeServiceDescriptorTable - is exported
    # on x86 and neither exported nor public on x64, so going through it works
    # on the wrong architecture. Both of these are private symbols, which is
    # why this needs a PDB and says so if it cannot get one.
    try:
        base = resolve("nt!KiServiceTable")
    except CtlError:
        return ("nt!KiServiceTable is not available. It is a private symbol, "
                "so this needs the kernel's PDB - svmhv_pdb_info on nt will "
                "say whether one has been loaded.")

    count = 0
    try:
        count = int.from_bytes(read_bytes(resolve("nt!KiServiceLimit"), 4),
                               "little")
    except CtlError:
        pass
    if not (0 < count < 4096):
        return (f"nt!KiServiceLimit reports {count} services, which is not "
                "plausible - refusing to walk a table of unknown length")

    entries = bytearray()
    for offset in range(0, count * 4, 0x1000):
        entries += read_bytes(base + offset, min(0x1000, count * 4 - offset))

    wanted = contains.lower()
    found = []
    for index in range(count):
        value = int.from_bytes(entries[index * 4:index * 4 + 4], "little",
                               signed=True)
        address = base + (value >> 4)
        name = symbolize(address)
        if wanted and wanted not in name.lower():
            continue
        found.append((index, address, name))

    lines = [f"{count} services; showing {min(len(found), limit)}"
             + (f" matching {contains!r}" if contains else ""), ""]
    for index, address, name in found[:limit]:
        lines.append(f"  {index:>4}  0x{index:03x}  {address:#018x}  {name}")
    if len(found) > limit:
        lines.append(f"  ... and {len(found) - limit} more")
    return "\n".join(lines)


# ------------------------------------------------------------- processes

def processes(name_filter: str = "") -> list[dict]:
    arguments = ["processes"] + ([name_filter] if name_filter else [])
    found = []
    for record in records(ctl(*arguments), "process"):
        try:
            found.append({"pid": int(record["pid"], 0),
                          "threads": int(record.get("threads", "0"), 0),
                          "name": record.get("name", "?"),
                          "peb": int(record.get("peb", "0"), 0)})
        except (KeyError, ValueError):
            continue
    return found


def tool_processes(name: str = "") -> str:
    found = processes(name)
    if not found:
        return f"no process matches {name!r}" if name else "no processes listed"
    lines = [f"{len(found)} process(es)", ""]
    for process in sorted(found, key=lambda p: p["pid"]):
        peb = f"{process['peb']:#x}" if process["peb"] else "(not readable)"
        lines.append(f"  {process['pid']:>6}  {process['name']:<32} "
                     f"threads {process['threads']:<4} peb {peb}")
    return "\n".join(lines)


def process_modules(pid: int) -> list[dict]:
    """Walk PEB -> Ldr -> InLoadOrderModuleList with cross-process reads.

    Every step is an ordinary read in the target's address space, which is why
    this needed no kernel code: the hypervisor already reaches into a process
    without opening a handle to it, so the loader's own bookkeeping is just
    more memory.
    """
    matching = [p for p in processes() if p["pid"] == int(pid)]
    if not matching:
        raise CtlError(f"no process with pid {pid}")
    peb = matching[0]["peb"]
    if peb == 0:
        raise CtlError(f"pid {pid} did not give up its PEB (protected?)")

    def qword(address):
        return int.from_bytes(read_bytes(address, 8, pid), "little")

    # PEB.Ldr is at +0x18 on x64; PEB_LDR_DATA.InLoadOrderModuleList at +0x10.
    ldr = qword(peb + 0x18)
    if ldr == 0:
        raise CtlError("the loader data is not mapped yet")
    head = ldr + 0x10
    entry = qword(head)

    found = []
    seen_entries = set()
    for _ in range(256):
        if entry == 0 or entry == head or entry in seen_entries:
            break
        seen_entries.add(entry)
        # LDR_DATA_TABLE_ENTRY: DllBase +0x30, SizeOfImage +0x40,
        # FullDllName +0x48, BaseDllName +0x58 (UNICODE_STRING: len, max, ptr)
        blob = read_bytes(entry, 0x70, pid)
        if len(blob) < 0x68:
            break

        def field(at, width=8):
            return int.from_bytes(blob[at:at + width], "little")

        base = field(0x30)
        size = field(0x40, 4)
        name_length = field(0x58, 2)
        name_buffer = field(0x60)
        name = ""
        path_length = field(0x48, 2)
        path_buffer = field(0x50)
        if name_buffer and 0 < name_length <= 512:
            try:
                name = read_bytes(name_buffer, name_length, pid).decode(
                    "utf-16-le", "replace")
            except CtlError:
                name = ""
        path = ""
        if path_buffer and 0 < path_length <= 4096:
            try:
                path = read_bytes(path_buffer, path_length, pid).decode(
                    "utf-16-le", "replace")
            except CtlError:
                path = ""
        if base:
            found.append({"base": base, "size": size, "name": name or "?",
                          "path": path})
        entry = field(0)                       # InLoadOrderLinks.Flink
    return found


def process_module_by_name(pid: int, name: str) -> dict | None:
    """Find a process image or DLL by its loader name, not kernel modules."""
    wanted = name.replace("\\", "/").rsplit("/", 1)[-1].lower()
    for module in process_modules(int(pid)):
        candidate = module["name"].replace("\\", "/").rsplit("/", 1)[-1]
        if candidate.lower() == wanted:
            return module
    return None


def tool_process_modules(pid: int) -> str:
    found = process_modules(int(pid))
    if not found:
        return f"pid {pid} has no readable module list"
    lines = [f"{len(found)} module(s) in pid {pid}", ""]
    for module in found:
        lines.append(f"  {module['base']:#018x}  {module['size']:>9,}  "
                     f"{module['name']}"
                     + (f"  {module['path']}" if module.get("path") else ""))
    lines += ["", "The first entry is the executable itself. Its base is what "
              "svmhv_read, svmhv_disassemble and svmhv_watch want as 'pid'."]
    return "\n".join(lines)


# --------------------------------------------------------- bulk scanning

def dump_range(address: int, length: int, pid: int = 0) -> dict[int, bytes]:
    """Read a span in one svmhvctl run, as {page address: bytes}.

    Returned as a map rather than one buffer because a sweep runs into holes -
    a module has unmapped or discarded sections - and pretending those are
    zeroes would invent content that a search then reports finding.
    """
    arguments = ["dump", f"{address:x}", str(int(length))]
    if pid:
        arguments.append(str(int(pid)))

    out: dict[int, bytes] = {}
    for record in records(ctl(*arguments), "page"):
        try:
            out[int(record["at"], 0)] = bytes.fromhex(record["data"])
        except (KeyError, ValueError):
            continue
    return out


def pe_sections(base: int, pid: int = 0) -> list[dict]:
    header = read_bytes(base, 0x400, pid)
    if header[:2] != b"MZ":
        raise CtlError(f"no MZ header at {base:#x}")
    pe = int.from_bytes(header[0x3C:0x40], "little")
    count = int.from_bytes(header[pe + 6:pe + 8], "little")
    optional_size = int.from_bytes(header[pe + 20:pe + 22], "little")
    table = pe + 24 + optional_size

    found = []
    for i in range(min(count, 32)):
        entry = header[table + i * 40:table + i * 40 + 40]
        if len(entry) < 40:
            break
        found.append({
            "name": entry[:8].rstrip(b"\0").decode("ascii", "replace"),
            "rva": int.from_bytes(entry[12:16], "little"),
            "size": int.from_bytes(entry[8:12], "little"),
            "characteristics": int.from_bytes(entry[36:40], "little"),
        })
    return found


def tool_sections(module: str, pid: int = 0) -> str:
    resolved = process_module_by_name(pid, module) if pid else module_by_name(module)
    if resolved is None:
        return (f"no module called {module!r} in pid {pid}" if pid
                else f"no loaded module called {module!r}")
    found = pe_sections(resolved["base"], pid)
    lines = [f"{resolved['name']} at {resolved['base']:#x}"
             + (f" in pid {pid}" if pid else ""), ""]
    for section in found:
        flags = section["characteristics"]
        marks = ("r" if flags & 0x40000000 else "-") + \
                ("w" if flags & 0x80000000 else "-") + \
                ("x" if flags & 0x20000000 else "-")
        lines.append(f"  {section['name']:<10} {resolved['base'] + section['rva']:#018x}  "
                     f"{section['size']:>9,}  {marks}")
    return "\n".join(lines)


def extract_strings(blob: bytes, base: int, minimum: int) -> list[tuple[int, str]]:
    found = []
    # ASCII
    run_start, run = None, bytearray()
    for index, byte in enumerate(blob + b"\0"):
        if 0x20 <= byte < 0x7F:
            if run_start is None:
                run_start = index
            run.append(byte)
        else:
            if len(run) >= minimum:
                found.append((base + run_start, run.decode("ascii")))
            run_start, run = None, bytearray()

    # UTF-16LE: the same run with a zero after every character
    index = 0
    while index + 1 < len(blob):
        if 0x20 <= blob[index] < 0x7F and blob[index + 1] == 0:
            start = index
            text = []
            while (index + 1 < len(blob) and 0x20 <= blob[index] < 0x7F
                   and blob[index + 1] == 0):
                text.append(chr(blob[index]))
                index += 2
            if len(text) >= minimum:
                found.append((base + start, "".join(text)))
        else:
            index += 1
    return found


def tool_strings(module: str, minimum: int = 6, limit: int = 200,
                 contains: str = "", pid: int = 0) -> str:
    """The classic first look at a binary.

    For a driver that exports nothing and whose functions have no names, the
    strings are frequently the only thing that says what it is for - registry
    paths, device names, the text of its own error messages.
    """
    resolved = process_module_by_name(pid, module) if pid else module_by_name(module)
    if resolved is None:
        return (f"no module called {module!r} in pid {pid}" if pid
                else f"no loaded module called {module!r}")
    minimum = max(4, min(int(minimum), 64))
    limit = max(1, min(int(limit), 1000))

    sections = [s for s in pe_sections(resolved["base"], pid)
                if not (s["characteristics"] & 0x20000000)]   # skip code
    if not sections:
        sections = pe_sections(resolved["base"], pid)

    found: list[tuple[int, str]] = []
    scanned = 0
    for section in sections:
        if len(found) >= limit * 4 or scanned > (4 << 20):
            break
        start = resolved["base"] + section["rva"]
        size = min(section["size"], 2 << 20)
        scanned += size
        for page, blob in sorted(dump_range(start, size, pid).items()):
            found += extract_strings(blob, page, minimum)

    wanted = contains.lower()
    if wanted:
        found = [(a, t) for a, t in found if wanted in t.lower()]

    lines = [f"{len(found)} string(s) in {resolved['name']}"
             + (f" in pid {pid}" if pid else "")
             + (f" matching {contains!r}" if contains else "")
             + (f"; showing {limit}" if len(found) > limit else ""), ""]
    for address, text in found[:limit]:
        lines.append(f"  {address:#018x}  {text}")
    return "\n".join(lines)


def tool_search(pattern: str, module: str = "", start: str = "",
                size: int = 0, pid: int = 0, limit: int = 40) -> str:
    """Find a byte pattern. '??' matches any byte.

    Either give a module to sweep, or a start and a size. Wildcards are what
    make this useful on code, where immediates and relative offsets differ
    between builds but the surrounding instructions do not.
    """
    cleaned = "".join(pattern.split()).lower()
    if len(cleaned) % 2 or not cleaned:
        return "pattern must be an even number of hex digits, '??' for any byte"

    needle: list[int | None] = []
    for i in range(0, len(cleaned), 2):
        pair = cleaned[i:i + 2]
        if pair == "??":
            needle.append(None)
        elif all(c in "0123456789abcdef" for c in pair):
            needle.append(int(pair, 16))
        else:
            return f"{pair!r} is neither a hex byte nor '??'"

    if module:
        resolved = process_module_by_name(pid, module) if pid else \
            module_by_name(module)
        if resolved is None:
            return (f"no module called {module!r} in pid {pid}" if pid
                    else f"no loaded module called {module!r}")
        begin, span = resolved["base"], min(resolved["size"], 4 << 20)
        where = resolved["name"]
    elif start and size:
        begin, span = resolve(start, pid), min(int(size), 4 << 20)
        where = start
    else:
        return "give either a module, or a start and a size"

    hits = []
    for page, blob in sorted(dump_range(begin, span, pid).items()):
        for offset in range(0, len(blob) - len(needle) + 1):
            if all(want is None or blob[offset + i] == want
                   for i, want in enumerate(needle)):
                hits.append(page + offset)
                if len(hits) >= limit:
                    break
        if len(hits) >= limit:
            break

    if not hits:
        return f"no match for {pattern!r} in {where}"
    lines = [f"{len(hits)} match(es) for {pattern!r} in {where}"
             + (f" in pid {pid}" if pid else ""), ""]
    for address in hits:
        lines.append(f"  {address:#018x}  {symbolize(address, pid)}")
    return "\n".join(lines)


def tool_xrefs(target: str, module: str = "", limit: int = 40,
               pid: int = 0) -> str:
    """Who reaches this address.

    svmhv_disassemble follows calls outwards; this follows them inwards, and
    between them a function stops being an isolated blob. Three kinds are worth
    finding and they mean different things: a direct call is a caller, a jump
    is usually a tail call or a thunk, and an eight-byte pointer sitting in
    data is a table - a dispatch table, a callback registration, an import.
    """
    limit = max(1, min(int(limit), 200))
    address = resolve(target, pid)

    resolved = (process_module_by_name(pid, module) if pid else module_by_name(module)) \
        if module else module_for(address, pid)
    if resolved is None and pid and not module:
        resolved = module_for(address)
    if resolved is None:
        return ("give a module to search: the target is not inside a loaded "
                "one, so there is nothing to sweep")

    begin, span = resolved["base"], min(resolved["size"], 8 << 20)
    absolute = address.to_bytes(8, "little")

    calls, jumps, pointers = [], [], []
    for page, blob in sorted(dump_range(begin, span, pid).items()):
        for offset in range(len(blob)):
            byte = blob[offset]

            # E8/E9 rel32: the displacement is from the end of the instruction.
            if byte in (0xE8, 0xE9) and offset + 5 <= len(blob):
                delta = int.from_bytes(blob[offset + 1:offset + 5], "little",
                                       signed=True)
                if page + offset + 5 + delta == address:
                    (calls if byte == 0xE8 else jumps).append(page + offset)

            if (offset + 8 <= len(blob)
                    and blob[offset:offset + 8] == absolute):
                pointers.append(page + offset)

        if len(calls) + len(jumps) + len(pointers) >= limit * 3:
            break

    lines = [f"references to {symbolize(address, pid)} ({address:#x}) in "
             f"{resolved['name']}" + (f" in pid {pid}" if pid else ""), ""]

    def render(title, found, note):
        if not found:
            return
        lines.append(f"{title} ({len(found)}) - {note}")
        for where in found[:limit]:
            lines.append(f"  {where:#018x}  {symbolize(where, pid)}")
        if len(found) > limit:
            lines.append(f"  ... and {len(found) - limit} more")
        lines.append("")

    render("direct calls", calls, "these are its callers")
    render("jumps", jumps, "usually a tail call or a thunk")
    render("pointers in data", pointers,
           "a table: dispatch, callback registration or import")

    if not (calls or jumps or pointers):
        lines.append("none found. A function reached only through a computed "
                     "call - a vtable or a table indexed at runtime - leaves "
                     "no reference a scan can see.")
    return "\n".join(lines)


def tool_disassemble(target: str, count: int = 24, pid: int = 0) -> str:
    """A listing with branch targets named.

    The naming is the point. A call to 0xfffff80023f1a2b0 tells a reader
    nothing; a call to nt!ExAllocatePool2 tells them what the function does.
    Following the calls out of a function is most of how anybody works out what
    it is for, and it is the one thing a raw byte dump cannot support.
    """
    count = max(1, min(int(count), 200))
    address = resolve(target, pid)
    # Roughly 15 bytes per instruction, bounded by what one transfer carries.
    wanted = min(4096, max(64, count * 15))
    code = read_bytes(address, wanted, pid)
    if not code:
        return f"nothing readable at {target}"

    lines = [f"{symbolize(address, pid)}  ({address:#x})", ""]
    offset = 0
    shown = 0
    calls: list[str] = []

    while offset < len(code) and shown < count:
        try:
            length, text, branch = disassemble_one(code, offset, address + offset)
        except DecodeError:
            lines.append(f"  {address + offset:#018x}  "
                         f"{code[offset]:02x}"
                         f"{'':<28}db {code[offset]:#04x}   <- not decoded")
            offset += 1
            shown += 1
            continue

        raw = code[offset:offset + length].hex()
        note = ""
        if branch is not None:
            named = symbolize(branch, pid)
            if named != f"{branch:#x}":
                note = f"   ; {named}"
                if text.startswith("call") and named not in calls:
                    calls.append(named)

        lines.append(f"  {address + offset:#018x}  {raw:<30} {text}{note}")
        offset += length
        shown += 1

    if calls:
        lines += ["", "calls out of this range:"]
        lines += [f"  {name}" for name in calls]
    return "\n".join(lines)


# ------------------------------------------------------------------- ioctls

# The device types that appear in a control code. Only the named ones matter:
# a code whose type is not in here and is below 0x8000 is almost certainly not
# a control code at all, which is what makes the scan below usable.
DEVICE_TYPES = {
    0x01: "BEEP", 0x02: "CD_ROM", 0x03: "CD_ROM_FILE_SYSTEM", 0x04: "CONTROLLER",
    0x05: "DATALINK", 0x06: "DFS", 0x07: "DISK", 0x08: "DISK_FILE_SYSTEM",
    0x09: "FILE_SYSTEM", 0x0A: "INPORT_PORT", 0x0B: "KEYBOARD", 0x0C: "MAILSLOT",
    0x0D: "MIDI_IN", 0x0E: "MIDI_OUT", 0x0F: "MOUSE",
    0x10: "MULTI_UNC_PROVIDER", 0x11: "NAMED_PIPE", 0x12: "NETWORK",
    0x13: "NETWORK_BROWSER", 0x14: "NETWORK_FILE_SYSTEM", 0x15: "NULL",
    0x16: "PARALLEL_PORT", 0x17: "PHYSICAL_NETCARD", 0x18: "PRINTER",
    0x19: "SCANNER", 0x1A: "SERIAL_MOUSE_PORT", 0x1B: "SERIAL_PORT",
    0x1C: "SCREEN", 0x1D: "SOUND", 0x1E: "STREAMS", 0x1F: "TAPE",
    0x20: "TAPE_FILE_SYSTEM", 0x21: "TRANSPORT", 0x22: "UNKNOWN",
    0x23: "VIDEO", 0x24: "VIRTUAL_DISK", 0x25: "WAVE_IN", 0x26: "WAVE_OUT",
    0x27: "8042_PORT", 0x28: "NETWORK_REDIRECTOR", 0x29: "BATTERY",
    0x2A: "BUS_EXTENDER", 0x2B: "MODEM", 0x2C: "VDM", 0x2D: "MASS_STORAGE",
    0x2E: "SMB", 0x2F: "KS", 0x30: "CHANGER", 0x31: "SMARTCARD",
    0x32: "ACPI", 0x33: "DVD", 0x34: "FULLSCREEN_VIDEO", 0x35: "DFS_FILE_SYSTEM",
    0x36: "DFS_VOLUME", 0x37: "SERENUM", 0x38: "TERMSRV", 0x39: "KSEC",
    0x3A: "FIPS", 0x3B: "INFINIBAND", 0x3E: "VMBUS", 0x3F: "CRYPT_PROVIDER",
    0x40: "WPD", 0x41: "BLUETOOTH", 0x42: "MT_COMPOSITE", 0x43: "MT_TRANSPORT",
    0x44: "BIOMETRIC", 0x45: "PMI", 0x46: "EHSTOR", 0x47: "DEVAPI",
    0x48: "GPIO", 0x49: "USBEX", 0x50: "CONSOLE", 0x51: "NFP", 0x52: "SYSENV",
    0x53: "VIRTUAL_BLOCK", 0x54: "POINT_OF_SERVICE", 0x55: "STORAGE_REPLICATION",
    0x56: "TRUST_ENV", 0x57: "UCM", 0x58: "UCMTCPCI", 0x59: "PERSISTENT_MEMORY",
    0x5A: "NVDIMM", 0x5B: "HOLOGRAPHIC", 0x5C: "SDFXHCI", 0x5D: "UCMUCSI",
}

METHODS = ["BUFFERED", "IN_DIRECT", "OUT_DIRECT", "NEITHER"]
ACCESSES = ["FILE_ANY_ACCESS", "FILE_READ_ACCESS", "FILE_WRITE_ACCESS",
            "FILE_READ_ACCESS | FILE_WRITE_ACCESS"]


def decode_ioctl(code: int) -> dict:
    """CTL_CODE, taken apart. Every field is fixed by the macro, not by taste."""
    device = (code >> 16) & 0xFFFF
    access = (code >> 14) & 0x3
    function = (code >> 2) & 0xFFF
    method = code & 0x3
    return {
        "code": code,
        "device": device,
        "device_name": DEVICE_TYPES.get(device,
                                        "vendor-defined" if device >= 0x8000
                                        else "unrecognised"),
        "access": access,
        "function": function,
        "method": method,
        # 0x800 and up is the range Microsoft reserves for third parties, so a
        # function number in it is a strong sign this driver defined the code
        # itself rather than implementing somebody else's interface.
        "custom": function >= 0x800 or device >= 0x8000,
    }


def plausible_ioctl(code: int) -> bool:
    """Is this 32-bit constant shaped like a control code?

    The scan below sees every immediate in a dispatcher, most of which are
    lengths, structure offsets and status values. The device type is what
    carries the discrimination, and it has to be a type that exists.

    Device types of 0x8000 and up are reserved for vendors and would be worth
    accepting on the documentation - except that accepting them also accepts
    every NTSTATUS in the function, and a dispatcher is full of them.
    0xc0000005 decoded as a control code looked entirely convincing in the
    first version of this and is STATUS_ACCESS_VIOLATION. Drivers defining
    their own codes overwhelmingly use FILE_DEVICE_UNKNOWN with a function in
    the vendor range, which this still finds.
    """
    if not 0 < code <= 0xFFFFFFFF:
        return False
    device = (code >> 16) & 0xFFFF
    function = (code >> 2) & 0xFFF
    if function == 0:
        return False
    return device in DEVICE_TYPES


# cmp/sub against a 32-bit register: eax, r10d, and the memory forms a
# dispatcher uses when it has spilled the code. "dword ptr [...]" counts, since
# comparing a dword in memory against a constant is the same statement.
IOCTL_COMPARE = re.compile(
    r"\A(?:cmp|sub) (?:e[a-z]{2}|r\d+d|dword ptr \[[^]]*\]), (0x[0-9a-f]+)\Z")


def format_ioctl(code: int) -> str:
    parts = decode_ioctl(code)
    return (f"{code:#010x}  device {parts['device']:#06x} "
            f"({parts['device_name']})  function {parts['function']:#05x}"
            f"{' [vendor range]' if parts['custom'] else ''}  "
            f"{METHODS[parts['method']]}  {ACCESSES[parts['access']]}")


def tool_ioctl(code: str) -> str:
    """One control code, taken apart.

    Worth its own call because the four fields decide how the driver is talked
    to, not just what it is asked. METHOD_NEITHER in particular means the driver
    receives the caller's own user-mode pointers and has to probe them itself,
    which is where a large share of driver vulnerabilities live.
    """
    try:
        value = int(code, 0) if isinstance(code, str) else int(code)
    except ValueError:
        return f"{code!r} is not a number"
    if not 0 <= value <= 0xFFFFFFFF:
        return "a control code is 32 bits"

    parts = decode_ioctl(value)
    lines = [
        f"{value:#010x}",
        f"  device type   : {parts['device']:#06x}  {parts['device_name']}",
        f"  function      : {parts['function']:#05x}"
        + ("   (0x800 and up is the vendor range, so this driver very likely "
           "defined it)" if parts['function'] >= 0x800 else ""),
        f"  method        : {METHODS[parts['method']]}",
        f"  access        : {ACCESSES[parts['access']]}",
        "",
        f"  CTL_CODE({parts['device']:#06x}, {parts['function']:#05x}, "
        f"METHOD_{METHODS[parts['method']]}, {ACCESSES[parts['access']]})",
    ]
    if parts["method"] == 3:
        lines += ["",
                  "  METHOD_NEITHER: the driver is handed the caller's own "
                  "user-mode pointers", "  and has to probe them itself. Check "
                  "that it does."]
    elif parts["method"] in (1, 2):
        lines += ["",
                  "  A direct method: the output buffer arrives as an MDL, so "
                  "the driver sees", "  a kernel mapping of pages the caller "
                  "still owns and can change underneath it."]
    return "\n".join(lines)


def scan_for_ioctls(address: int, budget: int = 3000,
                    seen: set[int] | None = None,
                    depth: int = 0) -> tuple[set[int], list[str]]:
    """Immediates that look like control codes, from one function outwards.

    A dispatcher compares the code against each one it handles, so the constants
    are in the instruction stream whether or not the driver has symbols - which
    for a .sys is the usual case. Following direct calls one level matters:
    plenty of dispatchers do nothing but validate and tail-call a worker, and
    stopping at the first function then finds nothing at all.
    """
    seen = set() if seen is None else seen
    found: set[int] = set()
    followed: list[str] = []

    if address in seen or depth > 1:
        return found, followed
    seen.add(address)

    try:
        code = read_bytes(address, min(budget, 4096))
    except CtlError:
        return found, followed

    offset = 0
    while offset < len(code):
        try:
            length, text, branch = disassemble_one(code, offset,
                                                   address + offset)
        except DecodeError:
            offset += 1
            continue

        # A dispatcher compares the code against each one it handles, or
        # subtracts the lowest before indexing a table. Both leave the constant
        # against a 32-bit register, because a control code is a ULONG - and
        # insisting on that is most of what keeps lengths and pool tags out,
        # since those are moved rather than compared.
        match = IOCTL_COMPARE.match(text)
        if match:
            value = int(match.group(1), 16)
            if plausible_ioctl(value):
                found.add(value)

        # ret ends the linear sweep only if nothing has branched past it, which
        # is not knowable here - so the budget is what stops it, and following
        # calls is what makes up for stopping early.
        if branch is not None and text.startswith(("call", "jmp")) and depth < 1:
            inner, _ = scan_for_ioctls(branch, budget, seen, depth + 1)
            if inner:
                found |= inner
                followed.append(symbolize(branch))

        offset += length

    return found, followed


def tool_ioctls(name: str) -> str:
    """The control codes a driver handles, recovered from its dispatcher.

    This is the interface a .sys exposes to user mode, and nothing publishes it:
    there is no table to read, no export to enumerate, and the header that
    defined the codes is not on the machine. What there is, is the dispatcher
    comparing against every one of them - so they are recovered by reading it.

    Constants, not proof. Anything shaped like a control code is reported;
    confirm one by opening the device and sending it, or by hooking the handler
    and watching what actually arrives.
    """
    address = driver_object(name)
    raw = read_bytes(address, DRIVER_OBJECT_SIZE)

    def pointer(at):
        return int.from_bytes(raw[at:at + 8], "little")

    base = pointer(DRIVER_START)
    size = int.from_bytes(raw[DRIVER_SIZE:DRIVER_SIZE + 4], "little")
    handlers = [pointer(DRIVER_MAJOR + i * 8) for i in range(len(IRP_NAMES))]
    default = unset_handler(handlers, base, size)

    lines = [f"{name}: control codes recovered by reading the dispatcher", ""]
    total: set[int] = set()

    scanned: dict[int, str] = {}

    for index, label in ((14, "IRP_MJ_DEVICE_CONTROL"),
                         (15, "IRP_MJ_INTERNAL_DEVICE_CONTROL")):
        handler = handlers[index]
        if handler == 0 or handler == default:
            lines.append(f"  {label}: not handled")
            continue

        # One function often serves both slots - and every other slot too. It
        # is the same scan and the same answer; saying so is more useful than
        # printing seventy identical lines a second time.
        if handler in scanned:
            lines += [f"  {label}: the same function as {scanned[handler]}", ""]
            continue
        scanned[handler] = label

        found, followed = scan_for_ioctls(handler)
        lines.append(f"  {label} at {symbolize(handler)}")
        if followed:
            lines.append(f"    (also read {', '.join(followed[:4])})")
        if not found:
            lines.append("    no constant in it is shaped like a control code")
            lines.append("    - the codes may be reached through a table, or "
                         "the dispatcher may be longer than one read")
        for code in sorted(found):
            lines.append(f"    {format_ioctl(code)}")
        total |= found
        lines.append("")

    if total:
        lines += [f"{len(total)} candidate(s). Send one and see, or hook the "
                  f"handler with svmhv_hook_trace to watch the real traffic.",
                  "Codes using METHOD_NEITHER are worth looking at first: the "
                  "driver gets raw user pointers."]
    return "\n".join(lines)


# --------------------------------------------------------------- callbacks

# The registration function that is exported, and what it registers. The arrays
# themselves - PspCreateProcessNotifyRoutine and the rest - are static data and
# are not in the public symbols even when private symbols are loaded, so there
# is nothing to look up. They are found by reading the function that writes to
# them, which is exported precisely because drivers have to call it.
CALLBACK_TABLES = [
    ("process creation", "PsSetCreateProcessNotifyRoutineEx",
     "runs on every process create and exit"),
    ("thread creation", "PsSetCreateThreadNotifyRoutine",
     "runs on every thread create and exit"),
    ("image load", "PsSetLoadImageNotifyRoutine",
     "runs on every driver and DLL mapped"),
    ("registry", "CmRegisterCallbackEx",
     "runs on every registry operation"),
]

CALLBACK_SLOTS = 64
RIP_ABSOLUTE = re.compile(r"\[0x([0-9a-f]{6,16})\]")


def array_shape(raw: bytes, packed: bool = True) -> list[int] | None:
    """The callback blocks in a candidate array, or None if it is not one.

    Decided entirely from the array's own contents, before anything in it is
    dereferenced - and that ordering is the point. A dereference goes wherever
    the contents point, so scanning a region of .data that is not one of these
    arrays means chasing arbitrary numbers as kernel pointers, thousands of
    them, through the read path. Reads are guarded, so this is a bound on work
    rather than a proven fix for anything: the guest did triple-fault during an
    unbounded version of this scan, but it also reset later with the scan
    finished and nothing running, which is the instability CLAUDE.md already
    describes. Do not read this filter as having closed that.

    An entry is a pointer to an EX_CALLBACK_ROUTINE_BLOCK with the low four
    bits used as a reference count. A real table holds a handful of them packed
    at the front and then zeroes; anything with a gap, a repeat, a non-kernel
    pointer or twenty entries is some other structure that happens to contain
    pointers.
    """
    blocks = []
    ended = False
    for slot in range(CALLBACK_SLOTS):
        value = int.from_bytes(raw[slot * 8:slot * 8 + 8], "little")
        if value == 0:
            ended = True                # registrations are packed at the front
            continue
        if ended and packed:
            # A gap. For the Ps arrays that means this is not one of them; for
            # registry callbacks, which are unregistered individually and leave
            # holes behind, it is normal - so the discovery pass asks for the
            # relaxed test and keeps every other constraint.
            return None
        block = value & ~0xF
        if block < 0xFFFF800000000000:
            return None                 # not a kernel pointer: wrong array
        blocks.append(block)

    if not blocks or len(blocks) > 16:
        return None
    if len(blocks) != len(set(blocks)):
        return None                     # the same entry twice: not a table
    return blocks


# How far into a callback block to look for the routine. EX_CALLBACK_ROUTINE_BLOCK
# has it at +0x8, which is what the Ps notification arrays use. Registry
# callbacks do not: CmpCallBackVector's entries point at a larger block with the
# routine somewhere else, which is why the first version of this located that
# array and then failed to identify it.
CALLBACK_BLOCK_SEARCH = 0x40


def block_routine(block: int, offset: int) -> int | None:
    """The pointer at block+offset, if it is code in a loaded module."""
    try:
        value = int.from_bytes(read_bytes(block + offset, 8), "little")
    except CtlError:
        return None
    return value if module_for(value) is not None else None


def callback_entries(array: int, offset: int = 8,
                     packed: bool = True) -> list[tuple[int, int]] | None:
    """Decode a candidate array of callback blocks, or decide it is not one.

    An entry is a pointer to a block with the low four bits used as a reference
    count, and a routine somewhere inside it. That shape is what identifies the
    array: it does not have to be found by recognising the right instruction,
    only by testing every data address the registration function touches and
    keeping the one whose contents decode.

    Returns (block, routine) pairs, or None when this is not such an array.
    """
    try:
        raw = read_bytes(array, CALLBACK_SLOTS * 8)
    except CtlError:
        return None
    if len(raw) < CALLBACK_SLOTS * 8:
        return None

    blocks = array_shape(raw, packed)
    if blocks is None:
        return None

    entries = []
    for block in blocks:
        routine = block_routine(block, offset)
        # The routine has to be code in something loaded. A stale or wrongly
        # identified array fails here, which is the whole point of checking.
        if routine is None:
            return None
        entries.append((block, routine))

    return entries


def find_routine_offsets(array: int, wanted: dict[str, int]) -> dict[str, int]:
    """Where in this array's blocks each probe's address turns up.

    The routine is at +0x8 in an EX_CALLBACK_ROUTINE_BLOCK, which is what the Ps
    notification arrays hold. Registry callbacks do not use that structure, so
    looking at +0x8 finds nothing and the array goes unidentified - which is
    exactly what happened to CmpCallBackVector.

    Rather than hardcode a second offset, ask: the probe was just registered, so
    its address is somewhere in one of these blocks, and wherever it is is the
    layout. Each block is read once and every outstanding probe checked against
    it, because reads are the expensive part.
    """
    try:
        raw = read_bytes(array, CALLBACK_SLOTS * 8)
    except CtlError:
        return {}

    blocks = array_shape(raw, packed=False)
    if blocks is None:
        return {}

    found: dict[str, int] = {}
    for block in blocks:
        try:
            body = read_bytes(block, CALLBACK_BLOCK_SEARCH)
        except CtlError:
            continue
        for offset in range(0, len(body) - 8, 8):
            value = int.from_bytes(body[offset:offset + 8], "little")
            for kind, probe in wanted.items():
                if value == probe and kind not in found:
                    found[kind] = offset
    return found


def callback_candidates(export: str) -> list[int]:
    """Data addresses a registration function touches.

    Reads the exported function and follows its direct calls two levels - these
    wrappers nest, PsSetCreateProcessNotifyRoutineEx through
    PsSetCreateProcessNotifyRoutineEx2 and on. Every RIP-relative address it
    sees is a candidate; which of them is the array is settled by the probe,
    not here.
    """
    try:
        start = resolve(f"nt!{export}")
    except (CtlError, ValueError):
        return []

    seen: set[int] = set()
    queue = [(start, 0)]
    candidates: list[int] = []

    # Bounded on purpose. Every function read is a round trip through the
    # control channel, and following calls two levels out of four exports
    # reaches far more of the kernel than it needs to.
    while queue and len(seen) < 12:
        address, depth = queue.pop(0)
        if address in seen or depth > 2:
            continue
        seen.add(address)

        try:
            code = read_bytes(address, 1024)
        except CtlError:
            continue

        offset = 0
        while offset < len(code):
            try:
                length, text, branch = disassemble_one(code, offset,
                                                       address + offset)
            except DecodeError:
                offset += 1
                continue

            for literal in RIP_ABSOLUTE.findall(text):
                value = int(literal, 16)
                if value not in candidates:
                    candidates.append(value)

            if (branch is not None and text.startswith("call")
                    and depth < 2):
                queue.append((branch, depth + 1))
            offset += length

    return candidates


def probe_addresses(arm: bool) -> dict[str, int]:
    """Arm or disarm the driver's own callbacks and say where they are.

    Refuses to answer if the four addresses are not distinct. They were once
    folded into a single function by the linker, and identical addresses do not
    fail - they silently identify whichever array is looked at first as all
    four kinds at once.
    """
    found = {}
    distinct = True
    for line in ctl("probe", "on" if arm else "off").splitlines():
        if not line.startswith("probe "):
            continue
        kind, _, value = line[len("probe "):].partition("=")
        if kind.strip() == "distinct":
            distinct = value.strip() == "1"
            continue
        if kind.strip() == "hits":
            continue
        try:
            found[kind.strip()] = int(value, 0)
        except ValueError:
            continue

    if arm and (not distinct or len(set(found.values())) != len(found)):
        raise CtlError("the driver's probe routines share an address, so they "
                       "cannot tell the callback arrays apart")
    return found


def tool_watch_ioctls(name: str, prolog_length: int | None = None) -> str:
    """Hook a driver's IRP_MJ_DEVICE_CONTROL and report what really arrives.

    svmhv_ioctls reads the dispatcher and recovers the codes a driver *can*
    handle. This is the other half: the codes anything actually sends, with the
    buffer sizes and the calling process, taken from the IRP as it goes past.

    The two disagree usefully. A candidate that never arrives may be a false
    positive or simply unused; a code that arrives and is not in the static list
    means the dispatcher reaches it some way the scan cannot see.
    """
    address = driver_object(name)
    raw = read_bytes(address, DRIVER_OBJECT_SIZE)

    def pointer(at):
        return int.from_bytes(raw[at:at + 8], "little")

    base = pointer(DRIVER_START)
    size = int.from_bytes(raw[DRIVER_SIZE:DRIVER_SIZE + 4], "little")
    handlers = [pointer(DRIVER_MAJOR + i * 8) for i in range(len(IRP_NAMES))]
    default = unset_handler(handlers, base, size)

    handler = handlers[14]
    if handler == 0 or handler == default:
        return (f"{name} does not handle IRP_MJ_DEVICE_CONTROL, so there is "
                "nothing to watch")

    # The IRP is the second argument to a dispatch routine, so RDX - argument 1
    # counting from zero, which is what the capture syntax uses.
    result = tool_hook_trace(f"{handler:#x}", prolog_length, capture="1:irp")

    # Say so rather than print the instructions for reading results that will
    # never arrive. The first version of this reported the failure and then
    # cheerfully explained what to do next, which reads as success.
    if "failed" in result or "hook id" not in result:
        return (f"could not hook {name}'s IRP_MJ_DEVICE_CONTROL at "
                f"{symbolize(handler)}\n{result}")

    return (f"watching {name}'s IRP_MJ_DEVICE_CONTROL at {symbolize(handler)}\n"
            f"{result}\n\n"
            "Every device control request now records its control code, the "
            "input and output buffer sizes and the device it went to. Compare "
            "them against svmhv_ioctls to see which recovered codes are real.\n"
            "\n"
            "One dispatcher usually serves every major function, so reads and "
            "writes come through here too and fill the ring - those rows show "
            "a major and no ioctl, which is the honest answer, since only the "
            "device control majors put a control code in that field. Call "
            "svmhv_trace_reset immediately before generating the traffic you "
            "care about.\n"
            "Take it off with svmhv_unhook when done.")


def tool_callbacks() -> str:
    """Every driver that asked to be told when something happens.

    This is the answer to "what else is watching", and for reverse engineering
    a driver it is often the whole story: a .sys with no device object and no
    IOCTL interface still runs on every process creation if it registered for
    it, and the registration is the only trace of that.

    It is also how the machine's own monitoring shows itself - anti-cheat,
    endpoint protection and the kernel's own consumers all appear here, named
    by the module each routine lives in.
    """
    # Every data address any of the four registration functions touches. The
    # arrays sit next to each other in .data and hold structurally identical
    # entries, so nothing here distinguishes them - the probe does.
    candidates: list[int] = []
    for _, export, _ in CALLBACK_TABLES:
        for candidate in callback_candidates(export):
            if candidate not in candidates:
                candidates.append(candidate)

    probes = probe_addresses(True)
    layouts: dict[str, int] = {}
    try:
        identified: dict[str, tuple[int, list[tuple[int, int]]]] = {}
        deferred: list[int] = []

        for candidate in candidates:
            if len(identified) == len(probes):
                break                   # every kind placed; stop reading
            entries = callback_entries(candidate)
            if not entries:
                # The shape may still be right with the routine somewhere other
                # than +0x8; that costs a read per block, so it waits until the
                # cheap pass has placed everything it can.
                deferred.append(candidate)
                continue
            routines = {routine for _, routine in entries}
            for kind, probe in probes.items():
                if probe in routines and kind not in identified:
                    identified[kind] = (candidate, entries)

        for candidate in deferred[:8]:
            outstanding = {kind: probe for kind, probe in probes.items()
                           if kind not in identified}
            if not outstanding:
                break
            for kind, offset in find_routine_offsets(candidate,
                                                     outstanding).items():
                entries = callback_entries(candidate, offset, packed=False)
                if entries:
                    identified[kind] = (candidate, entries)
                    layouts[kind] = offset
    finally:
        # Whatever happened above, the registry probe must not stay registered:
        # it runs on every registry operation in the system.
        probe_addresses(False)

    lines = ["registered notification callbacks", ""]
    total = 0

    for label, export, what in CALLBACK_TABLES:
        kind = label.split()[0]
        if kind not in identified:
            lines += [f"  {label} ({what})",
                      "    not identified - the driver's own probe did not "
                      f"turn up in any array reachable from nt!{export}", ""]
            continue

        array, entries = identified[kind]
        others = [(block, routine) for block, routine in entries
                  if routine != probes[kind]]
        lines.append(f"  {label} ({what})")
        lines.append(f"    array at {array:#x}, {len(others)} registered")
        if kind in layouts:
            lines.append(f"    (its blocks keep the routine at +{layouts[kind]:#x}, "
                         f"not the +0x8 the others use - found by looking for "
                         f"the probe rather than assuming)")
        for _, routine in others:
            module = module_for(routine)
            owner = module["name"] if module else "?"
            lines.append(f"      {routine:#018x}  {symbolize(routine):<44} "
                         f"[{owner}]")
        lines.append("")
        total += len(others)

    lines += ["Each array was identified by registering a callback of our own "
              "through the",
              "documented API and finding that exact address in it, then "
              "unregistering - the",
              "arrays have no symbol and look identical, so anything less is a "
              "guess.", ""]

    if total:
        lines += [f"{total} callback(s). Each runs in the context of the "
                  f"thread that caused the event,",
                  "so a hook on any of them sees the process it was called "
                  "for."]
    return "\n".join(lines)


def tool_explain(target: str) -> str:
    """Everything known about one address, in a single call."""
    address = resolve(target)
    lines = [f"{target} = {address:#x}", f"symbol   : {symbolize(address)}"]

    module = module_for(address)
    if module is None:
        lines.append("module   : not inside any loaded module")
    else:
        lines.append(f"module   : {module['name']} at {module['base']:#x} "
                     f"+{address - module['base']:#x}")
        lines.append(f"path     : {module['path']}")

    try:
        code = read_bytes(address, 64)
        lines += ["", f"bytes    : {code[:16].hex()}"]
        offsets = instruction_offsets(code, limit=8)
        lines.append("boundaries: " + ", ".join(str(o) for o in offsets))
        try:
            lines.append(f"prolog   : {safe_prolog_length(code)} bytes is the "
                         "smallest safe hook prologue")
        except DecodeError as error:
            lines.append(f"prolog   : cannot be computed here ({error}) - "
                         "do not guess one")
    except CtlError as error:
        lines.append(f"bytes    : unreadable ({error})")

    for hook in records(ctl("hooks"), "hook"):
        try:
            if int(hook.get("target", "0"), 0) == address:
                lines.append("")
                lines.append(f"hooked   : id {hook.get('id')} "
                             f"active={hook.get('active')} "
                             f"hits={hook.get('hits')}")
        except ValueError:
            pass

    return "\n".join(lines)


# --------------------------------------------------------- service control

SERVICE = "svmhv"


def service_command(*arguments: str) -> str:
    """Run sc.exe. Deliberately not routed through ctl(): this is the one thing
    that has to work when the hypervisor is *not* answering."""
    try:
        done = subprocess.run(["sc.exe", *arguments],
                              capture_output=True, text=True, timeout=120)
    except (FileNotFoundError, subprocess.TimeoutExpired) as error:
        raise CtlError(f"sc.exe: {error}")
    return (done.stdout or "") + (done.stderr or "")


def service_state() -> str:
    text = service_command("query", SERVICE)
    for line in text.splitlines():
        if "STATE" in line:
            parts = line.split(":", 1)[1].split()
            return parts[1] if len(parts) > 1 else parts[0]
    if "1060" in text or "does not exist" in text:
        return "ABSENT"
    return "UNKNOWN"


def tool_service(action: str = "status") -> str:
    """Load, unload or reload the hypervisor.

    This exists because the transport that would otherwise do it does not
    survive the thing being controlled: PowerShell Direct drops its session
    while the hypervisor is loaded and does not come back until the guest
    reboots. Without this, reloading a rebuilt driver means rebooting the
    machine, which throws away every piece of state an investigation has built
    up. Here the agent is inside the guest and outlives the driver.
    """
    action = action.lower()
    if action not in ("status", "load", "unload", "reload"):
        return "action must be status, load, unload or reload"

    if action == "status":
        return f"{SERVICE} is {service_state()}"

    lines = []
    if action in ("unload", "reload"):
        before = service_state()
        if before == "RUNNING":
            service_command("stop", SERVICE)
            for _ in range(40):
                if service_state() != "RUNNING":
                    break
                time.sleep(0.25)
            lines.append(f"stopped (was {before}, now {service_state()})")
        else:
            lines.append(f"not running (state {before}), nothing to stop")

    if action in ("load", "reload"):
        if service_state() == "ABSENT":
            return "\n".join(lines + [
                f"the {SERVICE} service does not exist; create it with "
                f"'sc create {SERVICE} type= kernel binPath= <path>' first"])
        service_command("start", SERVICE)
        for _ in range(40):
            if service_state() == "RUNNING":
                break
            time.sleep(0.25)
        state = service_state()
        lines.append(f"started (now {state})")
        if state != "RUNNING":
            lines.append("check the System event log: a driver that refuses to "
                         "load usually says why there")

    return "\n".join(lines)


# ----------------------------------------------------------- driver objects

# DRIVER_OBJECT on x64. Stable across every Windows 10/11 build; the dispatch
# table is the last field and the reason this structure is interesting at all.
#   0x00 Type/Size   0x08 DeviceObject   0x10 Flags
#   0x18 DriverStart 0x20 DriverSize     0x28 DriverSection
#   0x30 DriverExtension                 0x38 DriverName (UNICODE_STRING, 16)
#   0x48 HardwareDatabase                0x50 FastIoDispatch
#   0x58 DriverInit  0x60 DriverStartIo  0x68 DriverUnload
#   0x70 MajorFunction[28]
DRIVER_OBJECT_SIZE = 0x150
DRIVER_START = 0x18
DRIVER_SIZE = 0x20
DRIVER_SECTION = 0x28
DRIVER_NAME = 0x38
DRIVER_INIT = 0x58
DRIVER_STARTIO = 0x60
DRIVER_UNLOAD = 0x68
DRIVER_MAJOR = 0x70

IRP_NAMES = [
    "CREATE", "CREATE_NAMED_PIPE", "CLOSE", "READ", "WRITE",
    "QUERY_INFORMATION", "SET_INFORMATION", "QUERY_EA", "SET_EA",
    "FLUSH_BUFFERS", "QUERY_VOLUME_INFORMATION", "SET_VOLUME_INFORMATION",
    "DIRECTORY_CONTROL", "FILE_SYSTEM_CONTROL", "DEVICE_CONTROL",
    "INTERNAL_DEVICE_CONTROL", "SHUTDOWN", "LOCK_CONTROL", "CLEANUP",
    "CREATE_MAILSLOT", "QUERY_SECURITY", "SET_SECURITY", "POWER",
    "SYSTEM_CONTROL", "DEVICE_CHANGE", "QUERY_QUOTA", "SET_QUOTA", "PNP",
]


def describe_pointer(value: int) -> str:
    """A field that is often legitimately empty.

    Windows clears DriverInit once a driver has started and plenty of drivers
    have no StartIo or Unload at all, so "not set" is the common answer and has
    to be said rather than rendered as a symbol lookup for address zero.
    """
    if value == 0:
        return "(not set)"
    named = symbolize(value)
    return named if "!" in named or "+" in named else f"{value:#x}"


def unset_handler(handlers: list[int], base: int, size: int) -> int | None:
    """Which pointer in a dispatch table means "this driver does not do that".

    Almost every slot points at nt!IopInvalidDeviceRequest, so the majority
    pointer is the obvious way to find it - and it is wrong for the drivers that
    matter most. partmgr points all twenty-eight slots at one function of its
    own; taking the majority there declares the driver's only dispatcher to be
    the default and reports that it handles nothing.

    Outside the image is the test that actually holds. The default handler is
    in the kernel; anything a driver wrote is in the driver.
    """
    if not handlers:
        return None
    common = max(set(handlers), key=handlers.count)
    if base <= common < base + size:
        return None
    return common


def driver_object(name: str) -> int:
    values = pairs(ctl("driverobj", name))
    address = as_int(values, "driver_object")
    if address == 0:
        raise CtlError(f"no driver object for {name!r} "
                       f"(status {values.get('status', '?')})")
    return address


def tool_driver(name: str) -> str:
    """The dispatch table and everything around it, for one driver.

    This is the closest thing a .sys has to a symbol table. Almost none of them
    export anything, so the exported-name path that works for the kernel gives
    nothing here - but every driver has to publish its entry points in a
    DRIVER_OBJECT, and those are precisely the functions worth hooking.
    """
    address = driver_object(name)
    raw = read_bytes(address, DRIVER_OBJECT_SIZE)

    def pointer(at):
        return int.from_bytes(raw[at:at + 8], "little")

    base = pointer(DRIVER_START)
    size = int.from_bytes(raw[DRIVER_SIZE:DRIVER_SIZE + 4], "little")

    lines = [
        f"{name}",
        f"  driver object : {address:#x}",
        f"  image         : {base:#x} + {size:#x}",
        f"  DriverEntry   : {describe_pointer(pointer(DRIVER_INIT))}",
        f"  StartIo       : {describe_pointer(pointer(DRIVER_STARTIO))}",
        f"  Unload        : {describe_pointer(pointer(DRIVER_UNLOAD))}",
        "",
        "  dispatch table (only the entries it actually handles):",
    ]

    handlers = [pointer(DRIVER_MAJOR + i * 8) for i in range(len(IRP_NAMES))]
    default = unset_handler(handlers, base, size)

    if default is None and len(set(handlers)) == 1:
        # One function for every slot. partmgr does this, and the majority rule
        # below would have called its only dispatcher "the default handler" and
        # reported nothing at all.
        lines += [f"    every slot -> {symbolize(handlers[0])} "
                  f"({handlers[0]:#018x})",
                  "    one dispatcher for everything; it switches on the "
                  "major function itself",
                  "",
                  "  Hook that one function with svmhv_hook_trace to see every "
                  "request this driver gets."]
        return "\n".join(lines)

    shown = 0
    for index, handler in enumerate(handlers):
        if handler == 0 or handler == default:
            continue
        shown += 1
        inside = base <= handler < base + size
        lines.append(f"    IRP_MJ_{IRP_NAMES[index]:<24} {handler:#018x}"
                     f"  {symbolize(handler)}"
                     f"{'' if inside else '   [outside the image]'}")

    if shown == 0:
        lines.append("    none - every slot points at the default handler")
    lines += ["",
              f"  {shown} entry point(s) worth hooking. Hook one with "
              f"svmhv_hook_trace on its address."]
    return "\n".join(lines)


def tool_devices(name: str) -> str:
    """The devices a driver owns, and whatever is filtering them.

    The dispatch table says how a driver can be entered; this says how anything
    outside the kernel reaches it at all. A driver with no device object is not
    reachable from user mode by any name, which for a .sys that was loaded
    deliberately is a fact worth having early.
    """
    text = ctl("devices", name)
    body = "\n".join(line for line in text.splitlines()
                     if not line.startswith("status="))
    lines = [line for line in body.splitlines() if line.strip()]
    count = 0
    for line in lines:
        if line.startswith("devices="):
            count = int(line.split("=", 1)[1] or 0)

    if count == 0:
        return (f"{name} owns no device objects.\n"
                "Nothing in user mode can open it by name; it is reached "
                "some other way - as a filter, from another driver, or not "
                "at all after DriverEntry.")

    out = [f"{name}: {count} device object(s)", ""]
    for line in lines:
        if line.startswith("devices=") or line.startswith("truncated="):
            continue
        out.append("  " + line if not line.startswith("  ") else "  " + line)
    if any(line.startswith("truncated=") for line in lines):
        out.append("  ... more than fitted in one answer")

    named = [line for line in lines if " name=\\" in line]
    if named:
        out += ["",
                "Cross-reference a name against svmhv_symlinks to find the "
                "string an application would open."]
    return "\n".join(out)


def tool_symlinks(contains: str = "") -> str:
    """Every symbolic link in \\GLOBAL??, optionally filtered by substring.

    This is the missing half of a device name: an application opens \\\\.\\Foo,
    which is a link, and the link is the only record of which device that was.
    """
    wanted = contains.lower()
    found: list[str] = []
    start = 0

    # Several hundred of them, about forty to an answer; the driver says where
    # to resume and stops saying it when there is nothing left.
    for _ in range(64):
        text = ctl("symlinks", str(start))
        nxt = None
        for line in text.splitlines():
            if line.startswith("link "):
                found.append(line[len("link "):])
            elif line.startswith("next="):
                nxt = int(line.split("=", 1)[1] or 0)
        if nxt is None:
            break
        start = nxt

    matched = [entry for entry in found
               if not wanted or wanted in entry.lower()]
    if not matched:
        return (f"no symbolic link matches {contains!r} "
                f"({len(found)} link(s) looked at)")

    head = (f"{len(matched)} of {len(found)} symbolic link(s)"
            + (f" matching {contains!r}" if contains else ""))
    body = "\n".join(f"  {entry}" for entry in sorted(matched))
    return f"{head}\n\n{body}"


def tool_imports(module_name: str) -> str:
    """What a module calls. For a driver with no exports, this is the profile."""
    module = module_by_name(module_name)
    if module is None:
        return f"no loaded module called {module_name!r}"
    base = module["base"]

    header = read_bytes(base, 0x400)
    if header[:2] != b"MZ":
        return f"no MZ header at {base:#x}"
    pe = int.from_bytes(header[0x3C:0x40], "little")
    optional = pe + 0x18
    magic = int.from_bytes(header[optional:optional + 2], "little")
    directory = optional + (0x70 if magic == 0x20B else 0x60)
    # The import directory is the second entry, so 8 bytes past the export one.
    rva = int.from_bytes(header[directory + 8:directory + 12], "little")
    if rva == 0:
        return f"{module['name']} imports nothing"

    blob = read_bytes(base + rva, 0x1000)
    pages: dict[int, bytes] = {}

    def string_at(string_rva):
        page = (base + string_rva) & ~0xFFF
        if page not in pages:
            try:
                pages[page] = read_bytes(page, 0x1000)
            except CtlError:
                return ""
        chunk = pages[page][(base + string_rva) & 0xFFF:]
        return chunk.split(b"\0", 1)[0].decode("ascii", "replace")

    lines = [f"{module['name']} imports", ""]
    for i in range(0, len(blob), 20):
        entry = blob[i:i + 20]
        if len(entry) < 20 or entry == b"\0" * 20:
            break
        name_rva = int.from_bytes(entry[12:16], "little")
        thunk_rva = int.from_bytes(entry[0:4], "little") or \
            int.from_bytes(entry[16:20], "little")
        source = string_at(name_rva)
        if not source:
            continue

        functions = []
        try:
            thunks = read_bytes(base + thunk_rva, 0x800)
            for j in range(0, len(thunks), 8):
                value = int.from_bytes(thunks[j:j + 8], "little")
                if value == 0:
                    break
                if value & (1 << 63):
                    functions.append(f"#{value & 0xFFFF}")
                else:
                    functions.append(string_at(value + 2))
        except CtlError:
            pass

        lines.append(f"  {source}  ({len(functions)})")
        for function in functions[:40]:
            lines.append(f"      {function}")
        if len(functions) > 40:
            lines.append(f"      ... and {len(functions) - 40} more")
    return "\n".join(lines)


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
        f"captured return   : {values.get('traced_return', '?')}",
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


# ============================================================== experiments
#
# Everything above this line observes.  What follows is the half that changes
# something and puts it back, which is what turns reading a disassembly into an
# experiment - and the reason any of it is safe to try is the snapshot.

SNAPSHOT_ACTIONS = ("take", "restore", "release", "query")


def _snapshot_report(values: dict, what: str) -> str:
    state = values.get("snapshot_state", "?")
    base = as_int(values, "snapshot_base")
    size = as_int(values, "snapshot_size")
    dirty = as_int(values, "snapshot_dirty")
    capacity = as_int(values, "snapshot_capacity")
    restored = as_int(values, "snapshot_restored")

    lines = [f"{what}: {state}"]
    if base:
        lines.append(f"  range     {base:#x} + {size:#x} ({size // 4096} pages)")
        lines.append(f"  modified  {dirty} page(s) of {capacity} the store holds")
    if restored:
        lines.append(f"  restored  {restored} page(s)")

    if as_int(values, "snapshot_readonly"):
        lines += [
            "  locked    for reading only - the range is not writable by the "
            "guest",
            "",
            "That is the ordinary answer for code and for read-only image data, "
            "and for those it costs nothing: a page the guest cannot write "
            "cannot move out from under the snapshot either. It does mean that "
            "if anything in this range IS writable, its first store will "
            "relocate it and this snapshot will stop describing it.",
        ]

    if state == "overflowed":
        lines += [
            "",
            "The store is full, so this no longer describes a state the guest "
            "was ever in and restore will refuse. Take it again over a smaller "
            "range, or with more store pages - the store is fixed at arm time "
            "because a nested page fault cannot allocate one.",
        ]
    return "\n".join(lines)


def tool_snapshot(action: str = "query", target: str = "", size: int = 0,
                  pid: int = 0, store_pages: int = 0) -> str:
    """Take a copy-on-write snapshot of a range of memory, or put it back.

    This is the one tool here that makes an experiment repeatable. Snapshot the
    memory a routine works on, let it run, look at what changed, restore, and
    run it again with one input different - which is the difference between
    reading what a program did once and finding out what it does.

    It restores MEMORY IN ONE RANGE and nothing else. Not registers, not
    devices, not the pages outside the range that the same code touched. A
    range another processor is actively using gets restored underneath it,
    which for ordinary kernel data is a bugcheck rather than an experiment - so
    point it at memory whose owner you know: a target's heap, a decrypted
    buffer, a module's data section.
    """
    action = action.lower()
    if action not in SNAPSHOT_ACTIONS:
        return f"action must be one of {', '.join(SNAPSHOT_ACTIONS)}"

    if action != "take":
        values = pairs(ctl("snapshot", action))
        status = as_int(values, "status", 0) & 0xFFFFFFFF
        if status == 0x80000005:
            return _snapshot_report(values, "restore refused")
        if status == 0xC0000184:
            return ("there is no snapshot to " + action +
                    "; take one first with action='take'")
        if status:
            return f"{action} failed: {status:#010x}\n" + \
                   _snapshot_report(values, "snapshot")
        return _snapshot_report(values, action)

    if not target or not size:
        return "take needs a target address or symbol and a size in bytes"

    address = resolve(target, pid)
    arguments = ["snapshot", "take", f"{address:x}", f"{int(size):x}"]
    if pid or store_pages:
        arguments.append(str(int(pid)))
    if store_pages:
        arguments.append(str(int(store_pages)))

    values = pairs(ctl(*arguments))
    status = as_int(values, "status", 0) & 0xFFFFFFFF
    if status:
        why = {
            0xC0000010: " - the range is empty or larger than the 64 MiB cap",
            0xC0000009A & 0xFFFFFFFF: "",
            0xC0000141: " - the range could not be pinned; it may not all be "
                        "resident, or the process id is wrong",
            0xC0000022: " - some of that range is the hypervisor's own memory",
        }.get(status, "")
        return f"snapshot take failed: {status:#010x}{why}"

    return _snapshot_report(values, f"snapshot of {target}")


def tool_call(target: str, args: list | None = None, pid: int = 0,
              steps: int = 0) -> str:
    """Call a function with arguments of your choosing and report what it returns.

    The question a disassembly cannot answer. Everything else here waits for the
    guest to call something; this calls it, with the input you pick, and hands
    back the return value and the cycles it took.

    Read the warning and mean it: this RUNS the function. A target called with
    arguments it was not written for takes the guest down, and no exception
    handler can prevent that - an invalid kernel pointer is not an exception in
    Windows, it is a bugcheck. Take a snapshot of anything the call will write
    to first, and start with functions whose prototype you actually know.
    """
    address = resolve(target, pid)
    values = []
    for one in (args or []):
        if isinstance(one, int):
            values.append(one)
        else:
            text = str(one).strip()
            try:
                values.append(resolve(text, pid) if "!" in text
                              else int(text, 16))
            except (ValueError, CtlError):
                return f"could not make an argument out of {one!r}"

    if len(values) > 8:
        return "at most eight arguments"

    arguments = ["call", f"{address:x}"] + [f"{v:x}" for v in values]
    if pid:
        arguments.append(f"pid={int(pid)}")
    if steps:
        arguments.append(f"steps={int(max(1, min(int(steps), 4096)))}")

    result = pairs(ctl(*arguments))
    status = as_int(result, "status", 0) & 0xFFFFFFFF
    if status == 0xC0000141:
        return (f"{target} resolved to {address:#x}, which is not a valid "
                f"kernel address right now. A user-mode function cannot be "
                f"called this way at all.")
    if status == 0xC0000022:
        return "that address is inside the hypervisor itself"

    returned = as_int(result, "call_result")
    cycles = as_int(result, "call_cycles")
    exception = as_int(result, "call_exception")

    lines = [f"{symbolize(address, pid)}({', '.join(f'{v:#x}' for v in values)})",
             f"  returned  {returned:#x}  ({returned})",
             f"  cycles    {cycles:,}"]
    if exception:
        lines.append(f"  raised    {exception:#010x} - the call did not "
                     f"complete and the return value is meaningless")
    if steps:
        # Everything from the target's first instruction to its return.  Not
        # "rip >= address", which was the first attempt and counts this driver's
        # own code too, because svmhv.sys loads above ntoskrnl.
        rows = _step_rows(steps)
        inside, seen = 0, False
        for row in rows:
            rip = int(row.get("rip", "0"), 0)
            if rip == address:
                seen = True
            if seen:
                inside += 1
        lines.append(f"  stepped   {len(rows)} record(s), {inside} of them from "
                     f"the target's entry onwards; svmhv_reverse walks them")
    return "\n".join(lines)


def tool_usercall(target: str, pid: int, args: list | None = None,
                  tid: int = 0, timeout: int = 5000) -> str:
    """Call a function inside a user process by borrowing one of its threads.

    svmhv_call is for kernel functions. This is the same question for an .exe or
    a .dll, and it needs a user thread with a user stack, so it borrows one:
    suspends it, saves its whole context, points it at the target with your
    arguments, catches it when it returns, and puts the context back.

    The thread does not do its own work while this runs. Borrowing one that
    holds a lock and calling something that wants the same lock deadlocks the
    process until the timeout - so name a thread that is idle in a wait where
    you can. Everything the called function does to the process is real and is
    not undone; snapshot anything it will write to first.
    """
    address = resolve(target, pid)
    values = []
    for one in (args or []):
        if isinstance(one, int):
            values.append(one)
        else:
            text = str(one).strip()
            try:
                values.append(resolve(text, pid) if "!" in text
                              else int(text, 16))
            except (ValueError, CtlError):
                return f"could not make an argument out of {one!r}"
    if len(values) > 4:
        return ("at most four arguments. A fifth goes in the caller's stack "
                "slots, which needs the callee's expectations about home space "
                "and alignment - more than a generic mechanism can know.")
    if not pid:
        return "a user-mode call needs the process id"

    arguments = (["usercall", f"{address:x}", f"pid={int(pid)}"]
                 + [f"{v:x}" for v in values])
    if tid:
        arguments.append(f"tid={int(tid)}")
    if timeout:
        arguments.append(f"timeout={int(timeout)}")

    result = pairs(ctl(*arguments))
    status = as_int(result, "status", 0) & 0xFFFFFFFF

    if status == 0x00000102:
        return (f"borrowed thread {as_int(result, 'usercall_thread')} never came "
                f"back within {timeout} ms.\nIts original context has been put "
                f"back, so nothing is left running inside the call - but the "
                f"function either blocked or never returns. Try another thread, "
                f"a longer timeout, or check that the arguments are what it "
                f"expects.")
    if status == 0x8000000B:
        return ("that thread has no user-mode frame - it is a system thread, or "
                "one that has never been out to user mode. Name a different "
                "one.")
    if status == 0xC000000D and not tid:
        return "that process has no threads to borrow"
    if status == 0xC000007A:
        return ("the thread routines this needs could not be resolved on this "
                "kernel, so user-mode calls are unavailable here. It needs "
                "PsSuspendThread, PsResumeThread and PsGetNextProcessThread, "
                "none of which is in the WDK import library - the driver looks "
                "them up by name at run time and logs which one was missing.")
    if status:
        return f"usercall failed: {status:#010x}"

    returned = as_int(result, "usercall_result")
    used = as_int(result, "usercall_thread")
    return "\n".join([
        f"{symbolize(address, pid)}({', '.join(f'{v:#x}' for v in values)}) "
        f"in pid {pid}",
        f"  returned  {returned:#x}  ({returned})",
        f"  thread    {used}, put back where it was",
    ])


def tool_revive() -> str:
    """Put back the processors a fatal exit left running outside SVM.

    A processor that takes an exit this hypervisor cannot handle leaves guest
    mode and stays out, so the machine survives and the evidence survives - but
    the hypervisor is then covering fewer processors than it claims. Until this
    existed the only way back was a reload, which throws away every hook, every
    note the driver holds and the trace ring along with the problem.

    Read svmhv_status first: whatever caused the fatal exit is usually still
    there, and reviving into it produces another one.
    """
    values = pairs(ctl("revive"))
    down = as_int(values, "revive_were_down")
    up = as_int(values, "revive_virtualized")
    total = as_int(values, "revive_processors")

    if down == 0:
        return f"nothing to do: all {total} processor(s) are in guest mode"
    if up == total:
        return (f"{down} processor(s) had left SVM; all {total} are back in "
                f"guest mode.\nRead fatal_count in svmhv_status before "
                f"believing the run that follows.")
    return (f"{down} processor(s) had left SVM; {up} of {total} are in guest "
            f"mode now. The ones that did not come back are in the driver log "
            f"with the exit code that stopped them.")


# ------------------------------------------------------- the experiment loop

def _call_once(address: int, values: list[int], pid: int, steps: int = 0) -> dict:
    """One call, as parsed fields rather than a report."""
    arguments = ["call", f"{address:x}"] + [f"{v:x}" for v in values]
    if pid:
        arguments.append(f"pid={int(pid)}")
    if steps:
        arguments.append(f"steps={int(steps)}")
    result = pairs(ctl(*arguments))
    return {
        "status": as_int(result, "status", 0) & 0xFFFFFFFF,
        "result": as_int(result, "call_result"),
        "cycles": as_int(result, "call_cycles"),
        "exception": as_int(result, "call_exception"),
    }


def _parse_inputs(inputs: list, pid: int) -> tuple[list[list[int]], str]:
    """Each entry is one call's arguments: a list, or a space-separated string."""
    out = []
    for entry in inputs:
        pieces = entry.split() if isinstance(entry, str) else list(entry)
        values = []
        for piece in pieces:
            if isinstance(piece, int):
                values.append(piece)
                continue
            text = str(piece).strip()
            try:
                values.append(resolve(text, pid) if "!" in text
                              else int(text, 16))
            except (ValueError, CtlError):
                return [], f"could not make an argument out of {piece!r}"
        out.append(values)
    return out, ""


def tool_explore(target: str, inputs: list, snapshot_target: str = "",
                 snapshot_size: int = 0, pid: int = 0,
                 store_pages: int = 0) -> str:
    """Call a function once per input, and report which inputs reached new code.

    This is the loop the other tools were built for. Snapshot the memory the
    function works on, then for each input: restore, call, collect the coverage
    the call produced. What comes back is not a hundred traces, it is the short
    list of inputs that reached somewhere the others did not - which is the
    whole question when you are looking for the branch that matters.

    Arm a coverage sweep first with svmhv_sweep, or there is nothing to collect
    and this degrades to a list of return values (still useful, and said so).

    A sweep reports each page ONCE for its lifetime. That is exactly right here:
    the pages an input is credited with are pages no earlier input reached, so
    the report is genuinely "new ground" and not "everything this input
    touched". It also means order matters and the first input looks the most
    interesting - run a warm-up input first if that would mislead you.
    """
    address = resolve(target, pid)
    values, problem = _parse_inputs(inputs or [], pid)
    if problem:
        return problem
    if not values:
        return "give at least one input: a list of argument lists"
    if len(values) > 64:
        return "at most 64 inputs in one run; split it"

    snapshotting = bool(snapshot_target and snapshot_size)
    if snapshotting:
        taken = tool_snapshot("take", snapshot_target, snapshot_size, pid,
                              store_pages)
        if "armed" not in taken:
            return "could not take the snapshot, so nothing was run:\n" + taken

    # Only pages the TARGET's module reached are credited.
    #
    # A sweep is armed over physical memory, not over a function, so it reports
    # every page anything on the machine touches - and a call that takes 165
    # cycles is bracketed by seconds of ambient activity, which buries it. The
    # first run of this credited every input with the same 88 pages of graphics
    # and shell code. Filtering by the module the target lives in is what makes
    # the answer about the target.
    home = module_for(address, pid)
    low = home["base"] if home else 0
    high = (home["base"] + home["size"]) if home else 0

    def mine(found):
        if not low:
            return found, 0
        kept, dropped = {}, 0
        for page, entry in found.items():
            rip = int(entry["rip"], 0)
            if low <= rip < high:
                kept[page] = entry
            else:
                dropped += 1
        return kept, dropped

    # A running set, because reads do not consume: without it every input is
    # credited with every earlier input's records as well as its own.
    spent = _ring_sequences()
    _coverage_now(spent)

    rows = []
    ambient = 0
    try:
        for index, one in enumerate(values):
            if snapshotting and index != 0:
                restored = tool_snapshot("restore")
                if "refused" in restored or "overflow" in restored:
                    rows.append({"input": one, "failed": "snapshot overflowed"})
                    break

            outcome = _call_once(address, one, pid)
            found, dropped = mine(_coverage_now(spent))
            ambient += dropped
            rows.append({
                "input": one,
                "result": outcome["result"],
                "cycles": outcome["cycles"],
                "exception": outcome["exception"],
                "status": outcome["status"],
                "new": found,
            })
    finally:
        if snapshotting:
            tool_snapshot("restore")
            tool_snapshot("release")

    lines = [f"{symbolize(address, pid)} over {len(rows)} input(s)"
             + (f", snapshotting {snapshot_size:#x} bytes at {snapshot_target}"
                if snapshotting else ", WITHOUT a snapshot - anything the calls "
                                     "wrote is still written"),
             ""]

    interesting = [r for r in rows if r.get("new")]
    by_result: dict[int, int] = {}
    for row in rows:
        if "failed" not in row:
            by_result[row["result"]] = by_result.get(row["result"], 0) + 1

    for index, row in enumerate(rows):
        shown = " ".join(f"{v:#x}" for v in row["input"]) or "(no arguments)"
        if "failed" in row:
            lines.append(f"  [{index:>2}] {shown}  -- {row['failed']}")
            continue
        note = ""
        if row["exception"]:
            note = f"  RAISED {row['exception']:#010x}"
        elif row["status"]:
            note = f"  refused {row['status']:#010x}"
        lines.append(f"  [{index:>2}] {shown}  -> {row['result']:#x}"
                     f"  {row['cycles']:>8,} cycles"
                     + (f"  {len(row['new'])} NEW page(s)" if row["new"] else "")
                     + note)

    lines += ["", f"{len(by_result)} distinct return value(s): "
              + ", ".join(f"{v:#x} x{n}" for v, n in sorted(by_result.items()))]
    if ambient:
        lines.append(f"{ambient} page(s) reached by the rest of the machine "
                     f"during the run were dropped; only pages entered from "
                     f"{home['name'] if home else 'the target'} are credited.")
    if not low:
        lines.append("No module claims the target, so nothing could be "
                     "filtered - the pages below include everything the "
                     "machine did while this ran.")

    if not interesting:
        lines += ["",
                  "No input reached a page another had not. Either the sweep is "
                  "not armed - svmhv_sweep exec over the module first - or every "
                  "input takes the same path, which is itself an answer: the "
                  "branch you are looking for is not decided by these arguments."]
    else:
        lines += ["", "inputs that reached new code, and what entered it:"]
        for index, row in enumerate(rows):
            if not row.get("new"):
                continue
            shown = " ".join(f"{v:#x}" for v in row["input"]) or "(none)"
            lines.append(f"  [{index}] {shown}")
            for page, entry in sorted(row["new"].items(),
                                      key=lambda kv: int(kv[0], 16))[:8]:
                rip = int(entry["rip"], 0)
                state = int(entry["state"], 0)
                mark = "  WRITTEN-THEN-EXECUTED" if state & 0x04 else ""
                lines.append(f"        {int(page, 16):#014x} from "
                             f"{symbolize(rip, pid)}{mark}")
            if len(row["new"]) > 8:
                lines.append(f"        ... and {len(row['new']) - 8} more")

    return "\n".join(lines)


def tool_diverge(target: str, input_a: str, input_b: str, steps: int = 2000,
                 pid: int = 0, snapshot_target: str = "",
                 snapshot_size: int = 0) -> str:
    """Run a function under two inputs and report where the paths part.

    The canonical question in front of a licence check, a signature check or an
    anti-debug branch: not what the function does, but where the good input and
    the bad one stop agreeing. That single address is usually the whole answer,
    and finding it by reading two thousand-instruction traces is exactly what a
    reader should not have to do.

    Both runs are single-stepped into the trace ring and the two RIP sequences
    are compared. The first place they differ is reported with the instruction
    before it, which is the branch that decided.
    """
    address = resolve(target, pid)
    parsed, problem = _parse_inputs([input_a, input_b], pid)
    if problem:
        return problem
    steps = max(64, min(int(steps), 4096))

    snapshotting = bool(snapshot_target and snapshot_size)
    if snapshotting:
        taken = tool_snapshot("take", snapshot_target, snapshot_size, pid)
        if "armed" not in taken:
            return "could not take the snapshot, so nothing was run:\n" + taken

    paths = []
    try:
        for index, values in enumerate(parsed):
            if snapshotting and index != 0:
                tool_snapshot("restore")
            # Reset AND drain. The reset empties the ring; the drain moves this
            # reader's cursor past anything already in it, which a reset alone
            # does not do - and a leftover run from an earlier call is
            # indistinguishable from this one once both are in the list, which
            # is how the first version reported a divergence seven instructions
            # into a five-instruction function.
            ctl("trace-reset")
            spent = _ring_sequences()
            outcome = _call_once(address, values, pid, steps)
            rows = _step_rows(steps, spent)
            paths.append({"values": values, "rows": rows,
                          "result": outcome["result"]})
    finally:
        if snapshotting:
            tool_snapshot("restore")
            tool_snapshot("release")

    first, second = paths

    # The window covers this driver's own code at both ends - the instructions
    # between arming and the call, and everything after the return until the
    # window is closed.  Neither is the subject.  So: start at the target's
    # entry, and stop as soon as execution leaves the module the target is in,
    # which is the return.
    #
    # Bounded by the TARGET's module rather than by looking up this driver's,
    # because that lookup failing is silent and produces a comparison over
    # hundreds of instructions of instrument - which is what it did.  A target
    # that calls out into another module is cut short here, and that is the
    # right trade: the divergence being looked for is nearly always in the
    # function itself, and a wrong answer is worse than a short one.
    home = module_for(address, pid)
    low = home["base"] if home else 0
    high = (home["base"] + home["size"]) if home else 0

    def from_target(rows):
        trimmed = []
        started = False
        for row in rows:
            rip = int(row.get("rip", "0"), 0)
            if not started:
                if rip != address:
                    continue
                started = True
            elif low and not (low <= rip < high):
                break
            trimmed.append(rip)
        return trimmed

    left = from_target(first["rows"])
    right = from_target(second["rows"])

    header = [
        f"{symbolize(address, pid)}"
        + (f", bounded to {home['name']}" if home
           else ", UNBOUNDED - no module claims this address, so the counts "
                "below include whatever ran after the return"),
        f"  A  {' '.join(f'{v:#x}' for v in first['values']) or '(none)'}"
        f"  -> {first['result']:#x}   {len(left)} instruction(s)",
        f"  B  {' '.join(f'{v:#x}' for v in second['values']) or '(none)'}"
        f"  -> {second['result']:#x}   {len(right)} instruction(s)",
        "",
    ]

    if not left or not right:
        return "\n".join(header + [
            "One of the runs recorded nothing at the target's own address. The "
            "step window is a count of instructions and it is spent on whatever "
            "runs, so a preempted worker thread can burn it before reaching the "
            "call. Try again, or with more steps.",
        ])

    def head(path, count=10):
        return ["    " + ", ".join(
            (f"+{r - address:#x}" if low <= r < high else f"{r:#x}")
            for r in path[:count]) + (" ..." if len(path) > count else "")]

    for position, (one, other) in enumerate(zip(left, right)):
        if one == other:
            continue
        previous = left[position - 1] if position else None
        lines = header + [
            f"the paths part at instruction {position} into the function:",
            f"  A goes to {symbolize(one, pid)}",
            f"  B goes to {symbolize(other, pid)}",
            "",
            "  A ran:",
        ] + head(left) + ["  B ran:"] + head(right) + [""]
        if previous is not None:
            code = ""
            for row in first["rows"]:
                if int(row.get("rip", "0"), 0) == previous and row.get("code"):
                    try:
                        _, code, _ = disassemble_one(
                            bytes.fromhex(row["code"]), 0, previous)
                    except (ValueError, IndexError):
                        code = ""
                    break
            lines += ["",
                      f"the branch that decided it is at {symbolize(previous, pid)}"
                      + (f"   {code}" if code else ""),
                      "",
                      "That is the instruction to look at. svmhv_reverse will "
                      "say which register it tested and where that register got "
                      "its value."]
        return "\n".join(lines)

    if len(left) == len(right):
        return "\n".join(header + [
            "The two runs executed the same instructions in the same order for "
            "the whole window. Either the inputs do not reach a branch that "
            "distinguishes them, or the branch is beyond the window - raise "
            "steps.",
        ])
    return "\n".join(header + [
        f"identical for the first {min(len(left), len(right))} instruction(s), "
        f"then one run kept going. The shorter one returned early; the extra "
        f"instructions in the longer are what it did instead.",
    ])


# ------------------------------------------------------------ reverse window

REGISTER_NAMES = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")


def _read_ring(wanted: int, skip: set | None = None) -> list[dict]:
    """Records from the ring, de-duplicated by sequence.

    A read is NOT consuming: "trace 200" hands back the newest two hundred every
    time it is asked, so a loop that reads until it has enough gets the same two
    hundred over and over. That is not a hypothetical - it produced a comparison
    whose first seven entries were the same instruction seven times, once per
    read, which read exactly like a function looping.

    So the loop stops when a read brings nothing new rather than when it brings
    nothing, and `skip` carries the sequences a caller already considers spent.
    """
    seen = set(skip or ())
    out = []
    for _ in range(COVERAGE_MAX_READS):
        fresh = 0
        for row in records(ctl("trace", "200"), "trace"):
            sequence = row.get("seq")
            if sequence in seen:
                continue
            seen.add(sequence)
            out.append(row)
            fresh += 1
        if fresh == 0 or len(out) >= wanted:
            break
    return out


def _ring_sequences() -> set:
    """Every sequence currently visible, so a later read can ignore them."""
    return {row.get("seq") for row in records(ctl("trace", "200"), "trace")}


def _step_rows(count: int, skip: set | None = None) -> list[dict]:
    """The stepped records in the ring, oldest first, with registers parsed.

    Read across several passes, because one read returns at most 200 records and
    a step window can be twenty times that; see _read_ring for why that loop is
    not the obvious one. `skip` is what a caller already saw before it did the
    thing it is now measuring.
    """
    rows = _read_ring(max(int(count), 1), skip)
    out = []
    for row in rows:
        if int(row.get("type", "0"), 0) != 4:       # SVMHV_TRACE_STEP
            continue
        registers = []
        for piece in row.get("regs", "").split(","):
            try:
                registers.append(int(piece, 16))
            except ValueError:
                registers = []
                break
        row["registers"] = registers
        out.append(row)
    return sorted(out, key=lambda r: int(r.get("seq", "0"), 0))


def tool_reverse(register: str = "", value: str = "", count: int = 200) -> str:
    """Walk a stepped run backwards to find where a register got its value.

    The question in front of every disassembly is "why is this register that
    value", and the forward answer - run it again and watch - is what a stepped
    window exists to avoid. Every step record carries all sixteen registers, so
    the answer is a walk backwards: the last record where the value differs is
    the instruction that set it.

    Run svmhv_step first to fill the ring. With no register named this reports
    every register that changed across the window, which is the cheaper question
    and usually the one worth asking first.
    """
    rows = _step_rows(count)
    if not rows:
        return ("no step records in the ring. svmhv_step arms a window; this "
                "reads what it recorded.")
    if not rows[-1].get("registers"):
        return ("the step records carry no registers - the driver predates "
                "them. Rebuild and reload svmhv.sys.")

    usable = [r for r in rows if r.get("registers")]

    if not register:
        changed = {}
        for older, newer in zip(usable, usable[1:]):
            for index, name in enumerate(REGISTER_NAMES):
                if older["registers"][index] != newer["registers"][index]:
                    changed.setdefault(name, 0)
                    changed[name] += 1
        lines = [f"{len(usable)} step(s) recorded, "
                 f"{symbolize(int(usable[0].get('rip', '0'), 0))} .. "
                 f"{symbolize(int(usable[-1].get('rip', '0'), 0))}", ""]
        if not changed:
            lines.append("no register changed across the window")
        else:
            lines.append("registers that changed, and how often:")
            for name, times in sorted(changed.items(), key=lambda kv: -kv[1]):
                final = usable[-1]["registers"][REGISTER_NAMES.index(name)]
                lines.append(f"  {name:<4} {times:>4} time(s), "
                             f"now {final:#x}")
            lines += ["", "Name one of these to find the instruction that set "
                      "it last."]
        return "\n".join(lines)

    name = register.strip().lower()
    if name not in REGISTER_NAMES:
        return f"no register called {register!r}; one of {', '.join(REGISTER_NAMES)}"
    index = REGISTER_NAMES.index(name)

    if value:
        try:
            wanted = int(str(value), 16)
        except ValueError:
            return f"could not read {value!r} as hex"
    else:
        wanted = usable[-1]["registers"][index]

    # Backwards from the newest, for the first record where it was different.
    # That record's instruction is the one that produced the value: the step
    # record is taken BEFORE the instruction at Rip runs, so the change is
    # visible in the record after the one that caused it.
    for position in range(len(usable) - 1, 0, -1):
        if usable[position]["registers"][index] == wanted and \
           usable[position - 1]["registers"][index] != wanted:
            culprit = usable[position - 1]
            rip = int(culprit.get("rip", "0"), 0)
            was = usable[position - 1]["registers"][index]
            code = culprit.get("code", "")
            text = ""
            if code:
                try:
                    raw = bytes.fromhex(code)
                    _, text, _ = disassemble_one(raw, 0, rip)
                except (ValueError, IndexError):
                    text = ""
            lines = [
                f"{name} became {wanted:#x} at step {culprit.get('seq')}",
                f"  instruction {symbolize(rip)}" + (f"   {text}" if text else ""),
                f"  {name} was {was:#x} before it, {wanted:#x} after",
                "",
                "Context at that instruction:",
            ]
            for i, other in enumerate(REGISTER_NAMES):
                held = culprit["registers"][i]
                if held:
                    lines.append(f"    {other:<4} {held:#x}")
            return "\n".join(lines)

    oldest = usable[0]["registers"][index]
    if oldest == wanted:
        return (f"{name} held {wanted:#x} for the whole window - it was set "
                f"before the step run started. Step earlier, or watch the "
                f"memory it was loaded from with svmhv_provenance.")
    return f"{name} never held {wanted:#x} anywhere in the {len(usable)} steps recorded"


# ------------------------------------------------------------- provenance

def tool_provenance(target: str, size: int = 8, pid: int = 0,
                    seconds: int = 10, mode: str = "write") -> str:
    """Watch a buffer and report everything that writes to it, with symbols.

    "Where did this value come from" is most of reverse engineering and none of
    a disassembly. This arms a watch over the range, waits, and reports the
    writers grouped by instruction rather than as a list of events - so a
    thousand hits from one memcpy read as one line naming the memcpy, and the
    one write that came from somewhere else is visible instead of buried.

    The watch traps whole pages, so anything sharing them reports too; the
    grouping is what makes that survivable. It is taken off again before this
    returns, whatever happens.
    """
    if mode not in ("write", "access"):
        return "mode must be 'write' or 'access'"

    start = resolve(target, pid)
    size = max(1, min(int(size), 64 * 4096))
    seconds = max(1, min(int(seconds), 120))

    first = start & ~0xFFF
    last = (start + size - 1) & ~0xFFF
    pages = list(range(first, last + 0x1000, 0x1000))

    ctl("trace-reset")

    armed = []
    extra = hook_options(in_process=pid) if pid else []
    for page in pages:
        values = pairs(ctl("watch", f"{page:x}", mode, *extra))
        if not (as_int(values, "status", -1) & 0xFFFFFFFF):
            armed.append(page)

    if not armed:
        return (f"could not watch any of the {len(pages)} page(s) covering "
                f"{target}. Hypervisor memory and the trace ring are refused; "
                f"so is a page nothing has made resident.")

    try:
        time.sleep(seconds)
        text = ctl("trace", "200")
    finally:
        for page in armed:
            try:
                ctl("unhook", f"{page:x}")
            except CtlError:
                pass

    hits = [r for r in records(text, "trace")
            if int(r.get("type", "0"), 0) in (1, 2)]

    if not hits:
        return (f"nothing touched {target} in {seconds}s across "
                f"{len(armed)} page(s).\nEither it is genuinely quiet, or "
                f"whatever writes it needs provoking - run the thing that "
                f"exercises it while this is armed.")

    # Grouped by the instruction that did it, not by event.  One memcpy in a
    # loop is one line here and a thousand lines in the raw trace, and the
    # write that came from somewhere unexpected is the whole point.
    by_writer: dict[int, dict] = {}
    for hit in hits:
        rip = int(hit.get("rip", "0"), 0)
        entry = by_writer.setdefault(rip, {
            "count": 0, "gpas": set(), "before": None, "after": None,
            "cr3": hit.get("cr3", ""), "branch": hit.get("brfrom", ""),
        })
        entry["count"] += 1
        entry["gpas"].add(int(hit.get("gpa", "0"), 0) & ~0xFFF)
        if "before" in hit:
            entry["before"] = hit.get("before")
            entry["after"] = hit.get("after")

    lines = [f"{len(hits)} {mode} hit(s) on {target} "
             f"({start:#x}, {size} byte(s)) in {seconds}s, "
             f"from {len(by_writer)} distinct instruction(s):", ""]

    for rip, entry in sorted(by_writer.items(), key=lambda kv: -kv[1]["count"]):
        lines.append(f"  {entry['count']:>5}x  {symbolize(rip, pid)}")
        if entry["after"] is not None and entry["before"] != entry["after"]:
            lines.append(f"           wrote {entry['before']} -> {entry['after']}")
        if entry["branch"]:
            try:
                lines.append("           reached from "
                             f"{symbolize(int(entry['branch'], 0), pid)}")
            except ValueError:
                pass

    lines += ["", "Follow one hop: the writer above with the fewest hits is "
              "usually the interesting one, and svmhv_provenance on whatever "
              "IT read from is the next question."]
    return "\n".join(lines)


# ----------------------------------------------------------- what a buffer is

# "mov qword ptr [rcx], rdx" - the operand keyword is where the access width
# is, and it is the only place: the trace record's own width field says how much
# of the watched qword was inside the page, not how much the instruction moved.
# Longest first, and it matters: "word ptr" is a substring of "qword ptr", so
# checking in the obvious order calls every eight-byte store two bytes wide.
ACCESS_WIDTHS = (("xmmword", 16), ("qword", 8), ("dword", 4),
                 ("word", 2), ("byte", 1))


def _access_width(text: str) -> int:
    for keyword, width in ACCESS_WIDTHS:
        if f"{keyword} ptr" in text:
            return width
    return 0


def _name_or_address(address: int, pid: int = 0) -> str:
    """symbolize, but a failure to name something is not a failure to report it.

    symbolize reaches for export tables and PDBs, so it reads guest memory, and
    a read that fails raises. That is right for a tool whose whole job is the
    name and wrong here: losing an entire structure layout because one
    instruction could not be attributed is a bad trade.
    """
    try:
        return symbolize(address, pid)
    except (CtlError, ValueError, KeyError, IndexError):
        return f"{address:#x}"


def tool_struct(target: str, size: int = 64, pid: int = 0, seconds: int = 15,
                mode: str = "access") -> str:
    """Watch a buffer and infer what shape it is from how it is used.

    A structure with no symbols is recovered from the accesses to it: something
    that is always read four bytes at a time at +0x10 is a field, something read
    eight bytes at a time and then dereferenced is a pointer, and an offset
    nothing ever touches is padding. Doing that by hand from a trace is the most
    tedious job in reverse engineering and the most mechanical, which is a good
    reason for it not to be done by hand.

    What comes back is a candidate layout: offset, the width the instructions
    actually used, whether it is read or written and by what. It is evidence,
    not a declaration - a field only appears if something touched it while this
    was watching, so drive the code that uses the buffer during the window.
    """
    if mode not in ("write", "access"):
        return "mode must be 'write' or 'access'"

    start = resolve(target, pid)
    size = max(1, min(int(size), 4096))
    seconds = max(1, min(int(seconds), 120))

    first = start & ~0xFFF
    last = (start + size - 1) & ~0xFFF
    pages = list(range(first, last + 0x1000, 0x1000))

    ctl("trace-reset")

    # Offsets are computed from the faulting guest physical address, so the base
    # has to be physical too - and it comes from the watch install rather than
    # from a separate translate. Installing a watch necessarily resolves the
    # page, so asking twice is both redundant and a second thing that can
    # disagree: translate refused an address that read and watch both handled
    # perfectly well, and the layout came back empty with the base at zero.
    armed = []
    base_gpa = 0
    extra = hook_options(in_process=pid) if pid else []
    for page in pages:
        values = pairs(ctl("watch", f"{page:x}", mode, *extra))
        if as_int(values, "status", -1) & 0xFFFFFFFF:
            continue
        armed.append(page)
        if page == first:
            base_gpa = as_int(values, "gpa") + (start - first)

    if not armed:
        return f"could not watch any of the {len(pages)} page(s) covering {target}"
    if not base_gpa:
        for page in armed:
            try:
                ctl("unhook", f"{page:x}")
            except CtlError:
                pass
        return (f"the watch on {target} did not report a physical page, so "
                f"offsets cannot be worked out. Nothing is left armed.")

    try:
        time.sleep(seconds)
        text = ctl("trace", "200")
    finally:
        for page in armed:
            try:
                ctl("unhook", f"{page:x}")
            except CtlError:
                pass

    hits = [r for r in records(text, "trace")
            if int(r.get("type", "0"), 0) in (1, 2)]
    if not hits:
        return (f"nothing touched {target} in {seconds}s. A layout is inferred "
                f"from accesses, so something has to make them - run the code "
                f"that uses this buffer while the window is open.")

    fields: dict[int, dict] = {}
    outside = 0
    for hit in hits:
        gpa = int(hit.get("gpa", "0"), 0)
        offset = gpa - base_gpa
        if offset < 0 or offset >= size:
            outside += 1
            continue

        rip = int(hit.get("rip", "0"), 0)
        code = hit.get("code", "")
        text_of = ""
        if code:
            try:
                _, text_of, _ = disassemble_one(bytes.fromhex(code), 0, rip)
            except (ValueError, IndexError):
                text_of = ""

        entry = fields.setdefault(offset, {
            "reads": 0, "writes": 0, "width": 0, "by": {}, "last": None,
        })
        width = _access_width(text_of)
        entry["width"] = max(entry["width"], width)

        before, after = hit.get("before"), hit.get("after")

        # Direction comes from the fault, not from whether the value changed.
        # Comparing before and after is the obvious test and it is wrong: code
        # that stores the same bytes it found there is still storing, and the
        # first version of this reported a buffer of pure writes as read-only
        # because the writer happened to write a constant. NPF_WRITE is bit 1
        # of the nested-page-fault error code and says what the processor was
        # actually doing.
        if as_int(hit, "err") & 0x2:
            entry["writes"] += 1
            entry["last"] = after if after is not None else before
        else:
            entry["reads"] += 1
            if entry["last"] is None:
                entry["last"] = after or before
        entry["by"].setdefault(rip, text_of or "?")

    if not fields:
        sample = sorted({int(h.get("gpa", "0"), 0) for h in hits})[:6]
        return "\n".join([
            f"{len(hits)} hit(s), none of them inside the {size} bytes asked "
            f"about. The watch traps whole pages, so neighbours on the same "
            f"page report too - but if these look like they should have "
            f"counted, the base is what to check:",
            f"  {target} is guest physical {base_gpa:#x}",
            "  hits landed at " + ", ".join(f"{g:#x}" for g in sample)
            + (" ..." if len(sample) == 6 else ""),
        ])

    lines = [f"{target} ({start:#x}, {size} bytes) over {seconds}s: "
             f"{len(hits)} access(es), {len(fields)} offset(s) touched", ""]

    covered = 0
    previous_end = 0
    for offset in sorted(fields):
        entry = fields[offset]
        width = entry["width"] or 8
        if offset > previous_end:
            lines.append(f"  +{previous_end:#06x}  {offset - previous_end:>3} "
                         f"byte(s) untouched")
        kind = ("read/write" if entry["reads"] and entry["writes"]
                else "written" if entry["writes"] else "read")
        lines.append(f"  +{offset:#06x}  {width} byte(s)  {kind:<10}"
                     f"  {entry['reads']}r {entry['writes']}w"
                     + (f"  = {entry['last']}" if entry["last"] else ""))
        for rip, what in list(entry["by"].items())[:3]:
            lines.append(f"            {_name_or_address(rip, pid)}"
                         + (f"   {what}" if what and what != "?" else ""))
        covered += width
        previous_end = offset + width

    lines += ["",
              f"{covered} of {size} bytes accounted for. An offset that never "
              f"appears is not necessarily padding - it is only an offset "
              f"nothing touched while this was watching."]
    if outside:
        lines.append(f"{outside} hit(s) landed outside the range, on the rest "
                     f"of the page(s) the watch necessarily covers.")
    return "\n".join(lines)


# --------------------------------------------------------- dumping an image

DUMP_DIRECTORY = r"C:\lab\dumps"
DUMP_MAX_BYTES = 64 << 20


def _read_long(address: int, length: int, pid: int = 0) -> tuple[bytes, int]:
    """read_bytes in 4 KiB pieces, because the control buffer is one page.

    A page that is not resident is zero-filled and the read CARRIES ON, rather
    than stopping. Stopping is the obvious implementation and it is wrong for
    what this is used for: an image always has pages that were never touched,
    so the first of them truncated the dump - which left a file whose own
    section table described data past its end, and every tool that opened it
    called that corruption.

    Returns the bytes and how many of them were really read, so the caller can
    say how much of what it is handing over is a hole.
    """
    out = bytearray()
    have = 0
    while len(out) < length:
        want = min(4096, length - len(out))
        try:
            piece = read_bytes(address + len(out), want, pid)
        except CtlError:
            piece = b""
        if len(piece) < want:
            have += len(piece)
            out += piece + bytes(want - len(piece))
        else:
            have += want
            out += piece
    return bytes(out), have


def _find_pe_header(address: int, pid: int, back_pages: int = 512):
    """Walk back a page at a time for the MZ this address belongs to."""
    page = address & ~0xFFF
    for _ in range(back_pages):
        try:
            head = read_bytes(page, 64, pid)
        except CtlError:
            return None
        if len(head) >= 64 and head[:2] == b"MZ":
            lfanew = int.from_bytes(head[60:64], "little")
            if 0 < lfanew < 0x1000:
                try:
                    signature = read_bytes(page + lfanew, 4, pid)
                except CtlError:
                    return None
                if signature == b"PE\0\0":
                    return page, lfanew
        if page == 0:
            return None
        page -= 0x1000
    return None


def tool_dump(address: str, pid: int = 0, size: int = 0,
              name: str = "") -> str:
    """Dump the image around an address to a file, rebuilt so a disassembler loads it.

    The end of the sweep. svmhv_coverage in 'both' mode finds pages that were
    written and then executed, which is a manual map, an unpacker or a JIT and
    very little else - and then leaves you with a page number. This takes that
    address, finds the PE header it belongs to, reads the whole image out of
    guest memory and writes a file whose section table describes the memory
    layout, so IDA or any other tool opens it at the right addresses.

    Headerless is handled rather than refused: a manually mapped payload that
    erased its own MZ is exactly what this is for, so with no header found it
    dumps a flat region and says so.
    """
    start = resolve(address, pid)
    os.makedirs(DUMP_DIRECTORY, exist_ok=True)

    found = _find_pe_header(start, pid)

    if found is None:
        length = int(size) or 0x10000
        length = max(0x1000, min(length, DUMP_MAX_BYTES))
        raw, present = _read_long(start & ~0xFFF, length, pid)
        if not present:
            return f"nothing readable at {start:#x}"
        path = os.path.join(DUMP_DIRECTORY,
                            name or f"flat_{start:x}_{pid}.bin")
        with open(path, "wb") as handle:
            handle.write(raw)
        return "\n".join([
            f"no PE header above {start:#x} within 2 MiB.",
            f"dumped {len(raw):#x} bytes flat to {path} "
            f"({present:#x} of it resident, the rest zero-filled)",
            "",
            "Load it at the address it came from - there is no header to say "
            f"where that is, and it is {start & ~0xFFF:#x}. A payload with no "
            "MZ is the ordinary shape for something manually mapped by "
            "something that did not want to be found.",
        ])

    base, lfanew = found
    header, _ = _read_long(base, max(0x1000, lfanew + 0x108), pid)
    if len(header) < lfanew + 0x58:
        return f"found a PE header at {base:#x} but could not read it back"

    machine = int.from_bytes(header[lfanew + 4:lfanew + 6], "little")
    sections = int.from_bytes(header[lfanew + 6:lfanew + 8], "little")
    optional_size = int.from_bytes(header[lfanew + 20:lfanew + 22], "little")
    optional = lfanew + 24
    magic = int.from_bytes(header[optional:optional + 2], "little")
    size_of_image = int.from_bytes(header[optional + 56:optional + 60], "little")
    size_of_headers = int.from_bytes(header[optional + 60:optional + 64], "little")

    if size_of_image == 0 or size_of_image > DUMP_MAX_BYTES:
        return (f"the header at {base:#x} says SizeOfImage is {size_of_image:#x}, "
                f"which is not believable. Pass an explicit size to dump it flat.")

    raw, present = _read_long(base, size_of_image, pid)
    image = bytearray(raw)
    if present < size_of_headers:
        return f"could only read {present:#x} of {size_of_image:#x} bytes at {base:#x}"

    # Rewrite the section table so the file's raw offsets are its virtual ones.
    # A dumped image IS its memory layout; leaving the on-disk offsets in place
    # is what makes a dump open with every section at the wrong address, which
    # looks like corruption rather than like the one-line bug it is.
    table = optional + optional_size
    repaired = []
    for i in range(sections):
        entry = table + i * 40
        if entry + 40 > len(image):
            break
        section = image[entry:entry + 40]
        section_name = bytes(section[:8]).rstrip(b"\0").decode("latin-1")
        virtual_size = int.from_bytes(section[8:12], "little")
        virtual_address = int.from_bytes(section[12:16], "little")
        image[entry + 16:entry + 20] = virtual_size.to_bytes(4, "little")
        image[entry + 20:entry + 24] = virtual_address.to_bytes(4, "little")
        repaired.append((section_name, virtual_address, virtual_size))

    path = os.path.join(DUMP_DIRECTORY,
                        name or f"image_{base:x}_{pid}.bin")
    with open(path, "wb") as handle:
        handle.write(image)

    known = module_for(base, pid)
    lines = [
        f"dumped {len(image):#x} bytes from {base:#x} to {path}",
        f"  machine   {machine:#06x}  ({'x64' if machine == 0x8664 else 'not x64'})"
        f"   pe32{'+' if magic == 0x20b else ''}",
        f"  sections  {len(repaired)}, raw offsets rewritten to virtual ones",
    ]
    if present < len(image):
        lines.append(f"  resident  {present:#x} of {len(image):#x}; the rest is "
                     f"zero-filled because those pages were never touched")
    for section_name, virtual_address, virtual_size in repaired:
        lines.append(f"    {section_name:<8} {virtual_address:#010x} "
                     f"+{virtual_size:#x}")
    lines += ["", f"  declared  {known['name'] if known else 'NOTHING'}"]
    if not known:
        lines += [
            "",
            "No loaded module covers this address, which is the finding: an "
            "image the section manager placed is in the module list, and this "
            "one is not. Whatever mapped it did so by hand.",
        ]
    return "\n".join(lines)


# --------------------------------------------- coverage runs, kept and diffed

COVERAGE_PATH = r"C:\lab\coverage.json"

# 200 records a read, so this drains up to 12 800 pages before giving up.  A
# bound rather than a while-loop because the ring is being filled by a live
# guest: with a sweep armed over a busy range, "read until empty" is a race the
# reader can lose forever.
COVERAGE_MAX_READS = 64

# How many pages a diff spells out before it stops and summarises.  The whole
# reason this tool exists is that a coverage dump is too big to read, so a diff
# that prints two hundred lines has reproduced the problem it was meant to
# solve.
COVERAGE_DIFF_SHOWN = 40


def _coverage_store() -> dict:
    try:
        with open(COVERAGE_PATH, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def _coverage_now(skip: set | None = None) -> dict[str, dict]:
    """The coverage records the ring has produced since it was last read.

    `skip` is a caller-owned set of sequences already accounted for, and it is
    added to. Without it, repeated calls return the same records over and over -
    reads do not consume - which made every input in an explore run look as
    though it had reached exactly the same pages.

    Since, not in total - the reader holds a cursor, so each call consumes what
    has appeared since the previous one. That turns out to be exactly the right
    shape for this: a saved run is "what ran during that window" rather than
    "everything that has ever run", so two saves taken around an action bracket
    it, and the diff is the action's own footprint without having to subtract
    the world.

    Drained rather than read once. One read returns at most 200 records and a
    sweep over a gigabyte produces thousands, so a single read saturates - which
    made every window come back as exactly 200 pages, a number that is the shape
    of a bug rather than of an answer.

    Through _read_ring, which de-duplicates: reads are not consuming, so the
    obvious drain loop re-reads the same tail. This one got away with it because
    a dict keyed by page collapses the repeats, which is luck rather than
    design and is worth not relying on twice.
    """
    out = {}
    for row in _read_ring(COVERAGE_MAX_READS * 200, skip):
        if skip is not None:
            skip.add(row.get("seq"))
        if int(row.get("type", "0"), 0) != 7:        # SVMHV_TRACE_COVER
            continue
        gpa = int(row.get("a0", "0"), 0)
        out[f"{gpa:x}"] = {
            "rip": row.get("rip", "0"),
            "state": row.get("a1", "0"),
            "cr3": row.get("cr3", "0"),
        }
    return out


def tool_coverage_diff(action: str = "list", name: str = "",
                       against: str = "") -> str:
    """Save what a coverage sweep found under a name, and compare two of them.

    A coverage dump is hundreds of pages and almost all of them are the same
    hundreds of pages every time. The answer worth having is never the dump, it
    is the difference: run the target without doing the thing, save; do the
    thing, save; diff. What comes back is the handful of pages that ran because
    of it, which is small enough to read and is the actual question.

    save <name>  - snapshot the ring's coverage records under a name
    diff <name> against <name>  - what the second reached that the first did not
    list / drop <name>
    """
    store = _coverage_store()
    action = action.lower()

    if action == "list":
        if not store:
            return ("nothing saved. Arm a sweep with svmhv_sweep, let it run, "
                    "then save the result here under a name.")
        lines = [f"{len(store)} saved run(s):"]
        for saved, entry in sorted(store.items()):
            lines.append(f"  {saved:<24} {len(entry['pages'])} page(s)  "
                         f"{entry.get('when', '')}")
        return "\n".join(lines)

    if action == "drop":
        if name not in store:
            return f"no run called {name!r}"
        del store[name]
    elif action == "save":
        if not name:
            return "save needs a name"
        found = _coverage_now()
        if not found:
            return ("there are no coverage records in the ring to save. Arm a "
                    "sweep with svmhv_sweep first; a sweep reports each page "
                    "once, so read it before the ring laps.")
        store[name] = {
            "pages": found,
            "when": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
    elif action == "diff":
        if name not in store or against not in store:
            missing = [n for n in (name, against) if n not in store]
            return f"no saved run(s) called {', '.join(repr(m) for m in missing)}"
        first = store[against]["pages"]
        second = store[name]["pages"]
        new = {k: v for k, v in second.items() if k not in first}
        gone = [k for k in first if k not in second]

        lines = [f"{name} against {against}: "
                 f"{len(second)} vs {len(first)} page(s)", ""]
        if not new:
            lines.append(f"{name} reached nothing {against} did not.")
        else:
            # Grouped by what jumped into them, and the written-then-executed
            # ones first and separately.  Two hundred page numbers is the
            # problem this tool exists to solve, not the answer to it: the
            # signal is which few callers account for them and which pages
            # nothing declared.
            manual = [(p, e) for p, e in new.items()
                      if int(e["state"], 0) & 0x04]
            ordinary = [(p, e) for p, e in new.items()
                        if not int(e["state"], 0) & 0x04]

            lines.append(f"{len(new)} page(s) only {name} reached"
                         + (f", {len(manual)} of them WRITTEN THEN EXECUTED"
                            if manual else ""))

            if manual:
                lines += ["", "written then executed - a manual map, an "
                          "unpacker or a JIT, and nothing else looks like this:"]
                for page, entry in sorted(manual, key=lambda kv: int(kv[0], 16)):
                    lines.append(f"  {int(page, 16):#014x}  entered from "
                                 f"{symbolize(int(entry['rip'], 0))}")

            by_source: dict[int, list[int]] = {}
            for page, entry in ordinary:
                by_source.setdefault(int(entry["rip"], 0), []).append(
                    int(page, 16))

            if by_source:
                lines += ["", f"the other {len(ordinary)} page(s), by what "
                          f"entered them:"]
                ranked = sorted(by_source.items(), key=lambda kv: -len(kv[1]))
                for rip, found in ranked[:COVERAGE_DIFF_SHOWN]:
                    where = symbolize(rip)
                    if len(found) == 1:
                        lines.append(f"  {found[0]:#014x}  from {where}")
                    else:
                        lines.append(f"  {len(found):>4} page(s) from {where}"
                                     f"   ({min(found):#x} .. {max(found):#x})")
                if len(ranked) > COVERAGE_DIFF_SHOWN:
                    lines.append(f"  ... and {len(ranked) - COVERAGE_DIFF_SHOWN} "
                                 f"more source(s)")
        if gone:
            lines += ["", f"{len(gone)} page(s) appeared in {against}'s window "
                      f"and not in {name}'s. A sweep reports each page once "
                      f"ever, so this is not code that stopped running - it is "
                      f"code that had already been reached by the time {name}'s "
                      f"window opened."]
        return "\n".join(lines)
    else:
        return "action must be save, diff, list or drop"

    try:
        with open(COVERAGE_PATH, "w", encoding="utf-8") as handle:
            json.dump(store, handle, indent=1, sort_keys=True)
    except OSError as error:
        return f"could not write {COVERAGE_PATH}: {error}"
    return (f"saved {len(store[name]['pages'])} page(s) as {name!r}"
            if action == "save" else f"dropped {name!r}")


# ------------------------------------------------------------------- IBS

def tool_ibs(interval: int = 0, show: int = 30) -> str:
    """Sample what code touches memory, without instrumenting any of it.

    Every other instrument here costs an exit per event, so aiming one needs an
    address you do not have yet. Instruction-Based Sampling comes from the other
    end: the processor tags one micro-op in every N and writes down the
    instruction AND the linear address it touched. No hooks, no watchpoints, and
    a cost set by the interval rather than by how busy the code is - which makes
    "what memory does this thing touch at all" a question with an answer.

    interval 0 reads back what has been collected without changing the arming.
    """
    arguments = ["ibs", str(int(interval))]
    values = pairs(ctl(*arguments))
    status = as_int(values, "status", 0) & 0xFFFFFFFF

    if status == 0xC00000BB:
        return ("this processor does not expose IBS, so nothing was armed. "
                "It is optional on AMD and a hypervisor above this one is free "
                "not to pass it through - which is the usual reason inside a "
                "VM. The driver logs what CPUID said at load.")
    if status:
        return f"ibs failed: {status:#010x}"

    armed = as_int(values, "ibs_interval")
    total = as_int(values, "ibs_samples")

    lines = [f"IBS: {'sampling 1 in ' + str(armed) + ' micro-ops' if armed else 'off'}"
             f", {total:,} sample(s) taken"]

    if interval and armed:
        lines += ["", "Samples land in the trace ring as they ripen. Give it a "
                  "moment and read this again, or svmhv_trace."]
        return "\n".join(lines)

    hits = [r for r in records(ctl("trace", str(min(max(show, 1), 200))), "trace")
            if int(r.get("type", "0"), 0) == 8]      # SVMHV_TRACE_IBS
    if not hits:
        lines += ["", "no samples in the ring yet"]
        return "\n".join(lines)

    # Grouped by instruction, like the provenance report and for the same
    # reason: a sampling stream is repetitive by construction and the shape is
    # the answer, not the individual hits.
    by_rip: dict[int, dict] = {}
    for hit in hits:
        rip = int(hit.get("rip", "0"), 0)
        entry = by_rip.setdefault(rip, {"count": 0, "addresses": set(),
                                        "stores": 0})
        entry["count"] += 1
        address = int(hit.get("a0", "0"), 0)
        if address:
            entry["addresses"].add(address)
        if int(hit.get("a2", "0"), 0):
            entry["stores"] += 1

    lines += ["", f"{len(hits)} sample(s) from {len(by_rip)} instruction(s):"]
    for rip, entry in sorted(by_rip.items(), key=lambda kv: -kv[1]["count"]):
        kind = ("stores" if entry["stores"] == entry["count"]
                else "loads" if entry["stores"] == 0 else "loads and stores")
        lines.append(f"  {entry['count']:>4}x  {symbolize(rip)}")
        if entry["addresses"]:
            shown = sorted(entry["addresses"])[:4]
            lines.append(f"        {kind} touching " +
                         ", ".join(f"{a:#x}" for a in shown) +
                         (f" and {len(entry['addresses']) - 4} more"
                          if len(entry["addresses"]) > 4 else ""))
    return "\n".join(lines)


TOOLS = [
    {
        "name": "svmhv_service",
        "description":
            "Load, unload or reload the hypervisor driver, or report its state. "
            "The only way to put a rebuilt driver into service without "
            "rebooting the guest - PowerShell Direct drops while the "
            "hypervisor is loaded and does not recover until reboot, which "
            "throws away all the state an investigation has built up. Use "
            "reload after replacing svmhv.sys on disk.",
        "inputSchema": {
            "type": "object",
            "properties": {"action": {
                "type": "string", "enum": ["status", "load", "unload", "reload"],
                "description": "default status"}},
        },
        "handler": lambda a: tool_service(a.get("action", "status")),
    },
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
        "name": "svmhv_modules",
        "description":
            "Every loaded kernel module with its base and size. The starting "
            "point for anything else: with a base, svmhv_exports turns names "
            "into addresses and svmhv_explain makes an address legible.",
        "inputSchema": {
            "type": "object",
            "properties": {"filter": {
                "type": "string",
                "description": "substring of the module name, e.g. 'ndis'"}},
        },
        "handler": lambda a: tool_modules(a.get("filter", "")),
    },
    {
        "name": "svmhv_pdb_info",
        "description":
            "Which PDB a module was built with - name, GUID and age - read out "
            "of its debug directory in memory, with no network and no symbol "
            "file needed. Returns the exact symbol server URL. The GUID is the "
            "point: a PDB matched by name alone is for a different build and "
            "will answer confidently and wrongly.",
        "inputSchema": {
            "type": "object",
            "properties": {"module": {"type": "string"}},
            "required": ["module"],
        },
        "handler": lambda a: tool_pdb_info(a["module"]),
    },
    {
        "name": "svmhv_symbols_load",
        "description":
            "Parse a PDB and attach its symbols to a loaded module. This is "
            "what gets names for functions a module does not export - the "
            "Mi*, Ki* and Ob* internals of the kernel, and everything in a "
            "driver, which usually exports nothing at all. Once loaded these "
            "are used everywhere an address is rendered: disassembly, trace "
            "callers, cross-references.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "module": {"type": "string"},
                "path": {"type": "string",
                         "description": "path to a .pdb in the guest; omit to "
                                        "fetch it from the symbol server"},
            },
            "required": ["module"],
        },
        "handler": lambda a: tool_symbols_load(a["module"], a.get("path", "")),
    },
    {
        "name": "svmhv_symbols_auto",
        "description":
            "Turn automatic symbol download on or off. On by default: the "
            "first time anything needs a name in a module, its PDB is fetched "
            "from the Microsoft symbol server and cached, once per module per "
            "session. Turn it off to keep the guest from making outbound "
            "connections, or when working offline - exports still work either "
            "way.",
        "inputSchema": {
            "type": "object",
            "properties": {"enabled": {"type": "boolean"}},
        },
        "handler": lambda a: tool_symbols_auto(a.get("enabled", True)),
    },
    {
        "name": "svmhv_exports",
        "description":
            "Exported symbols of a loaded module, parsed out of its PE headers "
            "in memory - no PDB, no symbol server and no network needed. For "
            "the kernel that is several thousand functions including every Nt* "
            "entry point. Narrow it with 'contains'.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "module": {"type": "string",
                           "description": "module name; 'nt' means the kernel"},
                "contains": {"type": "string",
                             "description": "only names containing this"},
            },
            "required": ["module"],
        },
        "handler": lambda a: tool_exports(a["module"], a.get("contains", "")),
    },
    {
        "name": "svmhv_symbol",
        "description":
            "Resolve 'nt!NtCreateFile' or 'module!Export+0x20' to an address. "
            "Every tool that takes a target accepts this form directly, so this "
            "is mostly for checking what one resolves to.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string",
                                    "description": "module!symbol[+offset]"}},
            "required": ["name"],
        },
        "handler": lambda a: tool_symbol(a["name"]),
    },
    {
        "name": "svmhv_verify",
        "description":
            "Compare a module's executable sections against the file it was "
            "loaded from. This is how you find SOMEBODY ELSE'S hooks - an "
            "inline detour or a patched prologue is a difference between what "
            "is running and what shipped, and nothing that only reads memory "
            "can see it. Relocations are filtered out, so what is reported is "
            "a real difference.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "module": {"type": "string"},
                "limit": {"type": "integer", "description": "runs to show"},
            },
            "required": ["module"],
        },
        "handler": lambda a: tool_verify(a["module"], a.get("limit", 24)),
    },
    {
        "name": "svmhv_syscalls",
        "description":
            "The system service table as index -> function, symbolized. A "
            "syscall number is how a lot of code reaches the kernel without "
            "touching a named import, so knowing what index 0x55 is on this "
            "build is often the whole question. Filter with 'contains'.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "contains": {"type": "string",
                             "description": "only services whose name matches"},
                "limit": {"type": "integer"},
            },
        },
        "handler": lambda a: tool_syscalls(a.get("contains", ""),
                                           a.get("limit", 60)),
    },
    {
        "name": "svmhv_note",
        "description":
            "Record what you worked out about an address, or read it back. "
            "Reverse engineering is accumulated conclusions - this field is "
            "the flags, this branch is the check - and none of it is "
            "recoverable from the binary twice. Notes are keyed by symbol "
            "where one is known, so they survive the reboot that moves every "
            "address. Call with no text to read; with 'contains' to search.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string",
                            "description": "hex address or module!symbol"},
                "text": {"type": "string",
                         "description": "what you concluded; omit to read"},
                "pid": {"type": "integer",
                        "description": "the process a user-mode address is in. "
                                       "Needed for code no module claims: those "
                                       "notes are keyed on a hash of the bytes, "
                                       "so the bytes have to be readable"},
                "contains": {"type": "string",
                             "description": "search existing notes"},
            },
        },
        "handler": lambda a: tool_note(a.get("address", ""), a.get("text", ""),
                                       a.get("contains", ""), a.get("pid", 0)),
    },
    {
        "name": "svmhv_processes",
        "description":
            "Every running process with its pid, thread count and PEB address. "
            "The starting point for reverse engineering an .exe: pick the "
            "process here, then svmhv_process_modules for where its image is "
            "loaded, then read, disassemble or watch inside it.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string",
                                    "description": "exact image name filter"}},
        },
        "handler": lambda a: tool_processes(a.get("name", "")),
    },
    {
        "name": "svmhv_process_modules",
        "description":
            "The modules loaded in one process, walked out of its PEB with "
            "cross-process reads - the executable first, then its DLLs, each "
            "with base and size. This is how you find where an .exe actually "
            "landed under ASLR.",
        "inputSchema": {
            "type": "object",
            "properties": {"pid": {"type": "integer"}},
            "required": ["pid"],
        },
        "handler": lambda a: tool_process_modules(a["pid"]),
    },
    {
        "name": "svmhv_xrefs",
        "description":
            "Who reaches an address: direct calls (its callers), jumps (tail "
            "calls and thunks) and eight-byte pointers in data (dispatch "
            "tables, callback registrations, imports). svmhv_disassemble "
            "follows calls outwards; this follows them inwards. A function "
            "reached only through a computed call leaves nothing to find, and "
            "that is reported rather than hidden.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string",
                           "description": "hex address or module!symbol"},
                "module": {"type": "string",
                           "description": "module to sweep; defaults to the "
                                          "one containing the target"},
                "limit": {"type": "integer", "description": "default 40"},
            },
            "required": ["target"],
        },
        "handler": lambda a: tool_xrefs(a["target"], a.get("module", ""),
                                        a.get("limit", 40)),
    },
    {
        "name": "svmhv_disassemble",
        "description":
            "Disassemble at an address or symbol, with every call and jump "
            "target resolved to module!symbol and the calls summarised at the "
            "end. Following the calls out of a function is most of how you work "
            "out what it does, and it is the one thing a byte dump cannot "
            "support. Covers the integer subset a compiler emits; anything "
            "unrecognised is shown as db rather than guessed at.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string",
                           "description": "hex address or module!symbol"},
                "count": {"type": "integer",
                          "description": "instructions, 1-200 (default 24)"},
                "pid": {"type": "integer",
                        "description": "disassemble in this process"},
            },
            "required": ["target"],
        },
        "handler": lambda a: tool_disassemble(a["target"], a.get("count", 24),
                                              a.get("pid", 0)),
    },
    {
        "name": "svmhv_explain",
        "description":
            "Everything known about one address in a single call: which module "
            "it is in, the nearest exported symbol, the first bytes, where the "
            "instruction boundaries fall, the smallest safe hook prologue, and "
            "whether it is already hooked. The right first call for any address "
            "you do not recognise.",
        "inputSchema": {
            "type": "object",
            "properties": {"target": {
                "type": "string",
                "description": "hex address or module!symbol"}},
            "required": ["target"],
        },
        "handler": lambda a: tool_explain(a["target"]),
    },
    {
        "name": "svmhv_driver",
        "description":
            "A driver's DRIVER_OBJECT: its image range, DriverEntry, Unload, "
            "and the IRP dispatch table with every handler symbolized. This is "
            "the closest thing a .sys has to a symbol table - almost none of "
            "them export anything, but every one has to publish its entry "
            "points here, and those are exactly the functions worth hooking. "
            "Start here when reverse engineering a driver.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {
                "type": "string",
                "description": "driver name, e.g. 'null' for \\Driver\\Null"}},
            "required": ["name"],
        },
        "handler": lambda a: tool_driver(a["name"]),
    },
    {
        "name": "svmhv_devices",
        "description":
            "The device objects a driver owns, with their names, device type, "
            "flags, extension pointer, and every filter attached above them. "
            "The dispatch table says how a driver can be entered; this says how "
            "anything outside the kernel reaches it in the first place - and a "
            "filter driver becomes visible here and nowhere else. A driver with "
            "no device object cannot be opened by name at all.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {
                "type": "string",
                "description": "driver name, e.g. 'null' for \\Driver\\Null"}},
            "required": ["name"],
        },
        "handler": lambda a: tool_devices(a["name"]),
    },
    {
        "name": "svmhv_symlinks",
        "description":
            "Every symbolic link in \\GLOBAL?? and what it points at. This is "
            "the missing half of a device name: an application opens \\\\.\\Foo, "
            "which is a link, and the link is the only record of which device "
            "that was. Filter by substring to work backwards from a device name "
            "to the string a program would have used to open it.",
        "inputSchema": {
            "type": "object",
            "properties": {"contains": {
                "type": "string",
                "description": "only links whose name or target contains this"}},
        },
        "handler": lambda a: tool_symlinks(a.get("contains", "")),
    },
    {
        "name": "svmhv_ioctl",
        "description":
            "Decode one IOCTL control code into its device type, function "
            "number, transfer method and access. The method is the part worth "
            "knowing: METHOD_NEITHER means the driver is handed the caller's "
            "own user-mode pointers and has to probe them itself, which is "
            "where a large share of driver vulnerabilities live.",
        "inputSchema": {
            "type": "object",
            "properties": {"code": {
                "type": "string",
                "description": "the control code, e.g. '0x22e004'"}},
            "required": ["code"],
        },
        "handler": lambda a: tool_ioctl(a["code"]),
    },
    {
        "name": "svmhv_ioctls",
        "description":
            "Recover the control codes a driver handles by reading its "
            "IRP_MJ_DEVICE_CONTROL dispatcher. This is the interface a .sys "
            "exposes to user mode and nothing publishes it - no table, no "
            "export, and the header that defined the codes is not on the "
            "machine. The dispatcher compares against every one of them, so "
            "they are recovered from the instruction stream. Candidates, not "
            "proof: confirm by sending one or by hooking the handler.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {
                "type": "string", "description": "driver name"}},
            "required": ["name"],
        },
        "handler": lambda a: tool_ioctls(a["name"]),
    },
    {
        "name": "svmhv_watch_ioctls",
        "description":
            "Hook a driver's IRP_MJ_DEVICE_CONTROL so every request records the "
            "control code, buffer sizes and device it carries. This is the "
            "other half of svmhv_ioctls: that one recovers the codes a driver "
            "can handle by reading the dispatcher, this one shows which are "
            "really sent and by whom. Read the results with svmhv_trace, and "
            "svmhv_unhook when done.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "driver name"},
                "prolog_length": {"type": "integer", "description":
                    "bytes of prologue that may be overwritten; decoded "
                    "automatically when omitted"},
            },
            "required": ["name"],
        },
        "handler": lambda a: tool_watch_ioctls(
            a["name"], int(a["prolog_length"]) if a.get("prolog_length") else None),
    },
    {
        "name": "svmhv_callbacks",
        "description":
            "Every driver registered for process creation, thread creation, "
            "image load or registry notifications, named by the module each "
            "routine lives in. This is what else is watching: a .sys with no "
            "device object and no IOCTL interface still runs on every process "
            "creation if it registered for one, and the registration is the "
            "only trace of that. Anti-cheat and endpoint protection show up "
            "here.",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": lambda a: tool_callbacks(),
    },
    {
        "name": "svmhv_sections",
        "description":
            "A module's PE sections with addresses, sizes and rwx flags. Tells "
            "you where the code is, where the data is, and what is writable - "
            "which is where to point a watch.",
        "inputSchema": {
            "type": "object",
            "properties": {"module": {"type": "string"}},
            "required": ["module"],
        },
        "handler": lambda a: tool_sections(a["module"]),
    },
    {
        "name": "svmhv_strings",
        "description":
            "ASCII and UTF-16 strings from a module's data sections. The "
            "classic first look at a binary: for a driver that exports nothing "
            "and whose functions have no names, the registry paths, device "
            "names and error text are often the only thing that says what it "
            "is for. Filter with 'contains'.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "module": {"type": "string"},
                "minimum": {"type": "integer",
                            "description": "shortest string to report (default 6)"},
                "contains": {"type": "string",
                             "description": "only strings containing this"},
                "limit": {"type": "integer", "description": "default 200"},
            },
            "required": ["module"],
        },
        "handler": lambda a: tool_strings(a["module"], a.get("minimum", 6),
                                          a.get("limit", 200),
                                          a.get("contains", "")),
    },
    {
        "name": "svmhv_search",
        "description":
            "Find a byte pattern, with '??' matching any byte. Sweep a module, "
            "or a start and size - and in another process with pid. The "
            "wildcards are what make it usable on code, where immediates and "
            "relative offsets move between builds but the surrounding "
            "instructions do not. Matches are reported with the nearest symbol.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string",
                            "description": "hex bytes, e.g. '48 8b ?? ?? c3'"},
                "module": {"type": "string", "description": "module to sweep"},
                "start": {"type": "string", "description": "or an address"},
                "size": {"type": "integer", "description": "with a length"},
                "pid": {"type": "integer", "description": "search this process"},
                "limit": {"type": "integer", "description": "default 40"},
            },
            "required": ["pattern"],
        },
        "handler": lambda a: tool_search(a["pattern"], a.get("module", ""),
                                         a.get("start", ""), a.get("size", 0),
                                         a.get("pid", 0), a.get("limit", 40)),
    },
    {
        "name": "svmhv_imports",
        "description":
            "What a module calls, by DLL and function, from its import table. "
            "For a driver with no exports this is the best available profile of "
            "what it does - a driver importing ZwCreateFile and IoCreateDevice "
            "is doing something very different from one importing only Ke* "
            "synchronisation.",
        "inputSchema": {
            "type": "object",
            "properties": {"module": {"type": "string",
                                      "description": "module name"}},
            "required": ["module"],
        },
        "handler": lambda a: tool_imports(a["module"]),
    },
    {
        "name": "svmhv_read",
        "description":
            "Read guest memory and get back a hex dump and the raw bytes. With "
            "no pid this is kernel space; with a pid the driver attaches to that "
            "process from below, so it reaches memory no handle would open and "
            "the target sees nothing. A short read is normal and successful - the "
            "byte count says how far it got before hitting an unmapped page.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string",
                            "description": "hex virtual address"},
                "length": {"type": "integer",
                           "description": "bytes to read, 1-4096 (default 64)"},
                "pid": {"type": "integer",
                        "description": "read in this process; omit for kernel"},
            },
            "required": ["address"],
        },
        "handler": lambda a: tool_read(a["address"], a.get("length", 64),
                                       a.get("pid", 0)),
    },
    {
        "name": "svmhv_read_physical",
        "description":
            "Read guest physical memory directly, consulting no page tables. "
            "Sees pages that no virtual address currently describes, and is the "
            "only way to observe what the nested page tables actually present - "
            "a hooked page read this way shows the original bytes, not the patch. "
            "One page maximum per call, and it may not cross a page boundary.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "gpa": {"type": "string",
                        "description": "hex guest physical address"},
                "length": {"type": "integer",
                           "description": "bytes to read, 1-4096 (default 64)"},
            },
            "required": ["gpa"],
        },
        "handler": lambda a: tool_read_physical(a["gpa"], a.get("length", 64)),
    },
    {
        "name": "svmhv_write_physical",
        "description":
            "Write guest physical memory directly, consulting no page tables. "
            "There is no safety net: it goes where it is pointed, with no "
            "process, no page protection and no owner to consult - a page "
            "mapped read-only everywhere is still writable from here, because "
            "the tables saying otherwise are themselves just memory. One page "
            "maximum, and it may not cross a page boundary.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "gpa": {"type": "string",
                        "description": "hex guest physical address"},
                "hex_bytes": {"type": "string",
                              "description": "bytes to write, as hex"},
            },
            "required": ["gpa", "hex_bytes"],
        },
        "handler": lambda a: tool_write_physical(a["gpa"], a["hex_bytes"]),
    },
    {
        "name": "svmhv_translate",
        "description":
            "Translate a virtual address to a guest physical one, optionally in "
            "another process. This is what makes the two physical calls usable: "
            "they take an address nothing else in the interface produces. It is "
            "also how to tell whether a page moved - a physical address that "
            "changes under a virtual one invalidates anything keyed on the "
            "physical, hooks included.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "hex address"},
                "pid": {"type": "integer",
                        "description": "process id for a user address"},
            },
            "required": ["address"],
        },
        "handler": lambda a: tool_translate(a["address"], a.get("pid", 0)),
    },
    {
        "name": "svmhv_write",
        "description":
            "Write guest memory, in kernel space or in a named process. The "
            "counterpart to svmhv_read and the cheapest way to test what a byte "
            "controls; unlike a hook it leaves no trampoline and no shadow page. "
            "Take a checkpoint first - there is no undo.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string",
                            "description": "hex virtual address"},
                "hex_bytes": {"type": "string",
                              "description": "bytes to write, as hex"},
                "pid": {"type": "integer",
                        "description": "write in this process; omit for kernel"},
            },
            "required": ["address", "hex_bytes"],
        },
        "handler": lambda a: tool_write(a["address"], a["hex_bytes"],
                                        a.get("pid", 0)),
    },
    {
        "name": "svmhv_trace_summary",
        "description":
            "The trace ring collapsed instead of transcribed: which processes "
            "hit each hook, who called it with the return addresses "
            "symbolized, which processors, and which argument values are "
            "distinct. A hot hook produces thousands of near-identical records "
            "and reading them one by one buries the answer in the evidence - "
            "start here, then use svmhv_trace for the records behind anything "
            "that looks interesting.",
        "inputSchema": {
            "type": "object",
            "properties": {"count": {
                "type": "integer",
                "description": "how many newest records to summarise, 1-200"}},
        },
        "handler": lambda a: tool_trace_summary(int(a.get("count", 200))),
    },
    {
        "name": "svmhv_sweep",
        "description":
            "Mark every guest physical page in a range non-executable (or "
            "read-only) and record the first time each one runs, or is "
            "written. This is the thing a hypervisor can do that a debugger "
            "cannot: a module list describes code somebody declared, and says "
            "nothing about code that was mapped by hand and never written to "
            "disk. A page faults once and is then granted for good, so the "
            "cost is one exit per distinct page ever touched. Needs one table "
            "page per 2 MiB, and the pool covers 8 GiB in one arming.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "mode": {"type": "string",
                         "enum": ["exec", "write", "both", "off"],
                         "description":
                             "exec finds code that has run; write finds pages "
                             "something modified; BOTH is the one that finds "
                             "manually mapped code, because it remembers the "
                             "order - a page written and then executed had its "
                             "code arrive after its mapping, which a normally "
                             "loaded image never does"},
                "base": {"type": "string",
                         "description": "guest physical base, hex"},
                "size": {"type": "string", "description": "bytes, hex"},
            },
        },
        "handler": lambda a: tool_sweep(a.get("mode", "exec"),
                                        a.get("base", "0"),
                                        a.get("size", "0")),
    },
    {
        "name": "svmhv_coverage",
        "description":
            "What a sweep found, with the pages no loaded module accounts for "
            "listed first - those are the manual maps, the JIT pages and the "
            "data somebody jumped to.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer"},
                "unknown_only": {"type": "boolean",
                                 "description": "false to also list pages "
                                                "inside known modules"},
            },
        },
        "handler": lambda a: tool_coverage(int(a.get("limit", 400)),
                                           a.get("unknown_only", True)),
    },
    {
        "name": "svmhv_watch_msr",
        "description":
            "Trap a model-specific register and record every read and write: "
            "which register, the value, and where from. The MSRPM has been "
            "there since the driver could hide EFER; this is the first way to "
            "ask it for anything. Use it to see a driver program hardware, or "
            "to catch code probing IA32_FEATURE_CONTROL and friends looking "
            "for a hypervisor.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "msr": {"type": "string",
                        "description": "MSR number in hex, e.g. c0000080"},
                "enabled": {"type": "boolean",
                            "description": "false to stop watching"},
            },
            "required": ["msr"],
        },
        "handler": lambda a: tool_watch_msr(a["msr"], a.get("enabled", True)),
    },
    {
        "name": "svmhv_watch_io",
        "description":
            "Trap an I/O port and record every IN and OUT - port, value, "
            "width and where from. The instruction is not emulated: the port "
            "is unarmed for exactly one single step and re-armed afterwards, "
            "so string and repeated forms behave as they would unwatched.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "port": {"type": "string",
                         "description": "port number in hex, e.g. 3f8"},
                "enabled": {"type": "boolean",
                            "description": "false to stop watching"},
            },
            "required": ["port"],
        },
        "handler": lambda a: tool_watch_io(a["port"], a.get("enabled", True)),
    },
    {
        "name": "svmhv_step",
        "description":
            "Single-step the guest for N instructions, recording one trace "
            "record each: RIP, RFLAGS as the guest sees it, and the "
            "instruction bytes. AMD has no monitor trap flag, so this is "
            "RFLAGS.TF and #DB - but PUSHF and POPF are intercepted for the "
            "duration, so the guest reads back the trap flag it set rather "
            "than ours. The step is armed on the processor that issues it and "
            "starts at the next instruction, so it steps the client, not a "
            "target you name.",
        "inputSchema": {
            "type": "object",
            "properties": {"count": {"type": "integer",
                                     "description": "instructions, 1-4096"}},
        },
        "handler": lambda a: tool_step(int(a.get("count", 16))),
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
                "in_process": {"type": "integer", "description":
                    "the target is a USER-mode address in this process. Not "
                    "the same as pid, which narrows recording once a hook is "
                    "placed; this says which address space the target is in. "
                    "The page must be private to the process - an image page "
                    "is shared with every process that has it mapped, and a "
                    "stub exists in only one of them, so the driver refuses "
                    "those. A user-mode hook records the four argument "
                    "registers and the address space and nothing that needs "
                    "guest context: no captures, no filters, no process name."},
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
                    "(OBJECT_ATTRIBUTES* -> its ObjectName), bytes:LEN, or irp "
                    "(IRP* -> the control code, buffer sizes and device it "
                    "carries). Only taken at IRQL <= APC_LEVEL and under SEH"},
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
        # in_process belongs in this list and was missing from it: hook_options
        # has always known how to send it, and tool_hook_trace has always read
        # it, but the handler dropped it on the floor - which nobody could see
        # while a user-mode execution hook was refused by the driver anyway.
        # Without it the target address is resolved, and installed, against
        # whichever address space the worker happened to be in.
        "handler": lambda a: tool_hook_trace(
            a["target"], (int(a["prolog_length"]) if a.get("prolog_length") else None),
            **{k: a[k] for k in (
                "process", "pid", "caller_base", "caller_size", "filter_expr",
                "capture", "capture2", "spoof", "spoof2", "block",
                "capture_return", "capture_stack", "in_process") if k in a}),
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
                    "(OBJECT_ATTRIBUTES* -> its ObjectName), bytes:LEN, or irp "
                    "(IRP* -> the control code, buffer sizes and device it "
                    "carries). Only taken at IRQL <= APC_LEVEL and under SEH"},
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
            a["target"], a["detour"], (int(a["prolog_length"]) if a.get("prolog_length") else None),
            **{k: a[k] for k in (
                "process", "pid", "caller_base", "caller_size", "filter_expr",
                "capture", "capture2", "spoof", "spoof2", "block") if k in a}),
    },
    {
        "name": "svmhv_assemble",
        "description":
            "Assemble Intel-syntax x86-64 and show what it encodes to, without "
            "installing anything. The listing is produced by disassembling the "
            "result, so it is what will actually execute rather than a repeat "
            "of the input; if the two decoders disagree the assembly is "
            "refused. Supports mov/lea, add/sub/and/or/xor/cmp/test, push/pop, "
            "call/jmp/jcc with labels, and ret - the subset a hook stub needs. "
            "Use it to check a stub before svmhv_hook_shellcode runs it in "
            "kernel mode.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source": {"type": "string",
                           "description": "Intel syntax, one instruction per "
                                          "line; 'label:' on its own line, "
                                          "';' starts a comment"},
                "base": {"type": "string",
                         "description": "address to assemble at, for the "
                                        "listing (default 0)"},
            },
            "required": ["source"],
        },
        "handler": lambda a: tool_assemble(a["source"], a.get("base", "0")),
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
                "asm": {"type": "string", "description":
                    "Intel-syntax source, assembled and round-trip checked "
                    "before install; use this instead of shellcode_hex"},
                "shellcode_hex": {"type": "string", "description":
                    "raw bytes, if you already have them"},
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
                    "(OBJECT_ATTRIBUTES* -> its ObjectName), bytes:LEN, or irp "
                    "(IRP* -> the control code, buffer sizes and device it "
                    "carries). Only taken at IRQL <= APC_LEVEL and under SEH"},
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
        "handler": lambda a: tool_hook_shellcode(
            a["target"], a.get("shellcode_hex", ""), a.get("asm", ""),
            (int(a["prolog_length"]) if a.get("prolog_length") else None),
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
            "data you expect to be touched rarely.\n\n"
            "Pass in_process to watch a USER-mode address - the only way to "
            "instrument an .exe, since the address is meaningless without a "
            "process to translate it in. The watch is on the physical page, so "
            "a page shared between processes fires for all of them.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "mode": {"type": "string", "enum": ["write", "access"]},
                "in_process": {
                    "type": "integer",
                    "description": "pid owning a user-mode target; required "
                                   "for one, omit for a kernel address"},
            },
            "required": ["target"],
        },
        "handler": lambda a: tool_watch(a["target"], a.get("mode", "write"),
                                        in_process=a.get("in_process")),
    },
    {
        "name": "svmhv_hook_many",
        "description":
            "Trace every export in a module whose name matches, in one call - "
            "'every Nt* entry point' or 'every FsRtl* function'. Each target "
            "gets its own prologue decoded; one that cannot be decoded safely "
            "is skipped and named rather than hooked with a guessed length. "
            "Read the result with svmhv_trace_summary, and take them all off "
            "with svmhv_unhook_all.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "module": {"type": "string", "description": "'nt' for the kernel"},
                "contains": {"type": "string",
                             "description": "substring of the export name"},
                "limit": {"type": "integer",
                          "description": "how many at most, 1-64 (default 24)"},
                "process": {"type": "string",
                            "description": "only record calls from this image"},
            },
            "required": ["module", "contains"],
        },
        "handler": lambda a: tool_hook_many(
            a["module"], a["contains"], a.get("limit", 24),
            process=a.get("process")),
    },
    {
        "name": "svmhv_watch_range",
        "description":
            "Watch every page a range of memory touches, as one group - for a "
            "structure or a buffer, where working out which pages it spans by "
            "hand is a way to miss the edges. Each page is trapped whole, so "
            "accesses to anything sharing those pages are reported too.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string",
                           "description": "hex address or module!symbol"},
                "size": {"type": "integer", "description": "bytes to cover"},
                "mode": {"type": "string", "enum": ["write", "access"]},
            },
            "required": ["target", "size"],
        },
        "handler": lambda a: tool_watch_range(a["target"], a["size"],
                                              a.get("mode", "write")),
    },
    {
        "name": "svmhv_unhook_all",
        "description":
            "Remove every armed hook and watch in one call. The panic button: "
            "use it when something is flooding the trace ring or slowing the "
            "machine, which is exactly when removing them one at a time is "
            "painful.",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": lambda a: tool_unhook_all(),
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

TOOLS += [
    {
        "name": "svmhv_snapshot",
        "description":
            "Take a copy-on-write snapshot of a range of guest memory, or put "
            "it back. This is what makes an experiment repeatable: snapshot the "
            "memory a routine works on, let it run, look at what changed, "
            "restore, run it again with one input different. It restores MEMORY "
            "IN ONE RANGE and nothing else - not registers, not devices, not "
            "pages outside the range - and a range another processor is using "
            "gets restored underneath it. Point it at memory whose owner you "
            "know. Take one before svmhv_call or svmhv_write.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string",
                           "enum": ["take", "restore", "release", "query"],
                           "description": "default query"},
                "target": {"type": "string",
                           "description": "hex address or module!symbol; take only"},
                "size": {"type": "integer",
                         "description": "bytes, up to 64 MiB; take only"},
                "pid": {"type": "integer",
                        "description": "process owning a user-mode range"},
                "store_pages": {"type": "integer",
                                "description": "how many pages may be modified "
                                               "before it overflows; 0 = one "
                                               "per page of the range"},
            },
        },
        "handler": lambda a: tool_snapshot(
            a.get("action", "query"), a.get("target", ""), a.get("size", 0),
            a.get("pid", 0), a.get("store_pages", 0)),
    },
    {
        "name": "svmhv_call",
        "description":
            "Call a function with arguments of your choosing and report what it "
            "returns and how long it took. The question a disassembly cannot "
            "answer - everything else here waits for the guest to call "
            "something, this calls it. DANGEROUS: it runs the function, and a "
            "target called with arguments it was not written for takes the "
            "guest down with no exception to catch. Kernel addresses only. "
            "Snapshot anything it will write to first.",
        "inputSchema": {
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string",
                           "description": "hex address or module!symbol"},
                "args": {"type": "array", "items": {"type": "string"},
                         "description": "up to eight, hex or module!symbol"},
                "pid": {"type": "integer",
                        "description": "make the call in this address space, "
                                       "so user pointers in the arguments mean "
                                       "something"},
                "steps": {"type": "integer",
                          "description": "single-step this many instructions "
                                         "around the call into the trace ring, "
                                         "so svmhv_reverse can walk it"},
            },
        },
        "handler": lambda a: tool_call(a["target"], a.get("args"),
                                       a.get("pid", 0), a.get("steps", 0)),
    },
    {
        "name": "svmhv_reverse",
        "description":
            "Walk a single-stepped run backwards to find the instruction that "
            "gave a register its value. Run svmhv_step first to fill the ring; "
            "every step record carries all sixteen registers, so 'why is rax "
            "that' is a walk backwards rather than another run from the start. "
            "With no register named it reports which registers changed at all, "
            "which is the cheaper question and usually the first one.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "register": {"type": "string",
                             "description": "rax, rcx, ... r15; omit for a summary"},
                "value": {"type": "string",
                          "description": "hex value to trace back; defaults to "
                                         "whatever it ended up holding"},
                "count": {"type": "integer",
                          "description": "how many records to consider, 1-200"},
            },
        },
        "handler": lambda a: tool_reverse(a.get("register", ""),
                                          a.get("value", ""),
                                          a.get("count", 200)),
    },
    {
        "name": "svmhv_provenance",
        "description":
            "Watch a buffer and report everything that writes to it, grouped by "
            "the instruction that did it and named with symbols. 'Where did "
            "this value come from' is most of reverse engineering and none of a "
            "disassembly. Grouping is what makes it readable: a thousand hits "
            "from one memcpy are one line, and the single write from somewhere "
            "unexpected is visible instead of buried. The watch is removed "
            "before this returns.",
        "inputSchema": {
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string",
                           "description": "hex address or module!symbol"},
                "size": {"type": "integer", "description": "bytes to cover"},
                "pid": {"type": "integer", "description": "for a user address"},
                "seconds": {"type": "integer",
                            "description": "how long to watch, 1-120 (default 10)"},
                "mode": {"type": "string", "enum": ["write", "access"],
                         "description": "access also catches reads"},
            },
        },
        "handler": lambda a: tool_provenance(
            a["target"], a.get("size", 8), a.get("pid", 0),
            a.get("seconds", 10), a.get("mode", "write")),
    },
    {
        "name": "svmhv_dump",
        "description":
            "Dump the image around an address to a file, with its section table "
            "rewritten so a disassembler opens it at the right addresses. This "
            "is what to do with a page svmhv_coverage reported as "
            "written-then-executed: that is a manual map, an unpacker or a JIT, "
            "and this turns the page number into a file. A payload that erased "
            "its own MZ header is dumped flat rather than refused, which is the "
            "ordinary shape for something that did not want to be found.",
        "inputSchema": {
            "type": "object",
            "required": ["address"],
            "properties": {
                "address": {"type": "string",
                            "description": "anywhere inside the image"},
                "pid": {"type": "integer", "description": "for a user address"},
                "size": {"type": "integer",
                         "description": "bytes, when there is no PE header to "
                                        "ask (default 64 KiB)"},
                "name": {"type": "string", "description": "output file name"},
            },
        },
        "handler": lambda a: tool_dump(a["address"], a.get("pid", 0),
                                       a.get("size", 0), a.get("name", "")),
    },
    {
        "name": "svmhv_coverage_diff",
        "description":
            "Save what a coverage sweep found under a name, and compare two "
            "runs. A coverage dump is hundreds of pages and almost all of them "
            "are the same every time; the answer worth having is the "
            "difference. Run the target without doing the thing and save, do "
            "the thing and save, then diff - what comes back is the handful of "
            "pages that ran because of it.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string",
                           "enum": ["save", "diff", "list", "drop"],
                           "description": "default list"},
                "name": {"type": "string", "description": "the run to save or diff"},
                "against": {"type": "string",
                            "description": "the earlier run, for diff"},
            },
        },
        "handler": lambda a: tool_coverage_diff(a.get("action", "list"),
                                                a.get("name", ""),
                                                a.get("against", "")),
    },
    {
        "name": "svmhv_ibs",
        "description":
            "Sample which instructions touch memory and what addresses they "
            "touch, without instrumenting anything. The processor tags one "
            "micro-op in every N and records the instruction and the linear "
            "address - no hooks, no watchpoints, and a cost set by the interval "
            "rather than by how busy the code is. This is how to answer 'what "
            "memory does this thing touch at all' before you have an address to "
            "aim a watchpoint at. IBS is optional hardware and is often not "
            "exposed inside a VM; this says so plainly when it is not.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "interval": {"type": "integer",
                             "description": "micro-ops between samples; 0 reads "
                                            "back what has been collected "
                                            "without changing the arming. "
                                            "65536 is a reasonable start"},
                "show": {"type": "integer",
                         "description": "how many ring records to summarise"},
            },
        },
        "handler": lambda a: tool_ibs(a.get("interval", 0), a.get("show", 30)),
    },
    {
        "name": "svmhv_revive",
        "description":
            "Put back the processors a fatal exit left running outside SVM. A "
            "processor that takes an exit the hypervisor cannot handle leaves "
            "guest mode and stays out, so the machine and the evidence both "
            "survive - but fewer processors are covered than virtualized= "
            "claims. Until this existed the only way back was a reload, which "
            "throws away every hook and the trace ring along with the problem. "
            "Read fatal_count in svmhv_status first: whatever caused it is "
            "usually still there.",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": lambda a: tool_revive(),
    },
]

TOOLS += [
    {
        "name": "svmhv_explore",
        "description":
            "Call a function once per input and report which inputs reached new "
            "code. The loop the rest of this was built for: snapshot, call, "
            "collect coverage, restore, repeat. What comes back is not a "
            "hundred traces but the short list of inputs that got somewhere the "
            "others did not, which is the question when you are hunting the "
            "branch that matters. Arm a coverage sweep first with svmhv_sweep, "
            "and give it a snapshot range or the calls are not undone.",
        "inputSchema": {
            "type": "object",
            "required": ["target", "inputs"],
            "properties": {
                "target": {"type": "string",
                           "description": "hex address or module!symbol"},
                "inputs": {"type": "array", "items": {"type": "string"},
                           "description": "one entry per call: the arguments, "
                                          "space-separated hex, e.g. \"1 ff 0\""},
                "snapshot_target": {"type": "string",
                                    "description": "memory the calls write to, "
                                                   "restored between them"},
                "snapshot_size": {"type": "integer", "description": "bytes"},
                "pid": {"type": "integer", "description": "address space"},
                "store_pages": {"type": "integer",
                                "description": "snapshot store capacity"},
            },
        },
        "handler": lambda a: tool_explore(
            a["target"], a.get("inputs") or [], a.get("snapshot_target", ""),
            a.get("snapshot_size", 0), a.get("pid", 0), a.get("store_pages", 0)),
    },
    {
        "name": "svmhv_diverge",
        "description":
            "Run a function under two inputs and report the exact instruction "
            "where the paths part. The question in front of a licence check, a "
            "signature check or an anti-debug branch is not what the function "
            "does, it is where the good input and the bad one stop agreeing - "
            "and that one address is usually the whole answer. Both runs are "
            "single-stepped and compared; the branch that decided is reported "
            "with its disassembly.",
        "inputSchema": {
            "type": "object",
            "required": ["target", "input_a", "input_b"],
            "properties": {
                "target": {"type": "string",
                           "description": "hex address or module!symbol"},
                "input_a": {"type": "string",
                            "description": "arguments, space-separated hex"},
                "input_b": {"type": "string", "description": "the other input"},
                "steps": {"type": "integer",
                          "description": "instructions to record, 64-4096"},
                "pid": {"type": "integer", "description": "address space"},
                "snapshot_target": {"type": "string",
                                    "description": "memory to restore between "
                                                   "the two runs"},
                "snapshot_size": {"type": "integer", "description": "bytes"},
            },
        },
        "handler": lambda a: tool_diverge(
            a["target"], a["input_a"], a["input_b"], a.get("steps", 2000),
            a.get("pid", 0), a.get("snapshot_target", ""),
            a.get("snapshot_size", 0)),
    },
    {
        "name": "svmhv_usercall",
        "description":
            "Call a function inside a user process by borrowing one of its "
            "threads. svmhv_call is for kernel functions; this is the same "
            "question for an .exe or a .dll. It suspends a thread, saves its "
            "whole context, points it at the target with your arguments, "
            "catches it when it returns and puts the context back. The thread "
            "does not do its own work meanwhile, so borrowing one that holds a "
            "lock the target wants deadlocks the process until the timeout - "
            "name an idle thread where you can. Four arguments maximum.",
        "inputSchema": {
            "type": "object",
            "required": ["target", "pid"],
            "properties": {
                "target": {"type": "string",
                           "description": "user-mode address or module!symbol"},
                "pid": {"type": "integer", "description": "the process"},
                "args": {"type": "array", "items": {"type": "string"},
                         "description": "up to four, hex"},
                "tid": {"type": "integer",
                        "description": "thread to borrow; 0 takes the first, "
                                       "which for a GUI process is usually the "
                                       "message pump and the worst choice"},
                "timeout": {"type": "integer",
                            "description": "milliseconds to wait (default 5000)"},
            },
        },
        "handler": lambda a: tool_usercall(
            a["target"], a["pid"], a.get("args"), a.get("tid", 0),
            a.get("timeout", 5000)),
    },
    {
        "name": "svmhv_struct",
        "description":
            "Watch a buffer and infer what shape it is from how it is used. A "
            "structure with no symbols is recovered from its accesses: four "
            "bytes always read at +0x10 is a field, eight bytes read and then "
            "dereferenced is a pointer, an offset nothing touches is padding. "
            "Returns a candidate layout - offset, the width the instructions "
            "actually used, read or written, and by what. Drive the code that "
            "uses the buffer while the window is open or there is nothing to "
            "infer from.",
        "inputSchema": {
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string",
                           "description": "hex address or module!symbol"},
                "size": {"type": "integer",
                         "description": "bytes of the structure, up to 4096"},
                "pid": {"type": "integer", "description": "for a user address"},
                "seconds": {"type": "integer", "description": "1-120, default 15"},
                "mode": {"type": "string", "enum": ["access", "write"],
                         "description": "access catches reads too, which is "
                                        "what tells a field from a written one"},
            },
        },
        "handler": lambda a: tool_struct(
            a["target"], a.get("size", 64), a.get("pid", 0),
            a.get("seconds", 15), a.get("mode", "access")),
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

    def _error(self, code: int, rpc_code: int, message: str):
        self._send(code, json.dumps({
            "jsonrpc": "2.0", "id": None,
            "error": {"code": rpc_code, "message": message},
        }).encode(), "application/json")

    def _read_body(self) -> bytes | None:
        """The request body, or None once a refusal has been answered.

        Bounded twice: by what the client declares and by what it actually
        sends, and read under a timeout so a half-sent body occupies one
        worker thread for fifteen seconds rather than forever.  The timeout is
        applied to the body only - an idle keep-alive connection between tool
        calls is left alone, because closing those is how a client ends up
        seeing RemoteDisconnected instead of an answer.
        """
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._error(400, -32700, "invalid Content-Length")
            return None
        if length < 0 or length > MAX_REQUEST_BODY_BYTES:
            self._error(413, -32600,
                        f"request body limit is {MAX_REQUEST_BODY_BYTES} bytes")
            self.close_connection = True
            return None
        if not length:
            return b""

        previous = self.connection.gettimeout()
        self.connection.settimeout(REQUEST_READ_TIMEOUT_SECONDS)
        try:
            raw = self.rfile.read(length)
        except OSError:
            self.close_connection = True
            return None
        finally:
            self.connection.settimeout(previous)

        if len(raw) != length:
            self.close_connection = True
            return None
        return raw

    def do_POST(self):
        raw = self._read_body()
        if raw is None:
            return

        try:
            payload = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self._error(400, -32700, "parse error")
            return

        if isinstance(payload, list):
            if len(payload) > MAX_BATCH_REQUESTS:
                self._error(400, -32600,
                            f"batch limit is {MAX_BATCH_REQUESTS} requests")
                return
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
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
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
