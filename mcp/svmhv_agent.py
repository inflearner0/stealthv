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
import time
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
                 spoof=None, spoof2=None, block=None, in_process=None) -> list[str]:
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


def hook_target(target: str, prolog: int | None) -> tuple[str, str, str]:
    """Resolve a target and settle on a prologue length.

    Both halves exist because both are things a caller gets wrong. The target
    may now be 'nt!NtCreateFile' instead of an address nobody can verify by
    eye, and the length - the parameter the driver's own documentation warns
    will corrupt the function - is decoded from the bytes rather than defaulted
    to 14 and hoped for. An explicit length is still honoured; a caller who has
    disassembled the function themselves outranks this.
    """
    address = resolve(target)
    note = ""

    if prolog is None:
        try:
            computed = safe_prolog_length(read_bytes(address, 64))
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
    address, prolog, note = hook_target(target, prolog_length)
    extra = hook_options(**options)
    return hook_result(
        ctl("hook-trace", address, prolog, *extra),
        f"tracing {target}{note}" + (f" [{' '.join(extra)}]" if extra else ""))


def tool_hook_detour(target: str, detour: str, prolog_length: int | None = None,
                     **options) -> str:
    address, prolog, note = hook_target(target, prolog_length)
    extra = hook_options(**options)
    return hook_result(
        ctl("hook-detour", address, prolog, f"{resolve(detour):x}", *extra),
        f"detoured {target} -> {detour}{note}")


def tool_hook_shellcode(target: str, shellcode_hex: str,
                        prolog_length: int | None = None, **options) -> str:
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
    return hook_result(ctl("watch", f"{resolve(target):x}", mode, *extra),
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
    resolved = module_by_name(module)
    if resolved is None:
        return f"no loaded module called {module!r}"

    wanted = contains.lower()
    targets = [(a, n) for a, n in exports(resolved["base"])
               if wanted in n.lower()]
    if not targets:
        return f"{resolved['name']} exports nothing matching {contains!r}"

    extra = hook_options(**options)
    installed, skipped = [], []
    for address, name in targets[:limit]:
        try:
            prolog = safe_prolog_length(read_bytes(address, 64))
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

    start = resolve(target)
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


def tool_unhook(target: str) -> str:
    # Symbols everywhere a target is accepted, or the tool that installed a hook
    # by name cannot remove it by the same name.
    status = as_int(pairs(ctl("unhook", f"{resolve(target):x}")), "status", -1)
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
            value = _signed(int.from_bytes(code[i:i + width], "little"), width)
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
        value = _signed(int.from_bytes(code[i:i + width], "little"), width)
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
_exports_cache: dict[int, list[tuple[int, str]]] = {}


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


def module_for(address: int) -> dict | None:
    for module in modules():
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


def exports(base: int) -> list[tuple[int, str]]:
    """Every exported name in the image at `base`, as (address, name).

    Parsed straight out of the mapped image with the memory read primitive, so
    it needs no symbol server, no PDB and no network - which matters because the
    machine being reverse engineered is usually a lab VM with none of the three.
    It only sees exports, not private symbols; for the kernel that is still
    several thousand functions and every Nt* entry point.
    """
    if base in _exports_cache:
        return _exports_cache[base]

    header = read_bytes(base, 0x400)
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
        _exports_cache[base] = []
        return []

    # The export directory and its three arrays are contiguous and usually well
    # under a page; read it in page-sized pieces because that is the transfer
    # unit the driver offers.
    blob = bytearray()
    for offset in range(0, min(export_size, 0x20000), 0x1000):
        blob += read_bytes(base + export_rva + offset,
                           min(0x1000, export_size - offset))

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
            out += read_bytes(base + rva + offset, min(0x1000, wanted - offset))
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
                    pages[page] = read_bytes(page, 0x1000)
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
    _exports_cache[base] = found
    return found


def resolve(name: str) -> int:
    """'nt!NtCreateFile', 'ntoskrnl.exe!ZwClose' or a bare hex address."""
    text = name.strip()
    if "!" not in text:
        return int(hexarg(text), 16)

    module_name, symbol = text.split("!", 1)
    module = module_by_name(module_name)
    if module is None:
        raise CtlError(f"no loaded module called {module_name!r}")

    offset = 0
    if "+" in symbol:
        symbol, _, plus = symbol.partition("+")
        offset = int(plus, 0)

    for address, export in exports(module["base"]):
        if export.lower() == symbol.lower():
            return address + offset
    raise CtlError(f"{module['name']} exports no symbol called {symbol!r}")


def symbolize(address: int) -> str:
    """The inverse: an address as module!symbol+offset, as far as it can."""
    if address == 0:
        return "0"
    module = module_for(address)
    if module is None:
        return f"{address:#x}"

    best = None
    try:
        for export_address, name in exports(module["base"]):
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
    if delta > SYMBOL_MAX_OFFSET:
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


def tool_symbol(name: str) -> str:
    address = resolve(name)
    return f"{name} = {address:#x}"


def tool_exports(module_name: str, contains: str = "") -> str:
    module = module_by_name(module_name)
    if module is None:
        return f"no loaded module called {module_name!r}"
    wanted = contains.lower()
    found = [(a, n) for a, n in exports(module["base"])
             if not wanted or wanted in n.lower()]
    if not found:
        return f"{module['name']} exports nothing matching {contains!r}"

    lines = [f"{len(found)} export(s) in {module['name']} "
             f"(base {module['base']:#x})", ""]
    for address, name in found[:400]:
        lines.append(f"{address:#018x}  {name}")
    if len(found) > 400:
        lines.append(f"... and {len(found) - 400} more; narrow it with 'contains'")
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
    for _ in range(256):
        if entry == 0 or entry == head:
            break
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
        if name_buffer and 0 < name_length <= 512:
            try:
                name = read_bytes(name_buffer, name_length, pid).decode(
                    "utf-16-le", "replace")
            except CtlError:
                name = ""
        if base:
            found.append({"base": base, "size": size, "name": name or "?"})
        entry = field(0)                       # InLoadOrderLinks.Flink
    return found


def tool_process_modules(pid: int) -> str:
    found = process_modules(int(pid))
    if not found:
        return f"pid {pid} has no readable module list"
    lines = [f"{len(found)} module(s) in pid {pid}", ""]
    for module in found:
        lines.append(f"  {module['base']:#018x}  {module['size']:>9,}  "
                     f"{module['name']}")
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


def tool_sections(module: str) -> str:
    resolved = module_by_name(module)
    if resolved is None:
        return f"no loaded module called {module!r}"
    found = pe_sections(resolved["base"])
    lines = [f"{resolved['name']} at {resolved['base']:#x}", ""]
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
                 contains: str = "") -> str:
    """The classic first look at a binary.

    For a driver that exports nothing and whose functions have no names, the
    strings are frequently the only thing that says what it is for - registry
    paths, device names, the text of its own error messages.
    """
    resolved = module_by_name(module)
    if resolved is None:
        return f"no loaded module called {module!r}"
    minimum = max(4, min(int(minimum), 64))
    limit = max(1, min(int(limit), 1000))

    sections = [s for s in pe_sections(resolved["base"])
                if not (s["characteristics"] & 0x20000000)]   # skip code
    if not sections:
        sections = pe_sections(resolved["base"])

    found: list[tuple[int, str]] = []
    scanned = 0
    for section in sections:
        if len(found) >= limit * 4 or scanned > (4 << 20):
            break
        start = resolved["base"] + section["rva"]
        size = min(section["size"], 2 << 20)
        scanned += size
        for page, blob in sorted(dump_range(start, size).items()):
            found += extract_strings(blob, page, minimum)

    wanted = contains.lower()
    if wanted:
        found = [(a, t) for a, t in found if wanted in t.lower()]

    lines = [f"{len(found)} string(s) in {resolved['name']}"
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
        resolved = module_by_name(module)
        if resolved is None:
            return f"no loaded module called {module!r}"
        begin, span = resolved["base"], min(resolved["size"], 4 << 20)
        where = resolved["name"]
    elif start and size:
        begin, span = resolve(start), min(int(size), 4 << 20)
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
    lines = [f"{len(hits)} match(es) for {pattern!r} in {where}", ""]
    for address in hits:
        lines.append(f"  {address:#018x}  {symbolize(address)}")
    return "\n".join(lines)


def tool_disassemble(target: str, count: int = 24, pid: int = 0) -> str:
    """A listing with branch targets named.

    The naming is the point. A call to 0xfffff80023f1a2b0 tells a reader
    nothing; a call to nt!ExAllocatePool2 tells them what the function does.
    Following the calls out of a function is most of how anybody works out what
    it is for, and it is the one thing a raw byte dump cannot support.
    """
    count = max(1, min(int(count), 200))
    address = resolve(target)
    # Roughly 15 bytes per instruction, bounded by what one transfer carries.
    wanted = min(4096, max(64, count * 15))
    code = read_bytes(address, wanted, pid)
    if not code:
        return f"nothing readable at {target}"

    lines = [f"{symbolize(address)}  ({address:#x})", ""]
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
            named = symbolize(branch)
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

    # Most slots point at nt!IopInvalidDeviceRequest; the interesting ones are
    # those that do not, so find the majority pointer and treat it as "unset".
    handlers = [pointer(DRIVER_MAJOR + i * 8) for i in range(len(IRP_NAMES))]
    common = max(set(handlers), key=handlers.count) if handlers else 0

    shown = 0
    for index, handler in enumerate(handlers):
        if handler in (0, common):
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
            a["target"], (int(a["prolog_length"]) if a.get("prolog_length") else None),
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
            a["target"], a["detour"], (int(a["prolog_length"]) if a.get("prolog_length") else None),
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
            a["target"], a["shellcode_hex"], (int(a["prolog_length"]) if a.get("prolog_length") else None),
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
