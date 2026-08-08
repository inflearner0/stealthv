#!/usr/bin/env python3
"""
test_agent.py - checks the MCP agent without a hypervisor anywhere near it.

svmhvctl is stubbed out, so what is under test is everything between the JSON-RPC
wire and the command line: the protocol handshake, the tool schemas, the option
builder, the parsers, and the capture decoder.

The one thing this cannot check is whether the offsets in svmhvctl.c still match
the driver - the C_ASSERTs in include/svmhvctl.h do that, at compile time, which
is why CI builds as well as runs this.

    python mcp/test_agent.py
"""

import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

spec = importlib.util.spec_from_file_location(
    "agent", os.path.join(HERE, "svmhv_agent.py"))
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

failures = []


def check(label, condition, detail=""):
    print(f"  [{'pass' if condition else 'FAIL'}] {label}"
          + (f"  {detail}" if detail and not condition else ""))
    if not condition:
        failures.append(label)


def rpc(method, params=None, request_id=1):
    return agent.dispatch({"jsonrpc": "2.0", "id": request_id,
                           "method": method, "params": params or {}})


# ------------------------------------------------------------------ protocol

print("protocol")
result = rpc("initialize")["result"]
check("initialize returns a serverInfo",
      result["serverInfo"]["name"] == "svmhv", result)
check("initialize advertises tools", "tools" in result["capabilities"])
check("a notification gets no reply",
      agent.dispatch({"jsonrpc": "2.0",
                      "method": "notifications/initialized"}) is None)
check("ping answers", "result" in rpc("ping"))
check("an unknown method is an error", "error" in rpc("nosuchmethod"))

tools = rpc("tools/list")["result"]["tools"]
check("tools/list returns every tool", len(tools) == len(agent.TOOLS),
      f"got {len(tools)}, TOOLS has {len(agent.TOOLS)}")
check("no handler leaked into a schema",
      all("handler" not in tool for tool in tools))
check("every tool is described",
      all(tool.get("description") and tool.get("inputSchema") for tool in tools))
check("an unknown tool is rejected",
      "error" in rpc("tools/call", {"name": "nope", "arguments": {}}))

# ------------------------------------------------------------------- options

print("hook options")
built = agent.hook_options(process="notepad.exe", pid=1234,
                           caller_base="fffff80012340000", caller_size=0x50000,
                           capture="1:objattr", spoof="2:0", block="0xC0000022")
check("process, pid, caller, capture, spoof and block all appear",
      built == ["--process", "notepad.exe", "--pid", "1234",
                "--caller", "fffff80012340000", "327680",
                "--capture", "1:objattr", "--spoof", "2:0",
                "--block", "0xC0000022"], built)

check("an image name longer than Windows keeps is truncated",
      agent.hook_options(process="areallylongname.exe")[1] == "areallylongname")

for bad, why in (({"capture": "1:nope"}, "unknown capture type"),
                 ({"spoof": "nocolon"}, "spoof without a value"),
                 ({"caller_base": "ffff"}, "caller_base without a size")):
    try:
        agent.hook_options(**bad)
        check(f"rejects {why}", False)
    except agent.CtlError:
        check(f"rejects {why}", True)

check("capture_return becomes a flag with no value",
      agent.hook_options(capture_return=True) == ["--capture-return"],
      agent.hook_options(capture_return=True))
check("capture_return off adds nothing",
      agent.hook_options(capture_return=False) == [])

check("the sanitiser passes the option strings it has to",
      all(agent.SAFE_ARGUMENT.match(a) for a in
          ("notepad.exe", "1:objattr", "--process", "0xC0000022", "ffff8000")))
check("the sanitiser still rejects a shell metacharacter",
      not agent.SAFE_ARGUMENT.match("a;b"))

# ------------------------------------------------------------------ decoding

print("capture decoding")
check("a UTF-16 path comes back as text",
      agent.decode_capture("5c003f003f005c0043003a005c0078002e00740078007400")
      == r"\??\C:\x.txt")
check("an ANSI string comes back as text",
      agent.decode_capture("48656c6c6f2e74787400") == "Hello.txt")
check("junk hex does not raise", isinstance(agent.decode_capture("zz"), str))

print("parsers")
check("key=value lines parse",
      agent.pairs("cpus=8\noptions=0x7b\n") == {"cpus": "8", "options": "0x7b"})
check("record lines parse",
      agent.records("hook id=3 active=1\nnoise\n", "hook")
      == [{"id": "3", "active": "1"}])
check("as_int copes with a missing key", agent.as_int({}, "nope", 7) == 7)
check("hexarg strips 0x", agent.hexarg("0xFFFF") == "ffff")

# ------------------------------------------------------- tools end to end

print("tools, with svmhvctl stubbed")
calls = []


def fake_ctl(*arguments):
    calls.append(arguments)
    if arguments[0] == "status":
        return ("cpus=8\noptions=0x007b\nexits=100\nnpt_coverage=281474976710656\n"
                "cpu0_exits=60\ncpu1_exits=40\ncpuid_exits=7\n")
    if arguments[0] == "trace":
        return ("produced=1\nring_records=4096\nrecord_size=432\n"
                "trace seq=0 type=0 hook=1 cpu=2 pid=88 tid=9 irql=0 spoofed=1 "
                "proc=notepad.exe tsc=1 rip=0xdead rsp=0x1 ret=0x2 gpa=0x3 err=0x0 "
                "a0=0x1 a1=0x2 a2=0x3 a3=0x4 s0=0x0 s1=0x0 "
                "cap0=48656c6c6f2e74787400\n")
    if arguments[0] == "hooks":
        return "hooks=1\nhook id=0 active=1 kind=0 action=0 target=0xffff1000 " \
               "gpa=0x1000 detour=0x0 trampoline=0x0 prolog=14 hits=5 filters=0\n"
    if arguments[0] in ("read", "readphys"):
        # The hook tools decode this as a prologue, so it has to be
        # instructions - an MZ header is not, and a strict decoder is right to
        # refuse it. This is a real one: mov [rsp+8],rbx / push rdi /
        # sub rsp,0x20 / mov rbx,rcx / xor eax,eax / ret.
        return ("status=0x00000000\nbytes=16\n"
                "fffff78000000000  48 89 5c 24 08 57 48 83 ec 20 48 8b d9 33 c0 c3"
                "  H..$.WH.. H..3..\n")
    if arguments[0] == "write":
        return "status=0x00000000\nwritten=4\n"
    return "status=0x00000000\nhookid=1\ngpa=0x1000\ntrampoline=0x2000\n"


agent.ctl = fake_ctl

text = rpc("tools/call", {"name": "svmhv_status", "arguments": {}})["result"]["content"][0]["text"]
check("status reports the processor count", "processors      : 8" in text)
check("status does not mistake cpuid_exits for a per-cpu counter",
      "exits per processor: 0:60, 1:40" in text, text)

text = rpc("tools/call", {"name": "svmhv_trace", "arguments": {"count": 1}})["result"]["content"][0]["text"]
check("trace shows the image name", "notepad.exe" in text)
check("trace reports spoofed arguments", "1 argument(s) replaced" in text)
check("trace decodes the capture", 'arg capture 0: "Hello.txt"' in text, text)

def return_ctl(*arguments):
    calls.append(arguments)
    if arguments[0] == "trace":
        return ("produced=2\nring_records=4096\nrecord_size=432\n"
                "trace seq=1 type=3 hook=0 cpu=3 pid=88 tid=9 irql=0 spoofed=0 "
                "proc=- tsc=9 rip=0x1 rsp=0x2 ret=0xfffff80010001000 gpa=0x0 "
                "err=0x0 a0=0xc0000022 a1=0x1e240 a2=0x0 a3=0x0 s0=0x0 s1=0x0\n")
    return "status=0x00000000\n"


agent.ctl = return_ctl
text = rpc("tools/call", {"name": "svmhv_trace",
                          "arguments": {"count": 1}})["result"]["content"][0]["text"]
check("a return record shows the value and the cycles",
      "RETURNED 0xc0000022 after 123,456 cycles" in text, text)
agent.ctl = fake_ctl

calls.clear()
text = rpc("tools/call", {"name": "svmhv_hook_trace", "arguments": {
    "target": "0xffff1000", "process": "notepad.exe",
    "capture": "1:objattr", "spoof": "2:0"}})["result"]["content"][0]["text"]
check("hook_trace reports the new hook", "hook id    : 1" in text, text)
check("hook_trace passes the options through",
      calls[-1][:2] == ("hook-trace", "ffff1000")
      and int(calls[-1][2]) >= 14
      and calls[-1][3:] == ("--process", "notepad.exe",
                            "--capture", "1:objattr", "--spoof", "2:0"),
      calls[-1])

# The prologue length is the parameter the driver warns will corrupt the
# function, so check both that it is decoded when absent and that an explicit
# one still wins.
calls.clear()
text = rpc("tools/call", {"name": "svmhv_hook_trace", "arguments": {
    "target": "0xffff1000"}})["result"]["content"][0]["text"]
check("an absent prologue is decoded from the bytes",
      "(decoded)" in text and int(calls[-1][2]) >= 14, (text, calls[-1]))

calls.clear()
rpc("tools/call", {"name": "svmhv_hook_trace", "arguments": {
    "target": "0xffff1000", "prolog_length": 21}})
check("an explicit prologue outranks the decoder",
      calls[-1][2] == "21", calls[-1])


text = rpc("tools/call", {"name": "svmhv_hooks", "arguments": {}})["result"]["content"][0]["text"]
# the renderer zero-pads addresses to 16 digits, so match the digits only
check("hooks renders a record",
      "active" in text and "ffff1000" in text.lower(), text)

text = rpc("tools/call", {"name": "svmhv_watch",
                          "arguments": {"target": "0xffff1000", "mode": "sideways"}})["result"]["content"][0]["text"]
check("watch rejects an unknown mode", "must be" in text)

# ------------------------------------------------------- lengths and symbols

print("instruction lengths")
for encoding, want, what in (
        ("4889c8", 3, "mov rax,rcx"),
        ("48b81122334455667788", 10, "mov rax,imm64"),
        ("488b0d12345678", 7, "mov rcx,[rip+disp32]"),
        ("ff2500000000", 6, "jmp qword [rip+0]"),
        ("f30f1efa", 4, "endbr64"),
        ("0f1f440000", 5, "nop dword [rax+rax]"),
        ("48895c2408", 5, "mov [rsp+8],rbx"),
        ("f7c101000000", 6, "test ecx,imm32"),
        ("660f1f440000", 6, "66-prefixed nop"),
):
    got = agent.instruction_length(bytes.fromhex(encoding))
    check(f"decodes {what}", got == want, f"want {want}, got {got}")

prologue = bytes.fromhex("48895c2408" "57" "4883ec20" "488bd9" "33c0" "c3")
check("instruction boundaries are found",
      agent.instruction_offsets(prologue) == [0, 5, 6, 10, 13, 15],
      agent.instruction_offsets(prologue))
check("a prologue is rounded up to a boundary, never down",
      agent.safe_prolog_length(prologue) == 15,
      agent.safe_prolog_length(prologue))
check("the self-test victim needs exactly the 14 it has",
      agent.safe_prolog_length(bytes.fromhex("b811111111" + "90" * 9 + "c3")) == 14)

for bad, why in (("4889c8", "bytes that run out mid-prologue"),
                 ("62f27d48", "an opcode it does not know")):
    try:
        agent.safe_prolog_length(bytes.fromhex(bad))
        check(f"refuses {why}", False)
    except agent.DecodeError:
        check(f"refuses {why}", True)

print("disassembly")
# Exact rendering is the built-in decoder's contract; capstone words things its
# own way ("qword ptr gs:[0x188]"), so the strings are checked against ours.
for encoding, want in (
        ("4889c8", "mov rax, rcx"),
        ("4883ec28", "sub rsp, 0x28"),
        ("48895c2408", "mov [rsp+0x8], rbx"),
        ("4157", "push r15"),
        ("33c0", "xor eax, eax"),
        ("4885c9", "test rcx, rcx"),
        ("f30f1efa", "endbr64"),
        ("48b81122334455667788", "mov rax, 0x8877665544332211"),
        ("488b4c2420", "mov rcx, [rsp+0x20]"),
        ("65488b042588010000", "mov rax, gs:[0x188]"),
        ("64488b042530000000", "mov rax, fs:[0x30]"),
        ("0f1f440000", "nop [rax+rax*1]"),
):
    _, got, _ = agent._disassemble_builtin(bytes.fromhex(encoding), 0, 0x140001000)
    check(f"the built-in disassembles {want}", got == want, f"got {got!r}")

# Whichever decoder is in use, a segment override must not be dropped - gs:[0x188]
# is the current thread and [0x188] is nonsense.
_, got, _ = agent.disassemble_one(bytes.fromhex("65488b042588010000"), 0, 0x1000)
check("a segment override survives whichever decoder is used",
      "gs:" in got, got)

# And instruction lengths must agree, since that is what sizes a hook prologue.
for encoding in ("4889c8", "48895c2408", "0f1f440000", "48b81122334455667788",
                 "65488b042588010000", "e800000000"):
    raw = bytes.fromhex(encoding)
    check(f"length of {encoding} agrees with the built-in",
          agent.instruction_length(raw) == agent._instruction_length_builtin(raw),
          f"{agent.instruction_length(raw)} vs "
          f"{agent._instruction_length_builtin(raw)}")

# A kernel address is above 2^63; capstone hands the target back signed, and a
# negative one matches no module and silently loses the symbol.
_, _, target = agent.disassemble_one(bytes.fromhex("e800000000"), 0,
                                     0xfffff80010001000)
check("a branch target above 2^63 comes back unsigned",
      target == 0xfffff80010001005, hex(target) if target else target)

_, text, target = agent.disassemble_one(bytes.fromhex("e800000000"), 0, 0x140001000)
check("a call resolves its target", target == 0x140001005 and text.startswith("call"),
      (text, target))
_, text, target = agent.disassemble_one(bytes.fromhex("7405"), 0, 0x140001000)
check("a short jump resolves its target", target == 0x140001007, (text, target))
# An opcode it does not know must stop the decoder rather than produce a wrong
# mnemonic; the listing renders those as db, which is the tool's job, not this
# function's.
try:
    agent.disassemble_one(bytes.fromhex("6208"), 0, 0x1000)
    check("an unknown opcode is refused, never guessed", False)
except agent.DecodeError:
    check("an unknown opcode is refused, never guessed", True)

print(f"assembly  ({agent.engines()})")

# The built-in subset has a fixed contract regardless of what is installed, so
# it is tested directly rather than through assemble(), which prefers keystone.
for source, want, why in (
        ("mov rax, 0x100000000", "48b80000000001000000", "imm64 when it needs one"),
        ("mov rax, 0xC0000022", "b8220000c0", "a 32-bit load zero-extends"),
        ("mov rax, -1", "48c7c0ffffffff", "a negative needs sign extension"),
        ("mov rcx, rdx", "4889d1", "mov r64, r64"),
        ("xor eax, eax", "31c0", "32-bit needs no REX"),
        ("push r15", "4157", "push needs REX.B for r8-r15"),
        ("sub rsp, 0x28", "4883ec28", "imm8 form when it fits"),
        ("mov [rsp+0x20], rax", "4889442420", "rsp as a base needs a SIB"),
        ("mov [rbp+0], rax", "48894500", "rbp as a base needs a displacement"),
        ("mov rax, [rcx+8]", "488b4108", "load with disp8"),
        ("lea rdx, [rcx+0x10]", "488d5110", "lea"),
        ("test rcx, rcx", "4885c9", "test"),
        ("ret", "c3", "ret"),
):
    got = agent._assemble_builtin(source).hex()
    check(f"the built-in assembles {why}", got == want,
          f"{source!r} -> {got}, want {want}")

for bad, why in (("mov rax, rbx, rcx", "three operands"),
                 ("frobnicate rax", "an unknown mnemonic"),
                 ("mov rax, [rcx+rdx*4]", "a scaled index it cannot encode")):
    try:
        agent._assemble_builtin(bad)
        check(f"the built-in rejects {why}", False)
    except agent.AsmError:
        check(f"the built-in rejects {why}", True)

# Whichever engine is in use, these have to hold.
code, listing = agent.assemble_checked(
    "test rcx, rcx\nje done\nmov rax, 1\ndone:\nret", 0)
check("a forward label assembles and lands on the last instruction",
      listing.strip().splitlines()[-1].endswith("ret"), listing)
check("every line of the listing was decoded, none left as db",
      "db " not in listing, listing)
check("a branch target is resolved to an address",
      " 0x" in [l for l in listing.splitlines() if " je " in l][0], listing)

code, listing = agent.assemble_checked("mov rax, 1\nret", 0)
check("the round trip reads back what was asked for",
      "mov" in listing and "ret" in listing, listing)

try:
    agent.assemble("")
    check("empty source is refused", False)
except agent.AsmError:
    check("empty source is refused", True)

print("decorated names")
for mangled, want in (
        ("??1CClfsBaseFilePersisted@@UEAA@XZ",
         "CClfsBaseFilePersisted::~CClfsBaseFilePersisted"),
        ("??0CClfsBaseFile@@QEAA@XZ", "CClfsBaseFile::CClfsBaseFile"),
        ("?AhcGetLogFlags@@YAIXZ", "AhcGetLogFlags"),
        ("?Method@Inner@Outer@@AEAAXXZ", "Outer::Inner::Method"),
        ("SdbpGetMatchingXap", "SdbpGetMatchingXap"),
):
    got = agent.readable_name(mangled)
    check(f"reads {want}", got == want, f"got {got!r}")

check("an unrecognised decoration is left alone",
      agent.readable_name("??_C@_0CC@HPCEKKIJ@junk@")
      == "??_C@_0CC@HPCEKKIJ@junk@")

print("symbols")
_fake_modules = [
    {"base": 0xFFFFF80010000000, "size": 0x900000,
     "name": "ntoskrnl.exe", "path": r"\SystemRoot\system32\ntoskrnl.exe"},
    {"base": 0xFFFFF80020000000, "size": 0x10000,
     "name": "svmhv.sys", "path": r"\??\C:\lab\svmhv.sys"},
]
_fake_exports = {
    0xFFFFF80010000000: [(0xFFFFF80010001000, "NtCreateFile"),
                         (0xFFFFF80010002000, "NtOpenProcess")],
    0xFFFFF80020000000: [],
}
agent.modules = lambda refresh=False: _fake_modules
agent.exports = lambda base: _fake_exports.get(base, [])

check("a symbol resolves to its address",
      agent.resolve("nt!NtCreateFile") == 0xFFFFF80010001000)
check("'nt' is understood to mean ntoskrnl",
      agent.resolve("ntoskrnl.exe!NtOpenProcess") == 0xFFFFF80010002000)
check("an offset is applied",
      agent.resolve("nt!NtCreateFile+0x20") == 0xFFFFF80010001020)
check("a bare hex address still works",
      agent.resolve("0xfffff80010001000") == 0xFFFFF80010001000)
check("symbol lookup is case insensitive",
      agent.resolve("nt!ntcreatefile") == 0xFFFFF80010001000)
check("an address inside a function is named with its offset",
      agent.symbolize(0xFFFFF80010001004) == "ntoskrnl.exe!NtCreateFile+0x4",
      agent.symbolize(0xFFFFF80010001004))
check("an address in a module with no exports still names the module",
      agent.symbolize(0xFFFFF80020000100) == "svmhv.sys+0x100",
      agent.symbolize(0xFFFFF80020000100))
check("an address far past the nearest export is not given its name",
      agent.symbolize(0xFFFFF80010001000 + 0x9000) == "ntoskrnl.exe+0xa000",
      agent.symbolize(0xFFFFF80010001000 + 0x9000))
check("an address in no module is left as an address",
      agent.symbolize(0x1234) == "0x1234")

for bad, why in (("nosuch.sys!Foo", "an unloaded module"),
                 ("nt!NoSuchExport", "a symbol the module does not export")):
    try:
        agent.resolve(bad)
        check(f"rejects {why}", False)
    except agent.CtlError:
        check(f"rejects {why}", True)

# Now that symbols resolve, a hook can be asked for by name - which is the
# whole point: an address nobody can verify by eye becomes one that is checked.
calls.clear()
rpc("tools/call", {"name": "svmhv_hook_trace",
                   "arguments": {"target": "nt!NtCreateFile"}})
calls.clear()
rpc("tools/call", {"name": "svmhv_unhook",
                   "arguments": {"target": "nt!NtCreateFile"}})
check("unhook accepts a symbol too",
      calls and calls[-1] == ("unhook", "fffff80010001000"), calls)

check("a hook target may be a symbol",
      calls and calls[-1][1] == "fffff80010001000", calls)

print("trace summary")


def busy_ctl(*arguments):
    calls.append(arguments)
    if arguments[0] == "trace":
        rows = []
        for i in range(6):
            rows.append(
                f"trace seq={i} type=0 hook=1 cpu={i % 2} pid=88 tid=9 irql=0 "
                f"spoofed=0 proc=notepad.exe tsc={i} rip=0xdead rsp=0x1 "
                f"ret=0xfffff80010001000 gpa=0x3 err=0x0 "
                f"a0=0x1 a1=0x{i:x} a2=0x3 a3=0x4 s0=0x0 s1=0x0 "
                f"cap0=48656c6c6f2e74787400")
        return ("produced=6000\nring_records=4096\nrecord_size=432\n"
                + "\n".join(rows) + "\n")
    return "status=0x00000000\n"


agent.ctl = busy_ctl
text = rpc("tools/call", {"name": "svmhv_trace_summary",
                          "arguments": {"count": 6}})["result"]["content"][0]["text"]
check("the summary reports how many were produced", "6,000 records produced" in text,
      text)
check("it groups by hook", "hook 1" in text, text)
check("it tallies the process", "notepad.exe x6" in text, text)
check("it symbolizes the caller",
      "ntoskrnl.exe!NtCreateFile" in text, text)
check("a constant argument is shown with its count", "0x1 x6" in text, text)
check("an all-distinct argument is described, not listed",
      "6 distinct value(s)" in text, text)
check("captures are deduplicated", 'captured  : 1 distinct' in text, text)
agent.ctl = fake_ctl

# ------------------------------------------------------------------- memory

calls.clear()
text = rpc("tools/call", {"name": "svmhv_read", "arguments": {
    "address": "0xfffff78000000000", "length": 16}})["result"]["content"][0]["text"]
check("read returns the dump and the raw bytes",
      "hex: 48895c2408574883ec20488bd933c0c3" in text, text)
check("read passes the address without its 0x",
      calls[-1] == ("read", "fffff78000000000", "16"), calls[-1])

calls.clear()
rpc("tools/call", {"name": "svmhv_read", "arguments": {
    "address": "0x7ff600000000", "length": 32, "pid": 4321}})
check("read passes the pid through",
      calls[-1] == ("read", "7ff600000000", "32", "4321"), calls[-1])

calls.clear()
rpc("tools/call", {"name": "svmhv_read", "arguments": {
    "address": "0xffff1000", "length": 999999}})
check("read clamps the length to one page",
      calls[-1][2] == "4096", calls[-1])

text = rpc("tools/call", {"name": "svmhv_read_physical", "arguments": {
    "gpa": "0x1000"}})["result"]["content"][0]["text"]
check("a physical read reports guest physical", "guest physical" in text, text)

calls.clear()
text = rpc("tools/call", {"name": "svmhv_write", "arguments": {
    "address": "0xffff1000", "hex_bytes": "90 90 90 90"}})["result"]["content"][0]["text"]
check("write reports what it wrote", "wrote 4 of 4 bytes" in text, text)
check("write strips the spaces out of the payload",
      calls[-1] == ("write", "ffff1000", "90909090"), calls[-1])

for bad, why in (("909", "an odd number of digits"),
                 ("zz", "a non-hex digit"),
                 ("", "an empty payload")):
    text = rpc("tools/call", {"name": "svmhv_write", "arguments": {
        "address": "0xffff1000", "hex_bytes": bad}})["result"]["content"][0]["text"]
    check(f"write rejects {why}", "even number of hex digits" in text, text)


# a CtlError from the helper must come back as an isError result, not a crash
def angry_ctl(*arguments):
    raise agent.CtlError("the hypervisor did not answer")


agent.ctl = angry_ctl
result = rpc("tools/call", {"name": "svmhv_status", "arguments": {}})["result"]
check("a helper failure is reported as isError", result["isError"] is True)
check("the failure text survives", "did not answer" in result["content"][0]["text"])

print()
if failures:
    print(f"{len(failures)} check(s) failed:")
    for failure in failures:
        print(f"  - {failure}")
    sys.exit(1)

print("all checks passed")
