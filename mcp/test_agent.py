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
check("capture_stack is its own flag",
      agent.hook_options(capture_stack=True) == ["--capture-stack"],
      agent.hook_options(capture_stack=True))

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
def hexdump(address, raw):
    """svmhvctl's dump format, which the agent parses back into bytes."""
    out = [f"bytes={len(raw)}"]
    for offset in range(0, len(raw), 16):
        chunk = raw[offset:offset + 16]
        out.append(f"{address + offset:016x}  "
                   + " ".join(f"{b:02x}" for b in chunk))
    return "\n".join(out) + "\n"


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
    if arguments[0] == "driverobj":
        if arguments[1] == "onedispatch":
            return "status=0x00000000\ndriver_object=0xffffab0000003000\n"
        return "status=0x00000000\ndriver_object=0xffffab0000001000\n"
    if arguments[0] == "read" and arguments[1] == "ffffab0000003000":
        # Every slot pointing at one function inside the image, which is what
        # partmgr does and what the majority rule used to mistake for "unset".
        raw = bytearray(0x150)
        raw[0x18:0x20] = (0xfffff80000010000).to_bytes(8, "little")
        raw[0x20:0x24] = (0x30000).to_bytes(4, "little")
        for slot in range(28):
            raw[0x70 + slot * 8:0x78 + slot * 8] = \
                (0xfffff80000011f00).to_bytes(8, "little")
        return "status=0x00000000\n" + hexdump(0xffffab0000003000, bytes(raw))
    if arguments[0] == "read" and arguments[1] == "ffffab0000001000":
        # A DRIVER_OBJECT with one dispatch slot set: IRP_MJ_DEVICE_CONTROL is
        # index 14, so its handler lands at 0x70 + 14 * 8.
        raw = bytearray(0x150)
        raw[0x70 + 14 * 8:0x70 + 14 * 8 + 8] = (0xffffab0000002000).to_bytes(8, "little")
        return "status=0x00000000\n" + hexdump(0xffffab0000001000, bytes(raw))
    if arguments[0] == "read" and arguments[1] == "ffffab0000002000":
        # cmp eax, 0x222400 - FILE_DEVICE_UNKNOWN with a function in the vendor
        # range, which is what a driver defining its own codes writes - then a
        # constant that is not shaped like one, and an NTSTATUS, which decodes
        # as a plausible control code and must not be reported as one.
        code = bytes.fromhex("3d00242200") + bytes.fromhex("7402") \
             + bytes.fromhex("3d34120000") \
             + bytes.fromhex("3d050000c0") + b"\xc3"
        return "status=0x00000000\n" + hexdump(0xffffab0000002000, code)
    if arguments[0] in ("read", "readphys"):
        # The hook tools decode this as a prologue, so it has to be
        # instructions - an MZ header is not, and a strict decoder is right to
        # refuse it. This is a real one: mov [rsp+8],rbx / push rdi /
        # sub rsp,0x20 / mov rbx,rcx / xor eax,eax / ret.
        return ("status=0x00000000\nbytes=16\n"
                "fffff78000000000  48 89 5c 24 08 57 48 83 ec 20 48 8b d9 33 c0 c3"
                "  H..$.WH.. H..3..\n")
    if arguments[0] == "probe":
        if fake_ctl.folded:
            # What the linker did to the first version: four names, one
            # address, and an identification that cannot mean anything.
            return ("status=0x00000000\nprobe process=0xfffff80000020000\n"
                    "probe thread=0xfffff80000020000\n"
                    "probe image=0xfffff80000020000\n"
                    "probe registry=0xfffff80000020000\n"
                    "probe distinct=0\nprobe hits=0,0,0,0\n")
        return ("status=0x00000000\nprobe process=0xfffff80000020000\n"
                "probe thread=0xfffff80000020010\n"
                "probe image=0xfffff80000020020\n"
                "probe registry=0xfffff80000020030\n"
                "probe distinct=1\nprobe hits=1,2,3,4\n")
    if arguments[0] == "devices":
        if arguments[1] == "quiet":
            return "status=0x00000000\ndevices=0\n"
        return ("status=0x00000000\n"
                "device 0xffffab0011112220 type=0x22 flags=0x40 chars=0x100 "
                "ext=0xffffab0011112370 stack=1 name=\\Device\\Null\n"
                "  attached 0xffffab0022223330 driver=0xffffab0033334440 "
                "name=\\Driver\\Snoop\n"
                "devices=1\n")
    if arguments[0] == "symlinks":
        if arguments[1] == "0":
            return ("status=0x00000000\n"
                    "link NUL -> \\Device\\Null\n"
                    "next=1\n"
                    "links=1\n")
        return ("status=0x00000000\n"
                "link PhysicalDrive0 -> \\Device\\Harddisk0\\DR0\n"
                "links=1\n")
    if arguments[0] == "translate":
        if arguments[1] == "dead":
            return "status=0x00000000\nva=0xdead not mapped\n"
        return "status=0x00000000\nva=0xffff1234\ngpa=0x1a2b234\n"
    if arguments[0] in ("write", "writephys"):
        return "status=0x00000000\nwritten=4\n"
    if arguments[0].startswith("hook-") and fake_ctl.hook_fails:
        return "status=0xc000000d\n"
    return "status=0x00000000\nhookid=1\ngpa=0x1000\ntrampoline=0x2000\n"


fake_ctl.folded = False
fake_ctl.hook_fails = False
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

calls.clear()
text = rpc("tools/call", {"name": "svmhv_write_physical", "arguments": {
    "gpa": "0x1000", "hex_bytes": "de ad be ef"}})["result"]["content"][0]["text"]
check("a physical write reports what it wrote",
      "wrote 4 of 4 bytes at guest physical" in text, text)
check("a physical write takes no pid",
      calls[-1] == ("writephys", "1000", "deadbeef"), calls[-1])

# The filter that decides whether an address is one of the callback arrays.
# It is the thing standing between this tool and dereferencing arbitrary
# numbers as kernel pointers, which reset the machine once.
def array_bytes(values):
    raw = bytearray(agent.CALLBACK_SLOTS * 8)
    for index, value in enumerate(values):
        raw[index * 8:index * 8 + 8] = value.to_bytes(8, "little")
    return raw


check("an empty array is not a callback table",
      agent.array_shape(array_bytes([])) is None)
check("a table with a gap in it is refused",
      agent.array_shape(array_bytes(
          [0xffffab0000001001, 0, 0xffffab0000002001])) is None)
check("a densely populated region is refused",
      agent.array_shape(array_bytes(
          [0xffffab0000001000 + i * 0x100 + 1 for i in range(20)])) is None)
check("the same entry twice is refused",
      agent.array_shape(array_bytes(
          [0xffffab0000001001, 0xffffab0000001002])) is None)
check("a user-mode pointer is refused",
      agent.array_shape(array_bytes([0x00007ff600001001])) is None)
check("a plausible table is accepted",
      agent.array_shape(array_bytes(
          [0xffffab0000001001, 0xffffab0000002003]))
      == [0xffffab0000001000, 0xffffab0000002000])

check("irp is an accepted capture type",
      agent.hook_options(capture="1:irp") == ["--capture", "1:irp"],
      agent.hook_options(capture="1:irp"))

calls.clear()
text = rpc("tools/call", {"name": "svmhv_watch_ioctls", "arguments": {
    "name": "victim"}})["result"]["content"][0]["text"]
check("watching ioctls hooks the DEVICE_CONTROL handler",
      any(c[0] == "hook-trace" and c[1] == "ffffab0000002000" for c in calls),
      calls)
check("watching ioctls captures the IRP, which is argument 1",
      any("1:irp" in c for c in calls), calls)
check("watching ioctls says how to read the results",
      "svmhv_trace" in text and "svmhv_unhook" in text, text)
check("watching ioctls warns that a shared dispatcher floods the ring",
      "svmhv_trace_reset" in text, text)

fake_ctl.hook_fails = True
text = rpc("tools/call", {"name": "svmhv_watch_ioctls", "arguments": {
    "name": "victim"}})["result"]["content"][0]["text"]
check("a hook that did not install is not reported as watching",
      "could not hook" in text and "Read them with" not in text, text)
fake_ctl.hook_fails = False

text = rpc("tools/call", {"name": "svmhv_watch_ioctls", "arguments": {
    "name": "onedispatch"}})["result"]["content"][0]["text"]
check("a driver that does not handle device control is not hooked",
      "nothing to watch" in text or "hook" in text, text)

probes = agent.probe_addresses(True)
check("the probe reports one address per kind",
      len(set(probes.values())) == 4, probes)
check("the probe's hit counts are not mistaken for an address",
      "hits" not in probes and "distinct" not in probes, probes)

fake_ctl.folded = True
try:
    agent.probe_addresses(True)
    check("probes sharing an address are refused", False)
except agent.CtlError as error:
    check("probes sharing an address are refused",
          "cannot tell the callback arrays apart" in str(error), error)
fake_ctl.folded = False

text = rpc("tools/call", {"name": "svmhv_driver", "arguments": {
    "name": "onedispatch"}})["result"]["content"][0]["text"]
check("one dispatcher for every slot is not mistaken for an empty table",
      "every slot ->" in text and "0xfffff80000011f00" in text, text)
check("a single dispatcher is still offered as a hook target",
      "svmhv_hook_trace" in text, text)

length, text, _ = agent.disassemble_one(bytes.fromhex("3d0824409c"), 0, 0x1000)
check("a 32-bit immediate is not rendered as a negative number",
      text == "cmp eax, 0x9c402408", text)
length, text, _ = agent.disassemble_one(bytes.fromhex("4883f8ff"), 0, 0x1000)
check("an imm8 still reads as the small negative it is",
      text in ("cmp rax, -0x1", "cmp rax, -1"), text)   # capstone drops the 0x

text = rpc("tools/call", {"name": "svmhv_ioctl", "arguments": {
    "code": "0x22e004"}})["result"]["content"][0]["text"]
check("an ioctl decodes to its device type", "UNKNOWN" in text, text)
check("an ioctl decodes to its method", "METHOD_BUFFERED" in text or
      "method        : BUFFERED" in text, text)

text = rpc("tools/call", {"name": "svmhv_ioctl", "arguments": {
    "code": "0x22e003"}})["result"]["content"][0]["text"]
check("METHOD_NEITHER is called out as the dangerous one",
      "METHOD_NEITHER" in text and "probe them itself" in text, text)

text = rpc("tools/call", {"name": "svmhv_ioctl", "arguments": {
    "code": "not a number"}})["result"]["content"][0]["text"]
check("a bad ioctl code is refused", "is not a number" in text, text)

text = rpc("tools/call", {"name": "svmhv_ioctls", "arguments": {
    "name": "victim"}})["result"]["content"][0]["text"]
check("ioctls finds the code the dispatcher compares against",
      "0x00222400" in text, text)
check("ioctls does not report a constant that is not shaped like one",
      "0x00001234" not in text, text)
check("ioctls does not mistake an NTSTATUS for a control code",
      "0xc0000005" not in text, text)
check("ioctls says which dispatch slot it read",
      "IRP_MJ_DEVICE_CONTROL" in text, text)
check("ioctls reports an unhandled slot as unhandled",
      "IRP_MJ_INTERNAL_DEVICE_CONTROL: not handled" in text, text)

text = rpc("tools/call", {"name": "svmhv_devices", "arguments": {
    "name": "null"}})["result"]["content"][0]["text"]
check("devices names the device", "\\Device\\Null" in text, text)
check("devices shows what is filtering it", "\\Driver\\Snoop" in text, text)
check("devices counts them", "1 device object(s)" in text, text)
check("devices does not echo the count line back", "devices=1" not in text, text)

text = rpc("tools/call", {"name": "svmhv_devices", "arguments": {
    "name": "quiet"}})["result"]["content"][0]["text"]
check("a driver with no devices is said to be unreachable by name",
      "owns no device objects" in text, text)

calls.clear()
text = rpc("tools/call", {"name": "svmhv_symlinks", "arguments": {}})["result"]["content"][0]["text"]
check("symlinks follows the resume index",
      calls == [("symlinks", "0"), ("symlinks", "1")], calls)
check("symlinks reports both pages", "2 of 2 symbolic link(s)" in text, text)

text = rpc("tools/call", {"name": "svmhv_symlinks", "arguments": {
    "contains": "harddisk"}})["result"]["content"][0]["text"]
check("symlinks filters on the target as well as the name",
      "PhysicalDrive0" in text and "NUL ->" not in text, text)

text = rpc("tools/call", {"name": "svmhv_symlinks", "arguments": {
    "contains": "nothing-like-this"}})["result"]["content"][0]["text"]
check("symlinks says how many it looked at when nothing matches",
      "2 link(s) looked at" in text, text)

calls.clear()
text = rpc("tools/call", {"name": "svmhv_translate", "arguments": {
    "address": "0xffff1234"}})["result"]["content"][0]["text"]
check("translate reports the physical address", "0x1a2b234" in text, text)
check("translate splits the page from the offset",
      "page 0x1a2b000, offset 0x234" in text, text)
check("translate defaults to kernel space",
      calls[-1] == ("translate", "ffff1234"), calls[-1])

calls.clear()
text = rpc("tools/call", {"name": "svmhv_translate", "arguments": {
    "address": "0x7ff600001000", "pid": 4}})["result"]["content"][0]["text"]
check("translate passes a pid through",
      calls[-1] == ("translate", "7ff600001000", "4"), calls[-1])
check("translate names the process it looked in", "process 4" in text, text)

text = rpc("tools/call", {"name": "svmhv_translate", "arguments": {
    "address": "0xdead"}})["result"]["content"][0]["text"]
check("translate says so when nothing is mapped", "is not mapped" in text, text)

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
