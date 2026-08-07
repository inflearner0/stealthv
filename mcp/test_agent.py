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
check("tools/list returns every tool", len(tools) == 11, f"got {len(tools)}")
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

calls.clear()
text = rpc("tools/call", {"name": "svmhv_hook_trace", "arguments": {
    "target": "0xffff1000", "process": "notepad.exe",
    "capture": "1:objattr", "spoof": "2:0"}})["result"]["content"][0]["text"]
check("hook_trace reports the new hook", "hook id    : 1" in text, text)
check("hook_trace passes the options through",
      calls[-1] == ("hook-trace", "ffff1000", "14", "--process", "notepad.exe",
                    "--capture", "1:objattr", "--spoof", "2:0"), calls[-1])

text = rpc("tools/call", {"name": "svmhv_hooks", "arguments": {}})["result"]["content"][0]["text"]
# the renderer zero-pads addresses to 16 digits, so match the digits only
check("hooks renders a record",
      "active" in text and "ffff1000" in text.lower(), text)

text = rpc("tools/call", {"name": "svmhv_watch",
                          "arguments": {"target": "0xffff1000", "mode": "sideways"}})["result"]["content"][0]["text"]
check("watch rejects an unknown mode", "must be" in text)


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
