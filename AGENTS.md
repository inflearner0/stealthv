# Repository Guidelines

## Project Structure & Module Organization

- `driver/` contains the Windows x64 AMD-V kernel driver; keep hypervisor, nested-page-table, hook, trace, and control logic in their existing focused modules.
- `include/svmhvctl.h` is the ABI shared by the driver and user-mode tools. Treat layout and constant changes here as cross-component changes.
- `tools/` contains `svmhvctl` and `hvtest` C clients plus the x64 assembly call stub.
- `mcp/` contains the dependency-free Python MCP HTTP agent and `test_agent.py`.
- `scripts/` holds guest/lab automation. `bin/` is generated output and must not be committed.

## Build, Test, and Development Commands

Use PowerShell on Windows with Visual Studio C++ tools and the Windows Driver Kit installed:

```powershell
.\build.ps1          # builds bin\svmhv.sys, svmhvctl.exe, and hvtest.exe
.\build.ps1 -Sign    # builds and test-signs the driver for a lab guest
python mcp/test_agent.py  # runs MCP protocol and command-building tests
```

Run `scripts\runtests.ps1` only inside the isolated guest lab; it loads the driver and records results in `C:\lab\results.log`. Do not treat a short successful run as a stability result; see `CLAUDE.md` for known reset behavior.

## Coding Style & Naming Conventions

Follow the surrounding code. C uses four-space indentation, braces on their own line, descriptive block comments, and Windows kernel naming such as `SvHookInstall`, `SVMHV_CONTROL`, and `g_Control`. Keep driver exit-path code allocation-free and nonpageable where its context requires it. Python uses four spaces, `snake_case`, and standard-library-only behavior; optional capstone/keystone support must retain the fallback path. Build warnings are errors for the driver and control tool.

## Testing Guidelines

Run the agent tests with and without optional engines when changing `mcp/`:

```powershell
$env:SVMHV_NO_ENGINES = '1'; python mcp/test_agent.py
Remove-Item Env:SVMHV_NO_ENGINES; python mcp/test_agent.py
python -m compileall -q mcp
```

For ABI changes, rebuild all targets so C layout assertions are checked. Add focused assertions to `mcp/test_agent.py` for new agent behavior. Hardware-facing validation belongs in an owned, isolated AMD-SVM guest.

## Commit & Pull Request Guidelines

Use short, imperative commit subjects, e.g. `Recover the control codes a driver handles`. Keep commits narrowly scoped. PRs should explain the behavior and risk, identify affected driver/tool/agent interfaces, link relevant issues, and include test commands and results. Include logs or screenshots for guest-lab behavior; never commit binaries, PDBs, certificates, secrets, or `bin/` contents.
