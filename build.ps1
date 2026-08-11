<#
    build.ps1 - builds svmhv.sys, svmhvctl.exe and hvtest.exe with cl/ml64/link
    directly.

    No .vcxproj, no msbuild: the WDK ships everything needed on the command
    line, and a hand-written build is easier to read than a project file when
    the thing you want to know is which flags the driver is compiled with.

        .\build.ps1            # compile + link
        .\build.ps1 -Sign      # also create/reuse a test certificate and sign
        .\build.ps1 -Fixtures  # also build tools\umtarget.exe, a hook target

    driver\    the kernel driver
    include\   the control interface, shared with the tools
    tools\     svmhvctl.exe (the CPUID client) and hvtest.exe (the probe)
    bin\       output, not in source control
#>
[CmdletBinding()]
param(
    [switch]$Sign,
    [switch]$Fixtures,          # tools\umtarget.exe; see the section below
    [string]$SdkVersion,        # default: newest WDK with km\ headers
    [string]$VsPath,            # default: whatever vswhere reports
    [string]$KitRoot            # default: Program Files (x86)\Windows Kits\10
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$out  = Join-Path $root "bin"

# ---------------------------------------------------------------- toolchain
# Discovered rather than hardcoded, because this also has to build on a CI
# runner where nothing is where it is on a developer's machine.  -VsPath,
# -SdkVersion and -KitRoot override any of it.

function Find-VisualStudio {
    if ($VsPath) { return $VsPath }

    $vswhere = Join-Path ${env:ProgramFiles(x86)} `
                         "Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $found = & $vswhere -latest -products * `
                    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
                    -property installationPath 2>$null
        if ($found) { return ($found | Select-Object -First 1) }
    }

    # vswhere is missing on some Build Tools installs; fall back to looking.
    foreach ($base in @("${env:ProgramFiles}\Microsoft Visual Studio",
                        "${env:ProgramFiles(x86)}\Microsoft Visual Studio")) {
        if (-not (Test-Path $base)) { continue }
        $candidate = Get-ChildItem $base -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending |
            ForEach-Object { Get-ChildItem $_.FullName -Directory -ErrorAction SilentlyContinue } |
            Where-Object { Test-Path (Join-Path $_.FullName "VC\Tools\MSVC") } |
            Select-Object -First 1
        if ($candidate) { return $candidate.FullName }
    }

    throw "no Visual Studio with the C++ toolset found; pass -VsPath"
}

$vsRoot = Find-VisualStudio
$msvc = Get-ChildItem "$vsRoot\VC\Tools\MSVC" -Directory |
            Sort-Object Name -Descending | Select-Object -First 1
if (-not $msvc) { throw "no MSVC toolset under $vsRoot" }
$msvc = $msvc.FullName

$kit = $KitRoot
if (-not $kit) { $kit = "${env:ProgramFiles(x86)}\Windows Kits\10" }
if (-not (Test-Path $kit)) { throw "Windows Kits not found: $kit" }

# The WDK is a separate install from the SDK, and only the versions that
# actually ship km\ headers are usable here.
if (-not $SdkVersion) {
    $SdkVersion = Get-ChildItem "$kit\Include" -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path (Join-Path $_.FullName "km") } |
        Sort-Object Name -Descending |
        Select-Object -First 1 -ExpandProperty Name
}
if (-not $SdkVersion) {
    throw "no WDK found under $kit\Include (needs a version with km\ headers)"
}
if (-not (Test-Path "$kit\Lib\$SdkVersion\km\x64")) {
    throw "WDK libraries missing: $kit\Lib\$SdkVersion\km\x64"
}

$cl   = "$msvc\bin\Hostx64\x64\cl.exe"
$ml64 = "$msvc\bin\Hostx64\x64\ml64.exe"
$link = "$msvc\bin\Hostx64\x64\link.exe"

foreach ($t in @($cl, $ml64, $link)) {
    if (-not (Test-Path $t)) { throw "missing tool: $t" }
}

Write-Host "toolset : $msvc" -ForegroundColor DarkGray
Write-Host "wdk     : $kit ($SdkVersion)" -ForegroundColor DarkGray

if (-not (Test-Path $out)) { New-Item -ItemType Directory $out | Out-Null }

# cl and link need the toolchain's own directory on PATH (mspdb*.dll etc).
$env:PATH = "$msvc\bin\Hostx64\x64;$kit\bin\$SdkVersion\x64;$env:PATH"

function Invoke-Tool {
    # NB: do not name the parameter $Args - it collides with the automatic
    # variable and silently swallows every argument.
    param([string]$Exe, [string[]]$ToolArgs, [string]$What)
    Write-Host "[$What]" -ForegroundColor Cyan
    & $Exe @ToolArgs
    if ($LASTEXITCODE -ne 0) { throw "$What failed (exit $LASTEXITCODE)" }
}

# ------------------------------------------------------------------ driver
# Order matters: the WDK's km\crt must win over the user-mode CRT headers,
# otherwise <string.h> resolves to a mix of both and falls apart.
$kmInc = @(
    "/I$root\include",
    "/I$kit\Include\$SdkVersion\km\crt",
    "/I$kit\Include\$SdkVersion\km",
    "/I$kit\Include\$SdkVersion\shared",
    "/I$msvc\include",
    "/I$kit\Include\$SdkVersion\ucrt"
)

# /kernel already defines _KERNEL_MODE.
$kmDefs = @(
    "/D_AMD64_", "/DAMD64", "/D_WIN64",
    "/DNTDDI_VERSION=0x0A00000C", "/D_WIN32_WINNT=0x0A00", "/DWINVER=0x0A00"
)

$kmSources = @("svmhv.c", "npt.c", "hook.c", "trace.c", "step.c", "control.c",
               "hvcall.c", "memory.c", "objects.c", "snapshot.c", "call.c",
               "ibs.c")

foreach ($src in $kmSources) {
    $obj = [IO.Path]::ChangeExtension($src, ".obj")
    Invoke-Tool $cl (@(
        "/nologo", "/c", "/W4", "/WX", "/O2", "/Oi", "/GS-", "/Gy", "/Zi", "/FC",
        "/Zc:wchar_t", "/Zc:inline", "/kernel",
        "/wd4324"   # VIRTUAL_CPU is page-aligned on purpose
    ) + $kmDefs + $kmInc + @(
        "/Fo$out\$obj", "/Fd$out\svmhv.pdb", "$root\driver\$src"
    )) "cl $src"
}

Invoke-Tool $ml64 @(
    "/nologo", "/c", "/W3", "/Zi",
    "/Fo", "$out\svmasm.obj", "$root\driver\svmasm.asm"
) "ml64 svmasm.asm"

# The object list is derived from $kmSources rather than written out again: the
# two used to be separate, and adding a file to one and not the other links a
# driver with everything in it missing - which surfaces as unresolved externals
# named after the callers, never after the file that was forgotten.
$kmObjects = @($kmSources | ForEach-Object {
    "$out\" + [IO.Path]::ChangeExtension($_, ".obj")
})

Invoke-Tool $link (@(
    "/nologo", "/DRIVER", "/SUBSYSTEM:NATIVE,10.00", "/ENTRY:DriverEntry",
    "/NODEFAULTLIB", "/INCREMENTAL:NO", "/RELEASE", "/DEBUG",
    "/OPT:REF", "/OPT:ICF", "/MANIFEST:NO",
    "/LIBPATH:$kit\Lib\$SdkVersion\km\x64",
    "ntoskrnl.lib", "hal.lib",
    "/PDB:$out\svmhv.pdb", "/OUT:$out\svmhv.sys"
) + $kmObjects + @("$out\svmasm.obj")) "link svmhv.sys"

# --------------------------------------------------------------- test app
$umInc = @(
    "/I$root\include",
    "/I$msvc\include",
    "/I$kit\Include\$SdkVersion\um",
    "/I$kit\Include\$SdkVersion\shared",
    "/I$kit\Include\$SdkVersion\ucrt"
)

# The ring-3 side of the VMMCALL channel, shared by both tools.  It has to be
# assembled: the ABI puts the magic in RAX and the command in RBX, which no
# compiler intrinsic can reach, and MSVC has no inline assembler on x64.
Invoke-Tool $ml64 @(
    "/nologo", "/c", "/W3", "/Zi",
    "/Fo", "$out\hvasm.obj", "$root\tools\hvasm.asm"
) "ml64 hvasm.asm"

Invoke-Tool $cl (@("/nologo", "/W4", "/O2", "/MT", "/Zi", "/FC") + $umInc + @(
    "/Fo$out\", "/Fd$out\hvtest.pdb", "/Fe$out\hvtest.exe", "$root\tools\hvtest.c",
    "$out\hvasm.obj",
    "/link", "/INCREMENTAL:NO",
    "/LIBPATH:$msvc\lib\x64",
    "/LIBPATH:$kit\Lib\$SdkVersion\um\x64",
    "/LIBPATH:$kit\Lib\$SdkVersion\ucrt\x64"
)) "cl hvtest.c"

# -------------------------------------------------------- control helper

Invoke-Tool $cl (@("/nologo", "/W4", "/WX", "/O2", "/MT", "/Zi", "/FC") + $umInc + @(
    "/Fo$out\", "/Fd$out\svmhvctl.pdb", "/Fe$out\svmhvctl.exe",
    "$root\tools\svmhvctl.c", "$out\hvasm.obj",
    "/link", "/INCREMENTAL:NO",
    "/LIBPATH:$msvc\lib\x64",
    "/LIBPATH:$kit\Lib\$SdkVersion\um\x64",
    "/LIBPATH:$kit\Lib\$SdkVersion\ucrt\x64"
)) "cl svmhvctl.c"

# ------------------------------------------------- user-mode hook target
# Something for a user-mode execution hook to hook; see tools\umtarget.c.
#
# Off by default, and it should be: it is a fixture, not a part of the product.
# Nothing ships it, the CI artefact list does not mention it, and building it
# unconditionally puts a file nobody asked for in every build - including on
# toolchains this has never been compiled with. -Fixtures when you want it.

if ($Fixtures) {
    Invoke-Tool $cl (@("/nologo", "/W4", "/WX", "/O2", "/MT", "/Zi", "/FC") + $umInc + @(
        "/Fo$out\", "/Fd$out\umtarget.pdb", "/Fe$out\umtarget.exe",
        "$root\tools\umtarget.c",
        "/link", "/INCREMENTAL:NO",
        "/LIBPATH:$msvc\lib\x64",
        "/LIBPATH:$kit\Lib\$SdkVersion\um\x64",
        "/LIBPATH:$kit\Lib\$SdkVersion\ucrt\x64"
    )) "cl umtarget.c"
}

# ------------------------------------------------------------------ signing
if ($Sign) {
    $signtool = "$kit\bin\$SdkVersion\x64\signtool.exe"
    $cert = Get-ChildItem Cert:\CurrentUser\My |
                Where-Object { $_.Subject -eq "CN=svmhv-test" } |
                Select-Object -First 1
    if (-not $cert) {
        Write-Host "[creating test certificate CN=svmhv-test]" -ForegroundColor Cyan
        $cert = New-SelfSignedCertificate -Subject "CN=svmhv-test" `
                    -Type CodeSigningCert -CertStoreLocation Cert:\CurrentUser\My `
                    -KeyUsage DigitalSignature -NotAfter (Get-Date).AddYears(5)
    }
    Invoke-Tool $signtool @(
        "sign", "/v", "/fd", "SHA256", "/sha1", $cert.Thumbprint,
        "$out\svmhv.sys"
    ) "signtool"

    # Export the public cert so the guest can trust it.
    Export-Certificate -Cert $cert -FilePath "$out\svmhv-test.cer" -Force | Out-Null
    Write-Host "certificate exported to $out\svmhv-test.cer"
}

Write-Host ""
Write-Host "built:" -ForegroundColor Green
Get-ChildItem "$out\svmhv.sys", "$out\hvtest.exe", "$out\svmhvctl.exe" |
    Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
