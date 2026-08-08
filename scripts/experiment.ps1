<#
    experiment.ps1 - run something against the guest with a way back.

    Every risky thing this project does - installing a hook, running a stub,
    loading a rebuilt driver - can take the guest down, and recovering by hand
    costs ten to twenty minutes: reset, wait for boot, redeploy binaries,
    restart the agent, reload the driver.  A checkpoint turns that into about
    thirty seconds, which is the difference between exploring and being careful.

    This lives on the host rather than in the agent because the agent runs
    *inside* the guest and cannot ask Hyper-V for anything.

        .\experiment.ps1 -Name "user-mode hook" -Script {
            & $mcp call svmhv_hook_shellcode '{"target":"nt!NtCreateFile", ...}'
        }

    The checkpoint is taken with the driver stopped, so the snapshot never
    contains a processor sitting inside VMRUN - restoring one that did would
    resume a guest whose host state no longer exists.

    -Keep leaves the checkpoint behind; by default it is removed on success so
    a session does not accumulate dozens of them.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][scriptblock]$Script,
    [string]$VMName = "Windows 11 dev environment",
    [string]$Guest = "172.17.120.157",
    [int]$Port = 8765,
    [switch]$Keep,
    [switch]$RevertAlways
)

$ErrorActionPreference = "Stop"
$mcp = Join-Path $PSScriptRoot "mcp.ps1"
if (-not (Test-Path $mcp)) { $mcp = Join-Path (Split-Path $PSScriptRoot) "scripts\mcp.ps1" }

function Invoke-Mcp($toolName, $arguments = '{}') {
    & $mcp call $toolName $arguments -Guest $Guest -Port $Port
}

function Test-GuestAlive {
    try {
        $body = '{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}'
        Invoke-RestMethod -Uri "http://${Guest}:${Port}/mcp" -Method Post `
            -TimeoutSec 20 -ContentType 'application/json' -Body $body | Out-Null
        return $true
    } catch { return $false }
}

$checkpoint = "experiment-$([DateTime]::Now.ToString('HHmmss'))"

Write-Host "[$Name] stopping the driver so the checkpoint has no processor in guest mode" -ForegroundColor DarkGray
try { Invoke-Mcp svmhv_service '{"action":"unload"}' | Out-Null } catch { }

Write-Host "[$Name] checkpoint $checkpoint" -ForegroundColor Cyan
Checkpoint-VM -Name $VMName -SnapshotName $checkpoint

$reverted = $false
try {
    Invoke-Mcp svmhv_service '{"action":"load"}' | Out-Null
    Write-Host "[$Name] running" -ForegroundColor Cyan
    & $Script

    if ($RevertAlways) {
        Write-Host "[$Name] reverting as asked" -ForegroundColor Yellow
        Restore-VMSnapshot -VMName $VMName -Name $checkpoint -Confirm:$false
        Start-VM -Name $VMName -ErrorAction SilentlyContinue
        $reverted = $true
    }
}
catch {
    Write-Warning "[$Name] failed: $_"
    throw
}
finally {
    if (-not $reverted) {
        # The guest not answering is the case this exists for: it is either
        # wedged or rebooting, and either way the checkpoint is the way back.
        if (-not (Test-GuestAlive)) {
            Write-Warning "[$Name] the guest is not answering - restoring $checkpoint"
            Restore-VMSnapshot -VMName $VMName -Name $checkpoint -Confirm:$false
            Start-VM -Name $VMName -ErrorAction SilentlyContinue
            $reverted = $true
        }
    }

    if (-not $Keep) {
        Remove-VMSnapshot -VMName $VMName -Name $checkpoint -ErrorAction SilentlyContinue
    }
    Write-Host "[$Name] done (reverted: $reverted)" -ForegroundColor DarkGray
}
