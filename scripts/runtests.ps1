<#
    runtests.ps1 - runs inside the guest, launched by a scheduled task so it is
    detached from PowerShell Direct.

    Loading a hypervisor from a PowerShell Direct session does not work: that
    session is itself a VMBus channel with a timeout, and it drops as soon as
    the guest stalls for a moment.  A scheduled task survives that, and the
    results land in a log file instead of on a pipe.  The driver is stopped in a
    finally block for the same reason - if anything in here throws, the run
    still has to leave the machine without a hypervisor in it.
#>
$log = 'C:\lab\results.log'
Remove-Item $log -Force -ErrorAction SilentlyContinue

function Log($msg) {
    "$((Get-Date).ToString('HH:mm:ss.fff'))  $msg" | Add-Content -Path $log -Encoding utf8
}

function Run-HvTest($label) {
    Log "----- hvtest: $label -----"
    $out = & C:\lab\hvtest.exe 2>&1
    $code = $LASTEXITCODE
    Log (($out | Out-String).TrimEnd())
    Log "hvtest exit code: $code"
    return $code
}

$run1 = -1
$run2 = -1

Log "=== svmhv test run, $([Environment]::ProcessorCount) cpus, $(Get-Date) ==="

try {
    Run-HvTest 'before load' | Out-Null

    Log "----- sc start svmhv -----"
    Log ((sc.exe start svmhv 2>&1 | Out-String) -replace '\s+', ' ')
    Start-Sleep -Seconds 3

    # Twice: the second run proves a hook can be installed, removed and
    # installed again on the same page, and that the split nested page tables
    # survive the round trip.
    $run1 = Run-HvTest 'hypervisor live, run 1'
    $run2 = Run-HvTest 'hypervisor live, run 2'

    # TSC compensation is per-processor, so the thing worth checking is whether
    # a thread moving between processors can ever see the clock go backwards.
    Log "----- clock monotonicity across processors -----"
    try {
        $p = Get-Process -Id $PID
        $original = $p.ProcessorAffinity
        $cpus = [Environment]::ProcessorCount
        $worst = 0
        $freq = [Diagnostics.Stopwatch]::Frequency
        for ($i = 0; $i -lt 300; $i++) {
            for ($c = 0; $c -lt $cpus; $c++) {
                $a = [Diagnostics.Stopwatch]::GetTimestamp()
                $p.ProcessorAffinity = [IntPtr][int64][math]::Pow(2, $c)
                $b = [Diagnostics.Stopwatch]::GetTimestamp()
                if (($b - $a) -lt $worst) { $worst = $b - $a }
            }
        }
        $p.ProcessorAffinity = $original
        Log ("worst backwards step over {0} migrations: {1} ticks ({2:N4} ms), frequency {3}" -f `
             (300 * $cpus), $worst, ($worst / $freq * 1000), $freq)
    } catch {
        Log "clock check failed: $_"
    }
}
catch {
    Log "EXCEPTION: $_"
}
finally {
    Log "----- sc stop svmhv -----"
    Log ((sc.exe stop svmhv 2>&1 | Out-String) -replace '\s+', ' ')
    Start-Sleep -Seconds 3
    Run-HvTest 'after unload' | Out-Null
    Log "=== RESULT: run1=$run1 run2=$run2 (0 = all checks passed) ==="
    Log "=== done ==="
}
