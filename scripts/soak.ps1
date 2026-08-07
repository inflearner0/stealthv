<#
    soak.ps1 - runs inside the guest, launched by a scheduled task so it is
    detached from PowerShell Direct.

    Loads svmhv, hammers the paths that would expose a broken hypervisor -
    process creation, file I/O over VMBus-backed storage, and CPU-bound work
    across every processor - then unloads and reports.

    Note: do NOT break into the kernel debugger during a run.  Halting every
    CPU for tens of seconds trips PowerShell Direct's session timeout and, if
    you hold it long enough, the VMBus channels of the integration services
    too - which looks exactly like the hypervisor having broken VMBus.
#>
param([int]$DurationSeconds = 180)

$log = "C:\lab\soak.log"
Remove-Item $log -Force -ErrorAction SilentlyContinue

# Write-through, and flushed to the platter on every line.  A soak run is
# exactly the situation where the machine may have to be powered off under it,
# and a log sitting in the cache when that happens is no log at all - the first
# attempt at this lost 281 bytes of results to a hard reset.
function Log($msg) {
    $bytes = [Text.Encoding]::UTF8.GetBytes("$((Get-Date).ToString('HH:mm:ss.fff'))  $msg`r`n")
    $fs = New-Object IO.FileStream($log, [IO.FileMode]::Append, [IO.FileAccess]::Write,
                                   [IO.FileShare]::Read, 4096, [IO.FileOptions]::WriteThrough)
    try { $fs.Write($bytes, 0, $bytes.Length); $fs.Flush($true) } finally { $fs.Dispose() }
}

# Hyper-V's key-value pair channel, which the host can read with WMI whether or
# not PowerShell Direct is alive - and it is not, once a hypervisor is resident.
$kvp = 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters'
function Status($msg) {
    try { Set-ItemProperty -Path $kvp -Name SvmhvSoak -Value $msg -ErrorAction Stop } catch { }
}

$scratch = "C:\lab\scratch"
New-Item -ItemType Directory $scratch -Force | Out-Null

# Defender scanning every blob this script writes turns a three minute run into
# a twenty minute one and puts the contention in the wrong place: the point is
# to stress the hypervisor, not the antimalware filter.
try {
    Add-MpPreference -ExclusionPath C:\lab -ErrorAction Stop
    Log "defender exclusion added for C:\lab"
} catch {
    Log "could not add defender exclusion: $_"
}

$procFail = 0; $procTotal = 0
$ioFail   = 0; $ioTotal   = 0
$hvFail   = 0; $hvTotal   = 0
$hookFail = 0; $hookTotal = 0

Log "=== soak start ($DurationSeconds s), $([Environment]::ProcessorCount) cpus"
Log "start: $((sc.exe start svmhv | Out-String) -replace '\s+', ' ')"

try {
    # CPU-bound background load on half the processors, to keep the other vcpus
    # exiting without starving the loop below of a core to run on.
    $jobs = 1..([math]::Max(1, [Environment]::ProcessorCount / 2)) | ForEach-Object {
        Start-Job { $e = (Get-Date).AddSeconds($using:DurationSeconds)
                    while ((Get-Date) -lt $e) { $null = [math]::Sqrt((Get-Random)) } }
    }

    $deadline = (Get-Date).AddSeconds($DurationSeconds)
    $i = 0
    while ((Get-Date) -lt $deadline) {
        $i++
        $iterationStart = Get-Date

        # 1. Is the hypervisor still installed, and does the hook still work?
        #    hvtest installs and removes an NPT hook on every run, so this also
        #    soaks the page-splitting and the view switching.
        $hvTotal++; $hookTotal++
        $out = & C:\lab\hvtest.exe 2>&1 | Out-String
        if ($out -notmatch 'svmhv\s+: PRESENT') { $hvFail++; Log "HV CHECK FAILED: $out" }
        if ($out -notmatch 'reading the hooked function returns the original bytes' -or
            $out -match '\[FAIL\] reading') { $hookFail++; Log "HOOK CHECK FAILED: $out" }

        # 2. Process creation (the fork/clone paths that crashed the kernel before).
        for ($j = 0; $j -lt 10; $j++) {
            $procTotal++
            if ((& cmd.exe /c "echo alive" 2>&1) -notmatch 'alive') { $procFail++ }
        }

        # 3. File I/O - storage runs over VMBus, so this exercises hypercalls hard.
        for ($j = 0; $j -lt 3; $j++) {
            $ioTotal++
            $f = Join-Path $scratch "blob$j.bin"
            $data = [byte[]]::new(128KB)
            (New-Object Random).NextBytes($data)
            [IO.File]::WriteAllBytes($f, $data)
            $back = [IO.File]::ReadAllBytes($f)
            if ($back.Length -ne $data.Length -or
                [BitConverter]::ToString($back[0..63]) -ne [BitConverter]::ToString($data[0..63])) {
                $ioFail++; Log "IO MISMATCH on $f"
            }
            Remove-Item $f -Force
        }

        $line = ("t+{0,4}s  iter {1} took {2,5:N0} ms  proc {3}/{4} bad, io {5}/{6} bad, hv {7}/{8} bad, hook {9}/{10} bad" -f `
                 [int]((Get-Date) - $deadline.AddSeconds(-$DurationSeconds)).TotalSeconds, $i,
                 ((Get-Date) - $iterationStart).TotalMilliseconds,
                 $procFail, $procTotal, $ioFail, $ioTotal, $hvFail, $hvTotal, $hookFail, $hookTotal)
        Log $line
        Status $line
    }

    $jobs | Wait-Job -Timeout 30 | Out-Null
    $jobs | Remove-Job -Force -ErrorAction SilentlyContinue
}
catch {
    Log "EXCEPTION: $_"
}
finally {
    Log "RESULT  process creation : $($procTotal - $procFail)/$procTotal ok"
    Log "RESULT  file i/o         : $($ioTotal - $ioFail)/$ioTotal ok"
    Log "RESULT  hypervisor probe : $($hvTotal - $hvFail)/$hvTotal ok"
    Log "RESULT  npt hook         : $($hookTotal - $hookFail)/$hookTotal ok"
    Log "final stats:"
    Log (((& C:\lab\hvtest.exe 2>&1 | Out-String) -split "`n" |
          Select-String 'exits|cycles|hook|npt|switches' | Out-String).TrimEnd())
    Log "stop: $((sc.exe stop svmhv | Out-String) -replace '\s+', ' ')"
    Log "after unload: $((& C:\lab\hvtest.exe 2>&1 | Select-String 'NOT PRESENT|PRESENT') -join ' ')"
    Log "=== soak done"
    Status ("DONE proc $($procTotal - $procFail)/$procTotal io $($ioTotal - $ioFail)/$ioTotal " +
            "hv $($hvTotal - $hvFail)/$hvTotal hook $($hookTotal - $hookFail)/$hookTotal")
}
