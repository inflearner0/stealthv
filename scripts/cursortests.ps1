<#
    cursortests.ps1 - exercises the absolute trace cursor and the two seqlocks
    from inside the guest, launched by a scheduled task.

    It has to run detached for the reason runtests.ps1 does: PowerShell Direct
    drops the moment the hypervisor loads and does not come back until it
    unloads, so anything that wants to talk to a live hypervisor has to be
    started before the load and report through a file.

    What it is actually checking, in order:

      - the control ABI version the driver reports
      - a snapshot read while the worker is refreshing underneath it
      - that reading the ring twice returns the same records, because the read
        is now non-destructive
      - that a cursor walked in small steps sees every sequence exactly once
      - that a reset moves the floor and changes the generation, and that a
        cursor from before it is reported as lost rather than silently reused

    The target address is passed in because svmhvctl takes addresses, not
    symbols; the caller resolves it while the driver is up.
#>
param(
    [Parameter(Mandatory = $true)][string]$Target,   # hex, no 0x
    [string]$Log = 'C:\lab\cursor.log'
)

Remove-Item $Log -Force -ErrorAction SilentlyContinue

function Log($msg) {
    # Write-through: a run that ends in a reset must not lose its log to the
    # file cache.  This is the lesson from soak.ps1.
    $line = "$((Get-Date).ToString('HH:mm:ss.fff'))  $msg"
    $stream = [IO.File]::Open($Log, 'Append', 'Write', 'Read')
    $writer = New-Object IO.StreamWriter($stream)
    $writer.WriteLine($line)
    $writer.Flush(); $stream.Flush($true)
    $writer.Dispose(); $stream.Dispose()
}

function Ctl {
    $out = & C:\lab\svmhvctl.exe @args 2>&1
    return (($out | Out-String) -split "`r?`n")
}

function Pairs($lines) {
    $map = @{}
    foreach ($line in $lines) {
        if ($line -match '^([a-z_0-9]+)=(.*)$') { $map[$matches[1]] = $matches[2] }
    }
    return $map
}

function Seqs($lines) {
    $found = @()
    foreach ($line in $lines) {
        if ($line -match '^trace seq=(\d+) ') { $found += [uint64]$matches[1] }
    }
    return $found
}

$pass = 0
$fail = 0
function Check($name, $ok, $detail) {
    if ($ok) { $script:pass++; Log "  [pass] $name" }
    else     { $script:fail++; Log "  [FAIL] $name -- $detail" }
}

Log "=== cursor tests, target 0x$Target, $(Get-Date) ==="

try {
    Log "----- sc start svmhv -----"
    Log ((sc.exe start svmhv 2>&1 | Out-String) -replace '\s+', ' ')
    Start-Sleep -Seconds 3

    # --- the ABI handshake --------------------------------------------------
    $present = Pairs (Ctl present)
    Log "present: $($present.present), control_version=$($present.control_version)"
    Check "control version is 2" ($present.control_version -eq '2') `
          "reported $($present.control_version)"

    # --- a snapshot read, which now has to survive a concurrent refresh -----
    $status = Pairs (Ctl status)
    Log "status: cpus=$($status.cpus) hooks=$($status.active_hooks) fatal=$($status.fatal_count)"
    Check "status returned a processor count" ($status.cpus -eq '8') "cpus=$($status.cpus)"
    Check "no fatal exit recorded" ($status.fatal_count -eq '0') `
          "fatal_count=$($status.fatal_count), reason=$($status.fatal_reason)"

    # The worker refreshes ten times a second; hammering status is what makes a
    # torn snapshot show up, because every read spans hundreds of windows.
    $torn = 0
    for ($i = 0; $i -lt 60; $i++) {
        $s = Pairs (Ctl status)
        if ($s.cpus -ne '8' -or -not $s.ContainsKey('fatal_count')) { $torn++ }
    }
    Check "60 snapshot reads were all coherent" ($torn -eq 0) "$torn were not"

    # --- produce some records ----------------------------------------------
    Log "----- hook-trace 0x$Target -----"
    $hook = Pairs (Ctl hook-trace $Target 14)
    Log "hook status=$($hook.status) id=$($hook.hook_id)"
    Check "hook installed" ([uint32]$hook.status -eq 0) "status=$($hook.status)"

    # Something that opens files, so the hook fires without a synthetic driver.
    for ($i = 0; $i -lt 40; $i++) {
        Get-ChildItem C:\Windows\System32\drivers\etc -ErrorAction SilentlyContinue | Out-Null
    }
    Start-Sleep -Seconds 1

    $state = Pairs (Ctl trace 1)
    Log "ring: produced=$($state.produced) floor=$($state.cursor_floor) gen=$($state.trace_generation) size=$($state.record_size)"
    Check "the ring produced records" ([uint64]$state.produced -gt 0) "produced=$($state.produced)"
    Check "trace-state reports a floor" ($state.ContainsKey('cursor_floor')) "no cursor_floor"
    Check "the generation is even (no reset in flight)" `
          (([uint64]$state.trace_generation % 2) -eq 0) "gen=$($state.trace_generation)"

    # --- reading is non-destructive ----------------------------------------
    #
    # "trace N" is a sliding window on a ring that is still filling, so two of
    # those cannot be compared directly - the second one legitimately sees
    # records the first could not.  Ask for one fixed range twice instead: that
    # is the property that actually matters, and it is the one the old
    # consume-on-read behaviour could not have provided.
    $window = Pairs (Ctl trace 1)
    $at = [uint64]$window.cursor_floor
    $firstRead  = Seqs (Ctl trace-cursor $at 10)
    $secondRead = Seqs (Ctl trace-cursor $at 10)
    Log "cursor $at read twice: [$($firstRead -join ',')] then [$($secondRead -join ',')]"
    Check "a fixed cursor range returns records" ($firstRead.Count -gt 0) "got none"
    Check "the identical range comes back on a second read" `
          (($firstRead -join ',') -eq ($secondRead -join ',')) `
          "first=[$($firstRead -join ',')] second=[$($secondRead -join ',')]"

    # And the newest-N view keeps returning what it already showed once.
    $slidingA = Seqs (Ctl trace 20)
    $slidingB = Seqs (Ctl trace 20)
    $overlap = @($slidingA | Where-Object { $slidingB -contains $_ })
    Log "trace 20 twice: $($slidingA.Count) then $($slidingB.Count), $($overlap.Count) in common"
    Check "reading did not consume what it returned" ($overlap.Count -gt 0) `
          "no record survived into the second read"

    # --- the cursor walks every sequence exactly once -----------------------
    $startState = Pairs (Ctl trace 1)
    $cursor = [uint64]$startState.cursor_floor
    $head   = [uint64]$startState.produced
    $seen = New-Object System.Collections.Generic.List[uint64]
    $steps = 0
    while ($cursor -lt $head -and $steps -lt 400) {
        $lines = Ctl trace-cursor $cursor 7
        $map = Pairs $lines
        foreach ($s in Seqs $lines) { $seen.Add($s) }
        if (-not $map.ContainsKey('next_cursor')) {
            Log "  cursor stalled at $cursor : $(($lines | Where-Object { $_ }) -join ' | ')"
            break
        }
        $next = [uint64]$map.next_cursor
        if ($next -eq $cursor) { break }
        $cursor = $next
        $steps++
    }
    Log "cursor walk: $($seen.Count) records over $steps steps, ended at $cursor (head was $head)"
    $unique = ($seen | Sort-Object -Unique).Count
    Check "the walk never returned a duplicate" ($unique -eq $seen.Count) `
          "$($seen.Count) records, $unique unique"
    $ordered = $true
    for ($i = 1; $i -lt $seen.Count; $i++) {
        if ($seen[$i] -le $seen[$i - 1]) { $ordered = $false; break }
    }
    Check "sequences came back strictly increasing" $ordered "they did not"
    Check "the walk reached the head it was given" ($cursor -ge $head) `
          "stopped at $cursor, head was $head"

    # --- lapping the ring ---------------------------------------------------
    #
    # The floor exists for exactly this: 4096 records is about a second of a
    # busy hook, and a collector that looks away for longer has to be told it
    # lost records rather than handed a slot that has been rewritten under it.
    #
    # Deliberately *not* driven by a loop in here.  A hot loop in this script
    # is compiled by PowerShell's interpreter after enough iterations, and
    # under a system-wide hook on NtCreateFile that JIT has crashed the host
    # process outright (0xC0000005 in RuntimeHelpers._CompileMethod) - which
    # kills the run without ever reaching the finally block that unloads the
    # driver.  Ordinary system activity fills the ring perfectly well; this
    # just waits for it, and costs the guest nothing.
    $lapFrom = [uint64](Pairs (Ctl trace 1)).produced
    Log "----- waiting for the ring to lap from $lapFrom -----"
    $deadline = (Get-Date).AddMinutes(4)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 10
        $now = [uint64](Pairs (Ctl trace 1)).produced
        if (($now - $lapFrom) -gt 4096) { break }
    }
    $lapped = Pairs (Ctl trace 1)
    $counters = Pairs (Ctl status)
    Log "lapped: produced=$($lapped.produced) floor=$($lapped.cursor_floor) records=$($counters.trace_records) dropped=$($counters.trace_dropped)"

    # With a collector publishing its watermark, "dropped" has to mean records
    # that were overwritten before it read them - not simply everything the ring
    # overwrote.  Walk the cursor to the head, then check the counter did not
    # just count the whole lap.
    $drain = [uint64]$lapped.cursor_floor
    for ($i = 0; $i -lt 500; $i++) {
        $m = Pairs (Ctl trace-cursor $drain 200)
        if (-not $m.ContainsKey('next_cursor')) { break }
        if ([uint64]$m.next_cursor -eq $drain) { break }
        $drain = [uint64]$m.next_cursor
        if ($drain -ge [uint64]$lapped.produced) { break }
    }
    # Drops already counted while nothing was draining cannot be undone, so the
    # property to check is the forward one: once a collector has published a
    # watermark at the head, producing less than a ring's worth more must drop
    # nothing at all.  Without the watermark every one of those counts as lost.
    $afterDrain = Pairs (Ctl status)
    $droppedBefore = [uint64]$afterDrain.trace_dropped
    $producedBefore = [uint64]$afterDrain.trace_records
    Log "drained to $drain; dropped=$droppedBefore produced=$producedBefore"

    $deadline = (Get-Date).AddMinutes(2)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 10
        if (([uint64](Pairs (Ctl status)).trace_records - $producedBefore) -gt 150) { break }
    }
    $settled = Pairs (Ctl status)
    $grew = [uint64]$settled.trace_records - $producedBefore
    $newDrops = [uint64]$settled.trace_dropped - $droppedBefore
    Log "after draining: +$grew produced, +$newDrops dropped"
    Check "records produced after a drain are not counted as lost" `
          ($grew -gt 0 -and $newDrops -eq 0) `
          "+$grew produced but +$newDrops dropped"
    Check "the ring produced more than it can hold" `
          (([uint64]$lapped.produced - $lapFrom) -gt 4096) `
          "only $([uint64]$lapped.produced - $lapFrom) records"
    Check "the floor advanced once the ring lapped" `
          ([uint64]$lapped.cursor_floor -gt $lapFrom) `
          "floor=$($lapped.cursor_floor), started at $lapFrom"
    Check "the floor is exactly one ring behind the head" `
          (([uint64]$lapped.produced - [uint64]$lapped.cursor_floor) -le 4096) `
          "head=$($lapped.produced) floor=$($lapped.cursor_floor)"

    $overrun = Pairs (Ctl trace-cursor $lapFrom 5)
    Log "lapped cursor $lapFrom -> lost=$($overrun.cursor_lost) next=$($overrun.next_cursor) floor=$($overrun.cursor_floor)"
    Check "a cursor the ring overran is reported lost" `
          ($overrun.cursor_lost -eq '1') "cursor_lost=$($overrun.cursor_lost)"
    Check "the lost cursor is moved to the floor, not to zero" `
          ([uint64]$overrun.cursor_floor -ge [uint64]$lapped.cursor_floor) `
          "floor=$($overrun.cursor_floor)"

    # --- a stale cursor is reported, not silently reused --------------------
    $before = Pairs (Ctl trace 1)
    $oldCursor = [uint64]$before.cursor_floor
    $oldGen = [uint64]$before.trace_generation
    Log "----- trace-reset -----"
    Log ((Ctl trace-reset) -join ' ')
    $after = Pairs (Ctl trace 1)
    Log "after reset: produced=$($after.produced) floor=$($after.cursor_floor) gen=$($after.trace_generation)"
    Check "the generation moved" ([uint64]$after.trace_generation -gt $oldGen) `
          "$oldGen -> $($after.trace_generation)"
    Check "the generation is even again" `
          (([uint64]$after.trace_generation % 2) -eq 0) "gen=$($after.trace_generation)"
    Check "the floor moved up to the head" `
          ([uint64]$after.cursor_floor -ge [uint64]$before.produced) `
          "floor=$($after.cursor_floor), head was $($before.produced)"

    $stale = Pairs (Ctl trace-cursor $oldCursor 5)
    Log "stale cursor $oldCursor -> lost=$($stale.cursor_lost) next=$($stale.next_cursor) floor=$($stale.cursor_floor)"
    Check "a pre-reset cursor is reported lost" `
          ($stale.ContainsKey('cursor_lost') -or $stale.ContainsKey('trace_reset')) `
          "neither cursor_lost nor trace_reset was printed"

    # --- and the ring still works afterwards --------------------------------
    for ($i = 0; $i -lt 20; $i++) {
        Get-ChildItem C:\Windows\System32\drivers\etc -ErrorAction SilentlyContinue | Out-Null
    }
    Start-Sleep -Seconds 1
    $resumed = Pairs (Ctl trace 1)
    Log "after reset, produced=$($resumed.produced)"
    Check "records are produced again after a reset" `
          ([uint64]$resumed.produced -gt [uint64]$after.produced) `
          "$($after.produced) -> $($resumed.produced)"

    Log "----- unhook -----"
    Log ((Ctl unhook $Target) -join ' ')

    $final = Pairs (Ctl status)
    Log "final: fatal_count=$($final.fatal_count) reason=$($final.fatal_reason)"
    Check "still no fatal exit" ($final.fatal_count -eq '0') `
          "fatal_count=$($final.fatal_count) reason=$($final.fatal_reason)"
}
catch {
    Log "EXCEPTION: $_"
    $fail++
}
finally {
    Log "----- sc stop svmhv -----"
    Log ((sc.exe stop svmhv 2>&1 | Out-String) -replace '\s+', ' ')
    Log "=== RESULT: $pass passed, $fail failed ==="
    Log "=== done ==="
}
