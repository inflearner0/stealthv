# Talk to the in-guest svmhv MCP server over HTTP.
#
# This exists because PowerShell Direct is unusable while the hypervisor is
# loaded - its session is itself a VMBus channel and it drops as soon as the
# guest stalls, which loading a hypervisor guarantees.  HTTP crosses no VMBus
# channel, which is the whole reason the agent runs inside the guest.
#
#   .\mcp.ps1 tools
#   .\mcp.ps1 call svmhv_status
#   .\mcp.ps1 call svmhv_explain '{"target":"nt!NtCreateFile"}'
param(
    [Parameter(Mandatory = $true)][string]$Action,
    [string]$Name,
    [string]$Arguments = '{}',
    [string]$Guest = '172.17.120.157',
    [int]$Port = 8765,
    [int]$TimeoutSec = 90
)

$uri = "http://${Guest}:${Port}/mcp"

function Send-Rpc($method, $params) {
    $body = @{ jsonrpc = '2.0'; id = 1; method = $method; params = $params } |
        ConvertTo-Json -Depth 10 -Compress
    Invoke-RestMethod -Uri $uri -Method Post -TimeoutSec $TimeoutSec `
        -ContentType 'application/json' -Body $body
}

switch ($Action) {
    'tools' {
        $r = Send-Rpc 'tools/list' @{}
        "$($r.result.tools.Count) tools"
        $r.result.tools | ForEach-Object { "  - $($_.name)" }
    }
    'call' {
        if (-not $Name) { throw 'call needs -Name' }
        $r = Send-Rpc 'tools/call' @{ name = $Name
                                      arguments = ($Arguments | ConvertFrom-Json) }
        if ($r.result.isError) { "ERROR:" }
        $r.result.content | ForEach-Object { $_.text }
    }
    default { throw "unknown action $Action" }
}
