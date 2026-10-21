<#
.SYNOPSIS
    The external-exposure allowlist gate, offline. No network.

.DESCRIPTION
    TheHub #60852: external-exposure printed "Open ports : 7547 ... Ports are
    visible from the internet" and exited 0. These fixtures pin what replaced
    it: every visible port must be on config/exposure-allowlist.yml or the
    script exits 1, and a check that could not run exits 2 - never 0.

    Get-ExternalExposure.ps1 is run for real here, with Invoke-RestMethod
    replaced by a function in this scope (PowerShell resolves a function
    before a cmdlet of the same name, and a child script sees the caller's
    functions). Nothing leaves the machine; an unexpected URL throws.

    ALL FIXTURES ARE CONSTRUCTED. The IP is from TEST-NET-3 (RFC 5737).

.NOTES
    Usage: pwsh -NoProfile -File skills/network-assessment/tests/Test-ExposureVerdict.ps1
    ASCII only.
#>

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/../scripts/NetAssess.Verdicts.ps1"

$pass = 0; $fail = 0
function Check([string]$Name, [scriptblock]$Test, [string]$Shown) {
    if (& $Test) { Write-Host ("  [ok]   {0,-58} {1}" -f $Name, $Shown); $script:pass++ }
    else { Write-Host ("  [FAIL] {0,-58} got '{1}'" -f $Name, $Shown); $script:fail++ }
}
function Throws([scriptblock]$Block) { try { & $Block | Out-Null; return $false } catch { return $true } }

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("exposure-test-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
function Allow([string]$Name, [string]$Body) { $p = Join-Path $tmp $Name; Set-Content -LiteralPath $p -Value $Body; return $p }

try {
    Write-Host ""
    Write-Host "Read-ExposureAllowlist"

    $shipped = Join-Path $PSScriptRoot '../config/exposure-allowlist.yml'
    $a = Read-ExposureAllowlist -Path $shipped
    Check -Name "shipped allowlist parses, and is empty (7547 undecided)" -Test { $a.Count -eq 0 } -Shown "$($a -join ',')"

    $a = Read-ExposureAllowlist -Path (Allow 'inline.yml' "allowed_ports: [443, 8443]  # two")
    Check -Name "inline list" -Test { ($a -join ',') -eq '443,8443' } -Shown "$($a -join ',')"

    $a = Read-ExposureAllowlist -Path (Allow 'block.yml' @"
# header
allowed_ports:
  - port: 7547   # isp
    reason: TR-069 # hash in a reason
  - 443
  - reason: written key-first
    port: 8443
other_key: ignored
"@)
    Check -Name "block list, with reasons and comments" -Test { ($a -join ',') -eq '7547,443,8443' } -Shown "$($a -join ',')"

    Check -Name "missing file throws" -Test { Throws { Read-ExposureAllowlist -Path (Join-Path $tmp 'nope.yml') } } -Shown ''
    Check -Name "no allowed_ports key throws" -Test { Throws { Read-ExposureAllowlist -Path (Allow 'nokey.yml' "ports: [1]") } } -Shown ''
    Check -Name "non-number item throws" -Test { Throws { Read-ExposureAllowlist -Path (Allow 'bad.yml' "allowed_ports:`n  - https") } } -Shown ''
    Check -Name "out-of-range port throws" -Test { Throws { Read-ExposureAllowlist -Path (Allow 'range.yml' "allowed_ports: [70000]") } } -Shown ''
    Check -Name "bare scalar value throws" -Test { Throws { Read-ExposureAllowlist -Path (Allow 'scalar.yml' "allowed_ports: 443") } } -Shown ''

    Write-Host ""
    Write-Host "Get-ExposureVerdict"

    $v = Get-ExposureVerdict -Ports @(7547) -Allowed @()
    Check -Name "7547 with an empty allowlist fails" -Test { -not $v.Pass -and ($v.Unexpected -join ',') -eq '7547' } -Shown $v.Summary
    $v = Get-ExposureVerdict -Ports @(7547, 443) -Allowed @(7547)
    Check -Name "only the unlisted port is unexpected" -Test { -not $v.Pass -and ($v.Unexpected -join ',') -eq '443' -and ($v.Allowlisted -join ',') -eq '7547' } -Shown $v.Summary
    $v = Get-ExposureVerdict -Ports @(443) -Allowed @(443, 8443)
    Check -Name "all visible ports allowlisted passes" -Test { $v.Pass } -Shown $v.Summary
    $v = Get-ExposureVerdict -Ports $null -Allowed @()
    Check -Name "no ports visible passes" -Test { $v.Pass -and $v.Summary -eq 'no public ports visible' } -Shown $v.Summary

    Write-Host ""
    Write-Host "Get-ExternalExposure.ps1 exit codes (Invoke-RestMethod mocked)"

    # Mock state lives in one hashtable the mock closes over. Not $script: --
    # the mock runs while Get-ExternalExposure.ps1 is the current script, and
    # inside it $script: means THAT script's scope.
    $mock = @{ Ip = '203.0.113.7'; Db = $null; Mode = 'ok' }
    $mockBody = {
        param([Parameter(Position = 0)][string]$Uri, [int]$TimeoutSec)
        $null = $TimeoutSec
        if ($Uri -match 'ipify|ifconfig\.me|icanhazip') {
            if (-not $mock.Ip) { throw "mock: echo service down" }
            return $mock.Ip
        }
        if ($Uri -like 'https://internetdb.shodan.io/*') {
            switch ($mock.Mode) {
                'ok'    { return $mock.Db }
                'error' { throw "mock: connection reset" }
                '404'   {
                    $t = 'Microsoft.PowerShell.Commands.HttpResponseException' -as [type]
                    throw ($t::new('mock 404', [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::NotFound)))
                }
            }
        }
        throw "mock: unexpected URL $Uri - this test must not reach the network"
    }.GetNewClosure()
    # A function shadows the cmdlet of the same name, for this script and the
    # scripts it calls.
    Set-Item -Path function:Invoke-RestMethod -Value $mockBody

    $script_ = (Resolve-Path "$PSScriptRoot/../scripts/Get-ExternalExposure.ps1").Path
    function Run([string]$Allowlist) {
        $o = Join-Path $tmp ("out-" + [guid]::NewGuid().ToString('N'))
        Set-Variable -Name LASTEXITCODE -Scope Global -Value $null
        $text = if ($Allowlist) { & $script_ -OutDir $o -Allowlist $Allowlist *>&1 | Out-String }
                else            { & $script_ -OutDir $o *>&1 | Out-String }
        return [pscustomobject]@{ Code = $LASTEXITCODE; Text = $text; Out = $o }
    }

    $mock.Db = [pscustomobject]@{ ports = @(7547); vulns = @(); cpes = @(); hostnames = @(); tags = @() }
    $r = Run
    Check -Name "7547 visible, shipped (empty) allowlist: exit 1" -Test { $r.Code -eq 1 -and $r.Text -match 'FAIL: port\(s\) 7547' } -Shown "exit $($r.Code)"
    $j = Get-Content (Join-Path $r.Out 'external-exposure.json') -Raw | ConvertFrom-Json
    Check -Name "...and the json names it as unexpected" -Test { (@($j.unexpected_ports) -join ',') -eq '7547' } -Shown "$($j.unexpected_ports)"

    $r = Run (Allow 'ok.yml' "allowed_ports:`n  - port: 7547`n    reason: test")
    Check -Name "7547 visible and allowlisted: exit 0" -Test { $r.Code -eq 0 -and $r.Text -match 'allowlisted: 7547' } -Shown "exit $($r.Code)"

    $mock.Db = [pscustomobject]@{ ports = @(); vulns = @(); cpes = @(); hostnames = @(); tags = @() }
    $r = Run
    Check -Name "no ports visible: exit 0" -Test { $r.Code -eq 0 } -Shown "exit $($r.Code)"

    $mock.Mode = 'error'
    $r = Run
    Check -Name "InternetDB query failed: exit 2, not a pass" -Test { $r.Code -eq 2 -and $r.Text -match 'UNKNOWN' } -Shown "exit $($r.Code)"

    if ('Microsoft.PowerShell.Commands.HttpResponseException' -as [type]) {
        $mock.Mode = '404'
        $r = Run
        Check -Name "InternetDB 404 (not indexed): exit 0" -Test { $r.Code -eq 0 -and $r.Text -match 'HTTP 404' } -Shown "exit $($r.Code)"
    } else { Write-Host "  [skip] InternetDB 404 case needs PowerShell 7's HttpResponseException" }

    $mock.Mode = 'ok'; $mock.Ip = $null
    $r = Run
    Check -Name "no public IP: exit 2, sentence the pipeline greps" -Test { $r.Code -eq 2 -and $r.Text -match 'Could not determine public IP' } -Shown "exit $($r.Code)"

    $mock.Ip = '203.0.113.7'
    $r = Run (Join-Path $tmp 'missing.yml')
    Check -Name "allowlist missing: exit 2 before any lookup" -Test { $r.Code -eq 2 -and $r.Text -notmatch 'Public IP' } -Shown "exit $($r.Code)"
}
finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path function:Invoke-RestMethod -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host ("{0} passed, {1} failed" -f $pass, $fail)
if ($fail) { exit 1 }
exit 0
