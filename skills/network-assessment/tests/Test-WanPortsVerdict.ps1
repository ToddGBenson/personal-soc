<#
.SYNOPSIS
    Get-WanPortsVerdict against external-exposure.json fixtures. No network.

.DESCRIPTION
    TheHub #60987: every weekly network-status.md from 2026-08-24 to
    2026-10-19 read 'WAN (external) ports visible: n/a', and none of those
    runs kept raw/external-run.txt. netassess-ingest fails only on 'unknown'
    (and the NFS/SMBv1/Wi-Fi markers), so eleven runs passed a WAN check that
    never answered. 'n/a' was written both for a missing
    external-exposure.json and for one that would not parse.

    These fixtures pin: a check that did not answer starts with 'unknown',
    the word the gate fails on; a definite answer keeps the wording
    network-status.md has always used; and the weekly scan has no code path
    left that writes 'n/a' on the WAN line.

    ALL FIXTURES ARE CONSTRUCTED. Addresses are from the documentation range
    (RFC 5737).

.NOTES
    Usage: pwsh -NoProfile -File skills/network-assessment/tests/Test-WanPortsVerdict.ps1
    Also runs under Windows PowerShell 5.1, which is what the Scheduled Task uses.
    ASCII only.
#>

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/../scripts/NetAssess.Verdicts.ps1"

$pass = 0; $fail = 0
function Check([string]$Name, [scriptblock]$Test, [string]$Shown) {
    $ok = $false
    try { $ok = [bool](& $Test) } catch { $Shown = "threw: $($_.Exception.Message)" }
    if ($ok) { Write-Host ("  [ok]   {0,-52} {1}" -f $Name, $Shown); $script:pass++ }
    else { Write-Host ("  [FAIL] {0,-52} got '{1}'" -f $Name, $Shown); $script:fail++ }
}

# One verdict per fixture; a throw is recorded as the verdict so Check fails
# on it instead of the whole script stopping at the first missing function.
function Verdict([string]$Path) {
    try { return [string](Get-WanPortsVerdict -ExposureJsonPath $Path) }
    catch { return "threw: $($_.Exception.Message)" }
}

$dir = Join-Path ([System.IO.Path]::GetTempPath()) ("wan-verdict-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $dir | Out-Null
function Fixture([string]$Name, [string]$Body) {
    $p = Join-Path $dir $Name
    [System.IO.File]::WriteAllText($p, $Body)
    return $p
}

try {
    Write-Host ""
    Write-Host "the check did not answer"

    $v = Verdict (Join-Path $dir 'absent.json')
    Check -Name "missing file is unknown, pointing at the run log" -Test { $v -eq 'unknown (no external-exposure.json; see raw/external-run.txt)' } -Shown $v

    $v = Verdict (Fixture 'garbled.json' '{"ip": "192.0.2.10", "ports": [443,')
    Check -Name "unparseable file is unknown (unreadable ...)" -Test { $v -like 'unknown (external-exposure.json unreadable*' } -Shown $v

    $v = Verdict (Fixture 'empty.json' '')
    Check -Name "empty file is unknown (unreadable ...)" -Test { $v -like 'unknown (external-exposure.json unreadable*' } -Shown $v

    $v = Verdict (Fixture 'noports.json' '{"ip": "192.0.2.10", "cves": [], "unexpected_ports": []}')
    Check -Name "ports field absent is unknown, not 'none visible'" -Test { $v -like 'unknown*' } -Shown $v

    $v = Verdict (Fixture 'nullports.json' '{"ip": "192.0.2.10", "ports": null, "unexpected_ports": []}')
    Check -Name "ports null is unknown, not 'none visible'" -Test { $v -like 'unknown*' } -Shown $v

    Write-Host ""
    Write-Host "the check answered"

    $v = Verdict (Fixture 'none.json' '{"ip": "192.0.2.10", "ports": [], "unexpected_ports": [], "allowlisted_ports": []}')
    Check -Name "empty ports is 'none visible'" -Test { $v -eq 'none visible' } -Shown $v

    $v = Verdict (Fixture 'allowed.json' '{"ip": "192.0.2.10", "ports": [443, 8443], "unexpected_ports": [], "allowlisted_ports": [443, 8443]}')
    Check -Name "all allowlisted is the bare comma-joined list" -Test { $v -eq '443, 8443' } -Shown $v

    $v = Verdict (Fixture 'oneout.json' '{"ip": "192.0.2.10", "ports": [443, 7547], "unexpected_ports": [7547], "allowlisted_ports": [443]}')
    Check -Name "one port not allowlisted is named" -Test { $v -eq '443, 7547 (NOT allowlisted: 7547)' } -Shown $v

    $v = Verdict (Fixture 'single.json' '{"ip": "192.0.2.10", "ports": [7547], "unexpected_ports": [7547]}')
    Check -Name "a single visible port is handled" -Test { $v -eq '7547 (NOT allowlisted: 7547)' } -Shown $v

    $v = Verdict (Fixture 'nounexpected.json' '{"ip": "192.0.2.10", "ports": [443]}')
    Check -Name "unexpected_ports absent appends nothing" -Test { $v -eq '443' } -Shown $v

    Write-Host ""
    Write-Host "no answer reads as a pass"

    foreach ($n in 'absent.json', 'garbled.json', 'empty.json', 'noports.json', 'nullports.json') {
        $v = Verdict (Join-Path $dir $n)
        Check -Name "$n never reads 'n/a'" -Test { $v -notmatch 'n/a' -and $v -like 'unknown*' } -Shown $v
    }

    Write-Host ""
    Write-Host "the weekly scan uses it"

    $scan = Get-Content -Raw -LiteralPath "$PSScriptRoot/../scripts/Invoke-WeeklyNetworkScan.ps1"
    Check -Name "Invoke-WeeklyNetworkScan calls Get-WanPortsVerdict" -Test { $scan -match 'Get-WanPortsVerdict\s+-ExposureJsonPath' } -Shown ''
    Check -Name "no 'n/a' is assigned to the WAN value" -Test { $scan -notmatch '\$extPorts\s*(\+)?=\s*[''"]n/a' -and $scan -notmatch 'reported as n/a' } -Shown ''
    Check -Name "WAN bullet label is unchanged" -Test { $scan.Contains('- **WAN (external) ports visible:** $extPorts') } -Shown ''
}
finally {
    Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host ("{0} passed, {1} failed" -f $pass, $fail)
if ($fail) { exit 1 }
exit 0
