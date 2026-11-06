<#
.SYNOPSIS
    Get-MonitorFreshnessVerdict against temp-dir fixtures, and the weekly
    scan's network-status.md template. No network.

.DESCRIPTION
    TheHub #60988: the Weekly Threat Monitor wrote nothing for four Sundays
    running (2026-09-13 to 10-04) while its Scheduled Task kept reporting
    result 0, and nothing alerted. Its output lives only on local disk, where
    Concourse cannot see it.

    The weekly network scan (Monday morning) now writes one more bullet,
    "Threat monitor last run", into network-status.md. When the newest
    complete monitor run is more than 7 days old the bullet starts with
    'unknown', the word netassess-ingest already fails on, so a missed Sunday
    turns the ingest gate red the next morning.

    These fixtures pin: a dated folder counts only when all three outputs are
    in it, 7 days is fresh and 8 is not, an incomplete newest run falls back
    to the older complete one, and the status carries folder names, dates and
    day counts only - never text read from inside a run.

    ALL FIXTURES ARE CONSTRUCTED, in a fresh temp directory.

.NOTES
    Usage: pwsh -NoProfile -File skills/network-assessment/tests/Test-MonitorFreshness.ps1
    Also runs under Windows PowerShell 5.1, which is what the Scheduled Task uses.
    ASCII only.
#>

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/../scripts/NetAssess.Verdicts.ps1"

$pass = 0; $fail = 0
function Check([string]$Name, [scriptblock]$Test, [string]$Shown) {
    if (& $Test) { Write-Host ("  [ok]   {0,-56} {1}" -f $Name, $Shown); $script:pass++ }
    else { Write-Host ("  [FAIL] {0,-56} got '{1}'" -f $Name, $Shown); $script:fail++ }
}

$canary = 'CANARY-INSIDE-A-RUN-FOLDER'
$today = [datetime]'2026-11-09'   # a Monday, when the network scan runs

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("monitor-fresh-test-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
$n = 0
function Add-Root { $script:n++; $r = Join-Path $tmp "root$script:n"; New-Item -ItemType Directory -Path $r | Out-Null; return $r }
function Add-Run([string]$Root, [string]$Name, [string[]]$Files = @('threat-brief.md', 'security-digest.md', 'footprint.json')) {
    $d = Join-Path $Root $Name
    New-Item -ItemType Directory -Force -Path $d | Out-Null
    foreach ($f in $Files) { Set-Content -LiteralPath (Join-Path $d $f) -Value "$canary unknown $Name" }
}
function Verdict([string]$Root, [int]$Max = 0) {
    if ($Max) { return Get-MonitorFreshnessVerdict -Root $Root -Today $today -MaxAgeDays $Max }
    return Get-MonitorFreshnessVerdict -Root $Root -Today $today
}

try {
    Write-Host ""
    Write-Host "Get-MonitorFreshnessVerdict"

    $cmd = Get-Command Get-MonitorFreshnessVerdict -ErrorAction SilentlyContinue
    $def = if ($cmd) { $cmd.ScriptBlock.Ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'MaxAgeDays' } } else { $null }
    Check -Name "exported, MaxAgeDays defaults to 7" -Test { $def -and "$($def.DefaultValue)" -eq '7' } -Shown "$(if ($def) { $def.DefaultValue } else { 'not found' })"

    $all = @()

    $r = Add-Root; Add-Run $r '2026-11-08'
    $v = Verdict $r; $all += $v
    Check -Name "1 day old: fresh" -Test { $v.Status -eq '2026-11-08 (1 days)' } -Shown $v.Status
    Check -Name "Status is a string" -Test { $v.Status -is [string] } -Shown "$($v.Status.GetType().Name)"

    $r = Add-Root; Add-Run $r '2026-11-02'
    $v = Verdict $r; $all += $v
    Check -Name "exactly 7 days old: fresh" -Test { $v.Status -eq '2026-11-02 (7 days)' } -Shown $v.Status

    $r = Add-Root; Add-Run $r '2026-11-01'
    $v = Verdict $r; $all += $v
    Check -Name "8 days old: unknown" -Test { $v.Status.StartsWith('unknown (last complete run 2026-11-01, 8 days ago)') } -Shown $v.Status

    $v = Verdict $r 8; $all += $v
    Check -Name "8 days old with -MaxAgeDays 8: fresh" -Test { $v.Status -eq '2026-11-01 (8 days)' } -Shown $v.Status

    $r = Add-Root; Add-Run $r '2026-11-01'; Add-Run $r '2026-11-08' -Files @('threat-brief.md', 'footprint.json')
    $v = Verdict $r; $all += $v
    Check -Name "incomplete newest skipped for older complete one" -Test { $v.Status.StartsWith('unknown (last complete run 2026-11-01, 8 days ago)') } -Shown $v.Status

    $r = Add-Root; Add-Run $r '2026-11-05'; Add-Run $r '2026-11-08' -Files @()
    $v = Verdict $r; $all += $v
    Check -Name "empty newest folder skipped" -Test { $v.Status -eq '2026-11-05 (4 days)' } -Shown $v.Status

    $r = Add-Root
    $v = Verdict $r; $all += $v
    Check -Name "no folders: unknown (no completed run under root)" -Test { $v.Status -eq "unknown (no completed run under $r)" } -Shown $v.Status

    $r = Add-Root; Add-Run $r '2026-11-08' -Files @('threat-brief.md')
    $v = Verdict $r; $all += $v
    Check -Name "only incomplete runs: no completed run" -Test { $v.Status -eq "unknown (no completed run under $r)" } -Shown $v.Status

    $missing = Join-Path $tmp 'not-there'
    $v = Verdict $missing; $all += $v
    Check -Name "missing root: unknown (root not found)" -Test { $v.Status -eq "unknown ($missing not found)" } -Shown $v.Status

    $r = Add-Root; Add-Run $r '2026-10-30'; Add-Run $r 'latest'; Add-Run $r '2026-11-08-copy'; Add-Run $r '2026-13-45'
    Set-Content -LiteralPath (Join-Path $r '2026-11-07') -Value 'a file, not a folder'
    $v = Verdict $r; $all += $v
    Check -Name "non-date folders, bad dates and files ignored" -Test { $v.Status.StartsWith('unknown (last complete run 2026-10-30, 10 days ago)') } -Shown $v.Status

    $r = Add-Root; Add-Run $r '2026-11-06'; Add-Run $r '2026-11-20'
    $v = Verdict $r; $all += $v
    Check -Name "a folder dated after Today is not a run yet" -Test { $v.Status -eq '2026-11-06 (3 days)' } -Shown $v.Status

    $r = Add-Root; Add-Run $r '2026-11-09'
    $v = Verdict $r; $all += $v
    Check -Name "run dated Today: 0 days" -Test { $v.Status -eq '2026-11-09 (0 days)' } -Shown $v.Status

    $leak = @($all | Where-Object { $_.Status -match $canary })
    Check -Name "no Status carries text from inside a run folder" -Test { $leak.Count -eq 0 -and $all.Count -ge 12 } -Shown "$($leak.Count) of $($all.Count)"

    Write-Host ""
    Write-Host "Invoke-WeeklyNetworkScan.ps1 network-status.md template"

    $scan = Join-Path $PSScriptRoot '../scripts/Invoke-WeeklyNetworkScan.ps1'
    $tok = $null; $err = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $scan).Path, [ref]$tok, [ref]$err)
    Check -Name "script parses" -Test { $err.Count -eq 0 } -Shown "$($err.Count) error(s)"

    $p = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'MonitorRoot' }
    $pDefault = if ($p) { $p.DefaultValue.Extent.Text } else { 'no -MonitorRoot' }
    Check -Name "-MonitorRoot defaults to USERPROFILE personal-monitor" -Test { $pDefault -eq "(Join-Path `$env:USERPROFILE 'personal-soc\personal-monitor')" } -Shown $pDefault

    $here = @($ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -and $a.Value -match '## Network status' }, $true))
    Check -Name "one network-status.md here-string" -Test { $here.Count -eq 1 } -Shown "$($here.Count)"
    $bullets = if ($here.Count) { @($here[0].Value -split "`r?`n" | Where-Object { $_ -like '- **' + '*' }) } else { @() }
    $expected = @(
        '- **Hosts:** $curCount live ($hostDelta)',
        '- **NAS NFS exports:** $nfsOpen',
        '- **NAS SMB:** $smbv1',
        '- **NAS anonymous shares listed:** $anon',
        '- **Open Wi-Fi AP:** $openAP',
        '- **WAN (external) ports visible:** $extPorts'
    )
    $same = $bullets.Count -ge 6 -and (@(0..5 | Where-Object { [string]::CompareOrdinal($bullets[$_], $expected[$_]) -ne 0 }).Count -eq 0)
    Check -Name "the six existing bullets are unchanged" -Test { $same } -Shown "$($bullets.Count) bullet(s)"
    # Agreed order for PRs #25 -> #26 -> #27: the six original bullets, this
    # one seventh, then #27's 'Posture score' last. So this pins the seventh
    # bullet, not the last one, and allows only that one after it.
    $seventh = if ($bullets.Count -ge 7) { $bullets[6] } else { '' }
    Check -Name "7th bullet, right after WAN, is Threat monitor last run" -Test { $seventh -match '^- \*\*Threat monitor last run:\*\* \$\(?\$?\w' } -Shown $seventh
    $after = @($bullets | Select-Object -Skip 7)
    Check -Name "only the posture score may follow it" -Test { $after.Count -le 1 -and @($after | Where-Object { $_ -notlike '- **Posture score:** *' }).Count -eq 0 } -Shown "$($after.Count) after"

    $calls = @($ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandAst] -and $a.GetCommandName() -eq 'Get-MonitorFreshnessVerdict' }, $true))
    $callText = if ($calls.Count) { $calls[0].Extent.Text } else { 'no call' }
    Check -Name "scan calls Get-MonitorFreshnessVerdict on MonitorRoot" -Test { $calls.Count -eq 1 -and $callText -match '-Root \$MonitorRoot' } -Shown $callText
}
finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host ("{0} passed, {1} failed" -f $pass, $fail)
if ($fail) { exit 1 }
exit 0
