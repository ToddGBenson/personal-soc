<#
.SYNOPSIS
    Compare-Assessment.ps1 against fixture engagements. No network.

.DESCRIPTION
    The first block repeats the personal-soc pipeline's own functional
    fixtures, so this file fails if the change breaks what the pipeline
    asserts. The rest pin the 2026-10-11 fix: a finding that is absent from
    the current run, or marked 'untested', was not looked at. It is not
    resolved, and it still counts against the score at its last known
    severity.

.NOTES
    Usage: pwsh -NoProfile -File skills/network-assessment/tests/Test-CompareAssessment.ps1
    ASCII only.
#>

$ErrorActionPreference = 'Stop'
$cmp = Join-Path $PSScriptRoot '../scripts/Compare-Assessment.ps1'
$root = Join-Path ([IO.Path]::GetTempPath()) ("cmp-test-" + [guid]::NewGuid().ToString('N').Substring(0, 8))

$pass = 0; $fail = 0
function Check([string]$What, $Got, $Want) {
    if ($Got -eq $Want) { Write-Host ("  [ok]   {0,-46} {1}" -f $What, $Got); $script:pass++ }
    else { Write-Host ("  [FAIL] {0,-46} expected {1}, got {2}" -f $What, $Want, $Got); $script:fail++ }
}
function Run([string]$Name, [object[]]$Base, [object[]]$Cur) {
    $b = New-Item -ItemType Directory -Force -Path (Join-Path $root "$Name/base")
    $c = New-Item -ItemType Directory -Force -Path (Join-Path $root "$Name/cur")
    ConvertTo-Json -InputObject $Base | Set-Content (Join-Path $b 'findings.json')
    ConvertTo-Json -InputObject $Cur  | Set-Content (Join-Path $c 'findings.json')
    & $cmp -Baseline $b -Current $c *> $null
    return (Get-Content (Join-Path $c 'change-summary.json') -Raw | ConvertFrom-Json)
}

try {
    $f1 = @{ id = 'F-1'; title = 'Telnet open';  severity = 'high'; status = 'open' }
    $f2 = @{ id = 'F-2'; title = 'UPnP enabled'; severity = 'low';  status = 'open' }

    Write-Host ""
    Write-Host "the pipeline's fixtures (must not change)"
    $s = Run -Name 'pipeline' -Base @($f1, $f2) -Cur @(
        @{ id = 'F-1'; title = 'Telnet open';  severity = 'high';     status = 'resolved' },
        $f2,
        @{ id = 'F-3'; title = 'SMBv1 on NAS'; severity = 'critical'; status = 'open' })
    Check -What 'baseline score'  -Got $s.score_baseline -Want 93
    Check -What 'current score'   -Got $s.score_current  -Want 84
    Check -What 'score delta'     -Got $s.score_delta    -Want -9
    Check -What 'resolved count'  -Got $s.resolved       -Want 1
    Check -What 'new count'       -Got $s.new            -Want 1
    Check -What 'not re-assessed' -Got $s.not_reassessed -Want 0

    Write-Host ""
    Write-Host "absent is not resolved"
    # F-1 missing from the current run entirely. Old behaviour: resolved, and
    # the score rose to 99 for leaving it out.
    $s = Run -Name 'absent' -Base @($f1, $f2) -Cur @($f2)
    Check -What 'absent finding is not resolved'      -Got $s.resolved       -Want 0
    Check -What '...it is not re-assessed'            -Got $s.not_reassessed -Want 1
    Check -What '...and still counts (score)'         -Got $s.score_current  -Want 93
    Check -What '...so the delta is 0, not +6'        -Got $s.score_delta    -Want 0

    Write-Host ""
    Write-Host "'untested' is not resolved either"
    $s = Run -Name 'untested' -Base @($f1, $f2) -Cur @(
        @{ id = 'F-1'; title = 'Telnet open'; severity = 'high'; status = 'untested' }, $f2)
    Check -What 'untested finding is not resolved'    -Got $s.resolved       -Want 0
    Check -What '...it is not re-assessed'            -Got $s.not_reassessed -Want 1
    Check -What '...and counted once, not twice'      -Got $s.score_current  -Want 93
    Check -What '...and is not reported as new'       -Got $s.new            -Want 0
}
finally {
    Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host ("{0} passed, {1} failed" -f $pass, $fail)
if ($fail) { exit 1 }
