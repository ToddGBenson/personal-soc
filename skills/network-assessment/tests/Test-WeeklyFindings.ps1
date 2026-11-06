<#
.SYNOPSIS
    The weekly scan's findings.json, its baseline, and its posture-score line.
    No network.

.DESCRIPTION
    TheHub #60989: Compare-Assessment.ps1 (posture score, resolved / new /
    not re-assessed) needs findings.json, and only a full manual engagement
    wrote one. The weekly scan wrote network-status.md and inventory.csv, so
    neither the score nor a finding-level diff ran on schedule after
    2026-08-10. These fixtures pin what replaced that:

      - ConvertTo-WeeklyFindings maps the scan's verdict strings to the same
        five stable ids on every run, and a check that did not answer
        ('unknown', or the WAN line's legacy 'n/a') is 'untested' - never
        'resolved', which would let a switched-off NAS raise the score.
      - An untested finding keeps the last state a run observed, and the
        date, in findings.json (last_known_status, last_observed), for as
        many weeks as the check stays unanswered. Only a run that answers
        changes it, so an open finding is never dropped from the score and a
        later fix shows as resolved. A check that has never answered has no
        state, and the posture line then says 'not scored', never 100/100.
      - The baseline is the newest earlier weekly findings.json. A full
        engagement's findings.json (2026-08-10 has 13 findings under other
        ids) is never one: every id would read as new and the delta would be
        noise.
      - network-status.md gains one line, and the six it already had keep
        their exact wording, because netassess-ingest matches substrings of
        them (EXPOSURE_MARKERS, and any line containing 'unknown' fails the
        run). The new line must never contain 'unknown' for that reason.

    findings.json is gitignored, so every fixture folder is built in a temp
    directory here and removed afterwards.

.NOTES
    Usage: pwsh -NoProfile -File skills/network-assessment/tests/Test-WeeklyFindings.ps1
    Also runs under Windows PowerShell 5.1, which is what the Scheduled Task uses.
    ASCII only.
#>

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/../scripts/NetAssess.Verdicts.ps1"
$cmp = Join-Path $PSScriptRoot '../scripts/Compare-Assessment.ps1'
$scan = Join-Path $PSScriptRoot '../scripts/Invoke-WeeklyNetworkScan.ps1'
$root = Join-Path ([IO.Path]::GetTempPath()) ("weekly-findings-" + [guid]::NewGuid().ToString('N').Substring(0, 8))

$pass = 0; $fail = 0
function Check([string]$What, $Got, $Want) {
    if ("$Got" -ceq "$Want") { Write-Host ("  [ok]   {0,-58} {1}" -f $What, $Got); $script:pass++ }
    else { Write-Host ("  [FAIL] {0,-58} expected '{1}', got '{2}'" -f $What, $Want, $Got); $script:fail++ }
}

$ids = @(
    'netassess.nas.nfs-exports',
    'netassess.nas.smbv1',
    'netassess.nas.anon-shares',
    'netassess.wifi.open-ap',
    'netassess.wan.unallowlisted-ports'
)

# A clean week, as the scan prints each line today.
$clean = @{
    NfsVerdict    = 'no NFS service (port 111 closed)'
    SmbVerdict    = 'SMB2/3 only'
    SharesVerdict = '0'
    OpenApVerdict = 'no open AP'
    WanVerdict    = 'none visible'
}

function Get-Status([string]$Id, [hashtable]$Override) {
    $a = $clean.Clone()
    foreach ($k in $Override.Keys) { $a[$k] = $Override[$k] }
    $f = @(ConvertTo-WeeklyFindings @a) | Where-Object { $_.id -eq $Id }
    return $f.status
}

function Add-RunFolder([string]$Name, $Findings) {
    $d = New-Item -ItemType Directory -Force -Path (Join-Path $root $Name)
    if ($null -ne $Findings) {
        ConvertTo-Json -InputObject @($Findings) | Set-Content (Join-Path $d.FullName 'findings.json')
    }
    return $d.FullName
}

try {
    Write-Host ""
    Write-Host "ConvertTo-WeeklyFindings is exported by NetAssess.Verdicts.ps1"
    Check -What 'command exists' -Got ([bool](Get-Command ConvertTo-WeeklyFindings -ErrorAction SilentlyContinue)) -Want $true

    Write-Host ""
    Write-Host "the same five ids, in the same order, on every run"
    $a = @(ConvertTo-WeeklyFindings @clean)
    $b = @(ConvertTo-WeeklyFindings @clean)
    $unknownAll = @(ConvertTo-WeeklyFindings -NfsVerdict 'unknown (nmap did not complete)' -SmbVerdict 'unknown' `
            -SharesVerdict 'unknown (net view did not answer: System error 53 has occurred.)' `
            -OpenApVerdict 'unknown (no usable wireless interface)' -WanVerdict 'n/a')
    $empty = @(ConvertTo-WeeklyFindings -NfsVerdict '' -SmbVerdict '' -SharesVerdict '' -OpenApVerdict '' -WanVerdict '')
    Check -What 'clean run: ids'                -Got ($a.id -join ',')          -Want ($ids -join ',')
    Check -What 'second call: identical ids'    -Got ($b.id -join ',')          -Want ($a.id -join ',')
    Check -What 'all-unknown run: same ids'     -Got ($unknownAll.id -join ',') -Want ($ids -join ',')
    Check -What 'empty verdicts: same ids'      -Got ($empty.id -join ',')      -Want ($ids -join ',')
    Check -What 'all-unknown run: all untested' -Got (@($unknownAll | Where-Object { $_.status -ne 'untested' }).Count) -Want 0
    Check -What 'empty verdicts: all untested'  -Got (@($empty | Where-Object { $_.status -ne 'untested' }).Count) -Want 0

    Write-Host ""
    Write-Host "each finding has the shape Compare-Assessment reads"
    foreach ($f in $a) {
        $keys = (@($f.PSObject.Properties | ForEach-Object { $_.Name }) | Sort-Object) -join ','
        Check -What "$($f.id): keys"           -Got $keys -Want 'cis,id,severity,status,title'
        Check -What "$($f.id): scoreable severity" -Got (@('critical', 'high', 'medium', 'low') -contains $f.severity) -Want $true
        Check -What "$($f.id): has a title and a CIS control" -Got ([bool]$f.title -and [bool]$f.cis) -Want $true
    }

    Write-Host ""
    Write-Host "verdict -> status"
    $nfs = 'netassess.nas.nfs-exports'
    Check -What 'nfs: EXPORTS PRESENT -> open'        -Got (Get-Status $nfs @{ NfsVerdict = 'EXPORTS PRESENT (/shares/media, /shares/backup)' }) -Want 'open'
    Check -What 'nfs: port 111 closed -> resolved'    -Got (Get-Status $nfs @{ NfsVerdict = 'no NFS service (port 111 closed)' }) -Want 'resolved'
    Check -What 'nfs: no exports -> resolved'         -Got (Get-Status $nfs @{ NfsVerdict = 'service reachable, no exports (answered on attempt 2 of 3)' }) -Want 'resolved'
    Check -What 'nfs: no NFS registered -> resolved'  -Got (Get-Status $nfs @{ NfsVerdict = 'rpcbind reachable, no NFS service registered' }) -Want 'resolved'
    Check -What 'nfs: unknown -> untested'            -Got (Get-Status $nfs @{ NfsVerdict = 'unknown (NFS registered, exports not enumerable) (all 3 attempts)' }) -Want 'untested'
    Check -What 'nfs: unrecognised -> untested'       -Got (Get-Status $nfs @{ NfsVerdict = 'something new' }) -Want 'untested'

    $smb = 'netassess.nas.smbv1'
    Check -What 'smb: SMBv1 ENABLED -> open'          -Got (Get-Status $smb @{ SmbVerdict = 'SMBv1 ENABLED' }) -Want 'open'
    Check -What 'smb: SMB2/3 only -> resolved'        -Got (Get-Status $smb @{ SmbVerdict = 'SMB2/3 only' }) -Want 'resolved'
    Check -What 'smb: unknown -> untested'            -Got (Get-Status $smb @{ SmbVerdict = 'unknown' }) -Want 'untested'
    Check -What 'smb: empty -> untested'              -Got (Get-Status $smb @{ SmbVerdict = '' }) -Want 'untested'

    $shr = 'netassess.nas.anon-shares'
    Check -What 'shares: 2 listed -> open'            -Got (Get-Status $shr @{ SharesVerdict = '2 (media, public)' }) -Want 'open'
    Check -What 'shares: 0 -> resolved'               -Got (Get-Status $shr @{ SharesVerdict = '0' }) -Want 'resolved'
    Check -What 'shares: unknown -> untested'         -Got (Get-Status $shr @{ SharesVerdict = 'unknown (net view did not answer: no output)' }) -Want 'untested'
    Check -What 'shares: legacy bare count 5 -> open' -Got (Get-Status $shr @{ SharesVerdict = '5' }) -Want 'open'

    $ap = 'netassess.wifi.open-ap'
    Check -What 'wifi: in-home open AP -> open'       -Got (Get-Status $ap @{ OpenApVerdict = 'SetupPlug-1234 (88% signal) OPEN - broadcasting' }) -Want 'open'
    Check -What 'wifi: ours + neighbour -> open'      -Got (Get-Status $ap @{ OpenApVerdict = 'Guest (served by the gateway) OPEN - broadcasting; neighbouring, not ours: NextDoorWiFi 30%' }) -Want 'open'
    Check -What 'wifi: no open AP -> resolved'        -Got (Get-Status $ap @{ OpenApVerdict = 'no open AP' }) -Want 'resolved'
    Check -What 'wifi: only a neighbour -> resolved'  -Got (Get-Status $ap @{ OpenApVerdict = 'no open AP of ours (neighbouring, not ours: NextDoorWiFi 30%)' }) -Want 'resolved'
    Check -What 'wifi: unknown -> untested'           -Got (Get-Status $ap @{ OpenApVerdict = 'unknown (no usable wireless interface)' }) -Want 'untested'

    $wan = 'netassess.wan.unallowlisted-ports'
    Check -What 'wan: not allowlisted -> open'        -Got (Get-Status $wan @{ WanVerdict = '443, 7547 (NOT allowlisted: 7547)' }) -Want 'open'
    Check -What 'wan: none visible -> resolved'       -Got (Get-Status $wan @{ WanVerdict = 'none visible' }) -Want 'resolved'
    Check -What 'wan: all allowlisted -> resolved'    -Got (Get-Status $wan @{ WanVerdict = '443, 8443' }) -Want 'resolved'
    Check -What 'wan: legacy n/a -> untested'         -Got (Get-Status $wan @{ WanVerdict = 'n/a' }) -Want 'untested'
    Check -What 'wan: unknown -> untested'            -Got (Get-Status $wan @{ WanVerdict = 'unknown (no external-exposure.json; see raw/external-run.txt)' }) -Want 'untested'

    Write-Host ""
    Write-Host "baseline: the newest earlier WEEKLY findings.json"
    $weeklyClean = @(ConvertTo-WeeklyFindings @clean)
    $engagement = @(
        @{ id = 'nfs-export'; title = 'NFS export'; severity = 'critical'; cis = '03'; status = 'resolved' },
        @{ id = 'open-ap'; title = 'Open AP'; severity = 'critical'; cis = '04'; status = 'open' }
    )
    $mixed = @($weeklyClean) + @(@{ id = 'flat-network'; title = 'Flat network'; severity = 'high'; cis = '06'; status = 'open' })

    $r1 = Join-Path $root 'r1'
    Add-RunFolder 'r1/2026-08-10' $engagement | Out-Null
    Add-RunFolder 'r1/2026-10-19' $weeklyClean | Out-Null
    Add-RunFolder 'r1/2026-10-26' $mixed | Out-Null           # newest with a file, but not weekly-only
    Add-RunFolder 'r1/2026-11-02' $null | Out-Null            # no findings.json at all
    Add-RunFolder 'r1/2026-11-09' $weeklyClean | Out-Null     # today: never its own baseline
    Add-RunFolder 'r1/2026-11-16' $weeklyClean | Out-Null     # later: never a baseline
    Add-RunFolder 'r1/notes' $weeklyClean | Out-Null          # not a dated folder
    $bl = Get-WeeklyFindingsBaseline -Root $r1 -Today '2026-11-09'
    Check -What 'skips today, later, undated, no-file and mixed folders' -Got $bl.Name -Want '2026-10-19'

    $r2 = Join-Path $root 'r2'
    Add-RunFolder 'r2/2026-08-09' $engagement | Out-Null
    Add-RunFolder 'r2/2026-08-10' $engagement | Out-Null
    $bl = Get-WeeklyFindingsBaseline -Root $r2 -Today '2026-11-09'
    Check -What 'a full-engagement findings.json is never a baseline' -Got ($null -eq $bl) -Want $true

    $r3 = Join-Path $root 'r3'
    Add-RunFolder 'r3/2026-10-26' @() | Out-Null
    Set-Content (Join-Path (Add-RunFolder 'r3/2026-11-02' $null) 'findings.json') 'not json {'
    $bl = Get-WeeklyFindingsBaseline -Root $r3 -Today '2026-11-09'
    Check -What 'an empty or unreadable findings.json is not a baseline' -Got ($null -eq $bl) -Want $true

    Write-Host ""
    Write-Host "with a baseline: Compare-Assessment runs and the line carries the delta"
    $r4 = Join-Path $root 'r4'
    Add-RunFolder 'r4/2026-08-10' $engagement | Out-Null
    Add-RunFolder 'r4/2026-10-26' $weeklyClean | Out-Null
    $out4 = Add-RunFolder 'r4/2026-11-02' $null
    $cur4 = @(ConvertTo-WeeklyFindings -NfsVerdict 'EXPORTS PRESENT (/shares/x)' -SmbVerdict 'SMB2/3 only' -SharesVerdict '0' -OpenApVerdict 'no open AP' -WanVerdict 'none visible')
    $p4 = Write-WeeklyFindings -Findings $cur4 -OutDir $out4 -Root $r4 -Today '2026-11-02' -ComparePath $cmp
    Check -What 'findings.json written'                 -Got (Test-Path (Join-Path $out4 'findings.json')) -Want $true
    Check -What 'findings.json holds the five ids'      -Got (@(Get-Content (Join-Path $out4 'findings.json') -Raw | ConvertFrom-Json | ForEach-Object { $_ }).id -join ',') -Want ($ids -join ',')
    Check -What 'change-summary.json written'           -Got (Test-Path (Join-Path $out4 'change-summary.json')) -Want $true
    $sum4 = Get-Content (Join-Path $out4 'change-summary.json') -Raw | ConvertFrom-Json
    # 'new' in Compare-Assessment means an id the baseline did not have; here
    # every id is in both, and NFS went resolved -> open.
    Check -What 'compare scored the week (current)'     -Got $sum4.score_current -Want 85
    Check -What 'compare scored the week (delta)'       -Got $sum4.score_delta -Want -15
    Check -What 'posture line (critical NFS export new)' -Got $p4.Line -Want '- **Posture score:** 85/100 (Strong, -15 vs 2026-10-26)'

    # Baseline open, current untested: not re-assessed, carried at its last
    # known state, delta 0, and the line says how old that state is. The
    # baseline here is a findings.json without the carry fields.
    $r5 = Join-Path $root 'r5'
    Add-RunFolder 'r5/2026-10-26' $cur4 | Out-Null
    $out5 = Add-RunFolder 'r5/2026-11-02' $null
    $p5 = Write-WeeklyFindings -Findings $unknownAll -OutDir $out5 -Root $r5 -Today '2026-11-02' -ComparePath $cmp
    Check -What 'untested carries the open baseline finding' -Got $p5.Line -Want '- **Posture score:** 85/100 (Strong, +0 vs 2026-10-26; 5 checks carried, last observed 2026-10-26)'
    Check -What '...and the line never says unknown'        -Got ($p5.Line -match 'unknown') -Want $false
    $nfs5 = @(Get-Content (Join-Path $out5 'findings.json') -Raw | ConvertFrom-Json | ForEach-Object { $_ }) | Where-Object { $_.id -eq $nfs }
    Check -What 'findings.json: this run did not test it'   -Got $nfs5.status -Want 'untested'
    Check -What 'findings.json: last known state kept'      -Got $nfs5.last_known_status -Want 'open'
    Check -What 'findings.json: and when it was observed'   -Got $nfs5.last_observed -Want '2026-10-26'

    # TheHub #60989 review: a second unanswered week forgot the open critical
    # (85 -> 100, '+0'), and the fix that came later never showed. The last
    # known state is kept until a run answers again.
    Write-Host ""
    Write-Host "an unanswered check keeps its last known state until a run answers"
    $r10 = Join-Path $root 'r10'
    $cleanBut = @{ SmbVerdict = 'SMB2/3 only'; SharesVerdict = '0'; OpenApVerdict = 'no open AP'; WanVerdict = 'none visible' }
    $weeks = @(
        @('2026-10-19', 'EXPORTS PRESENT (/shares/x)',      '- **Posture score:** 85/100 (Strong, no prior weekly findings.json)'),
        @('2026-10-26', 'unknown (nmap did not complete)',  '- **Posture score:** 85/100 (Strong, +0 vs 2026-10-19; 1 check carried, last observed 2026-10-19)'),
        @('2026-11-02', 'unknown (nmap did not complete)',  '- **Posture score:** 85/100 (Strong, +0 vs 2026-10-26; 1 check carried, last observed 2026-10-19)'),
        @('2026-11-09', 'unknown (nmap did not complete)',  '- **Posture score:** 85/100 (Strong, +0 vs 2026-11-02; 1 check carried, last observed 2026-10-19)'),
        @('2026-11-16', 'no NFS service (port 111 closed)', '- **Posture score:** 100/100 (Strong, +15 vs 2026-11-09)')
    )
    foreach ($w in $weeks) {
        $o = Add-RunFolder "r10/$($w[0])" $null
        $f = @(ConvertTo-WeeklyFindings -NfsVerdict $w[1] @cleanBut)
        $p = Write-WeeklyFindings -Findings $f -OutDir $o -Root $r10 -Today $w[0] -ComparePath $cmp
        Check -What "$($w[0]) NFS $($w[1].Split(' ')[0])" -Got $p.Line -Want $w[2]
    }
    $nfs10 = @(Get-Content (Join-Path $r10 '2026-11-09/findings.json') -Raw | ConvertFrom-Json | ForEach-Object { $_ }) | Where-Object { $_.id -eq $nfs }
    Check -What 'third unanswered week: still open, from 10-19' -Got "$($nfs10.status) $($nfs10.last_known_status) $($nfs10.last_observed)" -Want 'untested open 2026-10-19'
    $sum10 = Get-Content (Join-Path $r10 '2026-11-16/change-summary.json') -Raw | ConvertFrom-Json
    Check -What 'the fix shows as resolved'                      -Got $sum10.resolved -Want 1
    $nfs10 = @(Get-Content (Join-Path $r10 '2026-11-16/findings.json') -Raw | ConvertFrom-Json | ForEach-Object { $_ }) | Where-Object { $_.id -eq $nfs }
    Check -What 'answered again: observed today'                 -Got "$($nfs10.status) $($nfs10.last_known_status) $($nfs10.last_observed)" -Want 'resolved resolved 2026-11-16'

    # The fix comes in after the all-unknown week of r5: resolved.
    $out6 = Add-RunFolder 'r5/2026-11-09' $null
    $p6 = Write-WeeklyFindings -Findings $weeklyClean -OutDir $out6 -Root $r5 -Today '2026-11-09' -ComparePath $cmp
    Check -What 'resolved against the untested week before' -Got $p6.Line -Want '- **Posture score:** 100/100 (Strong, +15 vs 2026-11-02)'

    Write-Host ""
    Write-Host "with no baseline: the line says so, and never says unknown"
    $out7 = Add-RunFolder 'r2/2026-11-09' $null
    $p7 = Write-WeeklyFindings -Findings $cur4 -OutDir $out7 -Root $r2 -Today '2026-11-09' -ComparePath $cmp
    Check -What 'no-baseline line (engagement folders skipped)' -Got $p7.Line -Want '- **Posture score:** 85/100 (Strong, no prior weekly findings.json)'
    Check -What 'findings.json still written'                  -Got (Test-Path (Join-Path $out7 'findings.json')) -Want $true
    Check -What 'no change-summary.json without a baseline'    -Got (Test-Path (Join-Path $out7 'change-summary.json')) -Want $false
    $r8 = Join-Path $root 'r8'
    $out8 = Add-RunFolder 'r8/2026-11-09' $null
    $p8 = Write-WeeklyFindings -Findings $unknownAll -OutDir $out8 -Root $r8 -Today '2026-11-09' -ComparePath $cmp
    # WAS: 100/100 (Strong, ...) - a perfect score from five checks that did
    # not answer. A check never observed has no state to carry, so there is
    # no score to give.
    Check -What 'all checks unknown, first run: not scored'    -Got $p8.Line -Want '- **Posture score:** not scored (5 of 5 checks have never answered)'
    Check -What '...never Strong'                              -Got ($p8.Line -match 'Strong|/100') -Want $false
    Check -What '...still no unknown in the line'              -Got ($p8.Line -match 'unknown') -Want $false
    Check -What '...Score is null'                             -Got ($null -eq $p8.Score) -Want $true
    $f8 = @(Get-Content (Join-Path $out8 'findings.json') -Raw | ConvertFrom-Json | ForEach-Object { $_ })
    Check -What '...findings.json has no last known state'     -Got (@($f8 | Where-Object { $null -ne $_.last_known_status }).Count) -Want 0
    $out8b = Add-RunFolder 'r8b/2026-11-09' $null
    $p8b = Write-WeeklyFindings -Findings @(ConvertTo-WeeklyFindings -NfsVerdict 'unknown (nmap did not complete)' -SmbVerdict 'SMB2/3 only' `
            -SharesVerdict '0' -OpenApVerdict 'no open AP' -WanVerdict 'none visible') -OutDir $out8b -Root (Join-Path $root 'r8b') -Today '2026-11-09' -ComparePath $cmp
    Check -What 'one check never answered: not scored either'  -Got $p8b.Line -Want '- **Posture score:** not scored (1 of 5 checks have never answered)'
    # The week after an unscored one: scored, but there is no delta to give.
    $out8c = Add-RunFolder 'r8/2026-11-16' $null
    $p8c = Write-WeeklyFindings -Findings $weeklyClean -OutDir $out8c -Root $r8 -Today '2026-11-16' -ComparePath $cmp
    Check -What 'first answered week after an unscored one'    -Got $p8c.Line -Want '- **Posture score:** 100/100 (Strong, 2026-11-09 was not scored)'
    $worst = @(ConvertTo-WeeklyFindings -NfsVerdict 'EXPORTS PRESENT (/a)' -SmbVerdict 'SMBv1 ENABLED' -SharesVerdict '3 (a, b, c)' `
            -OpenApVerdict 'X (90% signal) OPEN - broadcasting' -WanVerdict '7547 (NOT allowlisted: 7547)')
    $out9 = Add-RunFolder 'r9/2026-11-09' $null
    $p9 = Write-WeeklyFindings -Findings $worst -OutDir $out9 -Root (Join-Path $root 'r9') -Today '2026-11-09' -ComparePath $cmp
    Check -What 'everything open: score agrees with Compare-Assessment' -Got $p9.Score -Want (& {
            & $cmp -Baseline $out9 -Current $out9 *> $null
            (Get-Content (Join-Path $out9 'change-summary.json') -Raw | ConvertFrom-Json).score_current })
    Check -What '...and every band word is free of unknown'    -Got ($p9.Line -match 'unknown') -Want $false

    Write-Host ""
    Write-Host "network-status.md: the six existing lines keep their wording, the score is last"
    # The bullets stay literal in the scan's here-string, where the WAN test
    # (TheHub #60987) and the monitor-freshness test (TheHub #60988) read
    # them. Agreed order, PRs #25 -> #26 -> #27: the six original bullets,
    # then 'Threat monitor last run' (#26, when it is on the branch), then
    # 'Posture score' last, since it sums up the five checks above it.
    $tok = $null; $err = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $scan).Path, [ref]$tok, [ref]$err)
    Check -What 'scan script parses' -Got $err.Count -Want 0
    $here = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -and $n.Value -match '## Network status' }, $true))
    Check -What 'one network-status.md here-string' -Got $here.Count -Want 1
    $lines = if ($here.Count) { @($here[0].Value -split "`r?`n" | Where-Object { $_ -like '- **' + '*' }) } else { @() }
    $want = @(
        '- **Hosts:** $curCount live ($hostDelta)',
        '- **NAS NFS exports:** $nfsOpen',
        '- **NAS SMB:** $smbv1',
        '- **NAS anonymous shares listed:** $anon',
        '- **Open Wi-Fi AP:** $openAP',
        '- **WAN (external) ports visible:** $extPorts'
    )
    for ($i = 0; $i -lt $want.Count; $i++) { Check -What "bullet $($i + 1) unchanged" -Got $(if ($i -lt $lines.Count) { $lines[$i] }) -Want $want[$i] }
    $labels = @($lines | ForEach-Object { if ($_ -match '^- \*\*([^*]+):\*\*') { $Matches[1] } })
    $order = @('Hosts', 'NAS NFS exports', 'NAS SMB', 'NAS anonymous shares listed', 'Open Wi-Fi AP',
        'WAN (external) ports visible', 'Threat monitor last run', 'Posture score')
    Check -What 'bullets follow the agreed order' -Got ($labels -join ' | ') -Want (@($order | Where-Object { $labels -contains $_ }) -join ' | ')
    Check -What 'no bullet outside the agreed set' -Got (@($labels | Where-Object { $order -notcontains $_ }).Count) -Want 0
    Check -What 'posture score is the last bullet' -Got $(if ($lines.Count) { $lines[-1] }) -Want '- **Posture score:** $postureScore'

    Write-Host ""
    Write-Host "Invoke-WeeklyNetworkScan.ps1 writes findings.json on every run"
    $calls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
            Where-Object { @('ConvertTo-WeeklyFindings', 'Write-WeeklyFindings') -contains $_.GetCommandName() })
    foreach ($name in @('ConvertTo-WeeklyFindings', 'Write-WeeklyFindings')) {
        $c = @($calls | Where-Object { $_.GetCommandName() -eq $name })
        $conditional = @($c | Where-Object {
                $p = $_.Parent; $inIf = $false
                while ($p) { if ($p -is [System.Management.Automation.Language.IfStatementAst]) { $inIf = $true }; $p = $p.Parent }
                $inIf })
        Check -What "$name is called, not under an if" -Got ($c.Count -ge 1 -and $conditional.Count -eq 0) -Want $true
    }
}
finally {
    Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host ("{0} passed, {1} failed" -f $pass, $fail)
if ($fail) { exit 1 }
