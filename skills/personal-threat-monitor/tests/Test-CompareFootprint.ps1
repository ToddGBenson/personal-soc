<#
.SYNOPSIS
    Compare-Footprint.ps1 and the footprint.json contract, against fixtures
    written to a temp dir at runtime.

.DESCRIPTION
    TheHub #60991. Check A's "what is new since last run" used to be a diff the
    model did in its head, against a footprint.json whose shape changed every
    run and whose ids were run-scoped ('<run-date>-NN'), so no id was ever
    reused and a broker listing that silently dropped out of a run read as
    fixed. This pins the replacement:

      - the contract (references/footprint-schema.json) and the hand-written
        validator (scripts/FootprintSchema.ps1) agree, and the validator does
        not lean on Test-Json, which Windows PowerShell 5.1 does not have
      - an invalid footprint.json is exit 2 and names the first failing JSON
        path; no diff is written
      - an id open in the baseline and absent from the current run is
        not_reassessed, never removed
      - an id reused across runs is not new

    footprint.json is git-ignored, so every fixture is built here at runtime.

    ALL FIXTURES ARE CONSTRUCTED. Sources are placeholder keys
    (broker:example-people, paste:example-paste, ...) and domains are RFC 2606
    names. Nothing here describes a real person.

.NOTES
    Usage: pwsh -NoProfile -File skills/personal-threat-monitor/tests/Test-CompareFootprint.ps1
           powershell -NoProfile -File skills/personal-threat-monitor/tests/Test-CompareFootprint.ps1
    ASCII only.
#>

$ErrorActionPreference = 'Stop'
$script:SkillRoot = (Resolve-Path "$PSScriptRoot/..").Path
$script:Compare = Join-Path -Path $script:SkillRoot -ChildPath 'scripts/Compare-Footprint.ps1'
$script:Functions = Join-Path -Path $script:SkillRoot -ChildPath 'scripts/FootprintSchema.ps1'
$script:Schema = Join-Path -Path $script:SkillRoot -ChildPath 'references/footprint-schema.json'
$script:Skill = Join-Path -Path $script:SkillRoot -ChildPath 'SKILL.md'

$pass = 0; $fail = 0
function Check([string]$Name, [scriptblock]$Test, [string]$Shown) {
    $ok = $false
    try { $ok = [bool](& $Test) } catch { $Shown = "threw: $($_.Exception.Message)" }
    if ($ok) { Write-Host ("  [ok]   {0,-66} {1}" -f $Name, $Shown); $script:pass++ }
    else { Write-Host ("  [FAIL] {0,-66} got '{1}'" -f $Name, $Shown); $script:fail++ }
}

if (Test-Path -LiteralPath $script:Functions) { . $script:Functions }

$tmp = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath ("footprint-test-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null

function Finding([string]$Category, [string]$Source, [string]$Severity = 'nudge', [string]$Status = 'open', [string]$Confidence = 'confirmed') {
    [ordered]@{
        id         = "${Category}:${Source}"
        category   = $Category
        source     = $Source
        severity   = $Severity
        confidence = $Confidence
        status     = $Status
        summary    = "placeholder listing on $Source.example.com"
    }
}

function Doc([string]$RunDate, [object[]]$Findings) {
    [ordered]@{ schema_version = 1; run_date = $RunDate; findings = @($Findings) }
}

# Writes <tmp>/<guid>/footprint.json; -Raw writes the text as given, -NoFile
# leaves the folder empty.
function RunDir([object]$Document, [string]$Raw, [switch]$NoFile) {
    $d = Join-Path -Path $tmp -ChildPath ([guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $d | Out-Null
    $text = if ($PSBoundParameters.ContainsKey('Raw')) { $Raw } else { ConvertTo-Json -InputObject $Document -Depth 8 }
    if (-not $NoFile) { [IO.File]::WriteAllText((Join-Path -Path $d -ChildPath 'footprint.json'), $text) }
    return $d
}

# Runs the script, returns @{ Exit; Threw; Output; Diff; Wrote }.
function Invoke-Compare([string]$Baseline, [string]$Current) {
    $r = @{ Exit = $null; Threw = $false; Output = ''; Diff = $null; Wrote = $false }
    $global:LASTEXITCODE = $null
    try {
        $r.Output = & $script:Compare -Baseline $Baseline -Current $Current *>&1 | Out-String
        $r.Exit = $global:LASTEXITCODE
    } catch {
        $r.Threw = $true; $r.Output = $_.Exception.Message
    }
    $json = Join-Path -Path $Current -ChildPath 'footprint-diff.json'
    if (Test-Path -LiteralPath $json) {
        $r.Wrote = $true
        $r.Diff = [IO.File]::ReadAllText($json) | ConvertFrom-Json
    }
    return $r
}

function Ids([object]$Diff, [string]$Bucket) {
    if ($null -eq $Diff) { return '<no diff>' }
    return ((@($Diff.$Bucket) | Where-Object { $null -ne $_ } | ForEach-Object { $_.id }) -join ',')
}

try {
    # ---- the happy path: every bucket in one comparison ---------------------
    $base = RunDir (Doc '2026-10-11' @(
            (Finding 'broker' 'example-people' 'nudge'),     # reused, unchanged
            (Finding 'broker' 'example-search' 'nudge'),     # reused, severity up
            (Finding 'broker' 'example-lookup' 'nudge'),     # absent next run
            (Finding 'paste' 'example-paste' 'page'),        # untested next run
            (Finding 'social' 'example-forum' 'log')         # removed next run
        ))
    $cur = RunDir (Doc '2026-10-18' @(
            (Finding 'broker' 'example-people' 'nudge'),
            (Finding 'broker' 'example-search' 'page'),
            (Finding 'paste' 'example-paste' 'page' 'untested'),
            (Finding 'social' 'example-forum' 'log' 'removed'),
            (Finding 'breach' 'example.com' 'page')          # new
        ))
    $r = Invoke-Compare $base $cur
    Check -Name "valid baseline and current: exit 0" -Test { $r.Exit -eq 0 -and -not $r.Threw } -Shown "exit $($r.Exit) $($r.Output.Trim())"
    Check -Name "writes footprint-diff.json into the current run's folder" -Test { $r.Wrote } -Shown "$($r.Wrote)"
    Check -Name "new lists only the id first seen this run" -Test { (Ids $r.Diff 'new') -eq 'breach:example.com' } -Shown (Ids $r.Diff 'new')
    Check -Name "an id reused across runs is not new" -Test { $r.Wrote -and (Ids $r.Diff 'new') -notmatch 'broker:example-people' } -Shown (Ids $r.Diff 'new')
    Check -Name "removed lists the id whose status is 'removed' in current" -Test { (Ids $r.Diff 'removed') -eq 'social:example-forum' } -Shown (Ids $r.Diff 'removed')
    $nr = @((Ids $r.Diff 'not_reassessed') -split ',' | Sort-Object) -join ','
    Check -Name "not_reassessed lists the absent id and the untested id" -Test { $nr -eq 'broker:example-lookup,paste:example-paste' } -Shown $nr
    Check -Name "absent-not-removed: an open id missing from current is not removed" -Test { $r.Wrote -and (Ids $r.Diff 'removed') -notmatch 'broker:example-lookup' } -Shown (Ids $r.Diff 'removed')
    $sc = @(@($r.Diff.severity_changed) | Where-Object { $null -ne $_ })
    Check -Name "severity_changed carries id, from and to" -Test { $sc.Count -eq 1 -and $sc[0].id -eq 'broker:example-search' -and $sc[0].from -eq 'nudge' -and $sc[0].to -eq 'page' } -Shown (($sc | ForEach-Object { "$($_.id) $($_.from)->$($_.to)" }) -join ';')
    Check -Name "the diff names both run dates" -Test { $r.Diff.baseline_run_date -eq '2026-10-11' -and $r.Diff.current_run_date -eq '2026-10-18' } -Shown "$($r.Diff.baseline_run_date) $($r.Diff.current_run_date)"

    # Every bucket is an array even when empty, so a reader never sees null.
    $same = RunDir (Doc '2026-10-18' @((Finding 'broker' 'example-people')))
    $same2 = RunDir (Doc '2026-10-25' @((Finding 'broker' 'example-people')))
    $r = Invoke-Compare $same $same2
    $raw = if ($r.Wrote) { [IO.File]::ReadAllText((Join-Path -Path $same2 -ChildPath 'footprint-diff.json')) } else { '' }
    Check -Name "an unchanged run: exit 0 and four empty arrays" -Test { $r.Exit -eq 0 -and $raw -match '"new"\s*:\s*\[\s*\]' -and $raw -match '"removed"\s*:\s*\[\s*\]' -and $raw -match '"not_reassessed"\s*:\s*\[\s*\]' -and $raw -match '"severity_changed"\s*:\s*\[\s*\]' } -Shown ($raw -replace '\s+', ' ')

    # ---- invalid footprints: exit 2, the first failing path, no diff --------
    $good = RunDir (Doc '2026-10-11' @((Finding 'broker' 'example-people')))
    $cases = @(
        @{ Name = "free-text severity 'High' is rejected"; Path = '$.findings[0].severity'
            Doc = (Doc '2026-10-18' @((Finding 'broker' 'example-people' 'High'))) },
        @{ Name = "run-scoped id '2026-10-18-01' is rejected"; Path = '$.findings[0].id'
            Doc = (Doc '2026-10-18' @(([ordered]@{ id = '2026-10-18-01'; category = 'broker'; source = 'example-people'; severity = 'log'; confidence = 'confirmed'; status = 'open' }))) },
        @{ Name = "an id that is not category:source is rejected"; Path = '$.findings[1].id'
            Doc = (Doc '2026-10-18' @((Finding 'broker' 'example-people'), ([ordered]@{ id = 'broker:example-other'; category = 'broker'; source = 'example-search'; severity = 'log'; confidence = 'confirmed'; status = 'open' }))) },
        @{ Name = "a confidence outside confirmed|inferred|ambiguous is rejected"; Path = '$.findings[0].confidence'
            Doc = (Doc '2026-10-18' @((Finding 'broker' 'example-people' 'log' 'open' 'likely'))) },
        @{ Name = "a status outside open|removed|untested is rejected"; Path = '$.findings[0].status'
            Doc = (Doc '2026-10-18' @((Finding 'broker' 'example-people' 'log' 'fixed'))) },
        @{ Name = "a duplicate id is rejected at its second occurrence"; Path = '$.findings[1].id'
            Doc = (Doc '2026-10-18' @((Finding 'broker' 'example-people'), (Finding 'broker' 'example-people'))) },
        @{ Name = "a top-level key outside the contract is rejected"; Path = '$.exposures'
            Doc = ([ordered]@{ schema_version = 1; run_date = '2026-10-18'; findings = @(); exposures = @() }) },
        @{ Name = "a missing findings array is rejected"; Path = '$.findings'
            Doc = ([ordered]@{ schema_version = 1; run_date = '2026-10-18' }) },
        @{ Name = "a run_date that is not yyyy-MM-dd is rejected"; Path = '$.run_date'
            Doc = (Doc 'Oct 18' @()) },
        @{ Name = "schema_version other than 1 is rejected"; Path = '$.schema_version'
            Doc = ([ordered]@{ schema_version = 2; run_date = '2026-10-18'; findings = @() }) }
    )
    foreach ($c in $cases) {
        $bad = RunDir $c.Doc
        $r = Invoke-Compare $good $bad
        $shownPath = [regex]::Escape($c.Path)
        Check -Name "$($c.Name): exit 2" -Test { $r.Exit -eq 2 } -Shown "exit $($r.Exit)"
        Check -Name "  ...and the output names $($c.Path), no diff written" -Test { $r.Output -match "$shownPath(\W|$)" -and -not $r.Wrote } -Shown ($r.Output.Trim() -replace '\s+', ' ')
    }

    # A bad baseline is exit 2 too.
    $badBase = RunDir (Doc '2026-10-11' @((Finding 'broker' 'example-people' 'Medium')))
    $okCur = RunDir (Doc '2026-10-18' @((Finding 'broker' 'example-people')))
    $r = Invoke-Compare $badBase $okCur
    Check -Name "an invalid baseline is exit 2 and names its path" -Test { $r.Exit -eq 2 -and $r.Output -match '\$\.findings\[0\]\.severity' -and -not $r.Wrote } -Shown "exit $($r.Exit) $($r.Output.Trim())"

    $notJson = RunDir -Raw '{ "schema_version": 1, "run_date": '
    $r = Invoke-Compare $good $notJson
    Check -Name "a footprint.json that is not JSON is exit 2 at path `$" -Test { $r.Exit -eq 2 -and $r.Output -match '\$(\W|$)' -and -not $r.Wrote } -Shown "exit $($r.Exit) $($r.Output.Trim())"

    $missing = RunDir -NoFile
    $r = Invoke-Compare $good $missing
    Check -Name "a run folder with no footprint.json is exit 2" -Test { $r.Exit -eq 2 -and -not $r.Wrote } -Shown "exit $($r.Exit) $($r.Output.Trim())"

    # ---- the validator as a function --------------------------------------
    $okDoc = '{"schema_version":1,"run_date":"2026-10-18","findings":[{"id":"broker:example-people","category":"broker","source":"example-people","severity":"log","confidence":"inferred","status":"open"}]}' | ConvertFrom-Json
    $v = if (Get-Command -Name Test-FootprintDocument -ErrorAction SilentlyContinue) { Test-FootprintDocument -Document $okDoc } else { 'Test-FootprintDocument not defined' }
    Check -Name "Test-FootprintDocument returns nothing for a valid document" -Test { $null -eq $v } -Shown "$v"

    # ---- the contract file and the validator agree ------------------------
    $schemaDoc = if (Test-Path -LiteralPath $script:Schema) { [IO.File]::ReadAllText($script:Schema) | ConvertFrom-Json } else { $null }
    $item = if ($schemaDoc) { $schemaDoc.properties.findings.items.properties } else { $null }
    Check -Name "references/footprint-schema.json exists and parses" -Test { $null -ne $schemaDoc } -Shown ''
    Check -Name "schema id pattern is ^[a-z0-9-]+:[a-z0-9.-]+$" -Test { $item.id.pattern -eq '^[a-z0-9-]+:[a-z0-9.-]+$' } -Shown "$($item.id.pattern)"
    Check -Name "schema severity enum is page|nudge|log" -Test { (@($item.severity.enum) -join '|') -eq 'page|nudge|log' } -Shown (@($item.severity.enum) -join '|')
    Check -Name "schema confidence enum is confirmed|inferred|ambiguous" -Test { (@($item.confidence.enum) -join '|') -eq 'confirmed|inferred|ambiguous' } -Shown (@($item.confidence.enum) -join '|')
    Check -Name "schema status enum is open|removed|untested" -Test { (@($item.status.enum) -join '|') -eq 'open|removed|untested' } -Shown (@($item.status.enum) -join '|')
    $hasRule = Get-Variable -Name FootprintRules -Scope Script -ErrorAction SilentlyContinue
    Check -Name "the validator's id pattern and enums are the schema's" -Test {
        $hasRule -and $FootprintRules.IdPattern -eq $item.id.pattern -and
        (@($FootprintRules.Severity) -join '|') -eq (@($item.severity.enum) -join '|') -and
        (@($FootprintRules.Confidence) -join '|') -eq (@($item.confidence.enum) -join '|') -and
        (@($FootprintRules.Status) -join '|') -eq (@($item.status.enum) -join '|')
    } -Shown ''

    $srcText = (@($script:Compare, $script:Functions) | Where-Object { Test-Path -LiteralPath $_ } | ForEach-Object { [IO.File]::ReadAllText($_) }) -join "`n"
    # Comments may say why Test-Json is not used; code may not call it.
    $code = ($srcText -replace '(?s)<#.*?#>', '') -replace '(?m)#.*$', ''
    Check -Name "neither script calls Test-Json (absent on Windows PowerShell 5.1)" -Test { $srcText.Length -gt 0 -and $code -notmatch '(?i)\bTest-Json\b' } -Shown ''

    # ---- SKILL.md Check A step 5 ------------------------------------------
    $skillText = [IO.File]::ReadAllText($script:Skill)
    $step5 = ([regex]::Match($skillText, '(?ms)^## Check A.*?^5\.\s(.*?)(?=^## )')).Groups[1].Value
    Check -Name "SKILL.md Check A step 5 names footprint-schema.json" -Test { $step5 -match 'references/footprint-schema\.json' } -Shown ''
    Check -Name "  ...and scripts/Compare-Footprint.ps1" -Test { $step5 -match 'scripts/Compare-Footprint\.ps1' } -Shown ''
    Check -Name "  ...and says the id is category plus source, not the run date" -Test { $step5 -match 'broker:spokeo' -and $step5 -match '(?i)(not|never) .{0,40}run date' } -Shown ''

    # ---- what git keeps out ------------------------------------------------
    $gitOk = [bool](Get-Command -Name git -CommandType Application -ErrorAction SilentlyContinue)
    if ($gitOk) {
        Push-Location -LiteralPath $script:SkillRoot
        try {
            & git check-ignore -q -- 'personal-monitor/2026-10-18/footprint.json' 2>$null; $fpExit = $LASTEXITCODE
            & git check-ignore -q -- 'footprint-diff.json' 2>$null; $diffExit = $LASTEXITCODE
        } finally { Pop-Location }
        Check -Name "git check-ignore ignores footprint.json" -Test { $fpExit -eq 0 } -Shown "exit $fpExit"
        Check -Name "git check-ignore ignores footprint-diff.json anywhere" -Test { $diffExit -eq 0 } -Shown "exit $diffExit"
    } else {
        Write-Host "  NOTE  git not on PATH; the check-ignore cases did not run"
    }
}
finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
if ($fail -eq 0) {
    Write-Host "  $pass passed, 0 failed"
    exit 0
} else {
    Write-Host "  $pass passed, $fail FAILED"
    exit 1
}
