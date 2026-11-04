<#
.SYNOPSIS
  The footprint.json contract as code: a hand-written validator and the run-to-run comparison.
.DESCRIPTION
  Dot-sourced by Compare-Footprint.ps1 and by tests/Test-CompareFootprint.ps1. Pure functions:
  no file or network access.

  references/footprint-schema.json is the documented contract. It is not read at run time,
  because Windows PowerShell 5.1 (the scheduled task's host) has no Test-Json; the rules are
  repeated in $FootprintRules below and the test fails if the two disagree.

    Test-FootprintDocument   -> $null when valid, else "<json path>: <reason>" for the FIRST
                                failure, for example "$.findings[2].severity: must be one of
                                page|nudge|log (got 'High')".
    Compare-FootprintDocument -> the footprint-diff object (new, removed, not_reassessed,
                                severity_changed). Both inputs must already be valid.
.NOTES
  TheHub #60991. ASCII only; runs on Windows PowerShell 5.1 and pwsh 7.
#>

$script:FootprintRules = @{
  IdPattern       = '^[a-z0-9-]+:[a-z0-9.-]+$'
  CategoryPattern = '^[a-z0-9-]+$'
  SourcePattern   = '^[a-z0-9.-]+$'
  DatePattern     = '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'
  Severity        = @('page', 'nudge', 'log')
  Confidence      = @('confirmed', 'inferred', 'ambiguous')
  Status          = @('open', 'removed', 'untested')
  TopRequired     = @('schema_version', 'run_date', 'findings')
  TopOptional     = @('notes')
  ItemRequired    = @('id', 'category', 'source', 'severity', 'confidence', 'status')
  ItemOptional    = @('summary', 'exposed', 'removal_action', 'first_seen', 'evidence')
}

function Get-FootprintProperty([object]$Object, [string]$Name) {
  # Case-sensitive: 'Severity' is not 'severity'.
  foreach ($p in $Object.PSObject.Properties) {
    if ($p.Name -ceq $Name) { return , @{ Found = $true; Value = $p.Value } }
  }
  return , @{ Found = $false; Value = $null }
}

function Test-FootprintDate([object]$Value) {
  if ($Value -isnot [string] -or $Value -cnotmatch $script:FootprintRules.DatePattern) { return $false }
  $d = [datetime]::MinValue
  return [datetime]::TryParseExact($Value, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$d)
}

function Format-FootprintValue([object]$Value) {
  if ($null -eq $Value) { return 'null' }
  return "'$Value'"
}

function Test-FootprintDocument {
  [CmdletBinding()]
  [OutputType([string])]
  param([AllowNull()][object]$Document)

  $R = $script:FootprintRules
  if ($Document -isnot [System.Management.Automation.PSCustomObject]) {
    return '$: must be a JSON object'
  }
  foreach ($p in $Document.PSObject.Properties) {
    if (($R.TopRequired + $R.TopOptional) -cnotcontains $p.Name) {
      return "`$.$($p.Name): not in the contract (allowed: $(($R.TopRequired + $R.TopOptional) -join ', '))"
    }
  }
  foreach ($k in $R.TopRequired) {
    if (-not (Get-FootprintProperty $Document $k).Found) { return "`$.${k}: required" }
  }

  $v = (Get-FootprintProperty $Document 'schema_version').Value
  if (-not (($v -is [int] -or $v -is [long]) -and $v -eq 1)) {
    return "`$.schema_version: must be the integer 1 (got $(Format-FootprintValue $v))"
  }
  $v = (Get-FootprintProperty $Document 'run_date').Value
  if (-not (Test-FootprintDate $v)) {
    return "`$.run_date: must be a yyyy-MM-dd date string (got $(Format-FootprintValue $v))"
  }
  $notes = Get-FootprintProperty $Document 'notes'
  if ($notes.Found -and $notes.Value -isnot [string]) { return '$.notes: must be a string' }

  $findings = (Get-FootprintProperty $Document 'findings').Value
  if ($null -eq $findings -or $findings -isnot [array]) { return '$.findings: must be an array' }

  $seen = @{}
  for ($i = 0; $i -lt $findings.Count; $i++) {
    $f = $findings[$i]
    $at = "`$.findings[$i]"
    if ($f -isnot [System.Management.Automation.PSCustomObject]) { return "${at}: must be an object" }
    foreach ($p in $f.PSObject.Properties) {
      if (($R.ItemRequired + $R.ItemOptional) -cnotcontains $p.Name) {
        return "$at.$($p.Name): not in the contract (allowed: $(($R.ItemRequired + $R.ItemOptional) -join ', '))"
      }
    }
    $item = @{}
    foreach ($k in $R.ItemRequired) {
      $got = Get-FootprintProperty $f $k
      if (-not $got.Found) { return "$at.${k}: required" }
      if ($got.Value -isnot [string]) { return "$at.${k}: must be a string (got $(Format-FootprintValue $got.Value))" }
      $item[$k] = $got.Value
    }

    if ($item.id -cnotmatch $R.IdPattern) {
      return "$at.id: must match $($R.IdPattern), category:source, never a run-scoped id (got '$($item.id)')"
    }
    if ($seen.ContainsKey($item.id)) {
      return "$at.id: duplicate of `$.findings[$($seen[$item.id])].id ('$($item.id)')"
    }
    $seen[$item.id] = $i
    if ($item.category -cnotmatch $R.CategoryPattern) {
      return "$at.category: must match $($R.CategoryPattern) (got '$($item.category)')"
    }
    if ($item.source -cnotmatch $R.SourcePattern) {
      return "$at.source: must match $($R.SourcePattern) (got '$($item.source)')"
    }
    $want = "$($item.category):$($item.source)"
    if ($item.id -cne $want) {
      return "$at.id: must be category:source, '$want' (got '$($item.id)')"
    }
    foreach ($pair in @(@('severity', $R.Severity), @('confidence', $R.Confidence), @('status', $R.Status))) {
      $k = $pair[0]; $allowed = $pair[1]
      if ($allowed -cnotcontains $item[$k]) {
        return "$at.${k}: must be one of $($allowed -join '|') (got '$($item[$k])')"
      }
    }

    foreach ($k in 'summary', 'removal_action', 'evidence') {
      $got = Get-FootprintProperty $f $k
      if ($got.Found -and $got.Value -isnot [string]) { return "$at.${k}: must be a string" }
    }
    $got = Get-FootprintProperty $f 'first_seen'
    if ($got.Found -and -not (Test-FootprintDate $got.Value)) {
      return "$at.first_seen: must be a yyyy-MM-dd date string (got $(Format-FootprintValue $got.Value))"
    }
    $got = Get-FootprintProperty $f 'exposed'
    if ($got.Found) {
      if ($got.Value -isnot [array]) { return "$at.exposed: must be an array of strings" }
      for ($j = 0; $j -lt $got.Value.Count; $j++) {
        if ($got.Value[$j] -isnot [string]) { return "$at.exposed[$j]: must be a string" }
      }
    }
  }
  return $null
}

function Compare-FootprintDocument {
  <#
    new               open in current; absent from the baseline, or 'removed' there (reappeared)
    removed           'removed' in current; open or untested in the baseline
    not_reassessed    open or untested in the baseline; absent from current, or 'untested' there.
                      An id that drops out of a run is never counted as removed.
    severity_changed  open in both, severity differs
  #>
  [CmdletBinding()]
  [OutputType([System.Collections.Specialized.OrderedDictionary])]
  param(
    [Parameter(Mandatory = $true)][object]$Baseline,
    [Parameter(Mandatory = $true)][object]$Current
  )
  $base = @{}
  foreach ($f in @($Baseline.findings)) { $base[$f.id] = $f }
  $cur = @{}
  foreach ($f in @($Current.findings)) { $cur[$f.id] = $f }

  $new = [System.Collections.Generic.List[object]]::new()
  $removed = [System.Collections.Generic.List[object]]::new()
  $notReassessed = [System.Collections.Generic.List[object]]::new()
  $severityChanged = [System.Collections.Generic.List[object]]::new()

  foreach ($f in @($Current.findings)) {
    $b = $base[$f.id]
    if ($f.status -ceq 'open') {
      if ($null -eq $b -or $b.status -ceq 'removed') {
        $new.Add([ordered]@{ id = $f.id; severity = $f.severity; confidence = $f.confidence; reappeared = ($null -ne $b) })
      } elseif ($b.status -ceq 'open' -and $b.severity -cne $f.severity) {
        $severityChanged.Add([ordered]@{ id = $f.id; from = $b.severity; to = $f.severity })
      }
    } elseif ($f.status -ceq 'removed') {
      if ($null -ne $b -and $b.status -cne 'removed') {
        $removed.Add([ordered]@{ id = $f.id; severity = $b.severity })
      }
    }
  }
  foreach ($b in @($Baseline.findings)) {
    if ($b.status -ceq 'removed') { continue }
    $c = $cur[$b.id]
    if ($null -eq $c) {
      $notReassessed.Add([ordered]@{ id = $b.id; severity = $b.severity; reason = 'absent' })
    } elseif ($c.status -ceq 'untested') {
      $notReassessed.Add([ordered]@{ id = $b.id; severity = $b.severity; reason = 'untested' })
    }
  }

  return [ordered]@{
    baseline_run_date = $Baseline.run_date
    current_run_date  = $Current.run_date
    new               = $new.ToArray()
    removed           = $removed.ToArray()
    not_reassessed    = $notReassessed.ToArray()
    severity_changed  = $severityChanged.ToArray()
  }
}
