<#
.SYNOPSIS
  Deterministic run-to-run diff of Check A's footprint.json: what is new, removed, not
  reassessed, or changed severity since the previous run.
.DESCRIPTION
  Reads <Baseline>\footprint.json and <Current>\footprint.json, validates both against the
  contract in references/footprint-schema.json (by the hand-written validator in
  FootprintSchema.ps1; Windows PowerShell 5.1 has no Test-Json), and writes
  <OutDir>\footprint-diff.json:

    {
      "baseline_run_date": "...", "current_run_date": "...",
      "new":              [ { id, severity, confidence, reappeared } ],
      "removed":          [ { id, severity } ],
      "not_reassessed":   [ { id, severity, reason: absent|untested } ],
      "severity_changed": [ { id, from, to } ]
    }

  An id that is open in the baseline and absent from the current run is not_reassessed,
  never removed: a broker listing that silently drops out of a run has not been fixed. Only
  an explicit status 'removed' counts as removed.

  Exit codes:
    0  compared; footprint-diff.json written
    2  either footprint.json is missing, not JSON, or fails the contract. The first failing
       JSON path is printed and nothing is written.
.PARAMETER Baseline
  The previous run's folder, for example personal-monitor\2026-10-11.
.PARAMETER Current
  This run's folder, for example personal-monitor\2026-10-18.
.PARAMETER OutDir
  Where footprint-diff.json goes. Default: -Current.
.EXAMPLE
  .\Compare-Footprint.ps1 -Baseline .\personal-monitor\2026-10-11 -Current .\personal-monitor\2026-10-18
.NOTES
  TheHub #60991. ASCII only; runs on Windows PowerShell 5.1 and pwsh 7.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Baseline,
  [Parameter(Mandatory = $true)][string]$Current,
  [string]$OutDir
)
$ErrorActionPreference = 'Stop'
. (Join-Path -Path $PSScriptRoot -ChildPath 'FootprintSchema.ps1')

if (-not $OutDir) { $OutDir = $Current }

function Stop-Invalid([string]$File, [string]$Why) {
  Write-Host "INVALID: $File at $Why. No diff written; this is not a pass." -ForegroundColor Yellow
  exit 2
}

function Read-Footprint([string]$Dir) {
  $file = Join-Path -Path $Dir -ChildPath 'footprint.json'
  if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { Stop-Invalid $file '$: file not found' }
  $text = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $file).Path)
  $doc = $null
  try { $doc = ConvertFrom-Json -InputObject $text } catch { Stop-Invalid $file "`$: not valid JSON ($($_.Exception.Message -replace '\s+', ' '))" }
  $why = Test-FootprintDocument -Document $doc
  if ($why) { Stop-Invalid $file $why }
  return $doc
}

$base = Read-Footprint $Baseline
$cur = Read-Footprint $Current
$diff = Compare-FootprintDocument -Baseline $base -Current $cur

if (-not (Test-Path -LiteralPath $OutDir -PathType Container)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$out = Join-Path -Path (Resolve-Path -LiteralPath $OutDir).Path -ChildPath 'footprint-diff.json'
[IO.File]::WriteAllText($out, (ConvertTo-Json -InputObject $diff -Depth 6))

Write-Host ("{0} -> {1}: new {2}, removed {3}, not reassessed {4}, severity changed {5}" -f `
    $diff.baseline_run_date, $diff.current_run_date, $diff.new.Count, $diff.removed.Count, $diff.not_reassessed.Count, $diff.severity_changed.Count)
Write-Host "Wrote $out"
exit 0
