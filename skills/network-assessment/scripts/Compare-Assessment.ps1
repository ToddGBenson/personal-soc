<#
.SYNOPSIS
  Change detection + posture scoring across two assessment runs — ports a production SOC's
  NMAP/OSINT change-detection and self-assessment score into the skill.
.DESCRIPTION
  Compares two engagement folders (each with findings.json and optional inventory.csv):
  resolved / new / severity-changed findings, host add/remove, and a 0-100 posture
  score with delta. Read-only; no scanning.
.EXAMPLE
  .\Compare-Assessment.ps1 -Baseline C:\...\netassess\2026-08-07 -Current C:\...\netassess\2026-08-09
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Baseline,   # folder with baseline findings.json (+ inventory.csv)
  [Parameter(Mandatory)][string]$Current     # folder with current findings.json (+ inventory.csv)
)
$ErrorActionPreference = 'Stop'

# --- posture score model (documented weights; open findings only) ---
$W = @{ critical = 15; high = 6; medium = 2; low = 1 }
function Get-Score($findings){
  $s = 100
  foreach($f in $findings){ if($f.status -eq 'open'){ $s -= [int]$W[$f.severity.ToLower()] } }
  [Math]::Max(0, $s)
}
function Band($s){ if($s -ge 85){'Strong'}elseif($s -ge 70){'Good'}elseif($s -ge 50){'Fair'}elseif($s -ge 25){'Poor'}else{'Critical'} }

function Load($dir){
  $p = Join-Path $dir 'findings.json'
  if(-not (Test-Path $p)){ throw "findings.json not found in $dir" }
  ,(Get-Content $p -Raw | ConvertFrom-Json)
}
$base = Load $Baseline
$cur  = Load $Current
$baseById = @{}; foreach($f in $base){ $baseById[$f.id] = $f }
$curById  = @{}; foreach($f in $cur){ $curById[$f.id]  = $f }

Write-Host "`n=== ASSESSMENT CHANGE DETECTION ===" -ForegroundColor Cyan
Write-Host ("baseline: {0}" -f (Split-Path $Baseline -Leaf))
Write-Host ("current : {0}" -f (Split-Path $Current  -Leaf))

# --- RESOLVED: open in baseline, now resolved/absent ---
Write-Host "`n-- Resolved --" -ForegroundColor Green
$resolved = @()
foreach($f in $base){
  if($f.status -eq 'open'){
    $c = $curById[$f.id]
    if(-not $c -or $c.status -eq 'resolved'){ $resolved += $f; "  [{0,-8}] {1}" -f $f.severity.ToUpper(), $f.title }
  }
}
if(-not $resolved){ "  (none)" }

# --- NEW: open in current, not open in baseline ---
Write-Host "`n-- New --" -ForegroundColor Yellow
$new = @()
foreach($f in $cur){
  if($f.status -eq 'open'){
    $b = $baseById[$f.id]
    if(-not $b){ $new += $f; "  [{0,-8}] {1}" -f $f.severity.ToUpper(), $f.title }
  }
}
if(-not $new){ "  (none)" }

# --- SEVERITY CHANGES ---
Write-Host "`n-- Severity changed --" -ForegroundColor DarkYellow
$chg = @()
foreach($f in $cur){
  $b = $baseById[$f.id]
  if($b -and $b.severity -ne $f.severity -and $f.status -eq 'open'){ $chg += $f; "  {0}: {1} -> {2}" -f $f.title, $b.severity, $f.severity }
}
if(-not $chg){ "  (none)" }

# --- HOST DIFF (inventory.csv) ---
$bInv = Join-Path $Baseline 'inventory.csv'; $cInv = Join-Path $Current 'inventory.csv'
if((Test-Path $bInv) -and (Test-Path $cInv)){
  $bMac = (Import-Csv $bInv).MAC | ForEach-Object { $_.ToUpper() }
  $cMac = (Import-Csv $cInv).MAC | ForEach-Object { $_.ToUpper() }
  Write-Host "`n-- Host changes --" -ForegroundColor Magenta
  $added = $cMac | Where-Object { $bMac -notcontains $_ }
  $removed = $bMac | Where-Object { $cMac -notcontains $_ }
  if($added){ $added | ForEach-Object { "  + new host  $_" } }
  if($removed){ $removed | ForEach-Object { "  - gone      $_" } }
  if(-not $added -and -not $removed){ "  (no host add/remove)" }
}

# --- SCORE ---
$bs = Get-Score $base; $cs = Get-Score $cur; $d = $cs - $bs
Write-Host "`n=== POSTURE SCORE ===" -ForegroundColor Cyan
"  baseline : {0,3}/100  ({1})" -f $bs, (Band $bs)
"  current  : {0,3}/100  ({1})" -f $cs, (Band $cs)
$sign = if($d -ge 0){"+"}else{""}
$col = if($d -gt 0){'Green'}elseif($d -lt 0){'Red'}else{'Gray'}
Write-Host ("  delta    : {0}{1}" -f $sign, $d) -ForegroundColor $col
Write-Host ""

# emit machine-readable summary
$summary = [PSCustomObject]@{
  resolved = $resolved.Count; new = $new.Count; severity_changed = $chg.Count
  score_baseline = $bs; score_current = $cs; score_delta = $d
  band_current = (Band $cs)
}
$summary | ConvertTo-Json -Compress | Set-Content (Join-Path $Current 'change-summary.json')
$summary