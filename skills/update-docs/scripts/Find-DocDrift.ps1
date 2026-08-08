<#
.SYNOPSIS
  Documentation drift detector. Lists source files that changed since a doc was
  last updated — i.e. likely-stale documentation candidates.
.DESCRIPTION
  Finds the commit that last touched the doc, then shows source files under the
  given paths that have commits after it. Read-only (git history only).
.EXAMPLE
  .\Find-DocDrift.ps1 -Doc README.md -Paths src,scripts
.EXAMPLE
  .\Find-DocDrift.ps1 -Doc skills/network-assessment/SKILL.md -Paths skills/network-assessment
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Doc,               # path to the documentation file
  [string[]]$Paths = @('.'),                         # source paths to check for newer changes
  [string]$Repo = '.'                                # repo root
)
$ErrorActionPreference = 'Stop'
Push-Location $Repo
try {
  if (-not (git rev-parse --is-inside-work-tree 2>$null)) { throw "Not a git repository: $Repo" }
  if (-not (Test-Path $Doc)) { throw "Doc not found: $Doc" }

  # commit that last modified the doc
  $docCommit = (git log -1 --format='%H' -- "$Doc").Trim()
  if (-not $docCommit) { Write-Warning "No commit history for $Doc (uncommitted?). Treating all source as newer."; $docCommit = (git rev-list --max-parents=0 HEAD | Select-Object -Last 1).Trim() }
  $docDate = (git log -1 --format='%ci' -- "$Doc").Trim()

  Write-Host "Doc:        $Doc" -ForegroundColor Cyan
  Write-Host "Last doc'd: $docDate ($($docCommit.Substring(0,8)))" -ForegroundColor Cyan
  Write-Host "Checking:   $($Paths -join ', ')" -ForegroundColor Cyan
  Write-Host ""

  # source files changed AFTER the doc's last commit
  $changed = git diff --name-only "$docCommit..HEAD" -- @Paths | Where-Object { $_ -and $_ -ne $Doc }

  if (-not $changed) {
    Write-Host "No source changes since the doc was last updated. Docs are likely current." -ForegroundColor Green
  } else {
    Write-Host "Source files changed since the doc was last updated ($($changed.Count)) — review for drift:" -ForegroundColor Yellow
    foreach ($f in $changed) {
      $when = (git log -1 --format='%ci' -- "$f").Trim()
      "{0,-55} {1}" -f $f, $when
    }
    Write-Host "`nNext: read these files (ground truth), then update $Doc per the content model." -ForegroundColor DarkGray
  }
} finally { Pop-Location }
