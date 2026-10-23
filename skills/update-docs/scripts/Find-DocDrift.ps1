<#
.SYNOPSIS
  Documentation drift detector. Lists source files that changed since a doc was
  last updated — i.e. likely-stale documentation candidates.
.DESCRIPTION
  Finds the commit that last touched the doc, then shows source files under the
  given paths that have commits after it. Read-only (git history only).

  REPORT ONLY. Drift is listed for a human to review; finding it never makes this
  script exit non-zero, so nothing that runs it (the Concourse doc-drift job included)
  fails a build on drift. It exits non-zero only when it cannot answer at all - not a
  git repository, or the doc does not exist - because an unanswered check is not a
  clean one.
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
  # stderr is discarded on purpose: outside a work tree git prints "fatal: not a
  # git repository" and stdout is empty, which is the answer. Captured first so
  # the redirection is not inside the condition.
  $insideWorkTree = git rev-parse --is-inside-work-tree 2>$null
  if (-not $insideWorkTree) { throw "Not a git repository: $Repo" }
  if (-not (Test-Path $Doc)) { throw "Doc not found: $Doc" }

  # commit that last modified the doc. Wrapped in "$()" because git prints
  # nothing for a doc with no history, and $null.Trim() threw before the
  # warning below could be reached (TheHub #60939).
  $docCommit = "$(git log -1 --format='%H' -- "$Doc")".Trim()
  if (-not $docCommit) { Write-Warning "No commit history for $Doc (uncommitted?). Treating all source as newer."; $docCommit = (git rev-list --max-parents=0 HEAD | Select-Object -Last 1).Trim() }
  $docDate = "$(git log -1 --format='%ci' -- "$Doc")".Trim()
  if (-not $docDate) { $docDate = 'never committed' }

  Write-Host "Doc:        $Doc" -ForegroundColor Cyan
  Write-Host "Last doc'd: $docDate ($($docCommit.Substring(0,8)))" -ForegroundColor Cyan
  Write-Host "Checking:   $($Paths -join ', ')" -ForegroundColor Cyan
  Write-Host "Mode:       report only - drift is listed for review and never fails the build" -ForegroundColor Cyan
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
    Write-Host "(Report only: drift candidates do not fail the build.)" -ForegroundColor DarkGray
  }
} finally { Pop-Location }
