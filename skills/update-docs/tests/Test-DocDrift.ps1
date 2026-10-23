<#
.SYNOPSIS
    Find-DocDrift.ps1 against throwaway git repositories. No network.

.DESCRIPTION
    TheHub #60939. Find-DocDrift had no test in this repository; its only
    checks were three inline assertions in the Concourse functional job, so a
    change here could not be tested where it was made.

    Each case builds a small git repository under the temp directory, commits
    a doc and some source in a known order, and runs the script for real.
    Output is captured with *>&1, not 2>&1: the script reports through
    Write-Host (the information stream), and a capture that misses it makes
    "does not report X" pass against an empty string.

    What is pinned:
      - nothing newer than the doc -> "likely current", no file listed
      - every source file changed in ANY commit after the doc is listed,
        not only the latest commit's
      - changes outside -Paths are not drift
      - updating the doc clears the drift
      - -Repo works from another directory
      - report only: drift exits 0; no repository, or no doc, exits non-zero
        (an unanswered check is not a clean one)
      - an uncommitted doc is warned about and compared from the root commit

.NOTES
    Usage: pwsh -NoProfile -File skills/update-docs/tests/Test-DocDrift.ps1
    Needs git on PATH. ASCII only.
#>

$ErrorActionPreference = 'Stop'
$drift = (Resolve-Path "$PSScriptRoot/../scripts/Find-DocDrift.ps1").Path

$pass = 0; $fail = 0
function Check([string]$Name, [scriptblock]$Test, [string]$Shown) {
    if (& $Test) { Write-Host ("  [ok]   {0,-58} {1}" -f $Name, $Shown); $script:pass++ }
    else { Write-Host ("  [FAIL] {0,-58} got '{1}'" -f $Name, $Shown); $script:fail++ }
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("docdrift-test-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null

# git, with this host's global hooks and signing kept out of the fixture.
function G {
    $hooks = Join-Path $tmp 'no-hooks'
    & git -c "core.hooksPath=$hooks" -c commit.gpgsign=false -c user.email=test@example.com -c user.name=test @args
    if ($LASTEXITCODE -ne 0) { throw "git $($args -join ' ') exited $LASTEXITCODE" }
}

function MakeRepo([string]$Name) {
    $p = Join-Path $tmp $Name
    New-Item -ItemType Directory -Path $p | Out-Null
    Push-Location $p
    G init -q
    New-Item -ItemType Directory -Path src, other | Out-Null
    Set-Content README.md 'doc'
    Set-Content src/a.ps1 'Write-Output 1'
    Set-Content src/b.ps1 'Write-Output 1'
    Set-Content other/c.ps1 'Write-Output 1'
    G add -A
    G commit -q -m initial
    return $p
}

function Edit-Commit([string]$File, [string]$Body) {
    Set-Content $File $Body
    G add -A
    G commit -q -m "edit $File"
}

function Invoke-Drift([hashtable]$Params) {
    return (& $drift @Params *>&1 | Out-String)
}

# Run in a separate pwsh, as the doc-drift job does, for the exit code.
function Get-DriftExitCode([string[]]$Arguments) {
    $exe = (Get-Process -Id $PID).Path
    & $exe -NoProfile -NonInteractive -File $drift @Arguments *> $null
    return $LASTEXITCODE
}

try {
    Write-Host ""
    Write-Host "drift and no drift"

    MakeRepo -Name 'r1' | Out-Null
    $o = Invoke-Drift @{ Doc = 'README.md'; Paths = 'src' }
    Check -Name "doc is the newest change -> likely current" -Test { $o -match 'likely current' -and $o -notmatch 'src/' } -Shown ''

    Edit-Commit 'src/a.ps1' 'Write-Output 2'
    Edit-Commit 'src/b.ps1' 'Write-Output 2'
    $o = Invoke-Drift @{ Doc = 'README.md'; Paths = 'src' }
    Check -Name "a file changed two commits ago is still listed" -Test { $o -match 'src/a\.ps1' } -Shown ''
    Check -Name "the latest change is listed" -Test { $o -match 'src/b\.ps1' } -Shown ''
    Check -Name "the count covers both" -Test { $o -match 'updated \(2\)' } -Shown (($o -split "`n" | Select-String 'updated \(') -join '')
    Check -Name "drift does not also say current" -Test { $o -notmatch 'likely current' } -Shown ''

    Edit-Commit 'other/c.ps1' 'Write-Output 2'
    $o = Invoke-Drift @{ Doc = 'README.md'; Paths = 'src' }
    Check -Name "a change outside -Paths is not drift" -Test { $o -notmatch 'other/c\.ps1' } -Shown ''
    $o = Invoke-Drift @{ Doc = 'README.md'; Paths = @('src', 'other') }
    Check -Name "every -Paths entry is checked" -Test { $o -match 'other/c\.ps1' -and $o -match 'src/a\.ps1' } -Shown ''

    Edit-Commit 'README.md' 'doc, updated'
    $o = Invoke-Drift @{ Doc = 'README.md'; Paths = @('src', 'other') }
    Check -Name "updating the doc clears the drift" -Test { $o -match 'likely current' -and $o -notmatch 'src/a\.ps1' } -Shown ''
    $repo1 = (Get-Location).Path
    Pop-Location

    Write-Host ""
    Write-Host "-Repo"

    Push-Location $tmp
    try {
        Push-Location $repo1
        Edit-Commit 'src/a.ps1' 'Write-Output 3'
        Pop-Location
        $o = Invoke-Drift @{ Doc = 'README.md'; Paths = 'src'; Repo = $repo1 }
        Check -Name "-Repo answers about that repository, not the cwd" -Test { $o -match 'src/a\.ps1' } -Shown ''
        Check -Name "the caller's directory is restored" -Test { (Get-Location).Path -eq $tmp } -Shown (Get-Location).Path
    } finally { Pop-Location }

    Write-Host ""
    Write-Host "report only, but an unanswered check is not clean"

    $code = Get-DriftExitCode @('-Doc', 'README.md', '-Paths', 'src', '-Repo', $repo1)
    Check -Name "drift found -> exit 0" -Test { $code -eq 0 } -Shown "exit $code"

    $code = Get-DriftExitCode @('-Doc', 'NOPE.md', '-Paths', 'src', '-Repo', $repo1)
    Check -Name "doc does not exist -> non-zero" -Test { $code -ne 0 } -Shown "exit $code"

    $plain = Join-Path $tmp 'not-a-repo'
    New-Item -ItemType Directory -Path $plain | Out-Null
    Set-Content (Join-Path $plain 'README.md') 'doc'
    $code = Get-DriftExitCode @('-Doc', 'README.md', '-Repo', $plain)
    Check -Name "not a git repository -> non-zero" -Test { $code -ne 0 } -Shown "exit $code"

    $msg = ''
    try { Invoke-Drift @{ Doc = 'README.md'; Repo = $plain } | Out-Null } catch { $msg = $_.Exception.Message }
    Check -Name "and says which" -Test { $msg -like 'Not a git repository*' } -Shown $msg
    $msg = ''
    try { Invoke-Drift @{ Doc = 'NOPE.md'; Repo = $repo1 } | Out-Null } catch { $msg = $_.Exception.Message }
    Check -Name "and says which (doc)" -Test { $msg -like 'Doc not found*' } -Shown $msg

    Write-Host ""
    Write-Host "an uncommitted doc"

    MakeRepo -Name 'r2' | Out-Null
    Edit-Commit 'src/a.ps1' 'Write-Output 2'
    Set-Content NEW.md 'new doc, never committed'
    $o = Invoke-Drift @{ Doc = 'NEW.md'; Paths = 'src' }
    Check -Name "warned as having no history" -Test { $o -match 'No commit history for NEW\.md' } -Shown ''
    Check -Name "compared from the root commit" -Test { $o -match 'src/a\.ps1' -and $o -notmatch 'src/b\.ps1' } -Shown ''
    Pop-Location
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
