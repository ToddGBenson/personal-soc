<#
.SYNOPSIS
    Runs every skills/*/tests/Test-*.ps1 and fails if any of them fails.

.DESCRIPTION
    TheHub #61738: no check posted on most PRs, so a broken test could merge
    unseen. This is the one entry point the `tests` workflow calls, and the one
    to run locally before pushing.

    Each test file runs in its own pwsh process, so one test's functions,
    variables or location cannot leak into the next. The suite fails when:
      - any test file exits non-zero, or
      - no test files are found (a moved tests/ folder must not read as green).

.NOTES
    Usage: pwsh -NoProfile -File .github/scripts/Invoke-AllTests.ps1
    ASCII only.
#>

$ErrorActionPreference = 'Stop'
$root  = Resolve-Path (Join-Path $PSScriptRoot '../..')
$tests = @(Get-ChildItem -Path (Join-Path $root 'skills') -Recurse -File -Filter 'Test-*.ps1' |
           Where-Object { $_.Directory.Name -eq 'tests' } | Sort-Object FullName)

if ($tests.Count -eq 0) {
    Write-Host "::error::No skills/*/tests/Test-*.ps1 files found - refusing to report success."
    exit 1
}

$pwsh = (Get-Process -Id $PID).Path
$failed = @()
foreach ($t in $tests) {
    $rel = [IO.Path]::GetRelativePath($root, $t.FullName)
    Write-Host ""
    Write-Host "=== $rel"
    & $pwsh -NoProfile -File $t.FullName
    $rc = $LASTEXITCODE
    if ($rc -ne 0) {
        Write-Host "::error file=$rel::$rel exited $rc"
        $failed += "$rel (exit $rc)"
    }
}

Write-Host ""
Write-Host ("{0} test files, {1} failed" -f $tests.Count, $failed.Count)
if ($failed.Count -gt 0) {
    $failed | ForEach-Object { Write-Host "  FAILED: $_" }
    exit 1
}
exit 0
