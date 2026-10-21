<#
.SYNOPSIS
    Get-NetViewShareVerdict against `net view` text. No network.

.DESCRIPTION
    TheHub #60852: network-status.md said "NAS anonymous shares listed: 5"
    and netassess-ingest passed, because only a count was written and nothing
    gated on it. And the count came from `Select-String 'Disk'`, so a net view
    that failed outright counted 0 - an all-clear for a NAS nobody reached.

    These fixtures pin: share names are recovered (including names too long
    for net view's column, which it wraps onto their own line), zero is a
    definite '0', and anything that is not one of net view's success lines is
    'unknown' - the word netassess-ingest fails on.

    ALL FIXTURES ARE CONSTRUCTED; share names are invented. The layout follows
    `net view \\<host>` on Windows 11 (English).

.NOTES
    Usage: pwsh -NoProfile -File skills/network-assessment/tests/Test-NetViewShareVerdict.ps1
    Also runs under Windows PowerShell 5.1, which is what the Scheduled Task uses.
    ASCII only.
#>

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/../scripts/NetAssess.Verdicts.ps1"

$pass = 0; $fail = 0
function Check([string]$Name, [scriptblock]$Test, [string]$Shown) {
    if (& $Test) { Write-Host ("  [ok]   {0,-52} {1}" -f $Name, $Shown); $script:pass++ }
    else { Write-Host ("  [FAIL] {0,-52} got '{1}'" -f $Name, $Shown); $script:fail++ }
}

$rule = '-' * 79
$listed = @"
Shared resources at \\192.0.2.5

NAS-FIXTURE

Share name  Type  Used as  Comment

$rule
home        Disk           user home
media       Disk
public      Disk           everyone
IPC`$        IPC            Remote IPC
Multimedia Library
            Disk           long name, wrapped by net view
printer1    Print          office
The command completed successfully.

"@

$none = @"
There are no entries in the list.

"@

$err53 = @"
System error 53 has occurred.

The network path was not found.

"@

$denied = @"
System error 5 has occurred.

Access is denied.

"@

Write-Host ""
Write-Host "shares listed"

$v = Get-NetViewShareVerdict -NetViewText $listed
Check -Name "Disk shares counted, IPC and Print are not" -Test { $v.Count -eq 4 } -Shown "$($v.Count)"
Check -Name "names recovered, including a wrapped long name" -Test { ($v.Names -join '|') -eq 'home|media|public|Multimedia Library' } -Shown ($v.Names -join '|')
Check -Name "status line carries count and names" -Test { $v.Status -eq '4 (home, media, public, Multimedia Library)' } -Shown $v.Status
Check -Name "status line has no word the gate misreads" -Test { $v.Status -notmatch 'unknown' } -Shown $v.Status

$crlf = $listed -replace "`r?`n", "`r`n"
$v = Get-NetViewShareVerdict -NetViewText $crlf
Check -Name "CRLF output (as net view writes it) parses" -Test { $v.Count -eq 4 } -Shown "$($v.Count)"

Write-Host ""
Write-Host "nothing listed"

$v = Get-NetViewShareVerdict -NetViewText $none
Check -Name "'no entries' is a definite zero" -Test { $v.Count -eq 0 -and $v.Status -eq '0' } -Shown $v.Status

$headerOnly = $listed -replace '(?s)(-{79}\r?\n).*?(The command completed)', '$1$2'
$v = Get-NetViewShareVerdict -NetViewText $headerOnly
Check -Name "success with only non-Disk rows is zero" -Test { $v.Count -eq 0 -and $v.Status -eq '0' } -Shown $v.Status

Write-Host ""
Write-Host "states that must not read as zero"

$v = Get-NetViewShareVerdict -NetViewText $err53
Check -Name "System error 53 is unknown" -Test { $v.Count -eq -1 -and $v.Status -like 'unknown*' } -Shown $v.Status
$v = Get-NetViewShareVerdict -NetViewText $denied
Check -Name "access denied is unknown" -Test { $v.Status -like 'unknown*' } -Shown $v.Status
$v = Get-NetViewShareVerdict -NetViewText ''
Check -Name "no output at all is unknown" -Test { $v.Status -eq 'unknown (net view did not answer: no output)' } -Shown $v.Status

Write-Host ""
Write-Host ("{0} passed, {1} failed" -f $pass, $fail)
if ($fail) { exit 1 }
exit 0
