<#
.SYNOPSIS
    The weekly scan refuses to send a packet unless a signed, in-date rules of
    engagement file covers the target network. No network, nmap is a stub.

.DESCRIPTION
    TheHub #62304: the Scheduled Task ran active nmap every week and its script
    never read ~/netassess/roe.md, so a missing RoE was still a scan. The gate is
    Get-RoeVerdict (NetAssess.Verdicts.ps1) and Invoke-WeeklyNetworkScan.ps1
    calls it before anything else. It fails closed: every case that is not a
    clear yes is a refusal with a reason.

    The RoE carries no cryptographic signature; "signed" means the authoriser
    line and a parseable 'Signed:' date, with an 'expires:' date no more than
    90 days after it (the template's own rule). A missing, unsigned, malformed,
    future-dated, over-long or expired file is refused, and so is one that does
    not list the target CIDR under 'In scope'.

    The script-level cases run the real script as a child process against a
    temp Root with -NmapPath pointing at a stub that writes a marker file when
    called. The marker must never appear.

.NOTES
    Usage: pwsh -NoProfile -File skills/network-assessment/tests/Test-RulesOfEngagement.ps1
    Also runs under Windows PowerShell 5.1. ASCII only.
#>

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/../scripts/NetAssess.Verdicts.ps1"
$scan = (Resolve-Path (Join-Path $PSScriptRoot '../scripts/Invoke-WeeklyNetworkScan.ps1')).Path
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("roe-gate-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

$pass = 0; $fail = 0
function Check([string]$What, $Got, $Want) {
    if ("$Got" -ceq "$Want") { Write-Host ("  [ok]   {0,-62} {1}" -f $What, $Got); $script:pass++ }
    else { Write-Host ("  [FAIL] {0,-62} expected '{1}', got '{2}'" -f $What, $Want, $Got); $script:fail++ }
}

function New-Roe([string]$Signed = '2026-11-22', [string]$Expires = '2027-02-20', [string]$Owner = 'Owner and authoriser: A Person',
                 [string]$Scope = "- trusted 192.168.0.0/24`n- iot 192.168.20.0/24") {
    $lines = @('# Rules of engagement', '', $Owner)
    if ($Signed) { $lines += "Signed: $Signed" }
    if ($Expires) { $lines += "expires: $Expires   (at most 90 days after signing)" }
    $lines += @('', '## In scope (Tier 1)', '', $Scope, '', '## Out of scope', '', '- 10.0.0.0/8 is not here')
    return ($lines -join "`n")
}
$today = [datetime]'2026-11-25'

Write-Host "Get-RoeVerdict"
$v = Get-RoeVerdict -RoeText (New-Roe) -Cidr '192.168.0.0/24' -Today $today
Check 'valid RoE covering the target is allowed' $v.Ok $true
Check 'valid RoE covers a /24 inside a listed /24' (Get-RoeVerdict -RoeText (New-Roe) -Cidr '192.168.20.0/24' -Today $today).Ok $true
Check 'valid RoE covers a /28 inside a listed /24' (Get-RoeVerdict -RoeText (New-Roe) -Cidr '192.168.0.16/28' -Today $today).Ok $true
Check 'expiry day itself is still in date' (Get-RoeVerdict -RoeText (New-Roe) -Cidr '192.168.0.0/24' -Today ([datetime]'2027-02-20')).Ok $true

$v = Get-RoeVerdict -RoeText $null -Cidr '192.168.0.0/24' -Today $today
Check 'missing RoE (null text) is refused' $v.Ok $false
Check 'missing RoE says so' ($v.Reason -like '*missing*') $true
Check 'empty RoE is refused' (Get-RoeVerdict -RoeText '   ' -Cidr '192.168.0.0/24' -Today $today).Ok $false

$v = Get-RoeVerdict -RoeText (New-Roe) -Cidr '192.168.0.0/24' -Today ([datetime]'2027-02-21')
Check 'expired RoE is refused' $v.Ok $false
Check 'expired RoE says expired' ($v.Reason -like '*expired*') $true

Check 'no Signed line is refused (unsigned template)' (Get-RoeVerdict -RoeText (New-Roe -Signed '') -Cidr '192.168.0.0/24' -Today $today).Ok $false
Check 'placeholder Signed value is refused' (Get-RoeVerdict -RoeText (New-Roe -Signed '(date)') -Cidr '192.168.0.0/24' -Today $today).Ok $false
Check 'no authoriser is refused' (Get-RoeVerdict -RoeText (New-Roe -Owner 'Notes: none') -Cidr '192.168.0.0/24' -Today $today).Ok $false
Check 'empty authoriser is refused' (Get-RoeVerdict -RoeText (New-Roe -Owner 'Owner and authoriser:') -Cidr '192.168.0.0/24' -Today $today).Ok $false
Check 'no expires line is refused' (Get-RoeVerdict -RoeText (New-Roe -Expires '') -Cidr '192.168.0.0/24' -Today $today).Ok $false
Check 'unparseable expires is refused' (Get-RoeVerdict -RoeText (New-Roe -Expires 'someday') -Cidr '192.168.0.0/24' -Today $today).Ok $false
Check 'signed in the future is refused' (Get-RoeVerdict -RoeText (New-Roe -Signed '2026-12-01' -Expires '2027-02-20') -Cidr '192.168.0.0/24' -Today $today).Ok $false
Check 'expires before signed is refused' (Get-RoeVerdict -RoeText (New-Roe -Signed '2026-11-22' -Expires '2026-11-01') -Cidr '192.168.0.0/24' -Today $today).Ok $false
Check 'expires more than 90 days after signed is refused' (Get-RoeVerdict -RoeText (New-Roe -Signed '2026-11-22' -Expires '2027-06-01') -Cidr '192.168.0.0/24' -Today $today).Ok $false

Check 'a CIDR not listed is refused' (Get-RoeVerdict -RoeText (New-Roe) -Cidr '192.168.30.0/24' -Today $today).Ok $false
Check 'a CIDR only named under Out of scope is refused' (Get-RoeVerdict -RoeText (New-Roe) -Cidr '10.0.0.0/8' -Today $today).Ok $false
Check 'a target wider than the listed range is refused' (Get-RoeVerdict -RoeText (New-Roe) -Cidr '192.168.0.0/16' -Today $today).Ok $false
Check 'an empty In scope list is refused' (Get-RoeVerdict -RoeText (New-Roe -Scope '- nothing') -Cidr '192.168.0.0/24' -Today $today).Ok $false
Check 'a malformed target CIDR is refused' (Get-RoeVerdict -RoeText (New-Roe) -Cidr 'not-a-cidr' -Today $today).Ok $false
Check 'a missing target CIDR is refused' (Get-RoeVerdict -RoeText (New-Roe) -Cidr '' -Today $today).Ok $false

Write-Host ""
Write-Host "Invoke-WeeklyNetworkScan.ps1 refuses before any probe"
$marker = Join-Path $tmp 'nmap-was-called.txt'
$stub = Join-Path $tmp 'nmap-stub.cmd'
Set-Content -LiteralPath $stub -Value "@echo off`r`necho called> `"$marker`"`r`nexit 0" -Encoding ASCII
$pwsh = (Get-Process -Id $PID).Path

function Invoke-Scan([string]$Name, [string]$RoeContent) {
    $root = Join-Path $tmp $Name
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    $roePath = Join-Path $root 'roe.md'
    if ($null -ne $RoeContent) { Set-Content -LiteralPath $roePath -Value $RoeContent -Encoding ASCII }
    $text = (& $pwsh -NoProfile -File $scan -Cidr '192.168.0.0/24' -Root $root -RoePath $roePath -NmapPath $stub 2>&1 | Out-String)
    $rc = $LASTEXITCODE
    $log = Join-Path $root 'roe-refusals.log'
    return [pscustomobject]@{
        Rc = $rc; Text = $text; Root = $root
        Log = $(if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log -Raw } else { '' })
        DatedDirs = @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue).Count
    }
}

foreach ($case in @(
    @{ N = 'missing';  Roe = $null;                                         Why = 'missing' },
    @{ N = 'expired';  Roe = (New-Roe -Signed '2026-01-01' -Expires '2026-03-01'); Why = 'expired' },
    @{ N = 'unsigned'; Roe = (New-Roe -Signed '(date)');                    Why = 'Signed' },
    @{ N = 'outside';  Roe = (New-Roe -Scope '- trusted 192.168.50.0/24');  Why = 'not covered' }
)) {
    $r = Invoke-Scan $case.N $case.Roe
    Check "$($case.N) RoE: exit code is non-zero" ($r.Rc -ne 0) $true
    Check "$($case.N) RoE: reason is on screen" ($r.Text -like "*$($case.Why)*") $true
    Check "$($case.N) RoE: refusal is logged" ($r.Log -like "*$($case.Why)*") $true
    Check "$($case.N) RoE: nmap stub never called" (Test-Path -LiteralPath $marker) $false
    Check "$($case.N) RoE: no dated output folder created" $r.DatedDirs 0
}

Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ""
Write-Host ("{0} passed, {1} failed" -f $pass, $fail)
if ($fail) { exit 1 }
exit 0
