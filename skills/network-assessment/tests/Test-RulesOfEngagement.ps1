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
    Also runs under Windows PowerShell 5.1 (CI runs it under Linux pwsh). ASCII only.
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

Check 'Test-IpInCidr: address inside' (Test-IpInCidr -Ip '192.0.2.7' -Cidr '192.0.2.0/24') $true
Check 'Test-IpInCidr: address outside' (Test-IpInCidr -Ip '192.168.0.9' -Cidr '192.0.2.0/24') $false
Check 'Test-IpInCidr: empty address' (Test-IpInCidr -Ip '' -Cidr '192.0.2.0/24') $false
Check 'Test-IpInCidr: bad cidr' (Test-IpInCidr -Ip '192.0.2.7' -Cidr 'x') $false

Write-Host ""
Write-Host "Invoke-WeeklyNetworkScan.ps1 refuses before any probe"
# Every child run targets TEST-NET-1 (192.0.2.0/24, RFC 5737, never routed), and
# the child runs in a session where the other network entry points are tripwires,
# so a regressed gate cannot reach the real LAN or the internet from a test.
$tgt = '192.0.2.0/24'
$marker = Join-Path $tmp 'network-was-touched.txt'
$stub = Join-Path $tmp 'nmap-stub.cmd'
Set-Content -LiteralPath $stub -Value "@echo off`r`necho nmap> `"$marker`"`r`nexit 0" -Encoding ASCII
$pwsh = (Get-Process -Id $PID).Path
$q = { param($s) "'" + ($s -replace "'", "''") + "'" }

function Invoke-Scan([string]$Name, [string]$RoeContent) {
    $root = Join-Path $tmp $Name
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    $roePath = Join-Path $root 'roe.md'
    if ($null -ne $RoeContent) { Set-Content -LiteralPath $roePath -Value $RoeContent -Encoding ASCII }
    $m = & $q $marker
    $trip = @('Invoke-RestMethod', 'Invoke-WebRequest', 'net', 'netsh', 'Test-Connection', 'Resolve-DnsName') |
        ForEach-Object { "function $_ { Set-Content -LiteralPath $m -Value '$_'; throw 'tripwire' }" }
    $cmd = ($trip -join '; ') + "; & " + (& $q $scan) + " -Cidr $tgt -Root " + (& $q $root) + " -RoePath " + (& $q $roePath) +
        " -NmapPath " + (& $q $stub) + " -MonitorRoot " + (& $q $root) + "; exit `$LASTEXITCODE"
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'   # Windows PowerShell 5.1 turns child stderr under 2>&1 into a terminating error
    try { $text = (& $pwsh -NoProfile -Command $cmd 2>&1 | Out-String) } finally { $ErrorActionPreference = $old }
    $rc = $LASTEXITCODE
    $log = Join-Path $root 'roe-refusals.log'
    $audit = Join-Path $root 'roe-audit.log'
    return [pscustomobject]@{
        Rc = $rc; Text = ($text -replace '\s+', ' ')   # 5.1 wraps error text at console width
        Log = $(if (Test-Path -LiteralPath $log) { (Get-Content -LiteralPath $log -Raw) -replace '\s+', ' ' } else { '' })
        Audit = $(if (Test-Path -LiteralPath $audit) { (Get-Content -LiteralPath $audit -Raw) -replace '\s+', ' ' } else { '' })
        RoePath = $roePath
        DatedDirs = @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue).Count
    }
}

foreach ($case in @(
    @{ N = 'missing';  Roe = $null;                                         Why = 'missing' },
    @{ N = 'expired';  Roe = (New-Roe -Signed '2026-01-01' -Expires '2026-03-01' -Scope "- t $tgt"); Why = 'expired' },
    @{ N = 'unsigned'; Roe = (New-Roe -Signed '(date)' -Scope "- t $tgt");  Why = 'Signed' },
    @{ N = 'outside';  Roe = (New-Roe -Scope '- t 198.51.100.0/24');        Why = 'not covered' },
    # A valid RoE for the target, but this host's adapter is not on TEST-NET-1 (or
    # there is no adapter, as on a Linux runner): the probes would follow the
    # adapter, so the run is refused.
    @{ N = 'adapter';  Roe = (New-Roe -Scope "- t $tgt");                   Why = 'local adapter' }
)) {
    $r = Invoke-Scan $case.N $case.Roe
    Check "$($case.N) RoE: exit code is exactly 2" $r.Rc 2
    Check "$($case.N) RoE: reason is on screen" ($r.Text -like "*$($case.Why)*") $true
    Check "$($case.N) RoE: refusal is logged" ($r.Log -like "*$($case.Why)*") $true
    Check "$($case.N) RoE: audit log has a REFUSED line with the RoE hash" ($r.Audit -like '*REFUSED*roe_sha256=*') $true
    Check "$($case.N) RoE: nmap stub and network tripwires never called" (Test-Path -LiteralPath $marker) $false
    Check "$($case.N) RoE: no dated output folder created" $r.DatedDirs 0
    if ($case.N -eq 'adapter') {
        $sha = (Get-FileHash -LiteralPath $r.RoePath -Algorithm SHA256).Hash
        Check 'adapter RoE: audit log carries the file SHA-256' ($r.Audit -like "*roe_sha256=$sha*") $true
        Check 'adapter RoE: audit log carries the modified time' ($r.Audit -like '*roe_mtime_utc=20*') $true
    }
}

Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ""
Write-Host ("{0} passed, {1} failed" -f $pass, $fail)
if ($fail) { exit 1 }
exit 0
