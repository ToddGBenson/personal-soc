<#
.SYNOPSIS
  Key-free breach watch: alert when a service the owner uses appears in a newly added HIBP breach.
.DESCRIPTION
  Downloads Have I Been Pwned's public breach catalogue (GET /api/v3/breaches, free, no API
  key) and matches it locally against the owner's account domains. A breach is new when its
  Domain is a listed domain or a subdomain of one and HIBP added it on or after -Since.

  Exactly one request leaves the host, and it carries nothing about the owner: no email, no
  domain, no query string, no body. The domains list is read from a git-ignored local file
  and only ever compared on this machine.

  This is not Invoke-BreachCheck.ps1. That script asks HIBP whether specific email addresses
  were breached and needs a paid key; this one asks which services were breached and needs
  none. It says "a service you use was breached", not "your account was in it".

  Writes <OutDir>\new-breaches.json: an array of {name, domain, breach_date, added_date,
  data_classes}, empty when nothing matches. Nothing is written when the answer is unknown.

  Exit codes:
    0  nothing new
    1  at least one new breach (new-breaches.json lists them)
    2  unknown: the request failed, the response was not a JSON array, the domains file is
       missing or has no usable domain, or -Since is not yyyy-MM-dd. Unknown is not a pass.
.PARAMETER DomainsFile
  One domain per line; '#' starts a comment. Lines that are not a bare domain are skipped.
  Default references/account-domains.local.txt (ignored by the repo's *.local.* rule); copy
  references/account-domains.example.txt to start one.
.PARAMETER Since
  yyyy-MM-dd, inclusive. Default today (UTC) minus 8 days, so a weekly run overlaps by a day.
.EXAMPLE
  .\Get-NewBreaches.ps1 -OutDir .\personal-monitor\2026-11-04
.NOTES
  TheHub #60990. ASCII only; runs on Windows PowerShell 5.1 and pwsh 7.
#>
[CmdletBinding()]
param(
  [string]$DomainsFile = (Join-Path -Path $PSScriptRoot -ChildPath '../references/account-domains.local.txt'),
  [string]$Since = ([datetime]::UtcNow.Date.AddDays(-8).ToString('yyyy-MM-dd')),
  [string]$OutDir = '.'
)
$ErrorActionPreference = 'Stop'
. (Join-Path -Path $PSScriptRoot -ChildPath 'Select-NewBreaches.ps1')

$CatalogueUri = 'https://haveibeenpwned.com/api/v3/breaches'
$UserAgent = 'personal-soc-breach-watch'

function Stop-Unknown([string]$Why) {
  Write-Host "UNKNOWN: $Why" -ForegroundColor Yellow
  Write-Host "No breach signal this run; this is not a pass." -ForegroundColor Yellow
  exit 2
}

# ---- inputs, checked before anything leaves the host ------------------------
$sinceDay = [datetime]::MinValue
if (-not [datetime]::TryParseExact($Since, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$sinceDay)) {
  Stop-Unknown "-Since must be yyyy-MM-dd (got '$Since')."
}
if (-not (Test-Path -LiteralPath $DomainsFile -PathType Leaf)) {
  Stop-Unknown "domains file not found: $DomainsFile (copy references/account-domains.example.txt to account-domains.local.txt)."
}
$domains = @(ConvertTo-AccountDomains -Lines @(Get-Content -LiteralPath $DomainsFile))
if (-not $domains.Count) {
  Stop-Unknown "domains file has no usable domain: $DomainsFile"
}

# ---- the one request: the public catalogue, nothing about the owner ----------
if ($PSVersionTable.PSVersion.Major -lt 6) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
try {
  $resp = Invoke-WebRequest -Uri $CatalogueUri -Method Get -UserAgent $UserAgent -TimeoutSec 60 -UseBasicParsing
} catch {
  Stop-Unknown "GET $CatalogueUri failed: $($_.Exception.Message)"
}

# Parsed here rather than by Invoke-RestMethod, so a JSON object, an HTML challenge page or
# an empty body is told apart from an empty catalogue.
$body = [string]$resp.Content
if (-not $body.TrimStart().StartsWith('[')) {
  Stop-Unknown "the catalogue response is not a JSON array."
}
try {
  $catalogue = @(ConvertFrom-Json -InputObject $body | ForEach-Object { $_ })
} catch {
  Stop-Unknown "the catalogue response is not valid JSON: $($_.Exception.Message)"
}

# ---- match locally and write it down ------------------------------------------
$hits = @(Select-NewBreaches -Catalogue $catalogue -Domains $domains -Since $sinceDay)

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$outFile = Join-Path -Path (Resolve-Path -LiteralPath $OutDir).Path -ChildPath 'new-breaches.json'
$json = if ($hits.Count) { ConvertTo-Json -Depth 5 -InputObject @($hits) } else { '[]' }
[IO.File]::WriteAllText($outFile, $json + "`n", [Text.UTF8Encoding]::new($false))

Write-Host ("Catalogue: {0} breaches; {1} listed domain(s); new since {2}: {3}" -f $catalogue.Count, $domains.Count, $sinceDay.ToString('yyyy-MM-dd'), $hits.Count)
if ($hits.Count) {
  foreach ($h in $hits) {
    Write-Host ("  NEW  {0,-28} {1,-28} added {2}  [{3}]" -f $h.name, $h.domain, $h.added_date, ($h.data_classes -join ', ')) -ForegroundColor Red
  }
  Write-Host "A service you use was breached. Confirm whether your account was in it (references/breach-confirmation.md) and rotate that password." -ForegroundColor DarkGray
}
Write-Host "Wrote $outFile" -ForegroundColor DarkGray
if ($hits.Count) { exit 1 }
exit 0
