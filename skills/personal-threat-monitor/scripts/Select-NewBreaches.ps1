<#
.SYNOPSIS
  Pure functions for the key-free breach watch (Get-NewBreaches.ps1). Dot-source this file.
  Both emit their results one by one; wrap a call in @() to get an array.
.DESCRIPTION
  ConvertTo-AccountDomains turns the lines of a domains file into a clean, lower-case,
  de-duplicated list, skipping comments, blanks and anything that is not a bare domain.

  Select-NewBreaches matches HIBP's public breach catalogue (/api/v3/breaches rows:
  Name, Domain, BreachDate, AddedDate, DataClasses) against that list. A breach matches
  when its Domain equals a listed domain, case-insensitively, or is a subdomain of one
  (shop.example.com matches example.com; notexample.com does not), and its AddedDate,
  as a UTC day, is on or after -Since. A breach with no Domain never matches.

  Nothing here touches the network or the disk.
.NOTES
  TheHub #60990. ASCII only; runs on Windows PowerShell 5.1 and pwsh 7.
#>

# One label: letters, digits, inner hyphens. At least two labels, a letter-only TLD.
$script:AccountDomainPattern = '^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'

function ConvertTo-AccountDomains {
  [CmdletBinding()]
  [OutputType([string[]])]
  param([AllowEmptyCollection()][AllowEmptyString()][string[]]$Lines)
  $seen = @{}
  $out = [System.Collections.Generic.List[string]]::new()
  foreach ($line in @($Lines)) {
    if ($null -eq $line) { continue }
    $d = ($line -replace '#.*$', '').Trim().ToLowerInvariant()
    if (-not $d) { continue }
    if ($d -notmatch $script:AccountDomainPattern) {
      Write-Verbose "skipped a line that is not a bare domain"
      continue
    }
    if (-not $seen.ContainsKey($d)) { $seen[$d] = $true; $out.Add($d) }
  }
  return $out.ToArray()
}

# The UTC day of an AddedDate. pwsh 7's ConvertFrom-Json hands ISO strings over as
# [datetime]; Windows PowerShell 5.1 leaves them as strings. $null when unparseable.
function ConvertTo-BreachDay($Value) {
  if ($null -eq $Value) { return $null }
  if ($Value -is [datetime]) {
    if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return $Value.Date }
    return $Value.ToUniversalTime().Date
  }
  $s = [string]$Value
  if (-not $s) { return $null }
  $styles = [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal
  $parsed = [datetime]::MinValue
  if ([datetime]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) { return $parsed.Date }
  return $null
}

function Select-NewBreaches {
  [CmdletBinding()]
  param(
    [AllowEmptyCollection()][object[]]$Catalogue,
    [AllowEmptyCollection()][string[]]$Domains,
    [Parameter(Mandatory)][datetime]$Since
  )
  $listed = @(ConvertTo-AccountDomains -Lines $Domains)
  $sinceDay = $Since.Date
  $rows = [System.Collections.Generic.List[object]]::new()
  if (-not $listed.Count) { return }
  foreach ($b in @($Catalogue)) {
    if ($null -eq $b) { continue }
    $domain = ([string]$b.Domain).Trim().ToLowerInvariant()
    if (-not $domain) { continue }
    $hit = $false
    foreach ($d in $listed) {
      if ($domain -eq $d -or $domain.EndsWith(".$d")) { $hit = $true; break }
    }
    if (-not $hit) { continue }
    $added = ConvertTo-BreachDay $b.AddedDate
    if ($null -eq $added -or $added -lt $sinceDay) { continue }
    $breachDay = ConvertTo-BreachDay $b.BreachDate
    $rows.Add([pscustomobject][ordered]@{
        name         = [string]$b.Name
        domain       = [string]$b.Domain
        breach_date  = if ($breachDay) { $breachDay.ToString('yyyy-MM-dd') } else { [string]$b.BreachDate }
        added_date   = $added.ToString('yyyy-MM-dd')
        data_classes = [string[]]@($b.DataClasses | Where-Object { $null -ne $_ })
      })
  }
  return $rows.ToArray()
}
