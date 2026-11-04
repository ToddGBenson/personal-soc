<#
.SYNOPSIS
  Authoritative breach confirmation via Have I Been Pwned (HIBP) API v3.
  Turns "likely breached" (inference) into a confirmed, dated breach list per email.
.DESCRIPTION
  Queries HIBP breachedaccount + pasteaccount for each email. Requires a HIBP API key
  (haveibeenpwned.com/API/Key, ~$4/mo). Read-only. Respects the per-key rate limit:
  a 429 waits the Retry-After the server sends (at least 2s, at most -MaxRetryAfterSec)
  and is retried up to -MaxRetries times, then the run stops with HibpRateLimitExceeded.
  Runs on Windows PowerShell 5.1 and PowerShell 7. Keep this file ASCII: 5.1 reads a
  BOM-less script as the ANSI code page, and a UTF-8 dash there breaks a string literal.
.NOTES
  HIBP checks EMAILS against known breaches. For raw leaked-record content (passwords,
  addresses) use DeHashed (separate paid API); see references/breach-confirmation.md.
  Keep the API key out of the repo; pass it at runtime or via $env:HIBP_API_KEY.
.EXAMPLE
  .\Invoke-BreachCheck.ps1 -Emails you@example.com,old@oldisp.net -ApiKey $env:HIBP_API_KEY -OutDir .\personal-monitor\<date>
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string[]]$Emails,
  [string]$ApiKey = $env:HIBP_API_KEY,
  [string]$OutDir = ".",
  [int]$DelayMs = 1700,   # HIBP rate limit: stay above the per-key minimum interval
  [ValidateRange(0, 100)][int]$MaxRetries = 5,          # 429s retried per request before giving up
  [ValidateRange(1, 3600)][int]$MaxRetryAfterSec = 60   # longest Retry-After honoured; longer is capped
)
$ErrorActionPreference = 'Stop'
if(-not $ApiKey){ throw "No HIBP API key. Pass -ApiKey or set `$env:HIBP_API_KEY (get one at haveibeenpwned.com/API/Key)." }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$headers = @{ 'hibp-api-key' = $ApiKey; 'user-agent' = 'personal-soc-breach-check' }
$retryPolicy = @{ MaxRetries = $MaxRetries; MaxRetryAfterSec = $MaxRetryAfterSec }

# Retry-After as whole seconds, or $null when absent or not a number.
# The response differs by host (TheHub #61002):
#   PS 5.1: HttpWebResponse; Headers is a WebHeaderCollection with a string indexer.
#   PS 7:   HttpResponseMessage; Headers has no string indexer (Headers['retry-after']
#           is $null there), so the raw value is read with TryGetValues.
function Read-RetryAfter($response){
  if($null -eq $response){ return $null }
  $h = $response.Headers
  $raw = $null
  if($h -is [System.Net.WebHeaderCollection]){ $raw = $h['Retry-After'] }
  elseif($null -ne $h -and $h.PSObject.Methods['TryGetValues']){
    $values = $null
    if($h.TryGetValues('Retry-After', [ref]$values)){ $raw = @($values)[0] }
  }
  $sec = 0
  if($raw -and [int]::TryParse(([string]$raw).Trim(), [ref]$sec) -and $sec -ge 0){ return $sec }
  return $null
}

function Query($kind, $email){
  $uri = "https://haveibeenpwned.com/api/v3/$kind/$([uri]::EscapeDataString($email))"
  if($kind -eq 'breachedaccount'){ $uri += '?truncateResponse=false' }
  $retries = 0
  while($true){
    try { return Invoke-RestMethod -Uri $uri -Headers $headers -TimeoutSec 20 }
    catch {
      $code = $_.Exception.Response.StatusCode.value__
      if($code -eq 404){ return @() }                                   # not found = clean
      if($code -eq 401){ throw "HIBP 401: invalid API key." }
      if($code -eq 429){                                                # rate limited: back off
        if($retries -ge $retryPolicy.MaxRetries){
          throw "HibpRateLimitExceeded: HIBP still answered 429 to $kind after $($retryPolicy.MaxRetries) retries. Nothing was written; try later, or raise -MaxRetries or -DelayMs."
        }
        $retries++
        # Wait what the server asks, capped at -MaxRetryAfterSec; never less than 2s.
        # A missing or unparseable Retry-After waits the 2s default.
        $sec = Read-RetryAfter $_.Exception.Response
        $wait = if($null -eq $sec){ 2000 } else { [Math]::Min($sec, $retryPolicy.MaxRetryAfterSec) * 1000 }
        $wait = [Math]::Max($wait, 2000)
        Write-Verbose "HIBP 429 on $kind; retry $retries of $($retryPolicy.MaxRetries) after ${wait}ms"
        Start-Sleep -Milliseconds $wait; continue
      }
      throw
    }
  }
}

$report = @()
foreach($e in $Emails){
  Write-Host "Checking $e ..." -ForegroundColor Cyan
  $breaches = Query 'breachedaccount' $e
  Start-Sleep -Milliseconds $DelayMs
  $pastes   = Query 'pasteaccount'   $e
  Start-Sleep -Milliseconds $DelayMs
  $report += [PSCustomObject]@{
    email          = $e
    breach_count   = @($breaches).Count
    paste_count    = @($pastes).Count
    breaches       = @($breaches | ForEach-Object { [PSCustomObject]@{ name=$_.Name; date=$_.BreachDate; data=($_.DataClasses -join ', ') } })
  }
  if(@($breaches).Count){
    Write-Host ("  CONFIRMED in {0} breach(es):" -f @($breaches).Count) -ForegroundColor Red
    $breaches | Sort-Object BreachDate -Descending | Select-Object -First 8 | ForEach-Object {
      "    {0,-24} {1}  [{2}]" -f $_.Name, $_.BreachDate, ($_.DataClasses -join ', ')
    }
  } else { Write-Host "  No breaches found." -ForegroundColor Green }
}
$report | ConvertTo-Json -Depth 6 | Set-Content "$OutDir\breaches.json"
Write-Host "`nWrote $OutDir\breaches.json" -ForegroundColor DarkGray
Write-Host "Confirmed breaches feed the ledger: promote 'likely-breached' -> confirmed, and drive recovery actions (rotate/remove-as-recovery)." -ForegroundColor DarkGray
