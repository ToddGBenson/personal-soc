<#
.SYNOPSIS
  Authoritative breach confirmation via Have I Been Pwned (HIBP) API v3.
  Turns "likely breached" (inference) into a confirmed, dated breach list per email.
.DESCRIPTION
  Queries HIBP breachedaccount + pasteaccount for each email. Requires a HIBP API key
  (haveibeenpwned.com/API/Key, ~$4/mo). Read-only. Respects the per-key rate limit.
.NOTES
  HIBP checks EMAILS against known breaches. For raw leaked-record content (passwords,
  addresses) use DeHashed (separate paid API) — see references/breach-confirmation.md.
  Keep the API key out of the repo; pass it at runtime or via $env:HIBP_API_KEY.
.EXAMPLE
  .\Invoke-BreachCheck.ps1 -Emails you@example.com,old@oldisp.net -ApiKey $env:HIBP_API_KEY -OutDir .\personal-monitor\<date>
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string[]]$Emails,
  [string]$ApiKey = $env:HIBP_API_KEY,
  [string]$OutDir = ".",
  [int]$DelayMs = 1700    # HIBP rate limit: stay above the per-key minimum interval
)
$ErrorActionPreference = 'Stop'
if(-not $ApiKey){ throw "No HIBP API key. Pass -ApiKey or set `$env:HIBP_API_KEY (get one at haveibeenpwned.com/API/Key)." }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$headers = @{ 'hibp-api-key' = $ApiKey; 'user-agent' = 'personal-soc-breach-check' }

function Query($kind, $email){
  $uri = "https://haveibeenpwned.com/api/v3/$kind/$([uri]::EscapeDataString($email))"
  if($kind -eq 'breachedaccount'){ $uri += '?truncateResponse=false' }
  while($true){
    try { return Invoke-RestMethod -Uri $uri -Headers $headers -TimeoutSec 20 }
    catch {
      $code = $_.Exception.Response.StatusCode.value__
      if($code -eq 404){ return @() }                                   # not found = clean
      if($code -eq 401){ throw "HIBP 401 — invalid API key." }
      if($code -eq 429){                                                # rate limited — back off
        $wait = 2000; try { $wait = [int]($_.Exception.Response.Headers['retry-after']) * 1000 } catch {}
        Start-Sleep -Milliseconds ([Math]::Max($wait,2000)); continue
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
