<#
.SYNOPSIS
    Invoke-BreachCheck.ps1 against a fake HIBP. No network, no API key.

.DESCRIPTION
    TheHub #60939. Invoke-BreachCheck had no test anywhere: the functional job
    listed it as "not covered" because it needs a paid HIBP key and a live
    endpoint. Neither is needed to test what the script decides. The script is
    run for real here, with Invoke-RestMethod and Start-Sleep replaced by
    functions in this scope (PowerShell resolves a function before a cmdlet of
    the same name, and a child script sees the caller's functions). Every URL
    the fake does not know throws, so nothing can leave the machine.

    What is pinned:
      - a 404 is the only answer that reads as clean; a 500 aborts the run
        rather than being written down as "no breaches"
      - a missing key and a 401 stop the run
      - a 429 is retried, never skipped
      - the request: the escaped address, truncateResponse=false on
        breachedaccount only, the hibp-api-key and user-agent headers
      - the rate-limit delay after every request
      - what breaches.json says

    ALL FIXTURES ARE CONSTRUCTED. Addresses are under example.com / example.net
    (RFC 2606) and the key is a placeholder. The breach records follow the
    HIBP v3 breachedaccount shape (Name, BreachDate, DataClasses); they are
    not real records.

.NOTES
    Usage: pwsh -NoProfile -File skills/personal-threat-monitor/tests/Test-BreachCheck.ps1
    ASCII only.
#>

$ErrorActionPreference = 'Stop'
$script:BreachCheck = (Resolve-Path "$PSScriptRoot/../scripts/Invoke-BreachCheck.ps1").Path

$pass = 0; $fail = 0
function Check([string]$Name, [scriptblock]$Test, [string]$Shown) {
    if (& $Test) { Write-Host ("  [ok]   {0,-58} {1}" -f $Name, $Shown); $script:pass++ }
    else { Write-Host ("  [FAIL] {0,-58} got '{1}'" -f $Name, $Shown); $script:fail++ }
}

# ---- the fake HIBP ---------------------------------------------------------
#
# $FakeHibpReplies maps "<kind>/<escaped email>" to a queue of replies. A reply
# is either an integer HTTP status (thrown as the HttpResponseException
# Invoke-RestMethod throws) or an object array (the parsed JSON body). The
# last reply in a queue repeats. Names are unusual on purpose: the script
# under test runs in a child scope and must not shadow them.

$FakeHibpCalls  = [System.Collections.Generic.List[object]]::new()
$FakeHibpSleeps = [System.Collections.Generic.List[int]]::new()
$FakeHibpReplies = @{}

function New-HibpError([int]$Status, [string]$RetryAfter) {
    $msg = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]$Status)
    if ($RetryAfter) { $msg.Headers.Add('Retry-After', $RetryAfter) }
    return [Microsoft.PowerShell.Commands.HttpResponseException]::new("HTTP $Status", $msg)
}

function Invoke-RestMethod {
    [CmdletBinding()]
    param([string]$Uri, [hashtable]$Headers, [int]$TimeoutSec)
    $FakeHibpCalls.Add([pscustomobject]@{ Uri = $Uri; Headers = $Headers; TimeoutSec = $TimeoutSec })
    $prefix = 'https://haveibeenpwned.com/api/v3/'
    if (-not $Uri.StartsWith($prefix)) { throw "fake HIBP: unexpected URL $Uri" }
    $key = ($Uri.Substring($prefix.Length) -split '\?')[0]
    if (-not $FakeHibpReplies.ContainsKey($key)) { throw "fake HIBP: no reply for $key" }
    $queue = $FakeHibpReplies[$key]
    $reply = if ($queue.Count -gt 1) { $queue.Dequeue() } else { $queue.Peek() }
    if ($reply -is [int]) { throw (New-HibpError -Status $reply -RetryAfter $FakeHibpRetryAfter) }
    return , $reply
}

function Start-Sleep {
    [CmdletBinding()]
    param([int]$Milliseconds, [int]$Seconds)
    $FakeHibpSleeps.Add($Milliseconds + 1000 * $Seconds)
}

function Set-Reply([string]$Kind, [string]$Email, [object[]]$Replies) {
    $q = [System.Collections.Queue]::new()
    foreach ($r in $Replies) { $q.Enqueue($r) }
    $FakeHibpReplies["$Kind/$([uri]::EscapeDataString($Email))"] = $q
}

function Reset-Fake {
    $FakeHibpCalls.Clear(); $FakeHibpSleeps.Clear(); $FakeHibpReplies.Clear()
    $script:FakeHibpRetryAfter = ''
}

function Breach([string]$Name, [string]$Date, [string[]]$Classes) {
    [pscustomobject]@{ Name = $Name; BreachDate = $Date; DataClasses = $Classes }
}

# Runs the script, returns @{ Threw; Error; Output; Report }.
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("breachcheck-test-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
function Invoke-Under([string[]]$Emails, [hashtable]$Extra = @{}) {
    $out = Join-Path $tmp ([guid]::NewGuid().ToString('N'))
    $r = @{ Threw = $false; Error = ''; Output = ''; Report = $null; OutDir = $out }
    try {
        $r.Output = & $script:BreachCheck -Emails $Emails -OutDir $out @Extra *>&1 | Out-String
    } catch {
        $r.Threw = $true; $r.Error = $_.Exception.Message
    }
    $json = Join-Path $out 'breaches.json'
    if (Test-Path -LiteralPath $json) { $r.Report = @(Get-Content -LiteralPath $json -Raw | ConvertFrom-Json) }
    return $r
}

$key = @{ ApiKey = 'placeholder-not-a-real-key' }
$savedEnvKey = $env:HIBP_API_KEY

try {
    # ------------------------------------------------------------------------
    Write-Host ""
    Write-Host "the key"

    Reset-Fake
    $env:HIBP_API_KEY = $null
    $r = Invoke-Under -Emails 'a@example.com'
    Check -Name "no key at all stops before any request" -Test { $r.Threw -and $r.Error -like '*No HIBP API key*' -and $FakeHibpCalls.Count -eq 0 } -Shown $r.Error

    Reset-Fake
    $env:HIBP_API_KEY = 'placeholder-from-env'
    Set-Reply 'breachedaccount' 'a@example.com' @(404)
    Set-Reply 'pasteaccount'    'a@example.com' @(404)
    $r = Invoke-Under -Emails 'a@example.com'
    $sent = if ($FakeHibpCalls.Count) { $FakeHibpCalls[0].Headers['hibp-api-key'] } else { '' }
    Check -Name "the key falls back to `$env:HIBP_API_KEY" -Test { -not $r.Threw -and $sent -eq 'placeholder-from-env' } -Shown $sent
    $env:HIBP_API_KEY = $null

    Reset-Fake
    Set-Reply 'breachedaccount' 'a@example.com' @(401)
    $r = Invoke-Under -Emails 'a@example.com' -Extra $key
    Check -Name "401 stops the run as an invalid key" -Test { $r.Threw -and $r.Error -like '*401*invalid API key*' -and -not $r.Report } -Shown $r.Error

    # ------------------------------------------------------------------------
    Write-Host ""
    Write-Host "the request"

    Reset-Fake
    $addr = 'first.last+tag@example.com'
    Set-Reply 'breachedaccount' $addr @(404)
    Set-Reply 'pasteaccount'    $addr @(404)
    $r = Invoke-Under -Emails $addr -Extra $key
    $uris = @($FakeHibpCalls | ForEach-Object Uri)
    Check -Name "breachedaccount: escaped address, untruncated" -Test { $uris[0] -ceq 'https://haveibeenpwned.com/api/v3/breachedaccount/first.last%2Btag%40example.com?truncateResponse=false' } -Shown $uris[0]
    Check -Name "pasteaccount: escaped address, no query" -Test { $uris[1] -ceq 'https://haveibeenpwned.com/api/v3/pasteaccount/first.last%2Btag%40example.com' } -Shown $uris[1]
    $h = $FakeHibpCalls[0].Headers
    Check -Name "hibp-api-key header carries -ApiKey" -Test { $h['hibp-api-key'] -ceq 'placeholder-not-a-real-key' } -Shown ''
    Check -Name "user-agent header is set (HIBP refuses without)" -Test { [string]$h['user-agent'] -ne '' } -Shown $h['user-agent']
    Check -Name "every request has a timeout" -Test { @($FakeHibpCalls | Where-Object { $_.TimeoutSec -le 0 }).Count -eq 0 } -Shown (($FakeHibpCalls | ForEach-Object TimeoutSec) -join ',')
    Check -Name "a pause of -DelayMs after each request" -Test { ($FakeHibpSleeps -join ',') -eq '1700,1700' } -Shown ($FakeHibpSleeps -join ',')

    # ------------------------------------------------------------------------
    Write-Host ""
    Write-Host "what is written down"

    Reset-Fake
    Set-Reply 'breachedaccount' 'clean@example.com' @(404)
    Set-Reply 'pasteaccount'    'clean@example.com' @(404)
    Set-Reply 'breachedaccount' 'hit@example.net' @(, @(
        (Breach 'ExampleForum'  '2019-03-01' @('Email addresses', 'Passwords')),
        (Breach 'ExampleRetail' '2021-07-15' @('Email addresses', 'Phone numbers'))
    ))
    Set-Reply 'pasteaccount'    'hit@example.net' @(, @([pscustomobject]@{ Source = 'Pastebin'; Id = 'x' }))
    # One record, as a bare object: the shape a one-element JSON array has once
    # the pipeline unrolls it.
    Set-Reply 'breachedaccount' 'one@example.net' @((Breach 'ExampleSolo' '2020-01-02' @('Usernames')))
    Set-Reply 'pasteaccount'    'one@example.net' @(404)
    $r = Invoke-Under -Emails 'clean@example.com', 'hit@example.net', 'one@example.net' -Extra ($key + @{ DelayMs = 5 })
    $rep = $r.Report
    Check -Name "breaches.json written, one row per email, in order" -Test { -not $r.Threw -and $rep.Count -eq 3 -and (($rep | ForEach-Object email) -join ',') -eq 'clean@example.com,hit@example.net,one@example.net' } -Shown (($rep | ForEach-Object email) -join ',')
    Check -Name "404 on both is a clean row" -Test { $rep[0].breach_count -eq 0 -and $rep[0].paste_count -eq 0 -and @($rep[0].breaches).Count -eq 0 } -Shown "$($rep[0].breach_count)/$($rep[0].paste_count)"
    Check -Name "two breaches and a paste are counted" -Test { $rep[1].breach_count -eq 2 -and $rep[1].paste_count -eq 1 } -Shown "$($rep[1].breach_count)/$($rep[1].paste_count)"
    $b = @($rep[1].breaches)
    Check -Name "each breach keeps name, date and data classes" -Test { $b[0].name -eq 'ExampleForum' -and $b[0].date -eq '2019-03-01' -and $b[0].data -eq 'Email addresses, Passwords' -and $b[1].name -eq 'ExampleRetail' } -Shown "$($b[0].name) $($b[0].date) [$($b[0].data)]"
    Check -Name "a single breach is counted as one, not unrolled" -Test { $rep[2].breach_count -eq 1 -and @($rep[2].breaches)[0].name -eq 'ExampleSolo' } -Shown "$($rep[2].breach_count)"
    Check -Name "the console says CONFIRMED for a hit" -Test { $r.Output -match 'CONFIRMED in 2 breach' -and $r.Output -match 'No breaches found' } -Shown ''
    Check -Name "-DelayMs is honoured" -Test { (($FakeHibpSleeps | Sort-Object -Unique) -join ',') -eq '5' -and $FakeHibpSleeps.Count -eq 6 } -Shown ($FakeHibpSleeps -join ',')

    # ------------------------------------------------------------------------
    Write-Host ""
    Write-Host "unknown is not clean"

    Reset-Fake
    Set-Reply 'breachedaccount' 'a@example.com' @(500)
    $r = Invoke-Under -Emails 'a@example.com' -Extra $key
    Check -Name "500 aborts; it is not written down as clean" -Test { $r.Threw -and -not $r.Report } -Shown $r.Error

    Reset-Fake
    Set-Reply 'breachedaccount' 'a@example.com' @(404)
    Set-Reply 'pasteaccount'    'a@example.com' @(503)
    $r = Invoke-Under -Emails 'a@example.com' -Extra $key
    Check -Name "a failed paste lookup aborts too" -Test { $r.Threw -and -not $r.Report } -Shown $r.Error

    Reset-Fake
    $FakeHibpRetryAfter = '7'
    Set-Reply 'breachedaccount' 'a@example.com' @(429, @((Breach 'ExampleForum' '2019-03-01' @('Passwords'))))
    Set-Reply 'pasteaccount'    'a@example.com' @(404)
    $r = Invoke-Under -Emails 'a@example.com' -Extra $key
    $bcalls = @($FakeHibpCalls | Where-Object { $_.Uri -like '*/breachedaccount/*' }).Count
    Check -Name "429 is retried and the retry's answer is kept" -Test { -not $r.Threw -and $bcalls -eq 2 -and $r.Report[0].breach_count -eq 1 } -Shown "$bcalls breachedaccount call(s)"
    $backoff = if ($FakeHibpSleeps.Count) { $FakeHibpSleeps[0] } else { 0 }
    Check -Name "429 backs off at least 2s before retrying" -Test { $backoff -ge 2000 } -Shown "${backoff}ms"

    # Reported, not gated. The script reads Retry-After with
    # Headers['retry-after'], but on PowerShell 7 Response is an
    # HttpResponseMessage whose headers have no string indexer: the read is
    # $null, [int]$null is 0, and the 2s floor wins. A server asking for 7s
    # gets 2s. Pinned as a note so the day it is fixed is visible.
    if ($backoff -ge 7000) {
        Write-Host "  (Retry-After is now honoured: ${backoff}ms for 7s)"
    } else {
        Write-Host "  NOTE  Retry-After: 7 was not honoured (backed off ${backoff}ms). On"
        Write-Host "        PowerShell 7 Headers['retry-after'] reads `$null; see the comment."
    }
}
finally {
    $env:HIBP_API_KEY = $savedEnvKey
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
