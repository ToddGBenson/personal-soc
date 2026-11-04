<#
.SYNOPSIS
    Get-NewBreaches.ps1 and Select-NewBreaches against a fixture catalogue.
    No network, no API key.

.DESCRIPTION
    TheHub #60990. The key-free breach watch downloads HIBP's public breach
    catalogue (/api/v3/breaches) and matches it locally against the owner's
    account domains. Two things are pinned here:

      - the matching rule, by calling the dot-sourced pure functions
        (Select-NewBreaches, ConvertTo-AccountDomains) on fixture data
      - what the script sends and what it decides, by running it for real with
        Invoke-WebRequest replaced by a function in this scope (PowerShell
        resolves a function before a cmdlet of the same name, and a child
        script sees the caller's functions). The fake records every parameter
        of every call, so the test can assert that exactly one request leaves
        and that no listed domain appears anywhere in it.

    Exit codes: 0 nothing new, 1 at least one new breach, 2 unknown (request
    failed, response not a JSON array, domains file missing or empty, bad
    -Since). Unknown is never a pass.

    ALL FIXTURES ARE CONSTRUCTED. Domains are RFC 2606 names (example.com,
    example.net, example.org) or obvious lookalikes of them. The catalogue
    rows follow the HIBP v3 /breaches shape (Name, Domain, BreachDate,
    AddedDate, DataClasses); they are not real records.

.NOTES
    Usage: pwsh -NoProfile -File skills/personal-threat-monitor/tests/Test-NewBreaches.ps1
           powershell -NoProfile -File skills/personal-threat-monitor/tests/Test-NewBreaches.ps1
    ASCII only.
#>

$ErrorActionPreference = 'Stop'
$script:SkillRoot = (Resolve-Path "$PSScriptRoot/..").Path
$script:GetNewBreaches = Join-Path -Path $script:SkillRoot -ChildPath 'scripts/Get-NewBreaches.ps1'
$script:Functions = Join-Path -Path $script:SkillRoot -ChildPath 'scripts/Select-NewBreaches.ps1'

$pass = 0; $fail = 0
function Check([string]$Name, [scriptblock]$Test, [string]$Shown) {
    $ok = $false
    try { $ok = [bool](& $Test) } catch { $Shown = "threw: $($_.Exception.Message)" }
    if ($ok) { Write-Host ("  [ok]   {0,-62} {1}" -f $Name, $Shown); $script:pass++ }
    else { Write-Host ("  [FAIL] {0,-62} got '{1}'" -f $Name, $Shown); $script:fail++ }
}

function Row([string]$Name, [string]$Domain, [string]$Added, [string[]]$Classes = @('Email addresses')) {
    [pscustomobject]@{
        Name        = $Name
        Title       = $Name
        Domain      = $Domain
        BreachDate  = '2026-01-15'
        AddedDate   = "${Added}T12:34:56Z"
        DataClasses = $Classes
    }
}

if (Test-Path -LiteralPath $script:Functions) { . $script:Functions }

# ---- the fake HIBP ---------------------------------------------------------
#
# $FakeHibpBody is the response body as text; $FakeHibpStatus, when non-zero,
# makes the fake throw as a failed request does. Names are unusual on purpose:
# the script under test runs in a child scope and must not shadow them.

$FakeHibpCalls = [System.Collections.Generic.List[object]]::new()
$FakeHibpBody = '[]'
$FakeHibpThrow = $false

Set-Item -Path function:Invoke-WebRequest -Value {
    $bound = @{}
    foreach ($k in $PSBoundParameters.Keys) { $bound[$k] = $PSBoundParameters[$k] }
    $bound['_args'] = @($args)
    $FakeHibpCalls.Add([pscustomobject]$bound)
    if ($FakeHibpThrow) { throw 'fake HIBP: 503 Service Unavailable' }
    [pscustomobject]@{ StatusCode = 200; Content = $FakeHibpBody }
}
# Invoke-RestMethod must not be used; if it is, the call is recorded and fails.
Set-Item -Path function:Invoke-RestMethod -Value {
    $FakeHibpCalls.Add([pscustomobject]@{ Uri = 'Invoke-RestMethod'; _args = @($args) })
    throw 'fake HIBP: Invoke-RestMethod is not expected'
}

function ClearFake {
    $FakeHibpCalls.Clear()
    $script:FakeHibpBody = '[]'
    $script:FakeHibpThrow = $false
}

$tmp = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath ("newbreaches-test-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null

function DomainsFile([string[]]$Lines) {
    $p = Join-Path -Path $tmp -ChildPath ([guid]::NewGuid().ToString('N') + '.txt')
    [IO.File]::WriteAllText($p, (($Lines -join "`n") + "`n"))
    return $p
}

# Runs the script, returns @{ Exit; Threw; Output; Report; Wrote }.
function Invoke-Under([hashtable]$Params) {
    $out = Join-Path -Path $tmp -ChildPath ([guid]::NewGuid().ToString('N'))
    $r = @{ Exit = $null; Threw = $false; Output = ''; Report = $null; Wrote = $false }
    $global:LASTEXITCODE = $null
    try {
        $r.Output = & $script:GetNewBreaches @Params -OutDir $out *>&1 | Out-String
        $r.Exit = $global:LASTEXITCODE
    } catch {
        $r.Threw = $true; $r.Output = $_.Exception.Message
    }
    $json = Join-Path -Path $out -ChildPath 'new-breaches.json'
    if (Test-Path -LiteralPath $json) {
        $r.Wrote = $true
        $raw = [IO.File]::ReadAllText($json)
        $r.Raw = $raw.Trim()
        $r.Report = @(ConvertFrom-Json -InputObject $raw | ForEach-Object { $_ })
    }
    return $r
}

$domains = @('example.com', 'example.net')

try {
    # ------------------------------------------------------------------------
    Write-Host ""
    Write-Host "the matching rule (Select-NewBreaches, pure)"

    $have = [bool](Get-Command -Name Select-NewBreaches -CommandType Function -ErrorAction SilentlyContinue)
    Check -Name "scripts/Select-NewBreaches.ps1 defines Select-NewBreaches" -Test { $have } -Shown $script:Functions

    $since = [datetime]'2026-10-20'
    $cat = @(
        (Row -Name 'Exact' -Domain 'example.com' -Added '2026-10-25'),
        (Row -Name 'Sub' -Domain 'login.example.net' -Added '2026-10-25'),
        (Row -Name 'Lookalike' -Domain 'notexample.com' -Added '2026-10-25'),
        (Row -Name 'Suffix' -Domain 'example.com.evil.example.org' -Added '2026-10-25'),
        (Row -Name 'Upper' -Domain 'SHOP.EXAMPLE.COM' -Added '2026-10-25'),
        (Row -Name 'Boundary' -Domain 'example.com' -Added '2026-10-20'),
        (Row -Name 'DayBefore' -Domain 'example.com' -Added '2026-10-19'),
        (Row -Name 'NoDomain' -Domain '' -Added '2026-10-25')
    )
    $hits = @(Select-NewBreaches -Catalogue $cat -Domains $domains -Since $since)
    $names = @($hits | ForEach-Object { $_.name })
    $shown = $names -join ','

    Check -Name "exact domain matches" -Test { $names -contains 'Exact' } -Shown $shown
    Check -Name "a subdomain of a listed domain matches" -Test { $names -contains 'Sub' } -Shown $shown
    Check -Name "lookalike notexample.com does not match example.com" -Test { $names -notcontains 'Lookalike' } -Shown $shown
    Check -Name "a listed domain inside a longer name does not match" -Test { $names -notcontains 'Suffix' } -Shown $shown
    Check -Name "matching is case-insensitive" -Test { $names -contains 'Upper' } -Shown $shown
    Check -Name "AddedDate on -Since matches (inclusive)" -Test { $names -contains 'Boundary' } -Shown $shown
    Check -Name "AddedDate one day before -Since does not match" -Test { $names -notcontains 'DayBefore' } -Shown $shown
    Check -Name "a breach with no Domain never matches" -Test { $names -notcontains 'NoDomain' } -Shown $shown
    Check -Name "exactly the four expected rows" -Test { $names.Count -eq 4 } -Shown $shown

    $mixed = @(Select-NewBreaches -Catalogue $cat -Domains @('Example.COM') -Since $since)
    Check -Name "a listed domain in mixed case still matches" -Test { @($mixed | ForEach-Object { $_.name }) -contains 'Exact' } -Shown (@($mixed | ForEach-Object { $_.name }) -join ',')

    $empty = @(Select-NewBreaches -Catalogue @() -Domains $domains -Since $since)
    Check -Name "an empty catalogue gives no rows" -Test { $empty.Count -eq 0 } -Shown "$($empty.Count)"

    $one = @($hits | Where-Object { $_.name -eq 'Exact' })[0]
    $props = if ($one) { @($one.PSObject.Properties | ForEach-Object { $_.Name }) -join ',' } else { '' }
    Check -Name "a row is {name, domain, breach_date, added_date, data_classes}" -Test { $props -eq 'name,domain,breach_date,added_date,data_classes' } -Shown $props
    Check -Name "added_date is the day, breach_date kept" -Test { $one.added_date -eq '2026-10-25' -and $one.breach_date -eq '2026-01-15' } -Shown "$($one.added_date) / $($one.breach_date)"

    # ConvertFrom-Json on PowerShell 7 turns ISO timestamps into [datetime];
    # 5.1 leaves them as strings. Both must land on the same day.
    $parsed = ConvertFrom-Json -InputObject '[{"Name":"Parsed","Domain":"example.com","BreachDate":"2026-01-15","AddedDate":"2026-10-20T00:00:00Z","DataClasses":["Passwords"]},{"Name":"ParsedLate","Domain":"example.com","BreachDate":"2026-01-15","AddedDate":"2026-10-19T23:59:59Z","DataClasses":["Passwords"]}]'
    $p = @(Select-NewBreaches -Catalogue @($parsed | ForEach-Object { $_ }) -Domains $domains -Since $since)
    $pn = @($p | ForEach-Object { $_.name }) -join ','
    Check -Name "parsed AddedDate 00:00Z on -Since matches, 23:59Z before does not" -Test { $pn -eq 'Parsed' } -Shown $pn
    Check -Name "data_classes stays an array of one" -Test { $p.Count -eq 1 -and @($p[0].data_classes).Count -eq 1 -and $p[0].data_classes[0] -eq 'Passwords' } -Shown ''

    # ------------------------------------------------------------------------
    Write-Host ""
    Write-Host "the domains list (ConvertTo-AccountDomains, pure)"

    $d = @(ConvertTo-AccountDomains -Lines @(
        '# my accounts', '', '  Example.COM  ', 'shop.example.net # store',
        'not a domain', 'https://example.org/login', 'user@example.org', '-bad-.example.com', 'example', 'example.com'
    ))
    $ds = $d -join ','
    Check -Name "comments, blanks and malformed lines are skipped" -Test { $ds -eq 'example.com,shop.example.net' } -Shown $ds

    # ------------------------------------------------------------------------
    Write-Host ""
    Write-Host "the request"

    ClearFake
    $df = DomainsFile -Lines @('example.com', 'secret-owner-domain.example.net')
    $r = Invoke-Under -Params @{ DomainsFile = $df; Since = '2026-10-20' }
    $c = if ($FakeHibpCalls.Count) { $FakeHibpCalls[0] } else { $null }
    Check -Name "exactly one request" -Test { $FakeHibpCalls.Count -eq 1 } -Shown "$($FakeHibpCalls.Count)"
    Check -Name "to https://haveibeenpwned.com/api/v3/breaches, no query" -Test { [string]$c.Uri -ceq 'https://haveibeenpwned.com/api/v3/breaches' } -Shown ([string]$c.Uri)
    Check -Name "a GET" -Test { (-not $c.Method) -or ([string]$c.Method -eq 'Get') } -Shown ([string]$c.Method)
    Check -Name "with a User-Agent" -Test { [string]$c.UserAgent -ne '' } -Shown ([string]$c.UserAgent)
    $hk = if ($c.Headers) { @($c.Headers.Keys) -join ',' } else { '' }
    Check -Name "and no hibp-api-key header" -Test { @($hk -split ',') -notcontains 'hibp-api-key' } -Shown $hk
    Check -Name "with a timeout" -Test { [int]$c.TimeoutSec -gt 0 } -Shown ([string]$c.TimeoutSec)

    # Everything the request carries, flattened to text.
    $sent = @()
    foreach ($prop in $c.PSObject.Properties) {
        $v = $prop.Value
        if ($v -is [System.Collections.IDictionary]) { foreach ($k in $v.Keys) { $sent += "$k=$($v[$k])" } }
        else { $sent += "$($prop.Name)=$(@($v) -join ' ')" }
    }
    $sentText = $sent -join "`n"
    $leaks = @('example.com', 'secret-owner-domain', $df, (Split-Path -Leaf $df)) | Where-Object { $sentText -like "*$_*" }
    Check -Name "no listed domain or the domains file appears in the request" -Test { $leaks.Count -eq 0 -and -not $c.Body } -Shown ($leaks -join ',')

    # ------------------------------------------------------------------------
    Write-Host ""
    Write-Host "what is written down, and the exit code"

    ClearFake
    $FakeHibpBody = ConvertTo-Json -Depth 4 -InputObject @(
        (Row -Name 'ExampleForum' -Domain 'forum.example.com' -Added '2026-10-22' -Classes @('Email addresses', 'Passwords')),
        (Row -Name 'Elsewhere' -Domain 'example.org' -Added '2026-10-22')
    )
    $df = DomainsFile -Lines @('example.com')
    $r = Invoke-Under -Params @{ DomainsFile = $df; Since = '2026-10-20' }
    Check -Name "a match exits 1" -Test { -not $r.Threw -and $r.Exit -eq 1 } -Shown "$($r.Exit) $($r.Output)"
    Check -Name "new-breaches.json holds the match" -Test { $r.Report.Count -eq 1 -and $r.Report[0].name -eq 'ExampleForum' -and $r.Report[0].domain -eq 'forum.example.com' -and $r.Report[0].added_date -eq '2026-10-22' -and (@($r.Report[0].data_classes) -join '|') -eq 'Email addresses|Passwords' } -Shown "$($r.Raw)"
    Check -Name "a single match is still written as an array" -Test { $r.Raw.StartsWith('[') } -Shown ''

    ClearFake
    $FakeHibpBody = ConvertTo-Json -Depth 4 -InputObject @((Row -Name 'Elsewhere' -Domain 'example.org' -Added '2026-10-22'))
    $r = Invoke-Under -Params @{ DomainsFile = $df; Since = '2026-10-20' }
    Check -Name "nothing new exits 0" -Test { -not $r.Threw -and $r.Exit -eq 0 } -Shown "$($r.Exit) $($r.Output)"
    Check -Name "and writes an empty array" -Test { $r.Wrote -and $r.Raw -eq '[]' } -Shown "$($r.Raw)"

    ClearFake
    $today = [datetime]::UtcNow.Date
    $FakeHibpBody = ConvertTo-Json -Depth 4 -InputObject @(
        (Row -Name 'EightDays' -Domain 'example.com' -Added $today.AddDays(-8).ToString('yyyy-MM-dd')),
        (Row -Name 'NineDays' -Domain 'example.com' -Added $today.AddDays(-9).ToString('yyyy-MM-dd'))
    )
    $r = Invoke-Under -Params @{ DomainsFile = $df }
    $rn = @($r.Report | ForEach-Object { $_.name }) -join ','
    Check -Name "-Since defaults to today minus 8 days (UTC)" -Test { $r.Exit -eq 1 -and $rn -eq 'EightDays' } -Shown "$($r.Exit) $rn"

    # ------------------------------------------------------------------------
    Write-Host ""
    Write-Host "unknown is not a pass (exit 2, nothing written)"

    ClearFake
    $FakeHibpThrow = $true
    $r = Invoke-Under -Params @{ DomainsFile = $df; Since = '2026-10-20' }
    Check -Name "a failed request exits 2" -Test { -not $r.Threw -and $r.Exit -eq 2 -and -not $r.Wrote } -Shown "$($r.Exit) wrote=$($r.Wrote)"

    ClearFake
    $FakeHibpBody = '{"Name":"NotAnArray","Domain":"example.com","AddedDate":"2026-10-25T00:00:00Z"}'
    $r = Invoke-Under -Params @{ DomainsFile = $df; Since = '2026-10-20' }
    Check -Name "a JSON object, not an array, exits 2" -Test { $r.Exit -eq 2 -and -not $r.Wrote } -Shown "$($r.Exit) wrote=$($r.Wrote)"

    ClearFake
    $FakeHibpBody = '<html><body>Just a moment...</body></html>'
    $r = Invoke-Under -Params @{ DomainsFile = $df; Since = '2026-10-20' }
    Check -Name "an HTML page exits 2" -Test { $r.Exit -eq 2 -and -not $r.Wrote } -Shown "$($r.Exit) wrote=$($r.Wrote)"

    ClearFake
    $FakeHibpBody = ''
    $r = Invoke-Under -Params @{ DomainsFile = $df; Since = '2026-10-20' }
    Check -Name "an empty body exits 2" -Test { $r.Exit -eq 2 -and -not $r.Wrote } -Shown "$($r.Exit) wrote=$($r.Wrote)"

    ClearFake
    $r = Invoke-Under -Params @{ DomainsFile = (Join-Path -Path $tmp -ChildPath 'missing.txt'); Since = '2026-10-20' }
    Check -Name "a missing domains file exits 2 before any request" -Test { $r.Exit -eq 2 -and $FakeHibpCalls.Count -eq 0 -and -not $r.Wrote } -Shown "$($r.Exit) calls=$($FakeHibpCalls.Count)"

    ClearFake
    $r = Invoke-Under -Params @{ DomainsFile = (DomainsFile -Lines @('# only a comment', '', 'not a domain')); Since = '2026-10-20' }
    Check -Name "a domains file with no usable domain exits 2" -Test { $r.Exit -eq 2 -and $FakeHibpCalls.Count -eq 0 -and -not $r.Wrote } -Shown "$($r.Exit) calls=$($FakeHibpCalls.Count)"

    ClearFake
    $r = Invoke-Under -Params @{ DomainsFile = $df; Since = '20/10/2026' }
    Check -Name "a -Since that is not yyyy-MM-dd exits 2" -Test { $r.Exit -eq 2 -and $FakeHibpCalls.Count -eq 0 } -Shown "$($r.Exit) calls=$($FakeHibpCalls.Count)"

    # ------------------------------------------------------------------------
    Write-Host ""
    Write-Host "the domains file stays local"

    $example = Join-Path -Path $script:SkillRoot -ChildPath 'references/account-domains.example.txt'
    $exLines = if (Test-Path -LiteralPath $example) { @(ConvertTo-AccountDomains -Lines (Get-Content -LiteralPath $example)) } else { @() }
    $notPlaceholder = @($exLines | Where-Object { $_ -notmatch '(^|\.)example\.(com|net|org)$' })
    Check -Name "references/account-domains.example.txt ships placeholders only" -Test { $exLines.Count -gt 0 -and $notPlaceholder.Count -eq 0 } -Shown (($exLines + '|' + $notPlaceholder) -join ',')

    $gitOk = [bool](Get-Command -Name git -CommandType Application -ErrorAction SilentlyContinue)
    if ($gitOk) {
        Push-Location -LiteralPath $script:SkillRoot
        try {
            $ignored = & git check-ignore -q -- 'references/account-domains.local.txt' 2>$null; $ignoredExit = $LASTEXITCODE
            & git check-ignore -q -- 'references/account-domains.example.txt' 2>$null; $exampleExit = $LASTEXITCODE
        } finally { Pop-Location }
        Check -Name "git check-ignore ignores references/account-domains.local.txt" -Test { $ignoredExit -eq 0 } -Shown "exit $ignoredExit"
        Check -Name "and does not ignore the .example.txt" -Test { $exampleExit -eq 1 } -Shown "exit $exampleExit"
    } else {
        Write-Host "  NOTE  git not on PATH; the check-ignore cases did not run"
    }

    $src = if (Test-Path -LiteralPath $script:GetNewBreaches) { Get-Content -LiteralPath $script:GetNewBreaches -Raw } else { '' }
    Check -Name "the default -DomainsFile is references/account-domains.local.txt" -Test { $src -match "references[/\\]account-domains\.local\.txt" } -Shown ''
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
