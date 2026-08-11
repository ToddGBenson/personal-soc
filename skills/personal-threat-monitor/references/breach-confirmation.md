# Breach confirmation (authoritative, not inferred)

Closes the biggest accuracy gap in Check A: replaces "likely breached" (blast-radius inference) with a **confirmed, dated breach list** per email. Run via `scripts/Invoke-BreachCheck.ps1`.

## Why it matters
Web search can't authoritatively answer "is *this* email in a breach." Only a breach-index API can. Until then, findings like "an old email / your carrier likely exposed you" are **candidates** (see `verification.md`), not facts. This capability promotes them to confirmed — or clears them.

## Have I Been Pwned (primary)
- Get an API key: **haveibeenpwned.com/API/Key** (~$4/mo; email-search requires the key).
- The script queries `breachedaccount` (which breaches) + `pasteaccount` (paste-site appearances) for each email, with rate-limit backoff.
- **Never commit the key.** Pass `-ApiKey` at runtime or set `$env:HIBP_API_KEY`. It's not stored in the repo or the ledger.
- Run:
  ```
  Invoke-BreachCheck.ps1 -Emails you@example.com,old@oldisp.net,you@proton.me -ApiKey $env:HIBP_API_KEY -OutDir personal-monitor/<date>
  ```
- Output: `breaches.json` (per email: breach names, dates, exposed data classes).

## DeHashed (optional, deeper)
HIBP tells you *which* breaches. **DeHashed** (dehashed.com — separate paid subscription/API) returns the *leaked record content* (which password/phone/address leaked where) — useful to know exactly what to rotate. Higher sensitivity; use deliberately. A future `-Provider dehashed` mode can be added to the same script.

## Feeding results back
For each confirmed breach:
1. In `identifiers.md`, change the email's tag from "likely-breached" → **confirmed** with the breach names/dates.
2. Drive actions: rotate any reused password from that breach, **remove the email as a recovery address** anywhere, and if it exposed SSN/DL (e.g. a carrier breach), confirm the **credit freeze**.
3. Record as a finding so it flows into the digest; a *new* breach appearing between runs is **page-worthy**.

## Accuracy note
HIBP is authoritative for breaches *it has indexed* — comprehensive but not omniscient (some breaches never reach it). A clean result lowers probability but isn't absolute proof of non-exposure. Still a massive step up from inference.
