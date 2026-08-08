# Identifier Ledger — CONFIDENTIAL (copy to identifiers.md and fill; never commit the filled copy)

> Sanitized template. Copy to `identifiers.md` (gitignored) and populate locally. The expanded
> identifier set powers deeper OSINT (Check A) and sharper threat modeling (Check B).

## Handling classes
- **[S] Search** — actively queried against public sources.
- **[D] Disambiguation** — used only to confirm a record is yours; not broadcast/published.
- **[M] Monitor-only** — never stored in full, never searched. Exposure flag + protective action only.

Addresses: **city/state/ZIP** is `[S]`; **full street** is `[D]`.

---

## 1. Email addresses  [S]  — top breach/account unlock
| Email | Type | Years used | Recovery/2FA on any account? | Notes |
|-------|------|-----------|------------------------------|-------|
| <you@example.com> | personal | <..>–present | <yes/no> | primary |
| <old ISP/work/school email> | | | | often heavily breached |

## 2. Phone numbers  [S]  — SIM-swap & breach join key
| Number | Type | Years | Carrier | 2FA/recovery for? | Ported/reassigned? |
|--------|------|-------|---------|-------------------|--------------------|
| <current mobile> | mobile | <..>–present | | <high-value accts> | |
| <previous mobile> | mobile | | | | possibly reassigned |

## 3. Address history  — disambiguation backbone + KBA/SIM-swap surface
| City / State / ZIP  **[S]** | Full street (matching only) **[D]** | Years | Own/Rent |
|-----------------------------|-------------------------------------|-------|----------|
| <city, state ZIP> | <..> | <..>–present | |
> Best source: annualcreditreport.com lists full address history in one place.

## 4. Names & handles  [S]
- **Name variants / AKAs:** <name; middle; misspellings; suffixes>
- **Household surnames [D]:** <minimal, for matching only>
- **Usernames:**
  | Handle | Platform(s) | Era | Active? |
  |--------|-------------|-----|---------|
  | <handle> | <..> | <..> | |

## 5. Employers  [S]  — records + impersonation pretexts
| Employer | Role | Years |
|----------|------|-------|
| <current> | | |
| <previous> | | |

## 6. Digital assets  [S]
- **Domains:** <domain> — check WHOIS history for leaked historical registrant PII
- **Crypto wallet addresses (public):** <addr>
- **Home/static IP or ASN:** <..>

## 7. Voice / photo public-exposure audit  — whaling/deepfake risk
- <public talk / podcast / video — voice? photo? duration>

---

## MONITOR-ONLY set  [M]  — no full values stored
| Identifier | Exposed? | Protective action | Status |
|------------|----------|-------------------|--------|
| SSN | <unknown> | Credit freeze at all 3 bureaus | ☐ ☐ ☐ |
| Driver's license | | state MVD alert if breached | ☐ |
| Passport # | | monitor; replace if leaked | ☐ |
| Full DOB | likely public | treat KBA as compromised → app/hardware MFA | ☐ |
| Financial account #s | | bank alerts + monitoring | ☐ |

**Recovery-chain hygiene:**
- ☐ Removed old/defunct emails as recovery on important accounts
- ☐ Moved 2FA off SMS to app/passkey where possible
- ☐ Carrier port-out / SIM PIN enabled
- ☐ No unknown recovery email/phone on primary accounts

---

## How to collect your own history (fast path)
1. **annualcreditreport.com** → name variants, full address history, employers.
2. **Old email inboxes** → "welcome / confirm / receipt" to inventory forgotten accounts.
3. **Brokers themselves** (Spokeo/BeenVerified) → harvest displayed address+phone history, then opt out.
4. **Password manager / old devices** → old usernames + emails.
5. **WHOIS history** for domains; **LinkedIn/resume** for employer timeline.
