# OSINT source catalog & query patterns (Check A)

Where to look and how to query, by category. Run against the identifiers in `profile.md`. Public sources + the user's own accounts only (see `controls.md`). Cross-check at least two signals before attributing a record to the user — common names collide.

## 1. Search engines (broad footprint)

Query patterns (WebSearch):
- `"<Full Name>" <City> <State>`
- `"<Full Name>" <employer OR prior employer>`
- `"<primary email>"` and `"<secondary email>"` (paste/leak mentions)
- `<reused handle>` across `github twitter reddit`
- `"<Full Name>" (resume OR CV OR bio OR speaker OR conference)`
Note the **common-name problem**: filter out records tied to other cities/ages/employers.

## 2. Data brokers (people-search — the bulk of personal exposure)

Presence usually confirmed via search snippets. Primary brokers to check (and later opt out of): **Spokeo, BeenVerified, InstantCheckmate, Whitepages, 411, YellowBook, TruePeopleSearch, FastPeopleSearch, Radaris, MyLife, PeopleFinders, Intelius, ZoomInfo** (professional). Record which list the user, and what fields (age/phone/address/relatives). Removal steps → `broker-optout.md`.

## 3. Breach & paste exposure

- Recommend the user check **HaveIBeenPwned**, **DeHashed**, **Leak-Lookup** for each email/username (these need the user's own lookup or an API key — don't assert breach status from web search alone).
- WebSearch for `"<email>" breach OR paste OR leaked` to catch public mentions.
- Note the *blast radius* of major recent dumps (infostealer collections, provider breaches) even without a confirmed personal hit.

## 4. The user's own inbox (with consent — high signal)

Gmail query set (via the connected account, snippet/metadata first):
- **Breach / account exposure:** `subject:(breach OR "data breach" OR "security alert" OR "unusual sign-in" OR "new sign-in" OR "your password" OR compromised OR passkey) newer_than:1y`
- **Standing third-party access (OAuth):** search `from:no-reply@accounts.google.com "You allowed"` → list non-Claude grants to review/revoke.
- **Linked / recovery identities:** alerts "sent to <other address>. <primary> is the recovery email" → surfaces alternate accounts to secure.
- **Account inventory:** `subject:(welcome OR "confirm your email" OR receipt OR "your subscription")` → which services hold the user's data.
Record findings, not raw message contents.

## 5. Social media & forums / usenet

- Direct profile checks on LinkedIn, X, Facebook, Instagram, Reddit for the reused handle/name (public view only).
- Usenet / legacy forums: WebSearch `"<handle>" site:groups.google.com` and general `"<handle>" forum`.
- Look for over-shared PII: location tags, employer, family names, birthday, pet/first-car (security-answer fodder).

## 6. Code repositories (developer-specific)

The user is a security developer — leaked secrets are a real risk:
- GitHub/GitLab user search for the handle; review public repos and **commit author emails** (git history leaks personal emails).
- WebSearch `"<email>" site:github.com` and check for keys/tokens/`.env` in public gists.
- Note any repo tying the personal identity to home-lab/network details.

## 7. Public records & images

- County assessor / property records (already re-published by brokers) — note but these are hard to remove (public by law).
- Reverse-image / profile-photo reuse if a public avatar exists (note only; don't over-investigate).

## Output

Write `footprint.json`: array of `{category, source, exposed_fields, confidence, severity, removal_action}`. Diff against the prior run and lead the report with **new** exposures.
