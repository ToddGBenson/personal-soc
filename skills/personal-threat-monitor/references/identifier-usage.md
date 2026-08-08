# How the checks use the identifier ledger

Read `identifiers.md` at the start of each run and expand both checks with it. Respect handling classes: **[S]** search, **[D]** disambiguate only, **[M]** never search — monitor exposure only.

## Check A (OSINT) — query expansion & disambiguation

**Fan out searches across every [S] identifier, not just the current one:**
- **Each email** (current + previous) → breach/paste search, account-inventory, `"<email>" site:github.com`. Old ISP/school emails are high-yield — search them all.
- **Each phone** (current + previous) → reverse-phone on brokers, breach-dump join, spam/spoof-reputation DBs. Flag previous numbers as *possibly reassigned* (a stranger may now hold them).
- **Each city/ZIP** [S] → localized name+location searches, voter/property record hits.
- **Each username/handle** → cross-platform + usenet/forum + code-repo correlation.
- **Each employer** → professional records, work-email-pattern inference, employer-breach exposure.
- **Domains** → WHOIS-history for leaked historical registrant PII; **wallet addresses** → on-chain linkage.

**Disambiguation rule (this is what historical identifiers are *for*):** a broker/breach record is attributed to the user only when it corroborates on ≥2 ledger facts (e.g. a prior address **[D]** + a known employer, or an old email + DOB). Records that match name alone go in an "unconfirmed / possible collision" bucket — never merged into the profile. This is how you keep the other 10 Todd Bensons out of the report.

**Output additions to `footprint.json`:** tag each finding with which identifier surfaced it, so removals can target the right record and you can see which *old* identifier is leaking.

## Check B (threat intel) — derive the attack surface from the ledger

The identifier set defines what an attacker can do. Derive these each run:
- **SIM-swap exposure:** from §2 — which current/previous numbers are 2FA/recovery for high-value accounts. More SMS-2FA on valuable accounts = higher priority to move to app/passkey.
- **Recovery-chain risk:** from §1 — old emails still set as recovery on important accounts are takeover pivots; flag for removal.
- **KBA exposure:** from §3 address history + [M] DOB — assume attackers can answer "which street / which county / birth year" knowledge-based-auth questions, because brokers sell exactly that. Recommend treating KBA as compromised.
- **Voice-clone / deepfake risk:** from §7 — the more public voice/video, the lower the barrier to the multi-channel whaling attacks that are this user's top risk. Track it as a trend and recommend verification protocols (call-back on a known number, code words with family/finance contacts).
- **Pretext modeling:** from §5 employers + §4 handles — each ex-employer and old persona is a plausible impersonation angle; note which are being abused in current campaigns.

**Correlate with the inbox (consented):** for every [S] identifier, check whether campaigns from `threat-sources.md` are already arriving addressed to that identifier — an in-inbox match on an *old* email is an especially strong "this identifier is actively targeted" signal.

## Safety reminders
- Never put [M] values into a query or the report — only exposure flags + protective actions.
- Previous phone numbers may now belong to strangers; searching them is fine, but never contact them and don't attribute the current holder's data to the user.
- Relatives' names [D] are other people's PII — use only to confirm the user's records and for family-scam coverage, minimally.
