# OSINT verification (turning candidates into facts)

The footprint is only as trustworthy as its attribution. When the subject has a common name, every OSINT hit gets a confidence tier, and only verified items become "facts."

## Confidence tiers
- **[confirmed]** — direct evidence it's the subject (matches a known email/handle/employer/address the user gave), or the user confirmed it.
- **[probable]** — corroborates on **≥2** independent profile facts (e.g. prior address + known employer). Usable, but labeled.
- **[candidate]** — plausible but name-only / single-signal, with real collision risk. **Never merged into the profile or report as fact** — goes on the verify checklist.
- **[rejected]** — user or evidence ruled it out (e.g. a prominent namesake — an executive, an artist, an athlete who shares the name).

## The rule
Records enter `profile.md` / `identifiers.md` / findings only at **confirmed** or **probable** (labeled). Candidates live in a separate `verify-checklist.md` until the user rules on them. This is what keeps other people's data out of the subject's profile.

## Promotion workflow (each run)
1. After Check A, bucket new hits into the tiers above.
2. Emit/refresh `personal-monitor/<date>/verify-checklist.md` with the **candidate** items and the one question that would resolve each.
3. User confirms/rejects. Update the ledger tag (`[confirmed]` / `[rejected]`).
4. Rejected items are remembered so future runs don't re-surface them as new.

## Breach inferences count as candidates too
"Likely breached" from blast-radius reasoning (e.g. an old webmail account, or a carrier breach) is a **candidate** until an authoritative source confirms it — that's what the breach-confirmation capability (HIBP/DeHashed) is for. Report inferences as inferences, never as confirmed compromise.

## Common-name discipline
- Require ≥2 corroborating facts before candidate→probable.
- Prefer unique identifiers (exact email, exact handle, prior address) over name+city.
- When a prominent namesake exists (exec, artist, athlete), explicitly note it so it's not conflated.
