# Data-broker removal playbook (Check A output)

When the user wants removals (their selected default), pair each finding with a concrete action. The user must submit most opt-outs themselves (identity verification) — this skill produces the worklist and instructions, it does not impersonate the user to brokers.

## Approach

1. **Triage by reach.** Prioritize the big aggregators others scrape from: Spokeo, BeenVerified, Intelius/PeopleFinders family, Whitepages, Radaris, MyLife, TruePeopleSearch/FastPeopleSearch, ZoomInfo (professional).
2. **Opt out at the source first** — many small brokers pull from a few large ones; removing upstream reduces downstream re-listing.
3. **Expect re-listing.** Broker records regenerate; opt-outs need re-checking every 1–3 months. This is why Check A runs on a cadence.

## Per-broker opt-out pointers (verify URLs at run time — they change)

- **Spokeo:** spokeo.com/optout — submit the listing URL + email; confirm via email link.
- **BeenVerified:** beenverified.com/app/optout/search — find record, verify by email.
- **InstantCheckmate / TruthFinder / Intelius (PeopleConnect):** each has an opt-out/suppression page; PeopleConnect brands share a backend.
- **Whitepages:** whitepages.com/suppression-requests — find profile, request removal, phone verification.
- **Radaris:** radaris.com/page/how-to-remove — account-based control of the listing.
- **MyLife:** removal by request/phone; historically slow — persist.
- **TruePeopleSearch / FastPeopleSearch:** self-service "remove my record" by record URL.
- **ZoomInfo (professional data):** zoominfo.com/update — B2B opt-out; relevant since it exposes the work email/phone.

## Options to offer the user

- **DIY worklist:** this skill outputs the exact per-broker links + steps; user submits. Free, most control.
- **Authorization-based services:** mention (neutrally) that paid removal services (e.g. DeleteMe, Optery, EasyOptOuts) automate recurring opt-outs — a time-vs-money choice, not an endorsement.
- **Preventive hygiene:** register with the state/DMV and voter data suppression where available; use a forwarding email/VoIP number for new signups; tighten LinkedIn public visibility (the biggest professional-recon surface for this user).

## Things that generally can't be removed

- Public property/court records (public by law) — brokers re-publish these; mitigate by removing the *aggregated* broker profile, not the source record.
- Press mentions, conference bios, public GitHub commits — the user controls these directly (edit/remove at the source).

## Account-hygiene actions (from inbox findings)

- **Review & revoke non-Claude OAuth grants** (Google Account → Security → Third-party access). Flagged example: any unfamiliar app — e.g. a third-party notetaker, or a broad "apps & services" grant.
- **Verify unexpected passkeys/devices** (Google Account → Security → Passkeys / Your devices).
- **Secure the linked `.sec` account** and confirm recovery settings on both.
- **Password manager + unique passwords + hardware/passkey MFA** on the high-value accounts (email, financial, work-adjacent).
