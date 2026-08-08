# Threat-intel source catalog & demographic mapping (Check B)

How to build the weekly personalized brief: which sources to pull, mapped to the user's risk dimensions in `profile.md`. Always date the brief and cite sources. Prefer items from the **last 1–2 weeks**; note if a threat is ongoing vs newly emerging.

## General / cross-cutting sources

- **CISA** advisories & alerts; **FBI IC3** public service announcements; **FTC Consumer Alerts** (consumer.ftc.gov).
- Breach trackers: HaveIBeenPwned "recently added," reputable breach roundups (verify, don't take single-blog claims at face value).
- Vendor threat blogs for campaign specifics (Group-IB, Recorded Future, Forcepoint, Proofpoint, Mandiant, Microsoft/Google TAG). Corroborate a campaign across 2+ before headlining it.
- Query pattern: `<topic> campaign <current month year>`, `<service the user uses> breach <year>`.

## Dimension → what to pull

**1. Executive / security-leader (highest weight for this user)**
- Whaling / BEC / vendor-impersonation trends; deepfake-voice and multi-channel (email+call+LinkedIn/Teams) campaigns; consultant/Big-Four impersonation.
- Queries: `whaling OR BEC campaign <month year>`, `deepfake voice executive fraud <year>`, `consultant OR "professional services" impersonation phishing`.
- Personalize: the user's public career graph (current + former employers) is recon fuel — call out pretexts that would use it.

**2. Financial / investment / crypto**
- Account-takeover, SIM-swap→drainer, crypto-drainer lures, fake investment portals, payment fraud.
- Queries: `crypto drainer OR wallet drainer campaign <month year>`, `investment scam portal <year>`, `SIM swap account takeover <year>`.
- Seasonal hooks: major events (e.g. World Cup 2026) spawn ticket/crypto/token lures — flag when active.

**3. Health / medical**
- Large health-sector breaches and their blast radius (e.g. Change Healthcare ~192.7M); Medicare/insurance imposter scams; Open-Enrollment season spikes.
- Queries: `healthcare data breach <month year>`, `Medicare scam OR insurance imposter <year> FTC`.
- If the user supplies insurers/providers, check those specifically.

**4. Family / eldercare / dependents**
- Grandparent scams, benefit/tax/school fraud, romance/pig-butchering, and **package-delivery smishing** (very active).
- Queries: `elder fraud warning <month year>`, `grandparent scam OR package smishing <year>`.

## Locale overlay (user's state / metro)

- The state **Attorney General** consumer alerts; the regional **FBI field office** press releases; the state **financial / insurance regulator**; the state AARP chapter.
- Query: `<state OR metro> scam alert <month year>`. Some states rank far worse for elder-fraud losses — locale matters here.

## Correlate with the user's inbox (with consent)

The strongest personalization: is a researched campaign *already* hitting the user? Search recent mail/spam for the campaign's hallmarks (delivery-text lures, crypto/token offers, invoice/BEC pretexts, Medicare "activate your card"). An in-inbox match promotes a general threat to a **direct, act-now** item.

## Severity for the brief

- **Act now** — a campaign matching the user's profile is active AND evidence it's reaching them (inbox hit) or hitting their locale/sector this week.
- **Heightened** — active campaign matching a weighted dimension, not yet seen on the user.
- **Awareness** — relevant trend, lower immediacy.
