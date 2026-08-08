# Report outline

Fixes the *structure* of the deliverable so every engagement is comparable. **Design each report fresh** with the `artifact-design` and `artifact-diagramming` skills — do not reuse prior visuals. Publish as a private artifact; remind the user it maps live weaknesses.

## Required sections

0. **Bottom line** — 2–3 paragraphs. The posture verdict, the single worst finding, and the shape of the problem (e.g. "config + missing architecture"). If the user develops software, name the second track (securing the LAN vs. standing up a dev/lab environment).
1. **Current topology** — the *current-state* network diagram + inventory summary. Show the real mechanism, not a device list.
2. **Priority findings** — Critical/High as cards: severity, what (with evidence), impact, fix. Evidence must be real scan output.
3. **Controls gap assessment** — the full CIS v8 table (all 18), observed evidence per control, status chip, priority. Close with a scorecard sentence naming where Criticals and Highs cluster.
4. **Target architecture** — the *target-state* diagram. Draw the **difference** from §1 (flat → segmented), with allowed vs denied inter-zone flows labeled.
5. **Tooling verdicts** (when relevant) — direct yes/no on Security Onion, Kali, CI/CD, each right-sized. Use `remediation-library.md`.
6. **Builder environment** (when the user develops software) — pipeline + isolated-lab diagram mapped onto the VLANs.
7. **Roadmap** — Now / Next / Later, sequenced by risk-reduced-per-hour. The Now lane should need no purchases.
8. **Footer** — method, framework (CIS v8), scope, and **what was not tested** (WAN exposure, credential strength, guest isolation) + fingerprint caveats.

## The diagram set (draw the mechanism)

- **Current (flat):** internet → gateway (flag if EOL) → one segment bus → device groups all on it. Draw the key attack path (e.g. IoT → NAS unauth read/write) in the alert color. Claim: *no interior boundary*.
- **Target (segmented):** modem-bridge → firewall → VLAN trunk → zones. Draw allowed flows in the accent color, denied inter-zone flows crossed/dashed in the alert color. Claim: *boundaries + default-deny*.
- **Builder (optional):** vertical pipeline (dev → CI gates → staging → prod, artifacts to a store **not** the NAS) and a horizontal isolated Lab (Kali + targets, walled from home/WAN). Claim: *two clean separations*.

Follow `artifact-diagramming`: inline SVG, `currentColor` for structure, one meaningful hue for the element under discussion, labeled arrows, one figure/one claim.

## Severity model

| Severity | Anchor |
|----------|--------|
| Critical | Unauthenticated access to data or backups; broken recovery; open wireless entry |
| High | Missing structure — no segmentation, monitoring, or managed infra; EOL infra; downgradeable Wi-Fi |
| Medium | Hardening gaps — UPnP, excess services, transition-mode where low-impact |
| Low/Info | Observations without direct exposure |

Grade on *this network's* evidence, not the generic weight of the issue.

## Tone

Plain, factual, non-alarmist. Lead with the worst real finding. Give a recommendation, not an options survey. Separate what was **confirmed** from what is **recommended target** or **untested**. Never overstate: "inconclusive" when a probe didn't answer, not "clean".
