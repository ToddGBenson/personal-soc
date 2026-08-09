# Change detection, posture score & digest

Capabilities ported from a production SOC's security-automation subsystem so recurring runs behave like a monitoring system, not one-off scans. Skill-native: no server/DB — state lives in the dated engagement folders and is diffed across runs.

## Baseline & diff model
Each run writes `findings.json` (+ `inventory.csv`) to `netassess/<date>/`. A finding is `{id, title, severity, cis, status}` where `status` is `open` or `resolved`. Keep stable `id`s across runs so findings can be tracked over time. The previous engagement folder is the baseline.

## Posture score (0–100)
Mirrors a production SOC's self-assessment score. Start at 100; subtract per **open** finding:

| Severity | Penalty |
|---|---|
| critical | −15 |
| high | −6 |
| medium | −2 |
| low | −1 |

Bands: 85+ Strong · 70–84 Good · 50–69 Fair · 25–49 Poor · <25 Critical. It's a heuristic for tracking *direction over time*, not an absolute grade — report the number **with** the delta.

## Change categories (what a run reports vs baseline)
- **Resolved** — open in baseline, now resolved/absent (celebrate these).
- **New** — open now, not present in baseline.
- **Severity changed** — same id, different severity.
- **Host add/remove** — MAC-level diff of `inventory.csv` (a production SOC's NMAP change detection). New hosts are the highest-value alert — a device that shouldn't be there.

Run it: `scripts/Compare-Assessment.ps1 -Baseline <prev-folder> -Current <this-folder>` → prints the diff + score delta and writes `change-summary.json`.

## Severity-gated alerting
Like a production SOC, only **high/critical** changes should page. Tiers for a digest/notification: 🔴 critical (page), 🟠 high (nudge), ⚪ info (log only). A new host, a new open critical, or a score drop are page-worthy; a resolved finding or an idle IoT device dropping off is informational.

## Combined security digest
The "morning briefing" — one scannable page aggregating all three scans (network + OSINT + threat), the posture score + delta, the change list, and a ranked action list. See `netassess/2026-08-09/security-digest.md` for the shape. This is the artifact to deliver on a schedule.

## Cadence (the automation layer)
a production SOC schedules these (nmap weekly, OSINT weekly, threat feeds 6-hourly). Skill-native equivalent: drive with `/schedule` (cloud agent) or `/loop`. Each scheduled run: re-scan → write `findings.json` → `Compare-Assessment` vs last → emit the digest → surface only **new/changed** items. A full re-dump every run trains the reader to ignore it; lead with the delta.
