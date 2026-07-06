# Verdict — Case 019 (Final Exam, Stage 1)

## Final Verdicts

| Alert | Verdict | MITRE ATT&CK |
|---|---|---|
| **BA** — Download-Execute Unsigned Binary | 🔴 **TP** | T1105, T1204.002 |
| **BB** — Tor Exit Node Login | 🔴 **TP** | T1078, T1090 |
| **BD** — High-Volume DNS TXT Queries | 🔴 **TP** | T1071.004, T1048.003 |
| **BC** — Persistent AV-Enumeration Task | 🔴 **TP** | T1518.001, T1053.005 |
| **BF** — Windows Update Stopped | 🟢 **FP** | — |
| **BE** — AD Display Name Change | 🟢 **FP** | — |
| **BG** — Confirmed Mimikatz Process (interrupt) | 🔴 **TP** | T1003 |

**Result: 5 TP, 2 FP, 0 Ambiguous across 7 alerts.**

---

## Chain Correlation

Alerts BA and BG are directly linked: BA's download-and-execute of `svc.exe` from an external IP is confirmed by BG's EDR detection of an active Mimikatz-signature process — the same binary. This represents one continuous, active credential-theft attack chain rather than two isolated events, and should be treated as such in response planning.

---

## Prioritization Review

**Chosen order:** BA → BB → BD → BC → BF → BE, with BG (interrupt) correctly recognized as requiring no further deferral since the opening queue was already resolved by the time it arrived.

**Assessment:** Correctly prioritized the actively-executing threat (BA) and strong compromise indicator (BB) ahead of the recon/persistence items (BD, BC), with the two lower-risk, more ambiguous-leaning items (BF, BE) correctly triaged last. Order held up well under time pressure.

---

## Corrections Made During This Case

Of 7 alerts, 4 required correction before reaching the final verdict (BD, BC, BF, BE) — a higher rate than recent Phase 3 cases, attributable to the enforced pace pressure. All four corrections were accepted quickly and without repeated argument; no alert required more than one round of correction.

---

## Recommended Response Actions

- **BA/BG (linked):** Isolate host immediately; this is an active, confirmed credential-theft incident, not a suspected one.
- **BB:** Force password reset and session termination for account `hp`; review for further activity from this session.
- **BD:** Block outbound DNS to `*.datasync-cloud.net`; investigate what data may have already been tunneled out.
- **BC:** Remove the "SysCheck" scheduled task; investigate what security tooling was identified and whether evasion followed.
- **BF/BE:** No action required; close as FP.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Alerts in Stage | 7 (6 opening queue + 1 interrupt) |
| Total Time | ~14 minutes (approximate, self-reported average ~2 min/alert) |
| Correct Prioritization | Yes |
| Corrections Needed | 4 of 7 |
| Escalated | BA, BG (linked, immediate), BB, BD, BC |
| Closed, No Action | BF, BE |
