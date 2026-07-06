# Verdict — Case 017 (Phase 3)

## Final Verdicts

| Alert | Verdict | MITRE ATT&CK |
|---|---|---|
| **Alert AC** — Mimikatz-Named Tool Download | 🔴 **TP** | T1059.001, T1105 |
| **Alert AE** — SMTP-Style Exfil via PowerShell | 🔴 **TP** | T1071, T1048 |
| **Alert AD** — Self-Add to RDP Users Group | 🟡 **Ambiguous** | T1078 (related) |
| **Alert AF** — Backward Time Change | 🟡 **Ambiguous** | T1070.006 (related) |

---

## Justification Summary

**Alert AC (TP):** Fileless download-execute pattern targeting a named credential-dumping tool (Mimikatz) from a raw external IP — decisive combination with no legitimate explanation.

**Alert AE (TP):** The source process (`powershell.exe`), not the port or destination alone, is the deciding factor — a scripting engine has no legitimate reason to initiate SMTP-style traffic directly, consistent with mail-disguised exfiltration or C2 patterns.

**Alert AD (Ambiguous):** A user self-adding to a lower-privilege group (Remote Desktop Users, not Administrators) is genuinely dual-use — legitimate remote-work setup versus an attacker establishing RDP persistence on a possibly-compromised account. No corroborating follow-up activity (e.g., a subsequent external RDP connection) was available to resolve the tie, despite occurring in the same session as two confirmed TP alerts.

**Alert AF (Ambiguous):** A backward system clock change has legitimate explanations (NTP correction, DST adjustment) but is also a recognized anti-forensics-adjacent technique. Occurring within the same session as confirmed malicious activity (AC, AE) raises the concern level above what the event would carry in complete isolation, but no independent confirmation of deliberate intent is available.

---

## Prioritization Review

**Chosen order:** AC → AE → AD → AF

**Assessment:** Correctly prioritized the two actively-executing/communicating threats (AC, AE) ahead of the two context-dependent, harder-to-resolve alerts (AD, AF) — sound reasoning based on active-harm urgency over investigative complexity.

---

## Cross-Alert Correlation Note

Alerts AD and AF, while individually resolved as Ambiguous, occur within the same session as two confirmed TP alerts (AC, AE). This correlation does not change either verdict to TP on its own, since neither AD nor AF has independent confirming evidence of malicious intent — but it does elevate their priority for continued monitoring and supports treating the overall session as a likely active compromise requiring broader investigation beyond the four alerts triaged individually here.

---

## What Would Change Each Verdict

**Alert AC → FP if:** Confirmed as an authorized penetration-testing activity with a documented engagement record — not the case here.

**Alert AE → FP if:** Confirmed as a legitimate application using a non-standard SMTP relay through PowerShell (highly unusual, but theoretically possible with poor coding practices) — not supported by available evidence.

**Alert AD → TP if:** Followed by an actual external RDP connection using the `hp` account.
**Alert AD → FP if:** Confirmed as an intentional, documented remote-work setup by the account owner.

**Alert AF → TP if:** Correlated with additional anti-forensics activity (e.g., log clearing, similar to Case_002's `wevtutil` pattern) in the same session.
**Alert AF → FP if:** Confirmed as a routine NTP synchronization event with no connection to the surrounding suspicious activity.

---

## Recommended Response Actions

- **Alert AC:** Block the source IP; treat as confirmed credential-theft tooling staging; escalate to L2 immediately.
- **Alert AE:** Block outbound to 45.32.99.100; review for any data that may have already been transmitted; escalate to L2.
- **Alert AD:** Monitor for a subsequent external RDP connection using this account; hold at Ambiguous pending that correlation.
- **Alert AF:** Correlate with other log-integrity indicators across the session; hold at Ambiguous, but treat with elevated concern given the confirmed TP alerts in the same timeframe.
- **Session-wide:** Given AC and AE are both confirmed TP, recommend treating this session as a likely active compromise and broadening investigation beyond these four alerts.

---

## Triage Metadata

| Alert | Triage Time |
|---|---|
| Alert AC | 2 minutes (9:08 AM – 9:10 AM) |
| Alert AE | 3 minutes (9:12 AM – 9:15 AM) |
| Alert AD | 3 minutes (9:17 AM – 9:20 AM) |
| Alert AF | 1 minute (9:22 AM – 9:23 AM) |

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Queue Size | 4 alerts |
| Correct Prioritization | Yes |
| Escalated | AC (Yes), AE (Yes) |
| Held for Monitoring | AD, AF |
