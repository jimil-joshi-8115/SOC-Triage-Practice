# Verdict — Case 016 (Phase 3: 5-Alert Queue, Mixed Format)

## Final Verdicts

| Alert | Verdict | MITRE ATT&CK |
|---|---|---|
| **Alert Z** — PowerShell Download to Startup Folder | 🔴 **TP** | T1105, T1547.001 |
| **Alert Y** — Process Injection (EDR) | 🔴 **TP** | T1055 |
| **Alert AA** — RDP Brute Force (External) | 🔴 **TP** | T1110 |
| **Alert X** — Firewall Block Rule | 🟢 **FP** | — |
| **Alert AB** — Print Spooler Restart | 🟢 **FP** | — |

---

## Justification Summary

**Alert Z (TP):** Raw external IP download combined with Startup-folder placement confirms both active malware delivery and immediate persistence — decisive on command content alone.

**Alert Y (TP):** A confirmed EDR detection of process injection into `explorer.exe` is direct evidence of the technique occurring, not merely an attempted or theoretically-available action — no benign specific-outcome exists to weigh against it, unlike prior technique-vs-outcome Ambiguous cases.

**Alert AA (TP):** High-volume, tightly-timed, single-target RDP brute-force from an external IP demonstrates active external attack surface exposure, more severe than prior internal brute-force cases (Case_005/006) due to the external origin and high-value target account.

**Alert X (FP):** The rule blocks (not allows) outbound traffic to a named malicious IP — defensive action, not an attack. Firewall rule verdicts depend on direction and action type, not the mere presence of a suspicious-sounding label in the rule name.

**Alert AB (FP):** A routine, well-documented service restart with no aggravating factors — masquerading name, unusual account, unusual timing, or chained suspicious activity are all absent.

---

## Prioritization Review

**Chosen order:** Z → Y → AA → X → AB

**Assessment:** Correctly prioritized the two actively-executing malicious techniques (Z, Y) ahead of a completed-but-serious external attack attempt (AA), with the two events requiring context-dependent judgment (X: direction matters; AB: routine service event) correctly placed last without being pre-judged by their alert names or Info-level labels.

---

## Cross-Case Note: Firewall Rule Direction

This case reinforces a distinction first raised by comparison to Case_012's Alert R: firewall rule alerts must always be evaluated by **direction (in/out) and action (allow/block)** together, not by the rule name or target IP alone. An `allow` rule opening inbound access on a suspicious port (Case_012) and a `block` rule closing outbound access to a named-malicious IP (this case) can superficially resemble each other in a queue view but represent opposite realities.

---

## Recommended Response Actions

- **Alert Z:** Remove the downloaded file from Startup immediately; block the source IP; escalate to L2.
- **Alert Y:** Treat as an active, in-progress compromise; isolate the host if possible; escalate immediately.
- **Alert AA:** Block the external source IP at the firewall/edge if not already restricted; review RDP exposure (consider disabling if not required, or enforcing MFA/VPN-only access).
- **Alert X:** No action required; confirm this rule aligns with an existing incident response action if one is in progress.
- **Alert AB:** No action required; close as routine.

---

## Triage Metadata

| Alert | Triage Time |
|---|---|
| Alert Z | 3 minutes (8:02 AM – 8:05 AM) |
| Alert Y | 2 minutes (8:06 AM – 8:08 AM) |
| Alert AA | 2 minutes (8:10 AM – 8:12 AM) |
| Alert X | 1 minute (8:15 AM – 8:16 AM) |
| Alert AB | 1 minute (8:18 AM – 8:19 AM) |

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Queue Size | 5 alerts |
| Correct Prioritization | Yes |
| Escalated | Z (Yes), Y (Yes, immediate), AA (Yes) |
| Closed, No Action | X, AB |
