# Verdict — Case 013 (Phase 2 Batch 5)

## Final Verdicts

| Alert | Verdict | MITRE ATT&CK |
|---|---|---|
| **Alert M** — ScriptBlock Logging Disabled | 🔴 **TP** | T1562 — Impair Defenses |
| **Alert N** — ntds.dit Copy Attempt | 🔴 **TP** | T1003.003 — OS Credential Dumping: NTDS |
| **Alert O** — 3:14 AM Interactive Logon | 🟡 **Ambiguous** | T1078 (related — unusual usage pattern) |

---

## Justification Summary

**Alert M (TP):** Disabling PowerShell ScriptBlock logging via registry removes future investigative visibility into script execution, a defense-evasion action with no legitimate end-user justification. Decisive on command content alone.

**Alert N (TP):** Attempting to copy `ntds.dit` — the Active Directory credential database — into a disguised Temp-folder location is a clear credential-theft technique (T1003.003), regardless of whether the target file exists in meaningful form on this non-Domain-Controller host. The attempt itself, not its technical success, establishes intent — consistent with how Case_005's unsuccessful brute-force attempts were still evaluated as TP.

**Alert O (Ambiguous):** Unusual-hour interactive logon (3:14 AM, Type 2) is a real, worth-documenting indicator, but the Interactive logon type confirms physical presence at the machine (ruling out remote/network-based unauthorized access) and no baseline exists to establish whether this timing is actually abnormal for this account. Evidence supports neither a confident TP nor a clean FP dismissal.

---

## Prioritization Review

**Chosen order:** M → N → O

**Assessment:** Correctly prioritized the defense-evasion action (M) first, reasoning that it could mask subsequent activity — consistent with the prioritization principle established in Case_011. N was appropriately checked next given its severity (credential-theft-adjacent), with the genuinely ambiguous timing-based alert (O) triaged last without being dismissed.

---

## What Would Change Each Verdict

**Alert M → FP if:** Confirmed as part of an authorized security-tooling configuration change with a documented change record — not the case here.

**Alert N → FP if:** Confirmed as an authorized, scheduled backup process on a genuine Domain Controller with proper access controls — not applicable to this host's role.

**Alert O → TP if:** Correlated with other suspicious activity in the same session, or if a baseline later established that `hp` never logs in outside standard hours.
**Alert O → FP if:** The account owner confirms this was legitimate personal activity (e.g., working late, timezone difference) with no other correlating suspicious indicators.

---

## Recommended Response Actions

- **Alert M:** Re-enable ScriptBlock logging immediately; review any PowerShell activity that may have occurred while logging was disabled.
- **Alert N:** Treat as a confirmed credential-theft attempt regardless of technical success; escalate to L2; investigate what other actions occurred in the same session.
- **Alert O:** Establish a baseline of `hp`'s normal login hours going forward; hold at Ambiguous pending correlation with other session activity.

---

## Triage Metadata

| Alert | Triage Time |
|---|---|
| Alert M | 1 minute (10:21 AM – 10:22 AM) |
| Alert N | 3 minutes (10:27 AM – 10:30 AM) |
| Alert O | 2 minutes (10:30 AM – 10:32 AM) |

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Batch Size | 3 alerts |
| Correct Prioritization | Yes |
| Escalated | Alert M (Yes), Alert N (Yes), Alert O (Hold/Monitor) |
