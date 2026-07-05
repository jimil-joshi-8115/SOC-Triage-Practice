# Verdict — Case 012 (Phase 2 Batch 4)

## Final Verdicts

| Alert | Verdict | MITRE ATT&CK |
|---|---|---|
| **Alert K** — PowerShell IEX Download-and-Execute | 🔴 **TP** | T1059.001, T1105 |
| **Alert J** — New Admin Group Member | 🔴 **TP** | T1098, T1136 |
| **Alert L** — Outbound RDP to External IP | 🟡 **Ambiguous** | — |

---

## Justification Summary

**Alert K (TP):** `IEX(New-Object Net.WebClient).DownloadString(...)` achieves fileless remote code execution — script content is downloaded and executed directly in memory, evading disk-based detection. The destination is a public IP with no legitimate business justification. Decisive on command content alone.

**Alert J (TP):** Adding a non-baseline, service-like-named account (`hpbackup`) to the local Administrators group is a completed, unambiguous privilege escalation action. Consistent with the reasoning applied in Case_002 and Case_007 — a completed account/privilege action does not require further confirming events to establish TP.

**Alert L (Ambiguous):** Outbound RDP connections are genuinely dual-use — legitimate remote administration and attacker lateral movement/data staging produce identical log signatures at this visibility level. No confirmed malicious outcome (successful connection, follow-on activity, or destination reputation) is present in the available evidence.

---

## Prioritization Review

**Chosen order:** K → J → L

**Assessment:** Correctly prioritized based on active-execution urgency (K, code currently executing) over a completed-but-serious privilege escalation (J), with the genuinely ambiguous item (L) triaged last. This reflects sound reasoning about relative urgency, not just severity labels.

---

## What Would Change Each Verdict

**Alert K → FP if:** Confirmed as part of an authorized internal deployment script using this exact download pattern with a documented, trusted destination — not the case here.

**Alert J → FP if:** `hpbackup` were documented as an authorized, intentionally-elevated service account in `Noise-Baselines/known_legitimate_accounts.md` — not currently documented.

**Alert L → TP if:** The destination were confirmed as known malicious infrastructure, or correlated with data staging/exfiltration activity following the connection.
**Alert L → FP if:** The connection were confirmed as a routine, authorized remote administration session with a documented business justification.

---

## Recommended Response Actions

- **Alert K:** Block outbound to `45.142.212.61`; retrieve and analyze `s.ps1` if downloaded; escalate to L2 immediately.
- **Alert J:** Remove `hpbackup` from local Administrators immediately; investigate account creation timeline (correlates with Case_002's `hpbackup` account creation).
- **Alert L:** Review RDP connection logs for destination reputation and session duration; hold at Ambiguous pending further correlation.
- **Cross-case note:** The 4732 confirmation gap observed here adds to a pattern (alongside 4720 and 4698 gaps from earlier cases) suggesting a broader host-wide audit policy issue warranting a dedicated review.

---

## Triage Metadata

| Alert | Triage Time |
|---|---|
| Alert K | 2 minutes (8:10 AM – 8:12 AM) |
| Alert J | 2 minutes (8:15 AM – 8:17 AM) |
| Alert L | 2 minutes (8:20 AM – 8:22 AM) |

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Batch Size | 3 alerts |
| Correct Prioritization | Yes |
| Escalated | Alert K (Yes), Alert J (Yes), Alert L (Hold/Review) |
