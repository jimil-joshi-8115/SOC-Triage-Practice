# Verdict — Case 015 (Phase 3: Full Queue Simulation)

## Final Verdicts

| Alert | Verdict | MITRE ATT&CK |
|---|---|---|
| **Alert T** — Scheduled Task (AdobeUpdateSvc) | 🔴 **TP** | T1053.005 |
| **Alert W** — Defender Disable (mid-queue interrupt) | 🔴 **TP** | T1562.001 |
| **Alert U** — DNS Varying Subdomains | 🟡 **Ambiguous** | T1071.004/T1568 |
| **Alert S** — Failed Logon x2 | 🟡 **Ambiguous** | — |
| **Alert V** — USB Connected | 🟡 **Ambiguous** | T1052 |

---

## Justification Summary

**Alert T (TP):** Masquerading task name, SYSTEM privilege, and off-hours daily persistence trigger form a decisive combination independent of the encoded payload's specific content.

**Alert W (TP):** Disabling Defender real-time protection is decisive on command content alone, with no legitimate end-user use case.

**Alert U (Ambiguous):** Varying-subdomain DNS querying is a stronger structural match to known DGA/C2 tradecraft than simple repeated queries (Case_009), but no resolved IP reputation or follow-up connection confirms a malicious outcome.

**Alert S (Ambiguous):** A 2-attempt failed logon volume is insufficient to confidently confirm either a brute-force attempt (compare Case_005's 5-attempt TP) or dismiss it as routine user error.

**Alert V (Ambiguous):** No baseline exists for authorized USB usage on this host, and no follow-up activity (file access/copy) is available to confirm or rule out exfiltration intent. Business-hours timing does not establish legitimacy on its own.

---

## Queue Management Review

**Initial prioritization:** T → U → S → V — correctly ranked by combined severity/persistence factors rather than blind label-following.

**Mid-investigation interrupt handling:** Upon Alert W's arrival (🔴 High, active defense-evasion), the analyst correctly chose to interrupt in-progress work on Alert T to address W immediately, then resumed the original queue. This reflects sound real-world triage judgment — an active evasion action can mask or enable other malicious activity, including activity connected to items already in progress, and generally outranks continuing non-time-critical investigation.

**Final effective order:** T → W → U → S → V.

---

## What Would Change Each Verdict

**Alert T → FP if:** Confirmed as an authorized internal task deployment with proper naming and change documentation — not the case here.

**Alert W → FP if:** Confirmed as part of an authorized software installation requiring a temporary, documented Defender exclusion — not the case here.

**Alert U → TP if:** One or more subdomains resolved to known malicious infrastructure, or a follow-on outbound connection was observed.
**Alert U → FP if:** The domain were confirmed as a legitimate CDN/analytics service used by installed applications.

**Alert S → TP if:** Additional failed attempts followed, reaching a volume consistent with Case_005's pattern, or if a successful logon followed under suspicious circumstances.
**Alert S → FP if:** The account owner confirms this was their own mistyped password with no further attempts.

**Alert V → TP if:** File-copy or data-staging activity is observed following the connection, or the device is identified as unauthorized/unknown hardware.
**Alert V → FP if:** The device is confirmed as a known, authorized personal or IT-issued device per policy.

---

## Recommended Response Actions

- **Alert T:** Remove the scheduled task immediately; retrieve and analyze the encoded PowerShell payload; escalate to L2.
- **Alert W:** Re-enable Defender; review activity during the disabled window, particularly in connection with Alert T.
- **Alert U:** Perform DNS/passive reputation lookups on the queried subdomains; monitor for follow-on connections; hold at Ambiguous.
- **Alert S:** Monitor for additional failed attempts against this account; hold at Ambiguous pending further activity.
- **Alert V:** Review for file access/copy activity on drive E: following the connection; establish a USB-usage baseline for this host going forward; hold at Ambiguous.

---

## Shift Handoff Summary

> Queue of 4 alerts opened this shift, plus 1 mid-shift arrival (5 total). Closed as TP: Alert T (scheduled task persistence) and Alert W (Defender disable), both escalated to L2 — W was handled ahead of schedule due to its potential to mask other activity, including Alert T. Alerts U (DNS pattern), S (failed logons), and V (USB connection) held as Ambiguous pending further correlation (DNS reputation, additional logon activity, and file-access review respectively) — none dismissed, all flagged for continued monitoring. No alerts remain unopened at end of shift.

---

## Triage Metadata

| Alert | Triage Time |
|---|---|
| Alert T | 2 minutes (2:52 PM – 2:54 PM) |
| Alert W | 2 minutes (2:56 PM – 2:58 PM) |
| Alert U | 4 minutes (3:00 PM – 3:04 PM) |
| Alert S | 2 minutes (3:05 PM – 3:07 PM) |
| Alert V | 3 minutes (3:07 PM – 3:10 PM) |

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Queue Size | 5 alerts (4 initial + 1 mid-shift) |
| Correct Initial Prioritization | Yes |
| Correct Interrupt Handling | Yes |
| Alerts Escalated | T, W |
| Alerts Held for Monitoring | U, S, V |
