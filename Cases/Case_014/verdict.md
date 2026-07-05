# Verdict — Case 014 (Phase 2 Batch 6 — Final Phase 2 Batch)

## Final Verdicts

| Alert | Verdict | MITRE ATT&CK |
|---|---|---|
| **Alert R** — New Firewall Rule (Port 4444) | 🔴 **TP** | T1562.004 — Impair Defenses: Disable or Modify System Firewall |
| **Alert Q** — Outlook Spawning PowerShell | 🔴 **TP** | T1204.002, T1059.001 |
| **Alert P** — wmic process call create (whoami) | 🟡 **Ambiguous** | T1047 |

---

## Justification Summary

**Alert R (TP):** Opening inbound access on TCP port 4444 — the default Metasploit listener port — under an innocent-sounding rule name has no legitimate business justification and matches a known backdoor/C2 preparation pattern.

**Alert Q (TP):** The decisive factor is the parent process, not the encoded command content. `OUTLOOK.EXE` spawning `powershell.exe` is an abnormal execution chain with no legitimate explanation, consistent with malicious attachment/macro-triggered execution. This is the inverse case of the "don't over-flag normal parent-child chains" lesson from Case_009/010 — here, the parent itself is the primary red flag precisely because it is abnormal.

**Alert P (Ambiguous):** `wmic process call create` is a recognized lateral-movement technique, but the specific executed action (`whoami` to a local file) carries no malicious outcome on its own. Consistent with the technique-vs-outcome distinction established in Case_003 and Case_011.

---

## Prioritization Review

**Chosen order:** R → Q → P

**Assessment:** Correctly prioritized the standing exposure (open firewall port) first, followed by the likely-active malicious execution chain (Q), with the technique-only/harmless-outcome alert (P) triaged last. Sound reasoning based on persistence-of-risk (R is an ongoing exposure until closed) versus point-in-time actions.

---

## Phase 2 Completion Note

This is the final batch of Phase 2 (Cases 9-14). Across all six batches (18 total alerts in Phase 2), prioritization was correct in 6/6 batches, and individual verdict accuracy reached 18/18 correct after any needed corrections — with Case_012 and Case_013 both requiring zero-to-minimal correction, indicating the recurring early patterns (parent-chain over-flagging, elimination logic, unfamiliarity-based suspicion) identified in Cases 009-011 have been substantially resolved.

---

## What Would Change Each Verdict

**Alert R → FP if:** Confirmed as an authorized, documented firewall change for a legitimate internal service using port 4444 — highly unusual given the port's strong association with known attacker tooling, but theoretically possible with proper change documentation.

**Alert Q → FP if:** Confirmed as a legitimate internal Outlook add-in or automation tool that intentionally invokes PowerShell — uncommon but not impossible in poorly-managed environments; not documented here.

**Alert P → TP if:** Followed by additional wmic-based remote execution targeting other hosts, or if the redirected output were later exfiltrated.
**Alert P → FP if:** Confirmed as routine IT diagnostic/inventory scripting using wmic for legitimate remote administration.

---

## Recommended Response Actions

- **Alert R:** Remove the firewall rule immediately; investigate whether any inbound connections were received on port 4444 while the rule was active.
- **Alert Q:** Treat as a confirmed phishing/malicious-execution incident; review recent email attachments/links opened by this account; escalate to L2.
- **Alert P:** Monitor for additional wmic-based execution across the environment; hold at Ambiguous pending correlation.
- **Cross-case note:** The recurring logging gap (now 4720, 4698, 4732, and 4947) should be escalated as a dedicated host-wide audit policy review, separate from any individual case.

---

## Triage Metadata

| Alert | Triage Time |
|---|---|
| Alert R | 1 minute (10:48 AM – 10:49 AM) |
| Alert Q | 2 minutes (10:58 AM – 11:00 AM) |
| Alert P | 2 minutes (11:08 AM – 11:10 AM) |

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Batch Size | 3 alerts |
| Correct Prioritization | Yes |
| Escalated | Alert R (Yes), Alert Q (Yes), Alert P (Hold/Monitor) |
