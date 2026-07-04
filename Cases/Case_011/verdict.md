# Verdict — Case 011 (Phase 2 Batch 3)

## Final Verdicts

| Alert | Verdict | MITRE ATT&CK |
|---|---|---|
| **Alert G** — Set-MpPreference | 🔴 **TP** | T1562.001 — Impair Defenses: Disable or Modify Tools |
| **Alert I** — mshta.exe | 🔴 **TP** | T1218.005 — System Binary Proxy Execution: Mshta |
| **Alert H** — tasklist/lsass | 🟡 **Ambiguous** | T1003.001 (precursor stage) |

---

## Justification Summary

**Alert G (TP):** Disabling Windows Defender's real-time monitoring is an unambiguous defense-evasion action with no legitimate end-user justification. The command content alone is decisive, consistent with how Case_010's `vssadmin` action was evaluated.

**Alert I (TP):** `mshta.exe` executing inline JavaScript via ActiveX is a confirmed LOLBin abuse technique, independent of the specific payload launched. The mechanism itself (trusted-binary code execution bypass) is the basis for TP, not the harmlessness of the demonstration payload (`calc.exe`) — consistent with the reasoning applied to Case_007's registry persistence.

**Alert H (Ambiguous):** Filtering for `lsass.exe` by name is a recognized credential-dumping precursor, but a single query confirms only reconnaissance intent, not execution of an actual dumping tool. The action is genuinely dual-use — legitimate system troubleshooting would produce an identical log entry. Evidence available does not distinguish between the two possibilities.

---

## Prioritization Review

**Chosen order:** G → I → H

**Assessment:** Correctly prioritized defense-evasion (G) ahead of the others, reasoning that disabling security tooling could be a precursor enabling other malicious activity to succeed undetected. This is a sound, transferable prioritization principle — evasion/preparation-stage actions often warrant early attention because they can mask or enable subsequent activity.

---

## What Would Change Each Verdict

**Alert G → FP if:** Confirmed as part of an authorized software installation process that legitimately requires temporary Defender exclusions (documented and time-boxed) — not the case here.

**Alert I → FP if:** Confirmed as part of an authorized internal automation tool using mshta for legitimate scripting purposes (uncommon but possible) — not the case here.

**Alert H → TP if:** Followed by execution of a known credential-dumping tool (e.g., process memory access via a tool like Mimikatz, or a suspicious dump file write) targeting the identified lsass PID.
**Alert H → FP if:** Correlated with a documented IT support ticket for lsass-related performance troubleshooting on this host.

---

## Recommended Response Actions

- **Alert G:** Re-enable Defender real-time monitoring immediately; investigate what activity occurred while protection was disabled.
- **Alert I:** Review for any additional mshta invocations with different (non-calc.exe) payloads; treat as confirmed LOLBin abuse and escalate.
- **Alert H:** Monitor for follow-on process access to lsass.exe or known credential-dumping tool signatures; hold at Ambiguous pending that correlation.

---

## Triage Metadata

| Alert | Triage Time |
|---|---|
| Alert G | 2 minutes (7:37 PM – 7:39 PM) |
| Alert I | 3 minutes (7:43 PM – 7:46 PM) |
| Alert H | 5 minutes (7:51 PM – 7:56 PM) |

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Batch Size | 3 alerts |
| Correct Prioritization | Yes |
| Escalated | Alert G (Yes), Alert I (Yes), Alert H (Hold/Monitor) |
