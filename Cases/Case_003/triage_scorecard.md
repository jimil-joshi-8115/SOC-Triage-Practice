# 📊 Triage Scorecard

Running performance log across all closed cases in SOC-Triage-Practice.

---

## Summary

| Metric | Value |
|---|---|
| Total Cases Closed | 3 |
| True Positives (TP) | 2 |
| False Positives (FP) | 0 |
| Ambiguous | 1 |
| Correct Verdicts (analyst's final call vs. actual) | 3 / 3 |
| Average Triage Time | 3 minutes (only Case_003 tracked so far) |
| Most Common FP Pattern (so far) | N/A — no FP closed yet |
| Most Missed/Corrected TP Signal (so far) | Assuming "-EncodedCommand present" = FP without decoding the payload first (Case_001) |

---

## Case-by-Case Log

| Case | Verdict | Analyst's Initial Call | Final Call | Match? | Triage Time | Notes |
|---|---|---|---|---|---|---|
| Case_001 | TP | FP (all 3 events) | TP (all 3 events) | ❌ → ✅ (corrected) | Not tracked | Initial FP call was based on "-EncodedCommand is normal" without decoding. After decoding, external IP download (`Net.WebClient.DownloadString`) confirmed malicious pattern. Corrected in real time. |
| Case_002 | TP | TP | TP | ✅ | Not tracked | Correctly identified account-creation command buried among 2 noise `net user` calls. Also surfaced a real detection gap: EventCode 4720 not logging on this host (audit policy), meaning 4688 process monitoring was the only thing that caught this. |
| Case_003 | Ambiguous | Ambiguous | Ambiguous | ✅ | 3 minutes | Correctly resisted forcing a TP verdict despite strong structural indicators (masquerading name, hidden window, SYSTEM privilege, persistence trigger) because the actual payload (`whoami`) was benign. Also surfaced a second logging gap: EventCode 4698 not logging, consistent with the 4720 gap in Case_002 — likely a host-wide audit policy issue. |

---

## Key Lessons Log

Running list of triage lessons learned, to reinforce over time:

1. **Case_001:** The presence of a technique (e.g. `-EncodedCommand`) is never sufficient on its own to call FP. Always decode/inspect the actual payload before ruling out malicious intent.
2. **Case_002:** Don't assume all events at nearly the same timestamp are automated/scripted — distinguish "fast manual typing" (seconds apart, human-plausible) from "millisecond-identical repetition" (Case_001 pattern, scripted). Also: a single missing/empty log source (like 4720) is a detection gap to document, not a reason to downgrade a verdict when other evidence (4688) is solid.
3. **Case_003:** Suspicious *structure/packaging* (masquerading names, hidden windows, SYSTEM privilege, persistence triggers) does not automatically equal TP if the actual payload is benign. Ambiguous is the correct, honest verdict when technique and outcome disagree — don't force a clean TP/FP just to close the ticket faster.

---

## Detection Gaps Identified (Host-Wide)

| EventCode | Purpose | Status | First Seen |
|---|---|---|---|
| 4720 | Account Created | Not logging (0 events) | Case_002 |
| 4698 | Scheduled Task Created | Not logging (0 events) | Case_003 |

**Pattern:** Two separate audit subcategories both showing zero events strongly suggests a host-wide local audit policy gap (not two isolated coincidences). Recommend running `auditpol /get /category:*` on JIMIL-JOSHI to identify the full scope of disabled subcategories.

---

## How This Is Updated

After each case is closed (verdict.md finalized), this file is updated with:
- Running totals (TP/FP/Ambiguous count)
- Analyst's initial call vs. final call (to track accuracy over time)
- Triage time for that case (real, tracked from actual start/end times given by analyst)
- Any new noise pattern or missed signal worth logging
