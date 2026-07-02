# 📊 Triage Scorecard

Running performance log across all closed cases in SOC-Triage-Practice.

---

## Summary

| Metric | Value |
|---|---|
| Total Cases Closed | 2 |
| True Positives (TP) | 2 |
| False Positives (FP) | 0 |
| Ambiguous | 0 |
| Correct Verdicts (analyst's final call vs. actual) | 2 / 2 |
| Average Triage Time | ~13 minutes |
| Most Common FP Pattern (so far) | N/A — no FP closed yet |
| Most Missed/Corrected TP Signal (so far) | Assuming "-EncodedCommand present" = FP without decoding the payload first (Case_001) |

---

## Case-by-Case Log

| Case | Verdict | Analyst's Initial Call | Final Call | Match? | Triage Time | Notes |
|---|---|---|---|---|---|---|
| Case_001 | TP | FP (all 3 events) | TP (all 3 events) | ❌ → ✅ (corrected) | ~11 min | Initial FP call was based on "-EncodedCommand is normal" without decoding. After decoding, external IP download (`Net.WebClient.DownloadString`) confirmed malicious pattern. Corrected in real time. |
| Case_002 | TP | TP | TP | ✅ | ~15 min | Correctly identified account-creation command buried among 2 noise `net user` calls. Also surfaced a real detection gap: EventCode 4720 not logging on this host (audit policy), meaning 4688 process monitoring was the only thing that caught this. |

---

## Key Lessons Log

Running list of triage lessons learned, to reinforce over time:

1. **Case_001:** The presence of a technique (e.g. `-EncodedCommand`) is never sufficient on its own to call FP. Always decode/inspect the actual payload before ruling out malicious intent.
2. **Case_002:** Don't assume all events at nearly the same timestamp are automated/scripted — distinguish "fast manual typing" (seconds apart, human-plausible) from "millisecond-identical repetition" (Case_001 pattern, scripted). Also: a single missing/empty log source (like 4720) is a detection gap to document, not a reason to downgrade a verdict when other evidence (4688) is solid.

---

## How This Is Updated

After each case is closed (verdict.md finalized), this file is updated with:
- Running totals (TP/FP/Ambiguous count)
- Analyst's initial call vs. final call (to track accuracy over time)
- Triage time for that case
- Any new noise pattern or missed signal worth logging
