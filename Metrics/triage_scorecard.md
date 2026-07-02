# 📊 Triage Scorecard

Running performance log across all closed cases in SOC-Triage-Practice.

---

## Summary

| Metric | Value |
|---|---|
| Total Cases Closed | 1 |
| True Positives (TP) | 1 |
| False Positives (FP) | 0 |
| Ambiguous | 0 |
| Correct Verdicts (analyst vs. final) | 1 / 1 (after correction) |
| Average Triage Time | ~11 minutes |
| Most Common FP Pattern (so far) | N/A — no FP closed yet |
| Most Missed TP Signal (so far) | Assuming "-EncodedCommand present" = FP without decoding the payload first |

---

## Case-by-Case Log

| Case | Verdict | Analyst's Initial Call | Final Call | Match? | Triage Time | Notes |
|---|---|---|---|---|---|---|
| Case_001 | TP | FP (all 3 events) | TP (all 3 events) | ❌ → ✅ (corrected) | ~11 min | Initial FP call was based on "-EncodedCommand is normal" without decoding. After decoding, external IP download (`Net.WebClient.DownloadString`) confirmed malicious pattern. Corrected in real time. |

---

## Key Lessons Log

Running list of triage lessons learned, to reinforce over time:

1. **Case_001:** The presence of a technique (e.g. `-EncodedCommand`) is never sufficient on its own to call FP. Always decode/inspect the actual payload before ruling out malicious intent.

---

## How This Is Updated

After each case is closed (verdict.md finalized), this file is updated with:
- Running totals (TP/FP/Ambiguous count)
- Analyst's initial call vs. final call (to track accuracy over time)
- Triage time for that case
- Any new noise pattern or missed signal worth logging
