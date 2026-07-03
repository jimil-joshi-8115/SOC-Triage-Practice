# 📊 Triage Scorecard

Running performance log across all closed cases in SOC-Triage-Practice.

---

## Summary

| Metric | Value |
|---|---|
| Total Cases Closed | 6 |
| True Positives (TP) | 4 |
| False Positives (FP) | 1 |
| Ambiguous | 1 |
| Correct Verdicts (analyst's final call vs. actual) | 6 / 6 |
| Average Triage Time | ~3.25 minutes (Case_003: 3 min, Case_004: 2 min, Case_005: 4 min, Case_006: 4 min) |
| Most Common FP Pattern (so far) | rundll32.exe + PcaSvc.dll,PcaPatchSdbTask (Windows PCA) |
| Most Missed/Corrected TP Signal (so far) | Assuming "-EncodedCommand present" = FP without decoding the payload first (Case_001) |

---

## Case-by-Case Log

| Case | Verdict | Analyst's Initial Call | Final Call | Match? | Triage Time | Notes |
|---|---|---|---|---|---|---|
| Case_001 | TP | FP (all 3 events) | TP (all 3 events) | ❌ → ✅ (corrected) | Not tracked | Initial FP call was based on "-EncodedCommand is normal" without decoding. After decoding, external IP download (`Net.WebClient.DownloadString`) confirmed malicious pattern. Corrected in real time. |
| Case_002 | TP | TP | TP | ✅ | Not tracked | Correctly identified account-creation command buried among 2 noise `net user` calls. Also surfaced a real detection gap: EventCode 4720 not logging on this host (audit policy), meaning 4688 process monitoring was the only thing that caught this. |
| Case_003 | Ambiguous | Ambiguous | Ambiguous | ✅ | 3 minutes | Correctly resisted forcing a TP verdict despite strong structural indicators (masquerading name, hidden window, SYSTEM privilege, persistence trigger) because the actual payload (`whoami`) was benign. Also surfaced a second logging gap: EventCode 4698 not logging, consistent with the 4720 gap in Case_002 — likely a host-wide audit policy issue. |
| Case_004 | FP | FP | FP | ✅ | 2 minutes | Correctly matched command line against documented Noise-Baselines entry (Windows PCA) and closed quickly without over-escalating a known-benign pattern. |
| Case_005 | TP | TP | TP | ✅ | 4 minutes | First Phase 1 case (no checklist hints given). Reasoning had two early missteps corrected before final verdict: (1) misread "Unknown user name or bad password" as confirming an invalid username, and (2) treated rapid repeated failures against a known account as reassuring rather than a brute-force signal. Corrected after re-running follow-up checks (4624/4740) independently. Also surfaced a secondary finding: no account lockout policy triggered after 5 failures. |
| Case_006 | TP | Ambiguous | TP | ✅ (terminology correction) | 4 minutes | Correctly identified password-spray pattern (multiple distinct accounts, none in baseline, ~35 sec window) as suspicious, but initially mislabeled it "Ambiguous" due to conflating "needs L2 escalation" with the Ambiguous verdict category. Corrected: escalation is a response action, not a verdict downgrade — Ambiguous is reserved for cases where evidence itself cannot distinguish intent (see Case_003). |

---

## Key Lessons Log

Running list of triage lessons learned, to reinforce over time:

1. **Case_001:** The presence of a technique (e.g. `-EncodedCommand`) is never sufficient on its own to call FP. Always decode/inspect the actual payload before ruling out malicious intent.
2. **Case_002:** Don't assume all events at nearly the same timestamp are automated/scripted — distinguish "fast manual typing" (seconds apart, human-plausible) from "millisecond-identical repetition" (Case_001 pattern, scripted). Also: a single missing/empty log source (like 4720) is a detection gap to document, not a reason to downgrade a verdict when other evidence (4688) is solid.
3. **Case_003:** Suspicious *structure/packaging* (masquerading names, hidden windows, SYSTEM privilege, persistence triggers) does not automatically equal TP if the actual payload is benign. Ambiguous is the correct, honest verdict when technique and outcome disagree — don't force a clean TP/FP just to close the ticket faster.
4. **Case_004:** A documented baseline match speeds up triage significantly, but should still be sanity-checked against a quick secondary indicator pass (path, network, account, timing) to avoid confirmation bias — an attacker could theoretically reuse a known-benign DLL/function name to blend in.
5. **Case_005:** A known/valid account being targeted is not reassuring — it can mean the attacker already has a valid username and only needs the password, which is a narrower and often more dangerous scenario than random guessing. Also: "it didn't succeed" does not mean "not a TP" — a failed brute-force attempt is still malicious behavior worth escalating. Generic Windows failure messages ("Unknown user name or bad password") must not be over-interpreted as confirming which part failed.
6. **Case_006:** "Needs escalation to L2" is not the same as "Ambiguous." A confirmed TP is still TP even when it requires further handling — Ambiguous is reserved specifically for cases where the evidence cannot itself distinguish malicious from benign intent. Also: multiple distinct accounts attempted rapidly = password spraying (T1110.003), a distinct technique from single-account brute-force (T1110, Case_005).

---

## How This Is Updated

After each case is closed (verdict.md finalized), this file is updated with:
- Running totals (TP/FP/Ambiguous count)
- Analyst's initial call vs. final call (to track accuracy over time)
- Triage time for that case (real, tracked from actual start/end times given by analyst)
- Any new noise pattern or missed signal worth logging
