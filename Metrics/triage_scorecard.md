# 📊 Triage Scorecard

Running performance log across all closed cases in SOC-Triage-Practice.

---

## Summary

| Metric | Value |
|---|---|
| Total Cases Closed | 10 (14 individual alerts triaged) |
| True Positives (TP) | 8 |
| False Positives (FP) | 2 |
| Ambiguous | 4 |
| Correct Verdicts (analyst's final call vs. actual) | 14 / 14 |
| Average Triage Time | ~3.2 minutes per alert |
| Most Common FP Pattern (so far) | rundll32.exe + PcaSvc.dll,PcaPatchSdbTask (Windows PCA) |
| **Phase 1 Status** | ✅ Complete (Cases 5-8) |
| **Phase 2 Status** | 🔄 In Progress (Cases 9-10 done, 11-14 remaining) |

---

## Case-by-Case Log

| Case | Verdict | Analyst's Initial Call | Final Call | Match? | Triage Time | Notes |
|---|---|---|---|---|---|---|
| Case_001 | TP | FP | TP | ❌ → ✅ (corrected) | Not tracked | Initial FP call based on "-EncodedCommand is normal" without decoding. Corrected after decoding revealed external IP download. |
| Case_002 | TP | TP | TP | ✅ | Not tracked | Correctly separated signal from noise across 3 `net.exe` events; surfaced 4720 logging gap. |
| Case_003 | Ambiguous | Ambiguous | Ambiguous | ✅ | 3 minutes | Correctly resisted forcing TP despite strong structural indicators, since payload (`whoami`) was benign. |
| Case_004 | FP | FP | FP | ✅ | 2 minutes | Matched documented baseline (Windows PCA), closed efficiently. |
| Case_005 | TP | TP | TP | ✅ | 4 minutes | First unhinted case; two early missteps (failure-reason misread, timing misjudgment) self-corrected via follow-up checks. |
| Case_006 | TP | Ambiguous | TP | ✅ (terminology fix) | 4 minutes | Correctly identified password-spray pattern, initially mislabeled verdict category; corrected — escalation ≠ Ambiguous. |
| Case_007 | TP | TP | TP | ✅ | 3 minutes | Independently identified registry persistence; correctly distinguished from Case_003's Ambiguous pattern. |
| Case_008 | TP | TP | TP | ✅ | 2 minutes | Independently identified LOLBin abuse; fastest clean Phase 1 case. |
| Case_009 (Alert B) | TP | TP | TP | ✅ | 3 minutes | Correct prioritization (SYSTEM+Temp path reasoning); correct verdict. |
| Case_009 (Alert C) | Ambiguous | TP | Ambiguous | ❌ → ✅ (corrected) | 5 minutes | Over-weighted normal `cmd→nslookup` parent chain; corrected — no confirmed malicious outcome present. |
| Case_009 (Alert A) | FP | TP | FP | ❌ → ✅ (corrected) | 2 minutes | Over-weighted normal `cmd→powershell` parent chain; corrected — single visible command, no aggravating factors. |
| Case_010 (Alert E) | TP | TP | TP | ✅ | 2 minutes | Correctly identified destructive/irreversible action (vssadmin) without over-analyzing parent process. |
| Case_010 (Alert F) | Ambiguous | Ambiguous | Ambiguous | ✅ | 2 minutes | Correct verdict. Justification approach flagged for improvement — lean on positive, affirmative reasoning (why the evidence fits Ambiguous) rather than elimination logic. |
| Case_010 (Alert D) | Ambiguous | Ambiguous | Ambiguous | ✅ | 4 minutes | Correctly factored in the RDP (RemoteInteractive) logon-type context — same command carries different risk depending on session context. |

---

## Key Lessons Log

1. **Case_001:** Decode/inspect payloads before ruling out malicious intent based on technique alone.
2. **Case_002:** Distinguish scripted repetition from manual rapid typing. Missing logs are gaps to document, not reasons to downgrade a verdict.
3. **Case_003:** Suspicious structure ≠ automatic TP if payload is benign. Ambiguous is the honest call when technique and outcome disagree.
4. **Case_004:** Baseline matches still deserve a quick secondary-indicator sanity check.
5. **Case_005:** A known/valid account being targeted is not reassuring. Failed attempts are still TP-worthy behavior.
6. **Case_006:** "Needs escalation" ≠ "Ambiguous." Escalation is a response action; verdict category is separate.
7. **Case_007:** Completed persistence actions (registry writes) are TP even with benign current payloads, unlike pending/unconfirmed triggers (Case_003).
8. **Case_008:** LOLBin abuse (trusted binaries misused) is a recurring real-world pattern worth specifically checking for.
9. **Case_009:** Common parent-child chains (`cmd→powershell`, `cmd→nslookup`) are not inherently suspicious — this was over-flagged twice in one batch and is the primary habit to break.
10. **Case_010:** (a) Destructive/irreversible commands (e.g. `vssadmin delete shadows`) can be confirmed TP from the command content alone, without needing extensive context-gathering. (b) Verdicts should rest on positive, affirmative justification — explaining why the evidence fits a verdict — rather than elimination logic ("it's not X or Y, so it must be Z"), which won't hold up under scrutiny. (c) The same command (`whoami`) carries different risk depending on session context (RDP vs. local) — always check logon type/session context before dismissing a command as routine.

---

## Phase 2 Progress (Cases 9-14)

**Prioritization accuracy:** 2/2 batches correctly prioritized by actual risk/impact rather than blind label-following (Case_009: B→C→A: Case_010: E→F→D).

**Individual verdict accuracy:** 7/7 correct after corrections across both batches, but 4 of 7 required a correction before landing on the final verdict. Recurring root causes:
- Over-flagging normal parent-child process chains (Case_009 x2)
- Evaluating commands in isolation without checking session/logon context (Case_010, Alert D)
- Elimination-based reasoning instead of affirmative justification (Case_010, Alert F)

These three patterns are the explicit focus for Case_011 onward.

---

## How This Is Updated

After each case is closed (verdict.md finalized), this file is updated with running totals, analyst's initial call vs. final call, triage time, and any new pattern or missed signal worth logging.
