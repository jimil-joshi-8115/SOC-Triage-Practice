# 📊 Triage Scorecard

Running performance log across all closed cases in SOC-Triage-Practice.

---

## Summary

| Metric | Value |
|---|---|
| Total Cases Closed | 11 (17 individual alerts triaged) |
| True Positives (TP) | 10 |
| False Positives (FP) | 2 |
| Ambiguous | 5 |
| Correct Verdicts (analyst's final call vs. actual) | 17 / 17 |
| Average Triage Time | ~3.2 minutes per alert |
| Most Common FP Pattern (so far) | rundll32.exe + PcaSvc.dll,PcaPatchSdbTask (Windows PCA) |
| **Phase 1 Status** | ✅ Complete (Cases 5-8) |
| **Phase 2 Status** | 🔄 In Progress (Cases 9-11 done, 12-14 remaining) |

---

## Case-by-Case Log

| Case | Verdict | Analyst's Initial Call | Final Call | Match? | Triage Time | Notes |
|---|---|---|---|---|---|---|
| Case_001 | TP | FP | TP | ❌ → ✅ (corrected) | Not tracked | Initial FP call based on "-EncodedCommand is normal" without decoding. Corrected after decoding revealed external IP download. |
| Case_002 | TP | TP | TP | ✅ | Not tracked | Correctly separated signal from noise across 3 `net.exe` events; surfaced 4720 logging gap. |
| Case_003 | Ambiguous | Ambiguous | Ambiguous | ✅ | 3 minutes | Correctly resisted forcing TP despite strong structural indicators, since payload (`whoami`) was benign. |
| Case_004 | FP | FP | FP | ✅ | 2 minutes | Matched documented baseline (Windows PCA), closed efficiently. |
| Case_005 | TP | TP | TP | ✅ | 4 minutes | First unhinted case; two early missteps self-corrected via follow-up checks. |
| Case_006 | TP | Ambiguous | TP | ✅ (terminology fix) | 4 minutes | Correctly identified password-spray pattern; corrected verdict-category terminology. |
| Case_007 | TP | TP | TP | ✅ | 3 minutes | Independently identified registry persistence. |
| Case_008 | TP | TP | TP | ✅ | 2 minutes | Independently identified LOLBin abuse. |
| Case_009 (Alert B) | TP | TP | TP | ✅ | 3 minutes | Correct prioritization and verdict. |
| Case_009 (Alert C) | Ambiguous | TP | Ambiguous | ✅ | 5 minutes | Corrected after recognizing normal parent-child chain was over-weighted. |
| Case_009 (Alert A) | FP | TP | FP | ✅ | 2 minutes | Corrected after recognizing normal parent-child chain was over-weighted. |
| Case_010 (Alert E) | TP | TP | TP | ✅ | 2 minutes | Correctly identified destructive/irreversible action without over-analyzing parent process. |
| Case_010 (Alert F) | Ambiguous | Ambiguous | Ambiguous | ✅ | 2 minutes | Correct verdict; justification approach refined toward affirmative reasoning. |
| Case_010 (Alert D) | Ambiguous | Ambiguous | Ambiguous | ✅ | 4 minutes | Correctly factored in RDP logon-type context. |
| Case_011 (Alert G) | TP | TP | TP | ✅ | 2 minutes | Correctly identified Defender-disable as decisive on command content alone; no longer flagged cmd.exe parent as suspicious. |
| Case_011 (Alert I) | TP | TP | TP | ✅ | 3 minutes | Correctly identified mshta LOLBin abuse; correctly reasoned that the technique (not the harmless demo payload) drives the TP verdict. |
| Case_011 (Alert H) | Ambiguous | FP (initial) → Ambiguous | Ambiguous | ✅ (corrected) | 5 minutes | Initially misjudged lsass as suspicious due to unfamiliarity rather than its role as a credential-dumping precursor target; corrected to Ambiguous with proper reasoning after guidance — single query confirms recon only, not execution of a dumping tool. |

---

## Key Lessons Log

1. **Case_001:** Decode/inspect payloads before ruling out malicious intent based on technique alone.
2. **Case_002:** Distinguish scripted repetition from manual rapid typing. Missing logs are gaps to document, not reasons to downgrade a verdict.
3. **Case_003:** Suspicious structure ≠ automatic TP if payload is benign.
4. **Case_004:** Baseline matches still deserve a quick secondary-indicator sanity check.
5. **Case_005:** A known/valid account being targeted is not reassuring. Failed attempts are still TP-worthy.
6. **Case_006:** "Needs escalation" ≠ "Ambiguous." These are separate concepts.
7. **Case_007:** Completed persistence actions are TP even with benign current payloads.
8. **Case_008:** LOLBin abuse is a recurring real-world pattern worth specifically checking for.
9. **Case_009:** Common parent-child chains (`cmd→powershell`, `cmd→nslookup`) are not inherently suspicious.
10. **Case_010:** (a) Destructive/irreversible commands can be confirmed TP from content alone. (b) Verdicts need positive, affirmative justification, not elimination logic. (c) Same command, different risk depending on session context (RDP vs. local).
11. **Case_011:** (a) A confirmed technique (e.g. mshta LOLBin execution) is TP regardless of how harmless the demonstration payload is — the mechanism itself is the evidence. (b) A process being unfamiliar (e.g. `lsass.exe`) is not the reason for suspicion — the reason is what checking for it by name typically precedes (credential dumping). Suspicion should be grounded in known attacker tradecraft, not unfamiliarity with legitimate system processes.

---

## Phase 2 Progress (Cases 9-14)

**Prioritization accuracy:** 3/3 batches correctly prioritized by actual risk/impact (Case_009: B→C→A, Case_010: E→F→D, Case_011: G→I→H).

**Individual verdict accuracy:** 10/10 correct after corrections across three batches. Recurring root causes addressed so far:
- Over-flagging normal parent-child process chains — resolved by Case_011 (no longer appearing).
- Evaluating commands without session/logon context — resolved in Case_010.
- Elimination-based reasoning instead of affirmative justification — improving; still appeared briefly in Case_011 (Alert I, H) before being corrected each time.
- Misjudging system processes as suspicious due to unfamiliarity rather than known attacker use — newly identified in Case_011 (Alert H), to be watched in Case_012 onward.

---

## How This Is Updated

After each case is closed (verdict.md finalized), this file is updated with running totals, analyst's initial call vs. final call, triage time, and any new pattern or missed signal worth logging.
