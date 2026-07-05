# 📊 Triage Scorecard

Running performance log across all closed cases in SOC-Triage-Practice.

---

## Summary

| Metric | Value |
|---|---|
| Total Cases Closed | 15 (31 individual alerts triaged) |
| True Positives (TP) | 18 |
| False Positives (FP) | 2 |
| Ambiguous | 11 |
| Correct Verdicts (analyst's final call vs. actual) | 31 / 31 |
| Average Triage Time | ~2.8 minutes per alert |
| Most Common FP Pattern (so far) | rundll32.exe + PcaSvc.dll,PcaPatchSdbTask (Windows PCA) |
| **Phase 1 Status** | ✅ Complete (Cases 5-8) |
| **Phase 2 Status** | ✅ Complete (Cases 9-14) |
| **Phase 3 Status** | 🔄 In Progress (Case 15 done, 16-20 remaining) |

---

## Case-by-Case Log (Full History — Cases 001-015)

| Case | Verdict | Analyst's Initial Call | Final Call | Match? | Triage Time | Notes |
|---|---|---|---|---|---|---|
| Case_001 | TP | FP | TP | ✅ (corrected) | Not tracked | Initial FP call based on "-EncodedCommand is normal" without decoding. Corrected after decoding revealed external IP download (`Net.WebClient.DownloadString`). |
| Case_002 | TP | TP | TP | ✅ | Not tracked | Correctly separated signal from noise across 3 `net.exe` events; surfaced 4720 logging gap. |
| Case_003 | Ambiguous | Ambiguous | Ambiguous | ✅ | 3 minutes | Correctly resisted forcing TP despite strong structural indicators, since payload (`whoami`) was benign. Surfaced 4698 logging gap. |
| Case_004 | FP | FP | FP | ✅ | 2 minutes | Matched documented Noise-Baselines entry (Windows PCA), closed efficiently without over-escalating. |
| Case_005 | TP | TP | TP | ✅ | 4 minutes | First unhinted case; two early missteps (failure-reason misread, timing misjudgment) self-corrected via independent follow-up checks. |
| Case_006 | TP | Ambiguous | TP | ✅ (terminology fix) | 4 minutes | Correctly identified password-spray pattern; initially mislabeled verdict category — corrected: escalation ≠ Ambiguous. |
| Case_007 | TP | TP | TP | ✅ | 3 minutes | Independently identified registry Run key persistence; correctly distinguished from Case_003's Ambiguous pattern (completed action vs. pending trigger). |
| Case_008 | TP | TP | TP | ✅ | 2 minutes | Independently identified certutil LOLBin abuse; fastest clean Phase 1 case. |
| Case_009 (Alert B) | TP | TP | TP | ✅ | 3 minutes | Correct prioritization (SYSTEM+Temp path reasoning) and verdict for new service. |
| Case_009 (Alert C) | Ambiguous | TP | Ambiguous | ✅ (corrected) | 5 minutes | Over-weighted normal `cmd→nslookup` parent chain; corrected — no confirmed malicious outcome present for DNS repetition. |
| Case_009 (Alert A) | FP | TP | FP | ✅ (corrected) | 2 minutes | Over-weighted normal `cmd→powershell` parent chain; corrected — single visible Get-Clipboard call, no aggravating factors. |
| Case_010 (Alert E) | TP | TP | TP | ✅ | 2 minutes | Correctly identified destructive/irreversible action (vssadmin) without over-analyzing parent process. |
| Case_010 (Alert F) | Ambiguous | Ambiguous | Ambiguous | ✅ | 2 minutes | Correct verdict; justification approach refined toward affirmative reasoning over elimination logic. |
| Case_010 (Alert D) | Ambiguous | Ambiguous | Ambiguous | ✅ | 4 minutes | Correctly factored in RDP (Logon_Type 10) context for whoami interpretation. |
| Case_011 (Alert G) | TP | TP | TP | ✅ | 2 minutes | Correctly identified Defender-disable as decisive on command content; no longer flagged cmd.exe parent as suspicious. |
| Case_011 (Alert I) | TP | TP | TP | ✅ | 3 minutes | Correctly reasoned mshta LOLBin technique (not the harmless demo payload) drives TP verdict. |
| Case_011 (Alert H) | Ambiguous | FP (initial) | Ambiguous | ✅ (corrected) | 5 minutes | Initially misjudged lsass as suspicious due to unfamiliarity; corrected — lsass is a legitimate process, concern is the credential-dumping precursor context of checking for it by name. |
| Case_012 (Alert K) | TP | TP | TP | ✅ | 2 minutes | Correctly identified fileless IEX download-execute pattern independently. |
| Case_012 (Alert J) | TP | TP | TP | ✅ | 2 minutes | Correctly identified completed privilege escalation (admin group add) as decisive without further confirmation needed. |
| Case_012 (Alert L) | Ambiguous | Ambiguous | Ambiguous | ✅ | 2 minutes | Affirmative dual-use reasoning (RDP could be legitimate or malicious) — first fully clean batch, zero corrections needed. |
| Case_013 (Alert M) | TP | TP | TP | ✅ | 1 minute | Correctly identified ScriptBlock logging disable as defense evasion, fast and clean. |
| Case_013 (Alert N) | TP | TP | TP | ✅ | 3 minutes | Correctly reasoned that attempt (not technical success) confirms intent for ntds.dit copy, even on a non-Domain-Controller host. |
| Case_013 (Alert O) | Ambiguous | Ambiguous | Ambiguous | ✅ | 2 minutes | Correctly weighed Logon_Type (Interactive) context against unusual 3 AM timing to reach Ambiguous rather than TP or FP. |
| Case_014 (Alert R) | TP | TP | TP | ✅ | 1 minute | Correctly identified port 4444 (Metasploit default) significance and masquerading rule name. |
| Case_014 (Alert Q) | TP | TP | TP | ✅ (reasoning corrected) | 2 minutes | Correct verdict; reasoning corrected to center on the abnormal Outlook→PowerShell parent chain rather than the encoded command content — first clean application of the "abnormal parent is the red flag" principle in reverse. |
| Case_014 (Alert P) | Ambiguous | Ambiguous | Ambiguous | ✅ | 2 minutes | Correctly applied technique-vs-outcome distinction to a known WMI lateral-movement technique paired with a harmless specific action. |
| Case_015 (Alert T) | TP | TP | TP | ✅ | 2 minutes | Correctly identified masquerading name + SYSTEM + off-hours trigger combination without needing the encoded payload decoded first. |
| Case_015 (Alert W — interrupt) | TP | TP | TP | ✅ | 2 minutes | Correctly chose to interrupt in-progress work on Alert T to handle this immediately; clean verdict, no correction needed — first successful live queue-interrupt decision. |
| Case_015 (Alert U) | Ambiguous | TP (initial) | Ambiguous | ✅ (corrected) | 4 minutes | Initially over-called TP based on strong DGA-pattern match alone; corrected — no resolved IP/follow-up connection confirmed, technique strength alone is insufficient. |
| Case_015 (Alert S) | Ambiguous | FP (initial) | Ambiguous | ✅ (corrected) | 2 minutes | Initially called FP citing "normal time, same account" as reassuring; corrected — low volume (2 attempts) is insufficient evidence for either TP or FP. |
| Case_015 (Alert V) | Ambiguous | FP (initial, held twice) | Ambiguous | ✅ (corrected, required 2 pushbacks) | 3 minutes | Repeatedly called FP based on "normal business-hours timing" without a usage baseline to support legitimacy; required two rounds of correction before landing on the evidence-based Ambiguous call. |

---

## Key Lessons Log

1. **Case_001:** Decode/inspect payloads before ruling out malicious intent based on technique alone.
2. **Case_002:** Distinguish scripted repetition from manual rapid typing. Missing logs (4720) are gaps to document, not reasons to downgrade a verdict.
3. **Case_003:** Suspicious structure ≠ automatic TP if payload is benign. Ambiguous is the honest call when technique and outcome disagree.
4. **Case_004:** Baseline matches still deserve a quick secondary-indicator sanity check to avoid confirmation bias.
5. **Case_005:** A known/valid account being targeted is not reassuring. Failed attempts are still TP-worthy behavior — outcome ≠ verdict.
6. **Case_006:** "Needs escalation to L2" is not the same as "Ambiguous." Escalation is a response action, not a verdict category.
7. **Case_007:** A completed persistence action (registry write) is TP even with a benign current payload, distinct from a scheduled-but-unconfirmed trigger (Case_003).
8. **Case_008:** LOLBin abuse (trusted binaries misused for unintended purposes) is a recurring real-world evasion pattern worth specifically checking for.
9. **Case_009:** Common parent-child chains (`cmd→powershell`, `cmd→nslookup`) are not inherently suspicious — over-flagging these was the primary correction pattern in this batch.
10. **Case_010:** (a) Destructive/irreversible commands are TP from content alone. (b) Verdicts need positive, affirmative justification, not elimination logic. (c) The same command can carry different risk depending on session/logon context.
11. **Case_011:** A confirmed technique is TP regardless of a harmless demo payload; suspicion should be grounded in known attacker tradecraft, not unfamiliarity with legitimate system processes (e.g. lsass.exe).
12. **Case_012:** An abnormal parent-child chain is itself the red flag when the parent is a process that should never spawn what it spawned — the mirror-opposite of Case_009's lesson.
13. **Case_013:** A credential-theft attempt confirms intent regardless of host role or technical success. Logon_Type is a decisive contextual factor for identity/logon-timing alerts.
14. **Case_014:** (a) A known-abnormal parent process (e.g. Outlook spawning PowerShell) should be weighted as the primary indicator over payload content. (b) A known lateral-movement technique (WMI) does not automatically confirm TP when the specific executed action carries no malicious outcome.
15. **Case_015 (Phase 3, Batch 1):** (a) Live queue-interrupt decisions (pausing in-progress work for a higher-priority arrival) can be made correctly on the first attempt when grounded in clear impact reasoning. (b) DGA/varying-subdomain DNS patterns are a stronger technique-level match than simple repeated queries (Case_009) but still require a confirmed outcome to move from Ambiguous to TP. (c) Low-volume failed logons are inconclusive in either direction, not automatically benign just because the count is small. (d) "Normal timing" or "nothing obviously wrong" is not positive evidence of legitimacy — absence of a red flag is not the presence of a green one. This last point required two rounds of correction on a single alert (Alert V) and is the named focus area heading into Case_016.

---

## Phase Retrospectives

**Phase 1 (Cases 5-8) — Complete:** Built independent, unprompted investigation habits. 4/4 correct verdicts; checklist generation became self-directed by Case_007-008.

**Phase 2 (Cases 9-14) — Complete:** Built alert-prioritization judgment across 6 batches (18 alerts). 6/6 batches correctly prioritized by actual risk/impact reasoning; 18/18 individual verdicts correct after corrections. Recurring early patterns (parent-chain over-flagging, elimination logic, unfamiliarity-based suspicion) showed a clear downward trend, with Case_012-014 closing progressively cleaner.

**Phase 3 (Cases 15-20) — In Progress:** Testing live queue dynamics — mid-investigation interrupts, dynamic re-prioritization, broader evidentiary standards. Case_015 successfully demonstrated correct interrupt-handling on the first attempt (new skill), but also surfaced a new/renamed version of an old pattern: treating unremarkable-looking evidence as automatically benign without positive supporting proof. This is the explicit focus for Cases 016-020.

---

## How This Is Updated

After each case is closed (verdict.md finalized), this file is updated with running totals, analyst's initial call vs. final call, triage time, and any new pattern or missed signal worth logging.
