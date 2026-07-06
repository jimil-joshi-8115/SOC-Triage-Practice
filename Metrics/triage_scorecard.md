# 📊 Triage Scorecard — FINAL (All 20 Cases Complete)

Complete performance log across all closed cases in SOC-Triage-Practice.

---

## Summary

| Metric | Value |
|---|---|
| Total Cases Closed | 20 (61 individual alerts triaged) |
| True Positives (TP) | 32 |
| False Positives (FP) | 8 |
| Ambiguous | 14 |
| Also part of same active-incident chain (Final Exam) | 7 |
| Correct Final Verdicts | 61 / 61 |
| Average Triage Time | ~2.5 minutes per alert |
| Most Common FP Pattern | rundll32.exe + PcaSvc.dll,PcaPatchSdbTask (Windows PCA) |
| **Phase 1** | ✅ Complete (Cases 5-8) |
| **Phase 2** | ✅ Complete (Cases 9-14) |
| **Phase 3** | ✅ Complete (Cases 15-20, including Final Exam) |

---

## Key Lessons Log (All 20 Cases)

1. **Case_001:** Decode/inspect payloads before ruling out malicious intent based on technique alone.
2. **Case_002:** Distinguish scripted repetition from manual rapid typing. Missing logs are gaps to document.
3. **Case_003:** Suspicious structure ≠ automatic TP if payload is benign.
4. **Case_004:** Baseline matches still deserve a quick secondary-indicator sanity check.
5. **Case_005:** A known/valid account being targeted is not reassuring. Failed attempts are still TP-worthy.
6. **Case_006:** "Needs escalation to L2" is not the same as "Ambiguous."
7. **Case_007:** A completed persistence action is TP even with a benign current payload.
8. **Case_008:** LOLBin abuse is a recurring real-world pattern worth specifically checking for.
9. **Case_009:** Common parent-child chains are not inherently suspicious.
10. **Case_010:** Destructive commands are TP from content alone; use affirmative justification, not elimination logic; session context affects risk.
11. **Case_011:** A confirmed technique is TP regardless of a harmless demo payload; suspicion should be grounded in tradecraft, not unfamiliarity.
12. **Case_012:** An abnormal parent-child chain is itself the red flag when the parent shouldn't spawn what it spawned.
13. **Case_013:** A credential-theft attempt confirms intent regardless of technical success. Logon_Type is decisive for identity/timing alerts.
14. **Case_014:** A known-abnormal parent process outranks payload content as the primary indicator; technique + harmless outcome still leans Ambiguous.
15. **Case_015:** Live queue-interrupt decisions can be made correctly when grounded in impact reasoning; "normal timing" is not positive evidence of legitimacy.
16. **Case_016:** A confirmed EDR detection is direct evidence, not a technique-vs-outcome call; firewall verdicts hinge on direction; routine events with zero aggravating factors should be FP.
17. **Case_017:** Source process matters more than port legitimacy for network connections; self-add to a group differs from adding a separate account; session correlation with confirmed TP alerts should elevate concern for otherwise-isolated events.
18. **Case_018 (Rapid-Response):** System-wide security/audit config changes have no legitimate everyday use case and should be TP on content alone; "normal access method/timing ≠ proof of safety" recurred and remains the most persistent correction pattern in the repo.
19. **Case_019 (Final Exam, Stage 1):** Query/action **volume and rate** can be decisive evidence on its own (DNS TXT query flood), separate from needing a confirmed downstream outcome. Persistence + a recon-specific technique (AV enumeration) is a decisive combination even without observed follow-through. The type of service being stopped/disabled matters — routine software (Windows Update) differs fundamentally from security controls (Defender, audit logging) even when the action ("stop a service") looks identical on the surface.
20. **Case_020 (Final Exam, Stage 2):** Recognizing that a new alert is a **direct continuation of an already-confirmed incident** (same process, escalated privilege) — rather than treating it as a fresh investigation — is an advanced correlation skill, executed correctly and immediately in this case. A full active-incident chain can span many individually-triaged alerts; the shift-handoff deliverable is where that full picture gets communicated to the next analyst or response team.

---

## Final Exam Retrospective (Cases 019-020)

**Structure:** 10 alerts across two linked stages, mixed formats (Splunk, EDR-style, ticket-only), one mid-stage interrupt, enforced time pressure (~2-3 min/alert target), cross-alert correlation, and a required shift-handoff summary as the final deliverable.

**Result:** 10/10 correct final verdicts. Stage 1 required 4 corrections (out of 7 alerts) under time pressure; Stage 2 required 0 corrections (out of 3 alerts) — the analyst's accuracy improved once the active-incident context was firmly established, and the standout moment of the entire exam was immediately recognizing Alert BI as a continuation of the already-confirmed BA/BG chain rather than re-investigating it from scratch.

**What this proved:** the reasoning built across Phases 1-3 holds up under compressed time, multiple simultaneous alerts, mixed tool formats, and live interrupts — the core investigative judgment is sound. The recurring correction pattern (technique-alone ≠ automatic TP; normal-seeming ≠ automatic FP) is now well-documented across nearly every phase of this repo and remains the single clearest, nameable area for continued growth beyond this project.

---

## Repo Completion Note

This scorecard reflects the full, closed history of all 20 planned cases. The methodology — investigating blind, documenting corrections honestly rather than hiding them, and tracking real (not fabricated) triage time — was maintained consistently from Case_001 through Case_020, including through the Final Exam capstone. The 61/61 correct final-verdict record reflects a slower, more deliberate investigative process; the honestly-logged correction rate (a downward trend from ~50% early in Phase 3 drills toward more consistent first-pass accuracy by the Final Exam's second stage) is the more informative metric for anyone reviewing this portfolio.
