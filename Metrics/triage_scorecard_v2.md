# 📊 Triage Scorecard — Cases 1–24 (Phase 4 In Progress)

Complete performance log across all closed cases in SOC-Triage-Practice.

---

## Summary

| Metric | Value |
|---|---|
| Total Cases Closed | 24 (72 individual alerts triaged) |
| True Positives (TP) | 42 |
| False Positives (FP) | 9 |
| Ambiguous | 14 |
| Also part of same active-incident chain (Final Exam + Case_022 BEC + Case_023 AWS + Case_024 chain) | 16 |
| Correct Final Verdicts | 72 / 72 |
| Average Triage Time | ~2.5 minutes per alert (endpoint cases); Case_024 5-alert chain: 7 min total |
| Most Common FP Pattern | rundll32.exe + PcaSvc.dll,PcaPatchSdbTask (Windows PCA) |
| **Phase 1** | ✅ Complete (Cases 5-8) |
| **Phase 2** | ✅ Complete (Cases 9-14) |
| **Phase 3** | ✅ Complete (Cases 15-20, including Final Exam) |
| **Phase 4** | 🔄 In Progress (Cases 21-30, cloud/email domains introduced) |

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
21. **Case_021 (Phase 4, Azure AD — new domain):** Stacked cloud-identity deviations (legacy-auth MFA/CA bypass + risky-IP threat intel flag + geography anomaly + non-compliant device) on a **successful** sign-in form a decisive BEC/account-compromise pattern — "Success" in cloud identity logs is not reassuring the way it might seem; it means the deviation actually got through. First case applying endpoint-honed judgment (stacked-indicator reasoning, success ≠ safety) to a new alert domain, with zero corrections needed.
22. **Case_022 (Phase 4, Email/BEC, 3-alert batch, Splunk-verified):** A self-reported phishing email with no execution stays FP even when a real compromise is unfolding elsewhere in the same tenant — don't let proximity to a confirmed incident inflate an unrelated, clean alert. Conversely, once account takeover is confirmed (impossible travel + legacy-auth MFA bypass), a malicious inbox rule and subsequent high-volume fraud emails from the same session are not separate judgment calls — they're the same incident's concealment step and payload step. Zero corrections.
23. **Case_023 (Phase 4, AWS/GuardDuty, 2-finding batch, ticket-only):** Cloud IAM discovery-then-escalation follows the same pattern as endpoint privilege escalation — a burst of never-before-seen enumeration API calls is decisive on its own (same class of evidence as Case_019's DNS TXT flood), and creating a new access key for a *separate*, higher-privileged account is the real damage, not the initial login. Correctly recognized the second finding as a continuation of the first (identical source IP, direct time sequence) rather than a fresh investigation — third consecutive Phase 4 case with zero corrections.
24. **Case_024 (Phase 4, Mixed Endpoint + Cloud, 5-alert queue, Splunk-verified, first real-breach-grounded scenario):** A routine, individually-defensible action (a helpdesk password reset with standard verification) becomes a confirmed TP only in light of what follows it — verdict depends on chain context, not the isolated event. Persistence mechanisms (a rogue federated IdP bypassing MFA entirely) outrank even privilege escalation as the highest-priority remediation target, since they survive credential resets on the original account. Recognized the specific "disable AV, then delete shadow copies" combination as pre-ransomware staging from tool usage pattern, not tool identity (both are legitimate Windows binaries). Full 5-alert chain correctly triaged as one incident. Zero corrections, fastest chain-resolution time in the repo (7 minutes for 5 correlated alerts).

---

## Final Exam Retrospective (Cases 019-020)

**Structure:** 10 alerts across two linked stages, mixed formats (Splunk, EDR-style, ticket-only), one mid-stage interrupt, enforced time pressure (~2-3 min/alert target), cross-alert correlation, and a required shift-handoff summary as the final deliverable.

**Result:** 10/10 correct final verdicts. Stage 1 required 4 corrections (out of 7 alerts) under time pressure; Stage 2 required 0 corrections (out of 3 alerts) — the analyst's accuracy improved once the active-incident context was firmly established, and the standout moment of the entire exam was immediately recognizing Alert BI as a continuation of the already-confirmed BA/BG chain rather than re-investigating it from scratch.

**What this proved:** the reasoning built across Phases 1-3 holds up under compressed time, multiple simultaneous alerts, mixed tool formats, and live interrupts — the core investigative judgment is sound. The recurring correction pattern (technique-alone ≠ automatic TP; normal-seeming ≠ automatic FP) is now well-documented across nearly every phase of this repo and remains the single clearest, nameable area for continued growth beyond this project.

---

## Phase 4 Kickoff (Cases 21-30)

Following the Final Exam capstone, the repo expanded into new alert domains not covered in
Cases 1-20: Azure AD / cloud identity, AWS, and deeper email/phishing (BEC) scenarios, alongside
continued endpoint/Splunk-verified cases. Cloud-domain cases use realistic SOC-tool ticket
formats (Microsoft Sentinel incidents, Microsoft Defender for Office 365 alerts) matching what
an MNC SOC analyst would actually see. Some cloud cases are investigated ticket-only (no Splunk
verification, same precedent as Case_018's rapid-response format) per analyst decision; others
are Splunk-verified using realistic sample cloud log data (O365 Unified Audit Log, Azure AD
sign-in logs) ingested via CSV upload into a local Splunk lab instance. This is noted
transparently in each case's investigation.md and verdict.md.

**Case_021** (Azure AD, ticket-only): TP, 0 corrections — correctly generalized "success ≠
legitimacy" and stacked-indicator reasoning, both hard-won lessons from Cases 015-019, to a
domain never previously covered in this repo.

**Case_022** (Email/BEC, 3-alert batch, Splunk-verified via sample O365 Unified Audit Log data):
FP (BC-001, self-reported phishing) + TP (BC-002, impossible travel + malicious inbox rule) +
TP (BC-003, fraudulent payment-redirection emails, same session as BC-002). 0 corrections.
Correctly kept BC-001 isolated rather than letting it get swept up by the confirmed compromise
in BC-002/BC-003, and correctly recognized BC-003 as a continuation of BC-002 rather than a
fresh investigation — the same correlation skill first demonstrated in Case_020.

**Case_023** (AWS/GuardDuty, 2-finding batch, ticket-only): TP (AG-001, Tor-based console login
with no MFA against a 100%-MFA baseline) + TP (AG-002, IAM discovery burst followed by a new
access key created for a separate, high-privilege service account). 0 corrections. Correctly
identified AG-002 as the same attacker session as AG-001 via IP correlation, and correctly
flagged the *new access key* — not the original login — as the highest-priority remediation
target, since it represents an independently attacker-controlled administrator credential.

**Case_024** (Mixed Endpoint + Cloud, 5-alert queue, Splunk-verified): first case in the repo
explicitly adapted from a real, publicly documented breach (2023 MGM Resorts / Scattered
Spider) rather than an original scenario — company names, users, IPs, and timestamps fully
sanitized/fictional, but the attack chain structure (helpdesk vishing → cloud identity
takeover → rogue IdP persistence → privilege escalation → ransomware staging) mirrors the real
incident. TP × 5, single correlated chain, 0 corrections, resolved in 7 minutes. Established a
methodology going forward: cite the real public incident a scenario is grounded in directly in
investigation.md, keeping practice scenarios realistic without using any real, sensitive, or
non-public data.

---

## Repo Completion Note (Cases 1-20)

This section reflects the full, closed history of the original 20 planned cases. The methodology — investigating blind, documenting corrections honestly rather than hiding them, and tracking real (not fabricated) triage time — was maintained consistently from Case_001 through Case_020, including through the Final Exam capstone. The 61/61 correct final-verdict record reflects a slower, more deliberate investigative process; the honestly-logged correction rate (a downward trend from ~50% early in Phase 3 drills toward more consistent first-pass accuracy by the Final Exam's second stage) is the more informative metric for anyone reviewing this portfolio. The repo has since expanded into Phase 4 (see above).
