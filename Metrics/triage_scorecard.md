# 📊 Triage Scorecard — 🏁 REPO COMPLETE: 50 Cases, 150 Alerts (+ 3 Bonus Exam Cases)

Complete performance log across all closed cases in SOC-Triage-Practice.

---

## Summary

| Metric | Value |
|---|---|
| Total Cases Closed | 50 (150 officially-counted alerts, reached at Case_047, + 14 bonus alerts across Cases 048-050) |
| True Positives (TP) | 96 (official count through Case_047) + 10 (bonus cases) = 106 |
| False Positives (FP) | 30 (official count) + 4 (bonus cases) = 34 |
| Ambiguous | 17 |
| Also part of same active-incident chain | 65+ across the repo, culminating in Case_050's cross-incident convergence |
| Correct Final Verdicts | 150 / 150 (official) + 14 / 14 (bonus) |
| Average Triage Time | ~2.5 minutes per alert (endpoint cases, Phases 1-3); Phase 4-5 multi-alert batches ranged 2-8 minutes depending on batch size; fastest single-batch times: Case_042 (2.3 min), Case_037/046/050 (2 min) |
| Most Common FP Pattern | rundll32.exe + PcaSvc.dll,PcaPatchSdbTask (Windows PCA) — Phases 1-3; documented/ticketed cloud config changes — Phases 4-5 |
| **Phase 1** | ✅ Complete (Cases 5-8) |
| **Phase 2** | ✅ Complete (Cases 9-14) |
| **Phase 3** | ✅ Complete (Cases 15-20, including Final Exam) |
| **Phase 4** | ✅ Complete (Cases 21-30, including Capstone) |
| **Phase 5** | ✅ Complete (Cases 31-47, reaching the 150-alert target at Case_047) |
| **Bonus Final Exam** | ✅ Complete (Cases 48-50, 14 additional alerts not counted toward the 150 total, closing with full cross-incident convergence and shift-handoff) |

---

## Key Lessons Log (All 50 Cases)

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
21. **Case_021 (Phase 4, Azure AD — new domain):** Stacked cloud-identity deviations (legacy-auth MFA/CA bypass + risky-IP threat intel flag + geography anomaly + non-compliant device) on a **successful** sign-in form a decisive BEC/account-compromise pattern — "Success" in cloud identity logs is not reassuring; it means the deviation actually got through. First case applying endpoint-honed judgment to a new alert domain, zero corrections.
22. **Case_022 (Phase 4, Email/BEC, 3-alert batch, Splunk-verified):** A self-reported phishing email with no execution stays FP even when a real compromise is unfolding elsewhere in the same tenant — don't let proximity to a confirmed incident inflate an unrelated, clean alert. Conversely, once account takeover is confirmed, a malicious inbox rule and subsequent fraud emails from the same session are the same incident's concealment step and payload step, not separate judgment calls. Zero corrections.
23. **Case_023 (Phase 4, AWS/GuardDuty, 2-finding batch, ticket-only):** Cloud IAM discovery-then-escalation follows the same pattern as endpoint privilege escalation — a burst of never-before-seen enumeration API calls is decisive on its own. Creating a new access key for a *separate*, higher-privileged account is the real damage, not the initial login. Zero corrections.
24. **Case_024 (Phase 4, Mixed Endpoint + Cloud, 5-alert queue, Splunk-verified, first real-breach-grounded scenario):** A routine, individually-defensible action (a helpdesk password reset) becomes a confirmed TP only in light of what follows it — verdict depends on chain context, not the isolated event. Persistence mechanisms (a rogue federated IdP) outrank even privilege escalation as the highest-priority remediation target, since they survive credential resets. Zero corrections, fastest chain-resolution in Phase 4 at the time.
25. **Case_025 (Phase 4, Mixed queue, 6-alert batch with live interrupt, ticket-only, Colonial Pipeline-grounded):** Initial pattern-matching without checking correlation produced an incorrect first-pass TP on a deliberately-included discrimination-test alert (E-002) — corrected to FP once cross-referenced. A live interrupt confirming active ransomware encryption (E-006) flips response priority entirely, from "investigate in order" to "contain first, document after." 1 correction.
26. **Case_026 (Phase 4, Azure AD, 3-alert batch, Splunk-verified):** A confirmed calendar entry is positive, concrete mitigating evidence — not the same as merely "no red flags found." An alert with an established legitimate baseline and only a single missing-confirmation anomaly does not have the same evidentiary weight as a confirmed FP or TP; Ambiguous with a specific verification plan is the correct call. Logged transparently even under direct pressure to omit the correction. 1 correction.
27. **Case_027 (Phase 4, Mixed multi-domain queue, 4-alert batch, ticket-only):** A confirmed, complete malware delivery chain needs no further debate. A service account's total behavioral deviation combined with immediate, concrete impact is TP on its own. Analyst and reviewer reasoning diverged on one alert (spoofed-executive BEC email) — both positions preserved transparently rather than the record being adjusted to hide disagreement.
28. **Case_028 (Phase 4, Hybrid Identity — Azure AD + On-Prem AD, 4-alert batch, ticket-only):** A Kerberoasting indicator (RC4-downgraded TGS burst) is decisive from rate and encryption-choice alone. When a low-value account's activity is immediately followed by unusual activity on a high-value bridge account (Azure AD Connect sync), the second event is the real severity driver. Zero corrections, 3-minute triage — fastest in the repo at the time.
29. **Case_029 (Phase 4, AWS, 5-alert rapid-response queue, ticket-only, Capital One-grounded):** A single point of failure (an SSRF-vulnerable WAF with an overprivileged IAM role) can cascade into a full data breach without additional vulnerabilities. Correctly distinguished a live, active-exploitation chain from a routine, pre-existing, already-ticketed compliance finding sharing the same queue. Zero corrections.
30. **Case_030 (🏁 Phase 4 Capstone, Mixed Email + Cloud Identity + Endpoint, 7-alert queue with live interrupt, ticket-only, time pressure):** A full attack chain can span three previously-separate alert domains as one continuous incident. Naming the specific technique connecting two stages ("MFA fatigue / push bombing," the real 2022 Uber technique) rather than just "MFA was satisfied" is the difference between a generic writeup and an actionable one. Zero corrections, 3-minute total triage time for 7 alerts — matching the fastest pace in the repo. Closed Phase 4 with a full shift-handoff.
31. **Case_031 (Phase 5 opens, AWS — IAM role chaining, 2-alert batch, ticket-only):** A privilege-escalation path built on transitive trust is specifically dangerous because it's invisible to a review of the originating identity's direct policy alone. The *result* of an exposure (RDP opened to the entire internet on a prod DB security group) is critical regardless of whether the cause is a mistake or deliberate action. Zero corrections, 2-minute triage. Opens Phase 5's cloud-weighted expansion.
32. **Case_032 (Phase 5, Azure AD — Conditional Access bypass via privilege misuse, 3-alert batch, ticket-only):** An unexplained privilege grant is itself a red flag worth escalating as a root-cause access-review failure, independent of anything done with it afterward. A self-service action using improper privilege to weaken one's own security controls is a fundamentally different, more direct risk pattern than an admin action performed on behalf of the organization. Zero corrections, 4-minute triage.
33. **Case_033 (Phase 5, GCP — service account key exfiltration, 2-alert batch, Splunk-verified, first GCP case):** Comparing a suspicious action directly against a confirmed-legitimate baseline in the same dataset sharpens a "seems unusual" judgment into a concrete, evidenced finding. Correctly required actual query output before accepting a verdict, holding the line on evidence-based methodology. Zero corrections once verified.
34. **Case_034 (Phase 5, Okta/SaaS third-party support access, 3-alert batch, ticket-only, Okta/Sitel 2022-grounded):** A compromised third-party support account's blast radius is defined by *scope*, not just volume — spreading across 6 customer tenants rather than one is the decisive detail, mirroring the real incident's blast-radius concern. Zero corrections, 3-minute triage.
35. **Case_035 (Phase 5, Insider Threat, 3-alert batch, ticket-only, three unrelated employees, first case explicitly mixing all three verdict types after four consecutive all-TP cases):** Volume alone is not the deciding factor for insider-threat alerts — content and ownership matter more. Correctly resisted forcing a borderline case into a clean FP or TP bucket; Ambiguous with a specific verification step was the evidence-appropriate call. Reinforces a deliberate return to genuine TP/FP/Ambiguous variety after Cases 031-034's unintentional all-TP streak — flagged directly by the analyst and corrected going forward.
36. **Case_036 (Phase 5, Kubernetes — exposed dashboard cryptojacking, 3-alert batch, ticket-only, Tesla 2018-grounded):** A pre-existing, already-ticketed, non-urgent finding does not stay non-urgent forever — its risk status must be re-evaluated the moment new evidence shows active exploitation, contrasting directly with Case_029's I-005 (which stayed correctly de-prioritized because it had no such correlation). Zero corrections, 3-minute triage.
37. **Case_037 (Phase 5, CI/CD pipeline compromise, 3-alert batch, Splunk-verified, CircleCI 2023-grounded):** The decisive signal was a *session-type mismatch* — an interactive user session performing an action explicitly documented as automation-only. The action was legitimate in the abstract; the actor type performing it was the actual red flag. Zero corrections, 2-minute triage.
38. **Case_038 (Phase 5, Azure Storage SAS token overexposure, 3-alert batch, ticket-only):** The same underlying mechanism can be either a severe finding or a textbook example of proper practice depending entirely on configuration. Explicitly naming all distinguishing factors (scope, expiration, documentation) rather than a vague "this one looks fine" strengthens the verdict into something auditable and teachable. Zero corrections, 3-minute triage.
39. **Case_039 (Phase 5, AWS EC2 credential exfiltration + crypto-mining, 3-alert batch, ticket-only):** Reinforces "routine events with zero aggravating factors should be FP" (Case_016) — blocked scan attempts from an attributed benign source is FP on every available detail. Notable process lesson: a fast initial read under time pressure produced an unstable first-pass verdict before a full re-read settled correctly — logged transparently as a reading-speed issue, not a reasoning flaw, even under direct pressure to omit it. 1 correction.
40. **Case_040 (Phase 5 Halfway Checkpoint, Mixed Cloud queue — Azure AD + AWS + GCP + Okta, 5-alert batch with live interrupt, ticket-only):** Established a precise, reusable distinction between "confirmed FP" (deviation + positive confirming evidence) and "genuinely Ambiguous" (deviation + absence of confirming evidence either way). Confirmed for the third time in the repo that a live interrupt immediately reprioritizes response over continuing to process the remaining queue in order. 1 correction.
41. **Case_041 (Phase 5, Supply Chain / Trojanized Update, 3-alert batch, ticket-only, SolarWinds 2020-grounded):** A genuinely new pattern — a verdict that cannot be resolved from an alert's own contents at all, only established retroactively once a later alert confirms compromise. Distinct from every prior "technique alone ≠ automatic TP" lesson, which involved alerts with *some* available suspicious indicator. Zero corrections.
42. **Case_042 (Phase 5, Azure AD — Conditional Access exclusion abuse for persistence, 3-alert batch, ticket-only):** Distinguished persistence at the *security-policy level* from persistence at the individual-account level for the first time — modifying a trusted-location exemption weakens MFA enforcement for every account using that IP going forward, not just the compromised one. Zero corrections, 2.3-minute triage — fastest in the repo to date.
43. **Case_043 (Phase 5, AWS S3 SSE-C ransomware, 3-alert batch, Splunk-verified, Codefinger 2025-grounded):** A stale, unrotated credential is itself a standing risk independent of any specific incident. The attacker weaponized a *legitimate AWS encryption feature* (SSE-C) against its own victim, making the encryption itself technically "correct" AWS behavior — malicious intent lived entirely in the credential compromise and the deviation from historical encryption pattern. Zero corrections.
44. **Case_044 (Phase 5, Cloud database misconfiguration, 3-alert batch, ticket-only):** An internal inventory label ("dev/test") is a classification, not a technical control, and does not change a verdict when the actual technical facts independently justify the same severity. Unprotected dev/test environments carry elevated real-world risk precisely because they receive less scrutiny. Zero corrections.
45. **Case_045 (Phase 5, AI voice/video-clone-assisted BEC, 3-alert batch, ticket-only, Arup 2024-grounded):** First case involving AI-generated social engineering rather than a technical exploit — no systems were compromised in either the scenario or the real incident. Correctly named the precise control that failed (segregation of duties bypassed by a video call), not "the employee was deceived." Zero corrections.
46. **Case_046 (Phase 5, SaaS developer token theft, 3-alert batch, ticket-only, Slack 2022-grounded):** Explicitly ranked two co-occurring suspicious indicators by evidentiary strength rather than treating them as equal — off-hours timing is a soft signal with plausible innocent explanations, while access to a resource entirely outside an actor's documented scope is a hard signal with none. Zero corrections, 2-minute triage.
47. **Case_047 (🎯 150-Alert Milestone, Azure Hybrid Identity, 2-alert batch, ticket-only):** Established a clean separation between verdict-determining evidence and open investigative questions — an unapproved, no-ticket, off-hours federation trust bypassing a mandatory 2-person process is TP on its severity alone, regardless of whether the account was compromised or an insider acted outside policy. Zero corrections. **This case brought the repo to exactly 150 individually-triaged alerts.**
48. **Case_048 (🏁 Bonus Final Exam, Stage 1, 6-alert queue with live interrupt, ticket-only):** A queue can contain multiple genuinely separate incidents (not just one chain plus one unrelated noise alert) — correctly separating two confirmed incidents (s.mehta/backup-svc-2 cryptomining, t.oconnor endpoint compromise) from one unrelated benign alert required verifying actor identity explicitly rather than assuming queue-order implies chain continuation. 1 correction (an alert initially misread as a chain continuation based on position, corrected to FP after verifying no actual actor overlap) — logged transparently as bonus material, same honesty standard as the counted cases.
49. **Case_049 (🏁 Bonus Final Exam, Stage 2, 5-alert batch, ticket-only, direct continuation of Stage 1):** Credential-dumping tools harvest *every* cached credential on a compromised host, not just the primary user's — the presence of a different, high-privilege account's credentials authenticating from an already-compromised low-privilege host converts a contained single-workstation incident into a domain-controller-level threat. This is the clearest illustration in the repo of why lateral-movement alerts must be assessed for downstream reach, not the originating host's apparent value. Zero corrections.
50. **Case_050 (🏁 FINAL CAPSTONE, Stage 3, 3-alert batch with live interrupt, ticket-only, closes the repo):** The most complex correlation task in the repo's history — recognizing that concurrent, simultaneous sessions on the same account from different locations mean the underlying *credentials* are compromised, not merely a session or device, even while the legitimate account owner is actively using the same account for genuine incident remediation at the same moment. Correctly distinguished legitimate defender actions (emergency remediation, automated EDR containment) from the actual ongoing threat within the same queue. Two originally-unrelated incidents from Case_048 were traced to convergence through one shared, harvested credential. Zero corrections, 2-minute triage. Closed with a full 3-stage shift-handoff and complete repo retrospective.

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
sign-in logs) ingested via CSV upload into a local Splunk lab instance.

**Case_021** (Azure AD, ticket-only): TP, 0 corrections.

**Case_022** (Email/BEC, 3-alert batch, Splunk-verified): FP + TP + TP, 0 corrections.

**Case_023** (AWS/GuardDuty, 2-finding batch, ticket-only): TP + TP, 0 corrections.

**Case_024** (Mixed Endpoint + Cloud, 5-alert queue, Splunk-verified, first real-breach-grounded
scenario — MGM Resorts 2023): TP × 5, single correlated chain, 0 corrections, 7-minute
resolution.

**Case_025** (Mixed queue, 6-alert batch with live interrupt, ticket-only — Colonial Pipeline
2021): TP × 5 + FP × 1 (discrimination-test alert), 1 correction, 7-minute triage time.

**Case_026** (Azure AD, 3-alert batch, Splunk-verified): FP + TP + Ambiguous, 1 correction
logged transparently even under direct pressure to omit it.

**Case_027** (Mixed multi-domain queue, 4-alert batch, ticket-only): TP + TP + Ambiguous
(analyst/reviewer reasoning diverged, both preserved) + FP.

**Case_028** (Hybrid Identity — Azure AD + On-Prem AD, 4-alert batch, ticket-only): TP × 3 + FP,
0 corrections, 3-minute triage — fastest in the repo at the time.

**Case_029** (AWS, 5-alert rapid-response queue, ticket-only — Capital One 2019): TP × 4 + FP,
0 corrections, 4-minute triage.

**Case_030 — 🏁 Phase 4 Capstone** (Mixed Email + Cloud Identity + Endpoint, 7-alert queue with
live interrupt, ticket-only, time pressure — Uber 2022 MFA-fatigue technique): TP × 6 + FP, 0
corrections, 3-minute total triage time, closed with a full shift-handoff.

---

## Phase 4 Retrospective (Cases 021-030)

**Structure:** 10 cases spanning 4 new alert domains not covered in Cases 1-20 (Azure AD/cloud
identity, AWS, email/BEC, hybrid on-prem+cloud identity), alternating ticket-only and
Splunk-verified formats, real-breach-grounded scenarios (MGM Resorts 2023, Colonial Pipeline
2021, Capital One 2019, Uber 2022 technique), multiple live interrupts, and a 7-alert capstone
with a full shift-handoff deliverable closing the phase.

**Result:** All alerts correctly triaged across Cases 021-030. Two corrections logged across
the phase — both self-caught and corrected during investigation: Case_025's E-002 (initial TP →
corrected to FP after correlation check) and Case_026's F-003 (initial TP → corrected to
Ambiguous, notably logged transparently even after being directly asked to omit it).

**What this proved:** the investigative judgment built across Phases 1-3 transfers directly to
entirely new alert domains without needing to relearn the underlying reasoning from scratch. The
capstone closed the phase at the same pace as the fastest single-domain cases in the repo (3
minutes for 7 alerts), despite spanning three alert domains in one continuous chain.

---

## Phase 5 Kickoff (Cases 31-50)

Phase 5 expanded to 20 more cases targeting 49 additional alerts, bringing the repo to 50 cases
/ 150 alerts total. Deliberately weighted toward cloud and SaaS domains (AWS, Azure, GCP, Okta,
CI/CD, Kubernetes) — roughly 15 of 20 cases — since cloud alert volume was comparatively
underrepresented across Phases 1-4 relative to its real-world share of SOC alert queues.
Real-breach-grounding continues per the Phase 4 methodology, citing sources in investigation.md.
Verification method (ticket-only vs. Splunk) is decided per case as before.

**Case_031** (AWS — IAM role chaining, 2-alert batch, ticket-only): TP × 2, 0 corrections,
2-minute triage. Opens Phase 5.

**Case_032** (Azure AD — Conditional Access bypass, 2-alert batch, ticket-only): TP × 2, 0
corrections, 4-minute triage.

**Case_033** (GCP — service account key exfiltration, 2-alert batch, Splunk-verified, first GCP
case): TP × 2, 0 corrections, 4-minute triage.

**Case_034** (Okta/SaaS third-party support access, 3-alert batch, ticket-only — Okta/Sitel
2022): TP × 3, 0 corrections, 3-minute triage.

**Methodology note:** Cases 031-034 were unintentionally all-TP, a drift away from the
discrimination-testing variety established in Cases 025-030. Flagged by the analyst and
corrected explicitly going forward — every case from Case_035 onward deliberately mixes
TP/FP/Ambiguous outcomes rather than defaulting to confirmed-compromise chains.

**Case_035** (Insider Threat, 3-alert batch, ticket-only, three unrelated employees): TP +
Ambiguous + FP, 0 corrections, 3-minute triage. First case since the methodology note above to
genuinely span all three verdict categories in one ticket.

**Case_036** (Kubernetes — exposed dashboard cryptojacking, 3-alert batch, ticket-only — Tesla
2018): TP (re-escalated) + TP (critical) + FP, 0 corrections, 3-minute triage.

**Case_037** (CI/CD pipeline compromise, 3-alert batch, Splunk-verified — CircleCI 2023): TP +
TP (critical) + FP, 0 corrections, 2-minute triage.

**Case_038** (Azure Storage — SAS token overexposure, 3-alert batch, ticket-only): TP + TP
(critical) + FP, 0 corrections, 3-minute triage.

**Case_039** (AWS EC2 credential exfiltration + crypto-mining, 3-alert batch, ticket-only): TP +
TP (critical) + FP, 1 correction (reading-speed issue, not reasoning flaw), 5-minute triage.

**Case_040 — Phase 5 Halfway Checkpoint** (Mixed Cloud queue — Azure AD + AWS + GCP + Okta,
5-alert batch with live interrupt, ticket-only): FP + TP + FP (corrected from Ambiguous) + FP +
TP (critical), 1 correction, 6-minute triage.

**Case_041** (Supply Chain / Trojanized Update, 3-alert batch, ticket-only — SolarWinds 2020):
TP (retroactive) + TP (critical) + FP, 0 corrections, 3-minute triage.

**Case_042** (Azure AD — Conditional Access exclusion abuse for persistence, 3-alert batch,
ticket-only): TP + TP (critical) + FP, 0 corrections, 2.3-minute triage.

**Case_043** (AWS S3 SSE-C ransomware, 3-alert batch, Splunk-verified — Codefinger 2025): TP +
TP (critical) + FP, 0 corrections, 5-minute triage.

**Case_044** (Cloud database misconfiguration, 3-alert batch, ticket-only): TP (critical) × 2 +
FP, 0 corrections, 3-minute triage.

**Case_045** (AI voice/video-clone-assisted BEC, 3-alert batch, ticket-only — Arup 2024): TP +
TP (critical) + FP, 0 corrections, 4-minute triage.

**Case_046** (SaaS developer token theft, 3-alert batch, ticket-only — Slack 2022): TP + TP
(critical) + FP, 0 corrections, 2-minute triage.

**Case_047 — 🎯 150-Alert Milestone** (Azure Hybrid Identity, 2-alert batch, ticket-only): TP
(critical) + FP, 0 corrections, 3-minute triage. **Brings the repo to exactly 150
individually-triaged alerts, the project's original target.**

---

## 🎯 Milestone Note: 150 Alerts Reached

Per explicit agreement with the analyst, Case_047 was designated as the final case counting
toward the project's original 150-alert target, reached at exactly 47 cases. Cases 048, 049,
and 050 continue the case numbering through to 50 as bonus, Final-Exam-style material (mixed
alert queues, live interrupts, cross-case correlation, and a closing shift-handoff deliverable
for Case_050), but their alerts are **not added to the 150-alert count** — they exist to
continue demonstrating and stress-testing the analyst's skills beyond the original numeric
target, consistent with how the project's Phase 3 and Phase 4 capstones (Cases 019-020, 030)
were used as skill demonstrations beyond routine case counting.

---

## Phase 5 Halfway Checkpoint (Cases 031-040)

**Structure:** 10 cases (031-040) spanning AWS, Azure, GCP, Okta/SaaS, Kubernetes, and CI/CD
domains, deliberately cloud-weighted per the analyst's request, mostly ticket-only with two
Splunk-verified cases (033, 037), one live-interrupt checkpoint case (040) closing this half of
the phase. Following Cases 031-034's unintentional all-TP drift (self-identified by the analyst
and corrected), Cases 035-040 consistently mix TP/FP/Ambiguous outcomes.

**Result:** 27 individually-triaged alerts across Cases 031-040, all correct final verdicts. 2
corrections logged: Case_039's S-003 (a fast, incomplete initial read under time pressure that
produced an unstable TP → Ambiguous → FP sequence before settling correctly) and Case_040's
T-003 (an initial Ambiguous corrected to FP once compared consistently against T-001's
evidentiary standard). Both corrections were self-caught during investigation rather than
missed entirely, and both were logged transparently per the repo's standing methodology.

**What this proved:** the core investigative judgment built across Phases 1-4 continues to
transfer cleanly into cloud-native domains not previously covered in this repo (GCP, Kubernetes,
CI/CD pipelines, SAS token governance) — the same underlying principles recur in each new domain
with only the surface details changing. The Case_040 checkpoint reinforced that live-interrupt
discipline (established in Case_025 and Case_030) is now a consistently-applied skill rather
than a one-off response to a novel format.

---

## 🏁 Bonus Final Exam (Cases 048-050) — Full Retrospective

**Structure:** A 3-stage bonus exam, matching the format of the original Final Exam (Cases
019-020) and Phase 4 Capstone (Case_030): mixed alert domains, deliberate discrimination-test
alerts, a live interrupt in each stage, cross-stage correlation, and a final full shift-handoff
synthesizing the entire exam plus the whole 50-case repo.

**Case_048 (Stage 1, 6-alert queue, live interrupt):** Introduced two genuinely separate
confirmed incidents in one queue for the first time (not one chain plus one noise alert, but two
full incidents plus one noise alert): s.mehta/backup-svc-2 (Okta impossible travel → rogue AWS
admin account → GPU cryptomining instances) and t.oconnor (Outlook-spawned PowerShell download
cradle). 1 correction — an alert (r.bhagat's routine password reset) was initially misread as a
continuation of "the chain" based on queue position before being correctly identified as
unrelated once actor identity was explicitly verified.

**Case_049 (Stage 2, 5-alert batch, direct continuation):** Both incidents escalated —
confirmed cryptomining traffic resolved the purpose of Case_048's GPU instances, and a
credential-dumping tool on t.oconnor's host was found to have harvested a different,
high-privilege account's (it-infra-lead) credentials, which were then used to authenticate to
the domain controller. Zero corrections. Established the clearest lesson in the repo about
assessing lateral-movement alerts by downstream reach rather than originating-host value.

**Case_050 (Stage 3, 3-alert batch, live interrupt, FINAL CASE):** Distinguished legitimate
defender actions (verified emergency remediation, automated EDR containment) from an active,
ongoing threat within the same short queue — the exam's trickiest correlation task. A live
interrupt revealed a second, concurrent session on it-infra-lead's account (the same credentials
harvested in Case_049) attempting to register a persistent, tenant-wide OAuth backdoor from an
unrelated location, at the exact same time the legitimate account owner was using the same
credentials for real incident response. This confirmed the account's underlying credentials —
not just a session or device — were compromised. The two originally-unrelated Case_048 incidents
were traced to convergence through this one shared, harvested credential. Zero corrections.
Closed with a full 3-stage shift-handoff and the complete repo-closing retrospective below.

**Bonus exam total:** 14 alerts across 3 cases, 2 corrections (both in Case_048, both
self-caught and logged transparently), all final verdicts correct.

---

## 🏁 Repo Completion Note — Final (Cases 1-50)

This scorecard reflects the full, closed history of all 50 cases in SOC-Triage-Practice,
spanning five phases and a 3-stage bonus Final Exam:

- **Phases 1-3 (Cases 1-20):** Endpoint-focused investigation — single-alert deep dives, batch
  prioritization, and full queue simulation under time pressure, culminating in a 10-alert
  Final Exam and shift-handoff.
- **Phase 4 (Cases 21-30):** Expansion into cloud identity, AWS, and email/BEC domains, using
  realistic SOC-tool ticket formats, introducing real-breach-grounded scenarios starting at
  Case_024, closing with a second, cross-domain capstone.
- **Phase 5 (Cases 31-47):** A deliberately cloud-weighted expansion across AWS, Azure, GCP,
  Okta/SaaS, Kubernetes, and CI/CD, reaching the project's original 150-alert target at
  Case_047.
- **Bonus Final Exam (Cases 48-50):** A closing 3-stage exam converging two originally-separate
  incidents into a single cross-domain compromise via one shared, harvested credential,
  finishing with a complete shift-handoff and repo retrospective.

**The methodology held constant across all 50 cases:** investigating blind with no verdict
given upfront, documenting corrections honestly rather than hiding them — including under
direct pressure to omit one (Case_026) — tracking real, not fabricated, triage time throughout,
and, from Case_024 onward, grounding practice scenarios in real, publicly documented breaches
(MGM Resorts, Colonial Pipeline, Capital One, Uber's MFA-fatigue technique, Okta/Sitel, Tesla,
CircleCI, SolarWinds, Codefinger, Arup, Slack) with fully sanitized identities and IOCs.

**150 officially-counted alerts, 150/150 correct final verdicts.** Total corrections logged
across the entire repo's counted alerts: honestly tracked at each phase transition above, with
every single one self-caught during investigation and corrected before the case closed — not
missed entirely and not hidden after the fact.

**The recurring pattern across all five phases and the bonus exam** — technique alone ≠
automatic TP, normal-seeming ≠ automatic FP, correlation must be verified rather than assumed,
absence of confirming evidence ≠ positive evidence of compromise, and persistence/impact must be
assessed by scope and downstream reach rather than surface severity — proved to transfer
cleanly from single-alert endpoint investigation through full queue simulation into entirely
new cloud, SaaS, and hybrid-identity domains, culminating in a final exam where two unrelated
incidents were correctly traced to convergence through a single compromised credential — the
most complex correlation task in the repo's full history.
