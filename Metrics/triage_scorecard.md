# 📊 Triage Scorecard — Cases 1–40 (Phase 5 Halfway Checkpoint)

Complete performance log across all closed cases in SOC-Triage-Practice.

---

## Summary

| Metric | Value |
|---|---|
| Total Cases Closed | 40 (130 individual alerts triaged) |
| True Positives (TP) | 83 |
| False Positives (FP) | 23 |
| Ambiguous | 17 |
| Also part of same active-incident chain (Final Exam + Case_022 BEC + Case_023 AWS + Case_024 chain + Case_025 chain + Case_028 chain + Case_029 chain + Case_030 Capstone chain + Case_031 chain + Case_032 chain + Case_033 chain + Case_034 chain + Case_036 chain + Case_037 chain + Case_038 chain + Case_039 chain + Case_040 chain) | 53 |
| Correct Final Verdicts | 130 / 130 |
| Average Triage Time | ~2.5 minutes per alert (endpoint cases); Case_024 5-alert chain: 7 min; Case_025 6-alert chain w/ live interrupt: 7 min; Case_026 3-alert batch: 5 min; Case_027 4-alert batch: 8 min; Case_028 4-alert batch: 3 min; Case_029 5-alert rapid-response: 4 min; Case_030 Capstone, 7-alert chain w/ live interrupt: 3 min; Case_031 2-alert batch: 2 min; Case_032 2-alert batch: 4 min; Case_033 2-alert batch: 4 min; Case_034 3-alert batch: 3 min; Case_035 3-alert batch (3 distinct verdicts): 3 min; Case_036 3-alert batch: 3 min; Case_037 3-alert batch: 2 min; Case_038 3-alert batch: 3 min; Case_039 3-alert batch: 5 min; Case_040 5-alert mixed-cloud queue w/ live interrupt (checkpoint): 6 min |
| Most Common FP Pattern | rundll32.exe + PcaSvc.dll,PcaPatchSdbTask (Windows PCA) |
| **Phase 1** | ✅ Complete (Cases 5-8) |
| **Phase 2** | ✅ Complete (Cases 9-14) |
| **Phase 3** | ✅ Complete (Cases 15-20, including Final Exam) |
| **Phase 4** | ✅ Complete (Cases 21-30, including Capstone) |
| **Phase 5** | 🔄 In Progress (Cases 31-50, cloud-weighted expansion — targeting 150 total alerts) — Case_040 checkpoint reached, 10 cases remain |

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
25. **Case_025 (Phase 4, Mixed queue, 6-alert batch with live interrupt, ticket-only, Colonial Pipeline-grounded):** Initial pattern-matching on a surface-level signal ("failed logons = suspicious") without checking account/host/IP correlation against the rest of the queue produced an incorrect first-pass TP on a deliberately-included discrimination-test alert (E-002) — corrected to FP once cross-referenced and found to match a documented, recurring benign pattern. Reinforces that shared presence in a queue does not imply shared incident membership. Correctly recognized that a live interrupt confirming active ransomware encryption (E-006) doesn't just add one more TP to the list — it flips response priority entirely, from "investigate the queue in order" to "contain first, document after." 1 correction, 7-minute total triage time for a 6-alert chain with a mid-investigation interrupt.
26. **Case_026 (Phase 4, Azure AD, 3-alert batch, Splunk-verified):** A confirmed calendar entry is positive, concrete mitigating evidence (F-001, FP) — not the same thing as merely "no red flags found." Conversely, concrete attacker tradecraft (adding a second MFA method instead of replacing the original, F-002) is decisive on its own without needing a location anomaly to stand on. The key lesson: an alert with an established legitimate baseline pattern (frequent international travel) and only a single missing-confirmation anomaly (no calendar entry) — with MFA satisfied normally throughout — does not have the same evidentiary weight as either of the other two, and forcing it into TP or FP is guessing rather than concluding; Ambiguous with a specific out-of-band verification plan is the correct, defensible call (F-003). Initial instinct defaulted to TP on F-003 before this distinction was made explicit — corrected and logged transparently, consistent with the repo's stated honesty methodology even under direct pressure to omit it.
27. **Case_027 (Phase 4, Mixed multi-domain queue, 4-alert batch, ticket-only):** A confirmed, complete malware delivery chain (macro → LOLBin → execution) needs no further debate (G-001, TP). A service account's total behavioral deviation from its established role (a CI/CD-only account suddenly changing bucket ACLs) combined with immediate, concrete impact (public exposure of database backups) is TP on its own — briefly discussed as possible Ambiguous before confirming the deviation and impact were both concrete rather than speculative (G-002). G-003 is the notable entry: strong technical indicators (failed SPF/DKIM/DMARC, lookalike domain, CEO/finance/wire-transfer targeting) were weighed by the analyst against the absence of a malicious payload and zero recipient engagement, and the analyst's final judgment differed from the reviewer's technical read — both positions logged transparently per repo methodology, since an honest record preserves genuine analyst disagreement rather than only the "expected" answer.
28. **Case_028 (Phase 4, Hybrid Identity — Azure AD + On-Prem AD, 4-alert batch, ticket-only):** A Kerberoasting indicator (RC4-downgraded TGS request burst) is decisive from rate and encryption-choice alone, without needing a confirmed cracked credential (same evidentiary class as Case_019's DNS TXT flood and Case_023's IAM enumeration burst). The critical insight of this case: when a low-value account's suspicious activity is immediately followed by unusual activity on a *high-value bridge account* (the Azure AD Connect sync account connecting on-prem and cloud identity), the second event is the real severity driver — an unverified OAuth app receiving `Directory.ReadWrite.All` from that compromised bridge account represents a directory-wide, credential-reset-resistant backdoor, which is a categorically different and higher-priority remediation target than the initial Kerberoasting alone. Full chain correctly triaged as one incident spanning both on-prem and cloud in under 6 minutes of attacker activity. Zero corrections, 3-minute triage time — fastest in the repo.
29. **Case_029 (Phase 4, AWS, 5-alert rapid-response queue, ticket-only, Capital One-grounded):** A single point of failure (an SSRF-vulnerable WAF with an overprivileged IAM role) can cascade into a full data breach without any additional vulnerabilities or privilege escalation being needed — the entire I-002/I-003/I-004 chain was possible purely because the compromised role's existing permissions were broader than its documented purpose required, the same root cause as the real-world breach this scenario is grounded in. Correctly distinguished a live, active-exploitation chain from a routine, pre-existing, already-ticketed compliance finding (I-005) sharing the same queue but a different role entirely — same discrimination skill as Case_025 (E-002) and Case_027 (G-004), now the third consecutive case to include a deliberate unrelated-alert test. Zero corrections, 4-minute rapid-response triage time for a 5-alert queue.
30. **Case_030 (🏁 Phase 4 Capstone, Mixed Email + Cloud Identity + Endpoint, 7-alert queue with live interrupt, ticket-only, time pressure):** A full attack chain can span three previously-separate alert domains (email, cloud identity, endpoint) as one continuous incident, and the specific technique connecting two stages matters for the handoff, not just the fact that a stage occurred — naming "MFA fatigue / push bombing" (the real 2022 Uber technique) rather than just "MFA was satisfied" is the difference between a generic writeup and an actionable one for the next analyst. Correctly identified the fourth consecutive deliberate discrimination-test alert (J-006) despite time pressure and a live interrupt competing for attention in the same queue. Zero corrections across all 7 alerts, 3-minute total triage time for the full chain — matching the fastest pace in the repo despite this being the highest-alert-count single ticket outside the original Final Exam. Closes Phase 4 with a full shift-handoff deliverable, mirroring the structure established by Case_020.
31. **Case_031 (Phase 5 opens, AWS — IAM role chaining, 2-alert batch, ticket-only):** A privilege-escalation path built on transitive trust (an intermediate role's own permissions, not the originating user's) is specifically dangerous because it's invisible to a review of the originating identity's direct policy alone — this is the defining risk of role chaining as a technique, distinct from a simple over-permissive grant. Correctly reasoned that the *result* of the exposure (RDP opened to the entire internet on a production database security group) is critical regardless of whether the underlying cause turns out to be a serious mistake or deliberate action, since the immediate risk to the organization is identical either way. Zero corrections, 2-minute triage time. Opens Phase 5's cloud-weighted expansion (Cases 31-50, targeting 150 total alerts across the full repo).
32. **Case_032 (Phase 5, Azure AD — Conditional Access bypass via privilege misuse, 2-alert batch, ticket-only):** An unexplained privilege grant (Global Administrator on a standard Marketing account, no documented justification) is itself a red flag that should be caught independent of anything that happens afterward — the access-review process failure is a root cause worth escalating on its own, not just a footnote to the account takeover it enabled. Recognized that a self-service action using improper privilege to weaken one's own security controls (self-adding to an MFA/CA-bypass group) is a fundamentally different and more direct risk pattern than an admin action performed on behalf of the organization. Zero corrections, 4-minute triage time.
33. **Case_033 (Phase 5, GCP — service account key exfiltration, 2-alert batch, Splunk-verified, first GCP case in the repo):** Comparing a suspicious action directly against a confirmed-legitimate baseline in the same dataset (k.solanki's undocumented key creations vs. r.desai's change-ticket-backed ones) sharpens a "this seems unusual" judgment into a concrete, evidenced finding — the same discipline as checking Noise-Baselines before ruling on endpoint alerts in Phases 1-3, now applied to cloud IAM actions. Correctly required actual Splunk query output before accepting a verdict, holding the line on the repo's evidence-based methodology even under a fast "both TP" answer with no supporting screenshot initially provided. Zero corrections once verified, 4-minute triage time.
34. **Case_034 (Phase 5, Okta/SaaS third-party support access, 3-alert batch, ticket-only, Okta/Sitel 2022-grounded):** A compromised third-party support account's blast radius is defined by *scope*, not just volume — 14 password resets is concerning on its own, but the decisive detail is that they spread across 6 different customer tenants rather than staying within the engineer's single assigned tenant, mirroring the real Okta/Sitel incident's core risk (why hundreds of customers were initially flagged as potentially affected from compromise of one shared-service account). Correctly identified both the volume deviation and the scope deviation as separate, compounding factors rather than treating the alert as a single undifferentiated anomaly. Zero corrections, 3-minute triage time.
35. **Case_035 (Phase 5, Insider Threat, 3-alert batch, ticket-only, three unrelated employees, first case explicitly mixing all three verdict types after four consecutive all-TP cases):** Volume alone is not the deciding factor for insider-threat alerts — content and ownership matter more: 1,847 files of client/pricing/competitive data is TP, while 3 files of an employee's own HR-issued personal records is a fundamentally different risk category despite both being "unusual data movement" on the surface. Correctly resisted forcing a borderline case into a clean FP or TP bucket — Ambiguous, with a specific policy-violation note and a concrete verification step (confirm employment status), was the evidence-appropriate call when ownership/content argued one way but data-handling policy still technically applied. Reinforces a deliberate return to genuine TP/FP/Ambiguous variety after Cases 031-034 drifted into an unintentional all-TP streak — flagged directly by the analyst and corrected going forward as explicit repo methodology.
36. **Case_036 (Phase 5, Kubernetes — exposed dashboard cryptojacking, 3-alert batch, ticket-only, Tesla 2018-grounded):** A pre-existing, already-ticketed, non-urgent finding does not stay non-urgent forever — its risk status must be re-evaluated the moment new evidence shows active exploitation, which is the opposite lesson from Case_029's I-005 (a pre-existing finding that stayed correctly de-prioritized because it had no such correlation). The distinguishing factor between "leave it on the existing remediation timeline" and "escalate immediately" is not the finding's age or ticket status, but whether it's now connected to live, confirmed attacker activity. Correctly recognized a specific, named evasion technique (deliberately low resource throttling to avoid detection) as a decisive indicator rather than just "resource usage was a bit odd." Zero corrections, 3-minute triage time.
37. **Case_037 (Phase 5, CI/CD pipeline compromise, 3-alert batch, Splunk-verified, CircleCI 2023-grounded):** The decisive signal wasn't just location/timing anomalies on their own — it was a *session-type mismatch*: an interactive user session performing an action explicitly documented as automation-only (reading the production secrets context). This is a more precise version of "technique alone ≠ automatic TP" — here, the *action* was legitimate in the abstract (reading a context is routine), but the *actor type* performing it was the actual red flag, mirroring the real CircleCI breach where a compromised session token, not a novel exploit, was the entire attack vector. Zero corrections, 2-minute triage time.
38. **Case_038 (Phase 5, Azure Storage SAS token overexposure, 3-alert batch, ticket-only):** The same underlying mechanism (a SAS token) can be either a severe finding or a textbook example of proper practice depending entirely on configuration — R-001's account-wide Read+Write+Delete, ~2-year validity, undocumented, publicly-leaked token versus R-003's read-only, single-container, 7-day, fully-ticketed token are opposite ends of the same technology. Explicitly naming all three distinguishing factors (scope, expiration, documentation) rather than a vague "this one looks fine" strengthens the verdict into something auditable and teachable. Zero corrections, 3-minute triage time.
39. **Case_039 (Phase 5, AWS EC2 credential exfiltration + crypto-mining, 3-alert batch, ticket-only):** Reinforces Case_016's "routine events with zero aggravating factors should be FP" principle — S-003's blocked SSH scan attempts, from an attributed benign scanning source, against a correctly-configured security control, is FP on every available detail, contrasted directly against S-001/S-002's confirmed, successful compromise on a different instance. Notable process lesson: a fast initial read under time pressure produced an unstable first-pass verdict (TP → Ambiguous) before a full re-read settled on the correct FP — logged transparently as what actually happened (a reading-speed issue, not a reasoning flaw) rather than smoothed into a false zero-corrections record, consistent with this repo's standing honesty methodology even when directly pushed to omit it.
40. **Case_040 (Phase 5 Halfway Checkpoint, Mixed Cloud queue — Azure AD + AWS + GCP + Okta, 5-alert batch with live interrupt, ticket-only):** Established a precise, reusable distinction between "confirmed FP" and "genuinely Ambiguous": a real deviation from baseline paired with *direct, specific, dated confirming evidence* (a calendar entry matching the exact activity) is FP, not Ambiguous — Ambiguous is reserved for cases where the only available evidence is an *absence* of confirmation (as in Case_026's F-003), not a deviation that already has a positive explanation attached. Applied this distinction correctly to T-001 on the first pass and self-corrected T-003 from an initial Ambiguous to FP once the same standard was applied consistently. Confirmed, for the third time in the repo (after Case_025, Case_030), that a live interrupt (T-005) immediately reprioritizes response over continuing to process the remaining queue in order. 1 correction, 6-minute triage time for the full 5-alert checkpoint case.

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

**Case_025** (Mixed queue, 6-alert batch with live interrupt, ticket-only): adapted from the
May 2021 Colonial Pipeline / DarkSide ransomware attack (dormant VPN account, no MFA → lateral
movement → ~100GB exfiltration → ransomware). TP × 5 + FP × 1 (E-002, a deliberate
discrimination-test alert unrelated to the main chain). 1 correction — an initial surface-level
TP call on E-002 was corrected to FP after checking account/host/IP correlation against the
rest of the queue. Live interrupt (E-006, active file encryption) correctly triggered an
immediate re-prioritization from "investigate in order" to "contain first." 7-minute total
triage time. Splunk/ticket-only format now alternates case-by-case per repo methodology
(Case_024 Splunk → Case_025 ticket-only → Case_026 Splunk, etc.).

**Case_026** (Azure AD, 3-alert batch, Splunk-verified): FP (F-001, travel-calendar-confirmed
sign-in) + TP (F-002, password reset + second MFA method added without removing the original —
concrete persistence tradecraft) + Ambiguous (F-003, atypical-travel flag on an account with an
established legitimate travel baseline, MFA satisfied normally, only a missing calendar entry
as the sole anomaly). 1 correction — F-003 was initially called TP on surface pattern-matching
before being corrected to Ambiguous after directly comparing its evidence strength against
F-001 and F-002. Logged transparently per repo methodology even when asked directly to omit it
from the record.

**Case_027** (Mixed multi-domain queue — endpoint/AWS/email/endpoint, 4-alert batch,
ticket-only): TP (G-001, complete macro→LOLBin→execution chain) + TP (G-002, CI/CD account
total behavioral deviation exposing DB backups publicly) + Ambiguous (G-003, spoofed-executive
BEC email — strong technical indicators but analyst's final judgment weighed the absence of a
payload/link and zero recipient engagement) + FP (G-004, signed-binary Edge update matching
documented baseline exactly). No shared correlation found across the 4 alerts despite sharing
a queue. Notable for G-003: analyst and reviewer reasoning diverged, and both perspectives were
preserved in the case files rather than the record being adjusted to hide the disagreement —
directly tested when the analyst asked for a correction to be omitted from a prior case
(Case_026) and the repo's honesty methodology was upheld.

**Case_028** (Hybrid Identity — Azure AD + On-Prem AD, 4-alert batch, ticket-only): TP (H-001,
Kerberoasting via RC4-downgraded TGS request burst) + TP (H-002, Azure AD Connect sync/bridge
account compromised 3 minutes later by the same actor) + TP (H-003, unverified OAuth app
granted Directory.ReadWrite.All by the compromised bridge account 2 minutes after that) + FP
(H-004, documented automation account, routine scheduled GPO refresh). Full chain correctly
recognized as one hybrid-identity takeover spanning on-prem and cloud in under 6 minutes — the
sync/bridge account compromise (H-002) was identified as the pivotal escalation point that
turns a contained on-prem credential-theft attempt into full Azure AD directory control (H-003).
0 corrections, 3-minute triage time — fastest in the repo to date.

**Case_029** (AWS, 5-alert rapid-response queue, ticket-only): adapted from the July 2019
Capital One breach (SSRF against a misconfigured WAF → EC2 instance metadata credential theft →
mass S3 enumeration and exfiltration). TP × 4 (I-001 through I-004, one continuous incident
driven by a single root cause) + FP × 1 (I-005, a routine pre-existing compliance finding on an
unrelated IAM role, already tracked under an open ticket). 0 corrections, 4-minute
rapid-response triage time for 5 alerts. Third consecutive Phase 4 case to include a deliberate
discrimination-test alert, reinforcing that queue co-membership does not imply shared incident
membership as a now well-established pattern across this phase.

**Case_030 — 🏁 Phase 4 Capstone** (Mixed Email + Cloud Identity + Endpoint, 7-alert queue with
live interrupt, ticket-only, time pressure): a full attack chain spanning three previously
separate Phase 4 domains in one incident — phishing (J-001) → credential harvest (J-002) →
MFA-fatigue account takeover (J-003, explicitly naming the 2022 Uber technique) → mailbox
concealment (J-004) → lateral RDP movement (J-005) → active data staging for exfiltration
(J-007, live interrupt). TP × 6 + FP × 1 (J-006, fourth consecutive deliberate discrimination
test). 0 corrections, 3-minute total triage time for the full 7-alert chain — matching the
fastest pace in the repo. Closed with a full shift-handoff summary, mirroring Case_020's
capstone structure and formally closing out Phase 4.

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
CI/CD pipelines, SAS token governance) — the same underlying principles (technique alone ≠
automatic TP, confirmed correlation vs. assumed correlation, positive confirming evidence vs.
mere absence of red flags) recur in each new domain with only the surface details changing. The
Case_040 checkpoint reinforced that live-interrupt discipline (established in Case_025 and
Case_030) is now a consistently-applied skill rather than a one-off response to a novel format.

---

## Phase 5 Kickoff (Cases 31-50)

Phase 5 expands to 20 more cases targeting 49 additional alerts, bringing the repo to 50 cases
/ 150 alerts total. Deliberately weighted toward cloud and SaaS domains (AWS, Azure, GCP, Okta,
CI/CD, Kubernetes) — roughly 15 of 20 cases — since cloud alert volume was comparatively
underrepresented across Phases 1-4 relative to its real-world share of SOC alert queues.
Real-breach-grounding continues per the Phase 4 methodology, citing sources in investigation.md.
Verification method (ticket-only vs. Splunk) is decided per case as before. Phase 5 closes with
a second capstone (Case_050) spanning multiple cloud domains plus endpoint in one mega chain.

**Case_031** (AWS — IAM role chaining, 2-alert batch, ticket-only): TP (K-001, unauthorized
privilege escalation via a misconfigured transitive AssumeRole trust) + TP (K-002, critical —
RDP opened to the entire internet on a production database security group using the escalated
session). 0 corrections, 2-minute triage time. Grounded in the well-documented AWS role-chaining
escalation technique from cloud security research rather than a single named breach.

**Case_032** (Azure AD — Conditional Access bypass, 2-alert batch, ticket-only): TP (L-001, an
unexplained Global Administrator grant on a standard Marketing account used to self-add to a
service-account-only MFA/CA-bypass group) + TP (L-002, resulting legacy-protocol sign-in with no
MFA from a never-before-seen external IP). 0 corrections, 4-minute triage time. Notable for
identifying the unexplained privilege grant itself as a root-cause access-review failure worth
escalating independently, not just as context for the takeover it enabled.

**Case_033** (GCP — service account key exfiltration, 2-alert batch, Splunk-verified, first GCP
case in the repo): TP (M-001, an undocumented service account key created by a Support Analyst
with zero prior key-management history, no matching change ticket) + TP (M-002, critical — that
key used 21 minutes later from a never-before-seen external location to retrieve 8.2GB of
customer data). 0 corrections, 4-minute triage time. Investigation directly compared the
suspicious actor's activity against a confirmed-legitimate baseline present in the same dataset
to sharpen the finding from "seems unusual" to a concrete, evidenced conclusion.

**Case_034** (Okta/SaaS third-party support access, 3-alert batch, ticket-only): adapted from
the January 2022 Okta/Sitel breach (Lapsus$) — RDP access to a support engineer's laptop leading
to SuperUser-tier account abuse. TP (N-001, external RDP to a privileged support host) + TP
(N-002, new MFA factor added as a persistence mechanism during the suspicious session) + TP
(N-003, critical — 14 password resets across 6 different customer tenants in 25 minutes, vs. a
baseline of 2-3/day within one assigned tenant). 0 corrections, 3-minute triage time. Correctly
distinguished the volume deviation from the more critical scope deviation (multi-tenant spread)
as the decisive factor mirroring the real incident's blast-radius concern.

**Methodology note:** Cases 031-034 were unintentionally all-TP, a drift away from the
discrimination-testing variety established in Cases 025-030. Flagged by the analyst and
corrected explicitly going forward — every case from Case_035 onward deliberately mixes
TP/FP/Ambiguous outcomes rather than defaulting to confirmed-compromise chains.

**Case_035** (Insider Threat, 3-alert batch, ticket-only, three unrelated employees): TP
(O-001, pre-resignation mass exfiltration of client/pricing/competitive data to USB, off-hours)
+ Ambiguous (O-002, small volume of an employee's own personal HR documents sent to their own
email — content/ownership argue against malice, but the personal-email transmission is still a
policy consideration with no resignation context available either way) + FP (O-003, IT admin's
documented, scheduled, standing-access routine backup/DR verification). 0 corrections, 3-minute
triage time. First case since the methodology note above to genuinely span all three verdict
categories in one ticket.

**Case_036** (Kubernetes — exposed dashboard cryptojacking, 3-alert batch, ticket-only):
adapted from the February 2018 Tesla breach (unauthenticated Kubernetes Dashboard exploited for
cryptojacking with deliberate detection-evasion throttling). TP (P-001, re-escalated — a
3-week-old, already-ticketed non-urgent finding, re-classified as urgent once confirmed
exploited) + TP (P-002, critical — malicious pod deployed via the Dashboard UI with an unlisted
image and deliberately throttled CPU matching the real incident's evasion technique) + FP
(P-003, documented CI/CD service account activity tied to a traceable deployment record). 0
corrections, 3-minute triage time. Directly contrasts with Case_029's I-005 to reinforce that a
pre-existing finding's urgency depends on correlation with live activity, not its ticket age.

**Case_037** (CI/CD pipeline compromise, 3-alert batch, Splunk-verified): adapted from the
December 2022/January 2023 CircleCI breach (stolen 2FA-backed session token used to exfiltrate
production environment variables, tokens, and keys). TP (Q-001, session token used from a
never-before-seen location outside documented working hours) + TP (Q-002, critical — the same
session reading and bulk-exporting the production secrets context, a resource explicitly
documented as automation-only, never interactive) + FP (Q-003, fully automated, scheduled,
change-ticket-backed token rotation). 0 corrections, 2-minute triage time. Notable for
identifying a session-type mismatch (interactive vs. automated) as the decisive indicator,
rather than the action itself being unusual.

**Case_038** (Azure Storage — SAS token overexposure, 3-alert batch, ticket-only): TP (R-001,
an account-wide Read+Write+Delete SAS token with ~2-year validity leaked in a public GitHub
repo for 6 days) + TP (R-002, critical — the leaked token actively exploited immediately after
discovery, 550 read/list operations across 8 containers including customer invoices and
employee documents, versus the token's legitimate 2-3-PutBlob-per-booking baseline) + FP
(R-003, a read-only, single-container, 7-day, fully-ticketed SAS token — the inverse
configuration of R-001 in every dimension). 0 corrections, 3-minute triage time. Explicitly
contrasts two SAS token events to demonstrate that verdict depends on configuration and
documentation, not the underlying mechanism.

**Case_039** (AWS EC2 credential exfiltration + crypto-mining, 3-alert batch, ticket-only):
TP (S-001, DNS-rebinding attempt against an instance metadata service on a public-facing
instance with a documented unpatched vulnerability) + TP (S-002, critical — confirmed outbound
connection to a cryptocurrency mining pool 7 minutes later, same instance) + FP (S-003, blocked
SSH scan attempts from an attributed benign scanning service, zero successful connections,
unrelated internal instance). 1 correction — S-003's verdict moved through TP and Ambiguous
across a fast initial read under time pressure before settling on the correct FP on full review;
logged as a reading-speed issue rather than a reasoning error, per repo methodology.

**Case_040 — Phase 5 Halfway Checkpoint** (Mixed Cloud queue — Azure AD + AWS + GCP + Okta,
5-alert batch with live interrupt, ticket-only): FP (T-001, sign-in with a specific dated
calendar entry confirming the trip) + TP (T-002, unauthorized self-attached S3FullAccess policy,
no documented justification) + FP (T-003, query volume spike with a specific dated calendar
entry confirming the activity — corrected from an initial Ambiguous) + FP (T-004, documented
automated onboarding workflow) + TP (T-005, critical, live interrupt — confirmed exfiltration
of guest PII and financial data using T-002's unauthorized access). 1 correction, 6-minute
triage time. Established a reusable rule distinguishing confirmed-FP (deviation + positive
confirming evidence) from genuine Ambiguous (deviation + absence of confirming evidence either
way), directly correcting an inconsistent first-pass application of that standard within the
same case.

---

## Phase 4 Retrospective (Cases 021-030)

**Structure:** 10 cases spanning 4 new alert domains not covered in Cases 1-20 (Azure AD/cloud
identity, AWS, email/BEC, hybrid on-prem+cloud identity), alternating ticket-only and
Splunk-verified formats, real-breach-grounded scenarios (MGM Resorts 2023, Colonial Pipeline
2021, Capital One 2019, Uber 2022 technique), multiple live interrupts, deliberate
discrimination-test alerts in 4 consecutive cases (025, 027, 028's implicit baseline check, 029,
030), and a 7-alert capstone with a full shift-handoff deliverable closing the phase.

**Result:** 34 individually-triaged alerts across Cases 021-030, all correct final verdicts.
Two corrections logged across the phase — both self-caught and corrected during investigation
rather than missed: Case_025's E-002 (initial TP → corrected to FP after correlation check) and
Case_026's F-003 (initial TP → corrected to Ambiguous after evidence-strength comparison,
notably logged transparently even after being directly asked to omit it from the record).

**What this proved:** the investigative judgment built across Phases 1-3 — technique-alone
≠ automatic TP, normal-seeming ≠ automatic FP, correlation must be checked rather than assumed,
absence of confirming evidence ≠ positive evidence of compromise — transfers directly to
entirely new alert domains (cloud identity, AWS, hybrid identity, email/BEC) without needing to
relearn the underlying reasoning from scratch. The capstone (Case_030) closed the phase at the
same pace as the fastest single-domain cases in the repo (3 minutes for 7 alerts), despite
spanning three alert domains in one continuous chain — indicating the cross-domain correlation
skill is now as fluent as the single-domain pattern recognition built in Phases 1-3.

---

## Repo Status

Cases 1-20 (Phases 1-3) and Cases 21-30 (Phase 4) are both complete. The methodology —
investigating blind, documenting corrections honestly rather than hiding them, tracking real
(not fabricated) triage time, and since Case_024, grounding practice scenarios in real,
publicly documented breaches with fully sanitized IOCs — has been maintained consistently across
all 30 cases. The 101/101 correct final-verdict record reflects a deliberate investigative
process; the honestly-logged correction rate (2 corrections across all of Phase 4, both
self-caught) is the more informative metric for anyone reviewing this portfolio, alongside the
demonstrated ability to transfer core judgment skills into unfamiliar alert domains under time
pressure.

---

## Repo Completion Note (Cases 1-20)

This section reflects the full, closed history of the original 20 planned cases. The methodology — investigating blind, documenting corrections honestly rather than hiding them, and tracking real (not fabricated) triage time — was maintained consistently from Case_001 through Case_020, including through the Final Exam capstone. The 61/61 correct final-verdict record reflects a slower, more deliberate investigative process; the honestly-logged correction rate (a downward trend from ~50% early in Phase 3 drills toward more consistent first-pass accuracy by the Final Exam's second stage) is the more informative metric for anyone reviewing this portfolio. The repo has since expanded into Phase 4 (see above).
