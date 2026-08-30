# 🛡️ SOC-Triage-Practice — ✅ COMPLETE (50 Cases, 150 Alerts)

Real SOC L1 alert triage practice — TP / FP / Ambiguous verdicts on simulated malicious events **injected into real background noise** on a live Windows host (JIMIL-JOSHI), later expanded into cloud/SaaS ticket-and-Splunk-verified scenarios.

Unlike clean, isolated lab simulations, this repo mirrors actual SOC analyst queue work: alerts are investigated blind (no verdict given upfront), decoded/analyzed step by step, and closed with full justification — including cases where the initial assumption is wrong and has to be corrected mid-investigation, logged honestly rather than hidden.

Companion repo: [SOC-Lab-Splunk](https://github.com/jimil-joshi-8115/SOC-Lab-Splunk) — 16 foundational detection labs + 15 simulated attack scenarios + 4 Splunk dashboards.

---

## 📂 Repo Structure

```
SOC-Triage-Practice/
├── Cases/                     → 50 closed triage cases (ticket → investigation → verdict)
├── Noise-Baselines/           → Documented known-legitimate patterns, distilled from Phases 1-3
├── Triage-Playbooks/          → Step-by-step triage checklists by alert type, built from real case lessons
├── Metrics/                   → Full triage scorecard — accuracy, corrections, and key lessons across all 50 cases
└── Quickfire-Simulator/       → Standalone interactive tool: procedurally-generated TP/FP/Ambiguous drills
```

---

## 📋 Case Index — ✅ ALL 50 CASES COMPLETE (150 Alerts Officially Counted + 3 Bonus Exam Cases)

### Phase 1–3: Endpoint Foundations (Cases 1–20)

| Case | Title | Verdict | MITRE | Status |
|---|---|---|---|---|
| [Case_001](Cases/Case_001/) | Encoded PowerShell Execution | 🔴 TP | T1059.001, T1027, T1105 | ✅ Closed |
| [Case_002](Cases/Case_002/) | Local Account Creation Buried in Noise | 🔴 TP | T1136.001, T1059.001 | ✅ Closed |
| [Case_003](Cases/Case_003/) | Scheduled Task with Legitimate-Looking Name | 🟡 Ambiguous | T1053.005 | ✅ Closed |
| [Case_004](Cases/Case_004/) | rundll32.exe Execution | 🟢 FP | — | ✅ Closed |
| [Case_005](Cases/Case_005/) | Multiple Failed Logons, Same Account | 🔴 TP | T1110 | ✅ Closed |
| [Case_006](Cases/Case_006/) | Multiple Failed Logons, Different Accounts (Password Spray) | 🔴 TP | T1110.003 | ✅ Closed |
| [Case_007](Cases/Case_007/) | Registry Run Key Persistence | 🔴 TP | T1547.001 | ✅ Closed |
| [Case_008](Cases/Case_008/) | certutil.exe Living-off-the-Land Download | 🔴 TP | T1105 | ✅ Closed |
| [Case_009](Cases/Case_009/) | Phase 2 Batch 1: New Service, DNS Beaconing, Get-Clipboard | Mixed (3) | T1543.003, T1071.004 | ✅ Closed |
| [Case_010](Cases/Case_010/) | Phase 2 Batch 2: vssadmin, GitHub Script, whoami/RDP | Mixed (3) | T1490, T1105 | ✅ Closed |
| [Case_011](Cases/Case_011/) | Phase 2 Batch 3: Disable Defender, mshta, tasklist/lsass | Mixed (3) | T1562.001, T1218.005, T1003.001 | ✅ Closed |
| [Case_012](Cases/Case_012/) | Phase 2 Batch 4: IEX Download, Admin Group Add, Outbound RDP | Mixed (3) | T1059.001, T1105, T1098 | ✅ Closed |
| [Case_013](Cases/Case_013/) | Phase 2 Batch 5: ScriptBlock Logging, ntds.dit Copy, 3 AM Logon | Mixed (3) | T1562, T1003.003, T1078 | ✅ Closed |
| [Case_014](Cases/Case_014/) | Phase 2 Batch 6: Firewall Port 4444, Outlook→PowerShell, wmic/whoami | Mixed (3) | T1562.004, T1204.002, T1047 | ✅ Closed |
| [Case_015](Cases/Case_015/) | Phase 3 Batch 1: Scheduled Task, Defender Disable (live interrupt), DNS DGA, Failed Logon, USB | Mixed (5) | T1053.005, T1562.001, T1071.004, T1052 | ✅ Closed |
| [Case_016](Cases/Case_016/) | Phase 3 Batch 2: Startup Download, Process Injection (EDR), External RDP Brute Force, Firewall Block, Print Spooler | Mixed (5) | T1105, T1547.001, T1055, T1110 | ✅ Closed |
| [Case_017](Cases/Case_017/) | Phase 3 Batch 3: Mimikatz Download, SMTP Exfil, Self-Add RDP Users, Backward Time Change | Mixed (4) | T1059.001, T1105, T1071, T1078 | ✅ Closed |
| [Case_018](Cases/Case_018/) | Phase 3 Batch 4 (Rapid-Response): Reverse Shell, Audit Policy Disabled, Chrome Extension, BitLocker Key | Mixed (4) | T1059.001, T1071, T1562 | ✅ Closed |
| [Case_019](Cases/Case_019/) | 🏁 Final Exam, Stage 1: Download-Execute Malware, Tor Login, DNS Tunneling, AV-Enum Persistence + Mimikatz (live interrupt) | Mixed (7) | T1105, T1078, T1071.004, T1518.001, T1003 | ✅ Closed |
| [Case_020](Cases/Case_020/) | 🏁 Final Exam, Stage 2: SYSTEM C2 Callback, Kerberoasting, Self-Reported Phishing + Full Shift Handoff | Mixed (3) | T1071, T1558.003 | ✅ Closed |

### Phase 4: Cloud & Email Domains Introduced (Cases 21–30)

| Case | Title | Verdict | MITRE | Status |
|---|---|---|---|---|
| [Case_021](Cases/Case_021/) | Azure AD — Risky Sign-In + Legacy Auth MFA Bypass | 🔴 TP | T1078 | ✅ Closed |
| [Case_022](Cases/Case_022/) | Email/BEC — Phishing Report + Impossible Travel + Malicious Inbox Rule + Payment Fraud | Mixed (3) | T1078, T1114.003, T1114 | ✅ Closed |
| [Case_023](Cases/Case_023/) | AWS GuardDuty — Tor Console Login + IAM Privilege Escalation | Mixed (2) | T1078.004, T1087.004, T1136.003 | ✅ Closed |
| [Case_024](Cases/Case_024/) | Mixed Endpoint+Cloud (5): Helpdesk Vishing → Okta Takeover → Rogue IdP → Ransomware Staging *(MGM Resorts 2023-grounded)* | Mixed (5) | T1598, T1078.004, T1556, T1098, T1562.001, T1490 | ✅ Closed |
| [Case_025](Cases/Case_025/) | Mixed Queue (6, live interrupt): Dormant VPN Account → Lateral Movement → Exfiltration → Ransomware *(Colonial Pipeline-grounded)* | Mixed (6) | T1078, T1021.002, T1041, T1053.005, T1486 | ✅ Closed |
| [Case_026](Cases/Case_026/) | Azure AD (3): Travel-Confirmed Sign-In, MFA-Hijack Takeover, Inconclusive Atypical-Travel Flag | Mixed (3) | T1078.004, T1556.006 | ✅ Closed |
| [Case_027](Cases/Case_027/) | Mixed Multi-Domain Queue (4): LOLBin Delivery, Public S3 Exposure, Spoofed-Executive Email, Routine Task | Mixed (4) | T1566.001, T1105, T1530 | ✅ Closed |
| [Case_028](Cases/Case_028/) | Hybrid Identity (4): Kerberoasting → Azure AD Sync Account Compromise → Rogue OAuth App | Mixed (4) | T1558.003, T1078, T1098 | ✅ Closed |
| [Case_029](Cases/Case_029/) | AWS Rapid-Response (5): SSRF Against WAF → IAM Credential Theft → Mass S3 Exfiltration *(Capital One 2019-grounded)* | Mixed (5) | T1190, T1552.005, T1526, T1619, T1567 | ✅ Closed |
| [Case_030](Cases/Case_030/) | 🏁 Phase 4 Capstone (7, live interrupt): Phishing → MFA-Fatigue Takeover → Concealment → Lateral RDP → Exfiltration Staging *(Uber 2022 technique)* + Shift Handoff | Mixed (7) | T1566.002, T1621, T1564.008, T1021.001, T1560.001 | ✅ Closed |

### Phase 5: Cloud-Weighted Expansion (Cases 31–47, 150-Alert Target)

| Case | Title | Verdict | MITRE | Status |
|---|---|---|---|---|
| [Case_031](Cases/Case_031/) | AWS — IAM Role Chaining → Production DB Security Group Exposure | Mixed (2) | T1078.004, T1562.007 | ✅ Closed |
| [Case_032](Cases/Case_032/) | Azure AD — Unexplained Global Admin Grant → Self-Exemption from Conditional Access | Mixed (2) | T1078.004, T1556.009 | ✅ Closed |
| [Case_033](Cases/Case_033/) | GCP — Unauthorized Service Account Key → External Customer Data Exfiltration *(first GCP case)* | Mixed (2) | T1078.004, T1530 | ✅ Closed |
| [Case_034](Cases/Case_034/) | Okta/SaaS — Third-Party Support Engineer Compromise → Multi-Tenant Abuse *(Okta/Sitel 2022-grounded)* | Mixed (3) | T1021.001, T1556 | ✅ Closed |
| [Case_035](Cases/Case_035/) | Insider Threat (3, three unrelated employees): Pre-Resignation Exfiltration, Personal-Email Policy Question, Routine Access | Mixed (3) | T1052.001 | ✅ Closed |
| [Case_036](Cases/Case_036/) | Kubernetes — Unauthenticated Dashboard Exploited for Cryptojacking *(Tesla 2018-grounded)* | Mixed (3) | T1190, T1610, T1496 | ✅ Closed |
| [Case_037](Cases/Case_037/) | CI/CD — Stolen Session Token Used to Exfiltrate Production Secrets *(CircleCI 2023-grounded)* | Mixed (3) | T1539, T1078, T1552 | ✅ Closed |
| [Case_038](Cases/Case_038/) | Azure Storage — SAS Token Leaked to Public GitHub Repo, Exploited | Mixed (3) | T1552.001, T1078.004, T1530 | ✅ Closed |
| [Case_039](Cases/Case_039/) | AWS EC2 — Metadata Rebinding → Cryptocurrency Mining, Plus Blocked Routine Scan | Mixed (3) | T1190, T1552.005, T1496 | ✅ Closed |
| [Case_040](Cases/Case_040/) | 🎯 Phase 5 Halfway Checkpoint — Mixed Cloud Queue (5, live interrupt): Unauthorized S3 Access → Active Exfiltration | Mixed (5) | T1078.004, T1530, T1567 | ✅ Closed |
| [Case_041](Cases/Case_041/) | Supply Chain — Trojanized Monitoring Platform Update → Delayed DGA Beaconing *(SolarWinds 2020-grounded)* | Mixed (3) | T1195.002, T1568.002 | ✅ Closed |
| [Case_042](Cases/Case_042/) | Azure AD — Trusted Location Policy Modified for Tenant-Wide MFA Bypass Persistence | Mixed (3) | T1556.009, T1078.004 | ✅ Closed |
| [Case_043](Cases/Case_043/) | AWS S3 — SSE-C Ransomware via Compromised Credentials *(Codefinger 2025-grounded)* | Mixed (3) | T1078.004, T1619, T1486, T1485 | ✅ Closed |
| [Case_044](Cases/Case_044/) | Cloud Misconfiguration — Unauthenticated Public MongoDB → Extortion | Mixed (3) | T1595, T1530, T1485 | ✅ Closed |
| [Case_045](Cases/Case_045/) | AI Voice/Video-Clone BEC — Spoofed CFO Email + Deepfake Call Bypasses Dual-Approval *(Arup 2024-grounded)* | Mixed (3) | T1566.001, T1036, T1657 | ✅ Closed |
| [Case_046](Cases/Case_046/) | SaaS Developer Token Theft — Stolen GitHub PAT Clones Private Repos *(Slack 2022-grounded)* | Mixed (3) | T1078, T1552, T1213 | ✅ Closed |
| [Case_047](Cases/Case_047/) | 🎯 **150-Alert Milestone** — Azure Hybrid Identity: Unauthorized Federated Domain Trust | Mixed (2) | T1556 | ✅ Closed |

### 🏁 Bonus Final Exam (Cases 48–50, Not Counted Toward the 150-Alert Total)

| Case | Title | Verdict | MITRE | Status |
|---|---|---|---|---|
| [Case_048](Cases/Case_048/) | 🏁 Bonus Exam Stage 1 (6, live interrupt): Okta→AWS Account Takeover + Separate Endpoint Incident | Mixed (6) | T1078, T1136.003, T1105, T1496 | ✅ Closed |
| [Case_049](Cases/Case_049/) | 🏁 Bonus Exam Stage 2 (5): Credential Dumping → Domain Controller Pivot, Confirmed Cryptomining, S3 Lockout | Mixed (5) | T1003.001, T1496, T1550 | ✅ Closed |
| [Case_050](Cases/Case_050/) | 🏁 FINAL CAPSTONE, Stage 3 (3, live interrupt): Legitimate Remediation vs. Concurrent Compromised-Credential Attack + Full Shift Handoff | Mixed (3) | T1078, T1098.003 | ✅ Closed |

**50 cases, 150 individually-triaged alerts officially counted (target reached at Case_047), plus 3 bonus Final-Exam-style cases (14 additional alerts) closing the repo with a multi-stage, cross-domain incident spanning cloud identity, AWS, endpoint compromise, and Active Directory — spanning single-alert deep investigation (Phase 1), batch prioritization (Phase 2), full queue simulation under time pressure (Phase 3), and expansion into cloud, SaaS, and hybrid-identity domains grounded in real, publicly documented breaches (Phases 4–5).**

---

## How a Case Was Triaged

1. **Ticket (README.md)** — Alert fires, raw event data captured, no verdict given.
2. **Investigation (investigation.md)** — Step-by-step: decode/inspect payload or action, check actor/role context, check timing/correlation, check against documented baselines, compare against confirmed-legitimate examples where available.
3. **Verdict (verdict.md)** — Final TP / FP / Ambiguous call, MITRE ATT&CK mapping (if TP), justification, what would change the verdict, response actions, triage time, and — from Case_024 onward — the real public breach a scenario was grounded in, where applicable.

Cases followed a phased difficulty structure:
- **Phase 1 (Cases 5-8):** Ticket + raw data only, no checklist hints given — building independent investigation habits.
- **Phase 2 (Cases 9-14):** Mixed batches of 2-3 alerts with SIEM-style severity labels — building prioritization judgment.
- **Phase 3 (Cases 15-20):** Full queue simulation — multiple alerts, mixed formats (Splunk + EDR + ticket-only), live interrupts, cross-alert correlation, time pressure, and a 10-alert Final Exam culminating in a full shift-handoff deliverable.
- **Phase 4 (Cases 21-30):** New alert domains — Azure AD/cloud identity, AWS, and Business Email Compromise — using realistic SOC-tool ticket formats (Microsoft Sentinel, Defender for Office 365), some Splunk-verified against sample cloud log data. First cases grounded in real, publicly documented breaches (MGM Resorts, Colonial Pipeline, Capital One, Uber's MFA-fatigue technique). Closed with a second, cross-domain capstone.
- **Phase 5 (Cases 31-50):** Deliberately cloud-weighted expansion — AWS, Azure, GCP, Okta/SaaS, Kubernetes, and CI/CD pipelines — reaching the project's 150-alert target at Case_047, followed by a 3-stage bonus Final Exam (Cases 48-50) converging two originally-unrelated incidents into a single multi-domain compromise via a shared harvested credential.

---

## Real-World Breach Grounding (Phase 4 Onward)

Starting with Case_024, scenarios are explicitly adapted from real, publicly documented security
incidents rather than fully original inventions — company names, users, IPs, and timestamps are
fully sanitized/fictional, but the attack chain structure mirrors the real event, cited directly
in each case's `investigation.md`:

| Real Incident | Case(s) |
|---|---|
| MGM Resorts (2023, Scattered Spider) | Case_024 |
| Colonial Pipeline (2021, DarkSide) | Case_025 |
| Capital One (2019, SSRF/WAF) | Case_029 |
| Uber (2022, MFA fatigue technique) | Case_030 |
| Okta/Sitel (2022, Lapsus$) | Case_034 |
| Tesla Kubernetes Dashboard (2018) | Case_036 |
| CircleCI (2022/2023) | Case_037 |
| SolarWinds/SUNBURST (2020) | Case_041 |
| Codefinger AWS S3 SSE-C Ransomware (2025) | Case_043 |
| Arup Deepfake Fraud (2024) | Case_045 |
| Slack GitHub Breach (2022) | Case_046 |

---

## Noise-Baselines & Triage-Playbooks

These two folders are the distilled output of the Phase 1-3 investigation work — not generic
theory, but reference material built directly from confirmed verdicts across this repo, with
every rule traceable back to the specific case that established it.

**Noise-Baselines/** — documented FP patterns to check before investigating a new alert from scratch:
- `known_legitimate_processes.md` — confirmed-benign process/command patterns (e.g. rundll32+PcaSvc, routine diagnostics)
- `known_legitimate_accounts.md` — the standard account baseline vs. confirmed masquerading account patterns
- `known_legitimate_services.md` — routine vs. security-critical service actions, plus firewall rule direction logic

**Triage-Playbooks/** — step-by-step checklists per alert type, each rule tied to the case that proved it:
- `failed_logon_triage.md`
- `process_creation_triage.md`
- `powershell_triage.md`
- `scheduled_task_triage.md`

---

## Quickfire-Simulator

A standalone, self-contained interactive tool (`Quickfire-Simulator/index.html`) — procedurally generates realistic SOC alerts across 13 rule-based categories (process downloads, scheduled tasks, group changes, firewall rules, failed logons, EDR detections, and more), each resolving to a computed TP/FP/Ambiguous verdict with real reasoning. No two sessions repeat identical alerts. Includes live per-ticket timing, streaks, and milestone scorecards (accuracy + mean time to resolve) every 30 tickets — built to mirror the format of timed, externally-graded SOC drills.

Runs entirely in the browser — no server, no dependencies. Can be hosted live via GitHub Pages for a shareable link.

---

## Progress

See [Metrics/triage_scorecard.md](Metrics/triage_scorecard.md) for the full case-by-case log:
every verdict, every correction made and why (including cases where an initial verdict was
walked back — logged honestly, not hidden, even under direct pressure to omit one), real
(not fabricated) triage times, and the key lessons distilled from all 50 cases.

**Final numbers:** 50 cases closed · 150 officially-counted alerts (+ 14 bonus alerts across
Cases 48-50) · correction rate transparently tracked throughout · methodology consistent from
Case_001 through the final shift-handoff.

---

## Analyst

**Jimil Joshi** — SOC L1 Analyst (Fresher)
TryHackMe SOC L1 · Deloitte Cyber Job Simulation · TATA Cybersecurity Analyst Simulation (IAM) · Ministry of Home Affairs "Cyber Smart"
[LinkedIn](https://linkedin.com/in/jimil-joshi-soc-analyst) · [GitHub](https://github.com/jimil-joshi-8115)
