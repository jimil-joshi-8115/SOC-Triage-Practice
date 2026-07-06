# 🛡️ SOC-Triage-Practice

Real SOC L1 alert triage practice — TP / FP / Ambiguous verdicts on simulated malicious events **injected into real background noise** on a live Windows host (JIMIL-JOSHI).

Unlike clean, isolated lab simulations, this repo mirrors actual SOC analyst queue work: alerts are investigated blind (no verdict given upfront), decoded/analyzed step by step, and closed with full justification — including cases where the initial assumption is wrong and has to be corrected mid-investigation.

Companion repo: [SOC-Lab-Splunk](https://github.com/jimil-joshi-8115/SOC-Lab-Splunk) — 16 foundational detection labs + 15 simulated attack scenarios + 4 Splunk dashboards.

---

## 📂 Repo Structure

```
SOC-Triage-Practice/
├── Cases/                     → Individual triage cases (ticket → investigation → verdict)
├── Noise-Baselines/           → Documented known-legitimate noise on JIMIL-JOSHI
├── Triage-Playbooks/          → Step-by-step triage methodology by alert type
└── Metrics/                   → Running scorecard of triage performance
```

---

## 📋 Case Index — ✅ ALL 20 CASES COMPLETE

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
| [Case_009](Cases/Case_009/) | **Phase 2 Batch 1:** New Service, DNS Beaconing, Get-Clipboard | Mixed (3 alerts) | T1543.003, T1071.004 | ✅ Closed |
| [Case_010](Cases/Case_010/) | **Phase 2 Batch 2:** vssadmin, GitHub Script, whoami/RDP | Mixed (3 alerts) | T1490, T1105 | ✅ Closed |
| [Case_011](Cases/Case_011/) | **Phase 2 Batch 3:** Disable Defender, mshta, tasklist/lsass | Mixed (3 alerts) | T1562.001, T1218.005, T1003.001 | ✅ Closed |
| [Case_012](Cases/Case_012/) | **Phase 2 Batch 4:** IEX Download, Admin Group Add, Outbound RDP | Mixed (3 alerts) | T1059.001, T1105, T1098 | ✅ Closed |
| [Case_013](Cases/Case_013/) | **Phase 2 Batch 5:** ScriptBlock Logging, ntds.dit Copy, 3 AM Logon | Mixed (3 alerts) | T1562, T1003.003, T1078 | ✅ Closed |
| [Case_014](Cases/Case_014/) | **Phase 2 Batch 6:** Firewall Port 4444, Outlook→PowerShell, wmic/whoami | Mixed (3 alerts) | T1562.004, T1204.002, T1047 | ✅ Closed |
| [Case_015](Cases/Case_015/) | **Phase 3 Batch 1:** Scheduled Task, Defender Disable (live interrupt), DNS DGA, Failed Logon, USB | Mixed (5 alerts) | T1053.005, T1562.001, T1071.004, T1052 | ✅ Closed |
| [Case_016](Cases/Case_016/) | **Phase 3 Batch 2:** Startup Download, Process Injection (EDR), External RDP Brute Force, Firewall Block, Print Spooler | Mixed (5 alerts) | T1105, T1547.001, T1055, T1110 | ✅ Closed |
| [Case_017](Cases/Case_017/) | **Phase 3 Batch 3:** Mimikatz Download, SMTP Exfil, Self-Add RDP Users, Backward Time Change | Mixed (4 alerts) | T1059.001, T1105, T1071, T1078 | ✅ Closed |
| [Case_018](Cases/Case_018/) | **Phase 3 Batch 4 (Rapid-Response):** Reverse Shell, Audit Policy Disabled, Chrome Extension, BitLocker Key | Mixed (4 alerts) | T1059.001, T1071, T1562 | ✅ Closed |
| [Case_019](Cases/Case_019/) | **🏁 Final Exam, Stage 1:** Download-Execute Malware, Tor Login, DNS Tunneling, AV-Enum Persistence + Mimikatz Confirmation (live interrupt) | Mixed (7 alerts) | T1105, T1078, T1071.004, T1518.001, T1003 | ✅ Closed |
| [Case_020](Cases/Case_020/) | **🏁 Final Exam, Stage 2:** SYSTEM C2 Callback, Kerberoasting, Self-Reported Phishing + Full Shift Handoff | Mixed (3 alerts) | T1071, T1558.003 | ✅ Closed |

**🎉 Repo complete: 20 cases, 61 individual alerts triaged, spanning single-alert deep investigation (Phase 1), batch prioritization (Phase 2), and full queue simulation under time pressure with live interrupts and cross-alert correlation (Phase 3), culminating in a 10-alert Final Exam that resolved into a single active multi-stage compromise.**

---

## 🧭 How a Case Is Triaged

1. **Ticket (README.md)** — Alert fires, raw Splunk event captured, no verdict given.
2. **Investigation (investigation.md)** — Step-by-step: decode/inspect payload, check parent process, check account context, check timing/repetition, check destination.
3. **Verdict (verdict.md)** — Final TP / FP / Ambiguous call, MITRE ATT&CK mapping (if TP), justification, what would change the verdict, response actions, triage time.

Cases followed a **phased difficulty structure**:
- **Phase 1 (Cases 5-8):** Ticket + raw data only, no checklist hints given — building independent investigation habits.
- **Phase 2 (Cases 9-14):** Mixed batches of 2-3 alerts with SIEM-style severity labels — building prioritization judgment.
- **Phase 3 (Cases 15-20):** Full queue simulation — multiple alerts, mixed formats (Splunk + EDR + ticket-only), live interrupts, cross-alert correlation, time pressure, and a 10-alert Final Exam culminating in a full shift-handoff deliverable.

---

## 📊 Progress

See [Metrics/triage_scorecard.md](Metrics/triage_scorecard.md) for full totals: cases closed, TP/FP/Ambiguous breakdown, accuracy, correction patterns, and key lessons learned across all 20 cases.

---

## 👤 Analyst

**Jimil Joshi** — SOC L1 Analyst (Fresher)
TryHackMe SOC L1 · Deloitte Cyber Job Simulation · TATA Cybersecurity Analyst Simulation (IAM) · Ministry of Home Affairs "Cyber Smart"
[LinkedIn](https://linkedin.com/in/jimil-joshi-soc-analyst) · [GitHub](https://github.com/jimil-joshi-8115)
