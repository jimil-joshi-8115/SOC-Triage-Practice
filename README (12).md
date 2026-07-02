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

## 📋 Case Index

| Case | Title | Verdict | MITRE | Status |
|---|---|---|---|---|
| [Case_001](Cases/Case_001/) | Encoded PowerShell Execution | 🔴 TP | T1059.001, T1027, T1105 | ✅ Closed |
| [Case_002](Cases/Case_002/) | Local Account Creation Buried in Noise | 🔴 TP | T1136.001, T1059.001 | ✅ Closed |
| Case_003 | schtasks /create, legit-looking name | TBD | T1053.005 | ⏳ Planned |
| Case_004 | rundll32.exe firing | TBD | — | ⏳ Planned |
| Case_005 | Multiple failed logons, same account | TBD | T1110 | ⏳ Planned |
| Case_006 | Multiple failed logons, different accounts | TBD | T1110.003 | ⏳ Planned |
| Case_007 | reg add to Run key | TBD | T1547.001 | ⏳ Planned |
| Case_008 | certutil -urlcache | TBD | T1105 | ⏳ Planned |
| Case_009 | Get-Clipboard in PowerShell | TBD | T1115 | ⏳ Planned |
| Case_010 | nslookup to known domain | TBD | — | ⏳ Planned |
| Case_011 | nslookup repeated 3x same domain | TBD | T1071.004 | ⏳ Planned |
| Case_012 | whoami executed | TBD | — | ⏳ Planned |
| Case_013 | Log cleared (Event 1102) | TBD | T1070.001 | ⏳ Planned |
| Case_014 | Set-MpPreference -Disable | TBD | T1562.001 | ⏳ Planned |
| Case_015 | New service installed | TBD | — | ⏳ Planned |
| Case_016 | tasklist /fi lsass | TBD | T1003.001 | ⏳ Planned |
| Case_017 | Invoke-WebRequest to GitHub | TBD | T1105 | ⏳ Planned |
| Case_018 | Admin logon at unusual hour | TBD | T1078 | ⏳ Planned |
| Case_019 | vssadmin delete shadows | TBD | T1490 | ⏳ Planned |
| Case_020 | mshta.exe javascript: | TBD | T1218.005 | ⏳ Planned |

*Note: planned verdicts above are working hypotheses only — actual verdicts are determined during investigation and may differ from the plan, as happened with Case_001 (originally planned as FP, confirmed as TP after decoding the payload).*

---

## 🧭 How a Case Is Triaged

1. **Ticket (README.md)** — Alert fires, raw Splunk event captured, no verdict given.
2. **Investigation (investigation.md)** — Step-by-step: decode/inspect payload, check parent process, check account context, check timing/repetition, check destination.
3. **Verdict (verdict.md)** — Final TP / FP / Ambiguous call, MITRE ATT&CK mapping (if TP), justification, what would change the verdict, response actions, triage time.

---

## 📊 Progress

See [Metrics/triage_scorecard.md](Metrics/triage_scorecard.md) for running totals: cases closed, TP/FP/Ambiguous breakdown, accuracy, and common patterns.

---

## 👤 Analyst

**Jimil Joshi** — SOC L1 Analyst (Fresher)
TryHackMe SOC L1 · Deloitte Cyber Job Simulation · TATA Cybersecurity Analyst Simulation (IAM) · Ministry of Home Affairs "Cyber Smart"
[LinkedIn](https://linkedin.com/in/jimil-joshi-soc-analyst) · [GitHub](https://github.com/jimil-joshi-8115)
