# Investigation — Case 015 (Phase 3: Full Queue Simulation)

## Initial Prioritization Decision

**Chosen order: T → U → S → V**

**Justification:**
- **Alert T first** — a scheduled task combining a masquerading name, SYSTEM privilege, an off-hours daily trigger, and encoded PowerShell represents the most severe combination in the initial queue; prioritized above the other three regardless of label ties.
- **Alert U second** — a DNS query pattern with varying subdomains could indicate an active C2/DGA channel; checked before the lower-priority items.
- **Alert S third** — a low-volume failed logon pattern is a weaker signal than higher-priority items; appropriately triaged after them.
- **Alert V last** — a USB connection alone, with no corroborating activity, carries the lowest standalone urgency of the four.

## Mid-Investigation Interrupt Decision

**New alert (W) arrived while investigating T.** Decision: pause the original queue order to handle W immediately, then resume with T → W → U → S → V.

**Justification:** An active defense-evasion action (Defender disable) can mask or enable other malicious activity to proceed undetected — including activity related to the very alert in progress (T). Prioritizing an active evasion action over continuing a mid-investigation item mirrors the reasoning applied in Case_011 (Alert G handled first for the same reason) and reflects realistic SOC judgment: some interruptions genuinely outrank in-progress work.

---

## Alert T — New Scheduled Task (AdobeUpdateSvc)

**SPL Query:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*schtasks.exe"
| table _time, ComputerName, Account_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 5
```

**Result:** `schtasks /create /tn "AdobeUpdateSvc" /tr "powershell.exe -enc <base64>" /sc daily /st 03:00 /ru SYSTEM`, parent `cmd.exe`.

**Findings:**
- 🔴 `AdobeUpdateSvc` masquerades as a legitimate Adobe update service name, consistent with the naming pattern in Case_002, Case_007, and Case_014.
- 🔴 `/ru SYSTEM` grants full system privilege to the task.
- 🔴 `/sc daily /st 03:00` establishes a persistent, off-hours daily trigger — timing chosen to minimize the chance of user observation.
- 🟡 The encoded PowerShell payload's specific content is not the deciding factor — the combination of masquerading name, SYSTEM privilege, and off-hours persistence is decisive on its own, consistent with the reasoning applied to Case_007's registry persistence.

**Verdict: 🔴 TP — T1053.005 (Scheduled Task/Job: Scheduled Task)**

---

## Alert W — Set-MpPreference (Disable Defender)

**SPL Query:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*powershell.exe" Process_Command_Line="*Set-MpPreference*"
| table _time, ComputerName, Account_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 5
```

**Result:** `Set-MpPreference -DisableRealtimeMonitoring $true`, parent `cmd.exe`.

**Findings:**
- 🔴 Disables Windows Defender's real-time protection — a defense-evasion action with no legitimate end-user justification, decisive on command content alone (same pattern as Case_011's Alert G).

**Verdict: 🔴 TP — T1562.001 (Impair Defenses)**

---

## Alert U — DNS Query Pattern (Varying Subdomains)

**SPL Query:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*nslookup.exe"
| table _time, ComputerName, Account_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 10
```

**Result:** 7 events, `a1.cdn-analytics-sync.net` through `a7.cdn-analytics-sync.net`, within approximately 90 seconds, parent `cmd.exe`.

**Findings:**
- 🟠 Querying **varying subdomains** of the same base domain in rapid succession is a stronger structural indicator than simple repeated identical queries (compare Case_009's Alert C, which queried the same domain 3x) — this pattern is consistent with Domain Generation Algorithm (DGA) or fast-flux C2 infrastructure, where malware rotates through subdomains to evade static blocklists.
- 🟡 However, no resolved IP reputation check, follow-up network connection, or confirmed malicious response was available in this dataset. A strong technique-level pattern match does not, by itself, confirm a malicious outcome — consistent with the technique-vs-outcome principle applied throughout this repo (Case_003, Case_011 Alert H, Case_014 Alert P).

**Verdict: 🟡 Ambiguous — T1071.004/T1568 (DGA-adjacent pattern, unconfirmed outcome)**

---

## Alert S — Failed Logon x2

**SPL Query:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
| table _time, ComputerName, Account_Name, Logon_Type, Failure_Reason
| sort -_time
| head 5
```

**Result:** 2 failed attempts, account `hp`, Logon_Type 2 (Interactive), ~10 seconds apart.

**Findings:**
- 🟡 A volume of only 2 failed attempts is meaningfully lower than Case_005's clear 5-attempt brute-force pattern, and is genuinely explainable as ordinary user mistyping.
- 🟡 However, low volume alone does not confirm legitimacy either — it equally represents insufficient evidence to rule out an attacker's early, low-volume attempts before adjusting approach. Unlike Case_005, there isn't enough repetition here to confidently match a known attack pattern in either direction.

**Verdict: 🟡 Ambiguous**

---

## Alert V — USB Mass Storage Device Connected

**Given Data (ticket-based, no live reproduction):**
```
Device: USB Mass Storage Device connected | Time: 2:15 PM | Account: hp | Drive letter: E:
```

**Findings:**
- 🟡 No baseline exists documenting authorized USB devices or normal USB usage patterns for this account/host (no equivalent entry in `Noise-Baselines/`).
- 🟡 Business-hours timing does not establish legitimacy — unlike Case_013's Alert O, where *unusual* timing was itself the concerning signal, here *normal* timing provides no positive evidence of legitimacy either, since malicious USB use is not restricted to off-hours.
- 🟡 No corroborating data (file-copy activity following the connection, device serial/vendor reputation) is available to confirm or rule out exfiltration intent (T1052).

**Verdict: 🟡 Ambiguous — T1052 (Exfiltration via Removable Media, unconfirmed)**

---

## Summary Table

| Alert | Verdict | MITRE | SIEM Label vs. Reality |
|---|---|---|---|
| T — Scheduled Task | 🔴 TP | T1053.005 | High label matched reality |
| W — Defender Disable (interrupt) | 🔴 TP | T1562.001 | High label matched reality |
| U — DNS Varying Subdomains | 🟡 Ambiguous | T1071.004/T1568 | Medium label matched reality |
| S — 2 Failed Logons | 🟡 Ambiguous | — | Low label matched reality |
| V — USB Connected | 🟡 Ambiguous | T1052 | Info label underestimated the genuine evidentiary gap |
