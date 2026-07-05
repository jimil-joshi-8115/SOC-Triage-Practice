# Case 013 — Phase 2 Batch: 3 Concurrent Alerts

**Incident ID:** IR-2026-029
**Date Detected:** 2026-07-05
**Host:** JIMIL-JOSHI
**Reported By:** SOC Monitoring (Splunk Alert)
**Status:** 🔴 Open — Pending Triage

**Phase:** 2 — Mixed batch triage.

---

## 🎫 Alert Summary — Batch of 3

| Alert | Type | SIEM-Assigned Severity |
|---|---|---|
| Alert M | PowerShell ScriptBlock logging disabled via registry | 🔴 High |
| Alert N | Copy of ntds.dit attempted | 🔴 High |
| Alert O | Interactive logon outside normal business hours (3:14 AM) | 🟡 Low |

---

## 📄 Raw Event Data

### Alert M
```
Process_Command_Line: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 0 /f
Account: hp | Parent: cmd.exe
```

### Alert N
```
Process_Command_Line: copy C:\Windows\NTDS\ntds.dit C:\Users\hp\AppData\Local\Temp\backup.dit
Account: hp | Parent: cmd.exe
```

### Alert O
```
Logon_Type: 2 (Interactive) | Time: 03:14 AM | Account: hp
```

---

## 🎯 Task

1. Determine triage order across all 3 alerts and justify it.
2. Investigate each alert independently.
3. Give a verdict (TP/FP/Ambiguous) for each with justification.
4. For Alert N: does the host being a non-Domain-Controller change whether this is TP?
5. For Alert O: does Logon_Type matter here, and how?
