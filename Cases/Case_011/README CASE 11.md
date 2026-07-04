# Case 011 — Phase 2 Batch: 3 Concurrent Alerts

**Incident ID:** IR-2026-027
**Date Detected:** 2026-07-04
**Host:** JIMIL-JOSHI
**Reported By:** SOC Monitoring (Splunk Alert)
**Status:** 🔴 Open — Pending Triage

**Phase:** 2 — Mixed batch triage.

---

## 🎫 Alert Summary — Batch of 3

| Alert | Type | SIEM-Assigned Severity |
|---|---|---|
| Alert G | Set-MpPreference -DisableRealtimeMonitoring | 🔴 High |
| Alert H | tasklist filtered for lsass.exe | 🟠 Medium |
| Alert I | mshta.exe running inline JavaScript | 🔴 High |

---

## 📄 Raw Event Data

### Alert G
```
Process_Command_Line: powershell.exe -c "Set-MpPreference -DisableRealtimeMonitoring $true"
Account: hp | Parent: cmd.exe
```

### Alert H
```
Process_Command_Line: tasklist /fi "imagename eq lsass.exe"
Account: hp | Parent: cmd.exe
```

### Alert I
```
Process_Command_Line: mshta.exe javascript:a=(new ActiveXObject("WScript.Shell")).Run("calc.exe",0,true);close();
Account: hp | Parent: cmd.exe
```

---

## 🎯 Task

1. Determine triage order across all 3 alerts and justify it.
2. Investigate each alert independently.
3. Give a verdict (TP/FP/Ambiguous) for each with justification.
4. For Alert H: does checking for a specific process by name (`lsass.exe`) alone confirm malicious intent, or only suspicious intent?
