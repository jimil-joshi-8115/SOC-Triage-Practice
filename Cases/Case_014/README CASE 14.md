# Case 014 — Phase 2 Batch: 3 Concurrent Alerts (Final Phase 2 Batch)

**Incident ID:** IR-2026-030
**Date Detected:** 2026-07-05
**Host:** JIMIL-JOSHI
**Reported By:** SOC Monitoring (Splunk Alert)
**Status:** 🔴 Open — Pending Triage

**Phase:** 2 — Mixed batch triage (final batch of Phase 2).

---

## 🎫 Alert Summary — Batch of 3

| Alert | Type | SIEM-Assigned Severity |
|---|---|---|
| Alert P | wmic process call create (remote-style execution) | 🟠 Medium |
| Alert Q | Outlook spawning PowerShell | 🔴 High |
| Alert R | New firewall rule allowing inbound on high port | 🔴 High |

---

## 📄 Raw Event Data

### Alert P
```
Process_Command_Line: wmic process call create "cmd.exe /c whoami > C:\Users\hp\AppData\Local\Temp\out.txt"
Account: hp | Parent: cmd.exe
```

### Alert Q
```
Process_Command_Line: powershell.exe -enc <base64>
Account: hp | Parent: OUTLOOK.EXE
```

### Alert R
```
Process_Command_Line: netsh advfirewall firewall add rule name="UpdateSvc" dir=in action=allow protocol=TCP localport=4444
Account: hp | Parent: cmd.exe
```

---

## 🎯 Task

1. Determine triage order across all 3 alerts and justify it.
2. Investigate each alert independently.
3. Give a verdict (TP/FP/Ambiguous) for each with justification.
4. For Alert Q: does the parent process matter more than the encoded command content here?
5. For Alert P: does a known technique (WMI remote execution) automatically mean TP, regardless of the specific action performed?
