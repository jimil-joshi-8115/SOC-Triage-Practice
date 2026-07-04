# Case 009 — Phase 2 Batch: 3 Concurrent Alerts

**Incident ID:** IR-2026-025
**Date Detected:** 2026-07-04
**Host:** JIMIL-JOSHI
**Reported By:** SOC Monitoring (Splunk Alert)
**Status:** 🔴 Open — Pending Triage

**Phase:** 2 — Mixed batch triage. Analyst receives multiple alerts simultaneously with SIEM-assigned severity labels and must determine investigation order independently, then triage each.

---

## 🎫 Alert Summary — Batch of 3

| Alert | Type | SIEM-Assigned Severity |
|---|---|---|
| Alert A | Get-Clipboard PowerShell activity | 🟡 Low |
| Alert B | New local service installed | 🔴 High |
| Alert C | nslookup to external domain, repeated 3x | 🟠 Medium |

---

## 📄 Raw Event Data

### Alert A
```
Process_Command_Line: powershell.exe -c "Get-Clipboard"
Account: hp | Parent: cmd.exe
```

### Alert B
```
New service name: "WinDefenderHelper"
Binary path: C:\Users\hp\AppData\Local\Temp\svc.exe
Account: SYSTEM (service context)
```

### Alert C
```
nslookup update-cdn-cache.com (x3 within ~40 seconds)
Account: hp | Parent: cmd.exe
```

---

## 🎯 Task

1. **Before investigating**, determine your triage order across all 3 alerts and justify it — do not default to following the SIEM severity labels blindly.
2. Investigate each alert independently (own checklist, no hints).
3. Give a verdict (TP/FP/Ambiguous) for each alert with justification.
4. Reflect: did the SIEM-assigned severity match reality for each alert?
