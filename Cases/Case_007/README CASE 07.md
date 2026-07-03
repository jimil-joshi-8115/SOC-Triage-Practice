# Case 007 — Registry Run Key Persistence

**Incident ID:** IR-2026-023
**Date Detected:** 2026-07-03
**Host:** JIMIL-JOSHI
**Reported By:** SOC Monitoring (Splunk Alert)
**Status:** 🔴 Open — Pending Triage

---

## 🎫 Alert Summary

| Field | Value |
|---|---|
| EventCode | 4688 (Process Creation) |
| Process | reg.exe |
| Account | hp |
| Computer | JIMIL-JOSHI |
| Trigger | `reg add` targeting HKCU Run key detected |

---

## 📄 Raw Event Data

**SPL Query Used:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*reg.exe"
| table _time, ComputerName, Account_Name, New_Process_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 10
```

**Result:**

| _time | ComputerName | Account_Name | New_Process_Name | Process_Command_Line | Creator_Process_Name |
|---|---|---|---|---|---|
| 2026-07-03 09:00:55.615 | JIMIL-JOSHI | hp | C:\Windows\System32\reg.exe | reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v SystemHealthCheck /t REG_SZ /d "powershell.exe -windowstyle hidden -c whoami" /f | cmd.exe |

---

## 🎯 Task

Triage this alert. Determine:
1. Is this TP / FP / Ambiguous?
2. What does adding a value to the Run key achieve?
3. Is `SystemHealthCheck` a real/documented Windows registry value name?
4. What is your final verdict and justification?
