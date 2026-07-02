# Case 004 — rundll32.exe Execution

**Incident ID:** IR-2026-020
**Date Detected:** 2026-07-02
**Host:** JIMIL-JOSHI
**Reported By:** SOC Monitoring (Splunk Alert)
**Status:** 🔴 Open — Pending Triage

---

## 🎫 Alert Summary

| Field | Value |
|---|---|
| EventCode | 4688 (Process Creation) |
| Process | rundll32.exe |
| Account | hp |
| Computer | JIMIL-JOSHI |
| Trigger | `rundll32.exe` execution detected |

---

## 📄 Raw Event Data

**SPL Query Used:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*rundll32.exe"
| table _time, ComputerName, Account_Name, New_Process_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 10
```

**Result:**

| Field | Value |
|---|---|
| New_Process_Name | rundll32.exe |
| Process_Command_Line | rundll32.exe PcaSvc.dll,PcaPatchSdbTask |
| Account_Name | hp |
| ComputerName | JIMIL-JOSHI |

---

## 🎯 Task

Triage this alert. Determine:
1. Is this TP / FP / Ambiguous?
2. Does the DLL and exported function match a documented legitimate pattern?
3. What is your final verdict and justification?
