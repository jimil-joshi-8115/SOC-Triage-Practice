# Case 002 — Local Account Creation Buried in Noise

**Incident ID:** IR-2026-018
**Date Detected:** 2026-07-02
**Host:** JIMIL-JOSHI
**Reported By:** SOC Monitoring (Splunk Alert)
**Status:** 🔴 Open — Pending Triage

---

## 🎫 Alert Summary

| Field | Value |
|---|---|
| EventCode | 4688 (Process Creation) |
| Process | net.exe |
| Account | hp |
| Computer | JIMIL-JOSHI |
| Trigger | `net.exe` executions detected, one containing `/add` flag |
| Event Count | 3 events within ~0.5 seconds |

---

## 📄 Raw Event Data

**SPL Query Used:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*net.exe"
| table _time, ComputerName, Account_Name, New_Process_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 10
```

**Results (3 events):**

| _time | ComputerName | Account_Name | New_Process_Name | Process_Command_Line | Creator_Process_Name |
|---|---|---|---|---|---|
| 2026-07-02 16:11:16.290 | JIMIL-JOSHI | hp | C:\Windows\SysWOW64\net.exe | "C:\WINDOWS\system32\net.exe" user | powershell.exe |
| 2026-07-02 16:11:16.160 | JIMIL-JOSHI | hp | C:\Windows\SysWOW64\net.exe | "C:\WINDOWS\system32\net.exe" user hpbackup Temp@2026 /add | powershell.exe |
| 2026-07-02 16:11:15.833 | JIMIL-JOSHI | hp | C:\Windows\SysWOW64\net.exe | "C:\WINDOWS\system32\net.exe" user | powershell.exe |

**Follow-up query attempted (Account Creation confirmation):**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4720
| table _time, ComputerName, Account_Name, Security_ID
| sort -_time
| head 5
```
**Result:** 0 events returned.

---

## 🎯 Task

Triage this alert. Determine:
1. Is this TP / FP / Ambiguous?
2. Which of the 3 `net.exe` events is the actual concerning action, and which are noise?
3. Is the account name (`hpbackup`) present in the known legitimate accounts baseline?
4. Why did the EventCode=4720 query return 0 results, and what does that mean for detection coverage?
5. What is your final verdict and justification?
