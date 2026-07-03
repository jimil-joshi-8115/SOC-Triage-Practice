# Case 005 — Multiple Failed Logons, Same Account

**Incident ID:** IR-2026-021
**Date Detected:** 2026-07-03
**Host:** JIMIL-JOSHI
**Reported By:** SOC Monitoring (Splunk Alert)
**Status:** 🔴 Open — Pending Triage

---

## 🎫 Alert Summary

| Field | Value |
|---|---|
| EventCode | 4625 (Failed Logon) |
| Account | hp |
| Computer | JIMIL-JOSHI |
| Logon Type | 2 (Interactive) |
| Trigger | 5 failed logon attempts, same account, ~13 second window |

---

## 📄 Raw Event Data

**SPL Query Used:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
| table _time, ComputerName, Account_Name, Logon_Type, Failure_Reason, Creator_Process_Name
| sort -_time
| head 5
```

**Results (5 events):**

| _time | ComputerName | Account_Name | Logon_Type | Failure_Reason |
|---|---|---|---|---|
| 2026-07-03 08:12:55.792 | JIMIL-JOSHI | hp | 2 | Unknown user name or bad password. |
| 2026-07-03 08:12:52.885 | JIMIL-JOSHI | hp | 2 | Unknown user name or bad password. |
| 2026-07-03 08:12:48.237 | JIMIL-JOSHI | hp | 2 | Unknown user name or bad password. |
| 2026-07-03 08:12:45.683 | JIMIL-JOSHI | hp | 2 | Unknown user name or bad password. |
| 2026-07-03 08:12:42.125 | JIMIL-JOSHI | hp | 2 | Unknown user name or bad password. |

**Follow-up query (Successful Logon / Lockout check):**
```spl
index=* sourcetype="WinEventLog:Security" (EventCode=4624 OR EventCode=4740) Account_Name="hp"
| table _time, EventCode, ComputerName, Account_Name, Logon_Type
| sort -_time
| head 5
```

**Result:** 4 events, all EventCode=4624, timestamps **07:54:49 and 07:56:34** — both **before** the failed attempts began at 08:12:42. No EventCode=4740 (lockout) present. No successful logon occurred after the failed attempts.

---

## 🎯 Task

Triage this alert. Determine:
1. Is this TP / FP / Ambiguous?
2. Does "Unknown user name or bad password" tell you the username was actually invalid?
3. Did the attack result in a successful compromise? Does that change the verdict?
4. Was an account lockout triggered? What does its absence mean?
5. What is your final verdict and justification?
