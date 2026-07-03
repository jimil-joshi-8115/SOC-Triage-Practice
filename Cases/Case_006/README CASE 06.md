# Case 006 — Multiple Failed Logons, Different Accounts (Password Spray)

**Incident ID:** IR-2026-022
**Date Detected:** 2026-07-03
**Host:** JIMIL-JOSHI
**Reported By:** SOC Monitoring (Splunk Alert)
**Status:** 🔴 Open — Pending Triage

---

## 🎫 Alert Summary

| Field | Value |
|---|---|
| EventCode | 4625 (Failed Logon) |
| Accounts Targeted | admin, administrator, support (3 distinct accounts) |
| Computer | JIMIL-JOSHI |
| Logon Type | 2 (Interactive) |
| Trigger | 3 failed logon attempts across 3 different accounts within ~35 seconds |

---

## 📄 Raw Event Data

**SPL Query Used:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
| table _time, ComputerName, Account_Name, Logon_Type, Failure_Reason
| sort -_time
| head 20
```

**Results (3 events):**

| _time | ComputerName | Account_Name | Logon_Type | Failure_Reason |
|---|---|---|---|---|
| 2026-07-03 08:24:42.922 | JIMIL-JOSHI | support | 2 | Unknown user name or bad password. |
| 2026-07-03 08:24:36.308 | JIMIL-JOSHI | administrator | 2 | Unknown user name or bad password. |
| 2026-07-03 08:24:07.403 | JIMIL-JOSHI | admin | 2 | Unknown user name or bad password. |

---

## 🎯 Task

Triage this alert. Determine:
1. Is this TP / FP / Ambiguous?
2. How does targeting multiple different accounts differ from Case_005's single-account pattern? What technique does this map to?
3. Are `admin`, `administrator`, and `support` real accounts on this host?
4. What is your final verdict and justification?
