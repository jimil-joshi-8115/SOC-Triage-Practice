# Investigation — Case 013 (Phase 2 Batch 5)

## Prioritization Decision (Before Investigation)

**Chosen order: M → N → O**

**Justification:**
- **Alert M first** — disabling PowerShell ScriptBlock logging removes future investigative visibility; prioritized because it can mask whatever activity follows, same reasoning as Case_011's Alert G (Defender disable).
- **Alert N second** — a credential-theft-adjacent action (ntds.dit copy attempt) is severe regardless of the host's role; checked before the lowest-priority item.
- **Alert O last** — unusual logon timing alone is lower immediate urgency than an active defense-evasion or credential-theft attempt; appropriately triaged last, though not dismissed outright.

---

## Alert M — PowerShell ScriptBlock Logging Disabled

**SPL Query:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*reg.exe" Process_Command_Line="*ScriptBlockLogging*"
| table _time, ComputerName, Account_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 5
```

**Result:** `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 0 /f`, parent `cmd.exe`.

**Findings:**
- 🔴 The value `/d 0` sets `EnableScriptBlockLogging` to **disabled**. This is a defense-evasion action (T1562.001/T1562.002) with no legitimate end-user justification — disabling this specific audit control removes future visibility into PowerShell activity, commonly done immediately before running something intended to stay hidden.
- 🟡 Parent `cmd.exe` noted as standard, not treated as an independent indicator.

**Verdict: 🔴 TP — T1562 (Impair Defenses)**

---

## Alert N — ntds.dit Copy Attempt

**Attempted SPL Queries:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*cmd.exe" Process_Command_Line="*ntds.dit*"
| table _time, ComputerName, Account_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 5
```
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 Process_Command_Line="*ntds.dit*"
| table _time, ComputerName, Account_Name, New_Process_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 5
```

**Result:** No matching event returned in Splunk (likely because `copy` is a CMD-internal command rather than a separate executable, and may not generate its own distinct 4688 entry beyond the parent `cmd.exe` process). Analysis proceeds based on the original alert command data.

**Findings:**
- 🔴 `ntds.dit` is the Active Directory database file containing all domain account credential hashes. Copying it is a well-documented credential-theft technique (T1003.003) with no legitimate reason for a standard user to access.
- 🔴 The destination — `AppData\Local\Temp\backup.dit` — stages the file into a user's Temp directory under an innocuous name ("backup.dit"), a masquerading/staging pattern consistent with Case_007's `SystemHealthCheck` naming approach.
- 🟡 **Important environmental nuance:** JIMIL-JOSHI is not a Domain Controller, so a real, populated `ntds.dit` file likely does not exist at this path on this host — the copy command would almost certainly fail or return an empty/non-existent file. This does **not** change the verdict: the *attempt* itself confirms malicious intent (T1003.003), regardless of whether the target file existed or the copy technically succeeded — consistent with the reasoning applied to Case_005's unsuccessful brute-force attempts, where outcome and intent are evaluated separately.

**Verdict: 🔴 TP — T1003.003 (OS Credential Dumping: NTDS)**

---

## Alert O — Interactive Logon at 3:14 AM

**Given Data (no live reproduction possible — system clock dependent):**
```
Logon_Type: 2 (Interactive)
Time: 03:14 AM
Account: hp
```

**Findings:**
- 🟠 **What makes this concerning:** 3:14 AM is well outside typical business or personal-use hours. Unusual-hour access is a recognized indicator (T1078 — Valid Accounts, unusual usage pattern), particularly in the absence of any established baseline for this account's normal login times.
- 🟡 **What makes this explainable:** Logon_Type 2 (Interactive) requires physical presence at the machine — this rules out remote-attacker access via network-based logon types (e.g., Type 3, Type 10). This is consistent with the legitimate account owner working unusual hours, experiencing a sleep disruption, or operating across a different time zone.
- 🟡 **Why Ambiguous, not TP or FP:** No baseline exists documenting `hp`'s normal login pattern, and no additional suspicious activity is tied to this specific logon event in the available data. The timing is a real, valid indicator worth documenting, but is insufficient alone to confirm malicious intent — legitimate odd-hours access by an account's own physical owner is common and unremarkable in many environments.

**Verdict: 🟡 Ambiguous**

---

## Summary Table

| Alert | Verdict | MITRE | SIEM Label vs. Reality |
|---|---|---|---|
| M — ScriptBlock Logging Disabled | 🔴 TP | T1562 | High label matched reality |
| N — ntds.dit Copy Attempt | 🔴 TP | T1003.003 | High label matched reality |
| O — 3 AM Interactive Logon | 🟡 Ambiguous | T1078 (related) | Low label underestimated the timing concern, though ultimately correctly resolved as inconclusive rather than a confirmed threat |
