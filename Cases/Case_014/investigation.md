# Investigation — Case 014 (Phase 2 Batch 6 — Final Phase 2 Batch)

## Prioritization Decision (Before Investigation)

**Chosen order: R → Q → P**

**Justification:**
- **Alert R first** — a new inbound firewall rule represents a standing exposure (open port), a persistent condition rather than a one-time action; prioritized to assess and potentially close the exposure quickly.
- **Alert Q second** — an abnormal parent-child execution chain combined with an encoded command represents likely active or recent malicious execution; checked before the lowest-priority item.
- **Alert P last** — a WMI-based command execution using a known technique, but the specific action (a `whoami` redirect) is low-impact; appropriately triaged last.

---

## Alert R — New Firewall Rule (Port 4444)

**SPL Queries:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*netsh.exe"
| table _time, ComputerName, Account_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 5
```
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4947
| table _time, ComputerName, Account_Name
| sort -_time
| head 5
```

**Result:** 2 events, `netsh advfirewall firewall add rule name="UpdateSvc" dir=in action=allow protocol=TCP localport=4444`, parent `cmd.exe` (command was run twice during testing). EventCode=4947 (firewall rule change) returned 0 events — consistent with the recurring host-wide audit logging gap pattern observed across EventCodes 4720 (Case_002), 4698 (Case_003), and the 4732 confirmation gap (Case_012).

**Findings:**
- 🔴 The rule opens **inbound** access on TCP port 4444 — a port with no standard legitimate service association, but widely recognized as the **default Metasploit Meterpreter listener port**.
- 🟠 The rule name (`UpdateSvc`) is an innocent-sounding, masquerading name, consistent with the naming pattern seen in Case_002 (`hpbackup`) and Case_007 (`SystemHealthCheck`).
- 🟠 Recurring logging gap (now four separate EventCodes affected: 4720, 4698, 4732, 4947) — this pattern strongly suggests a host-wide audit policy configuration issue rather than isolated coincidences, and should be escalated as its own finding.

**Verdict: 🔴 TP — T1562.004 (Impair Defenses: Disable or Modify System Firewall)**

---

## Alert Q — Outlook Spawning PowerShell

**SPL Query:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*powershell.exe" Process_Command_Line="*-enc*"
| table _time, ComputerName, Account_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 5
```

**Result:** `powershell.exe -enc <base64>`. Per the original alert data, `Creator_Process_Name` for this scenario is `OUTLOOK.EXE` (simulated for this drill, since safely reproducing a live Outlook-spawned process was not practical in this environment).

**Findings:**
- 🔴 **The parent process is the primary indicator here, not the encoded command content.** `OUTLOOK.EXE` spawning `powershell.exe` is an abnormal execution chain — email clients do not legitimately launch script interpreters under normal operation. This is the mirror-opposite case of Case_009/010's lesson (`cmd.exe → powershell.exe` is normal and should not be flagged) — here, the *parent itself* is the red flag precisely because it is not a process that should ever spawn PowerShell.
- 🟠 The encoded command adds a layer of obfuscation on top of an already-abnormal execution chain, consistent with malicious attachment/macro-triggered execution patterns (T1204.002 → T1059.001) commonly seen in real-world phishing incidents.

**Verdict: 🔴 TP — T1204.002 (User Execution: Malicious File), T1059.001 (PowerShell)**

---

## Alert P — wmic process call create (whoami Redirect)

**SPL Query:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*wmic.exe"
| table _time, ComputerName, Account_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 5
```

**Result:** `wmic process call create "cmd.exe /c whoami > C:\Users\hp\AppData\Local\Temp\out.txt"`, parent `cmd.exe`.

**Findings:**
- 🟠 `wmic process call create` is a known technique (T1047 — Windows Management Instrumentation) frequently used for lateral movement and remote command execution — a legitimate concern to flag on technique alone.
- 🟡 However, the specific action performed is limited to a `whoami` command redirected to a local file — no persistence, no external communication, no privilege escalation, no destructive action. A known technique does not automatically confirm TP when the executed action itself carries no malicious outcome, mirroring the reasoning applied in Case_003 and Case_011's Alert H (tasklist/lsass) — technique-level suspicion and outcome-level evidence must both be weighed, not just the former.

**Verdict: 🟡 Ambiguous — T1047 (technique-level concern, outcome inconclusive)**

---

## Summary Table

| Alert | Verdict | MITRE | SIEM Label vs. Reality |
|---|---|---|---|
| R — Firewall Rule (4444) | 🔴 TP | T1562.004 | High label matched reality |
| Q — Outlook→PowerShell | 🔴 TP | T1204.002, T1059.001 | High label matched reality |
| P — wmic/whoami | 🟡 Ambiguous | T1047 | Medium label matched reality |
