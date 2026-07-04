# Investigation — Case 010 (Phase 2 Batch 2)

## Prioritization Decision (Before Investigation)

**Chosen order: E → F → D**

**Justification:**
- **Alert E first** — `vssadmin delete shadows` is a destructive, largely irreversible action if malicious (classic ransomware precursor, T1490). Impact severity if TP outweighs the other two, which are either observational or reversible — correctly prioritized regardless of SIEM label reasoning.
- **Alert F second** — script download from an external source (even a legitimate platform like GitHub) could stage a payload for later execution; worth checking before the lowest-priority item.
- **Alert D last** — a single `whoami` command is typically low-impact; appropriately triaged last, though context (RDP session) still needed to be factored in during investigation.

---

## Alert E — vssadmin Delete Shadows

**SPL Query:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*vssadmin.exe"
| table _time, ComputerName, Account_Name, New_Process_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 5
```

**Result:**

| _time | ComputerName | Account_Name | Process_Command_Line | Creator_Process_Name |
|---|---|---|---|---|
| 2026-07-04 08:38:26.960 | JIMIL-JOSHI | hp | vssadmin delete shadows /all /quiet | cmd.exe |

**Findings:**
- 🔴 `vssadmin delete shadows /all /quiet` deletes all Volume Shadow Copy backups on the system — a well-documented pre-ransomware action to prevent file recovery after encryption.
- 🟡 `cmd.exe` parent is standard/expected — noted as fact, not treated as an independent red flag.
- 🔴 The command itself is unambiguous in effect: it either ran (destroying backups) or didn't. No further context is needed to establish malicious intent — legitimate backup deletion of this scope is not a routine end-user action.

**Verdict: 🔴 TP — T1490 (Inhibit System Recovery)**

---

## Alert F — Invoke-WebRequest to GitHub Raw URL

**SPL Query:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*powershell.exe" Process_Command_Line="*Invoke-WebRequest*"
| table _time, ComputerName, Account_Name, New_Process_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 5
```

**Result:** `Invoke-WebRequest -Uri https://raw.githubusercontent.com/testuser/repo/main/tool.ps1 -OutFile tool.ps1`, parent `cmd.exe`.

**Findings:**
- 🟡 GitHub is a legitimate, widely-used developer platform — the domain itself is not inherently suspicious, unlike Case_008's raw-IP destination.
- 🟡 File extension (`.ps1`) is honest and undisguised, unlike Case_008's `.txt`-masked payload.
- 🟠 No baseline reference exists for `testuser/repo`; content of `tool.ps1` is unknown since no execution was observed in this dataset.
- 🟠 Attackers do commonly abuse trusted platforms like GitHub specifically because they are less likely to be blocked by network controls — this is a real, documented technique, not just theoretical.

**Verdict: 🟡 Ambiguous — T1105 (Ingress Tool Transfer)**
Cannot confirm malicious intent (legitimate platform, honest extension, no execution observed) or clear as FP (unknown script content, no documented business justification for this specific repo).

---

## Alert D — whoami After RDP Logon

**SPL Query:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*whoami.exe"
| table _time, ComputerName, Account_Name, New_Process_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 5
```

**Result:** `whoami`, parent `cmd.exe`.

**Findings:**
- 🟡 `whoami` alone is one of the most common, benign commands in existence.
- 🟠 **Context is decisive here:** this command followed a logon with `Logon_Type 10 (RemoteInteractive/RDP)`, not a local console session. An attacker who has just gained remote access commonly runs `whoami` as an immediate first recon step to confirm what user/privilege context they landed in. The same command from a local, already-authenticated user carries far less significance.
- 🟡 No further recon or lateral movement commands were observed following this single command in the available data.

**Verdict: 🟡 Ambiguous**
Single benign command insufficient alone for TP, but the RDP-session context is a real, relevant risk factor that prevents a clean FP dismissal — consistent with treating context (not just command content) as part of the evidence.

---

## Summary Table

| Alert | Verdict | MITRE | SIEM Label vs. Reality |
|---|---|---|---|
| E — vssadmin | 🔴 TP | T1490 | High label matched reality |
| F — Invoke-WebRequest | 🟡 Ambiguous | T1105 | Medium label matched reality |
| D — whoami (RDP) | 🟡 Ambiguous | — | Low label underestimated reality — context elevated this above a routine dismissal |
