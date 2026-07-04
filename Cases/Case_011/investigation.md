# Investigation — Case 011 (Phase 2 Batch 3)

## Prioritization Decision (Before Investigation)

**Chosen order: G → I → H**

**Justification:**
- **Alert G first** — disabling Windows Defender's real-time monitoring (T1562.001) is a defense-evasion action that could enable subsequent malicious activity to go undetected; prioritized both for its own severity and as a potential precursor to the other alerts in this batch.
- **Alert I second** — `mshta.exe` executing inline JavaScript demonstrates an active code-execution capability (T1218.005), a step beyond pure recon; checked before the lowest-priority item.
- **Alert H last** — a single `tasklist` query is recon-only, no confirmed follow-on action; appropriately triaged last, though "last priority" does not mean "safe to dismiss," as reflected in its final verdict.

---

## Alert G — Set-MpPreference (Disable Real-Time Monitoring)

**SPL Query:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*powershell.exe" Process_Command_Line="*Set-MpPreference*"
| table _time, ComputerName, Account_Name, New_Process_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 5
```

**Result:** `Set-MpPreference -DisableRealtimeMonitoring $true`, parent `cmd.exe`.

**Findings:**
- 🔴 Directly disables Windows Defender's real-time protection — a well-documented defense-evasion action (T1562.001) with no legitimate end-user use case; this is decisive on the command content alone, similar to Case_010's vssadmin action.
- 🟡 `cmd.exe` parent noted as standard/expected, not treated as an independent indicator.

**Verdict: 🔴 TP — T1562.001 (Impair Defenses: Disable or Modify Tools)**

---

## Alert I — mshta.exe Inline JavaScript Execution

**SPL Query:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*mshta.exe"
| table _time, ComputerName, Account_Name, New_Process_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 5
```

**Result:** `mshta.exe javascript:a=(new ActiveXObject("WScript.Shell")).Run("calc.exe",0,true);close();`, parent `cmd.exe`.

**Findings:**
- 🔴 `mshta.exe` executing inline JavaScript via `ActiveXObject("WScript.Shell").Run()` is a well-documented LOLBin abuse technique (T1218.005) — mshta is a trusted, signed Microsoft binary capable of executing arbitrary script content, commonly abused to bypass simple application allow-listing.
- 🟡 The specific payload launched (`calc.exe`) is harmless, but this does not reduce the verdict — the *mechanism* itself is the confirmed malicious technique; in a real attack the payload would be swapped for something harmful. This mirrors the reasoning applied in Case_007 (registry persistence): a confirmed technique is TP regardless of the current payload's severity.

**Verdict: 🔴 TP — T1218.005 (System Binary Proxy Execution: Mshta)**

---

## Alert H — tasklist Filtered for lsass.exe

**SPL Query:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*tasklist.exe"
| table _time, ComputerName, Account_Name, New_Process_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 5
```

**Result:** `tasklist /fi "imagename eq lsass.exe"`, parent `cmd.exe`.

**Findings:**
- 🟠 `lsass.exe` (Local Security Authority Subsystem Service) is a legitimate, critical Windows process responsible for enforcing security policy and storing credential material in memory. It is not suspicious because it is unrecognized — it is a well-known, standard system process.
- 🔴 Specifically filtering `tasklist` output for `lsass.exe` by name is a recognized reconnaissance step preceding credential-dumping attempts (tools such as Mimikatz require locating the lsass process ID before extracting credentials from its memory) — this maps to a precursor stage of T1003.001 (OS Credential Dumping: LSASS Memory).
- 🟡 A single `tasklist` query alone confirms *checking*, not *dumping* — no evidence of a follow-on memory-access or dumping tool execution is present in this dataset. The action is genuinely dual-use: legitimate system administrators troubleshooting a crashed or high-CPU lsass process would issue the same command.

**Verdict: 🟡 Ambiguous — T1003.001 (precursor stage only)**
The command is a real, named-target recon action consistent with credential-dumping preparation, but is equally consistent with legitimate administrative troubleshooting. Evidence does not confirm which, and no follow-on dumping activity was observed.

---

## Summary Table

| Alert | Verdict | MITRE | SIEM Label vs. Reality |
|---|---|---|---|
| G — Set-MpPreference | 🔴 TP | T1562.001 | High label matched reality |
| I — mshta | 🔴 TP | T1218.005 | High label matched reality |
| H — tasklist/lsass | 🟡 Ambiguous | T1003.001 (precursor) | Medium label matched reality |
