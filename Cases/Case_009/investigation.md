# Investigation — Case 009 (Phase 2 Batch)

## Prioritization Decision (Before Investigation)

**Chosen order: B → C → A**

**Justification:**
- **Alert B first** — a new service running in SYSTEM context with a binary located in `AppData\Local\Temp` is a high-impact combination (legitimate services are never installed from user Temp directories); this outranks the SIEM's own severity label reasoning because SYSTEM-level persistence represents the greatest potential impact if confirmed malicious.
- **Alert C second** — repeated DNS lookups to the same external domain in a short window can indicate an active C2 beaconing channel; worth checking before the lowest-priority item since active communication channels warrant faster attention than a single local action.
- **Alert A last** — clipboard access alone, without additional aggravating factors, is the most likely to be low-impact; appropriately triaged last.

This shows the SIEM's severity labels roughly aligned with actual risk in this batch (High → Medium → Low matched B → C → A), but the analyst's reasoning was based on independent factors (persistence + privilege for B, DNS repetition pattern for C), not blind trust in the labels themselves.

---

## Alert B — New Local Service Installed

**SPL Query:**
```spl
index=* sourcetype="WinEventLog:System" EventCode=7045
| table _time, ComputerName, Account_Name, Service_Name, Service_File_Name
| sort -_time
| head 5
```

**Result:**

| _time | ComputerName | Service_Name | Service_File_Name |
|---|---|---|---|
| 2026-07-04 08:07:13.701 | JIMIL-JOSHI | WinDefenderHelper | C:\Users\hp\AppData\Local\Temp\svc.exe |

**Findings:**
- 🔴 **Masquerading service name** — "WinDefenderHelper" is designed to mimic Microsoft Defender, but is not a real/documented Defender component.
- 🔴 **Binary path in `AppData\Local\Temp`** — the single strongest indicator here; legitimate Windows services install from `System32` or `Program Files`, never from a user's Temp folder.
- 🟡 `User=NOT_TRANSLATED` in the raw event is expected/normal for SYSTEM-context service installs and is not itself a red flag.

**Verdict: 🔴 TP — T1543.003 (Create or Modify System Process: Windows Service)**

---

## Alert C — Repeated nslookup to External Domain

**SPL Query:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*nslookup.exe"
| table _time, ComputerName, Account_Name, New_Process_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 10
```

**Result:** 3 events, `update-cdn-cache.com`, timestamps 08:14:30 → 08:15:01 (~31 seconds apart across 3 lookups), parent `cmd.exe`.

**Findings:**
- 🟡 `cmd.exe` as parent for `nslookup.exe` is standard, expected behavior — not a suspicious factor on its own (this was initially over-weighted during investigation and corrected).
- 🟠 `update-cdn-cache.com` is not a documented/known domain in the environment's baseline; the name is designed to resemble legitimate CDN infrastructure.
- 🟠 **3 identical lookups within ~31 seconds** does not match normal DNS caching behavior (a browser/app would not re-resolve the same domain repeatedly within seconds) — this pattern is consistent with C2 beaconing check-in behavior (T1071.004).
- 🟡 However, no confirmed malicious response, resolved IP reputation check, or follow-up network connection was observed in this dataset — only the DNS query pattern itself.

**Verdict: 🟡 Ambiguous — T1071.004 (Application Layer Protocol: DNS)**
Structural pattern (repetition, unknown domain) matches known beaconing behavior, but no confirmed malicious outcome (resolved IP, follow-up connection, or payload) is present in the available evidence.

---

## Alert A — Get-Clipboard PowerShell Activity

**SPL Query:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*powershell.exe" Process_Command_Line="*Get-Clipboard*"
| table _time, ComputerName, Account_Name, New_Process_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 5
```

**Result:**

| _time | ComputerName | Account_Name | Process_Command_Line | Creator_Process_Name |
|---|---|---|---|---|
| 2026-07-04 08:22:24.401 | JIMIL-JOSHI | hp | powershell.exe -c "Get-Clipboard" | cmd.exe |

**Findings:**
- 🟡 `cmd.exe` → `powershell.exe` is a standard, common execution chain and is not itself a suspicious indicator — this parent-child relationship needs additional aggravating factors (hidden window, encoding, external destination, repetition) to indicate malicious intent, none of which are present here. Initial assessment during investigation over-weighted this parent chain and was refined after reconsidering it against prior cases (Case_001, Case_007) where the *combination* of factors, not the parent process alone, drove the TP verdicts.
- 🟢 Single, fully visible command with no obfuscation, no persistence, no external network activity, no repetition/looping.
- 🟢 `Get-Clipboard` alone does not confirm data exfiltration — T1115 requires evidence of collection *for* exfiltration, not just a single read.

**Verdict: 🟢 FP**

---

## Summary Table

| Alert | Verdict | MITRE | SIEM Label vs. Reality |
|---|---|---|---|
| B — New Service | 🔴 TP | T1543.003 | High label matched reality |
| C — nslookup | 🟡 Ambiguous | T1071.004 | Medium label matched reality |
| A — Clipboard | 🟢 FP | — | Low label matched reality |
