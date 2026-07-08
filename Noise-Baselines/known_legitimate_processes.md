# Known Legitimate Processes — Noise Baseline

Documented FP patterns confirmed during Cases 001-020. Check here first before investigating a new alert from scratch — an exact match below is positive evidence of legitimacy, not just an absence of red flags.

---

## rundll32.exe Patterns

| DLL,Function | Verdict | Source Case |
|---|---|---|
| `PcaSvc.dll,PcaPatchSdbTask` | 🟢 FP — legitimate Windows Program Compatibility Assistant | Case_004 |
| `AppXDeploymentExtensions.OneCore.dll,ShellRefresh` | 🟢 FP — legitimate AppX shell refresh | SOC-Lab-Splunk baseline |
| `shell32.dll,Control_RunDLL` | 🟢 FP — legitimate COM activation | SOC-Lab-Splunk baseline |

**Rule:** An unrecognized DLL/function pair loaded from a non-standard path is not automatically FP just because it "looks like" a rundll32 call — cross-check against this table first. If it's not here, treat as Ambiguous/TP pending further checks (see `process_creation_triage.md`).

---

## Diagnostic / Recon Commands (Standalone, No Aggravating Factors)

| Command | Verdict | Notes |
|---|---|---|
| `ipconfig /all` | 🟢 FP | Standard network diagnostic, zero legitimate-use-case ambiguity |
| `Get-Process` (PowerShell) | 🟢 FP | Basic process listing, no hidden flags/encoding |
| `whoami` (standalone, local console session) | 🟢 FP | Harmless identity check — **only when session context is normal** (compare Ambiguous version in `powershell_triage.md` when tied to RDP/remote logon) |
| `ping -n 100 8.8.8.8` | 🟢 FP | Basic connectivity test to a well-known public IP |
| `net localgroup administrators` (no `/add`) | 🟢 FP | Read-only group membership check — flag only if followed by an `/add` |

**Rule:** A command "sounding technical" does not make it suspicious. Check for actual aggravating factors (hidden window, encoding, unusual destination, privilege escalation) before defaulting away from FP. (Lesson from Cases 009, 010, and repeated drill corrections.)

---

## Get-Clipboard / Single Benign PowerShell Calls

| Pattern | Verdict | Notes |
|---|---|---|
| `powershell.exe -c "Get-Clipboard"` (visible window, no encoding, single call) | 🟢 FP | Case_009, Alert A — standard cmd→powershell chain, no aggravating factors |

**Rule:** `cmd.exe → powershell.exe` is one of the most common, normal execution chains on Windows. Do not flag this parent-child relationship by default — only flag when combined with hidden windows, encoding, or unusual destinations (see Case_014's Outlook/Excel exception below).

---

## Abnormal Parent Processes (Flip Side — Treat as Red Flags, Not Baseline)

These are documented here as the **inverse** reference — parent processes that should NEVER appear spawning a script interpreter under normal conditions:

| Parent → Child | Verdict | Source Case |
|---|---|---|
| `OUTLOOK.EXE → powershell.exe` | 🔴 TP indicator | Case_014, Alert Q |
| `EXCEL.EXE → powershell.exe` / `WINWORD.EXE → powershell.exe` | 🔴 TP indicator | Drill practice, consistent with Case_014 logic |

**Rule:** Office/email applications never legitimately spawn script interpreters. Unlike `cmd→powershell` (normal, don't flag), an abnormal parent like this is itself the primary evidence — weight it above payload content.

---

## Service Actions — Routine vs. Security-Critical

| Service | Action | Verdict | Source Case |
|---|---|---|---|
| Print Spooler (`Spooler`) | Restarted | 🟢 FP | Case_016, Alert AB |
| Windows Update (`wuauserv`) | Stopped | 🟢 FP | Case_019, Alert BF |
| Windows Defender (`WinDefend`) | Disabled/stopped | 🔴 TP | Case_011, Alert G; Case_015, Alert W |
| Audit Policy / Event Log settings | Disabled | 🔴 TP | Case_013, Alert M; Case_018, Alert AJ |
| Windows Firewall (`MpsSvc`) | Disabled | 🔴 TP | Consistent with above pattern |

**Rule:** The *type* of service matters as much as the action. Routine/reliability-prone services (Print Spooler, Windows Update) being stopped/restarted is common and mundane. Security controls (Defender, Firewall, Event Log/Audit Policy) being disabled has no everyday legitimate use case and should be treated as TP on content alone.

---

## Maintenance Log

Add new confirmed-legitimate patterns here as they're validated in future cases, following the same table format.
