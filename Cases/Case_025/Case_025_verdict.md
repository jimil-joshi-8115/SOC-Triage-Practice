# Verdict — Case 025

## E-001: 🔴 Verdict: TRUE POSITIVE
## E-002: 🟢 Verdict: FALSE POSITIVE
## E-003: 🔴 Verdict: TRUE POSITIVE
## E-004: 🔴 Verdict: TRUE POSITIVE
## E-005: 🔴 Verdict: TRUE POSITIVE
## E-006: 🔴 Verdict: TRUE POSITIVE (Critical — Live Interrupt)

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Valid Accounts | T1078 | Dormant VPN account login, credentials likely leaked/reused (E-001) |
| Remote Services: SMB/Windows Admin Shares | T1021.002 | Lateral movement to file servers, DC, backup server (E-003) |
| Exfiltration Over C2 Channel | T1041 | 94.3 GB transferred to attacker-controlled IP (E-004) |
| Scheduled Task/Job | T1053.005 | Persistence via new scheduled task on DC (E-005) |
| Data Encrypted for Impact | T1486 | Mass file renaming/encryption across file servers (E-006) |

---

## Justification

### E-001 — TP
A dormant account (last login 247 days prior) with no MFA suddenly authenticating successfully
from a never-before-seen external IP is a textbook re-use of leaked or stale credentials —
directly mirroring the real-world entry vector this scenario is grounded in (a legacy VPN
account with no MFA).

### E-002 — FP
**Correction made during investigation.** Different account (`svc-printmgmt` vs.
`svc-remote-legacy`), different host (`MFL-PRINT02`, untouched elsewhere in the chain), no
shared IP with the rest of the incident, and a documented recurring benign pattern (expired
scheduled-task credential, resolved the same way 3 times in the prior 60 days). Initial
pattern-matching on "failed logons" without checking correlation first led to an incorrect
first-pass TP call; corrected after reviewing account/host/IP overlap.

### E-003 — TP
The compromised account's first-ever SMB activity in 180 days, hitting exactly the systems
relevant to a ransomware operation (file servers, domain controller, backup server) within
minutes of initial access — reconnaissance/staging for the attack that follows.

### E-004 — TP
94.3 GB exfiltrated to the same IP that performed the E-001 login, consistent with a
double-extortion pattern (steal data before encrypting).

### E-005 — TP
New scheduled task on the domain controller, created by the compromised account, running an
obfuscated PowerShell payload on every logon — persistence established on the most sensitive
host in the environment.

### E-006 — TP, Critical, Live Interrupt
14,200+ files encrypted across two file servers in under 4 minutes, same account context as the
rest of the chain. This is active, in-progress ransomware encryption, not a completed incident
being investigated after the fact. **This alert changes response priority immediately** —
containment (isolate MFL-FS01/FS02, kill active sessions) takes precedence over continuing to
document the remaining queue in order.

---

## Correlation Summary

E-001, E-003, E-004, E-005, and E-006 form one continuous incident: same account
(`svc-remote-legacy`) and/or same external IP (`91.219.212.44`), unbroken timeline from 03:02
to 05:31 UTC, coherent progression (dormant-account access → lateral movement → exfiltration →
persistence → encryption). E-002 shares no account, host, or IP with this chain and matches an
established, recurring benign pattern — correctly isolated as unrelated.

---

## What Would Change These Verdicts

- **E-001 → FP:** confirmed legitimate remote-access need for this account with an approved
  exception for MFA (e.g., documented service account with compensating controls).
- **E-002 → TP:** if the print server host or account showed any overlap with the attacker's IP
  or the compromised account, or if the "known recurring pattern" explanation were unverifiable.
- **E-003/004/005/006 → FP:** none plausible given the account's total absence of prior activity
  and the direct correlation to the confirmed-malicious E-001 login; no legitimate business
  justification exists for this account's behavior in this window.

---

## Recommended Response Actions

1. **Immediate — isolate MFL-FS01 and MFL-FS02 from the network** to halt further encryption
   (E-006 confirms this is actively in progress).
2. Disable `svc-remote-legacy` and terminate all active sessions immediately.
3. Block source IP 91.219.212.44 at the perimeter firewall.
4. Remove the "WindowsUpdateHealthCheck" scheduled task from MFL-DC01.
5. Assess backup integrity — MFL-BKP01 was touched during lateral movement (E-003); confirm
   backups were not also encrypted or tampered with before relying on them for recovery.
6. Treat the 94.3 GB transfer as a confirmed data breach — begin exfiltration/data-loss
   assessment and legal/compliance notification processes in parallel with technical response.
7. Escalate to IR immediately; this is active ransomware impact, not a pre-encryption
   investigation window.
8. No action needed on E-002 beyond standard closure — matches known benign pattern.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | E-001: TP · E-002: FP · E-003: TP · E-004: TP · E-005: TP · E-006: TP (Critical) |
| Confidence | High (all six) |
| Verification method | Ticket-only — no Splunk query run (analyst decision) |
| Triage Time | 7:22 – 7:29 (real, tracked) |
| Escalated | Yes — full chain (would be, in real SOC, as active ransomware impact) |
| Corrections during investigation | 1 (E-002: initial TP call corrected to FP after correlation check) |
| Scenario basis | Adapted from the publicly documented May 2021 Colonial Pipeline / DarkSide ransomware attack; IOCs and identities fully sanitized/fictional |
