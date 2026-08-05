# Case_025 — Dormant VPN Account → Lateral Movement → Exfiltration → Ransomware (Live Interrupt)

**Phase:** 4 (Cases 21–30) — Mixed queue, 6-alert batch with live interrupt
**Format:** Mixed — VPN/RADIUS log, EDR, firewall, file integrity monitoring (SIEM queue simulation)
**Company:** Meridian Fuel Logistics (internal alias — sanitized)
**Splunk verified:** No — ticket-only (analyst decision, alternating with Case_024)

**Scenario basis:** Adapted from the publicly documented May 2021 Colonial Pipeline / DarkSide
ransomware attack — a dormant VPN account with a leaked password and no MFA was the entry
point, followed by lateral movement, approximately 100GB of data exfiltrated in roughly two
hours, then ransomware deployment. All company, user, IP, and timestamp details below are
fictional/sanitized; only the attack chain structure is grounded in the real incident.

---

## Alerts (as received at trigger time)

```
Alert E-001 — VPN Login: Dormant Account, No MFA
  Severity: Low
  Account: svc-remote-legacy (last successful login: 247 days ago)
  Source IP: 91.219.212.44 (external, no prior history)
  MFA: Not enrolled on this account
  Time: 03:02:14 UTC

Alert E-002 — Multiple Failed Logons: Print Server Service Account
  Severity: Low
  Account: svc-printmgmt
  Host: MFL-PRINT02
  Detail: 6 failed logons over 40 minutes, standard interval — matches a known
          recurring pattern (expired scheduled-task credential), seen 3 times in
          the past 60 days, always resolved the same way
  Time: 03:05–03:45 UTC

Alert E-003 — Internal Lateral Movement: SMB Connections From VPN Session
  Severity: Medium
  Host: MFL-VPN-GW01 → MFL-FS01, MFL-FS02, MFL-DC01, MFL-BKP01
  Account: svc-remote-legacy
  Detail: 4 distinct internal hosts via SMB (445) within 6 minutes; no logged
          internal SMB activity for this account in prior 180 days
  Time: 03:11–03:17 UTC

Alert E-004 — Large Outbound Data Transfer
  Severity: High
  Source Host: MFL-FS01 (primary file server)
  Destination IP: 91.219.212.44 (same as E-001)
  Volume: 94.3 GB transferred over 118 minutes
  Time: 03:20–05:18 UTC

Alert E-005 — New Scheduled Task Created (Persistence)
  Severity: Medium
  Host: MFL-DC01
  Account: svc-remote-legacy
  Task Name: "WindowsUpdateHealthCheck"
  Action: Runs powershell.exe with a base64-encoded command block on every logon
  Time: 05:22:07 UTC

>>> LIVE INTERRUPT — fired mid-investigation <<<

Alert E-006 — Mass File Modification: New Extension Across File Shares
  Severity: Critical
  Host: MFL-FS01, MFL-FS02
  Detail: 14,200+ files renamed with new extension ".drkside" across both file
          servers in under 4 minutes; original file access denied
  Account context: svc-remote-legacy
  Time: 05:31:40 UTC
```

## Task

TP / FP / Ambiguous for E-001 through E-006. E-002 is a deliberate discrimination test — check
it against the pattern described before assuming it belongs to the chain. Note correlation
across the queue and flag any prioritization change once E-006 fires mid-investigation.
