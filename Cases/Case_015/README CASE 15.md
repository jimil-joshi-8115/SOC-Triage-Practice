# Case 015 — Phase 3: Full Queue Simulation (Live Interrupt)

**Incident ID:** IR-2026-031
**Date Detected:** 2026-07-05
**Host:** JIMIL-JOSHI
**Reported By:** SOC Monitoring (Splunk Alert)
**Status:** 🔴 Open — Pending Triage

**Phase:** 3 — Full queue simulation. Alerts arrive together and mid-investigation; analyst must manage prioritization dynamically, including interruptions to a planned order.

---

## 🎫 Initial Queue — 4 Alerts

| # | Alert | Type | SIEM Severity |
|---|---|---|---|
| 1 | Alert S | Failed logon x2, same account | 🟡 Low |
| 2 | Alert T | New scheduled task created | 🔴 High |
| 3 | Alert U | Suspicious DNS query pattern (varying subdomains) | 🟠 Medium |
| 4 | Alert V | USB mass storage device connected | 🟢 Info |

**Analyst's initial chosen order:** T → U → S → V

---

## 🚨 Mid-Investigation Interrupt

While investigating Alert T, a new alert arrived:

| # | Alert | Type | SIEM Severity |
|---|---|---|---|
| 5 | Alert W | PowerShell disabling Windows Defender (Set-MpPreference) | 🔴 High |

**Analyst's decision:** Interrupt current work to handle Alert W immediately, then resume the original planned order (T → W → U → S → V).

---

## 📄 Raw Event Data

### Alert T
```
Process_Command_Line: schtasks /create /tn "AdobeUpdateSvc" /tr "powershell.exe -enc <base64>" /sc daily /st 03:00 /ru SYSTEM
Account: hp | Parent: cmd.exe
```

### Alert W
```
Process_Command_Line: powershell.exe -c "Set-MpPreference -DisableRealtimeMonitoring $true"
Account: hp | Parent: cmd.exe
```

### Alert U
```
DNS queries to: a1-a7.cdn-analytics-sync.net (7 queries, varying subdomains, within ~90 seconds)
Account: hp | Parent: cmd.exe
```

### Alert S
```
2 failed logon attempts, account hp, Logon_Type 2 (Interactive), ~10 seconds apart
```

### Alert V
```
Device: USB Mass Storage Device connected | Time: 2:15 PM | Account: hp | Drive letter assigned: E:
```

---

## 🎯 Task

1. Determine initial triage order across the 4-alert queue and justify it.
2. When a new alert arrives mid-investigation, decide whether to interrupt current work or finish first, and justify the decision.
3. Investigate each alert and give a verdict.
4. Provide an end-of-queue summary suitable for a shift handoff.
