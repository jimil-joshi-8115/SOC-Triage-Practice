# Case 020 — Final Exam, Stage 2: The Cascade + Shift Handoff

**Incident ID:** IR-2026-036
**Date Detected:** 2026-07-06
**Host:** JIMIL-JOSHI
**Reported By:** SOC Monitoring (Splunk + ticket-based alerts)
**Status:** 🔴 Open — Escalated, Active Incident

**Phase:** 3 — Final Exam (Stage 2 of 2, capstone case of the repo). Continues directly from Case_019, where an active credential-theft chain (BA → BG) was already confirmed. Three additional alerts arrived during this stage, including one that directly extends the confirmed chain.

---

## 🎫 Cascade Queue — 3 Additional Alerts

| # | Alert | Type | Format | SIEM Severity |
|---|---|---|---|---|
| 8 | Alert BH | Kerberoasting-pattern: multiple TGS requests for service accounts | Ticket-only | 🔴 High |
| 9 | Alert BI | New outbound connection, same process as Alert BA, different port | Splunk | 🔴 High |
| 10 | Alert BJ | Employee self-reported phishing email, no execution | Ticket-only | 🟢 Info |

**Analyst's chosen order:** BI → BH → BJ

---

## 📄 Raw Event Data

### Alert BI
```
Process_Command_Line: (same PID as BA's svc.exe) connecting outbound to 91.242.217.88:8080
Account: SYSTEM | Parent: svc.exe
```

### Alert BH
```
Multiple Kerberos TGS-REQ events for 5 different service accounts within 90 seconds, account hp requesting
```

### Alert BJ
```
Employee "r.kumar" forwarded a suspicious email to IT-Security@company with subject "Urgent: Verify your account" — did not click any links, reported before taking action.
Account: r.kumar
```

---

## 🎯 Task

1. Determine where these 3 new alerts fit relative to the already-confirmed BA/BG chain from Case_019.
2. Give a verdict for each.
3. Produce an end-of-shift handoff summary covering the full 10-alert session (Cases 019 + 020 combined).
