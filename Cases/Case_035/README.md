# Case_035 — Insider Threat: Pre-Resignation Data Exfiltration, Personal-Email Policy Violation, and Documented Routine Access

**Phase:** 5 (Cases 31–50) — Insider Threat, 3-alert batch, three unrelated employees
**Format:** DLP (Endpoint + Email Gateway) + File Server Audit Log
**Company:** Aurora Resorts & Casinos (internal alias — sanitized)
**Splunk verified:** No — ticket-only (analyst decision)

---

## Alerts (as received at trigger time)

```
Alert O-001 — DLP: Mass Download to USB Storage
  Severity: High
  Host: MFL-WKS0312
  User: t.krishnan (Senior Business Development Manager)
  Detail: 1,847 files copied to a USB mass storage device over 22 minutes,
          including "Client_Contracts_2024-2026", "Pricing_Strategy_Confidential",
          and "Competitor_Analysis" folders
  HR context: t.krishnan submitted resignation 3 days prior; last working day
              in 11 days (standard notice period)
  Time: 19:41–20:03 UTC (2 hours after normal business hours)

Alert O-002 — DLP: Large Email Attachment to Personal Address
  Severity: Medium
  User: r.fernandes (Financial Analyst)
  Detail: Email sent to r.fernandes's own personal Gmail address, subject
          "my performance reviews", attachment: 3 PDF files (past self
          performance review documents, HR-issued, employee's own records)
  Time: 14:22:07 UTC (during business hours)

Alert O-003 — File Access: Unusual Access to HR Compensation Database
  Severity: Medium
  Host: MFL-FS01
  User: d.almeida (IT Systems Administrator)
  Detail: Accessed \\MFL-FS01\HR\Compensation\ — a share d.almeida has
          standing read access to as part of documented backup/DR
          administrative duties (scheduled quarterly backup verification,
          matches recurring calendar entry "Q3 DR Test - HR Share")
  Time: 10:15:00 UTC (within scheduled maintenance window)
```

## Task

TP / FP / Ambiguous for O-001 through O-003. These are three separate, unrelated employees —
don't assume correlation. Consider what distinguishes genuinely suspicious insider activity
from normal, if superficially alarming-looking, employee behavior.
