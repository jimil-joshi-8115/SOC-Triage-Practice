# Case_022 — Business Email Compromise (BEC): Impossible Travel + Malicious Inbox Rule + Fraudulent Payment Redirection

**Phase:** 4 (Cases 21–30) — Email/Phishing domain
**Format:** Microsoft Defender for Office 365 — Email Security Alerts (3-alert batch)
**Splunk verified:** Yes — sample O365 Unified Audit Log data ingested via CSV upload
(`source="o365_unifiedauditlog_case022.csv"`, `host="JIMIL-JOSHI"`, `sourcetype="csv"`)

---

## Alerts

```
Alert BC-001 — User reported email as phishing
  Severity: Informational
  Sender: it-support@corptenant-helpdesk.com
  Recipient: k.desai@corptenant.com
  Subject: "Your mailbox storage is full - action required"
  SPF/DKIM/DMARC: Fail/Fail/Fail
  Sender domain age: 6 days
  User action: Reported only — no click, no credential entry

Alert BC-002 — Impossible travel + inbox rule creation
  Severity: High
  Account: k.desai@corptenant.com
  Event 1: Sign-in, Ahmedabad, India — 09:14 UTC
  Event 2: Sign-in, Warsaw, Poland — 09:41 UTC (27 min gap, ~5,900 km)
  Event 3: New inbox rule '..' — moves invoice/payment/wire-transfer emails to
           hidden folder + forwards copy to fin-review@corptenant-audit.net
  MFA: Not satisfied (legacy auth, IMAP4)

Alert BC-003 — High-volume outbound to external domain
  Severity: Medium
  Account: k.desai@corptenant.com
  Detail: 14 emails in 6 minutes to finance/accounts/ap/billing@vendorpartner-inc.com,
          subject variations of "Updated bank details for upcoming payment"
  Time: 09:47–09:53 UTC, immediately following BC-002's inbox rule
```

## Task

TP / FP / Ambiguous for each alert, plus note any correlation between them.
