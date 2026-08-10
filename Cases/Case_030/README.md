# Case_030 — 🏁 Phase 4 Capstone: Phishing → MFA Fatigue Takeover → Mailbox Concealment → Lateral RDP → Active Exfiltration

**Phase:** 4 Capstone (Cases 21–30) — Mixed Email + Cloud Identity + Endpoint, 7-alert queue
with live interrupt and time pressure
**Format:** Defender for Office 365 + Web Proxy + Azure AD + Windows Security Event Log + EDR
**Company:** Meridian Fuel Logistics (internal alias — sanitized, same as Case_025)
**Splunk verified:** No — ticket-only (Final Exam Stage 1/2 style)
**Time pressure target:** ~2-3 minutes per alert

---

## Alerts (as received at trigger time)

```
Alert J-001 — Email: Malicious Link Delivered
  Severity: Medium
  Recipient: d.thakkar@meridianfuel.com
  Sender: security-alert@meridianfuel-portal.com (lookalike domain; legitimate
          is meridianfuel.com)
  Subject: "Action required: unusual sign-in blocked on your account"
  Link: hxxps://meridianfuel-portal-verify[.]com/reauth
  SPF/DKIM/DMARC: Fail/Fail/Fail
  Time: 10:02:14 UTC

Alert J-002 — Proxy: Outbound Connection to Newly-Registered Domain
  Severity: Medium
  Host: MFL-WKS0198 (d.thakkar's workstation)
  Destination: meridianfuel-portal-verify.com (registered 3 days ago)
  Detail: User clicked the link from J-001; page requested Microsoft 365
          credentials; proxy logged a POST request to the domain immediately
          after page load (consistent with credential submission)
  Time: 10:04:51 UTC

Alert J-003 — Azure AD: Successful Sign-In, Unfamiliar Location
  Severity: High
  Account: d.thakkar@meridianfuel.com
  Detail: Successful sign-in from 91.219.212.88 (Bucharest, Romania) — 14-day
          baseline shows Ahmedabad, India only
  MFA: Prompt sent, initially denied twice, approved on 3rd prompt within 90 seconds
  Time: 10:07:33 UTC

Alert J-004 — Azure AD: New Inbox Rule Created
  Severity: High
  Account: d.thakkar@meridianfuel.com
  Detail: Rule "Security" created — moves any email containing "unusual sign-in",
          "security alert", or "suspicious activity" to Deleted Items and marks
          as read; StopProcessingRules: True
  Source IP: 91.219.212.88 (same as J-003)
  Time: 10:09:02 UTC

Alert J-005 — Endpoint: RDP Connection to File Server
  Severity: Medium
  Host: MFL-FS03
  Account: d.thakkar
  Source Host: MFL-WKS0198 (same workstation as J-002)
  Detail: d.thakkar has no logged RDP activity to any file server in prior
          90-day history; role (Regional Dispatch Coordinator) has no
          documented business need for file server RDP access
  Time: 10:12:47 UTC

Alert J-006 — Endpoint: Account Lockout, Unrelated User
  Severity: Low
  Account: m.oconnor
  Host: MFL-WKS0055
  Detail: 3 failed logons, standard interval, consistent with a recent password
          change and an outdated saved credential in a mapped drive (documented,
          recurring pattern — auto-generated helpdesk ticket, historically no
          analyst action needed)
  Time: 10:13:10 UTC

>>> LIVE INTERRUPT — fired mid-investigation <<<

Alert J-007 — Endpoint: Large Archive File Created
  Severity: Critical
  Host: MFL-FS03
  Account: d.thakkar
  Detail: 7-Zip used to create "backup_0810.7z" (2.3GB) from
          \\MFL-FS03\Shared\DispatchRecords\ and \\MFL-FS03\Shared\CustomerContracts\;
          file immediately moved to C:\Users\Public\ on the same host
  Time: 10:16:29 UTC
```

## Task

TP / FP / Ambiguous for J-001 through J-007, at pace (~2-3 min/alert target). Note correlation
across the queue, flag prioritization changes once J-007 fires, and close with a shift-handoff
summary.
