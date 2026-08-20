# Case_040 — Mid-Phase-5 Checkpoint: Mixed Cloud Queue With Live Interrupt (Unauthorized S3 Access → Active Exfiltration)

**Phase:** 5 (Cases 31–50) — Mixed Cloud (Azure AD + AWS + GCP + Okta), 5-alert queue with
live interrupt, checkpoint case
**Format:** Mixed — Azure AD Sign-In Log, AWS CloudTrail, GCP BigQuery Audit Log, Okta System Log
**Company:** Aurora Resorts & Casinos (internal alias — sanitized)
**Splunk verified:** No — ticket-only (analyst decision)

---

## Alerts (as received at trigger time)

```
Alert T-001 — Azure AD: Sign-In From New Country
  Severity: Medium
  Account: v.pillai@auroraresorts.com
  Detail: Successful sign-in from Toronto, Canada — first appearance outside
          India in 30-day baseline; MFA satisfied via Authenticator push
          (single approval, no denial pattern)
  HR context: v.pillai's calendar shows "Client Site Visit - Toronto" for
              this exact date range, entered 9 days in advance
  Time: 08:41:02 UTC

Alert T-002 — AWS: IAM Policy Attached Granting S3 Full Access
  Severity: High
  Actor: IAMUser: n.bhatt (Junior DevOps Engineer)
  Detail: AttachUserPolicy — n.bhatt attached "AmazonS3FullAccess" to their
          OWN user account; n.bhatt's role has no documented need for
          account-wide S3 access (works exclusively on a single
          application's CI/CD pipeline, per role documentation); no change
          ticket found
  Time: 13:02:47 UTC

Alert T-003 — GCP: Unusual Query Volume Against BigQuery Dataset
  Severity: Medium
  Actor: a.krishnan@auroraresorts.com (Data Analyst)
  Detail: 40 queries against "customer_analytics" dataset within 15 minutes
          — analyst's normal daily average is 8-12 queries; queries ran
          during a documented quarterly reporting deadline (per team
          calendar: "Q3 Board Report - Data Pull," same week)
  Time: 14:15:00–14:30:00 UTC

Alert T-004 — Okta: Application Assigned to User Group
  Severity: Low
  Actor: IT-Automation-ServiceAccount
  Detail: "Expense-Reporting-Tool" application auto-assigned to the
          "New-Hires-Onboarding" group; matches documented automated
          onboarding workflow, 3 new hires processed this batch
  Time: 15:00:00 UTC

>>> LIVE INTERRUPT — fired while queue still in progress <<<

Alert T-005 — AWS: Using S3FullAccess (from T-002), Mass Bucket Download to External IP
  Severity: Critical
  Actor: n.bhatt (same session/permissions from T-002)
  Detail: 2,100+ GetObject calls across "aurora-guest-pii-archive" and
          "aurora-financial-reports" buckets, 15.6GB total, over 18 minutes
  Source IP: 203.0.113.44 (external, first appearance for this account)
  Time: 15:22:10 UTC
```

## Task

Checkpoint case — work carefully. TP / FP / Ambiguous for T-001 through T-005. Note
correlation, and flag what changes in priority once T-005 fires.
