# Case_029 — SSRF Against WAF → IAM Credential Theft → Mass S3 Enumeration & Exfiltration

**Phase:** 4 (Cases 21–30) — AWS, rapid-response format, 5-alert queue
**Format:** WAF Access Log + AWS CloudTrail + S3 Server Access Logs + AWS Config
**Company:** Aurora Resorts & Casinos (internal alias — sanitized, same as Case_024)
**Splunk verified:** No — ticket-only, rapid-response (no verification step, same format as Case_018)

**Scenario basis:** Adapted from the publicly documented July 2019 Capital One data breach — a
Server-Side Request Forgery (SSRF) vulnerability in a misconfigured WAF was used to query the
AWS EC2 instance metadata service, stealing temporary IAM credentials for an overprivileged
role, which were then used to enumerate and download data from over 700 S3 buckets. All
company, role, bucket, and IP names below are fictional/sanitized; only the attack chain
structure is grounded in the real incident.

---

## Alerts (as received at trigger time)

```
Alert I-001 — WAF: Anomalous Outbound Request Pattern
  Severity: Medium
  Detail: WAF backend made 47 outbound HTTP requests to 169.254.169.254 (AWS
          instance metadata service) within 90 seconds — this endpoint is never
          legitimately queried by WAF rule logic
  Host: aurora-waf-prod-01

Alert I-002 — IAM: Temporary Credentials Used From Unusual Source
  Severity: High
  Role: aurora-waf-ec2-role (attached to aurora-waf-prod-01)
  Detail: Temporary credentials for this role used to call `sts:GetCallerIdentity`
          then `s3:ListBuckets` — this role has never called S3 APIs in its
          180-day CloudTrail history (intended purpose: WAF logging to CloudWatch only)
  Source IP: 104.28.19.201 (external — role's API calls normally originate from
             the instance's internal AWS network path, never an external IP)

Alert I-003 — S3: Mass Object Enumeration Across Buckets
  Severity: Critical
  Actor: aurora-waf-ec2-role (same credentials as I-002)
  Detail: `ListObjectsV2` called against 14 different S3 buckets in 4 minutes,
          including `aurora-guest-pii-archive` and `aurora-payment-records-2024`
  Source IP: 104.28.19.201

Alert I-004 — S3: Large-Scale Object Download
  Severity: Critical
  Actor: aurora-waf-ec2-role
  Detail: 3,800+ GetObject calls across the 2 sensitive buckets identified in
          I-003, totaling 41GB, over 22 minutes
  Source IP: 104.28.19.201

Alert I-005 — IAM: Role Policy Review Flag (Pre-Existing, Unrelated Finding)
  Severity: Low
  Detail: `aurora-billing-readonly-role` flagged for having `iam:PassRole`
          permission broader than necessary — recurring finding, open ticket
          #SEC-4471 already tracking remediation, scheduled for next sprint
  Actor: N/A (automated compliance scan, not tied to any specific access event)
```

## Task

Rapid-response format — work fast. TP / FP / Ambiguous for I-001 through I-005. This queue
tests whether the analyst catches that I-005 is unrelated pre-existing noise, and correctly
identifies the single root cause driving I-001 through I-004.
