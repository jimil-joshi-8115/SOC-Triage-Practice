# Case_049 — 🏁 Bonus Final Exam, Stage 2: Credential Dumping → Domain Controller Pivot, Confirmed Cryptomining, S3 Lockout

**Status:** Bonus material — not counted toward the 150-alert target (reached at Case_047).
Continues directly from Case_048's two confirmed incidents.
**Format:** Mixed — EDR, AWS CloudTrail/network telemetry, Windows Security Event Log, Azure AD
Audit Log, 5-alert queue
**Company:** Aurora Resorts & Casinos (internal alias — sanitized)
**Splunk verified:** No — ticket-only (analyst decision)

---

## Alerts (as received at trigger time)

```
Alert DD-001 — Endpoint: Credential Dumping Tool Execution
  Severity: Critical
  Host: MFL-WKS0287 (t.oconnor's host, from Case_048's CC-003)
  Detail: loader.ps1 (downloaded in CC-003) executed and subsequently
          launched a process matching known credential-dumping tool
          behavior (LSASS memory access via a non-standard process,
          "svchost_update.exe", masquerading as a system process but
          running from C:\Users\t.oconnor\AppData\Local\Temp\)
  Time: 09:35:00 UTC

Alert DD-002 — AWS: Network Traffic From GPU Instances to Known Mining Pool
  Severity: Critical
  Actor: backup-svc-2 instances (from Case_048's CC-006)
  Detail: All 12 GPU instances in ap-southeast-3 established outbound
          connections to a domain associated with a cryptocurrency mining
          pool, port 3333 (Stratum protocol) — confirms the instances'
          purpose
  Time: 09:40:00 UTC

Alert DD-003 — Azure AD: Guest User Invited to Tenant
  Severity: Low
  Actor: hr-onboarding-automation@auroraresorts.com
  Detail: External guest user invited for an active recruiting/interview
          process (candidate access to a shared interview-scheduling
          document); matches documented HR process, guest scoped to a
          single SharePoint folder, auto-expires in 14 days
  Time: 09:42:00 UTC

Alert DD-004 — Endpoint: Domain Controller Authentication Using Dumped Credentials
  Severity: Critical
  Host: AURORA-DC01
  Account: it-infra-lead@auroraresorts.com (a DIFFERENT, high-privilege
           account — NOT t.oconnor's own credentials)
  Detail: Successful authentication to the domain controller using
          it-infra-lead's credentials, originating from t.oconnor's
          workstation (MFL-WKS0287) — same host as DD-001; it-infra-lead
          has no documented reason to authenticate FROM this workstation
  Time: 09:47:30 UTC (12 minutes after DD-001)

Alert DD-005 — AWS: S3 Bucket Policy Changed on Backup Archive
  Severity: High
  Actor: backup-svc-2
  Detail: Bucket policy on "aurora-backups-critical" changed to deny all
          access except from the backup-svc-2 role itself — effectively
          locking out all legitimate administrators from the organization's
          own backup archive
  Time: 09:50:15 UTC
```

## Task

Stage 2, continuing from Stage 1. TP / FP / Ambiguous for DD-001 through DD-005. Identify which
incident (s.mehta/backup-svc-2, or t.oconnor) each alert belongs to, or if it's unrelated to
both. Give particular thought to DD-004 — what it means for credentials to move from a
low-privilege compromised host to a high-privilege account.
