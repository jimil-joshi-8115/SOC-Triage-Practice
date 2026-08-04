# Case_024 — Helpdesk Vishing → Okta Takeover → Rogue IdP Persistence → Ransomware Staging

**Phase:** 4 (Cases 21–30) — Mixed Endpoint + Cloud, 5-alert queue
**Format:** Okta System Log + Windows Security Event Log (correlated queue)
**Company:** Aurora Resorts & Casinos (internal alias — sanitized)
**Splunk verified:** ✅ Yes

**Scenario basis:** Adapted from the publicly documented September 2023 MGM Resorts / Scattered
Spider breach — helpdesk social-engineering (vishing) leading to Okta privilege escalation and
a rogue Identity Provider registration for persistence, followed by on-prem ransomware staging.
All company names, usernames, IPs, and timestamps below are fictional/sanitized; only the
attack chain structure and technique sequence are grounded in the real incident.

**Data source:**
```
source      = mixed_case024.csv
host        = JIMIL-JOSHI
sourcetype  = csv
Total events indexed: 12 (5 signal events across the attack chain, 7 baseline/noise events)
```

---

## Alerts (as received at trigger time)

```
Alert D-001 — Privileged Account Password Reset via Helpdesk
  Severity: Low (routine helpdesk action, auto-logged)
  Actor: helpdesk-agent-hd07
  Target: r.kapoor@auroraresorts.com (VP Infrastructure — privileged admin account)
  Verification method logged: Employee ID + DOB (phone-based)

Alert D-002 — Login From Never-Before-Seen Location
  Severity: Medium
  Account: r.kapoor@auroraresorts.com
  Detail: Session started from Bucharest, Romania — immediately following D-001's reset
  Baseline: 90-day history shows Ahmedabad, India only

Alert D-003 — New External Identity Provider Registered
  Severity: High
  Account: r.kapoor@auroraresorts.com
  Detail: SAML2 IdP 'shadow-idp-relay' registered, accepts external assertions

Alert D-004 — Privilege Escalation to Super Administrator
  Severity: High
  Account: r.kapoor@auroraresorts.com
  Detail: Role changed from scoped Infrastructure admin to Super Administrator

Alert D-005 — Endpoint: Defender Disabled + Shadow Copies Deleted
  Severity: Critical
  Host: AURORA-DC01
  User: r.kapoor
  Detail: PowerShell disabled real-time monitoring, then vssadmin deleted all shadow copies
```

## Task

TP / FP / Ambiguous for each of D-001 through D-005 — verified against indexed Splunk data,
not assumed from the ticket alone. Note any correlation across the queue.
