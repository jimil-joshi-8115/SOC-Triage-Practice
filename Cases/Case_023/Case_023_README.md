# Case_023 — AWS Account Compromise: Tor Console Login + IAM Privilege Escalation

**Phase:** 4 (Cases 21–30) — AWS domain
**Format:** Amazon GuardDuty Findings (2-finding batch)
**Splunk verified:** No — ticket-only (analyst decision)

---

## Findings

```
Finding AG-001
  Type:            UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B
  Severity:        Medium (5.0)
  Account ID:      847291056633
  Resource:        IAMUser: s.rathod
  Region:          ap-south-1 (Mumbai)
  Description:     A successful console login was observed from an IP address on
                    our internal threat list.
  Actor IP:        193.32.248.14 (Netherlands — flagged as Tor exit node)
  MFA used:        No
  Time:            2026-08-01 02:11:47 UTC
  User's last 14-day console login pattern: 103.211.44.0/24 (India), MFA used 100% of time

Finding AG-002
  Type:            Discovery:IAMUser/AnomalousBehavior — followed by
                    Persistence:IAMUser/UserPermissions
  Severity:        High (7.5)
  Account ID:      847291056633
  Resource:        IAMUser: s.rathod
  Region:          ap-south-1 (Mumbai)
  Event 1 (02:13:02 UTC): ListUsers, ListRoles, ListAccessKeys, GetAccountAuthorizationDetails
                    — 4 API calls in 6 seconds, none of which s.rathod has called in the
                    prior 90 days of CloudTrail history.
  Event 2 (02:14:38 UTC): CreateAccessKey called for a DIFFERENT IAM user: svc-deploy-bot
                    (a service account with AdministratorAccess policy attached)
  Event 3 (02:15:10 UTC): AttachUserPolicy — svc-deploy-bot granted AdministratorAccess
                    (policy was already present, this was a redundant re-attach — no
                    privilege change, but logged as a distinct CloudTrail event)
  Source IP for all 3 events: 193.32.248.14 (same as AG-001)
```

## Task

TP / FP / Ambiguous for AG-001 and AG-002, plus note any correlation.
