# Case_046 — SaaS Developer Token Theft: Stolen GitHub PAT Used to Clone Private Repositories

**Phase:** 5 (Cases 31–50) — SaaS / Developer Token Theft, 3-alert batch
**Format:** GitHub Enterprise Audit Log
**Company:** Aurora Resorts & Casinos (internal alias — sanitized)
**Splunk verified:** No — ticket-only (analyst decision)

**Scenario basis:** Adapted from the December 2022 Slack GitHub breach — a limited number of
employee personal access tokens were stolen and misused to access Slack's externally-hosted
GitHub repositories, with the threat actor downloading private code repositories before
detection. Documented indicators of this pattern include token use from unfamiliar IPs,
unexpected repository cloning, and audit log entries showing access outside normal developer
patterns. All company, user, and identifier details below are fictional/sanitized.

---

## Alerts (as received at trigger time)

```
Alert AA-001 — GitHub: Personal Access Token Used From Unfamiliar IP
  Severity: High
  Token owner: m.desouza@auroraresorts.com (Backend Developer, internal
               booking-platform team)
  Detail: PAT (personal access token) used to authenticate from
          77.83.196.44 (Kyiv, Ukraine) — no prior history for this token
          outside Aurora's corporate VPN egress range in 6 months of
          token-creation-to-date history
  Time: 03:22:10 UTC

Alert AA-002 — GitHub: Private Repository Cloned, Off-Hours
  Severity: Critical
  Actor: m.desouza's token (same as AA-001)
  Detail: Full clone of "aurora-booking-platform-core" (contains hardcoded
          staging API keys per last quarter's code-security scan, ticket
          #SEC-4180, still unremediated) and "aurora-internal-tools"
          repositories; m.desouza has commit history on the first repo but
          has never accessed the second; clone occurred at 03:24:00 UTC,
          outside documented on-call hours for this developer
  Source IP: 77.83.196.44 (same as AA-001)

Alert AA-003 — GitHub: Repository Cloned, Normal Developer Activity
  Severity: Low
  Actor: k.iyer@auroraresorts.com (Frontend Developer)
  Detail: Clone of "aurora-web-frontend" repository from Aurora's corporate
          VPN IP range, during documented working hours; k.iyer has
          extensive commit history on this repo, clone matches a routine
          local-environment refresh pattern seen ~weekly for this developer
  Time: 14:10:00 UTC
```

## Task

TP / FP / Ambiguous for AA-001 through AA-003. Note correlation, and consider why access to
`aurora-internal-tools` in AA-002 (a repo the token owner has never touched) matters, relative
to the off-hours timing alone.
