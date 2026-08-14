# Case_034 — Third-Party Support Engineer Compromise → Okta SuperUser Abuse Across Multiple Customer Tenants

**Phase:** 5 (Cases 31–50) — Okta/SaaS Support Access, 3-alert batch
**Format:** EDR (shared third-party feed) + Okta System Log + Okta SuperUser Audit Log
**Company:** Aurora Resorts & Casinos (as an affected customer tenant)
**Splunk verified:** No — ticket-only (analyst decision)

**Scenario basis:** Adapted from the January 2022 Okta/Sitel breach (Lapsus$) — the real
incident began with RDP access to a third-party customer support engineer's laptop, during
which the attacker added a new authentication factor to the engineer's account and gained
SuperUser-tier access into customer Okta tenants. Support engineers in the real incident could
facilitate password/MFA resets for customer users but could not create/delete users or download
customer databases — this scenario reflects that same realistic scope of impact. All account,
host, and IP details below are fictional/sanitized.

---

## Alerts (as received at trigger time)

```
Alert N-001 — Endpoint: RDP Access to Support-Provider Laptop
  Severity: Medium
  Host: SITEL-SUP-WK14 (third-party customer support engineer laptop, has
        privileged access to Aurora's Okta tenant via the support-provider
        SuperUser tool)
  Detail: Inbound RDP session established from 185.220.101.203 (external,
          no prior history for this host); session active for several hours
  Time: 03:12–07:40 UTC

Alert N-002 — Okta: New MFA Factor Added to Support Engineer's Account
  Severity: High
  Account: support-eng-14@sitelsupport-provider.com
  Detail: New authentication factor (SMS, new phone number) added to this
          support account; account has SuperUser-tier access into customer
          Okta tenants including Aurora's
  Time: 07:22:18 UTC (during the RDP session window from N-001)

Alert N-003 — Okta: Unusual Volume of Password Resets Across Customer Tenants
  Severity: Critical
  Actor: support-eng-14@sitelsupport-provider.com
  Detail: 14 password reset actions triggered across 6 different customer
          organizations' Okta tenants (including Aurora's) within 25 minutes
          — this account's normal daily average is 2-3 resets, within a
          single assigned customer's tenant, tied to logged support tickets
  Time: 07:35–08:00 UTC
```

## Task

TP / FP / Ambiguous for N-001 through N-003. Note correlation, and consider what specifically
makes N-003 more alarming than N-002 alone.
