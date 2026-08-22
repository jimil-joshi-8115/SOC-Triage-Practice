# Case_042 — Azure AD: Trusted Location Policy Modified to Establish Tenant-Wide MFA Bypass Persistence

**Phase:** 5 (Cases 31–50) — Azure AD, 3-alert batch
**Format:** Microsoft Entra ID Audit Log
**Company:** Aurora Resorts & Casinos (internal alias — sanitized)
**Splunk verified:** No — ticket-only (analyst decision)

---

## Alerts (as received at trigger time)

```
Alert W-001 — Azure AD: Named Location "Trusted Locations" Modified
  Severity: High
  Named Location: "Corporate HQ - Trusted Range" (referenced by the org's
                  "Require MFA for All Users" Conditional Access policy —
                  sign-ins from this IP range are treated as trusted and
                  exempted from the MFA requirement)
  Actor: d.varma@auroraresorts.com (Marketing Coordinator — no IT/security
         role, no documented reason to modify network security config)
  Detail: A single new IP address, 185.220.101.212 (unrelated to any known
          Aurora office, ISP, or VPN range), was added to the trusted IP
          range; no change ticket found
  Time: 16:44:10 UTC

Alert W-002 — Azure AD: Sign-In From the Newly-Trusted IP, MFA Not Prompted
  Severity: Critical
  Account: d.varma@auroraresorts.com
  Detail: Successful sign-in from 185.220.101.212 — the exact IP added in
          W-001 — with no MFA prompt issued, because the sign-in matched
          the (now-modified) trusted location
  Time: 16:47:33 UTC (3 minutes after W-001)

Alert W-003 — Azure AD: Named Location Range Updated for New Branch Office
  Severity: Low
  Named Location: "Mumbai Branch - Trusted Range"
  Actor: it-infra-lead@auroraresorts.com (IT Infrastructure Lead)
  Detail: IP range for the new Mumbai branch office added to trusted
          locations, tied to documented change ticket CHG-9502 ("New office
          network onboarding — Mumbai"), matches ISP block confirmed with
          the office's internet provider
  Time: 10:05:00 UTC (6 hours before W-001, unrelated account)
```

## Task

TP / FP / Ambiguous for W-001 through W-003. Note correlation, and consider why W-001 is more
dangerous as a persistence mechanism than a simple stolen-credential login would be.
