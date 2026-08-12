# Case_032 — Azure AD: Unexplained Global Admin Grant → Self-Exemption From Conditional Access → Legacy-Protocol Takeover

**Phase:** 5 (Cases 31–50) — Azure AD, 2-alert batch
**Format:** Microsoft Entra ID Audit Log + Sign-In Log
**Company:** Aurora Resorts & Casinos (internal alias — sanitized)
**Splunk verified:** No — ticket-only (analyst decision)

---

## Alerts (as received at trigger time)

```
Alert L-001 — Azure AD: User Added to Conditional Access Exclusion Group
  Severity: High
  Group: "CA-Legacy-Exempt" (members excluded from all Conditional Access
         policies, including MFA enforcement — documented purpose: temporary
         exemption for service accounts during migration, reviewed quarterly)
  Added account: p.nair@auroraresorts.com (Standard user, Marketing dept —
                 not a service account)
  Actor who added: p.nair@auroraresorts.com (self-added; account has Global
                    Administrator role, granted 6 days ago as part of a
                    broader access review — no documented justification found
                    for Global Admin on a Marketing account)
  Time: 11:02:14 UTC

Alert L-002 — Azure AD: Sign-In via Legacy Protocol, No MFA
  Severity: High
  Account: p.nair@auroraresorts.com
  Detail: Successful sign-in via POP3, MFA not evaluated (Conditional Access
          not applied due to CA-Legacy-Exempt group membership from L-001)
  Source IP: 45.8.211.19 (external, first appearance in 90-day history)
  Application: Office 365 Exchange Online
  Time: 11:04:52 UTC
```

## Task

TP / FP / Ambiguous for L-001 and L-002. L-001 contains a detail worth scrutinizing closely
before assessing L-002.
