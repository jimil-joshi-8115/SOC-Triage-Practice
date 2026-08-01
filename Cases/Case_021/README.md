# Case_021 — Sign-in from Risky IP + Legacy Authentication (Azure AD)

**Phase:** 4 (Cases 21–30) — Cloud domain introduced
**Format:** Microsoft Sentinel Incident (ticket-only, no Splunk verification — analyst's call)
**Severity:** Medium

---

## Incident

```
Microsoft Sentinel
─────────────────────────────────────────────
Incident ID:        INC-40217
Title:               'Sign-in from a risky IP address' correlated with 
                      'Legacy authentication protocol used'
Severity:            Medium
Status:              New
Owner:               Unassigned
Created time:        2026-07-31 03:14:22 UTC

Alert 1: Sign-in from a risky IP address
  Provider:          Microsoft Entra ID Protection
  Description:       User signed in from an IP address that has been flagged 
                      as risky by Microsoft Threat Intelligence.
  Entities:
    Account:         r.mehta@corptenant.onmicrosoft.com
    IP:              41.223.118.52
    Location:        Lagos, Nigeria (ASN: AS37282, hosting/consumer ISP mix)

Alert 2: Legacy authentication protocol used
  Provider:          Microsoft Entra ID Protection
  Description:       Sign-in occurred using a legacy authentication protocol,
                      which does not support modern security controls (MFA,
                      Conditional Access).
  Entities:
    Account:         r.mehta@corptenant.onmicrosoft.com
    Client app:      IMAP4
    Application:     Office 365 Exchange Online
    Conditional Access Result: 
                     Not applied (legacy protocol not evaluated)
    Result:          Success
    Device state:    Not registered, Not compliant

Alert 2.5 (correlated context): 
    User's last 30-day sign-in geography: Ahmedabad (95%), Mumbai (5%)

MITRE ATT&CK (Sentinel-tagged):  InitialAccess, T1078 (Valid Accounts)
```

**Investigation Graph tab (Sentinel):** Account `r.mehta` ↔ IP `41.223.118.52` ↔ 2 alerts, 1 incident.

---

## Task

Determine TP / FP / Ambiguous. No hints — full independent judgment call.
