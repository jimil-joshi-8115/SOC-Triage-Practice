# Case_026 — Azure AD: Travel-Explained Sign-In, MFA-Method-Hijack Account Takeover, and an Inconclusive Atypical-Travel Flag

**Phase:** 4 (Cases 21–30) — Azure AD domain, 3-alert batch
**Format:** Microsoft Entra ID Protection — Risk Detections
**Splunk verified:** ✅ Yes

**Data source:**
```
source      = azuread_case026.csv
host        = JIMIL-JOSHI
sourcetype  = csv
Total events indexed: 15 (across 3 accounts: n.verma, p.shah, r.iyer)
```

---

## Alerts (as received at trigger time)

```
Finding F-001 — Sign-in from Unfamiliar Location
  Severity: Low
  Account: n.verma@corptenant.com
  Detail: Successful sign-in from Singapore — first appearance outside India in
          14-day baseline
  MFA: Satisfied
  Time: 2026-07-31 14:22:07 UTC

Finding F-002 — Password Reset + New MFA Method, Unfamiliar Location
  Severity: High
  Account: p.shah@corptenant.com
  Event 1 (02:47:19): Self-service password reset via Kyiv, Ukraine IP — no prior
             history for this user outside India
  Event 2 (02:49:03): New MFA phone method registered — original Authenticator
             method NOT removed, now 2 active methods on the account
  Event 3 (02:51:44): Successful sign-in using the newly-added phone method

Finding F-003 — Atypical Travel Detection
  Severity: Medium
  Account: r.iyer@corptenant.com
  Detail: Sign-in from Lagos, Nigeria, flagged by Entra ID Protection as
          'atypical travel' — Ahmedabad login 62 hours prior, no calendar
          entry found for this specific trip
  MFA: Satisfied
  Time: 2026-08-01 05:12:33 UTC
```

## Task

TP / FP / Ambiguous for F-001, F-002, F-003 — verified against indexed Splunk data. Check both
account baselines and look specifically for mitigating context before deciding.
