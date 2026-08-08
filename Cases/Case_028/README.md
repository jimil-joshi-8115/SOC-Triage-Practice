# Case_028 — Hybrid Identity Takeover: Kerberoasting → Sync Account Compromise → Rogue OAuth App

**Phase:** 4 (Cases 21–30) — Hybrid Identity (Azure AD + On-Prem), 4-alert batch
**Format:** Mixed — Windows Security Event Log (on-prem) + Microsoft Entra ID Protection (cloud)
**Splunk verified:** No — ticket-only (analyst decision, time-constrained)

---

## Alerts (as received at trigger time)

```
Alert H-001 — On-Prem: Kerberoasting Indicator
  Severity: Medium
  Host: MFL-DC01
  Account: t.bhatt
  Detail: 9 TGS (service ticket) requests in 45 seconds for 9 different service
          accounts, all using RC4 encryption (weaker, crackable offline) instead
          of AES — account's normal Kerberos activity is ~1 TGS request/hour, AES only
  Time: 22:14 UTC

Alert H-002 — Azure AD Connect: Sync Account Password Changed
  Severity: High
  Account: MSOL_a8f3d92e1c (Azure AD Connect sync service account — on-prem to
           cloud identity bridge)
  Detail: Password changed via on-prem AD; this account has no documented
          password rotation policy triggered in the last 400 days
  Actor: t.bhatt (same account as H-001)
  Time: 22:17 UTC

Alert H-003 — Azure AD: New OAuth App Granted Directory.ReadWrite.All
  Severity: High
  App name: "SecureSync Helper"
  Granted by: MSOL_a8f3d92e1c
  Permission: Directory.ReadWrite.All (full read/write access to all directory objects)
  App publisher: Unverified, registered 2 days ago
  Time: 22:19 UTC

Alert H-004 — On-Prem: Routine GPO Update Applied
  Severity: Low
  Host: MFL-DC01
  Account: svc-gpo-mgmt (documented automation account, scheduled task)
  Detail: Standard monthly GPO refresh — updated password complexity policy
          object; matches scheduled maintenance window (last day of month, 22:00-23:00)
  Time: 22:20 UTC
```

## Task

TP / FP / Ambiguous for H-001 through H-004. Pay attention to what `t.bhatt` and the sync
account (`MSOL_...`) have in common — this queue tests whether the analyst catches a specific
escalation pattern spanning on-prem and cloud in a single chain.
