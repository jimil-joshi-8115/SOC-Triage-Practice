# Verdict — Case 037

## Q-001: 🔴 Verdict: TRUE POSITIVE
## Q-002: 🔴 Verdict: TRUE POSITIVE (Critical)
## Q-003: 🟢 Verdict: FALSE POSITIVE

**Q-001 and Q-002 are TP as a single correlated incident. Q-003 is unrelated.**

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Steal Web Session Cookie | T1539 | Compromised session token used to impersonate r.desai (Q-001) |
| Valid Accounts | T1078 | Session token used to access resources as the legitimate user (Q-001/Q-002) |
| Unsecured Credentials: Credentials in Files / Cloud Secrets | T1552 | Bulk export of production environment variables including cloud and database credentials (Q-002) |

---

## Justification

### Q-001 — TP
r.desai's session token was used to clone a private repository from an IP with zero prior
history in 90 days, at 06:44 IST — outside the documented 09:00-18:00 IST working hours. Both
deviations (location and timing) are independently notable and compound each other.

### Q-002 — TP, Critical
The same session, 2 minutes later, read the production secrets context — a resource explicitly
noted as normally accessed only by automated pipeline jobs, never an interactive user session —
and 3 minutes after that, bulk-exported all 14 environment variables (including
AWS_SECRET_ACCESS_KEY, DB_PROD_PASSWORD, and STRIPE_API_KEY) in a single action, with no
equivalent bulk-export anywhere in 90 days of history. This directly mirrors the real-world
CircleCI breach this scenario is grounded in: a compromised session token used to reach and
exfiltrate production secrets that would otherwise require automation-level access.

**Correlation:** Q-001 and Q-002 are the same uninterrupted session — access to source code
followed immediately by access to and exfiltration of production credentials. One incident.

### Q-003 — FP
Fully automated action, performed by a documented rotation bot, from an internal IP, tied to an
explicit change record (CHG-9012) matching the stated quarterly schedule. No connection to the
Q-001/Q-002 session or account.

---

## What Would Change These Verdicts

- **Q-001 → FP:** confirmed remote work arrangement for r.desai placing them in Moldova at this
  time, or a known approved VPN egress point there.
- **Q-002 → FP:** essentially not plausible given the explicit note that this context is never
  read interactively — would require a documented, approved emergency access exception.
- **Q-003 → TP:** if the rotation timing deviated from CHG-9012's schedule or originated from an
  external/unexpected IP.

None of these apply in this ticket — verdicts stand as TP / TP / FP.

---

## Recommended Response Actions

1. **Immediately revoke r.desai's session token** and force re-authentication through a
   verified channel.
2. **Rotate all 14 exported environment variables/secrets immediately** — treat every one as
   compromised, including AWS_SECRET_ACCESS_KEY, DB_PROD_PASSWORD, and STRIPE_API_KEY.
3. Investigate r.desai's endpoint for malware/session-token theft (matching the real-world
   CircleCI pattern of laptop-based infostealer malware) — do not assume the account itself was
   maliciously used by its owner without ruling this out first.
4. Audit all production systems accessible via the exfiltrated credentials for signs of
   unauthorized access using them.
5. Review the private repository (`internal-payment-service`) for any unauthorized changes or
   additional access since the clone.
6. Treat this as a confirmed secrets/credentials breach — begin incident notification processes
   for any downstream systems (AWS, database, payment processor) tied to the exposed keys.
7. Escalate to L2/IR immediately.
8. No action needed on Q-003 beyond standard closure.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | Q-001: TP · Q-002: TP (Critical) · Q-003: FP |
| Confidence | High (all three) |
| Verification method | Splunk — sample CI/CD platform audit log data (CSV: `cicd_auditlog_case037.csv`, host `JIMIL-JOSHI`) |
| Triage Time | 2 minutes (real, tracked) |
| Escalated | Yes — Q-001/Q-002 (would be, in real SOC, as confirmed secrets breach) |
| Corrections during investigation | 0 |
| Scenario basis | Adapted from the December 2022/January 2023 CircleCI breach; IOCs and identities fully sanitized/fictional |
