# Verdict — Case 028

## H-001: 🔴 Verdict: TRUE POSITIVE
## H-002: 🔴 Verdict: TRUE POSITIVE
## H-003: 🔴 Verdict: TRUE POSITIVE
## H-004: 🟢 Verdict: FALSE POSITIVE

**H-001, H-002, and H-003 are TP as a single correlated hybrid-identity incident.**

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | RC4-downgraded TGS request burst against 9 service accounts (H-001) |
| Valid Accounts | T1078 | Compromise/misuse of the Azure AD Connect sync account (H-002) |
| Account Manipulation: Additional Cloud Roles | T1098.003 (adjacent) | Unverified OAuth app granted Directory.ReadWrite.All (H-003) |

---

## Justification

### H-001 — TP
9 TGS requests for 9 different service accounts within 45 seconds, using RC4 instead of AES,
against a baseline of ~1 AES-only request per hour, is the textbook Kerberoasting signature —
RC4 is deliberately targeted because its hashes are far cheaper to crack offline than AES.

### H-002 — TP
The Azure AD Connect sync account (`MSOL_...`) is the trust bridge between on-prem AD and
Azure AD. Its password being changed by a regular user account (`t.bhatt`) — the same account
that performed the Kerberoasting burst 3 minutes earlier — with no documented rotation policy
ever having touched this account in 400 days, is the direct continuation of H-001, not a
separate or explainable administrative action.

### H-003 — TP
`Directory.ReadWrite.All` is full read/write access to every object in Azure AD. An unverified
application, registered only 2 days prior, granted this permission by the just-compromised sync
account 2 minutes after H-002, is a deliberate persistence mechanism — a backdoor that operates
independently of any single compromised user account and survives ordinary credential resets on
`t.bhatt` or even the sync account itself.

**Correlation:** H-001, H-002, and H-003 are one continuous hybrid-identity takeover across a
6-minute window: Kerberoasting obtains crackable credential material → that access compromises
the on-prem/cloud identity bridge account → that bridge account's privilege plants a
directory-wide persistent backdoor in Azure AD. Treating these as three independent alerts
would miss that the real, complete impact is full Azure AD directory control, not just an
on-prem credential-theft attempt.

### H-004 — FP
Different account entirely (documented automation account `svc-gpo-mgmt`), routine monthly GPO
refresh, occurring within the documented scheduled maintenance window. No overlap in account,
timing pattern, or action type with the H-001/H-002/H-003 chain.

---

## What Would Change These Verdicts

- **H-001 → FP:** a documented, approved security assessment/pentest window covering this
  account and timeframe.
- **H-002 → FP:** a change ticket showing this was a planned, authorized sync account
  credential rotation performed by IT.
- **H-003 → FP:** the app publisher later verified as a legitimate, approved vendor with a
  documented business justification for `Directory.ReadWrite.All`.
- **H-004 → TP:** if the timing fell outside the documented maintenance window, or the account
  performing it were not the documented automation account.

None of these apply in this ticket — verdicts stand as TP / TP / TP / FP.

---

## Recommended Response Actions

1. **Immediately revoke "SecureSync Helper"'s OAuth grant and remove `Directory.ReadWrite.All`**
   — highest priority, since this is the persistent, directory-wide backdoor.
2. Force an immediate password reset on the Azure AD Connect sync account (`MSOL_a8f3d92e1c`)
   through a verified, secure process — not standard SSPR, given its sensitivity.
3. Disable `t.bhatt`'s account and investigate the source of the Kerberoasting activity
   (compromised workstation, stolen credentials, insider activity).
4. Audit all TGS requests and RC4 usage across the domain in the surrounding time window to
   identify if other service accounts were also targeted.
5. Review all OAuth app registrations and grants in the tenant from the last 7 days for
   similar unverified/newly-registered apps with high-privilege permissions.
6. Escalate to L2/IR immediately — this represents full hybrid-identity compromise with
   directory-wide persistence established.
7. No action needed on H-004 beyond standard closure.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | H-001: TP · H-002: TP · H-003: TP · H-004: FP |
| Confidence | High (all four) |
| Verification method | Ticket-only — no Splunk query run (analyst decision, time-constrained) |
| Triage Time | 3 minutes (real, tracked) |
| Escalated | Yes — H-001/H-002/H-003 chain (would be, in real SOC) |
| Corrections during investigation | 0 |
