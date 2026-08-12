# Verdict — Case 032

## L-001: 🔴 Verdict: TRUE POSITIVE
## L-002: 🔴 Verdict: TRUE POSITIVE

**Both alerts are TP as a single correlated incident.**

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Valid Accounts: Cloud Accounts | T1078.004 | Unexplained Global Admin privilege on a standard user account (L-001) |
| Modify Authentication Process: Conditional Access Policies | T1556.009 | Self-added to a Conditional Access exemption group to bypass MFA (L-001) |
| Use Alternate Authentication Material | T1550 (adjacent) | Legacy-protocol sign-in exploiting the CA bypass, MFA not evaluated (L-002) |

---

## Justification

### L-001 — TP
Two compounding issues, both requiring attention. First, `p.nair`, a standard Marketing
account, holds Global Administrator — the highest privilege tier in Azure AD — granted 6 days
prior with no documented justification found. This should have been caught by the access review
process itself. Second, that unexplained privilege was used to self-add the account to
`CA-Legacy-Exempt`, a group whose documented purpose is limited to service accounts and which
exempts members from all Conditional Access enforcement including MFA. A human user account
using admin rights to remove security controls from itself is self-service privilege abuse, not
a legitimate administrative action performed on behalf of the organization.

### L-002 — TP
Direct result of L-001: a legacy-protocol (POP3) sign-in, 2.5 minutes after the CA exemption was
obtained, from an external IP with no prior appearance in 90 days of history, with MFA never
evaluated because Conditional Access was bypassed. No mitigating context (travel, VPN, approved
exception) is present.

**Correlation:** L-001 and L-002 are one incident — the privilege grant, self-exemption, and
resulting unprotected sign-in form a complete, self-contained takeover sequence that required no
external technique like phishing or credential theft, only misuse of privileges that should not
have existed on this account in the first place.

---

## What Would Change These Verdicts

- **L-001 → FP:** a documented, approved justification for the Global Admin grant (e.g., a
  legitimate elevated-access project) surfacing after the fact, and a documented, approved
  reason for this specific account's temporary CA exemption tied to that project.
- **L-002 → FP:** confirmed employee travel, a known corporate VPN egress matching this IP, or
  a documented approved exception for POP3 use by this account.

None of these apply in this ticket — verdicts stand as TP / TP.

---

## Recommended Response Actions

1. **Immediately remove p.nair from the CA-Legacy-Exempt group** to restore MFA/Conditional
   Access enforcement.
2. **Revoke the Global Administrator role from p.nair immediately** — no standard Marketing
   account should hold this privilege without clear, documented justification.
3. Disable the account and force a credential reset through a verified, out-of-band channel;
   revoke all active sessions/tokens.
4. **Escalate the underlying access-review failure** — audit how this Global Admin grant was
   approved 6 days ago and identify whether other unjustified privilege grants exist from the
   same review cycle.
5. Audit the full membership of CA-Legacy-Exempt for any other non-service accounts that
   shouldn't be there.
6. Review mailbox activity since the L-002 sign-in for further compromise indicators (inbox
   rules, sent items, data access).
7. Block source IP 45.8.211.19 at the tenant/network level.
8. Escalate to L2/IR given the confirmed privilege misuse and unprotected account access.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | L-001: TP · L-002: TP |
| Confidence | High (both) |
| Verification method | Ticket-only — no Splunk query run (analyst decision) |
| Triage Time | 4 minutes (real, tracked) |
| Escalated | Yes — both, plus underlying access-review process (would be, in real SOC) |
| Corrections during investigation | 0 |
