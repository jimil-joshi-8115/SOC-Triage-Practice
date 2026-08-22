# Verdict — Case 042

## W-001: 🔴 Verdict: TRUE POSITIVE
## W-002: 🔴 Verdict: TRUE POSITIVE (Critical)
## W-003: 🟢 Verdict: FALSE POSITIVE

**W-001 and W-002 are TP as a single correlated incident. W-003 is unrelated and illustrates
the legitimate version of the same action type.**

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Modify Authentication Process: Conditional Access Policies | T1556.009 | Trusted location policy modified to exempt an attacker-controlled IP from MFA (W-001) |
| Valid Accounts: Cloud Accounts | T1078.004 | Sign-in exploiting the modified policy, no MFA required (W-002) |

---

## Justification

### W-001 — TP
d.varma, a Marketing Coordinator with no IT or security function, added an external IP with no
connection to any known Aurora office, ISP, or VPN range to the org's MFA-exempt trusted
location list — org-wide security infrastructure entirely outside this role's documented
function, with no supporting change ticket.

### W-002 — TP, Critical
The exact IP added in W-001 was used to sign in 3 minutes later with no MFA prompt, directly
confirming the policy modification was made to enable this bypass.

**Correlation:** W-001 and W-002 form one incident. Critically, this is more dangerous than a
standard compromised-credential sign-in: because the exemption is now embedded in the tenant's
Conditional Access policy rather than tied to a single account's credentials, **any account**
signing in from this IP going forward will also bypass MFA. A password reset on d.varma's
account alone would not remove this exposure — the trusted-location entry itself must be
identified and removed. This is persistence at the security-policy level, a fundamentally
broader and more durable foothold than typical account takeover.

### W-003 — FP
A role-appropriate action by the IT Infrastructure Lead, adding a confirmed, ISP-verified IP
range for a new branch office, tied to an explicit change ticket (CHG-9502). No connection to
the W-001/W-002 incident in actor, timing, or IP. Serves as a useful contrast: the same action
type (modifying a trusted location) is either a severe finding or standard practice depending
entirely on actor legitimacy and documentation.

---

## What Would Change These Verdicts

- **W-001/W-002 → FP:** a documented, approved exception explaining why a Marketing Coordinator
  needed to modify Conditional Access trusted locations, and independent confirmation that
  185.220.101.212 belongs to a legitimate Aurora-affiliated network (unlikely given the role
  mismatch and unexplained IP).
- **W-003 → TP:** if the added range were later found to not match the confirmed ISP block, or
  if CHG-9502 could not be verified as legitimate.

None of these apply in this ticket — verdicts stand as TP / TP / FP.

---

## Recommended Response Actions

1. **Immediately remove 185.220.101.212 from the "Corporate HQ - Trusted Range" named
   location** — highest priority, since this closes the tenant-wide MFA-bypass exposure, not
   just the individual account risk.
2. Disable d.varma's account and force a credential reset through a verified, out-of-band
   channel; revoke all active sessions/tokens.
3. Audit all sign-ins from 185.220.101.212 since W-002, across ALL accounts, not just
   d.varma's — since the trusted-location exemption applied tenant-wide, any account could have
   exploited it during the exposure window.
4. Review Conditional Access audit logs broadly for any other unauthorized modifications to
   trusted locations or other CA policies in the recent past.
5. Restrict who can modify Conditional Access named locations — this action should require a
   privileged administrative role, not be available to standard user accounts, if that gap
   exists in the current permission model.
6. Escalate to L2/IR given the tenant-wide security-control impact.
7. No action needed on W-003 beyond standard closure.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | W-001: TP · W-002: TP (Critical) · W-003: FP |
| Confidence | High (all three) |
| Verification method | Ticket-only — no Splunk query run (analyst decision) |
| Triage Time | 2.3 minutes (real, tracked) |
| Escalated | Yes — W-001/W-002 (would be, in real SOC, given tenant-wide policy impact) |
| Corrections during investigation | 0 |
