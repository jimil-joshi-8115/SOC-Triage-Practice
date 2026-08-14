# Verdict — Case 034

## N-001: 🔴 Verdict: TRUE POSITIVE
## N-002: 🔴 Verdict: TRUE POSITIVE
## N-003: 🔴 Verdict: TRUE POSITIVE (Critical)

**All three alerts are TP as a single correlated incident.**

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Remote Services: Remote Desktop Protocol | T1021.001 | External RDP access to the support-provider's privileged laptop (N-001) |
| Multi-Factor Authentication Interception / Modify Authentication Process | T1556 | New MFA factor added to the compromised support account (N-002) |
| Account Access Removal / Valid Accounts | T1531 / T1078 (adjacent) | Mass password resets across multiple customer tenants (N-003) |

---

## Justification

### N-001 — TP
A privileged support-tier machine with downstream SuperUser access into customer Okta tenants
received an inbound RDP session from an external IP with no prior history, active for
approximately 4.5 hours. This access pattern to a machine of this sensitivity is a significant
concern on its own.

### N-002 — TP
A new SMS-based authentication factor was added to the support engineer's account during the
active, unrecognized RDP session — establishing a persistence mechanism independent of the
initial access vector, consistent with an attacker ensuring continued account access even if the
original RDP session or credentials are cut off.

### N-003 — TP, Critical
14 password reset actions across 6 different customer organizations' Okta tenants within 25
minutes, against a documented baseline of 2-3 resets per day within a single assigned tenant,
each normally tied to a logged support ticket. Both the volume spike and — more critically —
the cross-tenant scope confirm this is systematic account-takeover activity spreading across
every customer the compromised account can reach, not routine support work. No ticket
justification is present for any of the 14 actions.

**Correlation:** N-001, N-002, and N-003 form one continuous incident — unauthorized access to
a privileged support machine, used to establish account persistence, immediately followed by
that persisted access being used to mass-reset passwords across multiple customer environments.
This mirrors the real-world concern behind the Okta/Sitel incident this scenario is grounded
in: a single compromised third-party support account creates a blast radius spanning every
customer tenant reachable through it, not just one.

---

## What Would Change These Verdicts

- **N-001 → FP:** a documented, approved remote-access arrangement (e.g., an authorized
  work-from-home VPN/RDP setup) covering this IP and host.
- **N-002 → FP:** a documented, approved account-recovery or device-change process explaining
  the new MFA factor.
- **N-003 → FP:** discovery of a legitimate, large-scale, ticketed maintenance event (e.g., a
  scheduled security-driven mass password reset across multiple customers) explaining the
  volume and scope — would need to be verified against an actual change record, not assumed.

None of these apply in this ticket — verdicts stand as TP / TP / TP.

---

## Recommended Response Actions

1. **Immediately suspend the support-eng-14 account** and terminate all active sessions across
   every customer tenant it has touched.
2. **Notify all 6 affected customer organizations** (including Aurora) — this is a multi-tenant
   incident requiring coordinated response, not one Aurora can fully remediate alone.
3. Remove the newly-added MFA factor from the support account.
4. Force password resets for every account that was reset by this actor during the 07:35–08:00
   window, across all 6 affected tenants, and re-verify the legitimate account owners
   out-of-band before restoring access.
5. Isolate SITEL-SUP-WK14 from the network; forensically image it before further use.
6. Escalate to the third-party support provider's security team and Aurora's own IR team
   simultaneously — this requires cross-organizational coordination given the shared-service
   nature of the compromised access.
7. Review the support-provider's remote-access policy for this class of privileged machine —
   external RDP exposure to a SuperUser-capable host is itself a process failure worth
   addressing regardless of this specific incident.
8. Block source IP 185.220.101.203 at any reachable network boundary.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | N-001: TP · N-002: TP · N-003: TP (Critical) |
| Confidence | High (all three) |
| Verification method | Ticket-only — no Splunk query run (analyst decision) |
| Triage Time | 3 minutes (real, tracked) |
| Escalated | Yes — full chain, multi-tenant (would be, in real SOC) |
| Corrections during investigation | 0 |
| Scenario basis | Adapted from the January 2022 Okta/Sitel breach (Lapsus$) — third-party support engineer laptop compromise via RDP, leading to SuperUser-tier abuse across customer tenants; IOCs and identities fully sanitized/fictional |
