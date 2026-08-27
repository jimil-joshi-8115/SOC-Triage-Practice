# Verdict — Case 047

## BB-001: 🔴 Verdict: TRUE POSITIVE (Critical)
## BB-002: 🟢 Verdict: FALSE POSITIVE

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Trusted Relationship / Modify Authentication Process: Federation Trust | T1556 (adjacent) | Unauthorized federated domain trust bypassing password/MFA for the entire tenant (BB-001) |

---

## Justification

### BB-001 — TP, Critical
A new federated domain trust to an unrecognized external identity provider was established,
giving that provider the ability to issue authentication tokens Azure AD will accept as valid
for any user in the tenant — an alternate authentication path bypassing password and MFA
entirely. No change ticket exists, and the mandatory 2-person change process required for
domain federation (policy SEC-SOP-08) was not followed. This action is TP on its technical and
procedural severity alone, independent of who performed it or why.

**On the account-status question:** the session originated 15 minutes after it-infra-lead's
normal login, from a new IP, with no separate alert confirming account compromise. This is a
genuinely open question — the action could reflect a hijacked session/compromised account, or
an insider bypassing proper process — but resolving it is not a precondition for this verdict.
Whether performed by an external attacker or the documented account holder acting outside
policy, an unapproved, no-ticket, off-hours tenant-wide authentication bypass is TP either way.
This open question is flagged explicitly for response and investigation, not left unresolved in
a way that weakens the verdict.

### BB-002 — FP
Fully documented, CISO-approved change tied to an explicit change ticket (CHG-9701), performed
during standard business hours the day prior, with no connection to BB-001.

---

## What Would Change This Verdict

- **BB-001 → FP:** discovery of an approved, documented emergency change process invoked for
  this exact federation trust (would require explicit verification given policy SEC-SOP-08 was
  bypassed) — even then, the off-hours timing and new-IP session origin would warrant follow-up.
- **BB-002 → TP:** if CHG-9701 could not be verified or the CISO approval were found to be
  fraudulent.

---

## Recommended Response Actions

1. **Immediately remove the unauthorized federated domain trust** — highest priority, since
   this represents a standing tenant-wide authentication bypass.
2. Investigate it-infra-lead's account and session directly: confirm whether the account/session
   was compromised (check for signs of credential theft, unusual device, or session hijacking)
   or whether the documented account holder performed this action, and if so, why the mandatory
   2-person process was bypassed.
3. Force a credential reset on it-infra-lead's account through a verified, out-of-band channel
   as a precaution regardless of the outcome of Step 2.
4. Audit sign-in logs tenant-wide for any authentications that used tokens issued via the rogue
   federation trust during its active window — treat any such sign-ins as potentially
   unauthorized.
5. Review and reinforce enforcement of SEC-SOP-08's 2-person approval requirement for domain
   federation changes — consider technical controls (e.g., requiring a second admin's explicit
   approval in Azure AD PIM) rather than relying on process alone.
6. Escalate to L2/IR immediately given the severity and tenant-wide impact.
7. No action needed on BB-002 beyond standard closure.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | BB-001: TP (Critical) · BB-002: FP |
| Confidence | High (both) |
| Verification method | Ticket-only — no Splunk query run (analyst decision) |
| Triage Time | 3 minutes (real, tracked) |
| Escalated | Yes — BB-001 (would be, in real SOC) |
| Corrections during investigation | 0 |
| Milestone | Final case counting toward the 150-alert target — 148 + 2 = 150 reached |
