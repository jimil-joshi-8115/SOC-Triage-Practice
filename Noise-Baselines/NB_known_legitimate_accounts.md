# Known-Legitimate Account Patterns vs. Confirmed Masquerading/Abuse Patterns

Distilled from confirmed verdicts across this repo — the standard account baseline vs.
patterns that indicate an account (human or service) is being misused or impersonated.

---

## Legitimate Baseline Account Behavior

- **Service/automation accounts** perform only their documented function, from expected
  IPs/hosts, on expected schedules, with traceable ticket/deployment references
  (e.g., `ci-deploy-sa`, `scheduled-rotation-bot`, `it-storage-admin` — Cases 022, 037, 038, 043).
- **Human accounts** show consistent geography, working-hours patterns, and device fingerprints
  over time, and any deviation is typically accompanied by a specific, dated, positive
  confirming record (a travel calendar entry, a change ticket) — not just an absence of
  suspicion (Cases 021, 026, 032, 040).
- **Frequent-traveler accounts** (e.g., sales/consulting roles) have an established pattern of
  varied international locations — deviation for these accounts must be judged against *their*
  baseline, not a generic "any foreign IP is suspicious" rule (Case_026, F-003 — genuinely
  Ambiguous when MFA held and only a missing calendar entry was the anomaly).

---

## Confirmed Account/Identity Abuse Patterns

### Service-Like Naming to Blend In
**Pattern:** A newly created account given a name that mimics a legitimate service/backup
account, to avoid scrutiny in casual account list reviews.
**Source case:** Case_002 (`hpbackup`)
**Check:** Compare against the actual documented service-account baseline — a plausible-sounding
name is not the same as a verified one.

### Self-Service Privilege Abuse
**Pattern:** An account uses improperly-held elevated privileges to modify its *own* security
posture (e.g., self-adding to an MFA-exemption group, self-attaching an over-permissive IAM
policy).
**Source cases:** Case_032 (W-001), Case_040 (T-002)
**Check:** This is a fundamentally different, more direct risk pattern than an admin action
performed *on behalf of* the organization — flag it as such explicitly in the write-up.

### Unexplained Privilege Grants
**Pattern:** An account holds a privilege level (e.g., Global Administrator) with no documented
justification, disproportionate to its role.
**Source case:** Case_032 (L-001)
**Check:** This is itself a red flag worth escalating as a root-cause access-review failure —
independent of anything the account subsequently does with that privilege.

### Role/Access-Scope Mismatch
**Pattern:** An actor's action, credential, or token reaches a resource, system, or repository
entirely outside their documented scope of work — with no comparable innocent explanation the
way off-hours timing alone might have.
**Source cases:** Case_033 (k.solanki), Case_037 (r.desai's session), Case_046 (m.desouza's
token accessing `aurora-internal-tools`)
**Check:** When multiple anomalies co-occur (e.g., off-hours timing AND scope mismatch), rank
them — timing alone is a soft signal with plausible innocent explanations; scope mismatch is a
hard signal with none. Don't treat all co-occurring red flags as equal weight.

### Session-Type Mismatch
**Pattern:** An interactive human session performs an action explicitly documented as
automation-only (e.g., reading a production secrets context that only CI/CD jobs should touch).
**Source case:** Case_037 (Q-002)
**Check:** The action itself may be routine in the abstract — the actor *type* performing it is
the actual signal.

### Compromised Bridge/Identity-Provider Accounts
**Pattern:** A low-value account compromise cascades into a high-value identity bridge account
(e.g., Azure AD Connect sync account, ADFS trust) being touched shortly after.
**Source case:** Case_028 (H-002)
**Check:** Treat any unusual activity on identity-bridge accounts as high priority regardless of
how it was reached — these accounts have outsized blast radius.

### Concurrent Sessions on One Account (Compromised Credentials, Not Just a Session)
**Pattern:** The same account performs two genuinely different actions from two different
locations/sessions at the same time.
**Source case:** Case_050 (EE-003)
**Check:** This indicates the underlying *credentials* are compromised, not merely a stolen
session/token — the legitimate owner and an attacker can both be actively using the account
simultaneously. Treat the account itself as untrustworthy mid-incident, even while it's being
used for legitimate remediation.
