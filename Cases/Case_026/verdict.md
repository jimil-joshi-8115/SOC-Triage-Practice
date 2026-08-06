# Verdict — Case 026

## F-001: 🟢 Verdict: FALSE POSITIVE
## F-002: 🔴 Verdict: TRUE POSITIVE
## F-003: 🟡 Verdict: AMBIGUOUS

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Valid Accounts: Cloud Accounts | T1078.004 | Account takeover via password reset from unfamiliar location (F-002) |
| Modify Authentication Process: Multi-Factor Authentication | T1556.006 | New MFA method added without removing original, establishing persistent access (F-002) |
| — | — | F-003 not mapped — insufficient evidence to confirm technique use |

---

## Justification

### F-001 — FP
Singapore sign-in explicitly matches an approved, dated travel calendar entry (APAC Partner
Summit), and the following day's login is consistent with the user still being on that
confirmed trip. Direct, positive mitigating evidence present in the event itself — not an
absence of red flags, but a confirmed explanation.

### F-002 — TP
Password reset from a never-before-seen location, immediately followed by registration of a
*second* MFA method rather than replacement of the original. This specific pattern — adding
rather than replacing — is what makes this decisive: it's an attacker establishing independent,
persistent access that survives the legitimate user noticing and resetting their password
again. No mitigating context of any kind is present for this account.

### F-003 — Ambiguous
MFA was satisfied normally (not bypassed), and the account has an established, confirmed
pattern of legitimate frequent international travel to multiple countries. The only deviation
from that pattern is a missing calendar entry for this specific trip — an absence of confirming
evidence, not a positive indicator of compromise. None of the concrete tradecraft markers
present in F-002 (password reset, new MFA method, method not removed) are present here. Forcing
a TP or FP call on this evidence would be guessing rather than concluding.

**Correction logged:** initial verdict was TP, based on surface pattern-matching ("unfamiliar
location + security tool flag") without weighing evidence strength against the account's
established legitimate baseline. Corrected to Ambiguous after direct comparison against F-001
(positive confirming evidence) and F-002 (concrete attacker tradecraft, no mitigating context)
as reference points. This is the same "suspicious structure ≠ automatic TP" pattern already
documented in Case_003 and Case_014 — logged transparently per this repo's methodology of
recording corrections honestly rather than hiding them.

---

## What Would Change These Verdicts

- **F-001 → TP:** if the calendar entry were found to be fraudulent, or if MFA had not been
  satisfied on either Singapore login.
- **F-002 → FP:** essentially not plausible given the concrete, unmitigated tradecraft present;
  would require a documented, approved emergency access exception for this account and IP.
- **F-003 → TP:** if out-of-band verification (see response actions) confirms r.iyer did not
  actually travel to Lagos, or if any further anomalous activity is found on this account.
- **F-003 → FP:** if out-of-band verification confirms this was a legitimate, simply
  uncalendared business trip.

---

## Recommended Response Actions

**F-001:** No action needed beyond standard closure — confirmed legitimate.

**F-002:**
1. Disable `p.shah@corptenant.com` immediately; force a full credential reset through a
   verified, out-of-band channel.
2. Remove the attacker-registered MFA phone method.
3. Revoke all active sessions/refresh tokens.
4. Review the account's activity since the takeover for further compromise indicators (mail
   rules, sent items, file access).
5. Escalate to L2/IR.

**F-003:**
1. Contact r.iyer directly via phone/text (not email) to confirm the Lagos trip.
2. Alternatively or additionally, check with their manager/HR for any travel authorization not
   reflected in the calendar system.
3. Do not take remediation action (disable account, force reset) until verification is
   complete, given MFA was satisfied normally and no other compromise indicators are present.
4. If verification cannot confirm the trip within a reasonable window, escalate to TP and
   proceed with the F-002-style remediation steps as a precaution.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | F-001: FP · F-002: TP · F-003: Ambiguous |
| Confidence | High (F-001, F-002); Low/Inconclusive by design (F-003) |
| Verification method | Splunk — sample Azure AD data (CSV: `azuread_case026.csv`, host `JIMIL-JOSHI`) |
| Triage Time | 7:41 – 7:46 (real, tracked) |
| Escalated | F-002: Yes (would be, in real SOC) · F-003: Pending out-of-band verification |
| Corrections during investigation | 1 (F-003: initial TP call corrected to Ambiguous after evidence-strength comparison against F-001/F-002) |
