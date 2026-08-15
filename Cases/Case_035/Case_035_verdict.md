# Verdict — Case 035

## O-001: 🔴 Verdict: TRUE POSITIVE
## O-002: 🟡 Verdict: AMBIGUOUS
## O-003: 🟢 Verdict: FALSE POSITIVE

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Exfiltration Over Physical Medium | T1052.001 | Mass file copy to USB storage, pre-resignation (O-001) |
| — | — | O-002 not mapped — verdict is Ambiguous, not confirmed malicious |
| — | — | O-003 not mapped — confirmed benign, documented routine access |

---

## Justification

### O-001 — TP
Every available factor aligns: 1,847 files copied in 22 minutes (high volume), content limited
to business-sensitive and competitive material (client contracts, pricing strategy, competitor
analysis — not personal files), occurring 2 hours after normal business hours, from an employee
who submitted their resignation 3 days prior with 11 days remaining. This is the standard
profile of pre-departure insider data theft — no single factor alone would be fully decisive,
but the combination leaves little alternative explanation.

### O-002 — Ambiguous
The content is the employee's own HR-issued performance review documents — not company IP,
client data, or competitive material — and the volume (3 files) is minor. These factors weigh
against a malicious-intent interpretation and clearly distinguish this from O-001's profile.
However, transmitting company-originated documents to a personal email address is typically a
data-handling policy violation on its own, independent of content sensitivity, and no
resignation or other HR context is available for r.fernandes to weigh either way. Forcing this
to a clean FP would ignore the policy dimension; forcing it to TP would overstate malicious
intent the evidence doesn't support. Ambiguous, with a recommendation to check r.fernandes's
employment status and address the policy violation regardless of that outcome, is the
evidence-appropriate call.

### O-003 — FP
Every element of this access — the share, the user's standing documented access tied to
backup/DR duties, and the timing matching a specific recurring scheduled calendar entry —
matches an established, legitimate administrative pattern exactly. No deviation present.

---

## Correlation Summary

No shared account, host, timing, or department across O-001, O-002, and O-003. Three
independent, unrelated employee actions sharing a queue — consistent with the discrimination-
testing pattern this repo has used since Case_025, extended here across three distinct verdict
categories in a single case.

---

## What Would Change These Verdicts

- **O-001 → FP/Ambiguous:** a documented, approved personal-device backup exception or a
  confirmed legitimate business reason for offline access to this exact data set before
  departure (would need explicit management/IT sign-off, not assumed).
- **O-002 → TP:** discovery that r.fernandes is also departing soon, or that the attachment
  actually contained additional non-personal company data beyond what was described.
- **O-002 → FP:** confirmation that personal-document forwarding of this kind is explicitly
  permitted under company policy (some organizations allow employees to retain copies of their
  own HR records).
- **O-003 → TP:** if the access fell outside the documented maintenance window or accessed data
  beyond the scope of the stated backup/DR purpose.

---

## Recommended Response Actions

**O-001:**
1. Immediately restrict t.krishnan's access to client, pricing, and competitive data pending
   investigation, without necessarily revealing the investigation (standard insider-threat
   handling).
2. Preserve the USB device and workstation for forensic review if possible.
3. Escalate to HR and Legal — this may involve contractual/NDA violations requiring formal
   action before the employee's last working day.
4. Review t.krishnan's access logs for the full notice period for any additional exfiltration
   activity.

**O-002:**
1. Verify r.fernandes's employment status (active, no pending resignation) before deciding next
   steps.
2. Address the personal-email policy violation through standard process regardless of intent
   (e.g., a documented reminder/warning per company data-handling policy).
3. No further escalation needed unless employment-status check or content review reveals
   additional concerns.

**O-003:** No action needed — confirmed legitimate, scheduled, documented access.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | O-001: TP · O-002: Ambiguous · O-003: FP |
| Confidence | High (O-001, O-003); Genuinely mixed evidence (O-002) |
| Verification method | Ticket-only — no Splunk query run (analyst decision) |
| Triage Time | 3 minutes (real, tracked) |
| Escalated | O-001: Yes (would be, in real SOC) · O-002: Pending employment-status verification · O-003: No |
| Corrections during investigation | 0 |
