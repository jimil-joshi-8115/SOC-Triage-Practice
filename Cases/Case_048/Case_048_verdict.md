# Verdict — Case 048 (Bonus Final Exam, Stage 1)

## CC-001: 🔴 TP · CC-002: 🔴 TP · CC-003: 🔴 TP (separate incident) · CC-004: 🟢 FP (corrected) · CC-005: 🔴 TP · CC-006: 🔴 TP (Critical, Live Interrupt)

**CC-001, CC-002, CC-005, and CC-006 are TP as one incident (s.mehta / backup-svc-2). CC-003 is
TP as a separate, unrelated incident (t.oconnor). CC-004 is FP.**

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Valid Accounts | T1078 | Impossible-travel sign-in on s.mehta's account (CC-001) |
| Account Manipulation: Additional Cloud Credentials | T1136.003 | Rogue AdministratorAccess IAM user created (CC-002) |
| Ingress Tool Transfer | T1105 | Encoded PowerShell download cradle (CC-003) |
| Additional Cloud Credentials | T1136.003 | Access key generated for the rogue IAM user (CC-005) |
| Resource Hijacking | T1496 | GPU-optimized EC2 instances launched in an unused region (CC-006) |

---

## Justification

### CC-001, CC-002, CC-005, CC-006 — TP (single incident)
Impossible travel (CC-001) on s.mehta's account is followed 7 minutes later by an unauthorized
AdministratorAccess IAM user creation with no role justification or change ticket (CC-002). An
access key is generated for that rogue identity (CC-005), which is then used to launch 12
GPU-optimized instances in a region the organization has never used, from an external IP
(CC-006). This is one continuous, escalating incident: account compromise → privilege
escalation → credential issuance → large-scale unauthorized compute provisioning, likely for
resource hijacking given the specific GPU-heavy instance selection.

### CC-003 — TP (separate incident)
An encoded PowerShell download cradle spawned from Outlook is TP on its own technical merits —
consistent with malicious email attachment execution. This involves a different account, host,
and department with no overlapping indicator with the s.mehta chain, and should be tracked as
its own incident.

### CC-004 — FP (corrected during investigation)
r.bhagat's password reset matches their own established baseline in every dimension: standard
verification, usual device, and historical ~90-day frequency. **Correction note:** this alert
was initially treated as a continuation of "the chain from 1 to 3" based on queue position
rather than verified actor overlap. On review, r.bhagat shares no account, host, or timing
connection with either the s.mehta chain or the t.oconnor incident. Corrected to FP after
explicitly checking actor identity — reinforces that queue order does not imply chain
continuation, the same principle behind the discrimination-test alerts in Cases 025, 027, 029,
039, and 040.

---

## Correlation Summary

Two separate confirmed incidents exist in this queue (s.mehta/backup-svc-2, and t.oconnor), plus
one unrelated, confirmed-benign alert (r.bhagat). Treating all four non-adjacent alerts as one
sequential chain would have been a significant correlation error — verifying actor identity
explicitly, rather than relying on the order alerts arrived in, was necessary to reach the
correct verdicts.

---

## What Would Change These Verdicts

- **CC-001/002/005/006 → FP:** confirmed legitimate remote work travel for s.mehta, combined
  with a documented, approved reason for the AWS admin actions (would require explicit
  verification given the severity and lack of any ticket).
- **CC-003 → FP:** confirmation the download was part of an approved software deployment
  (unlikely given the obfuscation and Outlook-spawned execution pattern).
- **CC-004 → TP:** if any link to s.mehta's or t.oconnor's activity were found (none present).

---

## Recommended Response Actions (Priority Order Following CC-006)

1. **Immediately terminate all 12 GPU instances in ap-southeast-3** and revoke the backup-svc-2
   access key.
2. Disable s.mehta's account and the backup-svc-2 IAM user; force credential reset for s.mehta
   through a verified out-of-band channel.
3. Isolate MFL-WKS0287 (t.oconnor's host) and investigate the PowerShell download's payload
   separately — treat as its own incident requiring its own containment.
4. Review AWS billing/cost anomalies for the exposure window to confirm no further unauthorized
   resources were provisioned.
5. Escalate both incidents to L2/IR — do not conflate them in a single incident report, since
   they involve different accounts, vectors, and root causes.
6. No action needed on CC-004 beyond standard closure.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | CC-001: TP · CC-002: TP · CC-003: TP (separate) · CC-004: FP · CC-005: TP · CC-006: TP (Critical) |
| Confidence | High (all six, after full review) |
| Verification method | Ticket-only — no Splunk query run (analyst decision) |
| Triage Time | 6 minutes (real, tracked) |
| Escalated | Yes — s.mehta chain and t.oconnor incident, separately |
| Corrections during investigation | 1 (CC-004: initially treated as chain continuation based on queue order, corrected to FP after verifying no actual actor overlap) |
| Status | Bonus material — not counted toward the 150-alert target |
