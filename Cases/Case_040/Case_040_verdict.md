# Verdict — Case 040 (Mid-Phase-5 Checkpoint)

## T-001: 🟢 FP · T-002: 🔴 TP · T-003: 🟢 FP (corrected from initial Ambiguous) · T-004: 🟢 FP · T-005: 🔴 TP (Critical, Live Interrupt)

**T-002 and T-005 are TP as a single correlated incident. T-001, T-003, and T-004 are
independent and confirmed benign.**

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Valid Accounts: Cloud Accounts | T1078.004 | Self-attached over-permissive IAM policy, no documented justification (T-002) |
| Data from Cloud Storage | T1530 | Mass GetObject calls across sensitive buckets (T-005) |
| Exfiltration Over Web Service | T1567 | 15.6GB transferred to an external IP (T-005) |

---

## Justification

### T-001 — FP
Sign-in from a first-seen location, but with a specific, dated calendar entry ("Client Site
Visit - Toronto") entered 9 days in advance, matching the exact date range. Direct confirming
evidence, not merely an absence of red flags.

### T-002 — TP
n.bhatt, a Junior DevOps Engineer whose documented role is scoped to a single application's
CI/CD pipeline, self-attached AmazonS3FullAccess — account-wide S3 access with no supporting
change ticket. This is unauthorized self-service privilege escalation, the same pattern
established in Case_032.

### T-003 — FP (corrected during investigation)
40 queries against a 15-minute window is a real deviation from the 8-12/day baseline, but a
documented, dated calendar entry ("Q3 Board Report - Data Pull") directly confirms the exact
activity as tied to a known quarterly reporting deadline. **Correction note:** this alert was
initially assessed as Ambiguous based on the volume deviation in isolation. On reconsideration,
it shares the same evidentiary structure as T-001 — a deviation with direct, positive confirming
evidence — rather than the structure of a genuinely ambiguous alert like Case_026's F-003,
where the only available evidence was an *absence* of confirmation. Corrected to FP.

### T-004 — FP
Fully automated action matching a documented onboarding workflow exactly, with a specific,
verifiable batch context (3 new hires). No deviation.

### T-005 — TP, Critical, Live Interrupt
2,100+ GetObject calls totaling 15.6GB across guest PII and financial report buckets, from the
permissions granted in T-002, to a never-before-seen external IP, roughly 2.3 hours after the
unauthorized policy attachment. This confirms T-002 was not a dormant misconfiguration but an
actively exploited access path. **This immediately re-prioritizes the response**: containment
of n.bhatt's account and the exfiltration in progress takes precedence over continuing to
review T-001/T-003/T-004 in order — the same live-interrupt discipline demonstrated in
Case_025 and Case_030.

---

## Correlation Summary

T-002 and T-005 are one incident — unauthorized privilege escalation followed by its active
exploitation for data exfiltration, same actor throughout. T-001, T-003, and T-004 are three
independent events, each confirmed benign by direct, specific evidence in their own right, with
no correlation to each other or to the T-002/T-005 incident.

---

## What Would Change These Verdicts

- **T-001/T-003 → TP:** if the referenced calendar entries were found to be fraudulent or
  post-dated after the fact (no indication of this in the ticket).
- **T-002/T-005 → FP:** a documented, approved change ticket explaining n.bhatt's need for
  account-wide S3 access and the subsequent large-scale download (unlikely given the explicit
  role-scope documentation stating otherwise, and the external, first-seen destination IP).
- **T-004 → TP:** if the assignment fell outside the documented onboarding batch or targeted an
  unexpected user.

---

## Recommended Response Actions (Priority Order Following T-005)

1. **Immediately revoke n.bhatt's AmazonS3FullAccess policy and terminate active sessions.**
2. **Block source IP 203.0.113.44** at the account/network level.
3. Preserve CloudTrail logs and begin a full audit of all actions taken by n.bhatt since the
   T-002 policy attachment.
4. Treat this as a confirmed data breach involving guest PII and financial reports — begin
   data-loss assessment and legal/compliance notification processes.
5. Review with n.bhatt/management whether this reflects a compromised account or intentional
   insider action.
6. Audit IAM policies broadly for other instances of self-attached over-permissive grants.
7. Escalate to L2/IR immediately given confirmed active exfiltration of sensitive data.
8. No action needed on T-001, T-003, or T-004 beyond standard closure.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | T-001: FP · T-002: TP · T-003: FP · T-004: FP · T-005: TP (Critical) |
| Confidence | High (all five, after full review) |
| Verification method | Ticket-only — no Splunk query run (analyst decision) |
| Triage Time | 6 minutes (real, tracked) |
| Escalated | Yes — T-002/T-005 (would be, in real SOC) |
| Corrections during investigation | 1 (T-003: initial Ambiguous corrected to FP after comparing evidentiary structure against T-001's confirmed-legitimate pattern) |
