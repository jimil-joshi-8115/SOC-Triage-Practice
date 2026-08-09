# Verdict — Case 029

## I-001: 🔴 Verdict: TRUE POSITIVE
## I-002: 🔴 Verdict: TRUE POSITIVE
## I-003: 🔴 Verdict: TRUE POSITIVE
## I-004: 🔴 Verdict: TRUE POSITIVE (Critical — Confirmed Data Exfiltration)
## I-005: 🟢 Verdict: FALSE POSITIVE

**I-001 through I-004 are TP as a single correlated incident.**

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Exploit Public-Facing Application | T1190 | SSRF exploitation of the WAF (I-001) |
| Unsecured Credentials: Cloud Instance Metadata API | T1552.005 | Credentials harvested from the instance metadata service (I-001/I-002) |
| Cloud Service Discovery | T1526 | GetCallerIdentity + ListBuckets reconnaissance (I-002) |
| Cloud Storage Object Discovery | T1619 | ListObjectsV2 across 14 buckets (I-003) |
| Exfiltration Over Web Service | T1567 | 3,800+ GetObject calls, 41GB downloaded (I-004) |

---

## Justification

### I-001 — TP
A WAF has no legitimate reason to query the instance metadata service — 47 requests to
`169.254.169.254` within 90 seconds is the signature of SSRF being used to harvest temporary
IAM credentials, mirroring the exact technique used in the real-world incident this scenario is
grounded in.

### I-002 — TP
The compromised role is used for an API category it has never called in 180 days
(`s3:ListBuckets`), from an external IP rather than its expected internal AWS network path.
`GetCallerIdentity` followed immediately by `ListBuckets` is the standard credential-
verification-then-reconnaissance sequence following credential theft.

### I-003 — TP
Same actor and IP as I-002, enumerating 14 buckets within 4 minutes, specifically including
buckets containing PII and payment records — targeted reconnaissance, not a random scan.

### I-004 — TP, Critical
3,800+ GetObject calls totaling 41GB from the two sensitive buckets identified in I-003, same
session throughout. This confirms actual data exfiltration occurred, not just unauthorized
access — the highest-severity finding in the chain.

### I-005 — FP
Different role entirely (`aurora-billing-readonly-role`, unrelated to the compromised
`aurora-waf-ec2-role`), no shared IP or access event, triggered by a routine scheduled
compliance scan rather than any live activity, and already tracked under an open remediation
ticket (#SEC-4471). No connection to the I-001–I-004 incident.

---

## Correlation Summary

I-001 through I-004 form one continuous incident driven by a single root cause: SSRF
exploitation of the WAF (I-001) leaked temporary credentials for an overprivileged IAM role,
which were then used for reconnaissance (I-002/I-003) and large-scale exfiltration (I-004) — the
same causal chain as the real 2019 Capital One breach. I-005 is unrelated, pre-existing,
already-tracked noise.

---

## What Would Change These Verdicts

- **I-001 → FP:** a documented, approved security assessment/pentest targeting this exact WAF
  and endpoint.
- **I-002/I-003/I-004 → FP:** essentially not plausible given the total absence of prior S3
  activity for this role and the direct causal link to the confirmed I-001 exploitation.
- **I-005 → TP:** if the flagged role were found to share any credential, IP, or access pattern
  with the confirmed-compromised `aurora-waf-ec2-role` (none found in this ticket).

---

## Recommended Response Actions

1. **Immediate — revoke all active temporary credentials for `aurora-waf-ec2-role`** and rotate
   the role entirely.
2. Patch or take the vulnerable WAF component offline pending an SSRF fix; enforce IMDSv2
   (session-token-based metadata service) on all EC2 instances to prevent this credential-theft
   vector entirely — the single most effective mitigation for this exact attack pattern.
3. Apply least-privilege review to `aurora-waf-ec2-role` — it should never have had S3
   permissions given its documented CloudWatch-only purpose.
4. Treat this as a confirmed data breach: begin data-loss assessment on the 41GB downloaded from
   `aurora-guest-pii-archive` and `aurora-payment-records-2024`, and initiate legal/compliance
   breach-notification processes in parallel with technical response.
5. Block source IP 104.28.19.201 at the account/network level.
6. Enable/verify GuardDuty and CloudTrail coverage across all buckets and roles to catch this
   pattern faster in the future.
7. Escalate to IR immediately — active, confirmed large-scale data exfiltration.
8. No action needed on I-005 beyond its existing tracked remediation timeline (#SEC-4471).

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | I-001: TP · I-002: TP · I-003: TP · I-004: TP (Critical) · I-005: FP |
| Confidence | High (all five) |
| Verification method | Ticket-only — rapid-response, no verification step (analyst decision) |
| Triage Time | 4 minutes (real, tracked) |
| Escalated | Yes — I-001 through I-004 (would be, in real SOC, as confirmed data breach) |
| Corrections during investigation | 0 |
| Scenario basis | Adapted from the publicly documented July 2019 Capital One data breach (SSRF → EC2 metadata credential theft → mass S3 exfiltration); IOCs and identities fully sanitized/fictional |
