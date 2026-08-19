# Verdict — Case 039

## S-001: 🔴 Verdict: TRUE POSITIVE
## S-002: 🔴 Verdict: TRUE POSITIVE (Critical)
## S-003: 🟢 Verdict: FALSE POSITIVE

**S-001 and S-002 are TP as a single correlated incident. S-003 is unrelated.**

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Exploit Public-Facing Application | T1190 | Exploitation of an unpatched Node.js vulnerability on a public-facing instance (S-001) |
| Unsecured Credentials: Cloud Instance Metadata API | T1552.005 | DNS rebinding attempt to reach the instance metadata service (S-001) |
| Resource Hijacking | T1496 | Confirmed cryptocurrency mining activity on the compromised instance (S-002) |

---

## Justification

### S-001 — TP
A public-facing instance with a documented, pre-existing unpatched vulnerability (VULN-2291)
exhibited a DNS rebinding pattern consistent with an attempt to reach the instance metadata
service — a known technique for stealing IAM credentials tied to the instance. The existing
vulnerability context makes this a credible attack path rather than a benign anomaly.

### S-002 — TP, Critical
The same instance, 7 minutes later, queried a domain associated with a known cryptocurrency
mining pool and established an outbound connection on port 3333 — the standard Stratum mining
protocol port. This is the confirmed, executed outcome of the S-001 compromise attempt:
resource hijacking for cryptomining, matching the exact real-world pattern this scenario is
grounded in.

**Correlation:** S-001 and S-002 form one incident on the same instance, in immediate
succession — a credential/access compromise attempt followed by its confirmed exploitation.

### S-003 — FP
Multiple inbound SSH connection attempts from a known, attributed internet-scanning service,
explicitly characterized in the alert as routine mass scanning rather than targeted activity,
with every single attempt rejected by a correctly-configured security group that does not
permit inbound SSH from any external range. No successful access occurred, the source is
identified as non-malicious background scanning, and no aggravating factor is present anywhere
in the alert — consistent with the established repo principle (Case_016) that routine events
with zero aggravating factors should be FP.

**Investigation note:** the initial read of S-003 moved through TP and Ambiguous before settling
on FP across three passes in this session. This reflected a fast, incomplete first read under
time pressure rather than a flawed analytical approach — the deciding details (rejected
connections, attributed scanning source, security-group confirmation) were present in the
ticket from the start. Logged transparently per this repo's standing methodology.

---

## What Would Change These Verdicts

- **S-001/S-002 → FP:** a documented, approved internal security assessment targeting this
  exact instance and vulnerability (would need explicit verification given the severity).
- **S-003 → TP:** if any connection attempt had succeeded, or if the source IP were later found
  to be spoofing/piggybacking on the scanning service's range for targeted reconnaissance.

None of these apply in this ticket — verdicts stand as TP / TP / FP.

---

## Recommended Response Actions

1. **Isolate instance i-0a3f8e21b9c4d5678 from the network immediately** to stop the active
   cryptomining connection.
2. Rotate the IAM instance role's credentials associated with this instance — assume they were
   accessed via the metadata rebinding attempt.
3. Patch the outdated Node.js version per the existing VULN-2291 finding — this should be
   escalated from a routine vulnerability-management item to urgent given confirmed
   exploitation.
4. Review CloudTrail for any actions taken using the instance's IAM credentials since the S-001
   timestamp.
5. Block the mining-pool domain and port 3333 outbound at the security group/network level
   organization-wide.
6. Terminate and rebuild the instance from a clean image rather than attempting in-place
   remediation, given confirmed compromise.
7. No action needed on S-003 beyond standard closure — confirmed benign, blocked scanning
   activity.
8. Escalate S-001/S-002 to L2/IR immediately.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | S-001: TP · S-002: TP (Critical) · S-003: FP |
| Confidence | High (all three, after full review) |
| Verification method | Ticket-only — no Splunk query run (analyst decision) |
| Triage Time | 5 minutes (real, tracked) |
| Escalated | Yes — S-001/S-002 (would be, in real SOC) · S-003: No |
| Corrections during investigation | 1 (S-003: fast initial read under time pressure moved through TP → Ambiguous before settling on FP; identified as an incomplete first read, not a reasoning error — deciding details were present in the ticket from the start) |
| Scenario basis | Grounded in widely-documented real-world EC2 cryptojacking campaigns (e.g., TeamTNT-style operations); IOCs and identities fully sanitized/fictional |
