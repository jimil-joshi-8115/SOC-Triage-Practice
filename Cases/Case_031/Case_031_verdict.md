# Verdict — Case 031

## K-001: 🔴 Verdict: TRUE POSITIVE
## K-002: 🔴 Verdict: TRUE POSITIVE (Critical)

**Both alerts are TP as a single correlated incident.**

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Valid Accounts: Cloud Accounts | T1078.004 | Legitimate credentials used to exploit a role-chaining misconfiguration (K-001) |
| Cloud Infrastructure Discovery / Account Manipulation | T1580 / T1098 (adjacent) | Escalation via transitive AssumeRole trust (K-001) |
| Impair Defenses: Disable or Modify Cloud Firewall | T1562.007 | Security group ingress rule opened to 0.0.0.0/0 (K-002) |

---

## Justification

### K-001 — TP
j.mehra's own user policy does not directly authorize assuming `aurora-prod-admin`, but the
intermediate role `aurora-readonly-analyst` — which j.mehra is legitimately authorized to
assume — has a misconfigured trust policy allowing it to further assume the admin role. This is
the defining risk of role chaining: the escalation path is invisible to a review of the
originating identity's direct permissions alone, and only becomes visible by tracing the
complete assume-role chain. The 40-second gap between the two assumptions is consistent with a
deliberate, sequential escalation rather than an accidental double-click.

### K-002 — TP, Critical
Using the illegitimately-escalated session, a security group rule was added opening RDP
(port 3389) to the entire internet (0.0.0.0/0) on the security group protecting production
database instances, 76 seconds after the escalation completed. There is no legitimate
operational scenario justifying this exposure on a database-tier security group. Whether this
reflects a junior engineer's serious error while operating with access they should never have
had, or deliberate malicious action, the resulting risk to production data is identical and
critical.

**Correlation:** K-002 is a direct, causal continuation of K-001 — the exact same escalated
session, used within just over a minute, to create a critical exposure. This is one incident.

---

## What Would Change These Verdicts

- **K-001 → FP:** a documented, approved change ticket showing j.mehra was intentionally granted
  temporary elevated access for a specific approved task via this exact escalation path
  (unlikely — legitimate elevated access should go through a direct, audited grant, not an
  undocumented chaining vulnerability).
- **K-002 → FP:** a documented, approved network change request explaining the RDP rule as
  intentional and time-boxed (e.g., approved emergency remote troubleshooting) — even then, the
  0.0.0.0/0 scope on a production database security group would still warrant review.

---

## Recommended Response Actions

1. **Immediately revert the security group rule** — remove the 0.0.0.0/0:3389 ingress from
   `aurora-prod-db-sg`.
2. **Fix the root-cause misconfiguration**: remove `aurora-readonly-analyst`'s trust
   relationship allowing it to assume `aurora-prod-admin`, or restrict it via conditions
   (e.g., MFA-required, source-IP-restricted) if any chaining is genuinely needed.
3. Suspend j.mehra's active sessions and review with the employee/manager whether this was
   intentional testing, accidental misconfiguration exploitation, or malicious action.
4. Audit all IAM roles in the account for similar transitive AssumeRole trust
   misconfigurations — this is rarely an isolated single-role issue.
5. Review CloudTrail for any other actions taken during the `aurora-prod-admin` session beyond
   the security group change.
6. Confirm no external access actually occurred via the exposed RDP port before it was
   remediated (check VPC Flow Logs for the exposure window).
7. Escalate to L2/cloud security team given the production database exposure.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | K-001: TP · K-002: TP (Critical) |
| Confidence | High (both) |
| Verification method | Ticket-only — no Splunk query run (analyst decision) |
| Triage Time | 2 minutes (real, tracked) |
| Escalated | Yes — both (would be, in real SOC) |
| Corrections during investigation | 0 |
| Scenario basis | Grounded in the documented "AssumeRole chaining" AWS privilege-escalation technique (cloud security research pattern, not a single named breach); IOCs and identities fully sanitized/fictional |
