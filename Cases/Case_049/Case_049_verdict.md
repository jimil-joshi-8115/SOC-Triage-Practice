# Verdict — Case 049 (Bonus Final Exam, Stage 2)

## DD-001: 🔴 TP · DD-002: 🔴 TP · DD-003: 🟢 FP · DD-004: 🔴 TP (Critical — Escalation) · DD-005: 🔴 TP

**DD-001 and DD-004 continue the t.oconnor incident, now escalated to domain-controller reach.
DD-002 and DD-005 continue the s.mehta/backup-svc-2 incident. DD-003 is unrelated.**

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| OS Credential Dumping: LSASS Memory | T1003.001 | Credential-dumping tool disguised as a system process (DD-001) |
| Resource Hijacking | T1496 | Confirmed cryptomining traffic from the GPU instances (DD-002) |
| Use Alternate Authentication Material / Lateral Movement | T1550 / TA0008 | High-privilege credentials harvested and used to authenticate to the DC from a low-privilege compromised host (DD-004) |
| Impair Defenses: Cloud Firewall / Data Destruction (adjacent) | T1562.007 (adjacent) | Backup archive locked to deny all but the compromised identity (DD-005) |

---

## Justification

### DD-001 — TP
The loader script from Case_048's CC-003 executed a credential-dumping tool disguised as a
system process, accessing LSASS memory from a user Temp directory. Confirms progression from
initial download to active credential theft on t.oconnor's host.

### DD-002 — TP
Confirmed outbound traffic to a known mining pool on the standard Stratum port resolves the
purpose of the GPU instances launched in Case_048's CC-006 as unauthorized cryptocurrency
mining.

### DD-003 — FP
Fully documented, automated, narrowly-scoped, time-limited HR onboarding action. No connection
to either active incident.

### DD-004 — TP, Critical (Escalation)
It-infra-lead's high-privilege credentials authenticated to the domain controller from
t.oconnor's already-compromised workstation, 12 minutes after that host's credential-dumping
tool executed. Credential-dumping tools extract credentials for any account that has
authenticated on the target machine, not only the primary user — this indicates the attacker
harvested a cached administrator credential from the compromised host and used it to pivot
directly to the domain controller. This converts a single-workstation compromise into a
domain-controller-level threat, a categorically more severe outcome than the initial incident
alone suggested, and the clearest illustration in this exam of why lateral-movement alerts must
be assessed for downstream reach rather than the originating host's apparent value.

### DD-005 — TP
The already-compromised backup-svc-2 identity modified the critical backup archive's bucket
policy to exclude all legitimate administrators — a defense-evasion/recovery-sabotage action
ensuring the organization cannot restore from its own backups without first identifying and
reverting this change.

---

## Correlation Summary

Two incidents continue from Case_048: the s.mehta/backup-svc-2 chain (now confirmed as
cryptomining plus backup sabotage) and the t.oconnor chain (now escalated via credential
dumping to domain-controller-level access using a different, high-privilege account). DD-003
remains confirmed unrelated to both.

---

## What Would Change These Verdicts

- **DD-001/DD-004 → FP:** essentially not plausible given the confirmed malicious process
  behavior and the complete absence of any documented reason for it-infra-lead to authenticate
  from t.oconnor's workstation.
- **DD-002 → FP:** not plausible given confirmed mining-pool traffic on the standard port.
- **DD-005 → FP:** a documented, approved reason for restricting backup access to the
  backup-svc-2 role alone (not plausible given that identity's already-confirmed compromise).

---

## Recommended Response Actions

1. **Treat AURORA-DC01 as potentially compromised** — force a full credential reset for
   it-infra-lead and any other privileged accounts that may have cached credentials on
   MFL-WKS0287; assume broader domain compromise until ruled out.
2. Isolate MFL-WKS0287 immediately and forensically image it before further remediation.
3. **Revert the S3 bucket policy on aurora-backups-critical** to restore legitimate
   administrator access before relying on backups for recovery.
4. Terminate the GPU instances and revoke backup-svc-2's credentials (continuing from Case_048's
   response actions).
5. Conduct a domain-wide credential reset if any evidence emerges that it-infra-lead's
   compromised credentials were used beyond the single DC authentication observed.
6. Escalate both incidents to L2/IR with updated severity — the t.oconnor incident now requires
   full domain-compromise-assumption handling, not single-workstation remediation.
7. No action needed on DD-003 beyond standard closure.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | DD-001: TP · DD-002: TP · DD-003: FP · DD-004: TP (Critical) · DD-005: TP |
| Confidence | High (all five) |
| Verification method | Ticket-only — no Splunk query run (analyst decision) |
| Triage Time | 3 minutes (real, tracked) |
| Escalated | Yes — both incident threads, with DD-004 triggering domain-compromise-assumption handling |
| Corrections during investigation | 0 |
| Status | Bonus material — not counted toward the 150-alert target |
