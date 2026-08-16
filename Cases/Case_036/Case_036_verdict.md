# Verdict — Case 036

## P-001: 🔴 Verdict: TRUE POSITIVE (re-escalated from tracked/non-urgent)
## P-002: 🔴 Verdict: TRUE POSITIVE (Critical)
## P-003: 🟢 Verdict: FALSE POSITIVE

**P-001 and P-002 are TP as a single correlated incident. P-003 is unrelated.**

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Exploit Public-Facing Application | T1190 | Unauthenticated Kubernetes Dashboard exploited (P-001/P-002) |
| Deploy Container | T1610 | Malicious pod deployed via the Dashboard UI (P-002) |
| Resource Hijacking | T1496 | Compute-intensive process with deliberately throttled CPU to evade detection (P-002) |

---

## Justification

### P-001 — TP (re-escalated)
This finding was known and ticketed for scheduled remediation 3 weeks prior, with no
exploitation evidence at that time — a legitimate non-urgent tracked issue on its own. However,
its status changes the moment it is confirmed being actively exploited (see P-002, 14 minutes
later). The remediation ticket describes the planned fix timeline; it does not reduce the
current risk once exploitation is underway. Re-classified as TP and urgent based on this
correlation.

### P-002 — TP, Critical
A pod was deployed directly through the Dashboard's web UI — bypassing the organization's
actual CI/CD deployment process entirely — using a container image from an unlisted public
registry, configured with a deliberately low CPU limit (0.3 vCPU) despite running a
compute-intensive process. This specific combination — unauthorized deployment path, unvetted
image source, and deliberate resource throttling — matches the documented evasion technique
from the real-world incident this scenario is grounded in, where attackers configured mining
software to keep usage low specifically to avoid detection.

### P-003 — FP
Standard, fully-documented service account activity tied to a specific, traceable deployment
record (a merged pull request). No deviation from expected process.

---

## Correlation Summary

P-001 and P-002 form one incident: the exact unauthenticated-dashboard vulnerability flagged in
P-001 was exploited 14 minutes later to deploy a resource-throttled pod via P-002. P-003 shares
no host, namespace, actor, or timing link with either and is confirmed unrelated.

---

## What Would Change These Verdicts

- **P-001/P-002 → FP:** a documented, approved internal security test or red-team exercise
  covering this exact dashboard and timeframe.
- **P-002 → Ambiguous (rather than TP):** if the deployed pod's actual running process were
  confirmed as legitimate (e.g., a genuinely low-resource internal tool a developer deployed
  manually via the Dashboard due to a CI/CD outage) — though the unlisted image source and
  bypass of the standard deployment path would still warrant scrutiny even then.
- **P-003 → TP:** if the ConfigMap access fell outside the documented deployment ID or occurred
  from an unexpected identity.

None of these apply in this ticket — verdicts stand as TP / TP / FP.

---

## Recommended Response Actions

1. **Immediately require authentication on the Kubernetes Dashboard** (or take it offline
   entirely if not actively needed) — do not wait for the scheduled sprint remediation given
   confirmed active exploitation.
2. **Terminate and remove the "sysbench-worker-7f9d" pod immediately.**
3. Audit the cluster for any additional unauthorized pods, images, or persistence mechanisms
   deployed via the same access — attackers who reach the Dashboard have full cluster-admin
   visibility, so assume broader compromise until ruled out.
4. Review network egress logs for the affected namespace/cluster for connections to
   cryptocurrency mining pools or unlisted endpoints.
5. Restrict the Dashboard's network exposure to internal-only access (VPN/bastion), and enforce
   RBAC-scoped service accounts rather than cluster-admin-level dashboard access going forward.
6. Escalate ticket #INFRA-2290 from "scheduled for next sprint" to immediate remediation given
   confirmed exploitation.
7. Escalate to L2/cloud security team.
8. No action needed on P-003 beyond standard closure.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | P-001: TP (re-escalated) · P-002: TP (Critical) · P-003: FP |
| Confidence | High (all three) |
| Verification method | Ticket-only — no Splunk query run (analyst decision) |
| Triage Time | 3 minutes (real, tracked) |
| Escalated | Yes — P-001/P-002 (would be, in real SOC) · P-003: No |
| Corrections during investigation | 0 |
| Scenario basis | Adapted from the February 2018 Tesla Kubernetes cryptojacking breach; IOCs and identities fully sanitized/fictional |
