# Investigation — Case 050 (Final Capstone, Stage 3)

**Verification method:** Ticket-only — no Splunk query run (analyst decision)

---

## Step 1: EE-001 — Distinguish Defender Action From Attacker Action

| Field | Value |
|---|---|
| Actor | it-infra-lead, via emergency break-glass access |
| Verification | MFA + physical security key, per EMERG-SOP-02 |
| Action | Terminates the confirmed-malicious backup-svc-2 instances and keys |
| Alignment | Matches the exact remediation steps recommended at the end of Case_049 |

**Finding:** 🟢 This is not a new attack — it is the defenders' own remediation action,
strongly verified (MFA plus physical key, the highest verification tier used anywhere in this
repo) and directly matching the recommended response from the prior stage. FP as a threat;
confirmed legitimate incident response.

---

## Step 2: EE-002 — Confirm Automated Defensive Action

| Field | Value |
|---|---|
| Actor | EDR-Automated-Containment |
| Trigger | Case_049's DD-001 credential-dumping detection |
| Action | Network isolation of the compromised host |

**Finding:** 🟢 A standard, automated containment response to an already-confirmed detection.
This is the security tooling working as intended, not a new incident.

---

## Step 3: EE-003 — Live Interrupt: Assess the Concurrent-Session Anomaly

| Field | it-infra-lead Session A (EE-001) | it-infra-lead Session B (EE-003) |
|---|---|---|
| Location | IT team's known location | Lagos, Nigeria — zero history |
| Verification | MFA + physical security key | Not equivalently verified |
| Action | Terminating malicious infrastructure | Creating a new OAuth app with Directory.ReadWrite.All |
| Session token | Distinct | Distinct, concurrent with Session A |

**Finding:** 🔴 Critical. Two different, concurrent sessions for the same account, from two
different locations, performing two entirely different classes of action, is only possible if
the account's credentials themselves are compromised — not merely a single session or device.
This directly connects to Case_049's DD-004, where it-infra-lead's credentials were already
confirmed harvested via the credential-dumping tool on t.oconnor's workstation. EE-003 is the
attacker actively using those harvested credentials for a second objective (a persistent,
directory-wide OAuth backdoor) at the exact same time the legitimate account owner is using the
same credentials for genuine remediation.

**Priority re-evaluation triggered by EE-003:** the account performing incident response
(it-infra-lead) cannot itself be trusted as an uncompromised identity mid-remediation. This
requires an immediate, parallel action: force a credential reset on it-infra-lead through an
out-of-band channel *without* interrupting the legitimate remediation already in progress if
possible, and independently verify that EE-001's actions were genuinely performed by the
authorized administrator and not the attacker impersonating them via the same compromised
credential set.

---

## Step 4: Synthesize the Full 3-Stage Incident

**Finding:** Two originally-separate incidents from Case_048 (s.mehta/backup-svc-2 cryptomining,
and t.oconnor's phishing-based compromise) escalated across Case_049 and converged by Case_050:
t.oconnor's compromise led to harvesting it-infra-lead's credentials (Case_049, DD-004), which
the attacker is now actively exploiting in parallel with the organization's own remediation
efforts (Case_050, EE-003) to attempt establishing a new, independent, tenant-wide persistence
mechanism. The two incidents that began as unrelated (different accounts, different vectors —
cloud misconfiguration/self-escalation for s.mehta, phishing for t.oconnor) are now connected
through the shared compromise of a single high-privilege identity.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| EE-001 | Legitimate, strongly-verified remediation action | 🟢 None — FP (defender action) |
| EE-002 | Standard automated containment response | 🟢 None — FP (defender action) |
| EE-003 | Concurrent compromised-credential session, new persistence attempt | 🔴 Critical — active, ongoing compromise |
| Synthesis | Two originally-separate incidents now connected via one compromised identity | 🔴 Critical — full-scope reassessment needed |
