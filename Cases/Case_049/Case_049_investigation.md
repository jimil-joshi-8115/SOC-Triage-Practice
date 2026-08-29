# Investigation — Case 049 (Bonus Final Exam, Stage 2)

**Verification method:** Ticket-only — no Splunk query run (analyst decision)

---

## Step 1: Map Each Alert to Its Incident Thread

| Alert | Incident Thread |
|---|---|
| DD-001 | t.oconnor (continuation of Case_048's CC-003) |
| DD-002 | s.mehta/backup-svc-2 (continuation of Case_048's CC-006) |
| DD-003 | Unrelated — HR onboarding automation |
| DD-004 | t.oconnor incident, escalating to a new account (it-infra-lead) |
| DD-005 | s.mehta/backup-svc-2 (continuation) |

---

## Step 2: DD-001 — Confirm the Download Cradle's Payload

**Finding:** 🔴 The PowerShell download cradle from Case_048's CC-003 executed a
credential-dumping tool, disguised as a system process (`svchost_update.exe`) but running from
a user Temp directory and accessing LSASS memory — the standard technique for extracting
cached credentials from a Windows host. This confirms t.oconnor's compromise progressed from
initial access to active credential theft.

---

## Step 3: DD-002 — Confirm the GPU Instances' Purpose

**Finding:** 🔴 Outbound connections from all 12 instances to a known mining-pool domain on the
standard Stratum port confirms the instances launched in Case_048's CC-006 were provisioned
specifically for unauthorized cryptocurrency mining — resolving the "likely purpose" question
raised in that case.

---

## Step 4: DD-003 — Check Against Documented HR Process

**Finding:** 🟢 Automated, documented onboarding action, narrowly scoped (single SharePoint
folder), time-limited (14-day auto-expiry), performed by a recognized automation account. No
connection to either active incident.

---

## Step 5: DD-004 — Assess the Significance of Cross-Account Credential Movement

| Field | Value |
|---|---|
| Credentials used | it-infra-lead — a different, high-privilege account |
| Origin host | MFL-WKS0287 — t.oconnor's already-compromised workstation |
| Justification | None — it-infra-lead has no documented reason to authenticate from this host |
| Timing | 12 minutes after DD-001's credential-dumping tool execution |

**Finding:** 🔴 Credential-dumping tools extract credentials for any account that has
authenticated on the target machine, not just the host's primary user. The presence of
it-infra-lead's credentials authenticating to the domain controller from t.oconnor's
compromised workstation, 12 minutes after DD-001, indicates the attacker harvested a
high-privilege administrator's cached credentials from that machine and used them to pivot
directly to the domain controller. This converts what began as a low-value single-workstation
compromise into a domain-controller-level threat — a categorically more severe outcome than the
initial phishing/download-cradle incident alone suggested, and the clearest example in this
exam of why lateral movement/credential-theft alerts must be evaluated for their downstream
reach, not just their originating host's perceived value.

---

## Step 6: DD-005 — Confirm Continuation of the s.mehta/backup-svc-2 Chain

**Finding:** 🔴 The backup-svc-2 identity — already confirmed compromised and actively mining
cryptocurrency (DD-002) — modified the backup archive's bucket policy to lock out all
legitimate administrators except itself. This is a defense-evasion/business-continuity-sabotage
action: even after the mining operation and rogue account are discovered, recovery via the
organization's own backups would be blocked unless this policy change is identified and
reverted.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| DD-001 | Confirmed credential-dumping tool execution on t.oconnor's host | 🔴 Critical |
| DD-002 | Confirmed cryptomining purpose for the GPU instances | 🔴 Critical |
| DD-003 | Documented, scoped, time-limited HR process | 🟢 None |
| DD-004 | High-privilege credentials harvested and used to pivot to the DC | 🔴 Critical — escalation |
| DD-005 | Backup archive locked out by the compromised cloud identity | 🔴 High |
