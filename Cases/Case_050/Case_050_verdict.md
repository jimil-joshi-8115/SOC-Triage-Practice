# Verdict — Case 050 (🏁 FINAL CAPSTONE, Stage 3)

## EE-001: 🟢 FP (confirmed legitimate defender action)
## EE-002: 🟢 FP (confirmed legitimate defender action)
## EE-003: 🔴 TP (Critical — Live Interrupt, Active Ongoing Compromise)

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Valid Accounts | T1078 | Compromised credentials used concurrently with the legitimate account owner (EE-003) |
| Account Manipulation: Additional Cloud Roles | T1098.003 (adjacent) | Attempted OAuth app registration with Directory.ReadWrite.All (EE-003) |

---

## Justification

### EE-001 — FP
Strongly-verified (MFA plus physical security key, the highest verification standard in this
repo) emergency remediation action, directly matching the response steps recommended at the
close of Case_049. Confirmed legitimate defender activity, not a new threat.

### EE-002 — FP
Standard automated EDR containment triggered by an already-confirmed detection from the prior
stage. Security tooling functioning as designed.

### EE-003 — TP, Critical, Live Interrupt
A second, concurrent session for it-infra-lead's account — different IP, different session
token, zero-history location (Lagos, Nigeria) — attempted to register a new OAuth application
with Directory.ReadWrite.All at the exact same time the legitimate account owner was performing
EE-001's remediation from a known, verified location. Two genuinely different sessions
performing two entirely different classes of action, simultaneously, on the same account, is
only possible if the account's underlying credentials are compromised — not a single device or
session. This directly connects to Case_049's DD-004, where these exact credentials were
confirmed harvested via a credential-dumping tool. EE-003 shows the attacker actively exploiting
those harvested credentials for a second objective (a persistent, tenant-wide backdoor) in
parallel with the organization's own incident response.

**This finding requires an immediate parallel response**: the account currently being used for
remediation cannot be trusted as uncompromised. Response must include an out-of-band credential
reset and independent verification that EE-001's actions were genuinely performed by the
authorized administrator.

---

## What Would Change These Verdicts

- **EE-001/EE-002 → TP:** if either action were found to lack proper authorization or
  verification (not the case here — both are strongly evidenced as legitimate).
- **EE-003 → FP:** essentially not plausible given the concurrent-session structure and
  zero-history location; would require an implausible explanation for two simultaneous,
  independently-authenticated sessions on one account from different continents.

---

## Recommended Response Actions

1. **Force an immediate, out-of-band credential reset for it-infra-lead** — do not wait for
   EE-001's remediation session to complete, but coordinate so the reset doesn't disrupt
   legitimate ongoing containment work.
2. **Block the attempted OAuth app registration** and audit for any other OAuth apps registered
   using these credentials in the recent window.
3. Independently verify, through a separate channel (e.g., direct contact with the IT team
   performing EE-001), that all actions attributed to it-infra-lead's account during this
   incident were genuinely performed by authorized personnel.
4. Revoke all active sessions for it-infra-lead's account, including the legitimate remediation
   session if necessary, and re-authenticate through a verified, secure process before resuming
   response work.
5. Escalate to executive/board-level incident communication given the domain-controller and
   directory-wide scope now confirmed across this 3-stage incident.
6. Treat this as a full domain and tenant compromise requiring comprehensive forensic review,
   not a contained single-host or single-account incident.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | EE-001: FP · EE-002: FP · EE-003: TP (Critical) |
| Confidence | High (all three) |
| Verification method | Ticket-only — no Splunk query run (analyst decision) |
| Triage Time | 2 minutes (real, tracked) |
| Escalated | Yes — EE-003 (would be, in real SOC, as active, ongoing, executive-level incident) |
| Corrections during investigation | 0 |
| Status | Final bonus case — not counted toward the 150-alert target |

---

---

# 🔄 Final Shift-Handoff Summary — Full 3-Stage Bonus Exam (Cases 048–050)

## Incident Overview

What began as two apparently unrelated incidents converged into a single, high-severity,
multi-domain compromise touching cloud infrastructure, identity, and on-premises Active
Directory.

## Timeline

**Incident A — s.mehta / backup-svc-2 (Cloud identity → resource hijacking):**
1. 08:00–08:45 — Impossible travel on s.mehta's Okta account (Ahmedabad → Warsaw)
2. 08:52 — Rogue AWS IAM user "backup-svc-2" created with AdministratorAccess, no ticket
3. 09:20 — Access key generated for backup-svc-2
4. 09:24 — 12 GPU-optimized EC2 instances launched in an unused region
5. 09:40 — Confirmed cryptocurrency mining traffic from all 12 instances
6. 09:50 — Critical backup archive locked to exclude all legitimate administrators
7. 10:05 — **Remediated**: instances terminated, keys revoked via verified emergency access

**Incident B — t.oconnor (Phishing → credential theft → domain-controller pivot):**
1. 09:10 — Encoded PowerShell download cradle spawned from Outlook
2. 09:35 — Credential-dumping tool executed on the host
3. 09:47 — Harvested credentials for it-infra-lead (a different, high-privilege account) used
   to authenticate to the domain controller from the compromised workstation
4. 10:06 — **Partially contained**: workstation isolated by automated EDR

**Convergence Point:**
5. 10:07 — **Active, ongoing**: it-infra-lead's compromised credentials (harvested in Incident
   B) used in a session concurrent with the organization's own legitimate remediation, to
   attempt registering a new, persistent, tenant-wide OAuth backdoor

**Unrelated, correctly-dismissed alerts throughout:** r.bhagat's routine password reset (Case
048, CC-004 — initially misread as chain continuation, corrected), and an HR onboarding guest
invite (Case 049, DD-003).

## Current Status at Handoff

- Incident A: Cryptomining infrastructure terminated; backup archive lockout requires policy
  reversion (not yet confirmed complete).
- Incident B: Compromised workstation isolated; domain controller access via harvested
  credentials requires full domain-compromise-assumption handling.
- **Convergence threat is ACTIVE**: it-infra-lead's credentials are compromised and being used
  by an attacker concurrently with legitimate remediation. This is the single highest-priority
  open item.

## Immediate Next Steps for Incoming Team

1. Complete the out-of-board credential reset for it-infra-lead without disrupting legitimate
   remediation.
2. Verify no other high-privilege accounts had credentials cached on t.oconnor's workstation.
3. Confirm the S3 backup archive policy has been reverted and backups are usable.
4. Conduct full domain-controller forensic review given confirmed credential use at that tier.
5. Review all OAuth application registrations across the tenant from the past 48 hours.

## Key Technique to Flag Going Forward

Credential-dumping tools harvest **every** cached credential on a compromised host, not just
the primary user's — a single low-privilege workstation compromise can expose any
administrator who has ever logged into that machine. This incident demonstrates that
containment scope must always be assessed against *what credentials could plausibly be
present* on a compromised host, not just the host's own assigned user's privilege level.

---

# 📁 Repo Closing Note (Case 050 of 50)

This concludes SOC-Triage-Practice: 50 cases, 150 individually-triaged alerts officially
counted (reached at Case_047), plus 3 bonus Final-Exam-style cases (048–050, 14 additional
alerts triaged with full rigor but not added to the official count) closing the repo with a
multi-stage, cross-domain incident spanning cloud identity, AWS infrastructure, endpoint
compromise, and Active Directory.

The methodology held constant across all 50 cases: investigating blind, documenting
corrections honestly rather than hiding them (including under direct pressure to omit one in
Case_026), tracking real triage time, and — from Case_024 onward — grounding practice scenarios
in real, publicly documented breaches (MGM Resorts, Colonial Pipeline, Capital One, Okta/Sitel,
CircleCI, SolarWinds, Codefinger, Arup, Slack) with fully sanitized identities and IOCs.

The recurring pattern across all five phases — technique alone ≠ automatic TP, normal-seeming
≠ automatic FP, correlation must be verified rather than assumed, and absence of confirming
evidence ≠ positive evidence of compromise — proved to transfer cleanly from single-alert
endpoint investigation (Phase 1) through full queue simulation (Phase 3) into entirely new
cloud, SaaS, and hybrid-identity domains (Phases 4–5), culminating in a final exam where two
unrelated incidents were correctly traced to convergence through a single compromised
credential — the most complex correlation task in the repo's full history.
