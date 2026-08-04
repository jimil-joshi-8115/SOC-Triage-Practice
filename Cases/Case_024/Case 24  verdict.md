# Verdict — Case 024

## D-001: 🔴 Verdict: TRUE POSITIVE
## D-002: 🔴 Verdict: TRUE POSITIVE
## D-003: 🔴 Verdict: TRUE POSITIVE
## D-004: 🔴 Verdict: TRUE POSITIVE
## D-005: 🔴 Verdict: TRUE POSITIVE

**All five alerts are TP as a single correlated incident.**

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Phishing: Voice Phishing / Trusted Relationship (helpdesk SE) | T1598 / T1199 (adjacent) | Privileged credential reset via helpdesk social engineering (D-001) |
| Valid Accounts: Cloud Accounts | T1078.004 | Login using reset credentials from attacker location (D-002) |
| Trusted Relationship / Modify Authentication Process | T1556 (adjacent) | Rogue external IdP registered for persistent, MFA-bypassing access (D-003) |
| Account Manipulation | T1098 | Privilege escalation to Super Administrator (D-004) |
| Impair Defenses: Disable/Modify Tools | T1562.001 | Windows Defender real-time monitoring disabled (D-005) |
| Inhibit System Recovery | T1490 | vssadmin deletes all shadow copies (D-005) |

---

## Justification

### D-001 — TP (as part of the chain)
In isolation, this is a routine, logged helpdesk action with standard phone verification. It
becomes a confirmed TP only in light of what follows — the reset is the entry point the entire
downstream chain depends on. Verification via employee ID + DOB is weak (both are obtainable
through public/social sources), which is the same root-cause weakness documented in real-world
helpdesk social-engineering incidents this scenario is based on.

### D-002 — TP
Login from a location never seen in 90 days of history, occurring within 3 minutes of the
reset. The timing correlation to D-001 — not geolocation physics alone — is what makes this
decisive.

### D-003 — TP
A new external Identity Provider registered specifically to accept authentication assertions
without needing the compromised account's actual credentials or MFA. This is a persistence
mechanism — the single highest-priority technical finding in the chain, since it survives
password resets and session revocation on the original account.

### D-004 — TP
Full escalation to Super Administrator, 90 seconds after the backdoor IdP was established, from
the same attacker session. Tenant-wide control, not a scoped or explainable admin action.

### D-005 — TP
Defender's real-time monitoring disabled, followed 3 minutes later by deletion of all shadow
copies, from the newly escalated account, on-host. Both are legitimate Windows tools being used
for a well-documented pre-ransomware staging pattern: eliminate live detection, then eliminate
the built-in recovery path, immediately before an expected encryption stage.

**Triage lesson reinforced from Case_020/Case_023:** recognizing D-002 through D-005 as direct
continuations of the same incident established by D-001 — rather than five separate
investigations — is the correlation skill this entire Phase 3-4 progression has been building
toward. The pattern (identity compromise → persistence → privilege escalation → defense
evasion/recovery inhibition) mirrors real, publicly documented breaches where helpdesk
social engineering against cloud identity providers preceded ransomware deployment.

---

## What Would Change These Verdicts

- **D-001 → less severe on its own:** if paired with a confirmed callback to a verified phone
  number on file (not just claimed identity), rather than knowledge-based verification alone.
- **D-002 → FP:** confirmed employee travel to Romania, or a known corporate VPN egress there.
- **D-003 → FP:** a documented, ticketed change request for a legitimate federation partner
  integration.
- **D-004 → FP:** an approved, ticketed role-change request tied to a business justification.
- **D-005 → FP:** a scheduled, ticketed AV-exclusion/maintenance window with a change record,
  though even then shadow-copy deletion alongside it would warrant re-examination.

None of these apply in this ticket — verdicts stand as TP × 5.

---

## Recommended Response Actions

1. **Immediately revoke the rogue IdP ('shadow-idp-relay')** — highest priority, since it is
   the persistence mechanism; removing it first prevents the attacker from simply re-entering
   after account remediation.
2. Disable r.kapoor's account and force a credential reset through a verified, out-of-band
   channel (not helpdesk phone verification alone).
3. Revert the Super Administrator privilege grant back to scoped Infrastructure admin (or
   suspend entirely pending investigation).
4. Re-enable Windows Defender real-time monitoring and IOAV protection on AURORA-DC01
   immediately.
5. Assess backup/recovery posture given shadow copy deletion — confirm offline/immutable
   backups are intact and unaffected, since local recovery options have been removed.
6. Treat this as active/imminent ransomware staging — escalate to IR immediately, isolate
   AURORA-DC01 from the network pending full forensic review, and check for additional hosts
   touched by the escalated account.
7. Review and tighten helpdesk identity-verification procedures (knowledge-based verification
   using employee ID + DOB is insufficient on its own).

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | D-001 through D-005: all TP (single correlated incident) |
| Confidence | High (all five) |
| Verification method | Splunk — sample Okta + Windows Security data (CSV: `mixed_case024.csv`, host `JIMIL-JOSHI`) |
| Triage Time | 7:47 – 7:54 (real, tracked) |
| Escalated | Yes — full chain (would be, in real SOC, as active ransomware precursor) |
| Corrections during investigation | 0 |
| Scenario basis | Adapted from the publicly documented 2023 MGM Resorts / Scattered Spider breach; IOCs and identities fully sanitized/fictional |
