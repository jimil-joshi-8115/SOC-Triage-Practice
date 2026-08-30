# Case_050 — 🏁 FINAL CAPSTONE, Stage 3: Legitimate Remediation vs. Concurrent Compromised-Credential Attack

**Status:** Bonus material, final case of the repo (50 of 50). Continues directly from Cases
048–049. Closes with a full shift-handoff synthesizing the entire 3-stage exam and the repo.
**Format:** Mixed — AWS CloudTrail, EDR, Azure AD Audit Log, 3-alert queue with live interrupt
**Company:** Aurora Resorts & Casinos (internal alias — sanitized)
**Splunk verified:** No — ticket-only (analyst decision)

---

## Alerts (as received at trigger time)

```
Alert EE-001 — AWS: backup-svc-2 Instances Terminated by Unknown Actor
  Severity: High
  Actor: it-infra-lead@auroraresorts.com (via emergency AWS root/break-glass
         access, logged with MFA + physical security key per emergency
         procedure EMERG-SOP-02)
  Detail: All 12 GPU instances terminated, backup-svc-2 access keys
          deactivated; matches incident response actions recommended in
          Case_049 — appears to be the legitimate IT team beginning
          remediation
  Time: 10:05:00 UTC

Alert EE-002 — Endpoint: MFL-WKS0287 Isolated From Network
  Severity: Low
  Actor: EDR-Automated-Containment
  Detail: Automated EDR containment action isolated t.oconnor's workstation
          from the network, triggered by the confirmed credential-dumping
          detection from Case_049's DD-001; matches standard automated
          containment playbook for this detection type
  Time: 10:06:30 UTC

>>> LIVE INTERRUPT — fired during remediation <<<

Alert EE-003 — Azure AD: it-infra-lead Account Attempting Actions From a SECOND New Location
  Severity: Critical
  Account: it-infra-lead@auroraresorts.com
  Detail: While EE-001's legitimate remediation was in progress from the
          IT team's known location, a SECOND, simultaneous session for the
          SAME account attempted to create a new OAuth application
          registration with Directory.ReadWrite.All — from Lagos, Nigeria,
          a location with zero history for this account; this session was
          NOT the one performing EE-001's remediation (different IP,
          different concurrent session token)
  Time: 10:07:15 UTC
```

## Task

Final stage. TP / FP / Ambiguous for EE-001 through EE-003. Consider what it means for the same
account to be performing two different actions, in two different locations, at the same time.
Close with a full shift-handoff summary for the entire 3-stage exam.
