# Verdict — Case 030 (Phase 4 Capstone)

## J-001: 🔴 TP · J-002: 🔴 TP · J-003: 🔴 TP · J-004: 🔴 TP · J-005: 🔴 TP · J-006: 🟢 FP · J-007: 🔴 TP (Critical — Live Interrupt)

**J-001 through J-005, plus J-007, are TP as a single correlated incident. J-006 is FP.**

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Phishing: Spearphishing Link | T1566.002 | Lookalike-domain credential phishing email (J-001) |
| Steal Web Session Cookie / Input Capture | T1539 / T1056 (adjacent) | Credential submission to fake portal (J-002) |
| Valid Accounts | T1078 | Account takeover via harvested credentials (J-003) |
| Multi-Factor Authentication Request Generation | T1621 | MFA fatigue / push bombing — 2 denials, approved on 3rd prompt (J-003) |
| Email Hiding Rules | T1564.008 | Inbox rule concealing security notifications (J-004) |
| Remote Services: Remote Desktop Protocol | T1021.001 | Lateral movement to file server via RDP (J-005) |
| Archive Collected Data | T1560.001 | 7-Zip archive of sensitive shares (J-007) |
| Data Staged: Local Data Staging | T1074.001 | Archive moved to public, accessible path (J-007) |

---

## Justification

### J-001 through J-005, J-007 — TP (single incident)
Each stage is directly supported by its own alert data and connects causally to the next:
a lookalike-domain phishing email with failed authentication checks (J-001) is clicked and
results in credential submission to a freshly-registered fake portal (J-002); those harvested
credentials are used for a successful sign-in from an unfamiliar location, secured against
detection via MFA fatigue — repeated push denials followed by an approval on the third prompt,
the same technique documented in the real 2022 Uber breach (J-003); the compromised account
immediately creates a mailbox rule specifically engineered to hide legitimate security alerts
from the real user (J-004); the same account then performs its first-ever RDP connection to a
file server outside its documented role function, from the same workstation where credentials
were harvested (J-005); and four minutes later, sensitive business data is compressed and
staged in a public, easily-exfiltrated location on that same file server (J-007). This is one
continuous, ~14-minute attack chain with no missing links.

### J-006 — FP
Different account (`m.oconnor`) and host (`MFL-WKS0055`), no shared IP or timing overlap with
the confirmed chain, and an explicitly documented, auto-ticketed recurring benign pattern
(stale saved credential following a password change). No connection to the incident.

### J-007 — Live Interrupt, Critical
Confirms the incident has progressed from unauthorized access to active data staging for
exfiltration. **This immediately re-prioritizes the response**: containment of MFL-FS03 and
MFL-WKS0198, and disabling d.thakkar's account, take precedence over continuing to document
the remaining queue in strict order — the same live-interrupt discipline demonstrated in
Case_025.

---

## What Would Change These Verdicts

- **J-001/J-002 → FP:** confirmed internal phishing-simulation/awareness-test campaign covering
  this exact domain and timeframe (would need to be verified against the security team's own
  campaign calendar, not assumed).
- **J-003 → FP:** essentially not plausible given the direct causal link to J-002's credential
  submission and the MFA-fatigue pattern present.
- **J-004/J-005 → FP:** no plausible legitimate explanation given the specificity of the inbox
  rule's targeting and the account's total lack of RDP history/role justification.
- **J-006 → TP:** if any link to d.thakkar's account, IP, or the attack timeline were found
  (none present in this ticket).
- **J-007 → FP:** essentially not plausible given the direct continuation from confirmed lateral
  movement in J-005, four minutes prior, same account and host.

---

## Recommended Response Actions (Immediate — Priority Order Following J-007)

1. **Isolate MFL-FS03 and MFL-WKS0198 from the network immediately** — halts any further staging
   or exfiltration.
2. **Disable d.thakkar's account and terminate all active sessions** — cuts off the attacker's
   access across email, Azure AD, and endpoint simultaneously.
3. Quarantine/delete `backup_0810.7z` from `C:\Users\Public\` on MFL-FS03 before it can be
   moved off the host.
4. Remove the "Security" inbox rule from d.thakkar's mailbox.
5. Block the sender domain and the phishing portal domain (`meridianfuel-portal.com`,
   `meridianfuel-portal-verify.com`) at the email gateway and proxy/firewall level.
6. Force a full credential reset for d.thakkar through a verified, out-of-band channel, and
   re-enroll MFA on a new, verified device (the existing method was defeated via fatigue).
7. Review CloudTrail/Azure AD sign-in logs for any other accounts targeted by the same
   phishing domain or exhibiting similar MFA-denial-then-approval patterns.
8. Assess the DispatchRecords and CustomerContracts shares for data sensitivity and initiate a
   breach/data-loss assessment in parallel with technical containment.
9. Escalate to IR immediately — this is an active, in-progress security incident with confirmed
   data staged for exfiltration.
10. No action needed on J-006 beyond its existing auto-generated helpdesk ticket process.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | J-001–J-005: TP · J-006: FP · J-007: TP (Critical) |
| Confidence | High (all seven) |
| Verification method | Ticket-only, time pressure, live interrupt (Final Exam format) |
| Triage Time | 3 minutes total for the full 7-alert queue |
| Escalated | Yes — full chain (would be, in real SOC, as active data-exfiltration incident) |
| Corrections during investigation | 0 |

---

# 🔄 Shift Handoff Summary

**Incident:** Business Email Compromise → MFA-fatigue account takeover → mailbox concealment →
lateral movement → active data staging for exfiltration.

**Affected account:** d.thakkar@meridianfuel.com (Regional Dispatch Coordinator)
**Affected hosts:** MFL-WKS0198 (workstation, initial compromise), MFL-FS03 (file server,
lateral target and staging location)

**Timeline (10:02–10:16 UTC, ~14 minutes):**
1. 10:02 — Phishing email delivered from a lookalike domain, failed all authentication checks
2. 10:04 — User clicked the link, submitted M365 credentials to a fake portal
3. 10:07 — Attacker signed in from Bucharest, Romania, bypassing MFA via push-bombing (denied
   twice, approved on 3rd prompt) — same technique as the 2022 Uber breach
4. 10:09 — Attacker created a mailbox rule to hide legitimate security alerts from the real user
5. 10:12 — Attacker moved laterally via RDP from the compromised workstation to the file server,
   outside the account's normal role function
6. 10:16 — **[LIVE INTERRUPT]** Attacker archived 2.3GB of dispatch records and customer
   contracts and staged the file in a public directory on the file server

**Status at handoff:** Containment actions in progress per the priority-ordered response list
above (isolate hosts, disable account, quarantine staged archive). Data has not yet been
confirmed exfiltrated off MFL-FS03, but staging is complete — this is time-critical.

**Unrelated, correctly-dismissed alert:** J-006 (m.oconnor account lockout) — documented,
recurring, auto-ticketed pattern, no connection to this incident. No action needed beyond
standard helpdesk process.

**Key technique to flag for the next analyst/IR team:** MFA fatigue / push bombing was the
specific mechanism that defeated MFA on this account — re-enrollment should use a verified
device and the organization should consider number-matching or phishing-resistant MFA (e.g.,
FIDO2) to prevent recurrence of this exact technique.

**Next steps for incoming shift:** confirm containment completed, monitor for any secondary
accounts touched by the same phishing domain, and begin formal data-loss assessment on the
staged archive's contents.
