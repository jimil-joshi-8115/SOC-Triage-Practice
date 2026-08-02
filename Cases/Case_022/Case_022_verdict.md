# Verdict — Case 022

## BC-001: 🟢 Verdict: FALSE POSITIVE

## BC-002: 🔴 Verdict: TRUE POSITIVE

## BC-003: 🔴 Verdict: TRUE POSITIVE

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Valid Accounts | T1078 | Account takeover via legacy-auth sign-in (BC-002) |
| Email Forwarding Rule | T1114.003 | Malicious inbox rule for concealment/exfil (BC-002) |
| Email Collection | T1114 | Fraudulent payment-redirection emails sent from compromised mailbox (BC-003) |
| — | — | BEC/Vendor Email Compromise (VEC) pattern, not a single ATT&CK ID (BC-003) |

---

## Justification

### BC-001 — FP
User self-reported a phishing email via the Report Message add-in. The reporting action's own
session shows the user's normal Ahmedabad IP — no click, no credential entry logged anywhere.
Nothing in this alert indicates the user's account was actually compromised; the awareness
process worked exactly as intended.

### BC-002 — TP
Impossible travel (Ahmedabad → Warsaw, 27 minutes, ~5,900 km) combined with a legacy-auth
(IMAP4) sign-in that bypassed MFA and Conditional Access, immediately followed by a malicious
inbox rule. The rule's configuration — targeting financial keywords, hiding matches in an
unused folder, forwarding a copy externally, and suppressing further rule processing — has no
legitimate business justification. This is account takeover with active concealment tradecraft,
not a borderline call.

### BC-003 — TP
14 "updated bank details" emails sent from the exact IP confirmed compromised in BC-002, within
minutes of the inbox rule's creation, targeting a real vendor's finance/AP/billing contacts.
This is a direct continuation of the BC-002 incident — the fraud payload itself, executed from
inside a trusted, legitimate mailbox. Treating this as a fresh, unrelated investigation would
have missed the correlation.

**Triage lesson reinforced from Case_020:** recognizing BC-003 as a continuation of an
already-confirmed incident (same session, same IP, immediate timing) rather than re-investigating
it from scratch is the same correlation skill demonstrated in the Final Exam.

---

## What Would Change These Verdicts

- **BC-001 → TP:** if the reporting user's own session showed an unusual IP/location, or if
  credential entry/click activity were found elsewhere in the logs.
- **BC-002 → FP:** confirmed employee travel to Warsaw at the time, or a known corporate VPN
  egress point there.
- **BC-003 → FP:** confirmation from the vendor that the "updated bank details" were legitimate
  and pre-arranged through a verified, out-of-band channel.

None of these apply in this ticket — verdicts stand as FP / TP / TP.

---

## Recommended Response Actions

- Disable `k.desai@corptenant.com` immediately; force password reset; revoke all
  sessions/refresh tokens.
- Delete the malicious inbox rule.
- Disable legacy authentication (IMAP4/POP3/SMTP AUTH) tenant-wide if not already planned.
- **Urgent — time-critical:** contact `vendorpartner-inc.com` out-of-band to flag the
  fraudulent bank-detail emails before any payment is processed against them.
- Review the mailbox for further rules, sent items, or additional exfiltration since compromise.
- Escalate to L2/IR and Finance/AP teams immediately given the active fraud attempt.
- No action needed on BC-001 beyond standard closure — correctly handled by the user.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | BC-001: FP · BC-002: TP · BC-003: TP |
| Confidence | High (all three) |
| Verification method | Splunk — sample O365 Unified Audit Log data (CSV: `o365_unifiedauditlog_case022.csv`, host `JIMIL-JOSHI`) |
| Triage Time | Start 09:19 UTC, End ~09:56 UTC |
| Escalated | Yes — BC-002/BC-003 (would be, in real SOC) |
| Corrections during investigation | 0 |
