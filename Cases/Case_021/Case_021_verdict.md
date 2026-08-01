# Verdict — Case 021

## 🔴 Verdict: TRUE POSITIVE

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Valid Accounts | T1078 | Successful sign-in on a legitimate account from an attacker-controlled location |
| (Sentinel-tagged) | InitialAccess | Native Sentinel incident classification |

---

## Justification

1. **Legacy authentication protocol (IMAP4) used** — this bypasses Conditional Access and MFA
   entirely, not incidentally. Legacy protocols are never evaluated by CA policy, so this is a
   known technique specifically to sidestep modern auth controls, not a side effect of an old
   client app.
2. **Geography deviation** — the user's 30-day baseline is 95% Ahmedabad, 5% Mumbai; Lagos,
   Nigeria is a first-seen location with zero prior overlap and no travel plausibility in the
   available window.
3. **IP independently flagged as risky by Microsoft Threat Intelligence** — external
   corroboration, not just an internal heuristic guessing at anomaly.
4. **Device unregistered and non-compliant** — consistent with attacker-owned hardware rather
   than the user's managed corporate device.
5. **Result: Success** — this is the deciding field. A successful legacy-auth sign-in from a
   flagged IP, from an unseen location, on a non-compliant device is not reassuring; it means
   the attacker got in, not that the system is functioning as intended.

**Triage lesson reinforced from Case_018 (rapid-response):** "normal access method/timing ≠
proof of safety" and its inverse here — "Success ≠ safety" — is the same pattern applied to a
new alert domain (cloud identity) for the first time in this repo.

---

## What Would Change This Verdict to FP

- Confirmed employee travel record placing the user in Nigeria at the time
- A known corporate VPN egress point in Lagos used by other employees
- Admin-flagged penetration test / red team activity for this account
- The IP later found to be a shared NAT/mobile carrier range with no other risk signals

None of these apply in this ticket — verdict stands as TP.

---

## Recommended Response Actions

- Disable the account's sign-in immediately.
- Force password reset and revoke all active sessions/refresh tokens.
- Disable legacy authentication (IMAP4/POP3/SMTP AUTH) for this user, ideally tenant-wide.
- Review the mailbox for inbox rules, forwarding rules, or sent items indicating BEC follow-through.
- Notify the user directly, out-of-band (not via email), to confirm this wasn't them.
- Escalate to L2/IR if the mailbox shows signs of forwarding-rule creation or further BEC activity.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdict | TP |
| Confidence | High |
| Verification method | Ticket-only — no Splunk query run (analyst decision) |
| Triage Time | Not tracked |
| Escalated | Yes (would be, in real SOC) |
| Corrections during investigation | 0 |
