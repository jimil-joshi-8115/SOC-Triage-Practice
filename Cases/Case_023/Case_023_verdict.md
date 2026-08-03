# Verdict — Case 023

## AG-001: 🔴 Verdict: TRUE POSITIVE

## AG-002: 🔴 Verdict: TRUE POSITIVE

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Valid Accounts: Cloud Accounts | T1078.004 | Console login using s.rathod's valid IAM credentials (AG-001) |
| Cloud Account Discovery | T1087.004 | ListUsers, ListRoles, GetAccountAuthorizationDetails (AG-002 Event 1) |
| Additional Cloud Credentials | T1136.003 | CreateAccessKey for svc-deploy-bot (AG-002 Event 2) |
| Cloud Account | T1098.001 (adjacent) | AttachUserPolicy touching a high-privilege service account (AG-002 Event 3) |

---

## Justification

### AG-001 — TP
Successful console login from a confirmed Tor exit node, with MFA not used, against a 14-day
baseline of 100%-consistent MFA usage from Indian IP ranges only. Both deviations are total,
not partial, and Tor usage specifically signals deliberate anonymization rather than
coincidental network variance. Same "success ≠ safety" pattern established in Case_021 — a
successful login here is the compromise, not proof of legitimacy.

### AG-002 — TP
Same attacker session (identical source IP to AG-001) immediately pivots into IAM discovery —
four API calls never seen in s.rathod's 90-day CloudTrail history, fired in a 6-second window.
This is reconnaissance volume/novelty evidence standing on its own, the same class of signal
established in Case_019's DNS TXT flood. The session then creates a new access key for
`svc-deploy-bot`, a *separate*, high-privilege service account — this is the actual escalation:
pivoting off a standard user identity onto a durable, powerful credential the attacker now
controls independently of s.rathod's account. The redundant AttachUserPolicy call, while not a
privilege change, still shows deliberate interaction with that account's permissions and is
consistent with an attacker confirming the access they now hold.

**Correlation:** AG-001 and AG-002 are one incident, not two independent findings. Identical
source IP, direct time sequence (login → discovery → escalation within ~3.5 minutes), and a
clear cause-and-effect chain. Treating AG-002 as a fresh investigation rather than a
continuation of AG-001 would have missed the fact that the real damage — the new
administrator-level credential — happened in AG-002, not AG-001.

---

## What Would Change These Verdicts

- **AG-001 → FP:** documented corporate policy of Tor/VPN use for this user, or an internal
  security-testing exception on file for that time window.
- **AG-002 → FP/Ambiguous:** a change ticket showing `svc-deploy-bot`'s access key rotation was
  scheduled maintenance performed by an authorized automation pipeline from that IP.

None of these apply in this ticket — verdicts stand as TP / TP.

---

## Recommended Response Actions

- Disable `s.rathod`'s IAM console access and access keys immediately.
- **Immediately deactivate the newly created access key on `svc-deploy-bot`** — this is the
  highest-priority action, since it's a live, attacker-controlled, AdministratorAccess-level
  credential independent of the originally compromised account.
- Review CloudTrail for any API activity performed using the new `svc-deploy-bot` access key
  since its creation (02:14:38 UTC) — assume full account compromise until ruled out.
- Rotate credentials/secrets for any resource `svc-deploy-bot` has touched.
- Block source IP 193.32.248.14 at the account/org level (Tor exit nodes should generally be
  blocked from console access via SCP/IP allowlisting going forward).
- Enforce MFA at the IAM policy level (not just as a login habit) to prevent recurrence.
- Escalate to L2/IR immediately — this is confirmed cloud account takeover with active
  privilege escalation to an administrator-level service account.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | AG-001: TP · AG-002: TP |
| Confidence | High (both) |
| Verification method | Ticket-only — no Splunk query run (analyst decision) |
| Triage Time | Not tracked |
| Escalated | Yes (would be, in real SOC) |
| Corrections during investigation | 0 |
