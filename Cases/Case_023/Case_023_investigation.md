# Investigation — Case 023

## Step 1: AG-001 — Check Login Context Against Baseline

| Field | Alert value | 14-day baseline |
|---|---|---|
| Source IP | 193.32.248.14 (Netherlands, Tor exit node) | 103.211.44.0/24 (India) |
| MFA used | No | Yes, 100% of time |

**Finding:** 🔴 Both the location and the MFA usage are total deviations from baseline, not
partial ones. A Tor exit node specifically (not just "a foreign IP") is a strong indicator of
deliberate anonymization, and losing 100%-consistent MFA usage on the same login is not
explainable by normal behavioral variance.

---

## Step 2: AG-002 — Separate the Three Chained Events

| Event | Action | Novelty check |
|---|---|---|
| 1 (02:13:02) | ListUsers, ListRoles, ListAccessKeys, GetAccountAuthorizationDetails | Not called by s.rathod in 90 days prior |
| 2 (02:14:38) | CreateAccessKey — for svc-deploy-bot (different user) | New access key on a high-privilege service account |
| 3 (02:15:10) | AttachUserPolicy — svc-deploy-bot, AdministratorAccess | Redundant (already attached) — logged but no privilege change |

**Finding:** 🔴 Event 1 alone is IAM enumeration/discovery — 4 unfamiliar API calls in 6
seconds is rate/pattern evidence on its own (same class of signal as the Case_019 DNS TXT
flood — volume and unfamiliarity, not needing a confirmed downstream outcome). Event 2 is the
decisive escalation step: creating a new access key for a *different*, high-privilege account
is how an attacker pivots off a lower-value compromised identity onto a durable, powerful one.
Event 3, while redundant in effect, still demonstrates the attacker deliberately touching
permissions on the target account — consistent with confirming/asserting access rather than
being a meaningless log artifact.

---

## Step 3: Check Source IP Correlation

AG-001 actor IP: 193.32.248.14. AG-002 event source IP (all 3 events): 193.32.248.14.

**Finding:** 🔴 Identical IP across both findings. AG-002 is not a separate incident — it's the
same attacker session immediately pivoting from initial access into discovery and privilege
escalation.

---

## Step 4: Check for Mitigating Context

Reviewed for: known corporate Tor/VPN usage policy, scheduled deploy-bot key rotation, change
ticket for AdministratorAccess re-attach. None present in the ticket.

**Finding:** 🔴 No mitigating explanation available for either finding.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| AG-001 login location vs. baseline | Tor exit node vs. India-only, 0% match | 🔴 High |
| AG-001 MFA vs. baseline | Not used vs. 100% baseline | 🔴 High |
| AG-002 API call novelty | 4 calls never seen in 90-day history | 🔴 High |
| AG-002 CreateAccessKey target | Different, high-privilege service account | 🔴 High |
| AG-002 AttachUserPolicy | Redundant but deliberate permission touch | 🟠 Contributing factor |
| IP correlation AG-001 ↔ AG-002 | Identical source IP | 🔴 High — same session |
| Mitigating context | None found | 🔴 High |
