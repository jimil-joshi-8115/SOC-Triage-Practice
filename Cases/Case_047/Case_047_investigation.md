# Investigation — Case 047

**Verification method:** Ticket-only — no Splunk query run (analyst decision)

---

## Step 1: BB-001 — Check the Action's Severity Independent of Account-Compromise Status

| Field | Value |
|---|---|
| Action | New federated domain trust to an unrecognized external IdP |
| Impact | Grants token-based authentication as ANY tenant user, bypassing password and MFA |
| Documentation | No change ticket found |
| Process compliance | Domain federation requires a documented 2-person change process (SEC-SOP-08) — not followed |
| Timing | 23:47 UTC, outside the documented 09:00-17:00 IST change window |

**Finding:** 🔴 This action is TP on its own technical and procedural merits, independent of
whether the account itself was compromised. A federated domain trust of this kind is one of the
most severe possible actions in Azure AD — it establishes an alternate authentication path for
every user in the tenant. The complete absence of a change ticket and the bypass of a mandatory
2-person approval process are sufficient grounds for TP regardless of actor intent.

---

## Step 2: BB-001 — Weigh the Timing/IP Anomaly as Additional Context

| Field | Value |
|---|---|
| Session origin | 15 minutes after the account's normal login |
| Source IP | New, does not match the normal login |
| Standalone compromise alert | None exists for this account |

**Finding:** 🟡 This detail raises a legitimate open question — whether it-infra-lead's account
or session was hijacked, or whether the documented account holder performed this action
themselves outside proper process — but it does not need to be resolved to reach a verdict on
BB-001. The action itself (unapproved, no-ticket, off-hours federation trust bypassing a
mandatory control) is TP whether the actor was an external attacker using a hijacked session or
an insider acting outside policy. The account-compromise question is flagged as an open
investigative thread for response actions, not a precondition for the TP verdict.

---

## Step 3: BB-002 — Check Against Documented Change Process

| Field | Value |
|---|---|
| Action | Password expiration policy shortened, 90 to 60 days |
| Documentation | Tied to CHG-9701, CISO-approved |
| Timing | Standard business hours, day before BB-001 |

**Finding:** 🟢 Fully documented, approved, business-hours security-hardening change. No
deviation from process. No connection to BB-001 in timing, action type, or approval status.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| BB-001 action severity | Tenant-wide auth bypass capability established | 🔴 Critical |
| BB-001 process compliance | No ticket, 2-person process bypassed, off-hours | 🔴 Critical |
| BB-001 account-status question | Open (compromise vs. insider action) — does not affect verdict | 🟡 Flagged for response, not verdict-determining |
| BB-002 vs. documented process | Fully ticketed, approved, routine | 🟢 None |
