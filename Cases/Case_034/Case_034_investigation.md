# Investigation — Case 034

**Verification method:** Ticket-only — no Splunk query run (analyst decision)

---

## Step 1: N-001 — Check the RDP Access

| Field | Value |
|---|---|
| Host | SITEL-SUP-WK14 — support-provider laptop with privileged Okta SuperUser access |
| Source IP | 185.220.101.203, external, no prior history for this host |
| Duration | ~4.5 hours (03:12–07:40 UTC) |

**Finding:** 🔴 A privileged support-tier machine receiving an inbound RDP connection from an
external IP with no prior history is a significant access-control concern on its own — this
type of machine, given its downstream access into customer environments, should not be
reachable this way from an unrecognized external source.

---

## Step 2: N-002 — Check the MFA Factor Addition

| Field | Value |
|---|---|
| Account | support-eng-14@sitelsupport-provider.com — SuperUser-tier access into customer tenants |
| Action | New SMS-based authentication factor added, new phone number |
| Timing | During the active RDP session window from N-001 |

**Finding:** 🔴 Adding a new authentication factor to a highly-privileged support account,
during an active session that originated from an unrecognized external RDP connection, is
consistent with an attacker establishing persistent access to the account independent of
whatever credentials or session got them in initially — the same persistence logic seen in
Case_024's rogue OAuth app and Case_028's rogue IdP.

---

## Step 3: N-003 — Check the Password Reset Pattern

| Field | Value |
|---|---|
| Actor | Same account as N-002 |
| Volume | 14 resets in 25 minutes |
| Scope | 6 different customer organizations' tenants |
| Baseline | 2-3 resets/day, single assigned tenant, ticket-tied |

**Finding:** 🔴 Two compounding deviations from baseline, not one. Volume alone (14 vs. 2-3) is
already a significant spike, but the scope — spreading across 6 different customer
organizations rather than the engineer's single assigned tenant — is what elevates this from
"a busy day" to "systematic account-takeover attempts across every customer this account can
reach." No support tickets are referenced for any of these actions, unlike the documented
baseline pattern.

---

## Step 4: Correlate the Chain

**Finding:** N-001 → N-002 → N-003 form one continuous incident: unauthorized RDP access to a
privileged support machine, used to add a persistence mechanism (new MFA factor) to the
account's own authentication, immediately followed by that account being used to mass-reset
passwords across multiple customer organizations with no ticket justification. This mirrors the
real-world incident's core concern — that compromise of a single third-party support account
creates a blast radius spanning every customer tenant that account can reach, not just one.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| N-001 access pattern | External RDP to privileged support host, no prior history | 🔴 High |
| N-002 MFA factor addition | New factor added during suspicious session, persistence mechanism | 🔴 High |
| N-003 volume | 14 resets vs. 2-3 baseline | 🔴 High |
| N-003 scope | 6 customer tenants vs. single-tenant baseline | 🔴 Critical |
| N-003 ticket justification | None found, vs. documented ticket-tied baseline | 🔴 High |
| Correlation | N-001→N-002→N-003 unbroken chain | 🔴 High — one incident |
