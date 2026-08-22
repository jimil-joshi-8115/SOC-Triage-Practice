# Investigation — Case 042

**Verification method:** Ticket-only — no Splunk query run (analyst decision)

---

## Step 1: W-001 — Check Actor Role Against Action Taken

| Field | Value |
|---|---|
| Actor | d.varma, Marketing Coordinator |
| Documented role | No IT/security function, no documented reason to touch network security config |
| Action | Added an unrelated external IP to the org-wide MFA-exempt trusted range |
| Change ticket | None found |

**Finding:** 🔴 A Conditional Access trusted-location policy is org-wide security
infrastructure, not something within any Marketing role's function. The added IP has no
connection to any known Aurora office, ISP, or VPN — it is a single, isolated, unexplained
addition with no supporting documentation.

---

## Step 2: W-002 — Check the Resulting Sign-In

| Field | Value |
|---|---|
| Source IP | 185.220.101.212 — the exact IP added in W-001 |
| MFA | Not prompted |
| Reason | Sign-in matched the newly-modified trusted location |
| Timing | 3 minutes after W-001 |

**Finding:** 🔴 Direct, immediate exploitation of the W-001 modification — the same IP that was
just added to the trusted range is used to sign in without triggering MFA, confirming the
policy change was made specifically to enable this bypass.

---

## Step 3: Assess the Persistence Implication of W-001 Specifically

**Finding:** 🔴 This is what distinguishes W-001 from a standard stolen-credential login: the
danger is not limited to this one sign-in. Once the IP is part of the org's trusted-location
policy, **every future sign-in from that IP, using any account — not only d.varma's** — will
also skip MFA, because the exemption is now built into the Conditional Access policy itself
rather than tied to a single compromised credential. Even a full password reset and
re-securing of d.varma's account would not remove this standing exemption; the trusted-location
entry itself must be identified and removed. This is a persistence mechanism operating at the
tenant security-policy level, not the individual-account level — a fundamentally broader and
more durable foothold than account compromise alone.

---

## Step 4: W-003 — Check Against Documented Change Process

| Field | Value |
|---|---|
| Actor | it-infra-lead — IT Infrastructure Lead, appropriate role for this action |
| Action | Added a confirmed, ISP-verified IP range for a new branch office |
| Documentation | Tied to change ticket CHG-9502, explicit business context |
| Timing | 6 hours before W-001, different account entirely |

**Finding:** 🟢 Fully documented, role-appropriate, business-justified change with independent
ISP confirmation. No overlap in actor, timing, or IP with the W-001/W-002 incident.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| W-001 actor vs. action | Marketing role modifying security policy, no ticket | 🔴 High |
| W-001 IP legitimacy | No connection to any known Aurora infrastructure | 🔴 High |
| W-002 exploitation | Immediate MFA-bypass sign-in from the added IP | 🔴 Critical |
| W-001 persistence scope | Tenant-wide exemption, not account-specific | 🔴 Critical |
| W-003 vs. documented process | Role-appropriate, ticketed, ISP-confirmed | 🟢 None |
| Correlation W-001/W-002 | Same IP, 3-minute gap, direct causal link | 🔴 High — one incident |
