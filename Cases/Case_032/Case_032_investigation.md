# Investigation — Case 032

**Verification method:** Ticket-only — no Splunk query run (analyst decision)

---

## Step 1: L-001 — Check the Account's Privilege Level Against Its Role

| Field | Value |
|---|---|
| Account | p.nair@auroraresorts.com |
| Department | Marketing |
| Role granted | Global Administrator |
| Granted | 6 days ago, "as part of a broader access review" |
| Documented justification | None found |

**Finding:** 🔴 This is the detail that should be caught before anything else in this ticket:
Global Administrator is the highest privilege tier in Azure AD, and there is no legitimate
reason a standard Marketing account should hold it — let alone with no documented justification
for the grant. This alone should have been flagged during the access review itself, independent
of anything that happens afterward.

---

## Step 2: L-001 — Check the Action Taken With That Privilege

| Field | Value |
|---|---|
| Group | CA-Legacy-Exempt — documented purpose: service accounts only, exempts members from ALL Conditional Access policies including MFA |
| Action | p.nair added themselves to this group |
| Actor | p.nair (using the Global Admin role from Step 1) |

**Finding:** 🔴 Using unexplained Global Admin rights to add oneself — a standard human user
account, not a service account — to a group specifically designed to disable MFA/CA
enforcement, is self-service privilege abuse to remove one's own security controls. This is not
an administrative task performed on behalf of the organization; it directly benefits the actor
performing it by weakening protections on their own account.

---

## Step 3: L-002 — Check the Resulting Sign-In

| Field | Value |
|---|---|
| Protocol | POP3 (legacy) |
| MFA | Not evaluated — CA bypassed due to L-001's group membership |
| Source IP | 45.8.211.19, first appearance in 90-day history |
| Application | Office 365 Exchange Online |

**Finding:** 🔴 This is the direct payoff of L-001: a legacy-protocol sign-in from a
never-before-seen external IP, with no MFA evaluation at all, made possible specifically
because of the CA exemption obtained two and a half minutes earlier. No mitigating context
(travel record, VPN, admin exception) is present in the ticket.

---

## Step 4: Correlate L-001 and L-002

**Finding:** This is a complete, self-contained account-takeover sequence with no external
technique (phishing, MFA fatigue, credential theft) required — the attacker used privileges
that shouldn't have existed (Step 1) to directly disable their own account's security controls
(Step 2), then immediately exploited that gap (L-002). The unexplained Global Admin grant is
the true root cause and should be treated as a broader access-review failure, not just an
isolated incident on this one account.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| L-001 privilege level | Global Admin on a standard Marketing account, no justification | 🔴 High |
| L-001 self-exemption action | Self-added to MFA/CA-bypass group using that privilege | 🔴 High |
| L-002 sign-in protocol | Legacy (POP3), MFA not evaluated | 🔴 High |
| L-002 source IP | First-ever appearance in 90-day history | 🔴 High |
| Correlation | L-002 directly enabled by L-001, 2.5-minute gap | 🔴 High — one incident |
