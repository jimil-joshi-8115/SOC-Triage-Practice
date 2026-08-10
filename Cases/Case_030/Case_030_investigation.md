# Investigation — Case 030 (Phase 4 Capstone)

**Verification method:** Ticket-only, time pressure (~2-3 min/alert target), live interrupt
mid-queue — same format as the original Final Exam (Cases 019-020)

---

## Step 1: J-001 — Check the Delivery Vector

| Field | Value |
|---|---|
| Sender domain | meridianfuel-**portal**.com (lookalike of meridianfuel.com) |
| SPF/DKIM/DMARC | Fail / Fail / Fail |
| Pretext | Fake "unusual sign-in blocked" security alert |
| Link | meridianfuel-portal-verify[.]com/reauth |

**Finding:** 🔴 All three authentication checks failed, deliberate lookalike domain, and the
pretext itself (a fake security alert) is designed to create urgency around exactly the kind of
action — reauthentication — that harvests credentials. Classic credential-phishing setup.

---

## Step 2: J-002 — Check the Click-Through

| Field | Value |
|---|---|
| Destination | Same domain from J-001, registered 3 days ago |
| Page behavior | Requested Microsoft 365 credentials |
| Proxy log | POST request immediately after page load |

**Finding:** 🔴 The user clicked the J-001 link, and the proxy log shows a POST request pattern
consistent with credential submission on a freshly-registered lookalike domain — this is the
credential theft actually occurring, not just a suspicious email sitting unopened.

---

## Step 3: J-003 — Check the Sign-In and MFA Pattern

| Field | Value |
|---|---|
| Location | Bucharest, Romania vs. 14-day baseline of Ahmedabad, India only |
| MFA sequence | Denied twice, approved on 3rd prompt within 90 seconds |

**Finding:** 🔴 Two things stack here, not one. The location is a first-seen deviation
immediately following the J-002 credential submission. Separately and specifically: the MFA
pattern — repeated push prompts denied, then approved shortly after — is the signature of
**MFA fatigue / push bombing**, the same technique used in the real 2022 Uber breach. This is a
named, specific technique, not just "MFA was technically satisfied."

---

## Step 4: J-004 — Check the Inbox Rule

| Field | Value |
|---|---|
| Rule name | "Security" |
| Targets | Emails containing "unusual sign-in," "security alert," "suspicious activity" |
| Action | Move to Deleted Items, mark as read, StopProcessingRules: True |
| Source IP | Same as J-003 |

**Finding:** 🔴 This rule exists for exactly one purpose: to hide legitimate security
notifications from the real account owner, specifically targeting the phrases that would appear
in a genuine "your account may be compromised" alert. This is concealment tradecraft, not a
user's personal mailbox organization.

---

## Step 5: J-005 — Check the RDP Connection

| Field | Value |
|---|---|
| Account | d.thakkar (Regional Dispatch Coordinator — no documented file-server RDP need) |
| Prior 90-day RDP history | None |
| Source | MFL-WKS0198 — same workstation as J-002 |

**Finding:** 🔴 First-ever RDP activity for this account to any file server, from the same
workstation where credentials were harvested, and outside the account's documented role
function. Lateral movement toward the file server that becomes the target of J-007.

---

## Step 6: J-006 — Check for Correlation

| Check | J-001–J-005/J-007 chain | J-006 |
|---|---|---|
| Account | d.thakkar | m.oconnor |
| Host | MFL-WKS0198 / MFL-FS03 | MFL-WKS0055 |
| Pattern | Novel, escalating attack chain | Documented, recurring, auto-ticketed benign pattern |

**Finding:** 🟢 Different account, different host, no shared IP or timing link, and an
explicitly documented recurring benign cause (stale saved credential after a password change).
Same discrimination-test structure as Case_025 (E-002), Case_027 (G-004), and Case_029 (I-005).

---

## Step 7: J-007 — Live Interrupt

| Field | Value |
|---|---|
| Action | 7-Zip archive of DispatchRecords + CustomerContracts, 2.3GB |
| Destination | Moved to C:\Users\Public\ on the same host (MFL-FS03) |
| Account | d.thakkar |
| Timing | 4 minutes after the J-005 lateral RDP connection |

**Finding:** 🔴 Critical. Data staging for exfiltration — sensitive business data compressed and
placed in a public, easily-accessible location, immediately following unauthorized lateral
access to the file server. This confirms the attack has progressed from access to active data
theft in progress.

**Priority re-evaluation triggered by J-007:** containment (isolate MFL-FS03 and MFL-WKS0198,
disable d.thakkar's account, kill active sessions) now takes precedence over continuing to
document remaining queue items in order — the same pattern established in Case_025's live
interrupt.

---

## Step 8: Correlate the Full Chain

**Finding:** J-001 → J-002 → J-003 → J-004 → J-005 → J-007 form one unbroken, escalating
incident: phishing delivery → credential harvest → MFA-fatigue account takeover → mailbox
concealment → lateral movement to the file server → data staged for exfiltration. Same account
(d.thakkar) and/or same source IP/workstation throughout, with a coherent ~14-minute timeline
(10:02–10:16 UTC). J-006 is confirmed unrelated noise.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| J-001 phishing delivery | Failed auth, lookalike domain, urgency pretext | 🔴 High |
| J-002 credential harvest | Click confirmed, POST to fresh lookalike domain | 🔴 High |
| J-003 account takeover | Location anomaly + MFA fatigue (named technique) | 🔴 High |
| J-004 mailbox concealment | Rule hides real security alerts specifically | 🔴 High |
| J-005 lateral movement | First-ever RDP, no role justification | 🔴 High |
| J-006 correlation check | Different account/host, documented benign pattern | 🟢 None — FP |
| J-007 live interrupt | Data staged for exfiltration, active in progress | 🔴 Critical |
| Chain correlation | J-001→J-002→J-003→J-004→J-005→J-007, one incident | 🔴 High |
