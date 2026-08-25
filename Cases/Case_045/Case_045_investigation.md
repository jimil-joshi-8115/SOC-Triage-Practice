# Investigation — Case 045

**Verification method:** Ticket-only — no Splunk query run (analyst decision)

---

## Step 1: Y-001 — Check the Email Itself

| Field | Value |
|---|---|
| Sender domain | auroraresorts-**group**.com (lookalike of auroraresorts.com) |
| SPF/DKIM/DMARC | Fail / Fail / Fail |
| Pretext | Confidential acquisition, secrecy request, video call to follow |
| Recipient action | Recognized as suspicious, forwarded to IT Security, not acted on |

**Finding:** 🔴 Failed authentication checks, a deliberate lookalike domain, and a pretext
structure (urgency + confidentiality + a promised "verification" call) matching the exact
setup used in the real-world Arup fraud this scenario is grounded in. TP as a phishing attempt,
independent of the fact that the recipient correctly did not act on it directly.

---

## Step 2: Y-002 — Check the Approval Basis and Bypassed Control

| Field | Value |
|---|---|
| Approver | p.kapadia — the same recipient as Y-001 |
| Payees | 4 newly-added accounts, same-day addition, no prior vendor relationship, unfamiliar jurisdiction |
| Approval basis logged | "Video call confirmation with CFO office" |
| Control normally required | Dual-approval sign-off from a second finance officer for transfers over $50K (FIN-POL-12) |

**Finding:** 🔴 The specific control bypassed here is **segregation of duties (dual-approval)**.
FIN-POL-12 exists precisely so that no single individual's judgment — however confident — is
sufficient to authorize a large transfer; a second, independent finance officer must verify it
separately. Here, a video call was treated as a substitute for that second approval. A video
call, however convincing, is not an independent finance-officer sign-off — it is exactly the
kind of trust cue that real-time deepfake technology is built to exploit, matching the
mechanism of the real-world Arup fraud, where a live deepfake video call overrode an employee's
correct initial suspicion of the preceding email. The control failure here is not that
p.kapadia was deceived — deception is the premise of social engineering — it is that no
independent second person ever verified the transfer through a channel separate from the
(compromised) video call itself.

---

## Step 3: Correlate Y-001 and Y-002

**Finding:** Y-001 and Y-002 form one incident: the phishing email set up the pretext and
promised a "confirmation" video call, and 4 hours later that same recipient authorized $2.1M in
transfers on the basis of exactly that call — bypassing the one control specifically designed to
catch this scenario. Even though the email itself was correctly flagged and not directly acted
upon, the attack succeeded through the second stage (the call) that the email was setting up.

---

## Step 4: Y-003 — Check Against Documented Process

| Field | Value |
|---|---|
| Approver | r.malhotra, AP Manager — appropriate role |
| Vendor | Established, 7-year relationship |
| Documentation | Tied to PO#88213 |
| Control compliance | Full dual-approval per FIN-POL-12 (both r.malhotra and finance director) |

**Finding:** 🟢 Every element of Y-003 is the inverse of Y-002: known vendor, purchase order on
file, and full compliance with the dual-approval policy that Y-002 bypassed. Direct contrast
case confirming the control (not the payment amount alone) is what distinguishes legitimate
from fraudulent activity here.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| Y-001 authentication/pretext | Failed SPF/DKIM/DMARC, lookalike domain, Arup-style pretext | 🔴 High |
| Y-002 payee legitimacy | New accounts, same-day addition, no vendor history | 🔴 Critical |
| Y-002 control bypass | Dual-approval (FIN-POL-12) replaced by a single video call | 🔴 Critical |
| Y-003 vs. documented process | Full dual-approval compliance, known vendor, PO on file | 🟢 None |
| Correlation Y-001/Y-002 | Same recipient, 4-hour gap, direct causal setup | 🔴 High — one incident |
