# Verdict — Case 045

## Y-001: 🔴 Verdict: TRUE POSITIVE
## Y-002: 🔴 Verdict: TRUE POSITIVE (Critical)
## Y-003: 🟢 Verdict: FALSE POSITIVE

**Y-001 and Y-002 are TP as a single correlated incident. Y-003 is unrelated and confirms
proper control compliance by contrast.**

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Phishing: Spearphishing Link | T1566.001 (adjacent — no link, but same technique family) | Spoofed-domain email impersonating the CFO with a confidentiality/urgency pretext (Y-001) |
| Masquerading | T1036 | Impersonation of the CFO and control bypass via a video call (Y-002, per real-world grounding) |
| Financial Theft | T1657 | $2.1M authorized to newly-added, unverified external accounts (Y-002) |

---

## Justification

### Y-001 — TP
Failed SPF/DKIM/DMARC on a deliberate lookalike domain, combined with an urgency-plus-secrecy
pretext promising a follow-up "confirmation" video call — the same setup used in the real-world
Arup fraud this scenario is grounded in. This is TP as a phishing/pretexting attempt regardless
of the fact that the recipient correctly did not act on the email directly.

### Y-002 — TP, Critical
$2.1M authorized to 4 newly-added external accounts, added the same day, in a jurisdiction with
no prior vendor relationship, on the basis of a single video call rather than the mandatory
dual-approval process required by policy FIN-POL-12 for transfers over $50K. The specific
control failure is segregation of duties: a video call — however convincing — was substituted
for an independent second finance officer's sign-off. This is exactly the mechanism the real
Arup fraud exploited: a live, convincing video call overriding an employee's own correct initial
suspicion, with no independent verification channel outside that call ever consulted.

**Correlation:** Y-001 and Y-002 are one incident — the email set up the pretext and promised
the call; 4 hours later, that call (or claimed call) became the sole basis for a large,
control-bypassing transfer to unverified accounts.

### Y-003 — FP
Full compliance with FIN-POL-12's dual-approval requirement, an established 7-year vendor
relationship, and a purchase order on file. Serves as a direct contrast to Y-002: the same
class of action (a large financial authorization) is either a severe control failure or standard
practice depending entirely on whether the required independent verification actually occurred.

---

## What Would Change These Verdicts

- **Y-001 → FP:** confirmation the domain is a legitimately-owned secondary Aurora domain
  (unlikely given the explicit CFO-impersonation framing and failed authentication).
- **Y-002 → FP:** documented evidence that a second finance officer independently verified the
  transfer through a channel separate from the video call itself (e.g., a callback to a known,
  pre-verified phone number) — no such evidence is present in this ticket.
- **Y-003 → TP:** if PO#88213 could not be verified as legitimate, or if the vendor relationship
  claim proved false.

None of these apply in this ticket — verdicts stand as TP / TP / FP.

---

## Recommended Response Actions

1. **Immediately attempt to halt/recall the 4 wire transfers** through the receiving banks —
   time-critical, as recovery odds drop sharply the longer funds sit in the destination
   accounts.
2. Freeze the newly-added payee accounts within the finance system pending investigation.
3. Contact p.kapadia directly and the purported "CFO office" through a separate, independently
   verified channel (not the video call platform or any contact info from the Y-001 email) to
   confirm whether any legitimate acquisition-related directive exists — expect it does not.
4. Report to law enforcement and initiate the organization's fraud/incident response process
   immediately, given the time-sensitivity of wire fraud recovery.
5. Review whether video/voice verification of this kind has been used to authorize any other
   recent transfers — assume this technique may have been attempted elsewhere.
6. **Close the control gap**: reinforce that video/voice calls, regardless of how convincing,
   cannot substitute for FIN-POL-12's required independent second-officer approval; consider
   requiring callback verification to a pre-registered number for any high-value transfer
   request received via video call or email.
7. Provide targeted awareness training on AI-assisted deepfake fraud to finance staff,
   referencing this pattern specifically.
8. Escalate to L2/IR and executive leadership immediately.
9. No action needed on Y-003 beyond standard closure.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | Y-001: TP · Y-002: TP (Critical) · Y-003: FP |
| Confidence | High (all three) |
| Verification method | Ticket-only — no Splunk query run (analyst decision) |
| Triage Time | 4 minutes (real, tracked) |
| Escalated | Yes — Y-001/Y-002 (would be, in real SOC, as active financial fraud) |
| Corrections during investigation | 0 |
| Scenario basis | Adapted from the January 2024 Arup deepfake fraud (~$25.6M lost via AI-generated video/voice impersonation of the CFO and colleagues); IOCs and identities fully sanitized/fictional |
