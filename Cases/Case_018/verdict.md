# Verdict — Case 018 (Phase 3: Rapid-Response Judgment)

## Final Verdicts

| Alert | Verdict | MITRE ATT&CK |
|---|---|---|
| **Alert AG** — Reverse-Shell Socket Code | 🔴 **TP** | T1059.001, T1071 |
| **Alert AJ** — Audit Policy Subcategory Disabled | 🔴 **TP** | T1562 |
| **Alert AH** — Chrome Extension Install | 🟢 **FP** | — |
| **Alert AI** — BitLocker Recovery Key Accessed | 🟡 **Ambiguous** | — |

---

## Justification Summary

**Alert AG (TP):** Definitional reverse-shell/C2 socket code — raw TCP connection to a specific external IP:port (194.31.98.14:4444) with continuous data reading, hidden window flag. No legitimate use case exists for this pattern.

**Alert AJ (TP):** Disabling audit policy subcategory forcing reduces future logging granularity host-wide, with no legitimate everyday justification for a standard user — decisive on command content alone, consistent with the standard applied to Case_011's Defender-disable and Case_013's ScriptBlock-logging-disable.

**Alert AH (FP):** Official Chrome Web Store source, common extension category, zero aggravating factors — clean, positive-evidence-supported FP.

**Alert AI (Ambiguous):** BitLocker recovery key access is genuinely sensitive and dual-use — the access method (Control Panel) and unremarkable timing do not constitute positive evidence of legitimate intent, only the absence of an obvious red flag. No baseline or corroborating context resolves the tie.

---

## Prioritization Review

**Chosen order:** AG → AJ → AH → AI

**Assessment:** Correctly prioritized the active C2 connection (AG) and defense-evasion action (AJ) ahead of the lower-immediate-impact browser extension (AH) and access-sensitive-but-unconfirmed BitLocker event (AI). Sound reasoning based on active-harm urgency.

---

## Methodology Note: Rapid-Response Format

This case intentionally omitted live command reproduction and Splunk verification to test first-instinct judgment under conditions closer to real-time queue pressure, where full evidence-gathering is not always possible before an initial call must be made. Two of the four alerts (AJ, AI) required correction during the write-up phase — both stemming from applying "no obvious red flag" reasoning as though it were equivalent to positive proof of safety, a recurring pattern across this repo's more ambiguous-leaning cases (see Case_015's Alert V, Case_016's Alert AB). This reinforces that the gap between slow, evidence-verified triage and fast, ticket-only judgment remains the primary area for continued practice.

---

## What Would Change Each Verdict

**Alert AG → FP if:** Confirmed as an authorized penetration-testing/red-team exercise with a documented engagement record — not supported by available ticket data.

**Alert AJ → FP if:** Confirmed as part of an authorized security-hardening or Group Policy rollback with a documented change record — not supported here.

**Alert AH → TP if:** The extension were later found to request excessive permissions inconsistent with its stated function, or sideloaded from an unofficial source.

**Alert AI → TP if:** Followed by BitLocker being disabled or the drive being accessed through an unusual method (e.g., booting from external media).
**Alert AI → FP if:** Correlated with a documented IT support ticket or a known device lockout event for this user.

---

## Recommended Response Actions

- **Alert AG:** Isolate host immediately; block outbound to 194.31.98.14; treat as active compromise; escalate to L2/IR team without delay.
- **Alert AJ:** Restore the audit policy setting; investigate what activity may have occurred or been under-logged during the disabled window; escalate to L2.
- **Alert AH:** No action required; close as FP.
- **Alert AI:** Follow up with the account owner or IT helpdesk to confirm the reason for key access; hold at Ambiguous pending that confirmation.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Batch Size | 4 alerts |
| Format | Rapid-response (ticket-only, no Splunk verification) |
| Total Triage Time | 5 minutes (9:39 AM – 9:44 AM, all 4 alerts combined) |
| Correct Prioritization | Yes |
| Corrections Needed | 2 of 4 (AJ, AI) — both resolved during write-up review |
| Escalated | AG (Yes, immediate), AJ (Yes) |
| Held for Follow-up | AI |
| Closed, No Action | AH |
