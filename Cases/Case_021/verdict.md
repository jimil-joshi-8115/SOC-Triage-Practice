# Case_022 — Verdict

## BC-001: ❌ False Positive (FP)

User self-reported a suspicious mailbox-storage phishing email via the Report Message add-in.
No click, no credential entry. Sender IP for the reporting action itself is the user's normal
Ahmedabad baseline — no compromise indicator. Awareness process functioned correctly.

## BC-002: ✅ True Positive (TP)

**MITRE ATT&CK:** T1078 (Valid Accounts), T1114.003 (Email Forwarding Rule)

Impossible travel (Ahmedabad → Warsaw, 27 minutes, ~5,900 km) combined with a legacy-auth
(IMAP4) sign-in that bypassed MFA and Conditional Access, followed immediately by a malicious
inbox rule that hides financially-themed emails and forwards them to an external address while
suppressing further rule processing. No legitimate business justification exists for this rule's
configuration — this is account takeover with active concealment tradecraft.

## BC-003: ✅ True Positive (TP)

**MITRE ATT&CK:** T1114 (Email Collection), Business Email Compromise / Vendor Email
Compromise (VEC) pattern

14 fraudulent "updated bank details" emails sent from the same Warsaw session confirmed
compromised in BC-002, targeting a real vendor's finance/AP/billing contacts within 6 minutes.
Direct continuation of the BC-002 chain, not an independent alert — the fraud payload itself.

## Correlation Summary

BC-001 is an isolated, correctly-handled user report — no link to the other two.
BC-002 and BC-003 form one continuous BEC incident: legacy-auth account takeover →
concealment via malicious inbox rule → fraudulent payment-redirection emails to a vendor,
all within a ~12-minute attacker session.

## What would change the verdict

- BC-002: confirmed employee travel to Warsaw at the time, or known corporate VPN egress there
- BC-003: confirmation from the vendor that the "updated bank details" were legitimate and
  pre-arranged through a verified out-of-band channel

## Response actions

1. Disable k.desai's account immediately; force password reset; revoke all sessions/tokens.
2. Delete the malicious inbox rule.
3. Disable legacy authentication (IMAP4/POP3/SMTP AUTH) tenant-wide if not already planned.
4. **Urgent:** contact vendorpartner-inc.com out-of-band to flag the fraudulent bank-detail
   emails before any payment is processed against them — this is time-critical financial fraud.
5. Review mailbox for further rules, sent items, or additional exfil since account compromise.
6. Escalate to L2/IR and Finance/AP teams immediately given the active fraud attempt.

## Triage time

Start: 09:19 UTC | End: ~09:56 UTC (real, tracked)

## Notes

Splunk-verified using sample O365 Unified Audit Log data (CSV ingestion). Corrections during
investigation: 0.
