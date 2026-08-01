# Case_021 — Investigation

**Analyst:** Jimil Joshi
**Verification method:** Ticket-only — no Splunk query run for this case (analyst decision;
same precedent as Case_018's rapid-response, no-Splunk-verification format).

## Reasoning

Reviewed the Sentinel incident directly, without pulling raw sign-in log data:

1. **Legacy auth protocol (IMAP4)** — this bypasses Conditional Access and MFA entirely.
   It's not just "old tech," it's a known technique used specifically to sidestep modern
   auth controls, because legacy protocols are never evaluated by CA policy.

2. **Geography deviation** — user's 30-day baseline is 95% Ahmedabad, 5% Mumbai. Lagos,
   Nigeria is a first-seen location with no travel plausibility given the tight time window.

3. **Risky IP flagged by Microsoft Threat Intelligence** — external validation, not just an
   internal heuristic.

4. **Device state** — unregistered, non-compliant. Another deviation from the user's normal
   posture (baseline assumed managed corporate device given Ahmedabad-based daily pattern).

5. **Result: Success** — this is the critical point. A successful legacy-auth sign-in from a
   flagged IP, from an unseen location, on a non-compliant device, is not reassuring — success
   here means the attacker got in, not that the system is working correctly.

## Verdict reasoning

All four indicators point the same direction with no mitigating explanation available in the
ticket (no travel record, no known VPN egress, no admin test flagged). Stacked deviations +
external threat intel flag + successful auth = compromise, not noise.
