# Case_021 — Verdict

**Verdict:** ✅ True Positive (TP)

**MITRE ATT&CK:** T1078 — Valid Accounts (Initial Access)

## Justification

Successful sign-in using a legacy authentication protocol (IMAP4) that bypassed Conditional
Access and MFA, originating from an IP address independently flagged as risky by Microsoft
Threat Intelligence, from a location (Lagos, Nigeria) never seen in the user's 30-day baseline
(95% Ahmedabad / 5% Mumbai), on a device that is neither registered nor compliant.

Each individual factor could theoretically have an innocent explanation in isolation, but the
combination — legacy-auth MFA bypass + risky IP + geography anomaly + non-compliant device,
all resulting in a **successful** authentication — is a textbook Business Email Compromise (BEC)
initial-access pattern. Success on a risky, deviating sign-in is not evidence of legitimacy;
it's evidence the attacker got past the front door.

## What would change the verdict

- Confirmed employee travel record placing the user in Nigeria at the time
- Known corporate VPN egress point in Lagos used by other employees
- Admin-flagged penetration test / red team activity for this account
- IP later found to be a shared NAT/mobile carrier range with no other risk signals

## Response actions

1. Disable the compromised account immediately (block sign-in).
2. Force password reset + revoke all active sessions/refresh tokens.
3. Disable legacy authentication (IMAP4/POP3/SMTP AUTH) for this user, ideally tenant-wide.
4. Review mailbox for inbox rules, forwarding rules, or sent items indicating BEC follow-through.
5. Notify user directly (out-of-band, not via email) to confirm this wasn't them.
6. Escalate to L2/IR if mailbox shows signs of forwarding rule creation or lateral BEC activity.

## Triage time

Not tracked.

## Notes

Ticket-only investigation — no Splunk verification performed for this case (analyst decision).
Corrections during investigation: 0.
