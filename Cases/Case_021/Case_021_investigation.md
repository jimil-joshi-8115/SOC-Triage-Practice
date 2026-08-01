# Investigation — Case 021

## Step 1: Separate the Two Correlated Alerts

Incident INC-40217 bundles two Entra ID Protection alerts on the same account within the same
sign-in event. Breaking down each:

| Alert | Signal | Purpose in the chain |
|---|---|---|
| Alert 1 | Sign-in from a risky IP address (41.223.118.52, Lagos, Nigeria) | External threat-intel flag |
| Alert 2 | Legacy authentication protocol used (IMAP4) | Explains *how* MFA/CA were bypassed |

**Finding:** These are not two independent events — Alert 2 is the mechanism that allowed
Alert 1's risky sign-in to succeed. Legacy protocols like IMAP4 are never evaluated by
Conditional Access policy, so MFA enforcement was never even attempted.

---

## Step 2: Check Result Status

`Result: Success` on both alerts.

**Finding:** 🔴 This is the critical field. A successful sign-in here does not mean the system
worked correctly — it means the deviation got through. Treating "Success" as reassuring would
be a mistake; in identity logs, success on an anomalous sign-in is the alarm, not the all-clear.

---

## Step 3: Check Geography Against Baseline

User's last 30-day sign-in geography: Ahmedabad, India (95%), Mumbai, India (5%).
This sign-in: Lagos, Nigeria.

**Finding:** 🔴 First-seen location, no overlap with baseline at all, no travel plausibility
given no prior sign-in anywhere outside India in the lookback window.

---

## Step 4: Check Device State

Device state on this sign-in: Not registered, Not compliant.

**Finding:** 🟠 Contributing factor — consistent with an attacker using their own unmanaged
device rather than the user's actual corporate machine. Not decisive alone, but stacks with
the other findings rather than standing in isolation.

---

## Step 5: Check for Mitigating Context

Reviewed the incident for any of: known VPN egress point, flagged pentest/red-team activity,
recorded employee travel. None present in the ticket.

**Finding:** 🔴 No mitigating explanation available. All four indicators point the same
direction with nothing to counter them.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| Legacy auth / MFA bypass | IMAP4, CA not evaluated, MFA not satisfied | 🔴 High |
| Result status | Success | 🔴 High (success = got through, not safe) |
| Geography vs. baseline | Lagos, Nigeria — 0% baseline match | 🔴 High |
| Device compliance | Not registered, not compliant | 🟠 Contributing factor |
| Mitigating context | None found in ticket | 🔴 High (nothing to counter the above) |
