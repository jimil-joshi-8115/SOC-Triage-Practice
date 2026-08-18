# Investigation — Case 038

**Verification method:** Ticket-only — no Splunk query run (analyst decision)

---

## Step 1: R-001 — Check the Token's Scope and Exposure

| Field | Value |
|---|---|
| Location found | Public GitHub repository, hardcoded in JavaScript |
| Permissions | Read+Write+Delete on the entire storage account (all containers) |
| Expiration | ~2 years total validity, ~13 months remaining |
| Committed | 6 days prior to discovery |

**Finding:** 🔴 A token with account-wide Read+Write+Delete permissions and a multi-year
expiration, publicly exposed for 6 days before being caught, is a severe finding regardless of
whether abuse has been confirmed yet — the scope alone (entire account, not one container) is
excessive for what should be a narrowly-scoped client-side token, and the exposure window gives
ample opportunity for discovery by automated scanning tools attackers commonly run against
public repositories.

---

## Step 2: R-002 — Check Actual Usage Against the Token's Legitimate Purpose

| Field | Legitimate baseline (booking widget) | Observed activity |
|---|---|---|
| Operation type | PutBlob only | GetBlob (340) + ListBlobs (210) |
| Container scope | booking-uploads only | 8 different containers |
| Sensitive containers touched | None | customer-invoices, employee-documents |
| Volume | 2-3 operations per booking | 550 operations in 40 minutes |
| Timing | N/A | Immediately following R-001's discovery alert |

**Finding:** 🔴 Every dimension of actual usage contradicts the token's legitimate purpose:
wrong operation type (read/list instead of write), wrong containers (including two containing
sensitive business and personal data), and a volume/timing pattern consistent with an attacker
systematically enumerating and reading everything reachable with the token immediately after
finding it. This confirms active exploitation, not just a theoretical exposure.

---

## Step 3: R-003 — Check Scope, Expiration, and Documentation

| Field | Value |
|---|---|
| Permissions | READ-ONLY |
| Scope | Single container ("marketing-assets") |
| Expiration | 7 days |
| Documentation | Tied to change ticket CHG-9401, named business purpose |

**Finding:** 🟢 Every factor that made R-001 severe is inverted here: minimal permission level
(read-only vs. read+write+delete), narrow scope (one low-sensitivity container vs. the entire
account), short-lived (7 days vs. ~2 years), and fully documented with a specific, traceable
business justification. This is what a properly-scoped SAS token issuance looks like, and it
serves as a useful contrast for understanding exactly why R-001 was dangerous — the technology
is identical, but the configuration and process around it are opposite.

---

## Step 4: Correlate R-001 and R-002

**Finding:** R-002 is the direct, immediate exploitation of the exact exposure identified in
R-001 — same token, activity beginning right after the discovery alert fired (suggesting the
token may have already been under active or recent abuse, or the exposure prompted rapid
opportunistic use once the discovery process itself may have coincided with attacker scanning).
One incident. R-003 shares no token, actor, or resource overlap with either and is confirmed
unrelated, legitimate activity.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| R-001 token scope/exposure | Account-wide R/W/D, ~13 months remaining, 6-day public exposure | 🔴 High |
| R-002 usage vs. legitimate purpose | Wrong operations, wrong containers, high volume | 🔴 Critical |
| R-002 sensitive data touched | customer-invoices, employee-documents | 🔴 Critical |
| R-003 scope/expiration/documentation | Minimal, short-lived, fully documented | 🟢 None |
| Correlation R-001/R-002 | Same token, immediate exploitation | 🔴 High — one incident |
