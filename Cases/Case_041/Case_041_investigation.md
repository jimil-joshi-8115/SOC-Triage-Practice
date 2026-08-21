# Investigation — Case 041

**Verification method:** Ticket-only — no Splunk query run (analyst decision)

---

## Step 1: U-001 — Assess in Isolation (as it would have appeared at the time)

| Field | Value |
|---|---|
| Delivery | Vendor's official update server, scheduled update window |
| Code signature | Valid, matches vendor's legitimate certificate |
| Hash reputation | No match against any known-malicious hash database |

**Finding:** 🟡 On its own, at the moment it occurred, this alert presents no available
indicator of compromise — a validly-signed update from the vendor's official channel, with no
malicious hash match. An analyst reviewing only this alert at the time it fired would have no
concrete basis to call it TP; this is precisely what made the real-world supply chain attack
this scenario is grounded in evade detection for months. Verdict on this alert alone is
therefore not resolvable in isolation — see Step 2.

---

## Step 2: U-002 — Check the Beaconing Pattern and Timing Relative to U-001

| Field | Value |
|---|---|
| Pattern | Randomized subdomains of a single parent domain, irregular intervals |
| Domain history | Registered 11 months ago, no legitimate business relationship found |
| Documented feature | None — monitoring platform has no legitimate function requiring this |
| Timing relative to U-001 | Exactly 14 days later |

**Finding:** 🔴 The domain generation algorithm pattern (randomized subdomains, irregular
intervals) combined with a domain that has no legitimate connection to the organization is a
classic C2 beaconing signature. The 14-day gap from U-001 is the critical detail: this matches
the documented dormancy period of the real-world malware this scenario is grounded in, which
delayed its first beacon specifically to separate the malicious update from any suspicious
activity in a defender's timeline.

---

## Step 3: Retroactively Re-Assess U-001 in Light of U-002

**Finding:** 🔴 U-002 confirms AURORA-MON01 is compromised, and the only new software introduced
to that host in the recent past is the U-001 update. A valid signature and clean hash reputation
describe how the update *evaded* detection — they do not rule out that the update itself was the
delivery mechanism. This is a case where a later alert (U-002) retroactively establishes the
verdict on an earlier one (U-001), rather than simply adding supporting weight to an
already-suspicious event. U-001 is re-classified as TP based on this correlation.

---

## Step 4: U-003 — Check Against Documented Schedule

| Field | Value |
|---|---|
| Action | Automatic Defender definition update |
| Schedule | Matches standard daily update pattern |
| Signature | Signed Microsoft update package |
| Timing relative to U-002 | 3 hours prior |

**Finding:** 🟢 Despite occurring on the same host shortly before the beaconing began, this is a
fully routine, scheduled, signed action from an entirely different vendor (Microsoft, not the
monitoring platform vendor), with no functional relationship to the compromise. Proximity in
time to a confirmed incident does not establish correlation without a supporting mechanism —
same principle applied in Case_035 (O-003) and Case_040 (T-004).

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| U-001 in isolation | Valid signature, clean hash — no indicator at the time | 🟡 Unresolvable alone |
| U-002 beaconing pattern | DGA-consistent, unrelated domain, no legitimate feature | 🔴 Critical |
| U-002 timing vs. U-001 | Exactly 14 days — matches known dormancy evasion pattern | 🔴 High correlation |
| U-001 re-assessed | Confirmed as the delivery vector via U-002 correlation | 🔴 High — TP |
| U-003 vs. documented schedule | Routine, different vendor, no functional link to compromise | 🟢 None |
