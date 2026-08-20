# Investigation — Case 040 (Mid-Phase-5 Checkpoint)

**Verification method:** Ticket-only — no Splunk query run (analyst decision)

---

## Step 1: T-001 — Check for Confirming Evidence

| Field | Value |
|---|---|
| Location | Toronto, Canada — first outside India in 30-day baseline |
| MFA | Satisfied, single approval, no denial pattern |
| Calendar | "Client Site Visit - Toronto," entered 9 days in advance, matching this exact date range |

**Finding:** 🟢 Direct, specific, dated confirming evidence — not just an absence of red flags.
The calendar entry predates the sign-in by over a week and matches the exact location and
timeframe. Same evidentiary shape as Case_026's F-001 and Case_032's contrast case: a positive
confirmation, not merely "nothing looks wrong."

---

## Step 2: T-002 — Check Role Justification and Documentation

| Field | Value |
|---|---|
| Actor | n.bhatt, Junior DevOps Engineer |
| Documented role scope | Single application's CI/CD pipeline only |
| Action | Self-attached AmazonS3FullAccess (account-wide) |
| Change ticket | None found |

**Finding:** 🔴 A junior engineer with a narrowly-scoped, documented role self-granting
account-wide S3 access, with no supporting change ticket, is unauthorized privilege escalation
on its own — the same self-service privilege abuse pattern established in Case_032.

---

## Step 3: T-003 — Check for Confirming Evidence (Same Standard as T-001)

| Field | Value |
|---|---|
| Volume | 40 queries vs. 8-12 baseline |
| Calendar | "Q3 Board Report - Data Pull," documented, same week as the activity |

**Finding:** 🟢 **Correction made during investigation:** initially flagged as Ambiguous based
on the volume deviation alone. On reconsideration, this alert has the same evidentiary
structure as T-001 — a real deviation from baseline, but with a direct, specific, dated
calendar entry confirming the exact activity, not merely an absence of contradicting evidence.
This is distinct from a genuinely ambiguous case like Case_026's F-003, where the *only*
available evidence was a missing calendar entry with nothing confirming the activity either
way. Here, confirming evidence is present. Corrected to FP.

---

## Step 4: T-004 — Check Against Documented Process

| Field | Value |
|---|---|
| Actor | IT-Automation-ServiceAccount |
| Action | App auto-assignment to onboarding group |
| Context | Matches documented automated onboarding workflow, 3 new hires this batch |

**Finding:** 🟢 Fully automated, documented, expected process activity. No deviation.

---

## Step 5: T-005 — Live Interrupt

| Field | Value |
|---|---|
| Actor | n.bhatt, using the T-002 permissions |
| Volume | 2,100+ GetObject calls, 15.6GB |
| Buckets | aurora-guest-pii-archive, aurora-financial-reports |
| Source IP | External, first appearance for this account |
| Timing | ~2 hours 19 minutes after T-002 |

**Finding:** 🔴 Critical. This confirms T-002's unauthorized privilege escalation was not a
dormant/unused grant — it is being actively exploited to exfiltrate guest PII and financial
data to an external location. This is the direct, confirmed payoff of T-002.

**Priority re-evaluation triggered by T-005:** the moment this alert fires, response priority
shifts entirely — containment (revoke n.bhatt's S3FullAccess policy, kill active sessions,
block the external IP) takes precedence over continuing to review the remaining queue in order.
Same live-interrupt discipline established in Case_025 and Case_030.

---

## Step 6: Correlate T-002 and T-005; Confirm T-001/T-003/T-004 Are Unrelated

**Finding:** T-002 and T-005 form one incident — the unauthorized S3FullAccess grant in T-002
was used roughly 2.3 hours later to exfiltrate sensitive data in T-005, same actor throughout.
T-001, T-003, and T-004 are three independent, unrelated, and confirmed-benign events with no
shared account, timing, or resource overlap with the T-002/T-005 incident or each other.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| T-001 confirming evidence | Specific, dated calendar entry matches exactly | 🟢 None — FP |
| T-002 role vs. action | Unauthorized self-escalation, no documentation | 🔴 High |
| T-003 confirming evidence | Specific, dated calendar entry matches exactly | 🟢 None — FP (corrected) |
| T-004 vs. documented process | Exact match to automated onboarding workflow | 🟢 None |
| T-005 live interrupt | Confirmed exfiltration using T-002's access | 🔴 Critical |
| Correlation | T-002→T-005 one incident; T-001/T-003/T-004 independent | 🔴 High for the T-002/T-005 chain |
