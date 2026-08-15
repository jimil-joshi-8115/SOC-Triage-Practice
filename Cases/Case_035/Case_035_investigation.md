# Investigation — Case 035

**Verification method:** Ticket-only — no Splunk query run (analyst decision)

---

## Step 1: O-001 — Check Volume, Content, and HR Context Together

| Field | Value |
|---|---|
| Volume | 1,847 files in 22 minutes |
| Content | Client contracts, pricing strategy, competitor analysis |
| HR status | Resignation submitted 3 days prior, 11 days remaining |
| Timing | 19:41–20:03 UTC — 2 hours after normal business hours |

**Finding:** 🔴 Every factor points the same direction: high volume, specifically
business-sensitive/competitive content (not personal files), off-hours timing, and a resignation
already on file. This is the textbook profile of pre-departure data theft — an employee with a
known exit date taking company competitive assets to a personal device shortly before leaving.

---

## Step 2: O-002 — Check Content, Ownership, and Volume

| Field | Value |
|---|---|
| Volume | 3 files |
| Content | The employee's own HR-issued performance review documents |
| Destination | Employee's own personal Gmail |
| Timing | 14:22 UTC — during business hours |

**Finding:** 🟡 This does not match O-001's profile. The content is personal to the employee
(their own reviews, not company IP, client data, or pricing information), the volume is small,
and the timing is unremarkable. However, sending any company-originated document to a personal
account is typically a data-handling policy violation regardless of the content's sensitivity
or ownership, and there's no HR/resignation context provided one way or the other for
r.fernandes — unlike O-001, where that context directly supports the verdict. Neither a clean
FP (there is a policy consideration) nor a clear TP (no malicious-intent indicators, no
sensitive company data, no resignation flag) is fully supported by the evidence available.

---

## Step 3: O-003 — Check Access Against Documented Role and Schedule

| Field | Value |
|---|---|
| Share accessed | HR Compensation |
| User's standing access | Documented, tied to backup/DR administrative duties |
| Timing | Within a scheduled maintenance window matching a recurring calendar entry |

**Finding:** 🟢 Every element of this access matches a pre-existing, documented, scheduled,
routine administrative function exactly — standing legitimate access, expected timing, and a
specific named recurring calendar entry accounting for it. No deviation from the documented
baseline is present.

---

## Step 4: Confirm No Correlation Between the Three Alerts

**Finding:** Three different employees, three different departments, three different hosts, no
shared timing window, no shared account or access pattern. These are independent events that
happen to share a queue — consistent with the discrimination-testing structure this repo has
used since Case_025, now applied across three genuinely distinct verdict categories in a single
case rather than one obvious chain plus one obvious noise alert.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| O-001 volume + content + HR context + timing | All factors align toward exfiltration | 🔴 High |
| O-002 content + ownership | Employee's own personal documents, small volume | 🟡 Mitigating |
| O-002 policy consideration | Personal-email transmission still a policy concern | 🟡 Not fully clear either way |
| O-003 access vs. documented role | Exact match to standing, scheduled, documented duty | 🟢 None |
| Cross-alert correlation | Three unrelated employees, no shared indicators | Independent alerts |
