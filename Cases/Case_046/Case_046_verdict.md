# Verdict — Case 046

## AA-001: 🔴 Verdict: TRUE POSITIVE
## AA-002: 🔴 Verdict: TRUE POSITIVE (Critical)
## AA-003: 🟢 Verdict: FALSE POSITIVE

**AA-001 and AA-002 are TP as a single correlated incident. AA-003 is unrelated.**

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Valid Accounts | T1078 | Stolen personal access token used to authenticate as the legitimate developer (AA-001) |
| Unsecured Credentials | T1552 (adjacent) | Access to a repository containing known unremediated hardcoded credentials (AA-002) |
| Data from Repositories | T1213 (adjacent) | Full clone of private source code repositories, including one outside the actor's normal scope (AA-002) |

---

## Justification

### AA-001 — TP
A personal access token used exclusively from Aurora's corporate VPN range across its entire
6-month lifetime suddenly authenticated from Kyiv, Ukraine — a location with zero prior history.
This matches the documented token-theft indicator pattern from the real-world incident this
scenario is grounded in.

### AA-002 — TP, Critical
Using the same token and IP as AA-001, two private repositories were cloned. Two indicators are
present but carry different evidentiary weight: off-hours timing is a soft signal with
plausible innocent explanations (legitimate late-night or cross-timezone work), while access to
`aurora-internal-tools` — a repository the token has never touched at any point in its history —
is a hard signal with no comparable innocent explanation, absent a documented role or project
change (none present). This mirrors the role/access-scope-mismatch pattern established in
Case_033 and Case_037. Additionally, the co-cloned `aurora-booking-platform-core` repository is
known to contain hardcoded staging API keys per an existing, unremediated finding (#SEC-4180),
meaning this incident may expose credentials beyond the source code itself.

**Correlation:** AA-001 and AA-002 form one incident — the stolen token identified in AA-001 was
used 2 minutes later to clone both repositories, matching the real-world pattern of stolen
developer tokens being exploited shortly after compromise, before detection.

### AA-003 — FP
Every dimension — actor's documented commit history, source location, working-hours timing, and
a recognized weekly refresh pattern — matches established, legitimate developer behavior
exactly. No deviation present.

---

## What Would Change These Verdicts

- **AA-001/AA-002 → FP:** confirmed remote work arrangement placing m.desouza in Ukraine at this
  time, or a documented, approved reason for accessing `aurora-internal-tools` (e.g., a recent,
  undocumented-in-this-ticket project reassignment) — would require explicit verification given
  the severity.
- **AA-003 → TP:** if the clone pattern deviated from k.iyer's established weekly frequency or
  targeted a repository outside their documented scope.

None of these apply in this ticket — verdicts stand as TP / TP / FP.

---

## Recommended Response Actions

1. **Immediately revoke/invalidate m.desouza's compromised personal access token.**
2. Force a credential reset for m.desouza through a verified, out-of-band channel; investigate
   the developer's endpoint for signs of token theft (infostealer malware, phishing).
3. **Audit and rotate any hardcoded staging API keys** in `aurora-booking-platform-core` per the
   existing #SEC-4180 finding — this incident elevates that finding's priority given confirmed
   unauthorized access to the repository containing them.
4. Review what was contained in `aurora-internal-tools` and assess exposure — this repo's
   contents and sensitivity should be evaluated given the token had no legitimate reason to
   access it.
5. Audit all other developer tokens for similar anomalous IP usage or repository-access-scope
   mismatches.
6. Implement IP allowlisting or conditional access for developer tokens where feasible, and
   enforce short-lived tokens with mandatory rotation going forward.
7. Escalate to L2/IR given confirmed unauthorized access to private source code and potential
   credential exposure.
8. No action needed on AA-003 beyond standard closure.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | AA-001: TP · AA-002: TP (Critical) · AA-003: FP |
| Confidence | High (all three) |
| Verification method | Ticket-only — no Splunk query run (analyst decision) |
| Triage Time | 2 minutes (real, tracked) |
| Escalated | Yes — AA-001/AA-002 (would be, in real SOC, as confirmed source-code/credential exposure) |
| Corrections during investigation | 0 |
| Scenario basis | Adapted from the December 2022 Slack GitHub breach; IOCs and identities fully sanitized/fictional |
