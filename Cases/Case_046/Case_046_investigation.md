# Investigation — Case 046

**Verification method:** Ticket-only — no Splunk query run (analyst decision)

---

## Step 1: AA-001 — Check the Token's IP History

| Field | Value |
|---|---|
| Token owner | m.desouza, Backend Developer |
| Source IP | 77.83.196.44, Kyiv, Ukraine |
| Prior history | Corporate VPN egress range only, across the token's full 6-month lifetime |

**Finding:** 🔴 A personal access token used exclusively from a corporate VPN range for its
entire lifetime, suddenly authenticating from an unrelated external location, is a strong
indicator of token theft — matching the documented pattern from the real-world incident this
scenario is grounded in.

---

## Step 2: AA-002 — Weigh Timing vs. Access-Scope as Separate-Strength Indicators

| Field | Value |
|---|---|
| Repos cloned | aurora-booking-platform-core, aurora-internal-tools |
| m.desouza's history on core repo | Has commit history — normal scope |
| m.desouza's history on internal-tools | **Never accessed, at any point** |
| Timing | Off-hours, outside documented on-call hours |
| Source IP | Same as AA-001 |

**Finding:** 🔴 Two indicators are present, but they carry different evidentiary weight and
should not be treated as equivalent. Off-hours timing has plausible innocent explanations —
developers do work outside standard hours for legitimate reasons (urgent fixes, cross-timezone
work), making it a soft signal on its own. Access to a repository the token has **never**
touched in its history is a harder signal: it reflects a mismatch in scope of legitimate need
rather than a mismatch in timing, and has no comparably plausible innocent explanation absent a
documented change in role or project assignment (none present here). This is the same
role/access-scope-mismatch pattern established in Case_033 and Case_037 — an actor operating
outside their documented scope of activity is more decisive evidence than timing alone, even
when both point the same direction, as they do here.

**Additional aggravating factor:** the `aurora-booking-platform-core` repository is known to
contain hardcoded staging API keys per an existing, unremediated code-security finding
(#SEC-4180) — meaning this clone may have exposed additional credentials beyond the source code
itself.

---

## Step 3: Correlate AA-001 and AA-002

**Finding:** Same token, same external IP, 2-minute gap — AA-002 is the direct exploitation of
the compromised token identified in AA-001, consistent with the real-world pattern of stolen
developer tokens being used to download private repositories shortly after compromise.

---

## Step 4: AA-003 — Check Against Established Developer Pattern

| Field | Value |
|---|---|
| Actor | k.iyer, Frontend Developer |
| Repo | aurora-web-frontend — matches k.iyer's extensive commit history |
| Source | Corporate VPN, working hours |
| Pattern | Matches a routine ~weekly local-environment refresh |

**Finding:** 🟢 Every dimension — actor's documented scope, source location, timing, and
frequency pattern — matches established, legitimate developer behavior exactly. No deviation.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| AA-001 IP history | First-ever location outside 6-month VPN-only pattern | 🔴 High |
| AA-002 timing | Off-hours — soft signal, plausible innocent explanations exist | 🟠 Contributing factor |
| AA-002 access scope | Repo never before accessed — hard signal, no innocent explanation | 🔴 Critical |
| AA-002 additional exposure | Cloned repo contains known unremediated hardcoded keys | 🔴 High |
| AA-003 vs. established pattern | Full match to documented, routine developer activity | 🟢 None |
| Correlation AA-001/AA-002 | Same token/IP, 2-minute gap | 🔴 High — one incident |
