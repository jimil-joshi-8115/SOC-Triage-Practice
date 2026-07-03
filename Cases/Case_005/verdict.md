# Verdict — Case 005

## 🔴 Verdict: TRUE POSITIVE

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Brute Force | T1110 | 5 rapid failed logon attempts against a single known account |

---

## Justification

1. **Pattern matches standard brute-force detection logic** — 5 failed logons against the same account within a ~13 second window is a textbook match for T1110, both in volume and timing.
2. **Verdict is based on the attempted behavior, not the outcome** — no successful compromise followed the failures, but that does not make this FP. A failed brute-force attempt is still a genuine hostile action worth logging and escalating; treating "unsuccessful" as "harmless" would be an incorrect triage shortcut.
3. **"Unknown user name or bad password" was correctly reinterpreted during investigation** — this generic Windows message does not confirm the username was invalid. `hp` is a valid, existing account on this host; the failures reflect incorrect passwords against a real account, which is arguably a stronger signal than random username guessing.
4. **No account lockout (4740) triggered after 5 failures** — this is a secondary but important finding: it suggests no lockout threshold policy is enforced on this host, meaning an attacker could continue unlimited attempts without being automatically blocked.

**Triage lesson reinforced:** an unsuccessful attack attempt is still a TP if the *behavior* matches a known attack pattern — "it didn't work" is not the same as "it wasn't malicious."

---

## What Would Change This Verdict

**→ Would increase severity (still TP, but higher priority) if:**
- A successful logon (4624) for `hp` occurred immediately after the failed attempts — would indicate the brute-force succeeded
- The failed attempts came from a different source IP/remote logon type (Type 3/10) rather than local interactive (Type 2) — would indicate remote attack rather than local

**→ Would become FP if:**
- The analyst (you) confirms this was a known, intentional self-test with no security relevance — which is the case in this lab context, but is being triaged as if genuinely unknown, per the exercise's design

---

## Recommended Response Actions

- Review whether an account lockout policy should be enabled on this host (currently absent — 5 failures did not trigger 4740)
- If this were a monitored production host, correlate source IP/session for the failed attempts to determine if local (physical access) or remote
- Consider alerting threshold tuning: 5 failures in 13 seconds is a strong signal; confirm this maps to an active correlation rule (per SOC-Lab-Splunk Lab 15/16 alerting work)
- No further action needed for this specific instance since no compromise occurred — but log the lockout-policy gap as a separate finding for host hardening

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdict | TP |
| Confidence | High |
| Triage Time | 4 minutes (8:14 AM – 8:18 AM) |
| Escalated | Yes (would be, in real SOC) |
| Detection Gap Identified | No account lockout policy enforced after repeated failures |
