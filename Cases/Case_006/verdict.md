# Verdict — Case 006

## 🔴 Verdict: TRUE POSITIVE

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Password Spraying | T1110.003 | Failed logon attempts against 3 distinct, non-baseline accounts within a ~35 second window |

---

## Justification

1. **Pattern matches password spraying, not simple brute-force** — unlike Case_005 (single account, repeated attempts), this case shows 3 different account names (`admin`, `administrator`, `support`) attempted in rapid succession. This is a distinct, well-documented technique (T1110.003) used to probe for valid/default accounts while often avoiding single-account lockout thresholds.
2. **None of the targeted accounts exist in the documented legitimate accounts baseline** — only `hp` is a real, known account on this host. Targeting generic/default admin-style names is a strong indicator of external or opportunistic probing rather than legitimate user error.
3. **Timing (~35 seconds across 3 accounts)** is not consistent with normal user behavior — no legitimate user attempts to log in as `admin`, `administrator`, and `support` in succession.

**Escalation note:** This is a confirmed TP that should be escalated to L2 for further correlation (e.g. source of the attempts, whether this is part of a broader campaign). Escalation is a *response action*, not a reason to downgrade the verdict — a TP remains TP whether or not it requires further handling. Ambiguous is reserved for cases where the evidence itself cannot distinguish malicious from benign intent (see Case_003); that is not the situation here.

---

## What Would Change This Verdict

**→ Would become FP if:**
- The analyst confirms these were intentional, authorized penetration-testing/red-team activities with a documented change record — not the case in this lab context, but the general condition that would apply in a real environment.

**→ Would increase severity if:**
- A successful logon (4624) followed any of these 3 attempts
- The same pattern repeated across multiple hosts (indicating a broader, coordinated spray campaign rather than an isolated single-host event)

---

## Recommended Response Actions

- Escalate to L2 for correlation across other hosts/logs (check if the same account names were targeted elsewhere in the environment)
- Confirm no successful logon occurred for any of the 3 targeted accounts
- Consider adding a detection rule specifically for "3+ distinct non-existent accounts attempted within 60 seconds" as a password-spray indicator, separate from the existing single-account brute-force rule from Case_005/SOC-Lab-Splunk Lab 15
- Review whether external-facing services (RDP, VPN, etc.) are exposed, since password spraying is commonly used against internet-facing logon points

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdict | TP |
| Confidence | High |
| Triage Time | 4 minutes (8:26 AM – 8:30 AM) |
| Escalated | Yes |
| Detection Gap Identified | None |
