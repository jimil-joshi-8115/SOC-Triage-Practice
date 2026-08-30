# Known-Legitimate Service, Network, and Cloud-Config Actions vs. Confirmed-Malicious Patterns

Distilled from confirmed verdicts across this repo — routine vs. security-critical service and
configuration actions, plus firewall/network-direction and cloud-mechanism logic.

---

## Routine vs. Security-Critical Service/Policy Actions

**Principle:** The *type* of service or policy being touched matters more than the action verb
alone. "Stop a service," "modify a policy," or "change a setting" look identical on the surface
regardless of target — the target's function determines severity.

| Action Type | Routine Example | Security-Critical Example |
|---|---|---|
| Stop/disable a service | Windows Update, print spooler | Windows Defender, audit logging (Case_019) |
| Modify a policy | GPO password complexity refresh (Case_024, H-004) | Conditional Access trusted-location exemption (Case_042) |
| Change a config value | Marketing app setting | S3 bucket ACL private→public (Case_027, G-002) |

**Source case:** Case_019 (service-type distinction), Case_024, Case_027, Case_042.
**Check:** Always ask "what does this specific service/policy control?" before judging severity
from the action verb alone.

---

## Firewall/Network Rule Direction and Scope

**Principle:** Direction (inbound vs. outbound) and scope (specific subnet vs. `0.0.0.0/0`)
determine severity more than the mere existence of a new rule.

- **Legitimate pattern:** A new rule scoped to a specific internal subnet, tied to a documented
  microservice/deployment need (Case_031's contrast, Case_044's X-003).
- **Malicious pattern:** A rule opening a sensitive port to the entire internet (`0.0.0.0/0`),
  especially on a security group protecting production data (Case_031, K-002).

**Source cases:** Case_017 (original firewall-direction lesson), Case_031, Case_044.

---

## Blocked/Rejected Connection Attempts vs. Successful Access

**Principle:** An attempted connection that is rejected by a correctly-configured control is
fundamentally different from one that succeeds — even from the same class of source.

**Source cases:** Case_016 (original "routine events with zero aggravating factors = FP" rule),
Case_039 (S-003 — blocked scan from an attributed benign source, contrasted against S-001/S-002's
confirmed successful compromise).
**Check:** Confirm explicitly whether the access attempt succeeded or was blocked before judging
severity — don't let source-IP reputation alone drive the verdict if the control worked.

---

## Success ≠ Safety (Identity/Access Logs)

**Principle:** A "Success" result field in a sign-in or access log does not mean the access was
legitimate — it means the security control (MFA, Conditional Access, authentication) was
satisfied or bypassed. Success on an anomalous access attempt is the alarm, not the all-clear.

**Source cases:** Case_018 (original lesson), Case_021, Case_023, Case_033, Case_034.

---

## Mechanism-Neutral Verdicts (Cloud Features Weaponized, Not Exploited)

**Principle:** Some of the most severe cloud incidents in this repo involved attackers using
**legitimate, correctly-functioning cloud features** (SSE-C encryption, SAS tokens, OAuth app
registration, IAM role chaining) against their intended purpose — not a technical exploit or
vulnerability. The mechanism itself is never inherently malicious; configuration, actor
legitimacy, and documentation determine the verdict.

**Source cases:** Case_031 (role chaining), Case_038 (SAS tokens — R-001 vs. R-003 direct
contrast), Case_042 (trusted locations — W-001 vs. W-003 direct contrast), Case_043 (SSE-C
ransomware — the encryption itself is "correct" AWS behavior).
**Check:** When evaluating a cloud-native alert, ask "is this mechanism being used outside its
documented scope/actor/permission level?" rather than "is this mechanism inherently dangerous?"
