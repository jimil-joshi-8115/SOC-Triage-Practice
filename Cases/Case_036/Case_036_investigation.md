# Investigation — Case 036

**Verification method:** Ticket-only — no Splunk query run (analyst decision)

---

## Step 1: P-001 — Check Prior Status vs. Current Context

| Field | Value |
|---|---|
| Finding | Unauthenticated Kubernetes Dashboard, internet-reachable |
| Prior status | Flagged 3 weeks ago, ticketed as #INFRA-2290, no exploitation evidence then |
| Current context | See P-002 |

**Finding:** 🔴 On its own 3 weeks ago, this was a known, tracked configuration issue with no
evidence of active exploitation — a legitimate case for scheduled remediation rather than
urgent escalation. However, this alert cannot be assessed in isolation from what happens 14
minutes later (P-002). A pre-existing, already-ticketed vulnerability becomes an active,
urgent incident the moment it is confirmed being exploited — the ticket status describes the
remediation timeline, not the current risk level once exploitation is underway.

---

## Step 2: P-002 — Check the Deployment Pattern

| Field | Value |
|---|---|
| Deployment method | Dashboard web UI — not the CI/CD pipeline |
| Image source | Unlisted public Docker Hub registry |
| Resource configuration | 0.3 vCPU limit, despite running a compute-intensive process |
| Timing | 14 minutes after the P-001 scan |

**Finding:** 🔴 Three details together confirm active exploitation of the P-001 vulnerability:
deployment through the Dashboard UI directly (bypassing the organization's actual deployment
process entirely), an image pulled from an unlisted source rather than an approved registry, and
a deliberately low CPU limit on a compute-intensive workload — this specific throttling pattern
is a known cryptojacking evasion technique, keeping resource usage low enough to avoid
triggering monitoring alerts, matching the real-world incident this scenario is grounded in.

---

## Step 3: P-003 — Check Against Documented Deployment Process

| Field | Value |
|---|---|
| Actor | ci-deploy-sa — the legitimate CI/CD service account |
| Action | ConfigMap read during deployment |
| Documentation | Tied to deployment ID DEP-44192, a merged pull request |

**Finding:** 🟢 Standard, documented, expected activity — a service account performing exactly
the action it exists to perform, tied to a specific, traceable deployment record. No deviation
present.

---

## Step 4: Correlate P-001 and P-002

**Finding:** P-001 and P-002 are one incident: the exact vulnerability flagged in P-001 was
exploited 14 minutes later via P-002's Dashboard-deployed pod. The re-classification of P-001
from "tracked, scheduled remediation" to "actively exploited, urgent" is driven entirely by this
correlation — without P-002, P-001 alone would remain a valid but non-urgent configuration
finding. P-003 shares no host, namespace, actor, or timing overlap with either and is confirmed
unrelated routine activity.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| P-001 in isolation (3 weeks ago) | Known issue, ticketed, no exploitation evidence | 🟡 Tracked, non-urgent at the time |
| P-001 in current context | Same vulnerability, now confirmed exploited | 🔴 High — re-escalated |
| P-002 deployment method | Bypassed CI/CD, used Dashboard UI directly | 🔴 Critical |
| P-002 resource throttling | Matches known cryptojacking evasion pattern | 🔴 Critical |
| P-003 vs. documented process | Exact match to routine, traceable deployment | 🟢 None |
| Correlation | P-001 exploited by P-002, 14-minute gap | 🔴 High — one incident |
