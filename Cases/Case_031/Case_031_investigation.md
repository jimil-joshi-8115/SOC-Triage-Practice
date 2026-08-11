# Investigation — Case 031

**Verification method:** Ticket-only — no Splunk query run (analyst decision)

---

## Step 1: K-001 — Trace the AssumeRole Chain

| Step | Role assumed | Authorized by direct user policy? |
|---|---|---|
| 1 | aurora-readonly-analyst | Yes — matches j.mehra's documented job function |
| 2 (40 sec later) | aurora-prod-admin | **No** — j.mehra's user policy has no direct sts:AssumeRole permission for this role |

**Finding:** 🔴 Step 2 was only possible because the intermediate role
(`aurora-readonly-analyst`) itself had a trust policy allowing it to assume
`aurora-prod-admin` — a misconfiguration. This is the defining characteristic of role
chaining as an escalation technique: the final privileged action is never directly
authorized for the original identity. A review of j.mehra's own IAM policy alone would show
nothing wrong; the vulnerability only becomes visible when tracing the full assume-role
chain, which is why this pattern is specifically dangerous and commonly missed in routine
access reviews.

---

## Step 2: K-002 — Check the Action Taken With the Escalated Session

| Field | Value |
|---|---|
| Session used | assumed-role/aurora-prod-admin/j.mehra (from K-001) |
| Action | AuthorizeSecurityGroupIngress |
| Rule added | 0.0.0.0/0 → port 3389 (RDP) |
| Target | aurora-prod-db-sg (attached to production database instances) |
| Timing | 76 seconds after the escalation completed |

**Finding:** 🔴 The illegitimately-obtained admin session was used almost immediately to expose
RDP access to the entire internet on the security group protecting production databases. There
is no legitimate operational reason to open RDP to `0.0.0.0/0` on a database-tier security
group under any circumstance — this is either a serious misconfiguration/mistake by a junior
engineer who should never have had this access, or deliberate malicious action; either way, the
resulting exposure is a critical, active risk to production data regardless of intent.

---

## Step 3: Correlate K-001 and K-002

**Finding:** Direct causal chain — the security group modification in K-002 was only possible
because of the unauthorized privilege escalation in K-001, executed by the exact same session
76 seconds later. This is one incident, not two independent findings: an escalation path being
discovered/used, immediately followed by that elevated access being used to create a critical
production exposure.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| K-001 chain authorization | Final role not directly authorized for j.mehra's user identity | 🔴 High |
| K-001 root cause | Misconfigured trust policy on intermediate role | 🔴 High |
| K-002 action taken | RDP opened to entire internet on prod DB security group | 🔴 Critical |
| K-002 timing | 76 seconds after escalation, same session | 🔴 High |
| Correlation | Single causal chain, K-001 enables K-002 | 🔴 High — one incident |
