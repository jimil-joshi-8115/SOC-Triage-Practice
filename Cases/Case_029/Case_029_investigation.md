# Investigation — Case 029

**Verification method:** Ticket-only — rapid-response format, no verification step (same
methodology as Case_018)

---

## Step 1: I-001 — Check the Metadata Service Query Pattern

| Field | Value |
|---|---|
| Target | 169.254.169.254 — AWS instance metadata service |
| Volume | 47 requests in 90 seconds |
| Source | WAF backend logic itself |
| Legitimate use case for WAF rule logic | None |

**Finding:** 🔴 A WAF has no legitimate reason to ever query the instance metadata service —
this endpoint exists to serve instance identity and temporary IAM credentials to the compute
resource itself. A burst of 47 requests to it from within the WAF's own request-handling logic
is the signature of SSRF exploitation: an attacker tricking the WAF into making this request on
their behalf to harvest credentials.

---

## Step 2: I-002 — Check the Credential Usage

| Field | Value |
|---|---|
| Role | aurora-waf-ec2-role |
| Intended purpose | CloudWatch logging only |
| 180-day CloudTrail history | Zero S3 API calls |
| Actions taken | sts:GetCallerIdentity, s3:ListBuckets |
| Source IP | 104.28.19.201 — external, not the instance's normal internal path |

**Finding:** 🔴 Two compounding deviations: the role is being used for an API category
(`s3:*`) it has never touched in 180 days, and the calls originate from an external IP instead
of the instance's expected internal AWS network path. `GetCallerIdentity` immediately followed
by `ListBuckets` is a textbook credential-verification-then-reconnaissance sequence — exactly
what an attacker does immediately after obtaining stolen temporary credentials.

---

## Step 3: I-003 — Check the Enumeration Scope

| Field | Value |
|---|---|
| Actor | Same credentials as I-002 |
| Buckets targeted | 14, including guest PII and payment records |
| Timeframe | 4 minutes |
| Source IP | Same as I-002 |

**Finding:** 🔴 Same actor, same IP, immediate continuation of I-002's reconnaissance —
enumerating objects specifically within buckets containing the most sensitive data categories
(PII, payment records) rather than a broad, undirected scan.

---

## Step 4: I-004 — Check the Download Activity

| Field | Value |
|---|---|
| Actor | Same role/credentials |
| Volume | 3,800+ GetObject calls, 41GB |
| Timeframe | 22 minutes |
| Buckets | The 2 sensitive buckets identified in I-003 |
| Source IP | Same as I-001/I-002/I-003 |

**Finding:** 🔴 This is the exfiltration stage — large-scale, sustained download from precisely
the sensitive buckets identified during enumeration, same attacker session throughout. This
confirms actual data loss, not just unauthorized access.

---

## Step 5: I-005 — Check for Correlation Before Assuming It Belongs to the Chain

| Check | I-001 through I-004 (confirmed chain) | I-005 |
|---|---|---|
| Role/actor | aurora-waf-ec2-role | aurora-billing-readonly-role |
| Source IP | 104.28.19.201 throughout | N/A — automated scan, no access event |
| Trigger type | Live event, active exploitation | Scheduled weekly compliance scan |
| Prior status | New, first-ever activity of this kind | Pre-existing, already tracked (ticket #SEC-4471) |

**Finding:** 🟢 No shared role, IP, or trigger mechanism with the confirmed chain. This is a
routine, already-known, already-ticketed configuration finding surfaced by a scheduled scan —
unrelated to the live incident. Same discrimination pattern as Case_025's E-002 and Case_027's
G-004: presence in the same queue does not imply shared incident membership.

---

## Step 6: Identify the Root Cause

**Finding:** All four confirmed-TP alerts trace back to a single root cause: the WAF's SSRF
vulnerability (exploited in I-001) leaking temporary IAM credentials for an overprivileged
role. Everything downstream (I-002 credential misuse, I-003 enumeration, I-004 exfiltration) is
a direct consequence of that single point of failure — mirroring the real Capital One incident,
where the WAF's excessive IAM permissions turned a single web application vulnerability into a
106-million-record breach.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| I-001 metadata service queries | 47 requests/90 sec, no legitimate WAF use case | 🔴 High |
| I-002 credential misuse | Never-used API category, external IP source | 🔴 High |
| I-003 enumeration scope | 14 buckets, targeting PII/payment data specifically | 🔴 High |
| I-004 download volume | 41GB, 3,800+ calls, same session | 🔴 High |
| I-005 correlation check | Different role/IP/trigger, pre-existing tracked finding | 🟢 None — FP |
| Root cause | Single SSRF vulnerability in the WAF | 🔴 High — one incident |
