# Investigation — Case 039

**Verification method:** Ticket-only — no Splunk query run (analyst decision)

---

## Step 1: S-001 — Check the Vulnerability Context and Behavior

| Field | Value |
|---|---|
| Instance | aurora-web-app-03, public-facing |
| Known vulnerability | Outdated Node.js version, unpatched, flagged in prior vuln scan VULN-2291 |
| Behavior observed | DNS rebinding pattern consistent with an IMDS bypass attempt |

**Finding:** 🔴 A public-facing instance with a documented, pre-existing unpatched
vulnerability exhibiting a DNS rebinding pattern aimed at reaching the instance metadata
service is a serious finding — this is a known technique for stealing an instance's IAM
credentials by tricking the application into making a request to the metadata endpoint on the
attacker's behalf.

---

## Step 2: S-002 — Check What Followed on the Same Instance

| Field | Value |
|---|---|
| Instance | Same as S-001 |
| Action | DNS query to a known mining-pool domain, followed by outbound connection on port 3333 |
| Timing | 7 minutes after S-001 |

**Finding:** 🔴 Port 3333 is the standard Stratum mining protocol port, and the destination
domain is independently associated with cryptocurrency mining infrastructure. This is the
direct, confirmed payoff of S-001's metadata-service compromise attempt — credential theft
followed by resource hijacking for cryptomining, matching the exact real-world pattern this
scenario is grounded in.

---

## Step 3: S-003 — Check the Full Detail Before Judging Severity Alone

| Field | Value |
|---|---|
| Instance | aurora-batch-processing-07, internal, not public-facing |
| Source | Known internet-scanning service IP range |
| Outcome | All connection attempts rejected |
| Security group | Explicitly does not allow inbound SSH from any external range |

**Finding:** 🟢 Every detail in this alert, read in full, points to a routine, unsuccessful
scanning attempt against a correctly-configured security control: the source is attributed to
a known non-malicious scanning service, the ticket explicitly characterizes the activity as
routine mass scanning rather than targeted, and — most decisively — the security group config
confirms none of the attempts succeeded. This mirrors the established repo lesson that routine
events with zero aggravating factors should be FP (first established in Case_016), and
contrasts directly with Case_038's R-001/R-002, where activity was confirmed *successful*
rather than blocked.

**Correction note:** initial read of this alert under time pressure moved through TP →
Ambiguous → FP across three passes before settling on FP. This was identified as a fast,
incomplete first read rather than a reasoning error — the deciding details (rejected
connections, attributed source, security-group confirmation) were present in the alert from the
start but were not fully weighed until a slower re-read. Logged per this repo's standing
methodology of recording what happened accurately rather than smoothing it over.

---

## Step 4: Correlate S-001 and S-002; Confirm S-003 Is Unrelated

**Finding:** S-001 and S-002 are the same instance, 7 minutes apart, forming one continuous
incident: metadata-service credential-theft attempt followed by confirmed cryptomining
activity. S-003 involves an entirely different, internal instance, a different actor category
(routine external scanner vs. the S-001/S-002 attacker), and — critically — no successful
access of any kind. No correlation exists between S-003 and the S-001/S-002 incident.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| S-001 vulnerability + behavior | Known unpatched CVE-class issue, metadata rebinding pattern | 🔴 High |
| S-002 confirmed outcome | Mining-pool connection, standard Stratum port | 🔴 Critical |
| S-003 source attribution | Known scanning service, not targeted | 🟢 Mitigating |
| S-003 outcome | All connections rejected, confirmed by security group | 🟢 None — FP |
| Correlation S-001/S-002 | Same instance, 7-minute gap, causal chain | 🔴 High — one incident |
| S-003 vs. S-001/S-002 | Different instance, different actor, no success | No correlation |
