# Investigation — Case 048 (Bonus Final Exam, Stage 1)

**Verification method:** Ticket-only — no Splunk query run (analyst decision)

---

## Step 1: Separate the Queue by Actor Before Assuming Correlation

| Alert | Account/Actor | Host |
|---|---|---|
| CC-001 | s.mehta | Okta (cloud identity) |
| CC-002 | s.mehta / backup-svc-2 (created) | AWS |
| CC-003 | t.oconnor | MFL-WKS0287 |
| CC-004 | r.bhagat | Okta (cloud identity) |
| CC-005 | s.mehta / backup-svc-2 | AWS |
| CC-006 | backup-svc-2 | AWS |

**Finding:** Three distinct actor groups exist in this queue, not one chain: (1) s.mehta and
the backup-svc-2 identity they created — CC-001, CC-002, CC-005, CC-006; (2) t.oconnor — CC-003
alone; (3) r.bhagat — CC-004 alone. Verifying this upfront prevents forcing an inaccurate
"1→2→3→4" narrative onto alerts that don't actually share an actor.

---

## Step 2: CC-001 — Check the Impossible Travel Pattern

**Finding:** 🔴 45-minute gap between Ahmedabad and Warsaw sign-ins is physically impossible.
MFA being satisfied both times does not indicate legitimacy — consistent with the repeated
"success ≠ safety" lesson established since Case_021.

---

## Step 3: CC-002 — Check Role Justification

**Finding:** 🔴 s.mehta (Marketing Analytics) creating an IAM user with full
AdministratorAccess, 7 minutes after the impossible-travel sign-in, with no documented AWS
admin function or change ticket, confirms the account is being used for privilege escalation
immediately following the anomalous access in CC-001.

---

## Step 4: CC-003 — Check as a Standalone Incident

**Finding:** 🔴 Encoded/obfuscated PowerShell download cradle spawned from Outlook (consistent
with a malicious email attachment) is TP on its own content and technique — but this is a
**separate incident** from s.mehta's chain, given the different account, host, and department
with no overlapping indicator.

---

## Step 5: CC-004 — Check Against Baseline, Not Against an Assumed Chain

| Field | Value |
|---|---|
| Account | r.bhagat — no connection to s.mehta or t.oconnor anywhere in this queue |
| Verification | Standard email verification completed |
| Device | Usual device/browser fingerprint |
| Frequency | Matches historical ~90-day reset pattern |

**Finding:** 🟢 **Correction made during investigation:** initially treated as a continuation of
"the chain from 1 to 3," but this account has no actor, host, or timing overlap with either
s.mehta's or t.oconnor's activity. Every detail matches r.bhagat's own established normal
behavior. Corrected to FP after verifying actor identity explicitly rather than assuming
queue-order implies chain continuation — the same discrimination-test pattern used since
Case_025, here made trickier by initially misreading unrelated alerts as sequential just because
they appear in order.

---

## Step 6: CC-005 — Check Continuation of s.mehta's Chain

**Finding:** 🔴 Access key generated for backup-svc-2, same session as CC-002. Direct
continuation — a key is a necessary precursor to programmatic/API-based abuse of the
account, which is exactly what follows in CC-006.

---

## Step 7: CC-006 — Live Interrupt

**Finding:** 🔴 Critical. 12 GPU-optimized instances (g5.48xlarge — high-end GPU instances
typically used for machine learning or, notably, cryptocurrency mining/password-cracking at
scale) launched in a region Aurora has never used, from an external IP, using the CC-005
access key. This confirms the s.mehta/backup-svc-2 chain has progressed to actively provisioning
large-scale compute resources for an unauthorized purpose — likely resource hijacking, given
the specific choice of GPU-heavy instance types rather than general-purpose compute.

**Priority re-evaluation:** the moment CC-006 fires, response priority shifts to immediate
containment (terminate the instances, revoke the access key, disable backup-svc-2) over
continuing to process the remaining queue in order — same live-interrupt discipline established
in Case_025, Case_030, and Case_040.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| CC-001/002/005/006 (s.mehta chain) | Impossible travel → admin account creation → key → GPU instances | 🔴 Critical — one incident |
| CC-003 (t.oconnor) | Encoded PowerShell download from Outlook, separate account | 🔴 High — separate incident |
| CC-004 (r.bhagat) | Matches own established baseline exactly, no chain overlap | 🟢 None — FP |
