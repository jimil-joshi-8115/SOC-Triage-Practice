# Investigation — Case 027

**Verification method:** Ticket-only — no Splunk query run (analyst decision, alternating with
Case_026's Splunk-verified format per repo methodology)

---

## Step 1: G-001 — Check the Delivery Chain

| Step | Event |
|---|---|
| 1 | Macro-enabled Word attachment opened |
| 2 | winword.exe spawns cmd.exe (40 sec later) |
| 3 | certutil.exe downloads upd.exe from an external IP |
| 4 | upd.exe executes (8 sec after download) |

**Finding:** 🔴 Complete, unbroken malware delivery chain — malicious document → LOLBin abuse
(certutil used for its documented download-and-execute capability, not its intended
certificate-management purpose) → payload execution. Every link in the chain is present and
explained.

---

## Step 2: G-002 — Check Actor Baseline and Impact

| Field | Value |
|---|---|
| Actor | automation-ci-deploy (CI/CD service account) |
| Prior 120-day history | Routine deployment actions only, zero ACL/policy changes |
| Action taken | PutBucketPolicy: private → public-read |
| Bucket contents | Database backup files (.sql.gz, .bak) |

**Finding:** 🔴 A CI/CD deployment account has no legitimate operational reason to ever modify
bucket ACLs — this is a complete behavioral deviation from its established 120-day baseline.
The impact is immediate and ongoing the moment the policy changes: database backups are
publicly accessible on the internet regardless of whether anyone has accessed them yet. This
was initially discussed as possible Ambiguous, but there is no scenario in which a deploy-only
service account making bucket contents containing database backups public is a defensible or
routine action — the deviation and the impact are both concrete, not speculative.

---

## Step 3: G-003 — Check Technical Indicators vs. Behavioral Outcome

| Indicator | Result |
|---|---|
| SPF | Fail |
| DKIM | Fail |
| DMARC | Fail |
| Sender domain | aurora-resorts.**co** (lookalike of legitimate aurora-resorts.**com**) |
| Attachment/link | None — plain text body only |
| Recipient action | No replies or forwards logged |

**Finding:** 🟡 All three authentication checks failed and the sender domain is a deliberate
one-character lookalike impersonating the CEO, targeting finance with a wire-transfer subject
line — this is the structural pattern of CEO fraud/BEC. **Final analyst call: Ambiguous.**
Reasoning provided: the email carries no attachment and no malicious link or file — it is
text-only — and no recipient interaction (reply/forward) was logged, meaning no follow-through
occurred. This was discussed directly during triage; the technical authentication failures and
domain spoofing point toward TP on their own, and that reasoning is preserved here for the
record, but the analyst's final judgment — weighing the absence of a malicious payload/link and
zero recipient engagement — was Ambiguous. Logged transparently per this repo's methodology of
recording the full reasoning process, including points of disagreement, rather than only the
final answer.

---

## Step 4: G-004 — Check Against Known Baseline

| Field | Value |
|---|---|
| Task name | MicrosoftEdgeUpdateTaskMachineCore |
| Binary | Signed Microsoft executable |
| Run context | SYSTEM |
| Timing | 03:14 UTC — matches standard Edge auto-update schedule for this exact task name |

**Finding:** 🟢 Every field matches a well-documented, legitimate Windows/Edge auto-update
pattern exactly — signed binary, standard task name, expected off-hours timing. No deviation
present.

---

## Step 5: Check for Cross-Alert Correlation

**Finding:** No shared host, account, IP, or timing link found between G-001, G-002, G-003, and
G-004. Different hosts (MFL-WKS0472 vs. MFL-FIN02), different domains entirely (endpoint vs.
AWS vs. email), different users/actors. These are four independent alerts that happen to share
a queue, not a single incident — consistent with the discrimination-testing pattern already
established in Case_025 (E-002).

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| G-001 delivery chain | Complete, unbroken: macro → LOLBin → execution | 🔴 High |
| G-002 actor baseline deviation | Zero prior ACL history, now exposes DB backups publicly | 🔴 High |
| G-003 auth checks | SPF/DKIM/DMARC all fail, lookalike domain | 🔴 High (technical) |
| G-003 payload/engagement | No attachment/link, no recipient interaction | 🟡 Mitigating (per analyst) |
| G-004 baseline match | Signed binary, standard task, expected timing | 🟢 None |
| Cross-alert correlation | No shared host/account/IP found | Independent alerts, not one incident |
