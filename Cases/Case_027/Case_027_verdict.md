# Verdict — Case 027

## G-001: 🔴 Verdict: TRUE POSITIVE
## G-002: 🔴 Verdict: TRUE POSITIVE
## G-003: 🟡 Verdict: AMBIGUOUS (analyst's final judgment call — see note below)
## G-004: 🟢 Verdict: FALSE POSITIVE

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Phishing: Spearphishing Attachment | T1566.001 | Macro-enabled attachment as initial vector (G-001) |
| Ingress Tool Transfer | T1105 | certutil.exe used to download payload (G-001) |
| Cloud Storage Object Discovery / Data from Cloud Storage | T1530 (adjacent) | S3 bucket ACL changed to public, exposing database backups (G-002) |
| — | — | G-003 not mapped — verdict is Ambiguous, not confirmed malicious |

---

## Justification

### G-001 — TP
Complete, unbroken delivery chain: macro-enabled Word attachment → cmd.exe spawned from
winword.exe → certutil.exe abused for its download capability → payload execution within
seconds. Every link in the chain is directly observed, not inferred.

### G-002 — TP
A CI/CD deployment service account with zero prior history of ACL/policy changes across 120
days of activity suddenly makes a bucket containing database backup files public. Both the
behavioral deviation (an account acting entirely outside its established function) and the
impact (backups immediately exposed to the public internet) are concrete and present, not
speculative — this was briefly discussed as possible Ambiguous but confirmed as TP once the
actor's total lack of legitimate reason to touch ACLs was weighed against the immediate,
ongoing exposure risk.

### G-003 — Ambiguous (analyst's final call)
**Technical indicators support TP:** SPF/DKIM/DMARC all failed, the sender domain is a
deliberate lookalike (`aurora-resorts.co` vs. the legitimate `aurora-resorts.com`), and the
email impersonates the CEO while targeting finance with a wire-transfer-authorization subject
line — structurally consistent with CEO fraud/BEC. This reasoning was raised directly during
triage.

**Analyst's final reasoning for Ambiguous:** the email contains no attachment and no
malicious link — plain text body only — and no recipient replied or forwarded the message, so
there was no follow-through or engagement with the email. Weighing the absence of a delivered
payload and zero recipient interaction against the authentication failures, the analyst's
judgment was that this does not rise to a confirmed TP and should be logged as Ambiguous.

**Note on this entry:** this verdict was discussed between analyst and reviewer during triage.
Both positions are preserved here for the record — the technical case for TP (auth failures +
spoofed domain + CEO/finance/wire-transfer targeting) and the analyst's case for Ambiguous
(no payload, no engagement) — consistent with this repo's methodology of logging the full
reasoning process rather than only the final answer.

### G-004 — FP
Every field matches a well-documented, legitimate Windows/Edge auto-update pattern exactly:
signed Microsoft binary, standard task name, expected timing. No deviation present.

---

## Correlation Summary

No shared host, account, IP, or timing link found across G-001 through G-004. Four independent
alerts sharing a queue, not a single incident — consistent with the discrimination-testing
pattern established in Case_025 (E-002).

---

## What Would Change These Verdicts

- **G-001 → FP:** essentially not plausible given the complete, directly-observed chain.
- **G-002 → FP:** a documented, ticketed change request explaining the ACL change as an
  intentional, approved action (unlikely given the account's role and the backup content).
- **G-003 → TP (escalated from Ambiguous):** if any recipient is later found to have replied,
  forwarded, or acted on the request, or if a linked/related email in the same campaign is
  found containing an actual payload.
- **G-003 → FP:** if the domain is found to be a legitimately owned secondary domain used
  intentionally by the organization (unlikely given the explicit CEO-impersonation framing).
- **G-004 → TP:** if the binary were found to be unsigned or the task name/timing deviated from
  the documented Edge update schedule.

---

## Recommended Response Actions

**G-001:**
1. Isolate MFL-WKS0472 from the network immediately.
2. Kill the upd.exe process; collect the binary for analysis.
3. Identify and remove the malicious Word attachment from the mail flow if other recipients
   received it.
4. Escalate to L2/IR.

**G-002:**
1. Immediately revert the S3 bucket ACL to private.
2. Audit CloudTrail for any GetObject calls against the bucket during the public-exposure
   window to determine if the backups were actually accessed.
3. Rotate any credentials/secrets contained in the exposed backup files as a precaution.
4. Review and restrict the `automation-ci-deploy` account's IAM permissions — it should likely
   never have `PutBucketPolicy` permission if ACL changes are outside its function.

**G-003:**
1. Given the technical indicators, recommend blocking the sender domain and adding it to the
   phishing block list regardless of the Ambiguous verdict — low-cost preventive action.
2. Send a brief awareness notice to the finance distribution list flagging the spoofed-domain
   pattern, since this style of attack often recurs with slight variations.
3. Monitor for related emails from similar lookalike domains in the following days.
4. No user-facing remediation needed (no credentials or systems were touched), but log for
   pattern-tracking purposes.

**G-004:** No action needed — standard closure.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | G-001: TP · G-002: TP · G-003: Ambiguous (analyst's final call, discussed) · G-004: FP |
| Confidence | High (G-001, G-002, G-004); Contested — analyst final judgment (G-003) |
| Verification method | Ticket-only — no Splunk query run (analyst decision) |
| Triage Time | ~8 minutes (real, tracked) |
| Escalated | G-001, G-002: Yes · G-003: Preventive action recommended despite Ambiguous verdict |
| Corrections during investigation | 0 formal corrections; G-002 briefly discussed as possible Ambiguous before confirming TP; G-003 verdict discussed at length with reviewer, analyst's final call retained as Ambiguous |
