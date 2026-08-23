# Verdict — Case 043

## V-001: 🔴 Verdict: TRUE POSITIVE
## V-002: 🔴 Verdict: TRUE POSITIVE (Critical)
## V-003: 🟢 Verdict: FALSE POSITIVE

**V-001 and V-002 are TP as a single correlated incident. V-003 is unrelated and serves as a
direct contrast case.**

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Valid Accounts: Cloud Accounts | T1078.004 | Compromised/unrotated access key used for account access (V-001) |
| Cloud Storage Object Discovery | T1619 | Full account bucket enumeration and object listing (V-001) |
| Data Encrypted for Impact | T1486 | Objects re-encrypted with attacker-controlled SSE-C keys AWS cannot recover (V-002) |
| Data Destruction | T1485 (adjacent) | 7-day lifecycle deletion policy applied for extortion pressure (V-002) |

---

## Justification

### V-001 — TP
A deprecated CI deploy access key, unrotated for 14 months since a departed contractor's
offboarding, was used from an external IP to enumerate all 22 buckets in the account and list
8,400 objects in `aurora-guest-records-archive`. A stale credential belonging to a departed
contractor being actively used from an external source is unauthorized access on its own merits.

### V-002 — TP, Critical
The same compromised key rewrote existing objects using SSE-C encryption — a mode this bucket
has never used in its 2-year history (always SSE-KMS with an AWS-managed key) — at a rate
consistent with scripted execution. AWS logs only an HMAC of an SSE-C key, never the key itself,
meaning the objects are now unrecoverable without the attacker's cooperation. This was
immediately followed by a new lifecycle rule expiring the entire bucket's contents within 7
days (no prior lifecycle rule existed) and the creation of an explicit ransom note file. This is
a complete, unambiguous match to the documented Codefinger ransomware pattern: compromised
credentials → SSE-C re-encryption → deletion-pressure lifecycle policy → ransom note.

**Correlation:** V-001 and V-002 are one incident — enumeration followed immediately by
encryption and extortion, same actor and IP throughout.

### V-003 — FP
A different actor entirely (a named, internal IT administrator), from an internal IP, updating
the lifecycle policy on a completely different, unrelated bucket (a log archive, not guest
records), explicitly tied to a documented retention policy (DOC-RET-004) as part of a routine
quarterly review. The direct side-by-side comparison against V-002's lifecycle change
(identical action type, opposite context in every other dimension) confirms verdict depends on
actor legitimacy and documentation, not the action itself.

---

## What Would Change These Verdicts

- **V-001/V-002 → FP:** essentially not plausible given the confirmed credential staleness,
  the encryption-mode deviation from 2 years of history, and the explicit ransom note — would
  require an implausible combination of an approved internal security test using a deprecated,
  unrotated key from an external IP.
- **V-003 → TP:** if the referenced retention policy DOC-RET-004 could not be verified, or if
  the affected bucket were found to contain sensitive data outside the scope of routine log
  retention.

None of these apply in this ticket — verdicts stand as TP / TP / FP.

---

## Recommended Response Actions

1. **Immediately deactivate the compromised access key** (`AKIA-compromised-key-devops`) —
   highest priority to stop further damage.
2. **Do not pay any ransom demand** — engage AWS Support immediately; per public guidance on
   this attack pattern, AWS actively monitors for and responds to reports of exposed/compromised
   keys used in this manner.
3. **Cancel the malicious lifecycle deletion rule** on `aurora-guest-records-archive`
   immediately to prevent the 7-day auto-deletion from executing.
4. Assess whether any backup or versioning exists for the affected bucket predating the SSE-C
   re-encryption (e.g., S3 Versioning, cross-region replication, or offline backups) — this is
   the only viable recovery path given AWS cannot recover attacker-held SSE-C keys.
5. Rotate all credentials associated with any account tied to the departed contractor
   immediately, and audit for any other stale/unrotated keys tied to former personnel.
6. Restrict SSE-C usage organization-wide via IAM policy conditions, limiting it to only
   specific authorized users/operations if it has any legitimate use case at all.
7. Review CloudTrail for the same access key's activity across all 22 enumerated buckets to
   determine the full scope of potential compromise beyond the one confirmed bucket.
8. Escalate to L2/IR immediately as an active ransomware incident.
9. No action needed on V-003 beyond standard closure.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | V-001: TP · V-002: TP (Critical) · V-003: FP |
| Confidence | High (all three) |
| Verification method | Splunk — sample AWS CloudTrail data (CSV: `cloudtrail_s3ransomware_case043.csv`, host `JIMIL-JOSHI`) |
| Triage Time | 5 minutes (real, tracked) |
| Escalated | Yes — V-001/V-002 (would be, in real SOC, as active ransomware/extortion incident) |
| Corrections during investigation | 0 |
| Scenario basis | Adapted from the January 2025 Codefinger AWS S3 SSE-C ransomware campaign; IOCs and identities fully sanitized/fictional |
