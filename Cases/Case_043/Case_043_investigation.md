# Investigation — Case 043

**Verification method:** Splunk — sample AWS CloudTrail data ingested via CSV upload
(`source="cloudtrail_s3ransomware_case043.csv"`, `host="JIMIL-JOSHI"`, `sourcetype="csv"`)

---

## Step 1: V-001/V-002 — Query the Compromised Key's Full Timeline

**Query:**
```
source="cloudtrail_s3ransomware_case043.csv" host="JIMIL-JOSHI" "AKIA-compromised-key-devops"
| table _time, EventName, Bucket, SourceIP, Details
| sort _time
```

**Result:** 7 events, all from the same external IP (91.219.212.55), forming an unbroken
attack sequence:
1. `ListBuckets` — full account enumeration, using a key explicitly noted as unrotated since a
   departed contractor's offboarding 14 months ago
2. `ListObjectsV2` — 8,400 objects listed in `aurora-guest-records-archive`
3-5. Three `PutObject` calls rewriting existing objects with SSE-C encryption headers — the
   details explicitly confirm this bucket has **never** used SSE-C in its 2-year history, always
   SSE-KMS with an AWS-managed key; the rate (3 objects in 4 seconds) suggests scripted/automated
   execution rather than manual action
6. `PutBucketLifecycleConfiguration` — a brand-new rule expiring **all** objects in the bucket
   after 7 days, with no prior lifecycle rule having existed
7. `PutObject` — a ransom note file (`_HOW_TO_RECOVER_YOUR_FILES.txt`) created in the bucket root

**Finding:** 🔴 This is a complete, unambiguous match to the Codefinger SSE-C ransomware
pattern: compromised/stale credential → enumeration → mass re-encryption using a
customer-provided key AWS never stores → deletion-pressure lifecycle policy → ransom note. Every
stage is directly observed in the log data, not inferred.

---

## Step 2: V-003 — Query the Comparison Lifecycle Change

**Query:**
```
source="cloudtrail_s3ransomware_case043.csv" host="JIMIL-JOSHI" "it-storage-admin"
```

**Result:** 1 event. `it-storage-admin@auroraresorts.com`, from internal IP 10.50.1.9, updated
the lifecycle policy on a completely different bucket (`aurora-log-archive-cold` — a log
archive, not guest records), tied explicitly to documented retention policy DOC-RET-004, framed
as a routine quarterly review.

**Finding:** 🟢 Different actor, different bucket, different IP (internal vs. external), and
explicit documentation tying the action to a known, routine process. No connection to the
V-001/V-002 incident.

---

## Step 3: Compare Both Lifecycle Policy Changes Directly

**Query:**
```
source="cloudtrail_s3ransomware_case043.csv" host="JIMIL-JOSHI" "PutBucketLifecycleConfiguration"
| table _time, Actor, Bucket, SourceIP, Details
```

**Result:** 2 events side by side — the malicious 7-day full-bucket expiration on
`aurora-guest-records-archive` (no prior rule, external IP, compromised key) versus the
legitimate Glacier-transition/730-day-expiration update on `aurora-log-archive-cold` (documented
policy, internal IP, routine admin).

**Finding:** 🟢 (as a direct comparison) Same action type (lifecycle policy change), opposite
context in every dimension — reinforcing the recurring repo lesson (Case_038, Case_042) that
mechanism alone never determines verdict; actor legitimacy, documentation, and historical
pattern do.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| V-001 key status | Compromised/stale, unrotated 14 months, external IP | 🔴 High |
| V-002 encryption pattern | SSE-C first-ever use, contradicts 2-year SSE-KMS history | 🔴 Critical |
| V-002 lifecycle policy | New 7-day full-bucket expiration, no prior rule | 🔴 Critical |
| V-002 ransom note | Explicit ransom note file created | 🔴 Critical |
| V-003 actor/documentation | Internal admin, documented policy, different bucket | 🟢 None |
| Comparison (V-002 vs. V-003 lifecycle actions) | Identical action type, opposite legitimacy | Confirms context-dependent verdict |
