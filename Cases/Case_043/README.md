# Case_043 — AWS S3 Ransomware: Compromised Key Used to SSE-C Encrypt Bucket + Deletion Lifecycle Pressure

**Phase:** 5 (Cases 31–50) — AWS S3, 3-alert batch
**Format:** AWS CloudTrail
**Company:** Aurora Resorts & Casinos (internal alias — sanitized)
**Splunk verified:** ✅ Yes

**Scenario basis:** Adapted from the January 2025 Codefinger ransomware campaign — attackers
used compromised AWS credentials with s3:GetObject/s3:PutObject permissions to encrypt S3
objects using Server-Side Encryption with Customer-Provided Keys (SSE-C), generating and
retaining the encryption key entirely outside the victim's environment. Because AWS logs only
an HMAC of the SSE-C key (never the key itself), recovery is impossible without the attacker's
cooperation. Attackers then set a 7-day S3 Object Lifecycle deletion policy to pressure victims
into paying. All company, bucket, and identifier details below are fictional/sanitized.

**Data source:**
```
source      = cloudtrail_s3ransomware_case043.csv
host        = JIMIL-JOSHI
sourcetype  = csv
Total events indexed: 8
```

---

## Alerts (as received at trigger time)

```
Alert V-001 — CloudTrail: Compromised/Deprecated Access Key Used for Bulk S3 Enumeration
  Severity: High
  Actor: AKIA-compromised-key-devops
  Detail: Access key belonging to a deprecated CI deploy user, not rotated
          since a departed contractor's offboarding 14 months ago, used to
          enumerate all 22 buckets and list 8,400 objects in
          aurora-guest-records-archive
  Source IP: 91.219.212.55 (external)

Alert V-002 — CloudTrail: Objects Rewritten With SSE-C, Ransom Note Deposited
  Severity: Critical
  Actor: Same access key as V-001
  Detail: Multiple PutObject calls rewriting existing objects with SSE-C
          headers (AWS logs only HMAC, not the key) — this bucket has never
          used SSE-C in its 2-year history, all prior objects use SSE-KMS;
          followed by a new lifecycle rule expiring ALL objects after 7
          days (no prior lifecycle rule existed); a file named
          "_HOW_TO_RECOVER_YOUR_FILES.txt" was subsequently created in the
          bucket root

Alert V-003 — CloudTrail: Bucket Lifecycle Policy Updated
  Severity: Low
  Actor: it-storage-admin@auroraresorts.com
  Detail: Lifecycle rule updated on aurora-log-archive-cold — transition to
          Glacier after 90 days, expire after 730 days; matches documented
          data-retention policy DOC-RET-004, routine quarterly review
  Source IP: 10.50.1.9 (internal)
```

## Task

Run Splunk queries — check the compromised key's activity timeline, confirm the bucket's
historical encryption pattern, and compare the two lifecycle policy changes. TP / FP / Ambiguous
for V-001 through V-003.
