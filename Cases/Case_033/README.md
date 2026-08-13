# Case_033 — GCP: Unauthorized Service Account Key Creation → External Exfiltration of Customer Data

**Phase:** 5 (Cases 31–50) — GCP, 2-alert batch (first GCP case in this repo)
**Format:** Google Cloud Audit Logs (Admin Activity + Data Access)
**Company:** Aurora Resorts & Casinos (internal alias — sanitized)
**Splunk verified:** ✅ Yes

**Data source:**
```
source      = gcp_auditlog_case033.csv
host        = JIMIL-JOSHI
sourcetype  = csv
Total events indexed: 8
```

---

## Alerts (as received at trigger time)

```
Alert M-001 — GCP IAM: Unusual Service Account Key Creation
  Severity: High
  Actor: k.solanki@auroraresorts.com (Support Analyst)
  Target Service Account: data-warehouse-admin (Editor role on all Cloud
                           Storage buckets in aurora-prod)
  Detail: 2 keys created 8 minutes apart for this service account; actor's
          120-day audit history shows no prior key-management activity; no
          matching change ticket found
  Time: 2026-08-06 14:33:19 – 14:41:07 UTC

Alert M-002 — GCP Storage: Unauthorized Bucket Access via Stolen Key
  Severity: Critical
  Actor: serviceAccount:data-warehouse-admin (authenticated via the key from M-001)
  Detail: 1,240 objects retrieved from aurora-customer-data-prod over 6 minutes,
          8.2GB total; source IP never seen for this account in 120-day history
          (normal usage: internal GCP network only)
  Source IP: 146.70.44.18 (Chisinau, Moldova)
  Time: 2026-08-06 15:02:51 – 15:04:12 UTC
```

## Task

Run Splunk queries — check k.solanki's baseline key-management activity, compare against
legitimate key-creation examples in the dataset, and verify M-002's source IP against this
service account's normal usage pattern. TP / FP / Ambiguous for M-001 and M-002.
