# Case_038 — Azure Storage: SAS Token Leaked to Public GitHub Repo, Exploited for Mass Data Access

**Phase:** 5 (Cases 31–50) — Azure Storage, 3-alert batch
**Format:** Third-Party Secret-Scanning Alert + Azure Storage Analytics Logs + Azure Activity Log
**Company:** Aurora Resorts & Casinos (internal alias — sanitized)
**Splunk verified:** No — ticket-only (analyst decision)

**Scenario basis:** Grounded in a widely-documented real-world misconfiguration pattern — SAS
(Shared Access Signature) tokens with excessive permissions and long expirations accidentally
committed to public source code repositories, then discovered and abused by attackers scanning
GitHub for leaked secrets. Not a single named breach, but the pattern behind numerous actual
cloud storage exposure incidents. All company, repo, and identifier details below are
fictional/sanitized.

---

## Alerts (as received at trigger time)

```
Alert R-001 — Azure Storage: SAS Token Found in Public GitHub Repository
  Severity: High
  Repository: auroraresorts/booking-widget (public repo, company's embeddable
              booking widget source code)
  Detail: A SAS token for storage account "aurorastorageprod" was found
          hardcoded in a JavaScript file, committed 6 days ago. Token scope:
          Read+Write+Delete on the ENTIRE storage account (all containers,
          not scoped to a single container). Expiration: 2 years from
          generation (generated 11 months ago; ~13 months remaining validity)
  Time: Discovered 09:14:00 UTC (alert time, not commit time)

Alert R-002 — Azure Storage: Anomalous Access Volume Using the Leaked Token
  Severity: Critical
  Detail: The SAS token identified in R-001 used to perform 340 GetBlob and
          210 ListBlobs operations across 8 different containers within 40
          minutes, including "customer-invoices" and "employee-documents"
          containers — normal legitimate usage of this token (by the booking
          widget) is exclusively 2-3 PutBlob operations per booking, to the
          single "booking-uploads" container only
  Source IP: 91.219.212.44 (external, unrelated to any known Aurora service)
  Time: 09:20–10:00 UTC (immediately after R-001's discovery alert)

Alert R-003 — Azure Storage: New SAS Token Generated for Partner Integration
  Severity: Low
  Actor: a.reddy@auroraresorts.com (Integrations Engineer)
  Detail: New SAS token generated, scoped to READ-ONLY on the single
          "marketing-assets" container, expiration set to 7 days, tied to
          documented change ticket CHG-9401 (temporary access for an
          approved marketing partner's asset-sync tool)
  Time: 11:15:00 UTC
```

## Task

TP / FP / Ambiguous for R-001 through R-003. Note correlation, and consider what makes R-003
fundamentally different from R-001 despite both involving SAS tokens.
