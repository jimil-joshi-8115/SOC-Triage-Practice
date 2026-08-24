# Case_044 — Cloud Misconfiguration: Unauthenticated Public MongoDB With Live Customer Data → Extortion

**Phase:** 5 (Cases 31–50) — Cloud Database Misconfiguration, 3-alert batch
**Format:** External Attack Surface Scan + MongoDB Server Log + Cloud Firewall Change Log
**Company:** Aurora Resorts & Casinos (internal alias — sanitized)
**Splunk verified:** No — ticket-only (analyst decision)

**Scenario basis:** Grounded in a widely-documented real-world pattern — MongoDB,
Elasticsearch, and Redis instances left with authentication disabled and bound to public IPs,
repeatedly discovered by security researchers and automated "database ransom" scanning
campaigns that have affected tens of thousands of exposed instances over the years. All
company, host, and identifier details below are fictional/sanitized.

---

## Alerts (as received at trigger time)

```
Alert X-001 — External Attack Surface Scan: MongoDB Instance Publicly Accessible, No Auth
  Severity: Critical
  Host: 34.126.88.201 (aurora-analytics-mongo-dev, tagged as a "dev/test"
        environment in internal asset inventory)
  Detail: MongoDB instance reachable on default port 27017 from the public
          internet, no authentication required (--noauth default config
          never changed post-deployment); database contains a collection
          named "guest_loyalty_profiles" with what the scan sampled as
          real customer names, emails, and loyalty point balances
  Note: This is a DEV environment, but the collection name and sampled data
        suggest it may contain a production data copy/snapshot, not
        synthetic test data
  Time: 06:00:00 UTC (scheduled scan)

Alert X-002 — MongoDB Server Log: Connections From Multiple External IPs, Collection Dropped
  Severity: Critical
  Host: Same MongoDB instance as X-001
  Detail: 6 distinct external IPs connected within 3 hours of X-001's scan
          (consistent with automated internet-wide scanning tools/bots that
          specifically hunt for exposed databases); the
          "guest_loyalty_profiles" collection was dropped and replaced with
          a single document reading "SEND 0.05 BTC TO [wallet address] TO
          RECOVER YOUR DATA — WE HAVE A BACKUP"
  Time: 08:15:00–09:40:00 UTC (2-3.5 hours after X-001's discovery)

Alert X-003 — Cloud Firewall: New Rule Allowing Internal Subnet Access to Database Tier
  Severity: Low
  Actor: it-storage-admin@auroraresorts.com
  Detail: New firewall rule added allowing the "aurora-app-tier" internal
          subnet (10.50.3.0/24) to reach the production database tier on
          port 5432 (PostgreSQL); tied to documented change ticket
          CHG-9601 ("New microservice deployment — inventory-sync-api
          requires DB access")
  Time: 11:20:00 UTC
```

## Task

TP / FP / Ambiguous for X-001 through X-003. Consider whether the "dev environment" label in
X-001 should change the verdict, and why.
