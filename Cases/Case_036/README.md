# Case_036 — Kubernetes: Unauthenticated Dashboard Exploited for Cryptojacking Pod Deployment

**Phase:** 5 (Cases 31–50) — Kubernetes, 3-alert batch
**Format:** External Attack Surface Scan + Kubernetes Audit Log
**Company:** Aurora Resorts & Casinos (internal alias — sanitized)
**Splunk verified:** No — ticket-only (analyst decision)

**Scenario basis:** Adapted from the February 2018 Tesla cryptojacking breach — an unprotected
Kubernetes Dashboard console with no authentication let attackers gain full cluster visibility
and control, from which they deployed cryptomining software configured to run with deliberately
low resource usage to evade detection, rather than using a well-known public mining pool. All
company, host, and identifier details below are fictional/sanitized.

---

## Alerts (as received at trigger time)

```
Alert P-001 — Kubernetes: Dashboard Accessible Without Authentication
  Severity: High
  Host: aurora-k8s-dashboard.internal-tools.auroraresorts.com
  Detail: Kubernetes Dashboard reachable over the internet with no
          authentication required — anyone with the URL has full
          cluster-admin visibility and control
  Note: Flagged by the same scheduled weekly scan 3 weeks ago; remediation
        ticket #INFRA-2290 open, scheduled for next sprint, no exploitation
        evidence in that prior scan
  Time: 06:00:00 UTC (scheduled scan)

Alert P-002 — Kubernetes: New Pod Deployed With Unusual Resource Requests
  Severity: Critical
  Namespace: default
  Pod name: "sysbench-worker-7f9d"
  Detail: Pod created via the Dashboard's web UI (not through the normal
          CI/CD deployment pipeline); container image pulled from an
          unlisted public Docker Hub registry; pod configured with CPU
          limits set unusually low (0.3 vCPU) despite running a
          compute-intensive process
  Time: 06:14:52 UTC (14 minutes after the P-001 scan)

Alert P-003 — Kubernetes: ConfigMap Read Access, Standard Deployment
  Severity: Low
  Namespace: aurora-web-prod
  Actor: system:serviceaccount:aurora-web-prod:ci-deploy-sa
  Detail: Read access to application ConfigMap during a deployment, matches
          the CI/CD pipeline's documented, routine deploy sequence
          (deployment ID: DEP-44192, tied to a merged pull request)
  Time: 06:20:11 UTC
```

## Task

TP / FP / Ambiguous for P-001 through P-003. P-001 was already a known, ticketed issue before
this alert fired — consider carefully whether that changes its verdict here.
