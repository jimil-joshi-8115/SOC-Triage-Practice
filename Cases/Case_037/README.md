# Case_037 — CI/CD: Stolen Session Token Used to Exfiltrate Production Secrets

**Phase:** 5 (Cases 31–50) — CI/CD Pipeline Compromise, 3-alert batch
**Format:** CI/CD Platform Audit Log ("PipelineForge" — fictional third-party CI/CD provider)
**Company:** Aurora Resorts & Casinos (as a customer of the CI/CD platform)
**Splunk verified:** ✅ Yes

**Scenario basis:** Adapted from the December 2022/January 2023 CircleCI breach — malware on an
engineer's laptop stole a 2FA-backed SSO session cookie, allowing the attacker to impersonate
the engineer and access internal systems; because the engineer had privileges to generate
production access tokens, the attacker was able to exfiltrate customer environment variables,
tokens, and keys. All company, user, and identifier details below are fictional/sanitized.

**Data source:**
```
source      = cicd_auditlog_case037.csv
host        = JIMIL-JOSHI
sourcetype  = csv
Total events indexed: 7
```

---

## Alerts (as received at trigger time)

```
Alert Q-001 — CI/CD: Session Token Used From Anomalous Location
  Severity: High
  Actor: session_token:r.desai
  Detail: r.desai's session token used to clone a private repository
          (internal-payment-service) from an IP never seen in 90-day history,
          at 06:44 IST — outside their normal 09:00-18:00 IST working hours
  Source IP: 146.70.44.18 (Chisinau, Moldova)

Alert Q-002 — CI/CD: Production Secrets Context Read by Interactive Session
  Severity: Critical
  Actor: session_token:r.desai (same session as Q-001)
  Detail: Read access to aurora-prod-deploy-context, including
          AWS_SECRET_ACCESS_KEY, DB_PROD_PASSWORD, STRIPE_API_KEY — this
          context is normally only read by automated pipeline jobs, never
          an interactive user session
  Source IP: 146.70.44.18 (same as Q-001)

Alert Q-003 — CI/CD: OAuth Token Rotation
  Severity: Low
  Actor: scheduled-rotation-bot
  Detail: Automated quarterly OAuth token rotation for aurora-web-prod,
          matches documented schedule CHG-9012
  Source IP: 10.50.1.5 (internal)
```

## Task

Run Splunk queries — check r.desai's normal working hours/IP baseline, and verify whether
context reads of this kind are typically automated or interactive. TP / FP / Ambiguous for
Q-001, Q-002, and Q-003.
