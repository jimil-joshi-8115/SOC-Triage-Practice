# Verdict — Case 044

## X-001: 🔴 Verdict: TRUE POSITIVE (Critical)
## X-002: 🔴 Verdict: TRUE POSITIVE (Critical)
## X-003: 🟢 Verdict: FALSE POSITIVE

**X-001 and X-002 are TP as a single correlated incident. X-003 is unrelated.**

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Active Scanning | T1595 (attacker-side) | Automated internet-wide database discovery scanning against the exposed instance (X-001/X-002) |
| Data from Cloud Storage / Network Shared Drive | T1530 (adjacent) | Unauthenticated public access to a database containing customer data (X-001) |
| Data Destruction | T1485 | Collection dropped and replaced with a ransom demand (X-002) |

---

## Justification

### X-001 — TP, Critical
A MongoDB instance is reachable on the public internet with no authentication, running the
default `--noauth` configuration never remediated post-deployment, and contains a collection
with real customer names, emails, and loyalty point balances. The "dev/test" inventory label
does not change this verdict: the label is an internal classification with no bearing on actual
network exposure or data sensitivity, and both concrete facts present here (no authentication,
confirmed real customer data) independently justify the highest severity regardless of the
label. An unprotected dev environment holding a live data copy is arguably higher-risk than a
properly-labeled production system, since dev environments typically receive less routine
security scrutiny.

### X-002 — TP, Critical
Six distinct external IPs connected within 3 hours of the exposure's discovery — a pattern
consistent with automated scanning tools that specifically hunt for exposed databases — and the
data was subsequently destroyed and replaced with an extortion demand. This confirms active
exploitation, not merely theoretical exposure, and represents the well-documented "database
ransom" pattern that has affected many thousands of similarly exposed instances industry-wide.

**Correlation:** X-001 and X-002 are one incident — the exact exposure identified in X-001 was
found and exploited by external actors within hours, consistent with (and likely preceding or
coinciding with) the internal scan's own discovery.

### X-003 — FP
A properly-scoped, internal-only firewall rule, added by the appropriate role, tied to a
documented change ticket with an explicit business justification. No authentication bypass is
implied, and the scope is limited to a specific internal subnet reaching a specific database
port for a named microservice — the inverse of X-001 in every dimension that matters.

---

## What Would Change These Verdicts

- **X-001/X-002 → FP:** essentially not plausible given the confirmed lack of authentication and
  the presence of real customer data — even in the unlikely case the data were confirmed
  synthetic, the public unauthenticated exposure itself would remain a valid finding on its own.
- **X-003 → TP:** if the referenced change ticket could not be verified, or if the rule scope
  were found to extend beyond the documented internal subnet.

None of these apply in this ticket — verdicts stand as TP / TP / FP.

---

## Recommended Response Actions

1. **Immediately restrict network access to the MongoDB instance** to internal-only/VPN
   sources, or take it offline if not actively required.
2. **Enable authentication** on the MongoDB instance before any further exposure.
3. **Do not pay the ransom** — the "we have a backup" claim from database-ransom actors is
   frequently false; recovery should rely on the organization's own backups, not attacker
   cooperation.
4. Assess whether the organization has its own backup/snapshot of the `guest_loyalty_profiles`
   collection predating the destruction — restore from that if available.
5. Treat this as a confirmed customer data breach — the collection was accessed and copied
   (implied by the ransom demand pattern) before being destroyed; begin breach-notification
   processes for affected customers.
6. Audit all "dev/test"-labeled cloud assets organization-wide for the same
   authentication/exposure gap — this incident indicates the inventory-labeling process alone
   is not a reliable indicator of actual risk.
7. Escalate to L2/IR immediately as a confirmed data breach and extortion incident.
8. No action needed on X-003 beyond standard closure.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | X-001: TP (Critical) · X-002: TP (Critical) · X-003: FP |
| Confidence | High (all three) |
| Verification method | Ticket-only — no Splunk query run (analyst decision) |
| Triage Time | 3 minutes (real, tracked) |
| Escalated | Yes — X-001/X-002 (would be, in real SOC, as confirmed data breach) |
| Corrections during investigation | 0 |
| Scenario basis | Grounded in a widely-documented real-world pattern of unauthenticated public database exposure and mass "database ransom" campaigns; IOCs and identities fully sanitized/fictional |
