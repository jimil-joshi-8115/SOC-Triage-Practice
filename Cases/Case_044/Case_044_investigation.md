# Investigation — Case 044

**Verification method:** Ticket-only — no Splunk query run (analyst decision)

---

## Step 1: X-001 — Check the "Dev Environment" Label Against Actual Technical State

| Field | Value |
|---|---|
| Asset inventory label | "dev/test" |
| Authentication | None — public internet reachable, default port |
| Data contents | Real customer names, emails, loyalty point balances (sampled by scan) |
| Config state | Default `--noauth` never changed post-deployment |

**Finding:** 🔴 The "dev" label is an internal inventory classification, not a technical
control — it has no bearing on what is actually reachable over the network or what data resides
inside. Two independent, concrete facts override the label: no authentication (meaning the
label provided zero actual access control), and confirmed real customer data (not synthetic
test records) inside a collection whose name and contents indicate a production data copy or
snapshot. An unprotected environment holding live customer data is not lower-risk because of an
inventory tag — if anything, dev environments often receive less security scrutiny by default,
making this pattern especially dangerous.

---

## Step 2: X-002 — Check Access Pattern and Confirmed Impact

| Field | Value |
|---|---|
| Connections | 6 distinct external IPs within 3 hours of discovery |
| Pattern | Consistent with automated internet-wide database-hunting scan tools |
| Impact | Collection dropped, replaced with a ransom note demanding 0.05 BTC |

**Finding:** 🔴 This confirms not just exposure but active exploitation: the exposed database
was found (likely by automated scanning bots, given the volume and speed of connections) and
the data was destroyed and held for ransom within hours of the internal scan's own discovery —
indicating external attackers likely found it before or around the same time internal security
did. This is the well-documented "database ransom" pattern seen repeatedly against exposed
MongoDB/Elasticsearch/Redis instances industry-wide.

---

## Step 3: X-003 — Check Actor, Documentation, and Scope

| Field | Value |
|---|---|
| Actor | it-storage-admin — appropriate role for this action |
| Scope | Internal subnet only (10.50.3.0/24) to production DB tier |
| Documentation | Tied to change ticket CHG-9601, explicit business purpose |
| Authentication implication | None stated as removed or bypassed — this is a network-layer rule, not an auth change |

**Finding:** 🟢 A properly-scoped, internal-only, documented firewall change enabling a specific
new microservice's database access — the inverse of X-001 in every relevant dimension: internal
subnet only vs. entire public internet, documented business need vs. unexplained default
config, and no authentication bypass implied.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| X-001 label vs. technical state | "Dev" label irrelevant given no auth + real customer data | 🔴 Critical |
| X-001 config state | Default --noauth never remediated | 🔴 Critical |
| X-002 access pattern | Automated scanning signature, 6 IPs in 3 hours | 🔴 Critical |
| X-002 confirmed impact | Data destroyed, ransom note deposited | 🔴 Critical |
| X-003 actor/scope/documentation | Internal-only, ticketed, role-appropriate | 🟢 None |
