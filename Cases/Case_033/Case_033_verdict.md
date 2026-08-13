# Verdict — Case 033

## M-001: 🔴 Verdict: TRUE POSITIVE
## M-002: 🔴 Verdict: TRUE POSITIVE (Critical)

**Both alerts are TP as a single correlated incident.**

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Cloud Accounts / Additional Cloud Credentials | T1136.003 (adjacent, GCP equivalent) | Unauthorized service account key creation (M-001) |
| Valid Accounts: Cloud Accounts | T1078.004 | Use of the newly-created key to authenticate as a high-privilege service account (M-002) |
| Exfiltration Over Web Service | T1567 | 1,240 objects / 8.2GB retrieved from a customer data bucket (M-002) |

---

## Justification

### M-001 — TP
k.solanki, a Support Analyst with zero prior key-management activity across 120 days of audit
history, created two keys 8 minutes apart for `data-warehouse-admin` — a service account with
Editor role on all Cloud Storage buckets in the production project. No change ticket was found
for either action, in direct contrast to the confirmed-legitimate baseline (r.desai's key
creations, both tied to documented change tickets or a quarterly rotation schedule). An action
this sensitive, performed by an account with no documented reason or history of doing so, and
with no supporting change record, is unauthorized on its own merits.

### M-002 — TP, Critical
The key created at 14:41:07 was used 21 minutes later to authenticate from Chisinau, Moldova —
a location with zero prior history for this service account, whose normal usage is exclusively
from the internal GCP network. This session retrieved 1,240 objects (8.2GB) from the
`aurora-customer-data-prod` bucket in 6 minutes. This confirms actual data exfiltration, not
just unauthorized key creation.

**Correlation:** M-001 and M-002 are one incident — the exact key created without justification
in M-001 was used just 21 minutes later, from a never-before-seen location, to exfiltrate
customer data. Direct, unambiguous causal chain.

---

## What Would Change These Verdicts

- **M-001 → FP:** a change ticket or documented business justification for k.solanki performing
  this action surfacing after the fact (would need to explain both the role mismatch and the
  lack of any prior similar activity).
- **M-002 → FP:** confirmed legitimate remote access for this service account from this location
  (e.g., an approved third-party integration or contractor) — unlikely given the account's
  documented internal-only usage pattern.

None of these apply in this ticket — verdicts stand as TP / TP.

---

## Recommended Response Actions

1. **Immediately revoke/delete both keys created for `data-warehouse-admin`** — highest
   priority, since the second key is confirmed compromised/misused.
2. Disable k.solanki's account pending investigation; review with the employee/manager whether
   this was intentional misuse, a compromised account, or a serious process violation.
3. Rotate the `data-warehouse-admin` service account entirely and review its IAM Editor role
   scope — a support-facing service account having Editor on all Cloud Storage buckets is
   itself worth revisiting regardless of this incident.
4. Audit CloudTrail-equivalent (Cloud Audit Log) history for any other actions taken by
   `data-warehouse-admin` during the Chisinau session beyond the confirmed object retrieval.
5. Treat this as a confirmed data breach involving customer data — begin data-loss assessment
   and legal/compliance breach-notification processes.
6. Block source IP 146.70.44.18 at the org/network level.
7. Review IAM key-creation permissions broadly — a Support Analyst role should likely not have
   `iam.serviceAccountKeys.create` permission at all.
8. Escalate to L2/IR immediately.

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdicts | M-001: TP · M-002: TP (Critical) |
| Confidence | High (both) |
| Verification method | Splunk — sample GCP Cloud Audit Log data (CSV: `gcp_auditlog_case033.csv`, host `JIMIL-JOSHI`) |
| Triage Time | 4 minutes (real, tracked) |
| Escalated | Yes — both (would be, in real SOC, as confirmed customer data breach) |
| Corrections during investigation | 0 |
