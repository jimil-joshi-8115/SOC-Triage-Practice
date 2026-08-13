# Investigation — Case 033

**Verification method:** Splunk — sample GCP Cloud Audit Log data ingested via CSV upload
(`source="gcp_auditlog_case033.csv"`, `host="JIMIL-JOSHI"`, `sourcetype="csv"`)

---

## Step 1: M-001 — Query k.solanki's Key-Creation Activity

**Query:**
```
source="gcp_auditlog_case033.csv" host="JIMIL-JOSHI" "k.solanki" "CreateServiceAccountKey"
```

**Result:** 2 events. Both against `data-warehouse-admin` (a service account with Editor role
on all Cloud Storage buckets in the prod project), 8 minutes apart. Event details confirm:
k.solanki's role is Support Analyst, with no prior key-management activity in 120 days of audit
history, and no matching change ticket was found for either action.

**Finding:** 🔴 A support analyst has no documented reason to create IAM keys at all, let alone
for a high-privilege service account, and creating a second key 8 minutes after the first is an
unusual pattern with no operational justification given in the ticket data.

---

## Step 2: Compare Against a Legitimate Key-Creation Baseline

**Query:**
```
source="gcp_auditlog_case033.csv" host="JIMIL-JOSHI" "r.desai" "CreateServiceAccountKey"
```

**Result:** 2 events for r.desai — one explicitly tied to a change ticket (CHG-8821, deployment
automation setup) and one tied to a documented quarterly rotation schedule (CHG-8790).

**Finding:** 🟢 (as a comparison baseline) This is what a legitimate key-creation event looks
like in this environment — tied to a change ticket or a documented rotation schedule. k.solanki's
events in Step 1 have neither, which sharpens the contrast rather than leaving it as a vague
"seems unusual" judgment call.

---

## Step 3: M-002 — Query the Resulting Storage Access

**Query:**
```
source="gcp_auditlog_case033.csv" host="JIMIL-JOSHI" "data-warehouse-admin" "storage.objects"
```

**Result:** 2 events. At 15:02:51, the service account authenticated using the key created at
14:41:07 (the second key from M-001), from IP 146.70.44.18 (Chisinau, Moldova) — a location
never seen for this account in 120 days; normal usage is exclusively from the internal GCP
network, never an external IP. At 15:04:12, 1,240 objects were retrieved from the
`aurora-customer-data-prod` bucket, totaling 8.2GB over 6 minutes.

**Finding:** 🔴 Direct use of the newly-created (and unjustified) key from a completely
anomalous external location, followed by large-scale retrieval of customer data. This is the
exfiltration stage.

---

## Step 4: Correlate M-001 and M-002

**Finding:** The key used in M-002 is the exact key created in M-001 (second key, 14:41:07), and
it was used just 21 minutes later from a location with zero prior history for this account. This
is one continuous incident: an unauthorized, undocumented key creation immediately followed by
its use to exfiltrate customer data from an external location.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| M-001 actor role vs. action | Support Analyst creating keys, zero prior history | 🔴 High |
| M-001 documentation | No change ticket found (vs. confirmed baseline with tickets) | 🔴 High |
| M-001 pattern | 2 keys created 8 minutes apart | 🟠 Contributing factor |
| M-002 source location | Chisinau, Moldova — never seen in 120-day history | 🔴 High |
| M-002 data volume | 1,240 objects, 8.2GB, customer data bucket | 🔴 Critical |
| Correlation | Same key, 21-minute gap, direct causal link | 🔴 High — one incident |
