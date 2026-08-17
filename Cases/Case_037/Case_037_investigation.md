# Investigation — Case 037

**Verification method:** Splunk — sample CI/CD platform audit log data ingested via CSV upload
(`source="cicd_auditlog_case037.csv"`, `host="JIMIL-JOSHI"`, `sourcetype="csv"`)

---

## Step 1: Q-001/Q-002 — Query r.desai's Full Session Activity

**Query:**
```
source="cicd_auditlog_case037.csv" host="JIMIL-JOSHI" "r.desai"
| table _time, Actor, Action, Resource, SourceIP, City, Country, Details
| sort _time
```

**Result:** 5 events. Baseline: 2 clean `context.read` events during normal working hours from
the internal Ahmedabad IP (10.50.2.14), tied to specific deploy job IDs. Then, from a
never-before-seen external IP (Chisinau, Moldova): `repo.clone` on a private payment-service
repository at 02:14 UTC (06:44 IST — outside the documented 09:00-18:00 IST working hours),
followed 2 minutes later by a `context.read` on the production secrets context — explicitly
noted as normally only accessed by automated jobs, never an interactive session — followed 3
minutes after that by a `secret.export` action pulling all 14 environment variables in a single
bulk action, with no equivalent bulk-export anywhere in r.desai's 90-day history.

**Finding:** 🔴 Three compounding anomalies in one uninterrupted session: never-before-seen
location, outside documented working hours, and an interactive session performing an action
(reading/exporting the production secrets context) that should only ever be performed by
automation. This is the same pattern as the real-world CircleCI breach — a compromised session
token used to reach and exfiltrate production secrets.

---

## Step 2: Q-003 — Query the Token Rotation Event

**Query:**
```
source="cicd_auditlog_case037.csv" host="JIMIL-JOSHI" "token.rotate"
```

**Result:** 1 event. Performed by `scheduled-rotation-bot`, from an internal IP, explicitly
tied to a documented change record (CHG-9012) and matching the stated quarterly schedule.

**Finding:** 🟢 Fully automated, documented, scheduled action with no deviation from expected
process. No relation to r.desai's account or the Q-001/Q-002 session.

---

## Step 3: Compare Against Legitimate Context-Read Baseline

**Query:**
```
source="cicd_auditlog_case037.csv" host="JIMIL-JOSHI" "context.read"
```

**Result:** 3 `context.read` events total — 2 from r.desai's own normal working-hours baseline
(prod context, tied to deploy jobs) and 1 from a.khanna against the staging context (also
tied to a deploy job). The anomalous read in Q-002 stands out clearly against this baseline:
same action type, but wrong session type (interactive vs. automated), wrong timing, and wrong
location.

**Finding:** 🟢 (as a comparison baseline) Confirms what legitimate context-read activity looks
like in this environment, sharpening the Q-002 finding from "seems unusual" to a direct,
evidenced contrast.

---

## Step 4: Correlate Q-001 and Q-002

**Finding:** Q-001 and Q-002 are the same session, 2 minutes apart, both from the same
never-before-seen IP. This is one incident: a compromised session token first used to access a
private repository, then immediately pivoted to reading and bulk-exporting production secrets —
directly mirroring the real CircleCI incident's progression from initial session-token theft to
exfiltration of environment variables, tokens, and keys.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| Q-001 location/timing | Never-seen IP, outside documented working hours | 🔴 High |
| Q-002 session type vs. resource | Interactive session reading automation-only context | 🔴 Critical |
| Q-002 export volume | All 14 variables in one action, no prior equivalent | 🔴 Critical |
| Q-003 vs. documented schedule | Exact match, internal IP, automated actor | 🟢 None |
| Correlation Q-001/Q-002 | Same session, same IP, 2-minute gap | 🔴 High — one incident |
