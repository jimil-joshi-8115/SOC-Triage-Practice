# Investigation — Case 024

**Verification method:** Splunk — sample Okta System Log + Windows Security Event Log data
ingested via CSV upload (`source="mixed_case024.csv"`, `host="JIMIL-JOSHI"`, `sourcetype="csv"`)

**Note on ingestion:** CSV headers were not auto-extracted into searchable fields on this
sourcetype (only `host`/`source`/`sourcetype` were parsed). Queries below use raw-text search
terms against the event body rather than structured field=value syntax as a result.

---

## Step 1: D-001 — Check the Reset Event in Isolation

**Query:**
```
source="mixed_case024.csv" host="JIMIL-JOSHI" "user.account.reset_password"
```

**Result:** 2 events — r.kapoor's reset (in question) and an unrelated routine reset for a
different employee (a.singh), which the ticket data itself flags as "no anomaly." Confirmed
these are two separate people and only r.kapoor's is relevant to this queue.

**Finding:** 🟡 Isolated, the reset event itself is a routine, logged administrative action —
employee ID + DOB phone verification, standard helpdesk workflow. Nothing in this single event
is independently malicious; its significance only becomes clear relative to what follows.

---

## Step 2: D-002 — Baseline r.kapoor's Login Geography

**Query:**
```
source="mixed_case024.csv" host="JIMIL-JOSHI" "r.kapoor@auroraresorts.com" "user.session.start"
```

**Result:** 4 events. 3 baseline logins — Ahmedabad, India, Modern Auth, MFA satisfied, spread
across the prior 3 days. Then: a 4th login from Bucharest, Romania, occurring 2 minutes 36
seconds after the D-001 reset, with no prior appearance anywhere outside the 10.40.0.0/16 range
in the 90-day lookback.

**Finding:** 🔴 First-ever location, immediately following the reset. This is a timing
correlation, not "impossible travel" in the strict geolocation-physics sense (no prior recent
login elsewhere to compare against) — but the tight coupling to the reset event is the actual
signal here.

---

## Step 3: D-003 — Check the IdP Registration

**Query:**
```
source="mixed_case024.csv" host="JIMIL-JOSHI" "system.idp.lifecycle.create"
```

**Result:** 1 event, 7 minutes after D-002's anomalous login, same Bucharest IP. A new SAML2
Identity Provider ('shadow-idp-relay') registered, explicitly configured to accept assertions
from an external, attacker-controlled source — bypassing the need for r.kapoor's actual
credentials or MFA on any future access.

**Finding:** 🔴 This is a persistence mechanism, not just unauthorized access. Even a full
password reset and session kill on r.kapoor's account would not remove this backdoor.

---

## Step 4: D-004 — Check the Privilege Change

**Query:**
```
source="mixed_case024.csv" host="JIMIL-JOSHI" "user.account.privilege.grant"
```

**Result:** 1 event, 1 minute 29 seconds after D-003's IdP registration, same Bucharest IP.
r.kapoor's role changed from scoped Infrastructure-only admin to full Super Administrator.

**Finding:** 🔴 Complete tenant-wide privilege escalation, immediately following the backdoor's
creation — consistent with the attacker cementing total control before moving further.

---

## Step 5: D-005 — Check Endpoint Activity

**Query:**
```
source="mixed_case024.csv" host="JIMIL-JOSHI" Domain="Endpoint"
```

**Result:** 4 events. 2 are baseline noise from days earlier (notepad.exe, mmc.exe — normal
business-hours use). The 2 that matter: 14:19:56 — PowerShell disables Windows Defender
real-time monitoring and IOAV protection; 14:22:41 (3 minutes later) — vssadmin deletes all
shadow copies. Both occur 6-9 minutes after D-004's escalation, same host (AURORA-DC01), same
user context.

**Finding:** 🔴 Both tools used (`powershell.exe`, `vssadmin.exe`) are legitimate Windows
binaries — the red flag is their combined purpose here, not their identity. Disabling Defender
removes live detection; deleting all shadow copies removes the built-in recovery path. This
specific combination, in this order, is a well-known pre-ransomware staging pattern — clearing
detection and recovery before encryption.

---

## Step 6: Correlate the Full Chain

**Finding:** All 5 alerts share one continuous session: same actor (r.kapoor's account), same
originating IP (185.220.101.203, Bucharest) for D-002 through D-004, same host for D-005, and
a tight, unbroken timing sequence (reset → new-location login within ~2.5 min → rogue IdP
within ~7 min → privilege escalation within ~1.5 min → Defender disabled within ~7 min → shadow
copies deleted within ~3 min). This is one incident with five stages, not five independent
alerts.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| D-001 reset event (isolated) | Routine helpdesk action | 🟡 Neutral in isolation |
| D-002 login geography | First-seen location, tightly coupled to reset timing | 🔴 High |
| D-003 IdP registration | Persistence backdoor, bypasses credentials/MFA | 🔴 High |
| D-004 privilege grant | Full Super Admin escalation | 🔴 High |
| D-005 endpoint activity | Defender disabled + shadow copies deleted (ransomware staging) | 🔴 High |
| Chain correlation | Single session, unbroken timing, D-001→D-005 | 🔴 High — one incident |
