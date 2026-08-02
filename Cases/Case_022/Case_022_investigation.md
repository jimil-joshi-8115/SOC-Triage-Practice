# Investigation — Case 022

## Step 1: Separate the Three Alerts

BC-001, BC-002, BC-003 all involve `k.desai@corptenant.com`, but that doesn't mean they're
automatically one incident — checked each independently first.

| Alert | Signal | Session |
|---|---|---|
| BC-001 | User-reported phishing email | Reporting user's own normal session (Ahmedabad) |
| BC-002 | Impossible travel + malicious inbox rule | Attacker session (Warsaw, legacy auth) |
| BC-003 | High-volume outbound "bank details" emails | Same session as BC-002 |

---

## Step 2: BC-001 — Query and Check for Compromise Indicators

```
source="o365_unifiedauditlog_case022.csv" host="JIMIL-JOSHI" sourcetype="csv"
Operation="ReportPhishing"
| table _time, UserId, ClientIP, City, Country, ClientApp, Result, Details
```

**Result:** 1 event. Reporting action itself came from ClientIP 103.211.44.20, Ahmedabad —
the user's normal baseline location. Details confirm: no click, no credential entry.

**Finding:** 🟢 No compromise indicator on this alert in isolation. The user correctly
identified and reported a phishing attempt without engaging with it.

---

## Step 3: BC-002 — Query Login and Inbox Rule Events

```
source="o365_unifiedauditlog_case022.csv" host="JIMIL-JOSHI" sourcetype="csv"
UserId="k.desai@corptenant.com"
Operation="UserLoggedIn" OR Operation="New-InboxRule"
| table _time, Operation, ClientIP, City, Country, ClientApp, Result, Details
| sort _time
```

**Result:** 7 events. Baseline: 5 clean Ahmedabad logins (Modern Auth, browser) across the
prior 3 days. Then: 09:14 normal Ahmedabad login → **09:41 Warsaw, Poland login via IMAP4**
(MFA not satisfied, Conditional Access not applied) → **09:43 inbox rule** created, named `'..'`,
condition matches "invoice"/"payment"/"wire transfer", moves matches to a hidden
"RSS Subscriptions" folder, forwards a copy to `fin-review@corptenant-audit.net`,
`StopProcessingRules: True`.

**Finding:** 🔴 27-minute gap between Ahmedabad and Warsaw — physically impossible travel.
Legacy-auth MFA bypass matches the confirmed-TP pattern from Case_021. The inbox rule has no
legitimate business purpose: financial-keyword targeting, concealment in an unused folder,
external forwarding, and rule-processing suppression are all attacker tradecraft.

---

## Step 4: BC-003 — Query Outbound Send Events

```
source="o365_unifiedauditlog_case022.csv" host="JIMIL-JOSHI" sourcetype="csv"
UserId="k.desai@corptenant.com"
Operation="SendAs"
| table _time, ClientIP, City, Country, Details
| sort _time
```

**Result:** 14 events, 09:47–09:53, all from ClientIP 185.220.101.47 (Warsaw) — the same IP
confirmed compromised in BC-002. All sent to `vendorpartner-inc.com` finance/accounts/ap/billing
addresses, subject variations of "Updated bank details for upcoming payment."

**Finding:** 🔴 Same session as BC-002, immediately following the inbox rule's creation. This
is not a fresh, independent alert — it's the fraud payload being executed from an already-
compromised account.

---

## Step 5: Correlate All Three

**Finding:** BC-001 shares only the recipient username with BC-002/BC-003 — different sender,
different IP, different vector, no execution. No basis to link it to the compromise chain.
BC-002 and BC-003 share the same attacker IP, same account, same ~12-minute window, and a clear
cause-and-effect ordering (access → concealment rule → fraud emails) — these are one incident.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| BC-001 sender session | User's normal Ahmedabad IP, no click/creds | 🟢 None |
| BC-002 impossible travel | Ahmedabad→Warsaw in 27 min | 🔴 High |
| BC-002 legacy auth | IMAP4, MFA not satisfied, CA not applied | 🔴 High |
| BC-002 inbox rule | Financial-keyword hide+forward, rule suppression | 🔴 High |
| BC-003 sender IP | Same Warsaw IP as BC-002 | 🔴 High |
| BC-003 volume/content | 14 emails/6 min, fraudulent bank-detail change | 🔴 High |
| BC-001 vs BC-002/003 link | No shared IP, vector, or execution | Isolated — no correlation |
