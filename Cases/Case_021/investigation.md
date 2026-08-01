# Case_022 — Investigation

**Analyst:** Jimil Joshi
**Verification method:** Splunk — sample O365 Unified Audit Log data ingested via CSV upload
(`source="o365_unifiedauditlog_case022.csv"`, `host="JIMIL-JOSHI"`, `sourcetype="csv"`)
**Triage time:** Start 09:19, End ~09:56 (real, tracked)

## BC-001 — Phishing report

**Query:**
```
source="o365_unifiedauditlog_case022.csv" host="JIMIL-JOSHI" sourcetype="csv"
Operation="ReportPhishing"
| table _time, UserId, ClientIP, City, Country, ClientApp, Result, Details
```

**Result:** 1 event. User reported the message via Report Message add-in; sender IP still
Ahmedabad (normal baseline location); no click, no credential entry logged anywhere.

**Reasoning:** No compromise indicator on the reporting user's own session. Awareness process
worked as intended — user correctly identified and reported without engaging.

## BC-002 — Impossible travel + inbox rule

**Query:**
```
source="o365_unifiedauditlog_case022.csv" host="JIMIL-JOSHI" sourcetype="csv"
UserId="k.desai@corptenant.com"
Operation="UserLoggedIn" OR Operation="New-InboxRule"
| table _time, Operation, ClientIP, City, Country, ClientApp, Result, Details
| sort _time
```

**Result:** 7 events — baseline shows 5 clean Ahmedabad logins (Modern Auth) over the
preceding 3 days. Then: 09:14 normal Ahmedabad login → 09:41 Warsaw, Poland login via legacy
IMAP4 (MFA not satisfied, Conditional Access not applied) → 09:43 malicious inbox rule created
(hides invoice/payment/wire-transfer emails in an unused folder, forwards copy externally,
`StopProcessingRules: True` to suppress user visibility).

**Reasoning:** 27-minute gap between Ahmedabad and Warsaw logins is not physically possible —
textbook impossible travel. Legacy auth bypassing MFA is the same access-vector pattern
confirmed TP in Case_021. The inbox rule itself has no legitimate business purpose: targeting
financial keywords, hiding in "RSS Subscriptions," forwarding to an external domain, and
stopping further rule processing are all attacker tradecraft, not user error.

## BC-003 — High-volume outbound

**Query:**
```
source="o365_unifiedauditlog_case022.csv" host="JIMIL-JOSHI" sourcetype="csv"
UserId="k.desai@corptenant.com"
Operation="SendAs"
| table _time, ClientIP, City, Country, Details
| sort _time
```

**Result:** 14 events, all from the Warsaw IP (185.220.101.47), 09:47–09:53, immediately
following the BC-002 inbox rule. All sent to vendorpartner-inc.com finance/accounts/ap/billing
addresses, subject variations of "Updated bank details for upcoming payment."

**Reasoning:** Same session as the confirmed BC-002 compromise. This is the fraud payload being
executed — a vendor email compromise (VEC) attempt to redirect a real payment to
attacker-controlled banking details, sent from inside a trusted, legitimate mailbox.

## Correlation

BC-001 is unrelated to the compromise chain (different sender, different vector, no execution) —
stands alone as FP. BC-002 and BC-003 are the same incident: account takeover via legacy-auth
bypass → malicious inbox rule for concealment/exfil → fraudulent payment redirection emails,
all within a single ~12-minute attacker session.
