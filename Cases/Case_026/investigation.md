# Investigation — Case 026

**Verification method:** Splunk — sample Azure AD sign-in/MFA/password-change data ingested via
CSV upload (`source="azuread_case026.csv"`, `host="JIMIL-JOSHI"`, `sourcetype="csv"`)

---

## Step 1: F-001 — Query n.verma's Sign-In History

**Query:**
```
source="azuread_case026.csv" host="JIMIL-JOSHI" "n.verma@corptenant.com"
```

**Result:** 4 events. 2 clean Ahmedabad logins, then a Singapore login on 31/07 that explicitly
matches an approved travel calendar entry (APAC Partner Summit, 31 Jul–03 Aug), then a second
Singapore login the following day — consistent with still being on that confirmed trip.

**Finding:** 🟢 Direct, confirmed mitigating context in the event details themselves. Not just
"foreign login," but a foreign login with a matching, dated calendar entry, followed by a
second login consistent with continued travel.

---

## Step 2: F-002 — Query p.shah's Account Activity

**Query:**
```
source="azuread_case026.csv" host="JIMIL-JOSHI" "p.shah@corptenant.com"
```

**Result:** 6 events. 3 clean Ahmedabad logins, then a tight sequence from a Kyiv, Ukraine IP
never seen before for this user: password reset (02:47:19) → new MFA phone method registered,
original Authenticator method **not removed** (02:49:03) → successful sign-in using the new
method (02:51:44).

**Finding:** 🔴 The decisive detail is not the location alone — it's that the attacker added a
*second* MFA method rather than replacing the first. This is deliberate persistence: even if
the legitimate user notices the reset and changes their password again, the attacker's
independently-registered phone method still works. No calendar entry, travel context, or any
other mitigating factor is present for this account.

---

## Step 3: F-003 — Query r.iyer's Account Activity

**Query:**
```
source="azuread_case026.csv" host="JIMIL-JOSHI" "r.iyer@corptenant.com"
```

**Result:** 5 events. Baseline shows an established pattern of legitimate frequent
international travel — Singapore, Nairobi, Dubai — each explicitly matching an approved travel
calendar entry. The flagged Lagos login is the only one in this account's history **without** a
matching calendar entry, but MFA was satisfied normally throughout.

**Finding:** 🟡 This does not fit cleanly into either the F-001 pattern (positive confirming
evidence of legitimacy) or the F-002 pattern (concrete attacker tradecraft — new persistence
mechanism, no mitigating context at all). MFA was never bypassed, and the account has a strong
prior pattern of legitimate travel to varied international locations. The single anomaly — a
missing calendar entry — is an absence of confirming evidence, not positive evidence of
compromise. A frequent-traveling sales consultant plausibly takes trips that aren't always
calendared in advance.

**Correction made:** initial call was TP, made by pattern-matching the "unfamiliar location +
security tool flag" surface signal without weighing it against the strength of the account's
legitimate baseline or the absence of any concrete attacker tradecraft (no new MFA method, no
password reset, no credential change — none of the markers present in the confirmed-TP F-002).
Corrected to **Ambiguous** after re-evaluating the evidence strength directly against F-001 and
F-002 as reference points — this is the same "suspicious structure ≠ automatic TP" pattern
already documented in Case_003 and Case_014.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| F-001 location vs. baseline | Foreign, but matches confirmed calendar entry | 🟢 None — FP |
| F-002 password reset origin | Never-seen IP, no mitigating context | 🔴 High |
| F-002 MFA method change | New method added, original not removed (persistence) | 🔴 High |
| F-003 location vs. baseline | Established travel pattern, but no calendar match this time | 🟡 Inconclusive |
| F-003 MFA status | Satisfied normally, no bypass or method change | 🟢 No compromise marker |
| F-003 overall | Neither confirming nor damning evidence present | 🟡 Ambiguous — needs out-of-band verification |
