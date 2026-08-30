# Failed Logon / Authentication Anomaly Triage Playbook

Step-by-step checklist for failed logon, password spray, credential stuffing, and identity
anomaly alerts (on-prem and cloud). Each rule is tied to the case that established it.

---

## Step 1: Identify the Pattern Type

| Pattern | Likely Technique | Source Case |
|---|---|---|
| Many failures, one account | Brute force (T1110) | Case_005 |
| Many failures, many accounts, few attempts each | Password spray (T1110.003) | Case_006 |
| Recurring, same interval, resolves the same way every time | Expired scheduled-task credential (benign) | Case_025 (E-002) |

**Rule:** A known/valid account being targeted is NOT reassuring — failed attempts against a
real account are still TP-worthy on their own (Case_005). Don't assume "they didn't get in" means
"nothing to escalate."

---

## Step 2: Check Successful Sign-Ins for the Same Account/Timeframe

- Did a failed pattern precede a *successful* sign-in? That combination is far more urgent than
  failures alone.
- **Rule:** "Success" in identity logs is not reassuring — it means the deviation got through,
  not that the system worked correctly (Case_018, Case_021, Case_023, Case_034).

---

## Step 3: Check Logon Type / Access Method

- **Logon_Type is decisive for identity/timing alerts** — an interactive logon at 3 AM is a
  different risk profile than a scheduled service logon at the same hour (Case_013).
- Check for **legacy authentication protocols** (IMAP4, POP3, SMTP AUTH) — these bypass MFA and
  Conditional Access entirely; their use is a red flag on its own, not just a side detail
  (Case_021, Case_022, Case_032).

---

## Step 4: Check Geography/Device Against Established Baseline

- Compare against the **specific account's own** history — a frequent traveler's baseline looks
  different from a desk-based employee's (Case_026, F-003).
- Look for **positive confirming evidence** (a calendar entry, a known VPN egress, a documented
  travel record) — not just "nothing looks wrong." A deviation + confirming evidence = FP; a
  deviation + no evidence either way = Ambiguous (Case_026, Case_040).
- **Impossible travel** vs. **first-seen-location-with-timing-correlation** are related but
  distinct signals — impossible travel requires two incompatible locations close in time;
  first-seen-location tied tightly to another suspicious event (e.g., a password reset) is
  decisive even without strict travel-time impossibility (Case_024, H-002).

---

## Step 5: Check MFA Bypass Mechanism Specifically

- **MFA fatigue / push bombing**: repeated denials followed by an approval shortly after — name
  this technique explicitly in the write-up, don't just note "MFA was satisfied" (Case_030, the
  2022 Uber technique).
- **Legacy protocol bypass**: MFA never evaluated because the protocol doesn't support it
  (Case_021, Case_022).
- **Policy-level bypass**: the account was added to an MFA-exemption group/trusted location —
  this is persistence at the tenant-policy level, not just this one login (Case_032, Case_042).

---

## Step 6: Correlate or Isolate

- Check account, host, and IP overlap with any other alert in the queue before assuming shared
  incident membership (Case_025's E-002 discrimination test, repeated in Cases 027, 029, 040,
  048).
- If part of a chain, identify the **root-cause entry point** — is this alert the initial
  compromise, or a downstream consequence of an earlier one (Case_041's retroactive
  U-001 re-assessment)?
