# Investigation — Case 028

**Verification method:** Ticket-only — no Splunk query run (analyst decision, time-constrained)

---

## Step 1: H-001 — Check the TGS Request Pattern

| Field | Value |
|---|---|
| Account | t.bhatt |
| Requests | 9 TGS requests, 9 different service accounts, 45 seconds |
| Encryption | RC4 (weaker, offline-crackable) instead of AES |
| Baseline | ~1 TGS request/hour, AES only |

**Finding:** 🔴 This is the textbook signature of Kerberoasting: requesting service tickets for
many service accounts in a rapid burst, deliberately downgrading to RC4 encryption because RC4
hashes are far faster to crack offline than AES. The volume/rate deviation from baseline (9 in
45 seconds vs. 1/hour) and the encryption downgrade together leave no reasonable benign
explanation.

---

## Step 2: H-002 — Check the Sync Account Password Change

| Field | Value |
|---|---|
| Account changed | MSOL_a8f3d92e1c (Azure AD Connect sync account) |
| Changed by | t.bhatt — same account as H-001 |
| Timing | 3 minutes after H-001 |
| Rotation history | None triggered in 400 days |

**Finding:** 🔴 The Azure AD Connect sync account is the bridge between on-prem AD and Azure AD
— compromising it grants significant influence over both environments. A regular user account
(`t.bhatt`) changing this specific service account's password, 3 minutes after a Kerberoasting
burst, and with no documented rotation policy ever having touched it, is not routine
administrative activity — it's the direct continuation of H-001's attack.

---

## Step 3: H-003 — Check the OAuth App Grant

| Field | Value |
|---|---|
| App | "SecureSync Helper" |
| Publisher | Unverified |
| Registered | 2 days ago |
| Permission granted | Directory.ReadWrite.All |
| Granted by | MSOL_a8f3d92e1c — the account compromised in H-002 |
| Timing | 2 minutes after H-002 |

**Finding:** 🔴 `Directory.ReadWrite.All` is one of the most powerful Azure AD permissions that
exists — full read/write access to every object in the directory. An unverified app, 2 days
old, granted this permission by the just-compromised sync account, 2 minutes after the password
change, is a deliberate, high-value persistence mechanism: a backdoor that operates independent
of any single user account and survives normal credential resets.

---

## Step 4: H-004 — Check Against Documented Baseline

| Field | Value |
|---|---|
| Account | svc-gpo-mgmt — documented automation account |
| Action | Monthly GPO refresh, password complexity policy object |
| Timing | Last day of month, within the documented 22:00-23:00 maintenance window |

**Finding:** 🟢 Every field matches a known, scheduled, documented maintenance pattern exactly
— different account entirely from the rest of the chain, routine action, expected timing
window.

---

## Step 5: Correlate the Chain

**Finding:** H-001 → H-002 → H-003 form one continuous, escalating hybrid-identity attack, all
within a 6-minute window: on-prem Kerberoasting (H-001) obtains crackable credential material →
that access is used to compromise the actual on-prem/cloud identity bridge account, MSOL_...
(H-002) → that bridge account's elevated privilege is used to plant a directory-wide,
persistent OAuth backdoor in Azure AD (H-003). This is a single incident spanning both
environments, not three separate alerts. H-004 is unrelated — different account, documented
routine action, no timing or actor overlap with the attack chain.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| H-001 TGS request pattern | 9 requests/45 sec, RC4, vs. 1/hour AES baseline | 🔴 High |
| H-002 sync account compromise | Changed by attacker account, no rotation history | 🔴 High |
| H-003 OAuth app grant | Unverified, 2 days old, Directory.ReadWrite.All | 🔴 High |
| H-004 baseline match | Documented account, scheduled window, routine action | 🟢 None |
| Chain correlation | H-001→H-002→H-003 continuous, 6-min window | 🔴 High — one incident |
