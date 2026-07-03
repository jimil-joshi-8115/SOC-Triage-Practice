# Investigation — Case 006

## Step 1: Assess the Pattern — Multiple Accounts vs. Single Account

3 failed logon attempts across **3 distinct accounts** (`admin`, `administrator`, `support`) within a **~35 second window** (08:24:07.403 → 08:24:42.922).

**Finding:** 🔴 This is structurally different from Case_005 (single account, multiple attempts = classic brute-force, T1110). Here, multiple different account names are being tried rapidly — this matches **password spraying (T1110.003)**, where an attacker tries common/default account names against a target rather than repeatedly guessing passwords for one known account. This is often used to avoid triggering single-account lockout thresholds while still probing for valid credentials.

---

## Step 2: Assess Account Legitimacy

None of `admin`, `administrator`, or `support` are documented in `Noise-Baselines/known_legitimate_accounts.md` — the only known legitimate interactive account on this host is `hp`.

**Finding:** 🔴 These are classic default/common account names attackers commonly try during automated or manual password-spray attempts, precisely because they're likely to exist by default on many systems (though not on this one). Targeting non-existent, generic admin-style names is itself a signal of external/opportunistic probing rather than a legitimate user's mistyped credentials.

---

## Step 3: Compare Failure Reason Interpretation to Case_005

Same generic message ("Unknown user name or bad password") appears here — but unlike Case_005 (where `hp` is a real account and the failure was password-only), here the accounts themselves are **not valid accounts on this host**. This time the "unknown user name" portion of the message is the more likely applicable interpretation, since none of the 3 targeted names exist locally.

---

## Step 4: Timing Pattern

3 attempts across 3 accounts in ~35 seconds — each roughly 15-30 seconds apart. Consistent with either a manual rapid-attempt sequence or a lightweight automated spray tool; either way, targeting multiple accounts back-to-back in under a minute is not typical of normal user behavior (a legitimate user does not try logging in as `admin`, `administrator`, and `support` in succession).

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| Account pattern | 3 distinct accounts, not 1 repeated | 🔴 High — matches T1110.003 |
| Account legitimacy | None of the 3 targeted accounts exist in baseline | 🔴 High |
| Timing | ~35 seconds across 3 accounts | 🔴 High |
| Technique match | Password spraying, distinct from Case_005's brute-force | 🔴 High |
