# Investigation — Case 005

## Step 1: Assess the Failed Logon Pattern

5 failed logon attempts, all against the **same account** (`hp`), within a **~13 second window** (08:12:42.125 → 08:12:55.792).

**Finding:** 🔴 This timing and repetition pattern matches the standard industry detection logic for brute-force activity (T1110) — multiple rapid failures against a single known account is the textbook trigger, not a reassuring pattern.

---

## Step 2: Interpret the Failure Reason Correctly

`Failure_Reason`: "Unknown user name or bad password" across all 5 events.

**Important correction during investigation:** This message is a **merged/generic Windows message** — it does NOT confirm the username itself was invalid. It equally covers the case of a valid username with an incorrect password, which is what actually occurred here (`hp` is a real, existing account on this host). Do not misread this string as evidence the attacker was guessing usernames — they were targeting a known, valid account and failing only on the password.

---

## Step 3: Check for Successful Logon or Lockout Following the Failures

```spl
index=* sourcetype="WinEventLog:Security" (EventCode=4624 OR EventCode=4740) Account_Name="hp"
| table _time, EventCode, ComputerName, Account_Name, Logon_Type
| sort -_time
| head 5
```

**Result:** 4 events, all EventCode=4624 (successful logon), all `hp` and `JIMIL-JOSHI$` pairs, timestamped **07:54:49** and **07:56:34** — both well **before** the failed attempts began at 08:12:42.

**Finding:** 🟢/🔴 mixed:
- 🟢 No successful logon occurred **after** the failed attempts — the brute-force attempt did **not** result in a confirmed compromise.
- 🔴 No EventCode=4740 (account lockout) appeared either — meaning **no lockout policy triggered** after 5 consecutive failures. This is a secondary finding worth flagging: if no lockout threshold exists, an attacker could continue attempting indefinitely without being automatically blocked.

**Note on `JIMIL-JOSHI$` in the 4624 results:** the `$` suffix indicates a machine/computer account, not the `hp` user account itself — these two entries per row appear to be paired system-level and user-level logon components, unrelated to the brute-force attempt under investigation.

---

## Step 4: Distinguish Verdict Basis — Attempt vs. Outcome

**Key reasoning point:** A TP verdict here is based on the **behavior matching a known attack technique (T1110)**, not on whether the attack succeeded. The absence of a successful logon afterward does not downgrade this to FP — it means the attempt was unsuccessful, which is still a real, loggable, escalation-worthy security event. Treating "it didn't work" as "therefore harmless" would be a triage mistake — failed attacks still indicate hostile intent or a real security testing activity worth review.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| Repetition/timing | 5 failures in ~13 seconds, same account | 🔴 High |
| Failure reason | Generic message; does not indicate invalid username | 🟡 Neutral (correctly reinterpreted) |
| Post-failure success (4624) | None found — attempt did not succeed | 🟢 Lowers severity slightly |
| Account lockout (4740) | Not triggered — no lockout policy observed | 🔴 Secondary finding (policy gap) |
