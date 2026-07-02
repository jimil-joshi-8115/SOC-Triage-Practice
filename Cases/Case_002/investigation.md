# Investigation — Case 002

## Step 1: Separate Noise From Signal

3 `net.exe` events fired within ~0.5 seconds. Breaking down each:

| Event | Command | Purpose |
|---|---|---|
| 16:11:15.833 | `net user` | Recon/noise — lists existing local accounts |
| 16:11:16.160 | `net user hpbackup Temp@2026 /add` | 🔴 **Actual action** — creates new local account `hpbackup` with password `Temp@2026` |
| 16:11:16.290 | `net user` | Recon/noise — likely re-checking account list post-creation |

**Finding:** Only the middle event is the actual concerning action. The two `net user` (no args) calls are consistent with checking the account list before and after — a pattern of "verify state → make change → verify state again."

---

## Step 2: Check Parent Process

`Creator_Process_Name` = `powershell.exe` (WindowsPowerShell v1.0) for all 3 events.

**Finding:** 🟠 PowerShell spawning `net.exe` is not inherently malicious (admins do this), but combined with the account-creation action itself, it adds to the overall picture rather than being a standalone red flag.

---

## Step 3: Check Timing

All 3 events fall within a ~0.5 second window (15.833 → 16.290).

**Finding:** 🟡 This is consistent with **manual rapid CLI entry** (someone typing 3 commands back-to-back), not the kind of exact millisecond repetition seen in Case_001 (which indicated scripted/automated execution). Important distinction — don't conflate "fast" with "automated." This looks like one operator/script running a short sequence once, not a loop.

---

## Step 4: Check Account Name Against Baseline

Checked `Noise-Baselines/known_legitimate_accounts.md`.

**Finding:** 🔴 `hpbackup` is **not present** in the documented legitimate accounts baseline. The name is deliberately service-like (mimicking a backup service account), which is a common technique to blend a newly created account into normal-looking account lists — worth flagging explicitly rather than just noting "unknown."

---

## Step 5: Attempt to Confirm via EventCode 4720 (Account Created)

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4720
| table _time, ComputerName, Account_Name, Security_ID
| sort -_time
| head 5
```

**Result:** 0 events.

**Finding:** 🔴 No 4720 event was generated for this account creation. Likely cause: the **"User Account Management" audit subcategory** is not enabled in the local audit policy on this host (unconfirmed — `auditpol` check not yet run to verify root cause).

**Significance:** This is a real detection gap. If confirmed, it means **4688 process-creation monitoring is the only thing that caught this activity** — a purely 4720-based detection rule would have completely missed this account creation. This strengthens the case for layered detection rather than relying on a single event ID.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| Command content | `net user hpbackup Temp@2026 /add` — real account creation | 🔴 High |
| Parent process | powershell.exe → net.exe | 🟠 Contributing factor |
| Timing | Manual rapid CLI entry (not automated loop) | 🟡 Neutral-ish |
| Account name vs. baseline | Not in known legitimate accounts | 🔴 High |
| 4720 confirmation | 0 events — likely audit policy gap | 🔴 High (detection gap) |
