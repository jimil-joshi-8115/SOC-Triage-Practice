# Verdict — Case 002

## 🔴 Verdict: TRUE POSITIVE

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Create Account: Local Account | T1136.001 | Local account `hpbackup` created via `net user /add` |
| PowerShell | T1059.001 | PowerShell used as parent process to spawn `net.exe` |

---

## Justification

1. **Confirmed account creation command** — `net user hpbackup Temp@2026 /add` is unambiguous; this is not a borderline or context-dependent command like an encoded string. The action and its intent are explicit in the command line itself.
2. **Account name not present in known legitimate accounts baseline** (`Noise-Baselines/known_legitimate_accounts.md`) — this is a new, undocumented account.
3. **Service-like naming (`hpbackup`)** is a common technique to make a newly created account blend into normal-looking account lists — worth flagging as a soft indicator of intent to evade casual review, though not proof by itself.
4. **Surrounding `net user` (no args) calls before and after** the creation event show a "check state → make change → check state again" pattern, consistent with someone deliberately verifying the account was added successfully.
5. **No EventCode 4720 was generated**, most likely due to the "User Account Management" audit subcategory not being enabled locally. This is treated as a **confirmed detection gap**, not as evidence against the verdict — the 4688 process-creation evidence stands on its own regardless of whether 4720 logging exists.

**Triage lesson reinforced from Case_001:** the presence of a technique alone (PowerShell, encoded commands, etc.) isn't what makes something TP — here, it's the explicit account-creation command content plus the missing baseline match that drives the verdict, not the parent process or timing alone.

---

## What Would Change This Verdict to FP

- If `hpbackup` were documented in the known legitimate accounts baseline as an actual backup service account created by IT/admin process
- If this activity coincided with a known, scheduled admin maintenance window with a ticket/change record
- If the analyst (you) had created this account intentionally as part of routine system administration, not as a simulated threat

None of these apply in this simulated case — verdict stands as TP.

---

## Recommended Response Actions

- Disable/investigate the `hpbackup` local account immediately
- Reset password and review group membership (was it added to Administrators? — check via `net localgroup administrators`)
- **Enable "User Account Management" audit subcategory** via `auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable` to close the 4720 logging gap
- Review PowerShell history/ScriptBlock logs (4104) around this timestamp to identify what else the PowerShell session did before/after this action
- Add `hpbackup` (and its creation method) as a documented reference in future noise-baseline reviews if it turns out to be legitimate — otherwise treat as confirmed unauthorized account

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdict | TP |
| Confidence | High |
| Triage Time | Not tracked (retroactively logged) |
| Escalated | Yes (would be, in real SOC) |
| Detection Gap Identified | Yes — EventCode 4720 not logging (audit policy) |
