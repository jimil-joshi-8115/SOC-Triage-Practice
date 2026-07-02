# Investigation — Case 003

## Step 1: Break Down the Two Events

| Event | Command | Purpose |
|---|---|---|
| 16:37:04.091 | `schtasks /create /tn "WindowsUpdateCheck" /tr "powershell.exe -windowstyle hidden -c whoami" /sc onlogon /ru SYSTEM` | 🔴 **Actual action** — creates a persistent scheduled task |
| 16:37:08.331 | `schtasks /query /tn "WindowsUpdateCheck"` | Verification — confirming the task was created successfully |

**Finding:** The second event is the operator/script checking that the task registered correctly — consistent with "make change → verify" pattern seen in Case_002.

---

## Step 2: Assess the Task Name

`WindowsUpdateCheck` closely mimics genuine Windows Update-related naming conventions, but is **not a real, documented Microsoft scheduled task name**. Real Windows Update tasks live under `\Microsoft\Windows\WindowsUpdate\` with specific names (e.g. `Scheduled Start`, `Reboot`) — a task created directly at root level named `WindowsUpdateCheck` does not match Microsoft's actual naming/pathing convention.

**Finding:** 🟠 Task name is **masquerading** — designed to look legitimate to a fast/casual review, but not an authentic system task name.

---

## Step 3: Assess What the Task Actually Executes

Command run by the task: `powershell.exe -windowstyle hidden -c whoami`

Breaking down each component:
- `-windowstyle hidden` — suppresses the PowerShell console window. Not required for legitimate scheduled maintenance scripts; commonly used to avoid drawing user attention. 🟠 Evasion-adjacent.
- `whoami` — prints the current username. **This is a completely benign command in isolation.** It does not exfiltrate data, install anything, modify the system, or contact any external resource.

**Finding:** 🟡 The *packaging* around this task (hidden window, fake-legit name, SYSTEM context, persistence trigger) matches known attacker tradecraft (T1053.005 pattern), but the *payload itself* does nothing harmful. This is the core tension of the case — structure suggests malicious intent, payload does not confirm it.

---

## Step 4: Assess Trigger and Run-As Context

- `/sc onlogon` — task fires every time any user logs on. This is a **persistence mechanism** — it survives reboots and re-executes automatically.
- `/ru SYSTEM` — task runs with SYSTEM privileges rather than the creating user's own context. This is a **privilege elevation** concern: even a harmless `whoami` running as SYSTEM demonstrates that a follow-up payload could run with full system privileges without further prompts.

**Finding:** 🔴 These two flags together are a strong structural indicator of an attacker establishing a persistence + privilege-escalation foothold, independent of what the current payload does.

---

## Step 5: Check Parent Process

`Creator_Process_Name` = `cmd.exe` for both events.

**Finding:** 🟡 Not unusual on its own — `schtasks` is commonly run from `cmd.exe` by both legitimate admins and attackers. Neutral signal.

---

## Step 6: Attempt to Confirm via EventCode 4698 (Scheduled Task Created)

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4698
| table _time, ComputerName, Account_Name, Task_Name
| sort -_time
| head 5
```

**Result:** 0 events.

**Finding:** 🔴 Same logging gap pattern as Case_002 (EventCode 4720 also returned 0 events). This strongly suggests a broader local audit policy issue on this host — likely multiple "Object Access" / "Account Management" / "Detailed Tracking" audit subcategories are not enabled, not just one isolated gap. This should be escalated as a host-wide logging configuration issue, separate from this specific case's verdict.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| Task name | Masquerading as legitimate Windows task | 🟠 Medium |
| Actual payload (`whoami`) | Benign in isolation | 🟡 Low (standalone) |
| Hidden window flag | Evasion-adjacent technique | 🟠 Medium |
| Trigger (`/sc onlogon`) | Persistence mechanism | 🔴 High (structural) |
| Run-as context (`/ru SYSTEM`) | Privilege elevation | 🔴 High (structural) |
| Parent process | cmd.exe — neutral | 🟡 Neutral |
| 4698 confirmation | 0 events — recurring logging gap | 🔴 High (detection gap) |
