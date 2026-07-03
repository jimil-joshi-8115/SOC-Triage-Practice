# Investigation — Case 007

## Step 1: Assess the Command

`reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v SystemHealthCheck /t REG_SZ /d "powershell.exe -windowstyle hidden -c whoami" /f`

**Finding:** 🔴 This targets the `Run` registry key, a well-documented autostart location — any value added here executes automatically at every user logon. This is a confirmed persistence mechanism (T1547.001).

---

## Step 2: Assess the Value Name

`SystemHealthCheck` — not a real or documented Microsoft registry value name under this key. Designed to sound like a legitimate system maintenance entry.

**Finding:** 🟠 Masquerading naming pattern, consistent with Case_003's `WindowsUpdateCheck`.

---

## Step 3: Assess the Payload

`powershell.exe -windowstyle hidden -c whoami` — hidden window flag (evasion-adjacent), payload itself (`whoami`) is benign in isolation.

**Finding:** 🟡 Same benign-payload pattern seen in Case_003.

---

## Step 4: Parent Process

`Creator_Process_Name` = `cmd.exe` — consistent with manual/scripted execution via command line, same as prior cases.

---

## Step 5: Compare to Case_003 — Why TP Here, Not Ambiguous

Case_003 (scheduled task) was ruled Ambiguous because the persistence trigger (`/sc onlogon`) had not yet fired, and payload was unproven in effect. Here, the registry Run key is a **direct, standing autostart entry** — the moment it's written, persistence is established; there is no separate "activation" step. The mechanism itself is the confirmed action, not a pending trigger. Combined with the masquerading name and hidden-window flag, this is treated as TP rather than Ambiguous — the persistence is achieved immediately upon the `reg add` succeeding, regardless of what the current payload does.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| Registry key targeted | Run key — confirmed persistence location | 🔴 High |
| Value name | Masquerading as legitimate system entry | 🟠 Medium |
| Payload | `whoami` — benign in isolation | 🟡 Low (standalone) |
| Hidden window | Evasion-adjacent | 🟠 Medium |
| Parent process | cmd.exe — neutral | 🟡 Neutral |
