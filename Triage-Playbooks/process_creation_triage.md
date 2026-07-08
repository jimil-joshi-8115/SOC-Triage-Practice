# Process Creation Triage Playbook

Built from real triage patterns confirmed across Cases 001, 002, 007, 008, 009, 010, 011, 012, 014, and 016.

---

## Step-by-Step Checklist

1. **Check the parent-child relationship — but know which direction the red flag runs.**
   - `cmd.exe → powershell.exe`, `cmd.exe → nslookup.exe`, `cmd.exe → net.exe`: **Normal, common chains.** Do not flag by default. (Lesson repeatedly reinforced across Cases 009, 010, 011)
   - `OUTLOOK.EXE → powershell.exe`, `EXCEL.EXE/WINWORD.EXE → powershell.exe`: **Abnormal — the parent itself is the primary red flag.** Office/email apps never legitimately spawn script interpreters. (Case_014, Alert Q)
   - **Rule of thumb:** ask "does this parent process have any legitimate reason to spawn this child?" — not "does this parent process sound suspicious?"

2. **Check for LOLBin abuse (trusted binaries misused).** Common patterns confirmed in this repo:
   - `certutil.exe -urlcache` / `-decode` used to download or convert files (Case_008)
   - `mshta.exe` executing inline JavaScript/HTA content (Case_011, Alert I)
   - `wmic.exe process call create` for remote-style execution (Case_014, Alert P — but see technique-vs-outcome below)
   - `rundll32.exe` with an unrecognized DLL/function pair (cross-check `Noise-Baselines/known_legitimate_processes.md` first)

3. **Decode before judging.** Never rule out (or confirm) intent based on a technique's *presence* alone — always decode/inspect the actual payload:
   - `-EncodedCommand` / `-enc` flags must be decoded before judging (Case_001)
   - A technique + harmless payload can still be Ambiguous, not automatic FP (Case_003's `whoami` inside a masquerading scheduled task) or automatic TP (Case_014's `wmic`+`whoami`)

4. **Apply the technique-vs-outcome distinction.**
   - **Confirmed completed action** (registry write, account creation, privilege escalation, file download-and-execute) = decisive TP on its own, regardless of how harmless a co-occurring payload looks. (Case_007, Case_002, Case_012)
   - **Technique present but specific action harmless, with no confirmed further impact** = Ambiguous. (Case_003, Case_011 Alert H, Case_014 Alert P)
   - **Confirmed EDR/tool detection of the technique actually occurring** (not just theoretically possible) = decisive TP, no outcome-weighing needed. (Case_016, Alert Y — process injection)

5. **Check the destination for external network calls.**
   - Raw external IP with no legitimate business justification = strong TP indicator (Case_001, Case_008, Case_012)
   - Legitimate platform (e.g., GitHub) with an undocumented specific path/repo = Ambiguous, not automatic TP or FP (Case_010, Alert F)
   - Documented internal server/domain = FP (positive evidence, not just absence of red flags)

6. **Check the process making a network connection, not just the port.**
   - A scripting engine (PowerShell, WMI) connecting on any port — even a port that could theoretically be used by a legitimate app — has no everyday justification. The *process* is the deciding factor. (Case_017, Alert AE)

7. **Check for masquerading names.** Service-like or brand-mimicking names (`SystemHealthCheck`, `AdobeUpdateSvc`, `WindowsUpdateCheck`) with no baseline match are a red flag, especially combined with persistence or privilege indicators (Cases 002, 003, 007, 015).

---

## Verdict Quick Reference

| Pattern | Verdict |
|---|---|
| Normal parent-child chain, no other factors | FP |
| Abnormal parent (Office/email app spawning script interpreter) | TP |
| LOLBin technique + confirmed harmful action/destination | TP |
| LOLBin technique + harmless specific action, no confirmed outcome | Ambiguous |
| Confirmed EDR detection of technique occurring | TP |
| Raw external IP, no justification | TP |
| Legitimate platform, undocumented specific resource | Ambiguous |
