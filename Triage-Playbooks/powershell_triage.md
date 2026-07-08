# PowerShell Triage Playbook

Built from real triage patterns confirmed across Cases 001, 003, 007, 009, 010, 012, 014, 017, and 018.

---

## Step-by-Step Checklist

1. **Always decode `-EncodedCommand` / `-enc` before forming a verdict.** The presence of encoding alone is never sufficient to call FP or TP — decode it and evaluate the actual content. (Case_001 — initial FP call was wrong precisely because this step was skipped)

2. **Check the parent process first.**
   - `cmd.exe → powershell.exe`: normal, not a signal by itself.
   - Office/email app (`OUTLOOK.EXE`, `EXCEL.EXE`, `WINWORD.EXE`) → `powershell.exe`: abnormal, primary red flag, weight above payload content. (Case_014, Alert Q)

3. **Check for evasion flags stacked together:** `-windowstyle hidden` / `-w hidden`, `-nop` (no profile), `-enc`. Any single flag alone may have edge-case legitimate uses, but multiple stacked together with no business justification is a strong indicator. (Case_003, Case_015 Alert T, drill practice)

4. **Check the destination if the command reaches out to the network.**
   - `IEX(New-Object Net.WebClient).DownloadString(...)` or `Invoke-WebRequest` to a raw external IP = fileless download-execute, decisive TP (Case_001, Case_010, Case_012, Case_015, Case_017)
   - Same technique to a legitimate platform (GitHub) with an undocumented specific resource = Ambiguous (Case_010, Alert F)
   - `[System.Reflection.Assembly]::Load([Convert]::FromBase64String(...))` = reflective assembly loading, a signature fileless-malware technique (Cobalt Strike/PowerSploit/Empire family) — decisive TP, no legitimate everyday use case (drill practice)

5. **Apply technique-vs-outcome when the payload is genuinely harmless.**
   - Masquerading scheduled task + hidden window + SYSTEM + persistence trigger, but payload is just `whoami` = Ambiguous — structure suspicious, outcome unconfirmed. (Case_003)
   - The same category of action but the mechanism itself is already a completed step (e.g., registry Run key write) = TP regardless of harmless current payload. (Case_007)

6. **Check the source process for network-protocol-mismatched connections.** A scripting engine (PowerShell) initiating SMTP-style or other protocol-specific traffic — not an actual mail client — has no legitimate use case, regardless of whether the port itself could theoretically be used by a real service. (Case_017, Alert AE)

7. **Security/audit configuration changes via PowerShell are decisive TP on content alone**, no further context needed:
   - `Set-MpPreference -DisableRealtimeMonitoring $true` (Case_011, Case_015)
   - Disabling ScriptBlock logging or audit policy subcategories (Case_013, Case_018)
   - These have no legitimate everyday use case for a standard user — do not soften to Ambiguous.

8. **Reverse-shell/socket code is always decisive TP.** `New-Object System.Net.Sockets.TCPClient(...)` connecting to a specific external IP:port with a continuous read loop is definitional C2/backdoor code — no ambiguity possible. (Case_018, Alert AG)

---

## Verdict Quick Reference

| Pattern | Verdict |
|---|---|
| Encoded command, not yet decoded | Investigate further — never assume either verdict |
| Decoded: external IP download-execute | TP |
| Decoded: harmless local command inside masquerading persistence | Ambiguous |
| Reflective assembly loading from Base64 | TP |
| Defender/audit/logging disable via PowerShell | TP |
| Reverse-shell socket pattern | TP |
| Abnormal parent (Office/email app) | TP, weight parent over payload |
