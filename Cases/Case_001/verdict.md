# Verdict — Case 001

## 🔴 Verdict: TRUE POSITIVE (all 3 events)

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| PowerShell | T1059.001 | Execution via encoded PowerShell command |
| Obfuscated Files or Information | T1027 | Base64 encoding used to obscure command intent |
| Ingress Tool Transfer | T1105 | Download of remote content via Net.WebClient from external IP |

---

## Justification

This is a true positive based on convergence of multiple high-risk indicators:

1. **Decoded payload confirms malicious-pattern behavior** — `Net.WebClient.DownloadString` pulling from a bare external IP is a well-documented fileless download technique, not standard admin activity.
2. **No legitimate business justification** for this host to contact `139.59.148.100`.
3. **Execution timing (3x in 1.4 sec)** is consistent with scripted/automated execution, not manual human interaction or a scheduled AV scan.
4. **Parent process is unlogged**, which is a gap that increases uncertainty rather than reducing risk — should be escalated for log source review, not dismissed.

**Important triage lesson:** The presence of `-EncodedCommand` alone is *not* sufficient to call FP or TP — it only becomes meaningful once decoded and the underlying action is assessed against context (destination, timing, parent, account).

---

## What Would Change This Verdict to FP

- If the destination resolved to a known internal patch/update server (not the case here — it's a public IP)
- If `Creator_Process_Name` showed a trusted AV/EDR engine (e.g. MsMpEng.exe) as parent
- If decoded content only queried local system info with no external network call

None of these conditions are met — verdict stands as TP.

---

## Recommended Response Actions

- Isolate host JIMIL-JOSHI from network pending further review (in a real environment)
- Block outbound to `139.59.148.100` at firewall/proxy
- Review PowerShell ScriptBlock logging (Event ID 4104) for this timeframe to capture full execution context
- Investigate why `Creator_Process_Name` was not captured — check audit policy / log source config

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdict | TP |
| Confidence | High |
| Triage Time | Not tracked (retroactively logged) |
| Escalated | Yes (would be, in real SOC) |
