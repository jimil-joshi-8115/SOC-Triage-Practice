# Verdict — Case 007

## 🔴 Verdict: TRUE POSITIVE

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Registry Run Keys / Startup Folder | T1547.001 | Persistence via `reg add` to HKCU Run key |

---

## Justification

1. **Direct persistence mechanism** — the Run key is a standing autostart location; once the value is written, persistence is achieved immediately at every logon, unlike a scheduled task that requires a separate trigger event.
2. **Masquerading value name** (`SystemHealthCheck`) does not match any real Microsoft-documented entry, consistent with the naming pattern seen in Case_003.
3. **Hidden window flag** on the PowerShell payload is evasion-adjacent and has no legitimate need for routine system entries.
4. **Verdict distinguished from Case_003 (Ambiguous):** there, the persistence trigger was scheduled but unconfirmed as fired; here, the registry write itself is the completed persistence action, making this a confirmed TP rather than a pending/ambiguous one — independent of the benign nature of the current payload (`whoami`).

---

## What Would Change This Verdict to FP

- If `SystemHealthCheck` were documented in `Noise-Baselines/known_legitimate_services.md` as an authorized IT monitoring entry
- If the value pointed to a signed, known internal utility rather than a hidden PowerShell invocation

None apply here — verdict stands as TP.

---

## Recommended Response Actions

- Remove the `SystemHealthCheck` value from `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Monitor for recurrence or modification of the `/d` payload over time
- Escalate to L2 for further correlation with other cases on this host

---

## Triage Metadata

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Verdict | TP |
| Confidence | High |
| Triage Time | 3 minutes (9:02 AM – 9:05 AM) |
| Escalated | Yes |
