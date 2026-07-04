# Verdict — Case 009 (Phase 2 Batch)

## Final Verdicts

| Alert | Verdict | MITRE ATT&CK |
|---|---|---|
| **Alert B** — New Local Service | 🔴 **TP** | T1543.003 — Create or Modify System Process: Windows Service |
| **Alert C** — Repeated nslookup | 🟡 **Ambiguous** | T1071.004 — Application Layer Protocol: DNS |
| **Alert A** — Get-Clipboard | 🟢 **FP** | — |

---

## Justification Summary

**Alert B (TP):** Service name masquerades as a legitimate Defender component, but the binary path (`AppData\Local\Temp`) is a decisive indicator — no legitimate Windows service installs from a user Temp directory. Combined with SYSTEM-context execution, this represents a high-impact persistence mechanism.

**Alert C (Ambiguous):** Three DNS lookups to an unrecognized domain within ~31 seconds do not match normal caching/browsing behavior and structurally resemble C2 beaconing (T1071.004). However, no confirmed malicious response, resolved IP reputation, or follow-up network connection was available in this dataset — the evidence shows a suspicious *pattern*, not a confirmed *outcome*.

**Alert A (FP):** A single, fully visible `Get-Clipboard` call with a standard `cmd.exe → powershell.exe` execution chain and no aggravating factors (no hidden window, no encoding, no external destination, no repetition). Consistent with benign/manual use rather than data collection for exfiltration.

---

## Prioritization Review

**Chosen order:** B → C → A

**Assessment:** This order was well-justified independently of the SIEM's own severity labels — the analyst prioritized based on actual risk factors (SYSTEM-level persistence for B, active-communication-pattern concern for C) rather than blindly following the High/Medium/Low labels. In this batch, the SIEM labels happened to align with the correct priority order, but the reasoning behind the analyst's choice was sound on its own merits and would have held up even if the labels had been reversed or mismatched.

---

## What Would Change Each Verdict

**Alert B → FP if:** `WinDefenderHelper` were documented as an authorized internal tool deployed via a legitimate but unconventional path (uncommon, but possible in poorly-managed environments) — not the case here.

**Alert C → TP if:** The resolved IP for `update-cdn-cache.com` matched known malicious infrastructure, or a follow-up outbound connection to that IP was observed.
**Alert C → FP if:** The domain were confirmed to belong to a legitimate CDN/software update service used by installed applications on this host.

**Alert A → TP if:** The clipboard read were paired with a subsequent network call, file write, or encoded/hidden execution — none of which are present here.

---

## Recommended Response Actions

- **Alert B:** Remove the `WinDefenderHelper` service immediately; inspect `svc.exe` in a sandboxed environment; escalate to L2.
- **Alert C:** Perform a passive DNS/reputation lookup on `update-cdn-cache.com`; monitor for recurrence or an actual outbound connection following resolution; hold at Ambiguous pending that data.
- **Alert A:** No action required; close as FP.

---

## Triage Metadata

| Alert | Triage Time |
|---|---|
| Alert B | 3 minutes (8:09 AM – 8:12 AM) |
| Alert C | 5 minutes (8:17 AM – 8:22 AM) |
| Alert A | 2 minutes (8:25 AM – 8:27 AM) |

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Batch Size | 3 alerts |
| Correct Prioritization | Yes |
| Escalated | Alert B (Yes), Alert C (Hold/Monitor), Alert A (No) |
