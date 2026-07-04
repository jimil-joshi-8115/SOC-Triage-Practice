# Verdict — Case 010 (Phase 2 Batch 2)

## Final Verdicts

| Alert | Verdict | MITRE ATT&CK |
|---|---|---|
| **Alert E** — vssadmin Delete Shadows | 🔴 **TP** | T1490 — Inhibit System Recovery |
| **Alert F** — Invoke-WebRequest (GitHub) | 🟡 **Ambiguous** | T1105 — Ingress Tool Transfer |
| **Alert D** — whoami After RDP Logon | 🟡 **Ambiguous** | — |

---

## Justification Summary

**Alert E (TP):** `vssadmin delete shadows /all /quiet` is an unambiguous, destructive action with a well-documented malicious use case (ransomware pre-encryption step). The command's effect does not depend on further context to establish concern — its scope and irreversibility alone justify TP.

**Alert F (Ambiguous):** Downloading a script from GitHub is not inherently malicious — the platform is legitimate and the file extension is undisguised, distinguishing this from Case_008's raw-IP/disguised-extension pattern. However, the specific repository is undocumented in any baseline, and the script's actual content/purpose is unknown since no execution was observed. Evidence supports neither a clean TP nor a clean FP.

**Alert D (Ambiguous):** A single `whoami` command is not inherently suspicious, but the surrounding context — occurring immediately after an RDP (RemoteInteractive) logon — is a recognized first-step recon pattern for an attacker confirming their access level after gaining remote entry. No further recon or lateral movement was observed following it, so a confident TP cannot be established, but the context also prevents a clean FP dismissal purely on the basis of the command being "just whoami."

**Note on investigation approach:** Initial assessment of Alert D treated the command in isolation and leaned toward FP based on the command content alone; the verdict was revised to Ambiguous after incorporating the RDP logon-type context provided in the alert data, reinforcing the practice of evaluating commands within their full session context rather than in isolation.

---

## Prioritization Review

**Chosen order:** E → F → D

**Assessment:** Correctly prioritized based on potential impact severity (destructive/irreversible action first) rather than defaulting to the SIEM's own label ordering, though in this batch the label ordering (High → Medium → Low) happened to align with the chosen priority. The reasoning behind the choice — assessing worst-case impact before investigating — is the transferable skill being demonstrated here.

---

## What Would Change Each Verdict

**Alert E → FP if:** Confirmed as part of an authorized backup/storage-cleanup maintenance window with a documented change ticket — not the case here.

**Alert F → TP if:** `tool.ps1` were retrieved and found to contain malicious code upon execution or static analysis.
**Alert F → FP if:** The repository were documented as an internally-used, vetted tool in the environment's baseline.

**Alert D → TP if:** Follow-up recon or lateral movement commands were observed in the same RDP session.
**Alert D → FP if:** The RDP session were confirmed to belong to a known, authorized remote administrator performing routine work.

---

## Recommended Response Actions

- **Alert E:** Immediate escalation — treat as a likely active incident; check for other ransomware precursor indicators (file encryption activity, mass file renames) on this and other hosts.
- **Alert F:** Retrieve and statically analyze `tool.ps1` in a sandbox before it executes, if not already run; hold at Ambiguous pending content review.
- **Alert D:** Review full session activity for the RDP logon (source IP, session duration, subsequent commands) to resolve the ambiguity; hold at Ambiguous pending that review.

---

## Triage Metadata

| Alert | Triage Time |
|---|---|
| Alert E | 2 minutes (8:40 AM – 8:42 AM) |
| Alert F | 2 minutes (8:45 AM – 8:47 AM) |
| Alert D | 4 minutes (8:51 AM – 8:55 AM) |

| Field | Value |
|---|---|
| Analyst | Jimil Joshi |
| Batch Size | 3 alerts |
| Correct Prioritization | Yes |
| Escalated | Alert E (Yes, immediate), Alert F (Hold/Review), Alert D (Hold/Review) |
