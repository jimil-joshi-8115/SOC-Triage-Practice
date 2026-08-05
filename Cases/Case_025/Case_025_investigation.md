# Investigation — Case 025

**Verification method:** Ticket-only — no Splunk query run (analyst decision, alternating with
Case_024's Splunk-verified format per repo methodology)

---

## Step 1: E-001 — Check the Dormant Account Login

| Field | Value |
|---|---|
| Account | svc-remote-legacy — dormant, last successful login 247 days ago |
| MFA | Not enrolled |
| Source IP | 91.219.212.44, no prior history |

**Finding:** 🔴 A service/legacy account with no recent activity suddenly authenticating
successfully, with no MFA enrolled and from a never-seen IP, is a textbook re-use of leaked or
stale credentials against an account that should likely have been disabled during access
review. Dormant accounts without MFA are a known, recurring real-world entry vector.

---

## Step 2: E-002 — Check for Correlation Before Assuming It Belongs to the Chain

| Check | E-001/E-003/E-004/E-005 (confirmed chain) | E-002 |
|---|---|---|
| Account | svc-remote-legacy | svc-printmgmt |
| Host(s) touched | MFL-VPN-GW01, MFL-FS01/02, MFL-DC01, MFL-BKP01 | MFL-PRINT02 |
| Source IP | 91.219.212.44 | Not external — internal auth failure |
| Pattern history | First-ever activity for this account | Recurring pattern, seen 3x in 60 days, always resolved as expired scheduled-task credential |

**Finding:** 🟢 No shared account, host, or IP with the rest of the queue. The documented
recurring pattern and standard resolution history are the deciding factor — this is a
known-benign pattern, not a fresh unknown. **Correction made:** initially called TP by pattern-
matching "failed logons = suspicious" without checking correlation first; corrected to FP after
review confirmed it doesn't connect to the rest of the incident and matches an established
benign baseline.

---

## Step 3: E-003 — Check Lateral Movement Against Account Baseline

**Finding:** 🔴 svc-remote-legacy, immediately after its first-ever login (E-001), connects via
SMB to 4 internal hosts within 6 minutes — including the primary file servers, domain
controller, and backup server. Zero SMB activity for this account in the prior 180 days. This
is reconnaissance/lateral-movement staging, targeting exactly the systems relevant to a
ransomware operation (file servers, DC, backups).

---

## Step 4: E-004 — Check the Outbound Transfer

**Finding:** 🔴 94.3 GB moved from the primary file server to the same external IP that
performed the E-001 login, over nearly two hours. This is large-scale exfiltration, consistent
with a double-extortion ransomware pattern (steal data before encrypting, to add leverage).

---

## Step 5: E-005 — Check the Scheduled Task

**Finding:** 🔴 A new scheduled task on the domain controller itself, created by the compromised
account, running an obfuscated (base64) PowerShell payload on every logon. This is persistence
being established on the most sensitive host in the environment, following the exfiltration.

---

## Step 6: E-006 — Live Interrupt

**Finding:** 🔴 14,200+ files renamed with a new extension across both file servers in under 4
minutes, in the same account context as the rest of the chain. This confirms active ransomware
encryption is underway, not just a completed compromise being investigated after the fact.

**Priority re-evaluation triggered by E-006:** the moment this alert fires, the response
priority shifts from "investigate and document E-001 through E-005 in order" to "isolate
MFL-FS01/FS02 from the network immediately, kill svc-remote-legacy's active sessions" — active
encryption in progress overrides normal queue order. Documentation of E-001–E-005 continues,
but containment action takes precedence over further investigation once E-006 confirms live
impact.

---

## Step 7: Correlate the Full Chain

**Finding:** E-001, E-003, E-004, E-005, and E-006 share the same account (svc-remote-legacy)
and/or the same external IP (91.219.212.44), form an unbroken timeline (03:02 → 05:31), and
follow a coherent attack progression: dormant-account access → lateral movement → exfiltration
→ persistence → encryption. E-002 is confirmed unrelated noise.

---

## Summary of Findings

| Check | Result | Risk |
|---|---|---|
| E-001 dormant account login | No MFA, first-ever IP | 🔴 High |
| E-002 correlation check | Different account/host/IP, documented benign pattern | 🟢 None — FP |
| E-003 lateral movement | 4 hosts via SMB, zero prior 180-day activity | 🔴 High |
| E-004 outbound transfer | 94.3 GB to same IP as E-001 | 🔴 High |
| E-005 persistence | New scheduled task, obfuscated payload, on DC | 🔴 High |
| E-006 live interrupt | 14,200+ files encrypted, active ransomware | 🔴 Critical |
| Chain correlation | Same account/IP, unbroken timeline, E-002 isolated | 🔴 High — single incident |
