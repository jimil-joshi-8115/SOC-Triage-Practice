# Investigation — Case 020 (Final Exam, Stage 2: The Cascade)

## Prioritization Decision

**Chosen order: BI → BH → BJ**

**Justification:**
- **BI first** — this is the same confirmed-malicious process (`svc.exe`, from BA/BG) now running as SYSTEM and making an additional outbound connection. This is not a new investigation from scratch; it is continuation evidence of an already-active, confirmed incident, correctly prioritized above all else.
- **BH second** — an independent, serious credential-theft technique (Kerberoasting pattern) deserves early attention even though it does not directly overlap with the BA/BG/BI chain.
- **BJ last** — a self-reported phishing email with no execution is the lowest-risk item in this stage; correctly triaged last.

---

## Alert BI — SYSTEM-Context Outbound Connection (Same Process as BA)

**SPL Query:**
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4688 New_Process_Name="*svc.exe"
| table _time, ComputerName, Account_Name, Process_Command_Line, Creator_Process_Name
| sort -_time
| head 5
```

**Result:** Same PID as Alert BA's `svc.exe`, now connecting outbound to `91.242.217.88:8080`, running as `SYSTEM`.

**Findings:** This is the clearest possible confirmation case in the entire exercise — the exact process already confirmed malicious in BA (and confirmed as Mimikatz via EDR in BG) has escalated to SYSTEM privilege and is making an additional outbound connection, likely a C2 callback or secondary data channel. No new investigation is required; this is direct continuation evidence.

**Verdict: 🔴 TP — T1071 (C2), correlated directly with BA/BG**

---

## Alert BH — Kerberoasting Pattern

**Given Data:** `5 different service-account TGS-REQ events within 90 seconds, requested by account hp`

**Findings:** Requesting Kerberos service tickets for 5 distinct service accounts in rapid succession has no legitimate everyday justification — this is a well-documented offline-crackable-credential harvesting technique (T1558.003). Combined with the already-confirmed BA/BG/BI chain, this indicates the compromised `hp` account/session is being used for multiple, independent credential-theft techniques, not a single isolated action.

**Verdict: 🔴 TP — T1558.003**

---

## Alert BJ — Self-Reported Phishing Email (No Execution)

**Given Data:** `Employee r.kumar forwarded a suspicious email to IT-Security, no links clicked, reported before taking action`

**Findings:** This represents the security-awareness process functioning exactly as intended — the employee identified a suspicious email and reported it without interacting with it. No aggravating factors, no execution, no compromise indicators.

**Verdict: 🟢 FP**

---

## Summary Table

| Alert | Verdict | MITRE | Notes |
|---|---|---|---|
| BI | 🔴 TP | T1071 | Direct continuation of BA/BG chain |
| BH | 🔴 TP | T1558.003 | Independent technique, same compromised session |
| BJ | 🟢 FP | — | Awareness process working correctly |

---

## Full-Session Attack Chain Reconstruction (Cases 019 + 020 Combined)

1. **BA** — Unsigned binary (`svc.exe`) downloaded from external IP and executed.
2. **BG** — EDR confirms `svc.exe` is an active Mimikatz-signature process.
3. **BB** — Login to the `hp` account from a Tor exit node (likely how initial access/control was obtained or reinforced).
4. **BD** — Large-scale DNS TXT tunneling, likely exfiltrating data or receiving C2 instructions.
5. **BC** — Persistent AV-enumeration task established, indicating the attacker is actively probing defenses for further evasion.
6. **BI** — The confirmed malicious process escalates to SYSTEM and opens an additional outbound channel.
7. **BH** — Kerberoasting attempted against 5 service accounts, indicating lateral-movement/credential-harvesting escalation is underway.

**Unrelated, correctly-closed items:** BF (Windows Update stopped), BE (AD display name change), BJ (self-reported phishing, no execution) — none connected to the active chain.
