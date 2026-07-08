# Failed Logon Triage Playbook

Built from real triage patterns confirmed across Cases 005, 006, 015, and 019.

---

## Step-by-Step Checklist

1. **Count the attempts.** Volume is often decisive on its own:
   - **1-2 attempts:** Insufficient volume to confirm either direction — lean **Ambiguous**. Too few to match a brute-force pattern, but not so few that an attacker's early guesses can be ruled out. (Case_015, Alert S)
   - **5+ attempts, same account, tight window (under ~1 min):** Decisive **TP** — brute force (T1110), regardless of whether any attempt succeeded. (Case_005)
   - **3+ distinct accounts attempted in a short window:** Decisive **TP** — password spraying (T1110.003), regardless of internal/external origin. (Case_006)

2. **Check same-account vs. multi-account pattern.**
   - Same account repeated = classic brute-force (T1110).
   - Multiple distinct accounts = password spray (T1110.003) — often targets default/common names like `admin`, `administrator`, `support`.

3. **Check source origin (internal vs. external).**
   - External source IP + high-value account target (e.g., `administrator`) = elevated severity, active outside attack surface exposure. (Case_016, Alert AA — RDP brute force from external IP)
   - Internal source doesn't clear the alert — still evaluate on volume/pattern alone.

4. **Check Logon_Type — context changes the read on some commands.**
   - Type 2 (Interactive) = physical presence, rules out remote-attacker access via network logon.
   - Type 3 (Network) / Type 10 (RemoteInteractive/RDP) = remote — combine with other recon signals (e.g., `whoami` immediately after) for elevated concern. (Case_010, Alert D)

5. **Never assume "it didn't succeed" = FP.** A failed brute-force attempt is still TP-worthy malicious behavior — outcome and verdict are evaluated separately. (Case_005, Case_013's ntds.dit-attempt logic applies the same principle)

6. **Check for a follow-up successful logon or account lockout.**
   - Query EventCode 4624 (success) and 4740 (lockout) after the failed attempts.
   - **No lockout after 5+ failures** is itself a secondary finding worth flagging — indicates no lockout policy is enforced (Case_005).

7. **Don't over-interpret the generic Windows failure message.** "Unknown user name or bad password" does not confirm *which* part failed — could be a valid account with a wrong password (Case_005) or a genuinely invalid username (Case_006). Check account existence against your baseline separately.

---

## Verdict Quick Reference

| Pattern | Verdict |
|---|---|
| 1-2 attempts, no other context | Ambiguous |
| 5+ attempts, same account | TP (T1110) |
| 3+ distinct accounts, short window | TP (T1110.003) |
| High volume, external IP, high-value account | TP (T1110), elevated severity |
| Followed by successful logon | TP, escalate immediately — likely compromise |
