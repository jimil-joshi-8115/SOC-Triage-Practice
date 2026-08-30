# Scheduled Task / Persistence Mechanism Triage Playbook

Step-by-step checklist for scheduled tasks, cron jobs, registry run keys, cloud persistence
mechanisms (rogue IdPs, OAuth apps, CA policy exemptions), and other standing-access
configurations. Each rule is tied to the case that established it.

---

## Step 1: Check the Name Against Legitimacy, Not Just Plausibility

- A **legitimate-looking name is not proof of legitimacy** — attackers deliberately name
  persistence mechanisms to blend in (e.g., `hpbackup`, a scheduled task mimicking a Windows
  system task name) (Case_002, Case_003).
- Compare against the **actual documented baseline** for that exact name/pattern, not just "does
  this sound like something Windows/the org would create."

---

## Step 2: Check What the Task/Mechanism Actually Executes

- A scheduled task or rule that is superficially named to sound routine but executes an
  obfuscated payload, hidden window, or unexpected binary is TP regardless of the name
  (Case_003, Case_024's "WindowsUpdateHealthCheck" running an obfuscated PowerShell block).
- Confirm binary signature and expected schedule together — a signed binary running off-schedule,
  or a task name matching schedule but running an unsigned/unexpected binary, are both red flags
  (Case_027 G-004, Case_036 P-003, Case_041 U-003).

---

## Step 3: Assess the Persistence Mechanism's *Scope*, Not Just Its Existence

This is the most important escalation this playbook has learned across Phases 4-5: some
persistence mechanisms operate at the **individual account level**, and some operate at the
**tenant/organization security-policy level**. The latter is categorically more dangerous.

| Scope | Example | Why It Matters | Source Case |
|---|---|---|---|
| Individual account | Registry Run key, local scheduled task | Removed by cleaning the one host/account | Case_007 |
| Individual account (cloud) | New MFA factor added to one compromised account | Removed by resetting that one account | Case_034 |
| **Tenant/policy-level** | Rogue federated IdP; OAuth app with `Directory.ReadWrite.All`; Conditional Access trusted-location exemption | Survives a full reset of the originally-compromised account — affects *any* account/session using the exploited policy going forward | Case_024, Case_028, Case_032, Case_042, Case_047 |

**Rule:** When you find a policy-level persistence mechanism, the remediation priority is
removing the *policy modification itself*, not just resetting the account that created it.

---

## Step 4: Check for Suppression/Concealment Mechanisms

- Inbox rules or similar mechanisms that specifically hide legitimate security notifications
  (e.g., moving "unusual sign-in" alerts to Deleted Items) are concealment tradecraft, not
  personal mailbox organization — check the exact keyword targeting (Case_022, Case_030).

---

## Step 5: Correlate Timing With the Suspected Entry Point

- Persistence is frequently established within minutes of initial compromise — check the timing
  gap between a suspected entry point (phishing click, credential theft, privilege escalation)
  and any subsequent policy/task/rule creation (Cases 022, 024, 028, 030, 042 all show
  persistence established within single-digit minutes of the initial compromise).
- Some persistence is **delayed deliberately** to evade detection — a multi-day dormancy period
  before activity begins is itself a documented evasion technique, not evidence of legitimacy
  (Case_041's 14-day gap).

---

## Step 6: Confirm Root-Cause Documentation Before Closing as FP

- A legitimate scheduled task, GPO update, or policy change should have a **specific, traceable
  change ticket or documented recurring schedule** — the absence of one, especially for
  security-relevant infrastructure, is itself worth escalating even before further investigation
  (Case_024 H-001, Case_047 BB-001).
