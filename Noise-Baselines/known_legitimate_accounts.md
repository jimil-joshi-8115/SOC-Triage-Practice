# Known Legitimate Accounts — Noise Baseline

Documented account patterns confirmed during Cases 001-020.

---

## Standard Interactive User

| Account | Status | Notes |
|---|---|---|
| `hp` | 🟢 Legitimate, standard interactive user | Primary account on JIMIL-JOSHI; normal Logon_Type 2 (Interactive) activity from this account is expected baseline behavior |

---

## Non-Baseline / Confirmed Malicious Account Patterns

These account names appeared during simulated attacks and are **not** legitimate — documented here as the inverse reference so they're instantly recognizable if seen again:

| Account | Status | Source Case |
|---|---|---|
| `hpbackup` | 🔴 Confirmed malicious — masquerading, service-like name | Case_002, Case_012 (Alert J) |
| `svc_backup_02`, `admin_tmp`, `support_local`, `sync_agent` | 🔴 Pattern class — masquerading service-account naming | Drill practice, consistent with `hpbackup` pattern |

**Rule:** Service-like account names (containing "backup," "svc," "sync," "admin," "support") that don't match a documented baseline are a masquerading red flag, not a reassurance. Attackers use these names specifically to blend into normal-looking account lists.

---

## Self-Add vs. Separate-Account Add — Key Distinction

| Scenario | Verdict | Reasoning | Source Case |
|---|---|---|---|
| Separate, unfamiliar account added to **Administrators** | 🔴 TP | No legitimate explanation for a new, unknown identity gaining high privilege | Case_002, Case_012 (Alert J) |
| Existing known user (`hp`) adds **themselves** to a lower-privilege group (e.g., Remote Desktop Users) | 🟡 Ambiguous | Genuinely dual-use — legitimate self-service remote-work setup vs. attacker establishing persistence on a compromised session | Case_017, Alert AD |
| Built-in Administrator account enabled, **against documented policy** stating it should remain disabled | 🔴 TP | Violates an explicit baseline control — no legitimate justification | Drill practice |

**Rule:** Always distinguish *who* is being added and *what privilege level* — a separate/unfamiliar identity gaining high privilege is decisive; an existing known user making a lower-privilege change to their own account is genuinely more ambiguous and needs corroborating context (e.g., a documented remote-work ticket) to resolve.

---

## Maintenance Log

Add newly confirmed legitimate or malicious account patterns here as they're validated in future cases.
