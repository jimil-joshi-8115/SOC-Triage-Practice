# PowerShell / Scripting Execution Triage Playbook

Step-by-step checklist for PowerShell, encoded command, and scripting-language alerts. Each
rule is tied to the case that established it.

---

## Step 1: Decode Every Encoded Command Before Judging

- Base64, encoded, or obfuscated PowerShell must be decoded and read in full before ruling on
  intent — never accept "it's encoded, therefore suspicious" or "it's encoded, therefore
  probably fine" without reading the actual content (Case_001, the foundational lesson of this
  entire repo).

---

## Step 2: Check What the Script Actually Does

- **Destructive commands (delete, wipe, disable) are TP from content alone** — use affirmative
  justification ("this command does X, which is harmful") rather than elimination logic ("I
  can't find a reason it's safe") (Case_010).
- **System-wide security/audit configuration changes have no legitimate everyday use case** and
  should be TP on content alone — disabling audit logging, disabling Defender, modifying
  Conditional Access policy via script (Case_018, Case_024).
- Check specifically for combinations that indicate **pre-ransomware staging**: disabling
  real-time AV protection followed by shadow-copy/backup deletion, in that order, using otherwise
  legitimate tools (`powershell.exe`, `vssadmin.exe`) — the tool identity is not the signal, the
  combined purpose is (Case_024, Case_025).

---

## Step 3: Check the Parent Process

- PowerShell spawned from `outlook.exe`/`winword.exe` (email/document-driven) is a strong
  indicator of a malicious delivery chain (Case_027, Case_030, Case_048).
- PowerShell spawned from `explorer.exe` or a legitimate admin tool may still be malicious —
  don't let a "normal-looking" parent alone clear an alert (Case_014's known-abnormal-parent
  lesson works both directions: abnormal parents are red flags, but normal parents don't grant
  automatic safety).

---

## Step 4: Check for Download-and-Execute Cradles

- `IEX(New-Object Net.WebClient).DownloadString(...)` and similar download cradles are a
  consistent, decisive malicious pattern regardless of the specific destination domain's
  reputation at scan time (Case_019, Case_027, Case_048/049 — the loader.ps1 chain).
- If the download source is unlisted/unverified and the deployment method bypasses the
  organization's normal CI/CD or software-distribution process, that combination compounds the
  finding (Case_036's Dashboard-deployed pod).

---

## Step 5: Check for Credential-Dumping Indicators

- LSASS memory access via a **non-standard process name masquerading as a system process**,
  especially running from a user Temp directory rather than a system path, is the standard
  credential-dumping signature (Case_049, DD-001).
- **Remember:** credential-dumping tools harvest *every* cached credential on the host, not just
  the primary user's — always check for downstream use of *other, higher-privilege* accounts
  authenticating from the same compromised host shortly afterward (Case_049, DD-004).

---

## Step 6: Weigh Evidence Retroactively When Needed

- Some scripts/updates have **zero available indicators of compromise at the time they run** (a
  validly-signed vendor update, for example) — the verdict may only be resolvable once a later,
  correlated alert confirms compromise. Don't force a verdict from incomplete information; flag
  it as pending correlation if genuinely unresolvable at that point (Case_041, the SolarWinds
  pattern).
