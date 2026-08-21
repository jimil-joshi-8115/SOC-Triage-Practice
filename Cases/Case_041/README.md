# Case_041 — Supply Chain: Trojanized Monitoring Platform Update → Delayed DGA Beaconing

**Phase:** 5 (Cases 31–50) — Supply Chain / Trojanized Software Update, 3-alert batch
**Format:** EDR + DNS Logs
**Company:** Aurora Resorts & Casinos (internal alias — sanitized)
**Splunk verified:** No — ticket-only (analyst decision)

**Scenario basis:** Adapted from the 2020 SolarWinds/SUNBURST supply chain attack — a
monitoring platform's legitimate, signed update mechanism delivered a trojanized DLL backdoor,
which remained dormant for approximately two weeks specifically to evade detection before
beginning DNS-based command-and-control communication using a domain generation algorithm
(DGA). All company, host, and identifier details below are fictional/sanitized.

---

## Alerts (as received at trigger time)

```
Alert U-001 — EDR: Signed DLL Loaded From Monitoring Platform Update
  Severity: Medium
  Host: AURORA-MON01 (internal infrastructure monitoring server)
  Detail: New DLL "NetworkGuard.Core.BusinessLayer.dll" loaded following a
          routine software update from the monitoring platform's official
          update server (update signed with the vendor's valid code-signing
          certificate); file hash does not match any known-malicious hash
          database (no detections at time of alert)
  Time: 2026-07-14 03:00:00 UTC (scheduled update window)

Alert U-002 — DNS: Beaconing Pattern From Monitoring Server, 14 Days Post-Update
  Severity: Critical
  Host: AURORA-MON01 (same host as U-001)
  Detail: Host began making periodic DNS requests to randomized subdomains
          of a single parent domain (pattern consistent with a domain
          generation algorithm), at irregular intervals (4-90 minutes
          apart); domain registered 11 months ago, no legitimate business
          relationship found; monitoring platform has no documented feature
          requiring this behavior
  Time: 2026-07-28 09:14:00 UTC onward (exactly 14 days after U-001)

Alert U-003 — EDR: Scheduled Antivirus Definition Update
  Severity: Low
  Host: AURORA-MON01 (same host)
  Detail: Windows Defender definition update applied automatically; matches
          standard daily update schedule, signed Microsoft update package
  Time: 2026-07-28 06:00:00 UTC (3 hours before U-002)
```

## Task

TP / FP / Ambiguous for U-001 through U-003. Note the 14-day gap between U-001 and U-002
specifically, and give U-003 full consideration before ruling on it.
