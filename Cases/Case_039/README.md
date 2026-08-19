# Case_039 — AWS EC2: Metadata Rebinding → Cryptocurrency Mining, Plus Blocked Routine Scanning

**Phase:** 5 (Cases 31–50) — AWS, 3-alert batch
**Format:** AWS GuardDuty Findings
**Company:** Aurora Resorts & Casinos (internal alias — sanitized)
**Splunk verified:** No — ticket-only (analyst decision)

**Scenario basis:** Grounded in widely-documented real-world cloud cryptojacking campaigns
(e.g., TeamTNT-style operations) targeting exposed or vulnerable EC2 instances — stealing
instance credentials via the metadata service and deploying cryptocurrency mining software.

---

## Alerts (as received at trigger time)

```
Alert S-001 — GuardDuty: UnauthorizedAccess:EC2/MetadataDNSRebind
  Severity: High
  Instance: i-0a3f8e21b9c4d5678 (aurora-web-app-03, public-facing web server
            running an outdated Node.js version with a known unpatched
            vulnerability, per last month's vuln scan report VULN-2291)
  Detail: Instance's application process made a DNS rebinding request pattern
          consistent with an attempt to bypass IMDS protections and reach the
          instance metadata service from external-facing application logic
  Time: 04:12:18 UTC

Alert S-002 — GuardDuty: CryptoCurrency:EC2/BitcoinTool.B!DNS
  Severity: Critical
  Instance: i-0a3f8e21b9c4d5678 (same instance as S-001)
  Detail: EC2 instance queried a domain associated with a known
          cryptocurrency mining pool; outbound connection established on
          port 3333 (standard Stratum mining protocol port) shortly after
  Time: 04:19:44 UTC (7 minutes after S-001)

Alert S-003 — GuardDuty: Recon:EC2/PortProbeUnprotectedPort
  Severity: Low
  Instance: i-0f7c2a91e3b8d4401 (aurora-batch-processing-07, internal batch
            job runner, not public-facing)
  Detail: Multiple inbound connection attempts detected on port 22 (SSH)
          from a security research/internet-scanning service's known IP
          range (routine mass internet scanning, not targeted); all
          connection attempts were rejected — instance's security group
          does not allow inbound SSH from any external range
  Time: 05:02:11 UTC
```

## Task

TP / FP / Ambiguous for S-001 through S-003. Note correlation, and consider what makes S-003
different in kind, not just severity, from S-001/S-002.
